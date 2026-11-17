"""A2A Protocol v1.0 Specification & Cryptographic Primitives.

Implements genuine, verifiable cryptography and protocol state machines:
- RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serializer
- RFC 8037 / RFC 7515 Asymmetric Ed25519 (`EdDSA`) JSON Web Signatures (`signatures[]`)
  on `/.well-known/agent-card.json` + public JWKS (`/.well-known/jwks.json`) + mathematical
  signature verification (`verify_agent_card_jws`)
- `AgentCapabilities` declaring `streaming`, `pushNotifications`, and `extendedAgentCard`
  (explicitly omitting deprecated v0.3 `supportsExtendedAgentCard`)
- `supportedInterfaces[]` with `url`, `protocolBinding`, and `protocolVersion: "1.0"`
- Unified `Part` objects with member-based `oneof` fields (`text`, `raw`, `url`, `data`) — no `kind`
- Immutable terminal states (`TASK_STATE_COMPLETED`, `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`, `TASK_STATE_REJECTED`)
  with `contextId` and `referenceTaskIds` lineage
- `SendStreamingMessage` SSE generator emitting `TaskStatusUpdateEvent` and chunked `TaskArtifactUpdateEvent`
  (`append` and `lastChunk` semantics)
- Standardized errors under `google.rpc.Status` with `google.rpc.ErrorInfo` (`domain: "a2a-protocol.org"`)
- `TaskPushNotificationConfig` webhook protection with SSRF guard + real Ed25519 JWT signature
  verification (`exp`, `aud`, and `jti` replay protection)
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import time
from enum import Enum
from typing import Any, Generator
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class TaskState(str, Enum):
    TASK_STATE_SUBMITTED = "TASK_STATE_SUBMITTED"
    TASK_STATE_WORKING = "TASK_STATE_WORKING"
    TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    TASK_STATE_COMPLETED = "TASK_STATE_COMPLETED"
    TASK_STATE_FAILED = "TASK_STATE_FAILED"
    TASK_STATE_CANCELED = "TASK_STATE_CANCELED"
    TASK_STATE_REJECTED = "TASK_STATE_REJECTED"


IMMUTABLE_TERMINAL_STATES: frozenset[TaskState] = frozenset(
    {
        TaskState.TASK_STATE_COMPLETED,
        TaskState.TASK_STATE_FAILED,
        TaskState.TASK_STATE_CANCELED,
        TaskState.TASK_STATE_REJECTED,
    }
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _jcs_serialize_value(val: Any) -> str:
    """RFC 8785 Section 3.2 compliant canonical JSON value serializer."""
    if val is None:
        return "null"
    if val is True:
        return "true"
    if val is False:
        return "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise ValueError("RFC 8785 JCS forbids NaN or Infinity in JSON numbers.")
        if val == 0.0:
            return "0"
        if val.is_integer() and abs(val) < 1e21:
            return str(int(val))
        return json.dumps(val, allow_nan=False)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(_jcs_serialize_value(item) for item in val) + "]"
    if isinstance(val, dict):
        # RFC 8785 sorts object properties lexicographically by UTF-16 code units
        sorted_items = sorted(
            ((str(k), v) for k, v in val.items()),
            key=lambda kv: kv[0].encode("utf-16-be"),
        )
        inner = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_jcs_serialize_value(v)}"
            for k, v in sorted_items
        )
        return "{" + inner + "}"
    raise TypeError(f"Unsupported type for RFC 8785 JCS canonicalization: {type(val)!r}")


def canonicalize_jcs(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (JCS) deterministic UTF-8 byte serializer."""
    return _jcs_serialize_value(obj).encode("utf-8")


class A2AKeyPair:
    """Asymmetric Ed25519 (`EdDSA`, RFC 8037) keypair for AgentCard JWS & Webhook JWT verification."""

    def __init__(self, private_key: Ed25519PrivateKey, kid: str = "mcpguard-ed25519-2026-11") -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.kid = kid

    @classmethod
    def from_env_or_ephemeral(cls, kid: str | None = None) -> A2AKeyPair:
        """Load 32-byte hex/base64url seed from `MCPGUARD_A2A_ED25519_SEED` or generate ephemeral key."""
        resolved_kid = kid or os.environ.get("MCPGUARD_A2A_SIGNING_KEY_ID", "mcpguard-ed25519-2026-11")
        seed_env = os.environ.get("MCPGUARD_A2A_ED25519_SEED", "").strip()
        if seed_env:
            seed_bytes = bytes.fromhex(seed_env) if len(seed_env) == 64 else _b64url_decode(seed_env)
            priv = Ed25519PrivateKey.from_private_bytes(seed_bytes[:32])
        else:
            priv = Ed25519PrivateKey.generate()
        return cls(private_key=priv, kid=resolved_kid)

    def public_jwk(self) -> dict[str, str]:
        """Export RFC 8037 `OKP` Ed25519 public JWK."""
        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": self.kid,
            "x": _b64url_encode(pub_bytes),
        }

    def public_jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [self.public_jwk()]}

    def sign_jws_detached(self, canonical_payload: bytes) -> dict[str, Any]:
        """Create RFC 7515 JWS signature entry over RFC 8785 JCS payload using Ed25519 (`EdDSA`)."""
        protected_header = {
            "alg": "EdDSA",
            "kid": self.kid,
            "typ": "JOSE+JSON",
            "crit": ["jcs"],
        }
        protected_b64 = _b64url_encode(canonicalize_jcs(protected_header))
        payload_b64 = _b64url_encode(canonical_payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        sig_bytes = self._private_key.sign(signing_input)
        return {
            "protected": protected_b64,
            "signature": _b64url_encode(sig_bytes),
            "header": {
                "kid": self.kid,
                "alg": "EdDSA",
                "jcs_sha256": hashlib.sha256(canonical_payload).hexdigest(),
            },
        }

    def issue_signed_jwt(self, claims: dict[str, Any]) -> str:
        """Issue a compact RFC 7519 + RFC 8037 `EdDSA` signed JWT for webhook testing/auth."""
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.kid}
        h_b64 = _b64url_encode(canonicalize_jcs(header))
        p_b64 = _b64url_encode(canonicalize_jcs(claims))
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        sig_b64 = _b64url_encode(self._private_key.sign(signing_input))
        return f"{h_b64}.{p_b64}.{sig_b64}"


DEFAULT_SERVER_KEYPAIR = A2AKeyPair.from_env_or_ephemeral()


def build_signed_agent_card(
    base_url: str = "http://localhost:8080",
    keypair: A2AKeyPair | None = None,
) -> dict[str, Any]:
    """Construct and asymmetrically sign (`EdDSA` over RFC 8785 JCS) the A2A v1.0 AgentCard."""
    kp = keypair or DEFAULT_SERVER_KEYPAIR
    card: dict[str, Any] = {
        "name": "MCPGuard-ADK",
        "description": (
            "Multi-agent MCP supply-chain, >200K token cost-cliff, and tool-trajectory auditor "
            "built on Google ADK 2.0, A2A Protocol v1.0, and OpenTelemetry."
        ),
        "version": "0.3.0",
        "provider": {
            "organization": "MCPGuard-ADK Open Source",
            "url": "https://github.com/Chitresh-Bhatia-264/MCPGuard-ADK",
        },
        "supportedInterfaces": [
            {
                "url": f"{base_url.rstrip('/')}/a2a/v1",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
            },
            {
                "url": f"{base_url.rstrip('/')}/a2a/v1/stream",
                "protocolBinding": "SSE",
                "protocolVersion": "1.0",
            },
        ],
        "capabilities": {
            "streaming": True,
            "pushNotifications": True,
            "extendedAgentCard": True,
        },
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/x-diff"],
        "skills": [
            {
                "id": "mcp-supply-chain-and-cost-audit",
                "name": "MCP Supply-Chain & >200K Cost-Cliff Audit",
                "description": (
                    "Audits MCP server configurations, Python ADK graphs, and PR diffs; emits "
                    "hardened unified patches, SARIF v2.1.0, and ADK .test.json regression fixtures."
                ),
                "tags": ["mcp-security", "google-adk", "cost-optimization", "opentelemetry"],
            }
        ],
    }

    jcs_bytes = canonicalize_jcs(card)
    card["signatures"] = [kp.sign_jws_detached(jcs_bytes)]
    return card


def verify_agent_card_jws(card: dict[str, Any], jwks: dict[str, Any]) -> bool:
    """Cryptographically verify an A2A v1.0 `AgentCard` against an RFC 8037 Ed25519 JWKS."""
    signatures = card.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False

    unsigned_card = {k: v for k, v in card.items() if k != "signatures"}
    canonical_bytes = canonicalize_jcs(unsigned_card)
    payload_b64 = _b64url_encode(canonical_bytes)

    keys_by_kid = {
        k["kid"]: k
        for k in jwks.get("keys", [])
        if isinstance(k, dict) and k.get("kty") == "OKP" and k.get("crv") == "Ed25519"
    }

    for sig_entry in signatures:
        try:
            protected_b64 = sig_entry["protected"]
            protected_hdr = json.loads(_b64url_decode(protected_b64).decode("utf-8"))
            if protected_hdr.get("alg") != "EdDSA":
                continue
            kid = protected_hdr.get("kid") or sig_entry.get("header", {}).get("kid")
            jwk = keys_by_kid.get(kid)
            if not jwk:
                continue
            pub_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
            signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
            pub_key.verify(_b64url_decode(sig_entry["signature"]), signing_input)
            return True
        except (KeyError, ValueError, InvalidSignature):
            continue
    return False


class A2APart:
    """Unified A2A v1.0 `Part` object using member-based `oneof` (`text`, `raw`, `url`, `data`).

    Explicitly omits the legacy v0.3 `kind` discriminator field.
    """

    VALID_ONEOF_KEYS = ("text", "raw", "url", "data")

    def __init__(
        self,
        *,
        text: str | None = None,
        raw: str | None = None,
        url: str | None = None,
        data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        populated = [
            k
            for k, v in (("text", text), ("raw", raw), ("url", url), ("data", data))
            if v is not None
        ]
        if len(populated) != 1:
            raise ValueError(
                f"A2A v1.0 Part requires exactly one member-based oneof field among {self.VALID_ONEOF_KEYS}; got {populated}"
            )
        self._field = populated[0]
        self._value = (
            text if text is not None else (raw if raw is not None else (url if url is not None else data))
        )
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {self._field: self._value}
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


def build_a2a_error_status(
    code: int,
    message: str,
    reason: str,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Format an A2A v1.0 error response under `google.rpc.Status` + `google.rpc.ErrorInfo`."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": reason,
                    "domain": "a2a-protocol.org",
                    "metadata": metadata or {},
                }
            ],
        }
    }


class A2ATaskManager:
    """Tracks A2A v1.0 tasks, enforcing immutable terminal states and `contextId` / `referenceTaskIds`."""

    def __init__(self) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}

    def create_task(
        self,
        task_id: str,
        context_id: str,
        reference_task_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        task = {
            "id": task_id,
            "contextId": context_id,
            "referenceTaskIds": reference_task_ids or [],
            "status": {"state": TaskState.TASK_STATE_SUBMITTED.value},
            "artifacts": [],
        }
        self._tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> dict[str, Any]:
        if task_id not in self._tasks:
            return build_a2a_error_status(
                code=5,
                message=f"Task '{task_id}' not found.",
                reason="TASK_NOT_FOUND",
                metadata={"taskId": task_id},
            )
        return self._tasks[task_id]

    def transition_state(self, task_id: str, new_state: TaskState) -> dict[str, Any]:
        if task_id not in self._tasks:
            return build_a2a_error_status(
                code=5,
                message=f"Task '{task_id}' not found.",
                reason="TASK_NOT_FOUND",
                metadata={"taskId": task_id},
            )
        current_state = TaskState(self._tasks[task_id]["status"]["state"])
        if current_state in IMMUTABLE_TERMINAL_STATES:
            return build_a2a_error_status(
                code=9,
                message=(
                    f"Task '{task_id}' is in immutable terminal state '{current_state.value}' "
                    f"and cannot transition to '{new_state.value}'. Create a follow-up task linked "
                    "via `contextId` and `referenceTaskIds`."
                ),
                reason="IMMUTABLE_TERMINAL_STATE_VIOLATION",
                metadata={
                    "taskId": task_id,
                    "terminalState": current_state.value,
                    "attemptedState": new_state.value,
                },
            )
        self._tasks[task_id]["status"]["state"] = new_state.value
        return self._tasks[task_id]

    def stream_audit_execution(
        self,
        task_id: str,
        context_id: str,
        unified_diff: str,
        test_fixture: dict[str, Any],
        reference_task_ids: list[str] | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Execute `SendStreamingMessage` SSE sequence (`TaskStatusUpdateEvent` + chunked `TaskArtifactUpdateEvent`)."""
        self.create_task(task_id=task_id, context_id=context_id, reference_task_ids=reference_task_ids)
        self.transition_state(task_id, TaskState.TASK_STATE_WORKING)

        yield {
            "event": "TaskStatusUpdateEvent",
            "data": {
                "taskId": task_id,
                "contextId": context_id,
                "status": {
                    "state": TaskState.TASK_STATE_WORKING.value,
                    "message": {
                        "role": "agent",
                        "parts": [
                            A2APart(
                                text="Running ADK 2.0 Hybrid Graph Workflow (Stage 1 AST Pre-Filter -> Stage 4 Optimizer)..."
                            ).to_dict()
                        ],
                    },
                },
                "final": False,
            },
        }

        midpoint = max(1, len(unified_diff) // 2)
        chunk_1 = unified_diff[:midpoint]
        chunk_2 = unified_diff[midpoint:]

        yield {
            "event": "TaskArtifactUpdateEvent",
            "data": {
                "taskId": task_id,
                "contextId": context_id,
                "artifact": {
                    "artifactId": f"{task_id}-hardened-patch",
                    "name": "hardened_mcpguard.patch",
                    "parts": [A2APart(text=chunk_1).to_dict()],
                },
                "append": False,
                "lastChunk": False,
            },
        }

        yield {
            "event": "TaskArtifactUpdateEvent",
            "data": {
                "taskId": task_id,
                "contextId": context_id,
                "artifact": {
                    "artifactId": f"{task_id}-hardened-patch",
                    "name": "hardened_mcpguard.patch",
                    "parts": [A2APart(text=chunk_2).to_dict()],
                },
                "append": True,
                "lastChunk": True,
            },
        }

        yield {
            "event": "TaskArtifactUpdateEvent",
            "data": {
                "taskId": task_id,
                "contextId": context_id,
                "artifact": {
                    "artifactId": f"{task_id}-adk-regression-test",
                    "name": "mcpguard_regression.test.json",
                    "parts": [A2APart(data=test_fixture).to_dict()],
                },
                "append": False,
                "lastChunk": True,
            },
        }

        self._tasks[task_id]["artifacts"] = [
            {"artifactId": f"{task_id}-hardened-patch", "name": "hardened_mcpguard.patch"},
            {"artifactId": f"{task_id}-adk-regression-test", "name": "mcpguard_regression.test.json"},
        ]
        self.transition_state(task_id, TaskState.TASK_STATE_COMPLETED)
        yield {
            "event": "TaskStatusUpdateEvent",
            "data": {
                "taskId": task_id,
                "contextId": context_id,
                "status": {"state": TaskState.TASK_STATE_COMPLETED.value},
                "final": True,
            },
        }


class TaskPushNotificationVerifier:
    """Protects `TaskPushNotificationConfig` webhooks against SSRF, forged JWTs, and `jti` replay."""

    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self.allowed_domains = {
            d.strip().lower()
            for d in (allowed_domains or ["ci.example.com", "hooks.internal.example.org"])
            if d.strip()
        }
        self._seen_jtis: dict[str, float] = {}

    def validate_webhook_url(self, url: str) -> tuple[bool, dict[str, Any] | None]:
        """Enforce HTTPS, reject private/loopback/link-local IPs (SSRF guard), and check allowlist."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False, build_a2a_error_status(
                code=3,
                message="TaskPushNotificationConfig webhook URL must use HTTPS.",
                reason="WEBHOOK_INSECURE_SCHEME",
                metadata={"url": url},
            )
        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname in {"localhost", "127.0.0.1", "::1", "169.254.169.254", "metadata.google.internal"}:
            return False, build_a2a_error_status(
                code=7,
                message="Webhook target blocked by SSRF loopback/metadata guard.",
                reason="WEBHOOK_SSRF_BLOCKED",
                metadata={"hostname": hostname},
            )
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False, build_a2a_error_status(
                    code=7,
                    message="Webhook IP literal blocked by SSRF private-network guard.",
                    reason="WEBHOOK_SSRF_PRIVATE_IP",
                    metadata={"ip": hostname},
                )
        except ValueError:
            pass

        if hostname not in self.allowed_domains:
            return False, build_a2a_error_status(
                code=7,
                message=f"Webhook domain '{hostname}' is not in the configured allowlist.",
                reason="WEBHOOK_DOMAIN_NOT_ALLOWLISTED",
                metadata={"hostname": hostname},
            )
        return True, None

    def verify_signed_webhook_jwt(
        self,
        token: str,
        jwks: dict[str, Any],
        expected_audience: str | None = None,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Cryptographically verify asymmetric `EdDSA` JWT signature, `exp`, `aud`, and `jti` uniqueness."""
        parts = token.split(".")
        if len(parts) != 3:
            return False, build_a2a_error_status(
                code=16, message="Malformed JWT compact serialization.", reason="JWT_MALFORMED"
            )
        h_b64, p_b64, s_b64 = parts
        try:
            header = json.loads(_b64url_decode(h_b64).decode("utf-8"))
            claims = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        except Exception:
            return False, build_a2a_error_status(
                code=16, message="Invalid base64url JSON in JWT.", reason="JWT_DECODE_ERROR"
            )

        if header.get("alg") != "EdDSA":
            return False, build_a2a_error_status(
                code=16, message="Webhook JWT must use asymmetric EdDSA.", reason="JWT_UNSUPPORTED_ALG"
            )

        kid = header.get("kid")
        jwk = next(
            (
                k
                for k in jwks.get("keys", [])
                if k.get("kid") == kid and k.get("kty") == "OKP" and k.get("crv") == "Ed25519"
            ),
            None,
        )
        if not jwk:
            return False, build_a2a_error_status(
                code=16, message=f"Unknown signing key kid='{kid}'.", reason="JWT_UNKNOWN_KID"
            )

        try:
            pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
            pub.verify(_b64url_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
        except InvalidSignature:
            return False, build_a2a_error_status(
                code=16, message="JWT cryptographic signature verification failed.", reason="JWT_INVALID_SIGNATURE"
            )

        now = time.time()
        if "exp" in claims and float(claims["exp"]) < now:
            return False, build_a2a_error_status(
                code=16, message="Webhook JWT has expired.", reason="JWT_EXPIRED"
            )
        if expected_audience and claims.get("aud") != expected_audience:
            return False, build_a2a_error_status(
                code=16, message="Webhook JWT audience mismatch.", reason="JWT_AUDIENCE_MISMATCH"
            )

        return self.verify_jwt_jti_replay(claims)

    def verify_jwt_jti_replay(self, jwt_claims: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
        """Validate `jti` claim uniqueness to block webhook token replay attacks."""
        jti = str(jwt_claims.get("jti", "")).strip()
        if not jti:
            return False, build_a2a_error_status(
                code=16,
                message="Missing `jti` replay-protection claim in webhook JWT.",
                reason="JWT_MISSING_JTI",
            )
        if jti in self._seen_jtis:
            return False, build_a2a_error_status(
                code=16,
                message=f"Replayed webhook JWT detected (`jti={jti}`).",
                reason="JWT_REPLAY_DETECTED",
                metadata={"jti": jti},
            )
        self._seen_jtis[jti] = time.time()
        return True, None
