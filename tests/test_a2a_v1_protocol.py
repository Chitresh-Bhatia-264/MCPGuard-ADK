"""Tests for A2A Protocol v1.0 Ed25519/JCS Cryptography, SSE Streaming, and Asymmetric JWT Security."""

from __future__ import annotations

import copy
import time

import pytest

from mcpguard_adk.a2a.protocol import (
    A2AKeyPair,
    A2APart,
    A2ATaskManager,
    TaskPushNotificationVerifier,
    TaskState,
    build_signed_agent_card,
    verify_agent_card_jws,
)


def test_ed25519_jcs_signed_agent_card_and_tamper_detection() -> None:
    kp = A2AKeyPair.from_env_or_ephemeral(kid="test-ed25519-key")
    card = build_signed_agent_card(base_url="https://mcpguard.example.com", keypair=kp)
    jwks = kp.public_jwks()

    # 1. Must NOT contain deprecated v0.3 top-level `supportsExtendedAgentCard`
    assert "supportsExtendedAgentCard" not in card
    # 2. Capabilities & v1.0 interfaces
    caps = card["capabilities"]
    assert caps["streaming"] is True
    assert caps["pushNotifications"] is True
    assert caps["extendedAgentCard"] is True
    assert all(iface["protocolVersion"] == "1.0" for iface in card["supportedInterfaces"])

    # 3. Cryptographic Ed25519 (`EdDSA`) signature must verify mathematically against public JWKS
    assert card["signatures"][0]["header"]["alg"] == "EdDSA"
    assert verify_agent_card_jws(card, jwks) is True

    # 4. Tampering with ANY field in the AgentCard must invalidate the Ed25519 JCS signature
    tampered = copy.deepcopy(card)
    tampered["description"] = "Tampered by MITM attacker"
    assert verify_agent_card_jws(tampered, jwks) is False

    # 5. Verifying against a different keypair's JWKS must fail
    wrong_kp = A2AKeyPair.from_env_or_ephemeral(kid="test-ed25519-key")
    assert verify_agent_card_jws(card, wrong_kp.public_jwks()) is False


def test_unified_part_member_oneof_rejects_legacy_or_multi_fields() -> None:
    text_part = A2APart(text="Hello A2A v1.0").to_dict()
    assert text_part == {"text": "Hello A2A v1.0"}
    assert "kind" not in text_part

    data_part = A2APart(data={"rule": "MCPG-SEC-001"}).to_dict()
    assert data_part == {"data": {"rule": "MCPG-SEC-001"}}
    assert "kind" not in data_part

    with pytest.raises(ValueError):
        A2APart(text="both", url="https://example.com")


def test_immutable_terminal_states_and_sse_streaming() -> None:
    mgr = A2ATaskManager()
    events = list(
        mgr.stream_audit_execution(
            task_id="task-101",
            context_id="ctx-2026",
            unified_diff="--- a/mcp.json\n+++ b/mcp.json\n@@ -1 +1 @@\n-/\n+./workspace",
            test_fixture={"eval_set_id": "test_1"},
            reference_task_ids=["task-100"],
        )
    )
    assert events[0]["event"] == "TaskStatusUpdateEvent"
    artifact_events = [e for e in events if e["event"] == "TaskArtifactUpdateEvent"]
    assert len(artifact_events) == 3
    assert artifact_events[0]["data"]["append"] is False
    assert artifact_events[0]["data"]["lastChunk"] is False
    assert artifact_events[1]["data"]["append"] is True
    assert artifact_events[1]["data"]["lastChunk"] is True
    assert events[-1]["data"]["status"]["state"] == "TASK_STATE_COMPLETED"

    err = mgr.transition_state("task-101", TaskState.TASK_STATE_WORKING)
    assert "error" in err
    details = err["error"]["details"][0]
    assert details["@type"] == "type.googleapis.com/google.rpc.ErrorInfo"
    assert details["domain"] == "a2a-protocol.org"
    assert details["reason"] == "IMMUTABLE_TERMINAL_STATE_VIOLATION"


def test_webhook_ssrf_and_asymmetric_eddsa_jwt_replay_protection() -> None:
    kp = A2AKeyPair.from_env_or_ephemeral(kid="webhook-key-1")
    jwks = kp.public_jwks()
    verifier = TaskPushNotificationVerifier(allowed_domains=["ci.example.com"])

    # SSRF protections (HTTP, loopback, GCP/AWS metadata endpoints)
    assert verifier.validate_webhook_url("http://ci.example.com/hook")[0] is False
    assert verifier.validate_webhook_url("https://127.0.0.1/hook")[0] is False
    assert verifier.validate_webhook_url("https://169.254.169.254/latest/meta-data/")[0] is False
    assert verifier.validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/")[0] is False
    assert verifier.validate_webhook_url("https://ci.example.com/a2a/webhook")[0] is True

    # Real Ed25519 signed JWT verification + replay protection
    valid_jwt = kp.issue_signed_jwt(
        {"jti": "unique-jti-001", "aud": "mcpguard-a2a", "exp": time.time() + 300}
    )
    ok_first, err_first = verifier.verify_signed_webhook_jwt(
        valid_jwt, jwks, expected_audience="mcpguard-a2a"
    )
    assert ok_first is True and err_first is None

    # Replay of exact same signed JWT must be blocked via `jti` cache
    ok_replay, err_replay = verifier.verify_signed_webhook_jwt(
        valid_jwt, jwks, expected_audience="mcpguard-a2a"
    )
    assert ok_replay is False
    assert err_replay["error"]["details"][0]["reason"] == "JWT_REPLAY_DETECTED"

    # Forged signature from attacker keypair must fail cryptographic verification
    attacker_kp = A2AKeyPair.from_env_or_ephemeral(kid="webhook-key-1")
    forged_jwt = attacker_kp.issue_signed_jwt(
        {"jti": "unique-jti-002", "aud": "mcpguard-a2a", "exp": time.time() + 300}
    )
    ok_forged, err_forged = verifier.verify_signed_webhook_jwt(forged_jwt, jwks)
    assert ok_forged is False
    assert err_forged["error"]["details"][0]["reason"] == "JWT_INVALID_SIGNATURE"
