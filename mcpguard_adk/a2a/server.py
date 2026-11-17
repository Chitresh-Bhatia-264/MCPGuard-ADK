"""Production HTTP+JSON & SSE Server for A2A Protocol v1.0 Interoperability.

Exposes:
- `GET  /.well-known/agent-card.json` (RFC 8785 JCS + Ed25519 `EdDSA` signed AgentCard)
- `GET  /.well-known/jwks.json`       (Public RFC 8037 Ed25519 JWKS for signature verification)
- `POST /a2a/v1`                      (`message/send`, `tasks/get`, `tasks/cancel`, `tasks/pushNotificationConfig/set`)
- `POST /a2a/v1/stream`               (`SendStreamingMessage` over HTTP Server-Sent Events)
"""

from __future__ import annotations

import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from mcpguard_adk.a2a.protocol import (
    DEFAULT_SERVER_KEYPAIR,
    A2APart,
    A2ATaskManager,
    TaskPushNotificationVerifier,
    TaskState,
    build_a2a_error_status,
    build_signed_agent_card,
)
from mcpguard_adk.agent import MCPGuardGraphWorkflow


class A2AV1RequestHandler(BaseHTTPRequestHandler):
    workflow = MCPGuardGraphWorkflow()
    task_manager = A2ATaskManager()
    webhook_verifier = TaskPushNotificationVerifier(
        allowed_domains=os.environ.get(
            "MCPGUARD_A2A_WEBHOOK_ALLOWED_DOMAINS",
            "ci.example.com,hooks.internal.example.org",
        ).split(",")
    )

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/.well-known/agent-card.json"):
            host = self.headers.get("Host", "localhost:8080")
            card = build_signed_agent_card(base_url=f"http://{host}", keypair=DEFAULT_SERVER_KEYPAIR)
            self._send_json(200, card)
            return

        if self.path.startswith("/.well-known/jwks.json"):
            self._send_json(200, DEFAULT_SERVER_KEYPAIR.public_jwks())
            return

        self._send_json(
            404,
            build_a2a_error_status(404, f"Unknown endpoint '{self.path}'.", "ENDPOINT_NOT_FOUND"),
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload: dict[str, Any] = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(
                400, build_a2a_error_status(3, "Invalid JSON request body.", "INVALID_JSON")
            )
            return

        if self.path.startswith("/a2a/v1/stream"):
            target_path = payload.get("target_path", "./examples")
            task_id = payload.get("taskId", f"task-{uuid.uuid4().hex[:8]}")
            context_id = payload.get("contextId", f"ctx-{uuid.uuid4().hex[:8]}")
            ref_ids = payload.get("referenceTaskIds", [])

            report = self.workflow.run(target_path=target_path, hitl_approved=False)

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            for event in self.task_manager.stream_audit_execution(
                task_id=task_id,
                context_id=context_id,
                unified_diff=report.unified_diff_patch,
                test_fixture=report.generated_test_fixture,
                reference_task_ids=ref_ids,
            ):
                sse_frame = f"event: {event['event']}\ndata: {json.dumps(event['data'])}\n\n"
                self.wfile.write(sse_frame.encode("utf-8"))
                self.wfile.flush()
            return

        if self.path.rstrip("/") == "/a2a/v1":
            method = payload.get("method", "message/send")
            params = payload.get("params", payload)

            if method == "tasks/get":
                res = self.task_manager.get_task(str(params.get("id", "")))
                self._send_json(404 if "error" in res else 200, res)
                return

            if method == "tasks/cancel":
                res = self.task_manager.transition_state(
                    str(params.get("id", "")), TaskState.TASK_STATE_CANCELED
                )
                self._send_json(400 if "error" in res else 200, res)
                return

            if method == "tasks/pushNotificationConfig/set":
                webhook_url = str(params.get("url", ""))
                ok, err = self.webhook_verifier.validate_webhook_url(webhook_url)
                if not ok and err:
                    self._send_json(403, err)
                    return
                jwt_tok = params.get("token")
                if jwt_tok:
                    tok_ok, tok_err = self.webhook_verifier.verify_signed_webhook_jwt(
                        str(jwt_tok), DEFAULT_SERVER_KEYPAIR.public_jwks()
                    )
                    if not tok_ok and tok_err:
                        self._send_json(401, tok_err)
                        return
                self._send_json(200, {"status": "CONFIGURED", "url": webhook_url})
                return

            # Default `message/send` synchronous A2A v1.0 execution
            target_path = params.get("target_path", "./examples")
            task_id = params.get("taskId", f"task-{uuid.uuid4().hex[:8]}")
            context_id = params.get("contextId", f"ctx-{uuid.uuid4().hex[:8]}")
            report = self.workflow.run(target_path=target_path, hitl_approved=False)
            self.task_manager.create_task(task_id=task_id, context_id=context_id)
            self.task_manager.transition_state(task_id, TaskState.TASK_STATE_COMPLETED)
            self._send_json(
                200,
                {
                    "id": task_id,
                    "contextId": context_id,
                    "status": {"state": TaskState.TASK_STATE_COMPLETED.value},
                    "artifacts": [
                        {
                            "artifactId": f"{task_id}-report",
                            "name": "audit_summary.json",
                            "parts": [
                                A2APart(
                                    data={
                                        "findings_count": len(report.findings),
                                        "otel_trace_id": report.otel_trace_id,
                                        "cost_summary": report.cost_summary.model_dump(),
                                    }
                                ).to_dict()
                            ],
                        },
                        {
                            "artifactId": f"{task_id}-patch",
                            "name": "hardened.patch",
                            "parts": [A2APart(text=report.unified_diff_patch).to_dict()],
                        },
                    ],
                },
            )
            return

        self._send_json(
            404,
            build_a2a_error_status(404, f"Unknown endpoint '{self.path}'.", "ENDPOINT_NOT_FOUND"),
        )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


def run_a2a_http_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), A2AV1RequestHandler)
    print(f"MCPGuard-ADK A2A v1.0 Server listening on http://{host}:{port}")
    print(f"Signed AgentCard (EdDSA/JCS): http://{host}:{port}/.well-known/agent-card.json")
    print(f"Public Ed25519 JWKS         : http://{host}:{port}/.well-known/jwks.json")
    server.serve_forever()
