"""Real Model Context Protocol (MCP) JSON-RPC 2.0 Stdio Server (`to_mcp_server`).

Allows AI IDEs (Google Antigravity, Gemini CLI, Cursor, VS Code, Claude Desktop) to mount
the entire MCPGuard-ADK multi-agent workflow as a single MCP tool endpoint via:
`python -m mcpguard_adk.cli serve-mcp`

Supported JSON-RPC 2.0 MCP methods:
- `initialize` (returns MCP protocol version `2024-11-05` & tool capabilities)
- `notifications/initialized`
- `ping`
- `tools/list`
- `tools/call` (`mcpguard_audit_repository`, `mcpguard_simulate_cost_cliff`, `mcpguard_verify_agent_card`)
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, TextIO

from mcpguard_adk.a2a.protocol import (
    DEFAULT_SERVER_KEYPAIR,
    build_signed_agent_card,
    verify_agent_card_jws,
)
from mcpguard_adk.cost_engine import simulate_pr_audit_benchmarks


class MCPStdioServer:
    """Spec-compliant JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio."""

    def __init__(self, audit_handler: Callable[..., Any]) -> None:
        self.server_name = "mcpguard-adk"
        self.version = "0.3.0"
        self.protocol_version = "2024-11-05"
        self._audit_handler = audit_handler

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "mcpguard_audit_repository",
                "description": (
                    "Audits MCP server configs, dependencies, Python ADK graphs, and React/TS code "
                    "for supply-chain risks and >200K Gemini token cost cliffs; returns findings, "
                    "hardened unified diff patches, and ADK .test.json fixtures."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {
                            "type": "string",
                            "description": "Directory or file path to audit.",
                        },
                        "hitl_approved": {
                            "type": "boolean",
                            "default": False,
                            "description": "Approve Stage 5 HITL gate to write patch artifacts.",
                        },
                        "git_diff_only": {
                            "type": "boolean",
                            "default": False,
                            "description": "Scan only files modified in git working tree/index.",
                        },
                    },
                    "required": ["target_path"],
                },
            },
            {
                "name": "mcpguard_simulate_cost_cliff",
                "description": (
                    "Simulates Late-2026 Gemini API & Vertex AI rate-card spend across N pull-request "
                    "audits (>200K Pro cliff vs ADK 2.0 hybrid routing)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pr_count": {"type": "integer", "default": 1000, "minimum": 1}
                    },
                },
            },
            {
                "name": "mcpguard_verify_agent_card",
                "description": (
                    "Generates or verifies an A2A Protocol v1.0 AgentCard signed with Ed25519 (EdDSA) "
                    "and RFC 8785 JSON Canonicalization Scheme (JCS)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "default": "http://localhost:8080"}
                    },
                },
            },
        ]

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC 2.0 MCP request or notification and return response (or None)."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params") or {}

        # JSON-RPC Notifications (no `id` field) do not return a response frame
        if msg_id is None and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": self.server_name, "version": self.version},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.list_tools()}}

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments") or {}
            try:
                if tool_name == "mcpguard_audit_repository":
                    report = self._audit_handler(
                        target_path=args.get("target_path", "."),
                        hitl_approved=bool(args.get("hitl_approved", False)),
                        git_diff_only=bool(args.get("git_diff_only", False)),
                    )
                    payload = {
                        "target_path": report.target_path,
                        "findings_count": len(report.findings),
                        "findings": [f.model_dump() for f in report.findings],
                        "unified_diff_patch": report.unified_diff_patch,
                        "otel_trace_id": report.otel_trace_id,
                        "cost_summary": report.cost_summary.model_dump(),
                    }
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                            "isError": False,
                        },
                    }

                if tool_name == "mcpguard_simulate_cost_cliff":
                    sim = simulate_pr_audit_benchmarks(pr_count=int(args.get("pr_count", 1000)))
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(sim.model_dump(), indent=2)}],
                            "isError": False,
                        },
                    }

                if tool_name == "mcpguard_verify_agent_card":
                    card = build_signed_agent_card(
                        base_url=str(args.get("base_url", "http://localhost:8080")),
                        keypair=DEFAULT_SERVER_KEYPAIR,
                    )
                    jwks = DEFAULT_SERVER_KEYPAIR.public_jwks()
                    verified = verify_agent_card_jws(card, jwks)
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        {"eddsa_jcs_verified": verified, "agent_card": card, "jwks": jwks},
                                        indent=2,
                                    ),
                                }
                            ],
                            "isError": False,
                        },
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": f"Unknown MCP tool: {tool_name}"},
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"MCP tool execution error: {exc}"}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(
        self,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        """Run JSON-RPC 2.0 stdio transport supporting both newline-delimited & Content-Length frames."""
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout

        while True:
            raw_line = in_stream.readline()
            if not raw_line:
                break
            stripped = raw_line.strip()
            if not stripped:
                continue

            use_content_length = False
            if stripped.lower().startswith("content-length:"):
                use_content_length = True
                length = int(stripped.split(":", 1)[1].strip())
                # Consume blank header separator line
                while True:
                    hdr = in_stream.readline()
                    if not hdr or hdr.strip() == "":
                        break
                body_str = in_stream.read(length)
            else:
                body_str = stripped

            try:
                msg = json.loads(body_str)
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                continue

            resp = self.handle_jsonrpc_message(msg)
            if resp is not None:
                encoded = json.dumps(resp)
                if use_content_length:
                    byte_len = len(encoded.encode("utf-8"))
                    out_stream.write(f"Content-Length: {byte_len}\r\n\r\n{encoded}")
                else:
                    out_stream.write(encoded + "\n")
                out_stream.flush()
