"""Command-Line Interface (`mcpguard`) for MCPGuard-ADK.

Commands:
- `mcpguard scan [path] [--git-diff] [--live] [--approve-patches] [--emit-test-json PATH] [--emit-sarif PATH] [--export-otel PATH] [--json]`
- `mcpguard serve-mcp`      (Starts live JSON-RPC 2.0 MCP Stdio server for Cursor / Antigravity / Gemini CLI)
- `mcpguard serve-a2a`      (Starts A2A Protocol v1.0 HTTP+JSON & SSE server with `/.well-known/jwks.json`)
- `mcpguard agent-card`     (Prints & cryptographically verifies Ed25519/JCS signed A2A v1.0 AgentCard)
- `mcpguard cost-sim`       (Runs transparent Late-2026 Gemini rate-card FinOps simulation)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcpguard_adk.a2a.protocol import (
    DEFAULT_SERVER_KEYPAIR,
    build_signed_agent_card,
    verify_agent_card_jws,
)
from mcpguard_adk.a2a.server import run_a2a_http_server
from mcpguard_adk.agent import MCPGuardGraphWorkflow, to_mcp_server
from mcpguard_adk.agents.voice_debrief import LiveVoiceDebriefSession
from mcpguard_adk.cost_engine import simulate_pr_audit_benchmarks
from mcpguard_adk.sarif import build_sarif_report
from mcpguard_adk.schemas import AuditReport, FindingSeverity
from mcpguard_adk.tui import render_rich_audit_report, run_interactive_terminal_repl
from mcpguard_adk.web_studio import generate_studio_html, serve_studio_ui


def _run_interactive_voice_debrief_demo(report: AuditReport) -> list[dict[str, str | bool]]:
    session = LiveVoiceDebriefSession(report)
    session.request_queue.send_interrupt(
        "Hold on—what is the exact 1,000-PR cost savings vs Gemini 3.1 Pro?"
    )
    session.request_queue.close()
    return list(session.iter_live_events())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="MCPGuard-ADK: Multi-agent MCP supply-chain, >200K token cost-cliff, and tool-trajectory auditor.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # `mcpguard scan`
    scan_p = subparsers.add_parser("scan", help="Scan a repository or directory for MCP and ADK cost-cliff risks.")
    scan_p.add_argument("target", nargs="?", default="./examples", help="Target path to scan (default: ./examples)")
    scan_p.add_argument("--git-diff", action="store_true", help="Scan only modified/untracked files in Git working tree.")
    scan_p.add_argument("--approve-patches", action="store_true", help="Approve Stage 5 HITL gate to write `reports/hardened_remediation.patch`.")
    scan_p.add_argument("--emit-test-json", type=str, default="", help="Write generated ADK .test.json regression fixture to path.")
    scan_p.add_argument("--emit-sarif", type=str, default="", help="Write SARIF v2.1.0 report for GitHub Code Scanning.")
    scan_p.add_argument("--emit-dashboard", type=str, default="", help="Write standalone Google Material 3 HTML Studio dashboard.")
    scan_p.add_argument("--export-otel", type=str, default="", help="Export OTLP/JSON `resourceSpans` trace file for Jaeger/Cloud Trace.")
    scan_p.add_argument("--live", action="store_true", help="Launch Stage 6 ADK Live Voice Incident Debrief (`runner.run_live()`).")
    scan_p.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium"],
        default="none",
        help="Return non-zero exit code (2) in CI when findings meet or exceed severity threshold.",
    )
    scan_p.add_argument("--json", action="store_true", help="Output full AuditReport as JSON.")

    # `mcpguard serve-mcp`
    subparsers.add_parser("serve-mcp", help="Run JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio.")

    # `mcpguard cost-sim`
    cost_p = subparsers.add_parser("cost-sim", help="Run transparent Late-2026 Gemini rate-card cost simulation.")
    cost_p.add_argument("--prs", type=int, default=1000, help="Number of pull-request audits to simulate (default: 1000).")

    # `mcpguard agent-card`
    card_p = subparsers.add_parser("agent-card", help="Print & verify Ed25519 (EdDSA) + RFC 8785 (JCS) signed A2A v1.0 AgentCard.")
    card_p.add_argument("--jwks", action="store_true", help="Include public Ed25519 JWKS alongside the signed AgentCard.")

    # `mcpguard serve-a2a`
    a2a_p = subparsers.add_parser("serve-a2a", help="Start A2A Protocol v1.0 HTTP + SSE server.")
    a2a_p.add_argument("--host", type=str, default="127.0.0.1")
    a2a_p.add_argument("--port", type=int, default=8080)

    # `mcpguard ui`
    ui_p = subparsers.add_parser("ui", help="Launch interactive Google Material 3 / ADK 2.0 Web Studio in browser.")
    ui_p.add_argument("target", nargs="?", default="./examples", help="Target path to scan and visualize.")
    ui_p.add_argument("--host", type=str, default="127.0.0.1")
    ui_p.add_argument("--port", type=int, default=8090)
    ui_p.add_argument("--no-open", action="store_true", help="Do not auto-open browser window.")

    # `mcpguard shell` (Claude Code / Gemini CLI style interactive slash-command REPL)
    subparsers.add_parser("shell", help="Launch interactive Gemini CLI / Claude Code style terminal shell.")

    args = parser.parse_args(argv)

    if args.command == "serve-mcp":
        mcp_server = to_mcp_server()
        mcp_server.serve_stdio()
        return 0

    if args.command == "cost-sim":
        summary = simulate_pr_audit_benchmarks(pr_count=args.prs)
        print(json.dumps(summary.model_dump(), indent=2))
        return 0

    if args.command == "agent-card":
        card = build_signed_agent_card(keypair=DEFAULT_SERVER_KEYPAIR)
        jwks = DEFAULT_SERVER_KEYPAIR.public_jwks()
        verified = verify_agent_card_jws(card, jwks)
        if getattr(args, "jwks", False):
            print(json.dumps({"verified": verified, "agentCard": card, "jwks": jwks}, indent=2))
        else:
            print(json.dumps(card, indent=2))
        return 0 if verified else 1

    if args.command == "serve-a2a":
        run_a2a_http_server(host=args.host, port=args.port)
        return 0

    if args.command == "ui":
        report = MCPGuardGraphWorkflow().run(target_path=args.target, hitl_approved=False)
        serve_studio_ui(report, host=args.host, port=args.port, open_browser=not args.no_open)
        return 0

    def _quick_scan(path_str: str, approve_flag: bool, live_flag: bool) -> int:
        rep = MCPGuardGraphWorkflow().run(target_path=path_str, hitl_approved=approve_flag)
        ev = _run_interactive_voice_debrief_demo(rep) if live_flag else None
        print(render_rich_audit_report(rep, live_events=ev))
        return 0

    if args.command == "shell" or (args.command is None and sys.stdin.isatty() and argv is None):
        return run_interactive_terminal_repl(_quick_scan)

    # Default or `scan`
    target = getattr(args, "target", "./examples")
    if not Path(target).exists():
        print(f"Error: Target path '{target}' does not exist.", file=sys.stderr)
        return 1
    git_diff_only = getattr(args, "git_diff", False)
    approve = getattr(args, "approve_patches", False)
    emit_test_path = getattr(args, "emit_test_json", "")
    emit_sarif_path = getattr(args, "emit_sarif", "")
    emit_dashboard_path = getattr(args, "emit_dashboard", "")
    export_otel_path = getattr(args, "export_otel", "")
    live_mode = getattr(args, "live", False)
    as_json = getattr(args, "json", False)

    workflow = MCPGuardGraphWorkflow()
    report = workflow.run(
        target_path=target,
        hitl_approved=approve,
        git_diff_only=git_diff_only,
    )

    if emit_test_path:
        out_path = Path(emit_test_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.generated_test_fixture, indent=2), encoding="utf-8")

    if emit_sarif_path:
        sarif_path = Path(emit_sarif_path)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(build_sarif_report(report), indent=2), encoding="utf-8")

    if export_otel_path:
        otel_path = Path(export_otel_path)
        otel_path.parent.mkdir(parents=True, exist_ok=True)
        otel_path.write_text(json.dumps(report.otlp_trace_export, indent=2), encoding="utf-8")

    if emit_dashboard_path:
        dash_path = Path(emit_dashboard_path)
        dash_path.parent.mkdir(parents=True, exist_ok=True)
        dash_path.write_text(generate_studio_html(report), encoding="utf-8")

    live_events = _run_interactive_voice_debrief_demo(report) if live_mode else None

    if as_json:
        print(json.dumps(report.model_dump(), indent=2))
    else:
        print(render_rich_audit_report(report, live_events=live_events))

    fail_on = getattr(args, "fail_on", "none")
    if fail_on != "none":
        threshold_map = {
            "critical": {FindingSeverity.CRITICAL},
            "high": {FindingSeverity.CRITICAL, FindingSeverity.HIGH},
            "medium": {FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM},
        }
        blocking = threshold_map.get(fail_on, set())
        if any(f.severity in blocking for f in report.findings):
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
