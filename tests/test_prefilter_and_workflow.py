"""Tests for ADK 2.0 Hybrid Graph, MCP JSON-RPC Stdio Server, Stage 5 Patch Writer, and Voice Debrief."""

from __future__ import annotations

import io
import json
from pathlib import Path

from mcpguard_adk.agent import (
    MCPGuardGraphWorkflow,
    readonly_filesystem_mcp_toolset,
    root_agent,
    to_mcp_server,
)
from mcpguard_adk.agents.voice_debrief import LiveVoiceDebriefSession
from mcpguard_adk.nodes.prefilter import run_manifest_and_ast_prefilter
from mcpguard_adk.nodes.triage_router import run_triage_router_node
from mcpguard_adk.schemas import RouteDecision


def test_stage_1_prefilter_skips_clean_files_with_zero_tokens() -> None:
    clean_dir = Path(__file__).resolve().parent.parent / "examples" / "clean_manifest"
    res = run_manifest_and_ast_prefilter(clean_dir)
    assert res.llm_tokens_consumed == 0
    assert res.is_clean is True
    assert len(res.skipped_clean_files) == 1

    triage = run_triage_router_node(res)
    assert triage.routes == [RouteDecision.DEFAULT_ROUTE]
    assert triage.input_tokens == 0
    assert triage.output_tokens == 0


def test_stage_1_and_full_graph_workflow_and_hitl_patch_writing(tmp_path: Path) -> None:
    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    wf = MCPGuardGraphWorkflow()

    # 1. When hitl_approved=False, patch is previewed in memory but NOT written to disk
    unapproved_patch_path = tmp_path / "should_not_exist.patch"
    report_paused = wf.run(examples_dir, hitl_approved=False, patch_output_path=unapproved_patch_path)
    assert not unapproved_patch_path.exists()
    assert report_paused.written_patch_path is None

    rule_ids = {f.rule_id for f in report_paused.findings}
    assert {
        "MCPG-SEC-001",
        "MCPG-SEC-002",
        "MCPG-SEC-003",
        "MCPG-SEC-004",
        "MCPG-ADK-001",
        "MCPG-ADK-002",
        "MCPG-COST-001",
    }.issubset(rule_ids)

    # 2. When hitl_approved=True, Stage 5 writes a valid unified diff `.patch` file to disk
    approved_patch_path = tmp_path / "hardened_remediation.patch"
    report_approved = wf.run(examples_dir, hitl_approved=True, patch_output_path=approved_patch_path)
    assert approved_patch_path.is_file()
    assert report_approved.written_patch_path == str(approved_patch_path.resolve())
    assert "@modelcontextprotocol/server-filesystem@2026.11.1" in approved_patch_path.read_text(encoding="utf-8")


def test_real_mcp_jsonrpc_stdio_server_protocol() -> None:
    mcp_srv = to_mcp_server()
    assert mcp_srv.server_name == "mcpguard-adk"

    examples_dir = str((Path(__file__).resolve().parent.parent / "examples").resolve())
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "mcpguard_audit_repository",
                "arguments": {"target_path": examples_dir, "hitl_approved": False},
            },
        },
    ]
    in_buf = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    out_buf = io.StringIO()

    mcp_srv.serve_stdio(stdin=in_buf, stdout=out_buf)
    responses = [json.loads(line) for line in out_buf.getvalue().splitlines() if line.strip()]

    # Notification produces no response, so 3 responses expected for ids 1, 2, 3
    assert len(responses) == 3
    assert responses[0]["result"]["protocolVersion"] == "2024-11-05"
    tool_names = [t["name"] for t in responses[1]["result"]["tools"]]
    assert "mcpguard_audit_repository" in tool_names
    call_result = json.loads(responses[2]["result"]["content"][0]["text"])
    assert call_result["findings_count"] == 8
    assert len(call_result["otel_trace_id"]) == 32


def test_synchronous_mcp_toolset_and_stage_6_voice_debrief() -> None:
    assert readonly_filesystem_mcp_toolset.initialized_synchronously is True
    assert readonly_filesystem_mcp_toolset.tool_filter == ["list_directory", "read_file"]
    for tool in root_agent.tools:
        assert getattr(tool, "isolated_context", False) is True

    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    report = MCPGuardGraphWorkflow().run(examples_dir, hitl_approved=False)
    session = LiveVoiceDebriefSession(report)
    session.request_queue.send_interrupt("What is the 1,000-PR cost savings?")
    session.request_queue.close()

    events = list(session.iter_live_events())
    assert any(e["event"] == "barge_in_interrupted" and e["interrupted"] is True for e in events)
