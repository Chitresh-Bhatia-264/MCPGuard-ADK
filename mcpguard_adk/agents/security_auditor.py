"""Stage 3: Context-Isolated Security & MCP Auditor Sub-Agent.

Wrapped via `AgentTool` with synchronous `McpToolset` (`StdioConnectionParams` wrapping
`StdioServerParameters` and `tool_filter=["list_directory", "read_file"]`) so raw file
blobs and >20 tool schemas never pollute the root orchestrator's context window.
Records exact billed tokens when `GEMINI_API_KEY` is active, and honest `0` billed tokens
when running in offline deterministic mode.
"""

from __future__ import annotations

import os
from typing import Any

from mcpguard_adk.llm_client import call_gemini_generate_content
from mcpguard_adk.schemas import AuditFinding, FindingCategory

SECURITY_AUDITOR_INSTRUCTION = """You are the MCPGuard-ADK Stage 3 Security & MCP Supply-Chain Auditor.
You operate inside an isolated `AgentTool` context window with read-only `McpToolset`
(`tool_filter=["list_directory", "read_file"]`).
Inspect MCP server manifests, filesystem scopes, unpinned `npx -y` dependencies,
plaintext environment credentials, and prompt-injection surfaces in tool metadata.
Return concise, structured remediation guidance without dumping raw file blobs into parent context.
"""


def run_security_and_mcp_auditor(
    findings: list[AuditFinding],
    escalate_to_pro: bool = False,
) -> tuple[list[AuditFinding], dict[str, Any]]:
    """Run Stage 3 isolated security audit and enrich security findings."""
    preferred_model = (
        os.environ.get("MCPGUARD_ESCALATION_MODEL", "gemini-3.1-pro-preview")
        if escalate_to_pro
        else os.environ.get("MCPGUARD_AUDIT_MODEL", "gemini-3.8-flash")
    )

    security_categories = {
        FindingCategory.MCP_OVERBROAD_SCOPE,
        FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
        FindingCategory.MCP_SECRET_EXPOSURE,
        FindingCategory.MCP_PROMPT_INJECTION_SURFACE,
        FindingCategory.MCP_ASYNC_RUNTIME_INIT,
    }
    targeted = [f for f in findings if f.category in security_categories]

    in_tokens = 0
    out_tokens = 0
    execution_mode = "offline_deterministic"
    resolved_model = preferred_model
    live_summary = ""

    if targeted:
        compact_summary = "\n".join(
            f"- [{f.rule_id}] {f.title} ({f.file_path}:{f.line_number})" for f in targeted[:15]
        )
        api_res = call_gemini_generate_content(
            preferred_model=preferred_model,
            system_instruction=SECURITY_AUDITOR_INSTRUCTION,
            user_prompt=f"Provide a concise 2-sentence security remediation priority for:\n{compact_summary}",
        )
        execution_mode = str(api_res["execution_mode"])
        resolved_model = str(api_res["resolved_model"])
        if api_res["live_api_called"]:
            in_tokens = int(api_res["input_tokens"])
            out_tokens = int(api_res["output_tokens"])
            live_summary = str(api_res["text"])

    telemetry = {
        "sub_agent": "security_and_mcp_auditor",
        "model": resolved_model,
        "execution_mode": execution_mode,
        "live_gemini_summary": live_summary,
        "isolated_via_agent_tool": True,
        "mcp_toolset_filter": ["list_directory", "read_file"],
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "escalated_to_pro": escalate_to_pro,
    }
    return targeted, telemetry
