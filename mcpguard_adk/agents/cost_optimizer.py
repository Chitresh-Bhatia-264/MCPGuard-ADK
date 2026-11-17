"""Stage 4: Cost-Cliff & Tool-Trajectory Optimizer Sub-Agent.

Wrapped via `AgentTool` on `gemini-3.8-flash`. Flags uncompacted loops liable to trigger
the >200K Gemini 3.1 Pro pricing cliff ($2.00 -> $4.00/1M input, $12.00 -> $18.00/1M output),
thinking-token cost amplification, and negative-ROI context caches.
"""

from __future__ import annotations

import os
from typing import Any

from mcpguard_adk.cost_engine import evaluate_context_cache_roi
from mcpguard_adk.llm_client import call_gemini_generate_content
from mcpguard_adk.schemas import AuditFinding, FindingCategory

COST_OPTIMIZER_INSTRUCTION = """You are the MCPGuard-ADK Stage 4 Cost & Trajectory Optimizer.
Analyze ADK agent graphs and loops for:
1. Uncompacted prompts exceeding 200,000 tokens on Gemini 3.1 Pro Preview (2x input / 1.5x output cliff).
2. Root-level McpToolset attachments without `tool_filter` or `AgentTool` isolation (>20 tool schema bloat).
3. Context caching configurations where hourly storage ($0.50/1M/hr on 3.8 Flash; $4.50/1M/hr on 3.1 Pro)
   exceeds read discounts due to low request frequency.
"""


def run_cost_and_trajectory_optimizer(
    findings: list[AuditFinding],
) -> tuple[list[AuditFinding], dict[str, Any]]:
    """Run Stage 4 isolated cost and trajectory analysis."""
    preferred_model = os.environ.get("MCPGUARD_AUDIT_MODEL", "gemini-3.8-flash")
    cost_categories = {
        FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
        FindingCategory.COST_CLIFF_200K_UNCOMPACTED,
        FindingCategory.COST_THINKING_TOKEN_AMPLIFICATION,
        FindingCategory.COST_CACHE_STORAGE_NEGATIVE_ROI,
        FindingCategory.TRAJECTORY_DRIFT_MISSING_EVAL,
    }
    targeted = [f for f in findings if f.category in cost_categories]

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
            system_instruction=COST_OPTIMIZER_INSTRUCTION,
            user_prompt=f"Summarize the >200K token cost-cliff mitigation for:\n{compact_summary}",
        )
        execution_mode = str(api_res["execution_mode"])
        resolved_model = str(api_res["resolved_model"])
        if api_res["live_api_called"]:
            in_tokens = int(api_res["input_tokens"])
            out_tokens = int(api_res["output_tokens"])
            live_summary = str(api_res["text"])

    cache_roi_check = evaluate_context_cache_roi(
        model_id="gemini-3.1-pro-preview",
        cached_prefix_tokens=100_000,
        reads_per_hour=1.0,
    )

    telemetry = {
        "sub_agent": "cost_and_trajectory_optimizer",
        "model": resolved_model,
        "execution_mode": execution_mode,
        "live_gemini_summary": live_summary,
        "isolated_via_agent_tool": True,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "sample_pro_cache_roi_at_1_read_per_hr": cache_roi_check,
    }
    return targeted, telemetry
