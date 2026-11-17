"""Stage 2: Diff and Risk Triage Router Node (Gemini 3.1 Flash-Lite).

Classifies pre-filtered payloads into `SECURITY`, `COST_CLIFF`, `TRAJECTORY_DRIFT`,
or `DEFAULT_ROUTE` and fans out parallel sub-agent branches.
Uses live `google.genai` when `GEMINI_API_KEY` is configured; otherwise reports
honest `0` billed API tokens (never fabricated magic constants).
"""

from __future__ import annotations

import json
import os

from mcpguard_adk.llm_client import call_gemini_generate_content
from mcpguard_adk.schemas import (
    FindingCategory,
    PrefilterResult,
    RouteDecision,
    TriageClassification,
)

SECURITY_CATEGORIES = {
    FindingCategory.MCP_OVERBROAD_SCOPE,
    FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
    FindingCategory.MCP_SECRET_EXPOSURE,
    FindingCategory.MCP_PROMPT_INJECTION_SURFACE,
    FindingCategory.MCP_ASYNC_RUNTIME_INIT,
}

COST_CATEGORIES = {
    FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
    FindingCategory.COST_CLIFF_200K_UNCOMPACTED,
    FindingCategory.COST_THINKING_TOKEN_AMPLIFICATION,
    FindingCategory.COST_CACHE_STORAGE_NEGATIVE_ROI,
}


def run_triage_router_node(prefilter: PrefilterResult) -> TriageClassification:
    """Classify findings and select downstream parallel ADK 2.0 Graph Workflow branches."""
    triage_model = os.environ.get("MCPGUARD_TRIAGE_MODEL", "gemini-3.1-flash-lite")

    if prefilter.is_clean:
        return TriageClassification(
            routes=[RouteDecision.DEFAULT_ROUTE],
            escalate_to_pro=False,
            model_used="none (short-circuited by Stage 1 code node)",
            rationale="Stage 1 deterministic AST/manifest pre-filter found 0 anomalies; skipping LLM invocation.",
            input_tokens=0,
            output_tokens=0,
        )

    routes: list[RouteDecision] = []
    categories = {f.category for f in prefilter.deterministic_findings}

    if categories & SECURITY_CATEGORIES:
        routes.append(RouteDecision.SECURITY)
    if categories & COST_CATEGORIES:
        routes.append(RouteDecision.COST_CLIFF)
        routes.append(RouteDecision.TRAJECTORY_DRIFT)

    if not routes:
        routes.append(RouteDecision.DEFAULT_ROUTE)

    escalate_to_pro = any(f.requires_pro_escalation for f in prefilter.deterministic_findings)

    serialized_digest = json.dumps(
        [{"rule": f.rule_id, "cat": f.category.value, "sev": f.severity.value} for f in prefilter.deterministic_findings]
    )
    api_res = call_gemini_generate_content(
        preferred_model=triage_model,
        system_instruction="Classify pre-filtered MCP/ADK findings into SECURITY, COST_CLIFF, or TRAJECTORY_DRIFT.",
        user_prompt=serialized_digest,
    )

    if api_res["live_api_called"]:
        model_label = f"{api_res['resolved_model']} [LIVE API]"
        in_tok = int(api_res["input_tokens"])
        out_tok = int(api_res["output_tokens"])
        upper_txt = str(api_res.get("text", "")).upper()
        for candidate_route in (
            RouteDecision.SECURITY,
            RouteDecision.COST_CLIFF,
            RouteDecision.TRAJECTORY_DRIFT,
        ):
            if candidate_route.value in upper_txt and candidate_route not in routes:
                routes.append(candidate_route)
    else:
        model_label = f"{triage_model} [offline-rule-router]"
        in_tok = 0
        out_tok = 0

    return TriageClassification(
        routes=routes,
        escalate_to_pro=escalate_to_pro,
        model_used=model_label,
        rationale=(
            f"Routed {len(prefilter.deterministic_findings)} pre-filtered findings to "
            f"{', '.join(r.value for r in routes)} via {model_label}"
            + (" with Gemini Pro escalation enabled." if escalate_to_pro else ".")
        ),
        input_tokens=in_tok,
        output_tokens=out_tok,
    )
