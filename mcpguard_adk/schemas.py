"""Typed schemas for ADK 2.0 Graph Workflow event.Output passing and audit reporting."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    MCP_OVERBROAD_SCOPE = "MCP_OVERBROAD_SCOPE"
    MCP_UNPINNED_SUPPLY_CHAIN = "MCP_UNPINNED_SUPPLY_CHAIN"
    MCP_SECRET_EXPOSURE = "MCP_SECRET_EXPOSURE"
    MCP_PROMPT_INJECTION_SURFACE = "MCP_PROMPT_INJECTION_SURFACE"
    MCP_CONTEXT_BLOAT_ROOT_TOOLSET = "MCP_CONTEXT_BLOAT_ROOT_TOOLSET"
    MCP_ASYNC_RUNTIME_INIT = "MCP_ASYNC_RUNTIME_INIT"
    COST_CLIFF_200K_UNCOMPACTED = "COST_CLIFF_200K_UNCOMPACTED"
    COST_THINKING_TOKEN_AMPLIFICATION = "COST_THINKING_TOKEN_AMPLIFICATION"
    COST_CACHE_STORAGE_NEGATIVE_ROI = "COST_CACHE_STORAGE_NEGATIVE_ROI"
    TRAJECTORY_DRIFT_MISSING_EVAL = "TRAJECTORY_DRIFT_MISSING_EVAL"


class RouteDecision(str, Enum):
    SECURITY = "SECURITY"
    COST_CLIFF = "COST_CLIFF"
    TRAJECTORY_DRIFT = "TRAJECTORY_DRIFT"
    DEFAULT_ROUTE = "DEFAULT_ROUTE"


class AuditFinding(BaseModel):
    rule_id: str = Field(..., description="Deterministic or sub-agent rule identifier, e.g. MCPG-SEC-001")
    category: FindingCategory
    severity: FindingSeverity
    file_path: str
    line_number: int = 1
    column_start: int = 1
    column_end: int = 1
    leak_type: str = ""
    leaked_evidence: str = ""
    source_line: str = ""
    context_before: str = ""
    context_after: str = ""
    title: str
    description: str
    remediation: str
    estimated_monthly_cost_impact_usd: float = 0.0
    requires_pro_escalation: bool = False
    patched_snippet: str | None = None


class PrefilterResult(BaseModel):
    target_path: str
    scanned_files: list[str] = Field(default_factory=list)
    skipped_clean_files: list[str] = Field(default_factory=list)
    mcp_configs_found: list[str] = Field(default_factory=list)
    agent_sources_found: list[str] = Field(default_factory=list)
    manifests_found: list[str] = Field(default_factory=list)
    deterministic_findings: list[AuditFinding] = Field(default_factory=list)
    llm_tokens_consumed: int = 0

    @property
    def is_clean(self) -> bool:
        return len(self.deterministic_findings) == 0


class TriageClassification(BaseModel):
    routes: list[RouteDecision] = Field(default_factory=list)
    escalate_to_pro: bool = False
    model_used: str = "gemini-3.1-flash-lite"
    rationale: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class CostComparisonSummary(BaseModel):
    pr_count: int = 1000
    naive_pro_over_200k_usd: float
    naive_pro_compacted_usd: float
    mcpguard_tiered_2026_promo_usd: float
    mcpguard_async_batch_2027_usd: float
    savings_vs_naive_over_200k_pct: float
    savings_vs_naive_compacted_pct: float


class AuditReport(BaseModel):
    target_path: str
    prefilter: PrefilterResult
    triage: TriageClassification
    findings: list[AuditFinding] = Field(default_factory=list)
    unified_diff_patch: str = ""
    written_patch_path: str | None = None
    live_ai_insights: list[str] = Field(default_factory=list)
    generated_test_fixture: dict[str, Any] = Field(default_factory=dict)
    cost_summary: CostComparisonSummary
    hitl_approved: bool = False
    otel_trace_id: str = ""
    otel_Waterfall_spans: list[dict[str, Any]] = Field(default_factory=list)
    otlp_trace_export: dict[str, Any] = Field(default_factory=dict)
