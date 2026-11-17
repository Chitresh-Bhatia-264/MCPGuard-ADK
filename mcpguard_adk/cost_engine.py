"""Late-2026 Gemini API & Vertex AI Model Garden Rate-Card & Cost-Cliff Calculator.

Implements transparent per-PR and 1,000-PR cost modeling across:
- Gemini 3.1 Flash-Lite ($0.25 input / $1.50 output per 1M tokens; flat to 1M context)
- Gemini 3.8 Flash ($0.75 input / $3.75 output thru Dec 31, 2026; steps up to $1.50 / $7.50 on Jan 1, 2027)
- Gemini 3.1 Pro Preview (<=200K: $2.00 input / $12.00 output; >200K cliff: $4.00 input / $18.00 output)
- Gemini 4 Argon / Carbon ($2.00 input / $10.00 API or $11.00 Vertex output thru Nov 30, 2026;
  steps up to $4.00 / $20.00-$22.00 on Dec 1, 2026)
- Context Caching Storage vs Read ROI ($0.075/1M read + $0.50/1M/hr storage on 3.8 Flash;
  $4.50/1M/hr storage on 3.1 Pro Preview)
- Grounding with Google Search (5,000 free queries/mo shared on Gemini 3 & 4, then $14/1,000 queries)
"""

from __future__ import annotations

from dataclasses import dataclass

from mcpguard_adk.schemas import CostComparisonSummary


@dataclass(frozen=True)
class ModelRateCard:
    model_id: str
    input_per_1m_le_200k: float
    output_per_1m_le_200k: float
    input_per_1m_gt_200k: float
    output_per_1m_gt_200k: float
    cache_read_per_1m: float = 0.0
    cache_storage_per_1m_per_hour: float = 0.0
    notes: str = ""


RATE_CARDS_2026: dict[str, ModelRateCard] = {
    "gemini-3.1-flash-lite": ModelRateCard(
        model_id="gemini-3.1-flash-lite",
        input_per_1m_le_200k=0.25,
        output_per_1m_le_200k=1.50,
        input_per_1m_gt_200k=0.25,
        output_per_1m_gt_200k=1.50,
        cache_read_per_1m=0.025,
        cache_storage_per_1m_per_hour=0.25,
        notes="Flat rate across full 1M token window; 8x-16x cheaper than 3.1 Pro.",
    ),
    "gemini-3.8-flash": ModelRateCard(
        model_id="gemini-3.8-flash",
        input_per_1m_le_200k=0.75,
        output_per_1m_le_200k=3.75,
        input_per_1m_gt_200k=0.75,
        output_per_1m_gt_200k=3.75,
        cache_read_per_1m=0.075,
        cache_storage_per_1m_per_hour=0.50,
        notes="2026 promotional rate thru Dec 31, 2026; doubles to $1.50/$7.50 on Jan 1, 2027.",
    ),
    "gemini-3.8-flash-2027": ModelRateCard(
        model_id="gemini-3.8-flash-2027",
        input_per_1m_le_200k=1.50,
        output_per_1m_le_200k=7.50,
        input_per_1m_gt_200k=1.50,
        output_per_1m_gt_200k=7.50,
        cache_read_per_1m=0.15,
        cache_storage_per_1m_per_hour=1.00,
        notes="Post-promo list rate effective Jan 1, 2027.",
    ),
    "gemini-3.1-pro-preview": ModelRateCard(
        model_id="gemini-3.1-pro-preview",
        input_per_1m_le_200k=2.00,
        output_per_1m_le_200k=12.00,
        input_per_1m_gt_200k=4.00,
        output_per_1m_gt_200k=18.00,
        cache_read_per_1m=0.20,
        cache_storage_per_1m_per_hour=4.50,
        notes="2x input ($4.00) and 1.5x output ($18.00) pricing cliff when prompt > 200,000 tokens.",
    ),
    "gemini-4-argon-2026-promo": ModelRateCard(
        model_id="gemini-4-argon-2026-promo",
        input_per_1m_le_200k=2.00,
        output_per_1m_le_200k=10.00,
        input_per_1m_gt_200k=4.00,
        output_per_1m_gt_200k=20.00,
        cache_read_per_1m=0.20,
        cache_storage_per_1m_per_hour=4.50,
        notes="Introductory rate thru Nov 30, 2026 ($10 API / $11 Vertex); doubles Dec 1, 2026.",
    ),
    "gemini-4-argon-2026-dec": ModelRateCard(
        model_id="gemini-4-argon-2026-dec",
        input_per_1m_le_200k=4.00,
        output_per_1m_le_200k=20.00,
        input_per_1m_gt_200k=8.00,
        output_per_1m_gt_200k=30.00,
        cache_read_per_1m=0.40,
        cache_storage_per_1m_per_hour=4.50,
        notes="Post-introductory rate effective Dec 1, 2026 ($20 API / $22 Vertex).",
    ),
}


def compute_turn_cost_usd(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    thinking_tokens: int = 0,
    batch_mode: bool = False,
) -> float:
    """Compute exact USD cost for a single turn, accounting for the >200K cliff and thinking tokens.

    Note: Thinking tokens bill at the model's output token rate.
    """
    card = RATE_CARDS_2026.get(model_id, RATE_CARDS_2026["gemini-3.8-flash"])
    over_cliff = input_tokens > 200_000
    in_rate = card.input_per_1m_gt_200k if over_cliff else card.input_per_1m_le_200k
    out_rate = card.output_per_1m_gt_200k if over_cliff else card.output_per_1m_le_200k

    total_billable_output = output_tokens + thinking_tokens
    cost = (input_tokens / 1_000_000.0) * in_rate + (total_billable_output / 1_000_000.0) * out_rate
    if batch_mode:
        cost *= 0.5
    return round(cost, 6)


def evaluate_context_cache_roi(
    model_id: str,
    cached_prefix_tokens: int,
    reads_per_hour: float,
) -> dict[str, float | bool | str]:
    """Verify whether explicit context caching saves or loses money given read frequency.

    Cached input on Gemini 3.8 Flash reads at $0.075/1M tokens vs $0.75/1M standard,
    but incurs $0.50/1M/hr storage. On Gemini 3.1 Pro Preview, storage runs $4.50/1M/hr.
    """
    card = RATE_CARDS_2026.get(model_id, RATE_CARDS_2026["gemini-3.8-flash"])
    tokens_m = cached_prefix_tokens / 1_000_000.0
    uncached_hourly_cost = tokens_m * card.input_per_1m_le_200k * reads_per_hour
    cached_hourly_cost = (tokens_m * card.cache_read_per_1m * reads_per_hour) + (
        tokens_m * card.cache_storage_per_1m_per_hour
    )
    savings_per_token_m_read = card.input_per_1m_le_200k - card.cache_read_per_1m
    breakeven_reads_per_hour = (
        card.cache_storage_per_1m_per_hour / savings_per_token_m_read
        if savings_per_token_m_read > 0
        else float("inf")
    )
    return {
        "model_id": card.model_id,
        "uncached_hourly_usd": round(uncached_hourly_cost, 5),
        "cached_hourly_usd": round(cached_hourly_cost, 5),
        "net_hourly_savings_usd": round(uncached_hourly_cost - cached_hourly_cost, 5),
        "breakeven_reads_per_hour": round(breakeven_reads_per_hour, 2),
        "is_profitable": cached_hourly_cost < uncached_hourly_cost,
    }


def simulate_pr_audit_benchmarks(pr_count: int = 1000) -> CostComparisonSummary:
    """Reproduce the transparent rate-card benchmark across `pr_count` pull-request audits."""
    # 1. Naive Single-Agent Loop (>200K Cliff): 250K input, 8K output on Gemini 3.1 Pro Preview
    # (0.25 * $4.00) + (0.008 * $18.00) = $1.144 per PR -> $1,144.00 per 1,000 PRs
    naive_over_200k_per_pr = compute_turn_cost_usd(
        "gemini-3.1-pro-preview", input_tokens=250_000, output_tokens=8_000
    )
    naive_over_200k_total = round(naive_over_200k_per_pr * pr_count, 2)

    # 2. Naive Single-Agent Loop (<=200K Compacted): 120K input, 8K output on Gemini 3.1 Pro Preview
    # (0.12 * $2.00) + (0.008 * $12.00) = $0.336 per PR -> $336.00 per 1,000 PRs
    naive_compacted_per_pr = compute_turn_cost_usd(
        "gemini-3.1-pro-preview", input_tokens=120_000, output_tokens=8_000
    )
    naive_compacted_total = round(naive_compacted_per_pr * pr_count, 2)

    # 3. MCPGuard-ADK Tiered Hybrid (2026 Promo):
    # - Stage 1 Code node skips clean files (0 tokens)
    # - Stage 2 3.1 Flash-Lite triage (40K in / 2K out) -> $0.013
    # - Stage 3/4 3.8 Flash isolated audit (25K in / 4K out) -> $0.03375
    # - 3.1 Pro escalation on 10% of PRs (15K in / 2K out) -> 0.1 * $0.054 = $0.0054
    # Total per PR = $0.05215 -> $52.15 per 1,000 PRs
    triage_cost = compute_turn_cost_usd(
        "gemini-3.1-flash-lite", input_tokens=40_000, output_tokens=2_000
    )
    audit_cost_2026 = compute_turn_cost_usd(
        "gemini-3.8-flash", input_tokens=25_000, output_tokens=4_000
    )
    pro_escalation_cost = 0.10 * compute_turn_cost_usd(
        "gemini-3.1-pro-preview", input_tokens=15_000, output_tokens=2_000
    )
    tiered_2026_per_pr = triage_cost + audit_cost_2026 + pro_escalation_cost
    tiered_2026_total = round(tiered_2026_per_pr * pr_count, 2)

    # 4. MCPGuard-ADK Async Batch (2027 Post-Promo, 50% Batch discount, 3.8 Flash at $1.50/$7.50 list):
    # Batch rates: 3.1 Flash-Lite $0.125/$0.75 -> $0.0065
    # 3.8 Flash (2027 list $1.50/$7.50 * 50% Batch = $0.75/$3.75) -> $0.03375
    # 3.1 Pro ($1.00/$6.00 Batch) on 10% -> $0.0027
    # Total per PR = $0.04295 -> $42.95 per 1,000 PRs
    triage_batch_2027 = compute_turn_cost_usd(
        "gemini-3.1-flash-lite", input_tokens=40_000, output_tokens=2_000, batch_mode=True
    )
    audit_batch_2027 = compute_turn_cost_usd(
        "gemini-3.8-flash-2027", input_tokens=25_000, output_tokens=4_000, batch_mode=True
    )
    pro_escalation_batch_2027 = 0.10 * compute_turn_cost_usd(
        "gemini-3.1-pro-preview", input_tokens=15_000, output_tokens=2_000, batch_mode=True
    )
    batch_2027_per_pr = triage_batch_2027 + audit_batch_2027 + pro_escalation_batch_2027
    batch_2027_total = round(batch_2027_per_pr * pr_count, 2)

    savings_vs_over_200k = round(
        (1.0 - (tiered_2026_total / naive_over_200k_total)) * 100.0, 1
    )
    savings_vs_compacted = round(
        (1.0 - (tiered_2026_total / naive_compacted_total)) * 100.0, 1
    )

    return CostComparisonSummary(
        pr_count=pr_count,
        naive_pro_over_200k_usd=naive_over_200k_total,
        naive_pro_compacted_usd=naive_compacted_total,
        mcpguard_tiered_2026_promo_usd=tiered_2026_total,
        mcpguard_async_batch_2027_usd=batch_2027_total,
        savings_vs_naive_over_200k_pct=savings_vs_over_200k,
        savings_vs_naive_compacted_pct=savings_vs_compacted,
    )
