"""Tests for Late-2026 Gemini Rate-Card & >200K Cost-Cliff Engineering."""

from __future__ import annotations

from mcpguard_adk.cost_engine import (
    compute_turn_cost_usd,
    evaluate_context_cache_roi,
    simulate_pr_audit_benchmarks,
)


def test_published_1000_pr_rate_card_table_exact_match() -> None:
    summary = simulate_pr_audit_benchmarks(pr_count=1000)
    # Verify exact figures from the architectural rate-card table:
    # Naive (>200K Pro cliff): $1,144.00
    # Naive (<=200K Pro compacted): $336.00
    # MCPGuard-ADK Tiered Hybrid (2026 Promo): $52.15 (~95.4% below >200K, ~84.5% below <=200K)
    # MCPGuard-ADK Async Batch (2027 Post-Promo): $42.95
    assert summary.naive_pro_over_200k_usd == 1144.00
    assert summary.naive_pro_compacted_usd == 336.00
    assert summary.mcpguard_tiered_2026_promo_usd == 52.15
    assert summary.mcpguard_async_batch_2027_usd == 42.95
    assert summary.savings_vs_naive_over_200k_pct == 95.4
    assert summary.savings_vs_naive_compacted_pct == 84.5


def test_thinking_tokens_and_200k_pro_cliff_pricing() -> None:
    # <=200K on Gemini 3.1 Pro: $2.00/1M in, $12.00/1M out (including thinking tokens)
    cost_le_200k = compute_turn_cost_usd(
        "gemini-3.1-pro-preview",
        input_tokens=100_000,
        output_tokens=2_000,
        thinking_tokens=3_000,
    )
    # (0.1 * 2.00) + (0.005 * 12.00) = 0.20 + 0.06 = $0.26
    assert cost_le_200k == 0.26

    # >200K on Gemini 3.1 Pro: $4.00/1M in, $18.00/1M out
    cost_gt_200k = compute_turn_cost_usd(
        "gemini-3.1-pro-preview",
        input_tokens=250_000,
        output_tokens=8_000,
    )
    # (0.25 * 4.00) + (0.008 * 18.00) = 1.00 + 0.144 = $1.144
    assert cost_gt_200k == 1.144


def test_context_caching_storage_roi_breakeven() -> None:
    # Infrequent reads (1 read/hr) on Gemini 3.1 Pro ($4.50/1M/hr storage) lose money
    low_freq_pro = evaluate_context_cache_roi(
        model_id="gemini-3.1-pro-preview",
        cached_prefix_tokens=500_000,
        reads_per_hour=1.0,
    )
    assert low_freq_pro["is_profitable"] is False

    # High-frequency reads (10 reads/hr) on Gemini 3.8 Flash ($0.50/1M/hr storage) save money
    high_freq_flash = evaluate_context_cache_roi(
        model_id="gemini-3.8-flash",
        cached_prefix_tokens=500_000,
        reads_per_hour=10.0,
    )
    assert high_freq_flash["is_profitable"] is True
