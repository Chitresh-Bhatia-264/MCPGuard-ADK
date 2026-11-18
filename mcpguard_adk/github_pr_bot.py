"""GitHub Pull Request Bot & Inline Code-Suggestion Reviewer for MCPGuard-ADK.

Turns Stage 1 findings and Stage 5 `difflib` remediations into:
1. A Markdown PR Summary Comment (reporting actual scan telemetry, auto-redacted findings,
   and collapsible unified Git patch; includes simulated FinOps benchmark only when
   cost-cliff findings exist or `include_finops_sim=True`).
2. Exact GitHub Pull Request Review Inline Comments using GitHub's `suggestion` fence.
3. Safe error handling for fork PRs with read-only `GITHUB_TOKEN` (catches HTTP 403/401 on
   both endpoints without crashing so CI `--fail-on` exit codes always execute).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from mcpguard_adk.nodes.hitl_patch_emitter import _remediate_file_content
from mcpguard_adk.nodes.prefilter import NAMED_SECRET_PATTERNS
from mcpguard_adk.schemas import AuditFinding, AuditReport, FindingCategory
from mcpguard_adk.tui import _redact_secrets_in_line


def _surgical_single_line_fix(orig_line: str, finding: AuditFinding) -> str | None:
    """Produce an indentation-preserving single-line GitHub `suggestion` replacement."""
    if finding.rule_id == "MCPG-SEC-003":
        # Extract env/JSON key name if present, else fallback to `SECRET_ENV_VAR`
        key_name = "SECRET_ENV_VAR"
        if ":" in orig_line:
            lhs = orig_line.split(":", 1)[0].strip().strip('"').strip("'")
            if lhs.isidentifier():
                key_name = lhs
        elif "=" in orig_line:
            lhs = orig_line.split("=", 1)[0].strip()
            if lhs.isidentifier():
                key_name = lhs
        updated = orig_line
        for _, pat in NAMED_SECRET_PATTERNS:
            updated = pat.sub(f"${{{key_name}}}", updated)
        if updated != orig_line:
            return updated

    if finding.rule_id == "MCPG-SEC-001":
        for bad in ('"/"', '"~"', '".."', '"../"', '"/etc"', '"/root"'):
            if bad in orig_line:
                return orig_line.replace(bad, '"./workspace"', 1)

    if finding.rule_id == "MCPG-SEC-002":
        if '"-y"' in orig_line:
            return None
        if "@" in orig_line and orig_line.count("@") == 1 and '"' in orig_line:
            # Scoped package `@scope/pkg` without version suffix
            return orig_line.replace('",', '@2026.11.1",', 1) if '",' in orig_line else orig_line

    if finding.rule_id == "MCPG-COST-001" and "gemini-3.1-pro-preview" in orig_line:
        return orig_line.replace("gemini-3.1-pro-preview", "gemini-3.8-flash", 1)

    return None


def _compute_inline_suggestion_for_finding(
    finding: AuditFinding,
    repo_root: Path,
) -> dict[str, Any] | None:
    """Build a GitHub Pull Request Review comment with a 1-click ````suggestion```` block."""
    fpath = Path(finding.file_path).resolve()
    try:
        rel_posix = str(fpath.relative_to(repo_root.resolve())).replace("\\", "/")
    except ValueError:
        rel_posix = fpath.name

    suggestion_line: str | None = None
    remediated = _remediate_file_content(fpath)
    idx = finding.line_number - 1
    if remediated is not None:
        orig_lines, new_lines = remediated
        if 0 <= idx < len(orig_lines):
            if len(orig_lines) == len(new_lines) and orig_lines[idx] != new_lines[idx]:
                suggestion_line = new_lines[idx]
            else:
                suggestion_line = _surgical_single_line_fix(orig_lines[idx], finding)
    elif fpath.is_file():
        try:
            raw_lines = fpath.read_text(encoding="utf-8").splitlines()
            if 0 <= idx < len(raw_lines):
                suggestion_line = _surgical_single_line_fix(raw_lines[idx], finding)
        except Exception:
            pass

    masked_what = _redact_secrets_in_line(finding.leaked_evidence or finding.title)
    label = "Leaked Credential" if finding.category == FindingCategory.MCP_SECRET_EXPOSURE else "Detected Issue"
    body_lines = [
        f"### 🛡️ MCPGuard-ADK: `{finding.rule_id}` ({finding.severity.value})",
        f"**{label}**: `{masked_what}`",
        f"**Why it matters**: {finding.description}",
        f"**Remediation**: {finding.remediation}",
    ]
    if suggestion_line is not None:
        body_lines.extend(
            [
                "",
                "**1-Click Hardened Fix:**",
                "```suggestion",
                suggestion_line,
                "```",
            ]
        )

    return {
        "path": rel_posix,
        "line": max(1, finding.line_number),
        "side": "RIGHT",
        "body": "\n".join(body_lines),
    }


def build_github_pr_review_payload(
    report: AuditReport,
    repo_root: str | Path = ".",
    include_finops_sim: bool = False,
) -> dict[str, Any]:
    """Construct a complete GitHub Pull Request Review API payload (`event`, `body`, `comments`)."""
    root_path = Path(repo_root).resolve()
    cs = report.cost_summary
    billed_in = sum(int(sp.get("gen_ai.usage.input_tokens", 0)) for sp in report.otel_Waterfall_spans)
    billed_out = sum(int(sp.get("gen_ai.usage.output_tokens", 0)) for sp in report.otel_Waterfall_spans)
    has_cost_finding = any(
        f.category
        in {
            FindingCategory.COST_CLIFF_200K_UNCOMPACTED,
            FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
        }
        for f in report.findings
    )

    header_badge = (
        "✅ **PASSED — 0 Security or >200K Cost-Cliff Issues**"
        if not report.findings
        else f"🚨 **ACTION REQUIRED — {len(report.findings)} Findings Detected**"
    )

    md: list[str] = [
        "## 🛡️ MCPGuard-ADK Pull Request Security & FinOps Audit",
        header_badge,
        "",
        f"- **Stage 1 Deterministic AST Pre-Filter**: `{len(report.prefilter.skipped_clean_files)}/{len(report.prefilter.scanned_files)}` clean files skipped",
        f"- **Measured Scan Token Usage**: `{billed_in + billed_out}` billed LLM tokens (`in={billed_in}`, `out={billed_out}`)",
        f"- **W3C Cloud Trace ID**: `{report.otel_trace_id}`",
    ]

    if include_finops_sim or has_cost_finding:
        md.append(
            f"- **Simulated 1,000-PR Rate-Card Model**: `${cs.mcpguard_tiered_2026_promo_usd:.2f}` Tiered Hybrid vs "
            f"`${cs.naive_pro_over_200k_usd:,.2f}` Naive >200K Pro (`-{cs.savings_vs_naive_over_200k_pct}%` simulated estimate)"
        )

    md.append("")

    inline_comments: list[dict[str, Any]] = []
    seen_locations: set[tuple[str, int]] = set()

    if report.findings:
        md.extend(
            [
                "| Severity | Rule | Location | Finding Detail |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for f in report.findings:
            try:
                rel_loc = str(Path(f.file_path).resolve().relative_to(root_path)).replace("\\", "/")
            except ValueError:
                rel_loc = Path(f.file_path).name

            safe_evidence = _redact_secrets_in_line(f.leaked_evidence or f.title).replace("|", "\\|")
            md.append(
                f"| **{f.severity.value}** | `{f.rule_id}` | `{rel_loc}:{f.line_number}:{f.column_start}` | {safe_evidence} |"
            )

            loc_key = (rel_loc, f.line_number)
            if loc_key not in seen_locations:
                seen_locations.add(loc_key)
                comment = _compute_inline_suggestion_for_finding(f, root_path)
                if comment is not None:
                    inline_comments.append(comment)

    if report.unified_diff_patch:
        redacted_diff = "\n".join(
            _redact_secrets_in_line(line) for line in report.unified_diff_patch.splitlines()
        )
        md.extend(
            [
                "",
                "<details>",
                "<summary>🩹 <strong>View Full Stage 5 Hardened Unified Diff Patch (git apply ready)</strong></summary>",
                "",
                "```diff",
                redacted_diff,
                "```",
                "</details>",
            ]
        )

    return {
        "event": "COMMENT",
        "body": "\n".join(md),
        "comments": inline_comments,
    }


def resolve_pr_number_from_github_env() -> int | None:
    """Auto-detect PR number from `PR_NUMBER` env var or GitHub Actions `GITHUB_EVENT_PATH` JSON."""
    explicit = os.environ.get("PR_NUMBER", "").strip()
    if explicit.isdigit():
        return int(explicit)

    event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()
    if event_path and Path(event_path).is_file():
        try:
            event_data = json.loads(Path(event_path).read_text(encoding="utf-8"))
            pr_num = event_data.get("pull_request", {}).get("number") or event_data.get("number")
            if isinstance(pr_num, int):
                return pr_num
        except Exception:
            return None
    return None


def post_github_pr_review(
    repo: str,
    pr_number: int,
    review_payload: dict[str, Any],
    github_token: str,
    api_base: str = "https://api.github.com",
) -> dict[str, Any]:
    """Post inline PR review suggestions to GitHub REST API with graceful read-only fork fallback.

    Never raises uncaught HTTP/network exceptions (e.g. HTTP 403 on read-only fork PR tokens)
    so downstream `--fail-on` severity exit-code gates always execute cleanly.
    """
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "MCPGuard-ADK-PR-Bot/0.3.3",
    }
    reviews_url = f"{api_base.rstrip('/')}/repos/{repo}/pulls/{pr_number}/reviews"
    req = urllib.request.Request(
        reviews_url,
        data=json.dumps(review_payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"posted": True, "mode": "pull_request_review", "status": resp.status}
    except Exception as primary_err:
        # Fallback 1: Try posting summary issue comment (if inline diff hunk didn't match)
        comments_url = f"{api_base.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments"
        fallback_req = urllib.request.Request(
            comments_url,
            data=json.dumps({"body": review_payload["body"]}).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(fallback_req, timeout=15) as resp2:
                return {"posted": True, "mode": "issue_summary_comment", "status": resp2.status}
        except Exception as fallback_err:
            # Fallback 2: Fork PR read-only token (HTTP 403) or offline CI — return structured failure without crashing
            return {
                "posted": False,
                "mode": "stdout_job_log_fallback",
                "primary_error": str(primary_err),
                "fallback_error": str(fallback_err),
            }
