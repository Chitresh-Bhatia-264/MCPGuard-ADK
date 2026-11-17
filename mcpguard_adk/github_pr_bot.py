"""GitHub Pull Request Bot & Inline Code-Suggestion Reviewer for MCPGuard-ADK.

Turns Stage 1 findings and Stage 5 `difflib` remediations into:
1. A rich Markdown PR Summary Comment (with auto-redacted leak pinpoints, FinOps benchmark,
   and collapsible unified Git patch).
2. Exact GitHub Pull Request Review Inline Comments using GitHub's `suggestion` fence
   (````suggestion ... ````) so developers can click **"Commit suggestion"** in 1 click on PRs.

Works automatically inside GitHub Actions (`GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`)
or locally in `--dry-run` mode for testing and inspection.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from mcpguard_adk.nodes.hitl_patch_emitter import _remediate_file_content
from mcpguard_adk.schemas import AuditFinding, AuditReport
from mcpguard_adk.tui import _redact_secrets_in_line


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

    remediated = _remediate_file_content(fpath)
    suggestion_line: str | None = None
    if remediated is not None:
        orig_lines, new_lines = remediated
        idx = finding.line_number - 1
        if 0 <= idx < len(orig_lines) and len(orig_lines) == len(new_lines):
            if orig_lines[idx] != new_lines[idx]:
                suggestion_line = new_lines[idx]

    masked_what = _redact_secrets_in_line(finding.leaked_evidence or finding.title)
    body_lines = [
        f"### 🛡️ MCPGuard-ADK: `{finding.rule_id}` ({finding.severity.value})",
        f"**Detected**: `{masked_what}`",
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
) -> dict[str, Any]:
    """Construct a complete GitHub Pull Request Review API payload (`event`, `body`, `comments`)."""
    root_path = Path(repo_root).resolve()
    cs = report.cost_summary

    header_badge = (
        "✅ **PASSED — 0 Security or >200K Cost-Cliff Issues**"
        if not report.findings
        else f"🚨 **ACTION REQUIRED — {len(report.findings)} Findings Detected**"
    )

    md: list[str] = [
        "## 🛡️ MCPGuard-ADK Pull Request Security & FinOps Audit",
        header_badge,
        "",
        f"- **Stage 1 Deterministic AST Pre-Filter**: `{len(report.prefilter.skipped_clean_files)}/{len(report.prefilter.scanned_files)}` clean files skipped at **$0.00 (0 LLM tokens)**",
        f"- **1,000-PR FinOps Benchmark**: **`${cs.mcpguard_tiered_2026_promo_usd:.2f}`** Hybrid vs `${cs.naive_pro_over_200k_usd:,.2f}` Naive >200K Pro (**`-{cs.savings_vs_naive_over_200k_pct}%` saved**)",
        f"- **W3C Cloud Trace ID**: `{report.otel_trace_id}`",
        "",
    ]

    inline_comments: list[dict[str, Any]] = []
    seen_locations: set[tuple[str, int]] = set()

    if report.findings:
        md.extend(
            [
                "| Severity | Rule | Location | What Leaked / Risk |",
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
    """Post inline PR review suggestions to GitHub REST API (falls back to PR issue comment if line outside diff)."""
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "MCPGuard-ADK-PR-Bot/0.3.0",
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
    except Exception:
        # Fallback: if an inline line was not part of the PR diff hunk, post the full summary + patch comment
        comments_url = f"{api_base.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments"
        fallback_req = urllib.request.Request(
            comments_url,
            data=json.dumps({"body": review_payload["body"]}).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(fallback_req, timeout=15) as resp2:
            return {"posted": True, "mode": "issue_summary_comment", "status": resp2.status}
