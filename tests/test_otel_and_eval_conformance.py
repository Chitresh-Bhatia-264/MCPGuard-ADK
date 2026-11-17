"""Tests for OpenTelemetry GenAI Semantic Conventions and ADK Evaluation / Conformance Suites."""

from __future__ import annotations

import json
from pathlib import Path

from mcpguard_adk.telemetry.otel import (
    OtelTraceRecorder,
    configure_adk_otel_environment,
    validate_otel_env_safety,
)


def test_otel_env_safety_guards_against_capture_message_content_true() -> None:
    env = configure_adk_otel_environment()
    assert env["OTEL_SEMCONV_STABILITY_OPT_IN"] == "gen_ai_latest_experimental"
    assert env["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] == "EVENT_ONLY"
    assert env["ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"] == "false"

    bad_env = {
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "true",
        "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": "true",
    }
    issues = validate_otel_env_safety(bad_env)
    assert len(issues) == 2


def test_otel_waterfall_spans_recorded() -> None:
    recorder = OtelTraceRecorder()
    with recorder.span("invoke_workflow", "mcpguard_root", model="adk-2.0-graph"):
        with recorder.span("execute_tool", "stage_1_prefilter", input_tokens=0, output_tokens=0):
            pass
    assert len(recorder.spans) == 2
    assert recorder.spans[0]["gen_ai.operation.name"] == "execute_tool"
    assert recorder.spans[1]["gen_ai.operation.name"] == "invoke_workflow"


def test_adk_eval_and_conformance_fixtures_valid() -> None:
    root_dir = Path(__file__).resolve().parent.parent
    unit_test_json = json.loads((root_dir / "evals" / "mcpguard_unit.test.json").read_text(encoding="utf-8"))
    evalset_json = json.loads((root_dir / "evals" / "mcpguard_suite.evalset.json").read_text(encoding="utf-8"))

    required_metrics = {
        "rubric_based_tool_use_quality_v1",
        "final_response_match_v2",
        "hallucinations_v1",
        "safety_v1",
        "tool_call_count_v1",
        "token_usage_v1",
        "invocation_duration_v1",
    }
    assert required_metrics.issubset(set(unit_test_json["metrics"]))
    assert required_metrics.issubset(set(evalset_json["metrics"]))
    assert evalset_json["user_simulation"]["enabled"] is True


def test_sarif_v2_1_0_exporter_and_real_difflib_patches() -> None:
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.sarif import build_sarif_report

    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    report = MCPGuardGraphWorkflow().run(examples_dir)
    sarif = build_sarif_report(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.findings)
    assert "@modelcontextprotocol/server-filesystem@2026.11.1" in report.unified_diff_patch
    assert "[sanitized by MCPGuard-ADK]" in report.unified_diff_patch


def test_google_studio_html_dashboard_generation() -> None:
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.web_studio import generate_studio_html

    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    report = MCPGuardGraphWorkflow().run(examples_dir)
    html_doc = generate_studio_html(report)
    assert "MCPGuard-ADK Studio" in html_doc
    assert "verified_ed25519_jcs" in html_doc
    assert report.otel_trace_id in html_doc


def test_cli_fail_on_severity_exit_code_gate() -> None:
    from mcpguard_adk.cli import main

    examples_dir = str((Path(__file__).resolve().parent.parent / "examples").resolve())
    clean_dir = str((Path(__file__).resolve().parent.parent / "examples" / "clean_manifest").resolve())

    # Vulnerable directory returns exit code 2 when --fail-on critical is enabled
    assert main(["scan", examples_dir, "--fail-on", "critical", "--json"]) == 2
    # Clean directory returns exit code 0 even with --fail-on medium
    assert main(["scan", clean_dir, "--fail-on", "medium", "--json"]) == 0


def test_github_pr_review_inline_suggestions_and_uvx_entrypoints(tmp_path: Path) -> None:
    import tomllib
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.cli import main
    from mcpguard_adk.github_pr_bot import build_github_pr_review_payload

    root_dir = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root_dir / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert "mcpguard" in scripts and "mcpguard-adk" in scripts

    examples_dir = root_dir / "examples"
    report = MCPGuardGraphWorkflow().run(examples_dir)
    pr_payload = build_github_pr_review_payload(report, repo_root=examples_dir)

    assert pr_payload["event"] == "COMMENT"
    assert len(pr_payload["comments"]) >= 3
    # Verify 1-click GitHub ```suggestion block is generated for Python ADK fixes
    assert any("```suggestion" in c["body"] for c in pr_payload["comments"])
    # Verify plaintext example token is auto-redacted inside the PR comment body
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in pr_payload["body"]

    dry_out = tmp_path / "pr_review.json"
    rc = main(["pr-review", str(examples_dir), "--dry-run-output", str(dry_out)])
    assert rc == 0 and dry_out.is_file()


def test_fork_pr_http_403_does_not_crash_and_enforces_fail_on(
    monkeypatch: object, capsys: object
) -> None:
    import email.message
    import urllib.error
    import urllib.request
    from mcpguard_adk.cli import main

    def _raise_403(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError(
            url="https://api.github.com/repos/org/repo/issues/1/comments",
            code=403,
            msg="Resource not accessible by integration",
            hdrs=email.message.Message(),
            fp=None,
        )

    mp = monkeypatch  # type: ignore[assignment]
    mp.setattr(urllib.request, "urlopen", _raise_403)
    mp.setenv("GITHUB_TOKEN", "ghs_readonly_fork_token")

    examples_dir = str((Path(__file__).resolve().parent.parent / "examples").resolve())
    rc = main(
        ["pr-review", examples_dir, "--repo", "org/repo", "--pr", "1", "--fail-on", "critical"]
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    # Must NOT crash with exit code 1; must print audit report to job log and return exit code 2
    assert rc == 2
    assert "MCPGuard-ADK Pull Request Security & FinOps Audit" in captured.out
    assert "Could not post GitHub PR comment" in captured.err


def test_clean_scan_omits_simulated_finops_banner_until_requested() -> None:
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.github_pr_bot import build_github_pr_review_payload
    from mcpguard_adk.tui import render_rich_audit_report

    clean_dir = Path(__file__).resolve().parent.parent / "examples" / "clean_manifest"
    clean_report = MCPGuardGraphWorkflow().run(clean_dir)

    tui_default = render_rich_audit_report(clean_report, show_finops_sim=False)
    assert "$0.0000 Actual" in tui_default
    assert "Simulated 1,000-PR Gemini Rate-Card Model" not in tui_default

    tui_with_flag = render_rich_audit_report(clean_report, show_finops_sim=True)
    assert "Simulated 1,000-PR Gemini Rate-Card Model" in tui_with_flag

    pr_clean = build_github_pr_review_payload(clean_report, repo_root=clean_dir, include_finops_sim=False)
    assert "Simulated 1,000-PR Rate-Card Model" not in pr_clean["body"]


def test_scorecard_dynamically_detects_broken_invariants() -> None:
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.tui import evaluate_runtime_scorecard

    clean_dir = Path(__file__).resolve().parent.parent / "examples" / "clean_manifest"
    report = MCPGuardGraphWorkflow().run(clean_dir)

    baseline = evaluate_runtime_scorecard(report)
    assert all(ok for ok, _, _ in baseline)

    # Corrupt Stage 1 token invariant and W3C traceId -> checks #1 and #4 must flip to False
    corrupted = report.model_copy(deep=True)
    corrupted.prefilter.llm_tokens_consumed = 99
    corrupted.otel_trace_id = "invalid-short-trace"
    degraded = evaluate_runtime_scorecard(corrupted)
    assert degraded[0][0] is False  # ADK 2.0 Hybrid Graph check failed
    assert degraded[3][0] is False  # Cloud Trace OTLP SDK check failed


def test_action_yml_blocks_shell_injection_and_tui_uses_accurate_labels() -> None:
    from mcpguard_adk.agent import MCPGuardGraphWorkflow
    from mcpguard_adk.tui import render_rich_audit_report

    root_dir = Path(__file__).resolve().parent.parent
    action_text = (root_dir / "action.yml").read_text(encoding="utf-8")
    # Ensure `${{ inputs.* }}` only appears in `env:` mappings, never inside `run:` shell commands
    for block in action_text.split("run:")[1:]:
        run_section = block.split("\n    - name:")[0]
        assert "${{ inputs." not in run_section
        assert "${{ github.action_path }}" not in run_section

    report = MCPGuardGraphWorkflow().run(root_dir / "examples")
    rendered = render_rich_audit_report(report)
    assert "WHAT LEAKED :" in rendered  # Used for MCPG-SEC-003 secret exposure
    assert "DETECTED    :" in rendered  # Used for non-leak rules like async McpToolset init
    assert "COST RISK   :" in rendered  # Used for >200K Pro loop cost cliff


def test_git_diff_detects_committed_pr_branch_when_worktree_clean(tmp_path: Path, monkeypatch) -> None:
    import subprocess
    from mcpguard_adk.nodes.prefilter import run_manifest_and_ast_prefilter

    repo = tmp_path / "pr_sim_repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "ci@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "CI Bot"], check=True)

    # Base commit on `main`
    (repo / "README.md").write_text("# Clean Repo\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "initial"], check=True, capture_output=True)

    # PR branch commit with clean working tree (`git status --porcelain` is empty, simulating GitHub Actions checkout)
    subprocess.run(["git", "-C", str(repo), "checkout", "-b", "feat/mcp"], check=True, capture_output=True)
    (repo / "mcp.json").write_text(
        '{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "mcp.json"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "add mcp"], check=True, capture_output=True)

    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    pf = run_manifest_and_ast_prefilter(repo, git_diff_only=True)
    assert any(Path(p).name == "mcp.json" for p in pf.scanned_files)
    assert len(pf.deterministic_findings) >= 2

