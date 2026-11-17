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
