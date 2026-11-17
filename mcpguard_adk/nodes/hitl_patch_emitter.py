"""Stage 5: HITL Confirmation Gate, Real File-Aware Unified Diff Emitter & Patch Writer.

Uses Python's `difflib.unified_diff` against actual file contents on disk to synthesize
reviewable Git patches.
- When `hitl_approved=False` (default): pauses mutation and only previews the diff.
- When `hitl_approved=True` (`--approve-patches`): writes the `git apply`-compatible patch
  artifact to `reports/hardened_remediation.patch` (or custom `patch_output_path`).
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any

from mcpguard_adk.schemas import AuditFinding

SECRET_ENV_KEY_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD")


def _remediate_file_content(file_path: Path) -> tuple[list[str], list[str]] | None:
    """Compute (original_lines, hardened_lines) for a real file on disk."""
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    orig_lines = raw_text.splitlines()
    name_lower = file_path.name.lower()

    if name_lower.endswith(".json"):
        try:
            data = json.loads(raw_text)
        except Exception:
            return None
        servers = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers, dict):
            return None
        mutated = False
        for _, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            args = cfg.get("args")
            if isinstance(args, list):
                new_args: list[str] = []
                for a in args:
                    a_str = str(a)
                    if a_str in {"-y", "--yes"}:
                        mutated = True
                        continue
                    if a_str in {"/", "~", "C:\\", "C:/", "..", "../", "/etc", "/root", "/Users"}:
                        new_args.append("./workspace")
                        mutated = True
                    elif a_str.startswith("@modelcontextprotocol/") and "@" not in a_str[1:]:
                        new_args.append(f"{a_str}@2026.11.1")
                        mutated = True
                    else:
                        new_args.append(a_str)
                cfg["args"] = new_args
            if "tool_filter" not in cfg and "toolFilter" not in cfg:
                cfg["tool_filter"] = ["list_directory", "read_file"]
                mutated = True
            env_map = cfg.get("env")
            if isinstance(env_map, dict):
                for ek, ev in list(env_map.items()):
                    ev_str = str(ev)
                    if any(w in ek.upper() for w in SECRET_ENV_KEY_WORDS) and not ev_str.startswith("${"):
                        env_map[ek] = f"${{{ek}}}"
                        mutated = True
            meta = cfg.get("metadata")
            if isinstance(meta, dict) and "description" in meta:
                desc = str(meta["description"])
                cleaned = re.sub(
                    r"ignore\s+(all\s+)?previous\s+instructions.*",
                    "[sanitized by MCPGuard-ADK]",
                    desc,
                    flags=re.IGNORECASE,
                )
                if cleaned != desc:
                    meta["description"] = cleaned
                    mutated = True
        if not mutated:
            return None
        new_lines = json.dumps(data, indent=2).splitlines()
        return orig_lines, new_lines

    if name_lower.endswith((".js", ".jsx", ".ts", ".tsx")):
        new_lines = []
        mutated = False
        for line in orig_lines:
            if "dangerouslySetInnerHTML" in line and "DOMPurify" not in line:
                indent = line[: len(line) - len(line.lstrip())]
                new_lines.append(
                    f"{indent}/* [MCPGuard-ADK MCPG-SEC-004] Sanitize untrusted HTML/CSS before injection */"
                )
                new_lines.append(line)
                mutated = True
            else:
                new_lines.append(line)
        return (orig_lines, new_lines) if mutated else None

    if name_lower.endswith(".py"):
        new_lines = []
        mutated = False
        for line in orig_lines:
            if "McpToolset(" in line and "tool_filter" not in line:
                fixed = line.replace(
                    "McpToolset(",
                    "McpToolset(tool_filter=['list_directory', 'read_file'], ",
                )
                new_lines.append(fixed)
                mutated = True
            elif 'model = "gemini-3.1-pro-preview"' in line:
                new_lines.append(
                    line.replace(
                        'model = "gemini-3.1-pro-preview"',
                        'model = "gemini-3.8-flash"  # Tiered by MCPGuard-ADK to avoid >200K Pro cliff',
                    )
                )
                mutated = True
            else:
                new_lines.append(line)
        return (orig_lines, new_lines) if mutated else None

    return None


def build_hardened_unified_diff(findings: list[AuditFinding]) -> str:
    """Synthesize real `difflib.unified_diff` patches across all flagged files."""
    if not findings:
        return ""

    diff_blocks: list[str] = []
    seen_files: set[str] = set()

    for finding in findings:
        if finding.file_path in seen_files:
            continue
        seen_files.add(finding.file_path)

        fpath = Path(finding.file_path)
        remediated = _remediate_file_content(fpath)
        if remediated is not None:
            orig_lines, new_lines = remediated
            diff = list(
                difflib.unified_diff(
                    orig_lines,
                    new_lines,
                    fromfile=f"a/{fpath.name}",
                    tofile=f"b/{fpath.name}",
                    lineterm="",
                )
            )
            if diff:
                diff_blocks.append("\n".join(diff))

    return "\n\n".join(diff_blocks)


def build_adk_regression_test_fixture(findings: list[AuditFinding]) -> dict[str, Any]:
    """Generate an ADK `.test.json` trajectory & safety regression fixture for `adk eval`."""
    rule_ids = sorted({f.rule_id for f in findings})
    return {
        "eval_set_id": "mcpguard_adk_regression_suite",
        "name": "mcpguard_supply_chain_and_cost_cliff_regression",
        "description": "Auto-generated ADK 2.0 regression fixture gating MCP scope, secret hygiene, and <200K token compaction.",
        "metrics": [
            "rubric_based_tool_use_quality_v1",
            "final_response_match_v2",
            "hallucinations_v1",
            "safety_v1",
            "tool_call_count_v1",
            "token_usage_v1",
            "invocation_duration_v1",
        ],
        "eval_cases": [
            {
                "eval_id": "verify_zero_context_bloat_and_patch_emission",
                "conversation": [
                    {
                        "invocation_id": "turn-1",
                        "user_content": {
                            "parts": [
                                {
                                    "text": "Audit repository MCP configs and agent loops for supply-chain and >200K token cost-cliff risks."
                                }
                            ]
                        },
                        "intermediate_data": {
                            "tool_uses": [
                                {
                                    "name": "manifest_and_ast_prefilter",
                                    "args": {"llm_tokens": 0},
                                },
                                {
                                    "name": "security_and_mcp_auditor_agent_tool",
                                    "args": {
                                        "isolated_context": True,
                                        "tool_filter": ["list_directory", "read_file"],
                                    },
                                },
                                {
                                    "name": "cost_and_trajectory_optimizer_agent_tool",
                                    "args": {"max_prompt_tokens": 200000},
                                },
                            ]
                        },
                        "final_response": {
                            "parts": [
                                {
                                    "text": f"Detected and remediated rules: {', '.join(rule_ids) if rule_ids else 'CLEAN'}."
                                }
                            ]
                        },
                    }
                ],
            }
        ],
    }


def run_hitl_patch_emitter_node(
    findings: list[AuditFinding],
    hitl_approved: bool = False,
    patch_output_path: str | Path | None = None,
) -> tuple[str, dict[str, Any], str | None]:
    """Run Stage 5 HITL gate; write `.patch` artifact to disk ONLY when `hitl_approved=True`."""
    unified_diff = build_hardened_unified_diff(findings)
    test_fixture = build_adk_regression_test_fixture(findings)
    written_patch_file: str | None = None

    if hitl_approved and unified_diff:
        out_file = Path(patch_output_path) if patch_output_path else (Path("reports") / "hardened_remediation.patch")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(unified_diff + "\n", encoding="utf-8")
        written_patch_file = str(out_file.resolve())

    return unified_diff, test_fixture, written_patch_file
