"""Stage 1: Deterministic Manifest, Secret-Leak, Git-Diff & AST Pre-Filter Node (0 LLM Tokens).

Pinpoints exact `file_path:line:column`, 3-line source context (`context_before`, `source_line`,
`context_after`), `leak_type`, and `leaked_evidence` across:
- MCP server configs (`mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, `*mcp*.json`)
- Python ADK agent ASTs (`.py`)
- React / TypeScript / JavaScript files (`.js`, `.jsx`, `.ts`, `.tsx`)
- Environment & Config files (`.env`, `.env.local`, `.env.production` — ignoring `.env.example` placeholders)
- Dependency manifests (`package.json`, `pyproject.toml` via `tomllib`, `go.mod`)
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

from mcpguard_adk.schemas import (
    AuditFinding,
    FindingCategory,
    FindingSeverity,
    PrefilterResult,
)

NAMED_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Google Cloud / Gemini API Key", re.compile(r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z\-_]{20,})")),
    ("GitHub Personal Access Token", re.compile(r"(?<![A-Za-z0-9_\-])((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{25,})")),
    ("Anthropic API Secret Key", re.compile(r"(?<![A-Za-z0-9_\-])(sk-ant-[0-9A-Za-z\-_]{20,})")),
    ("OpenAI / LLM API Secret Key", re.compile(r"(?<![A-Za-z0-9_\-])(sk-(?!ant-)[0-9A-Za-z\-_]{20,})")),
    ("AWS Access Key ID", re.compile(r"(?<![A-Za-z0-9_\-])(AKIA[0-9A-Z]{16})")),
    ("Stripe Live Secret Key", re.compile(r"(?<![A-Za-z0-9_\-])(sk_live_[0-9A-Za-z]{16,})")),
    ("Slack Bot / User Token", re.compile(r"(?<![A-Za-z0-9_\-])(xox[baprs]-[0-9A-Za-z\-]{10,})")),
    ("Database URI with Password", re.compile(r"((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^/\s:@\[]+:[^/\s@*\]]+@[^\s\"'`\)]+)")),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(ignore\s+(?:all\s+)?previous\s+instructions[^\"'\n]*)", re.IGNORECASE),
    re.compile(r"(system\s+override[^\"'\n]*)", re.IGNORECASE),
    re.compile(r"((?:exfiltrate|curl\s+http|wget\s+http)[^\"'\n]*)", re.IGNORECASE),
]

OVERBROAD_PATHS = {"/", "~", "C:\\", "C:/", "..", "../", "/etc", "/root", "/Users"}

PLACEHOLDER_VALUES = {
    "your-google-ai-studio-api-key",
    "your-free-ai-studio-key",
    "your_api_key_here",
    "your-api-key",
    "changeme",
    "replace_me",
    "xxx",
    "none",
    "null",
    "true",
    "false",
}

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".turbo",
    "coverage",
    "out",
    ".cache",
    "tests",
    "__tests__",
    "unittests",
}


def _mask_secret_preview(val: str) -> str:
    """Show exact prefix + suffix + length so user sees WHAT leaked safely."""
    clean = val.strip()
    if len(clean) <= 10:
        return f"{clean[:3]}••• ({len(clean)} chars)"
    return f"{clean[:8]}••••••••{clean[-4:]} ({len(clean)} chars)"


def _extract_line_context(lines: list[str], line_no: int) -> tuple[str, str, str]:
    """Return (context_before, source_line, context_after) for 1-based `line_no`."""
    if not lines:
        return "", "", ""
    idx = max(0, min(len(lines) - 1, line_no - 1))
    before = lines[idx - 1] if idx > 0 else ""
    cur = lines[idx]
    after = lines[idx + 1] if idx + 1 < len(lines) else ""
    return before, cur, after


def _locate_token_in_lines(
    lines: list[str],
    needle: str,
    fallback_key: str = "",
) -> tuple[int, int, int]:
    """Find 1-based `(line_number, col_start, col_end)` of `needle` inside raw file lines."""
    quoted = f'"{needle}"'
    # Pass 1: exact JSON/Python quoted string match across all lines first
    for idx, line in enumerate(lines, start=1):
        pos = line.find(quoted)
        if pos != -1:
            return idx, pos + 1, pos + 1 + len(quoted)
    # Pass 2: unquoted token match
    for idx, line in enumerate(lines, start=1):
        pos2 = line.find(needle)
        if pos2 != -1 and (not fallback_key or fallback_key in line or len(needle) > 2):
            return idx, pos2 + 1, pos2 + 1 + len(needle)

    if fallback_key:
        for idx, line in enumerate(lines, start=1):
            pos = line.find(fallback_key)
            if pos != -1:
                return idx, pos + 1, pos + 1 + len(fallback_key)
    return 1, 1, max(2, len(needle))


def _match_secret_type(val_str: str) -> tuple[str, str] | None:
    """Return `(secret_provider_name, matched_literal)` if `val_str` matches a real secret."""
    for label, pat in NAMED_SECRET_PATTERNS:
        m = pat.search(val_str)
        if not m:
            continue
        tok = m.group(1)
        if tok.startswith("sk-"):
            # Reject lowercase English kebab-case prose/placeholders (`sk-my-api-key`, `sk-live-should-not-appear`)
            suffix = tok[3:]
            if not any(ch.isdigit() or ch.isupper() for ch in suffix):
                continue
        if "://" in tok and "@" in tok:
            creds = tok.split("://", 1)[1].split("@", 1)[0].lower()
            if creds in {"user:pass", "user:password", "user:secret", "username:password", "u:secret"}:
                continue
        return label, tok
    return None


def _inspect_mcp_config_file(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        raw_text = file_path.read_text(encoding="utf-8")
        lines = raw_text.splitlines()
        data = json.loads(raw_text)
    except Exception:
        return findings

    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return findings

    for server_name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        command = str(cfg.get("command", ""))
        args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int, float))]
        env_map = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
        tool_filter = cfg.get("tool_filter") or cfg.get("toolFilter")

        # 1. Over-broad filesystem scopes
        for arg in args:
            normalized = arg.strip()
            if normalized in OVERBROAD_PATHS or normalized.startswith("/etc") or normalized.startswith(".."):
                ln, c1, c2 = _locate_token_in_lines(lines, normalized)
                b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-SEC-001",
                        category=FindingCategory.MCP_OVERBROAD_SCOPE,
                        severity=FindingSeverity.CRITICAL,
                        file_path=str(file_path),
                        line_number=ln,
                        column_start=c1,
                        column_end=c2,
                        leak_type="Host Root Filesystem Exposure",
                        leaked_evidence=f'mcpServers.{server_name}.args -> "{normalized}" (Full Disk Access)',
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Over-broad filesystem scope '{normalized}' on MCP server '{server_name}'",
                        description=(
                            f"MCP server '{server_name}' mounts '{normalized}' without a least-privilege "
                            "directory boundary or `tool_filter` restriction, allowing arbitrary host reads/writes."
                        ),
                        remediation=(
                            "Restrict the path argument to `./workspace` and attach `McpToolset` inside an "
                            "isolated `AgentTool` with `tool_filter=['list_directory', 'read_file']`."
                        ),
                        requires_pro_escalation=True,
                    )
                )

        # 2. Unpinned npx -y supply-chain auto-execution
        if command in {"npx", "uvx", "bunx"} and ("-y" in args or "--yes" in args):
            unpinned = [
                a for a in args if not a.startswith("-") and a not in OVERBROAD_PATHS and "@" not in a[1:]
            ]
            if unpinned:
                target_pkg = unpinned[0]
                ln, c1, c2 = _locate_token_in_lines(lines, target_pkg)
                b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-SEC-002",
                        category=FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
                        severity=FindingSeverity.HIGH,
                        file_path=str(file_path),
                        line_number=ln,
                        column_start=c1,
                        column_end=c2,
                        leak_type="Unpinned Remote Package Execution",
                        leaked_evidence=f"{command} -y {target_pkg} (No version or SHA-256 lock)",
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Unpinned `{command} -y` package execution in MCP server '{server_name}'",
                        description=(
                            f"Server '{server_name}' executes `{command} -y {' '.join(unpinned)}` without an "
                            "immutable version pin, exposing the host to npm/PyPI supply-chain compromises."
                        ),
                        remediation="Pin exact package version (e.g. `@modelcontextprotocol/server-filesystem@2026.11.1`) and remove `-y`.",
                    )
                )

        # 3. Hardcoded secrets in env block
        for env_key, env_val in env_map.items():
            val_str = str(env_val).strip()
            if val_str.lower() in PLACEHOLDER_VALUES or val_str.startswith("${") or val_str.startswith("$"):
                continue
            secret_hit = _match_secret_type(val_str)
            is_generic_secret = (
                any(k in env_key.upper() for k in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
                and len(val_str) >= 12
            )
            if secret_hit or is_generic_secret:
                provider_label = secret_hit[0] if secret_hit else "Plaintext Environment Credential"
                raw_secret = secret_hit[1] if secret_hit else val_str
                ln, c1, c2 = _locate_token_in_lines(lines, raw_secret, fallback_key=env_key)
                b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-SEC-003",
                        category=FindingCategory.MCP_SECRET_EXPOSURE,
                        severity=FindingSeverity.CRITICAL,
                        file_path=str(file_path),
                        line_number=ln,
                        column_start=c1,
                        column_end=c2,
                        leak_type=provider_label,
                        leaked_evidence=f"{env_key} = {_mask_secret_preview(raw_secret)}",
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Leaked {provider_label} in `{server_name}.env.{env_key}`",
                        description=(
                            f"Environment variable `{env_key}` in MCP server `{server_name}` exposes a "
                            f"live {provider_label} literal in plaintext JSON."
                        ),
                        remediation=f"Replace literal value with `${{{env_key}}}` and load from OS secret store or `.env`.",
                        requires_pro_escalation=True,
                    )
                )

        # 4. Prompt-injection instructions embedded in metadata/descriptions
        for idx_l, raw_l in enumerate(lines, start=1):
            matched_inj = None
            for pattern in PROMPT_INJECTION_PATTERNS:
                m = pattern.search(raw_l)
                if m:
                    matched_inj = m
                    break
            if matched_inj:
                b_ctx, s_line, a_ctx = _extract_line_context(lines, idx_l)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-SEC-004",
                        category=FindingCategory.MCP_PROMPT_INJECTION_SURFACE,
                        severity=FindingSeverity.CRITICAL,
                        file_path=str(file_path),
                        line_number=idx_l,
                        column_start=matched_inj.start(1) + 1,
                        column_end=matched_inj.end(1) + 1,
                        leak_type="Indirect Prompt Injection / SSH Exfiltration",
                        leaked_evidence=f'"{matched_inj.group(1)[:68]}"',
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Prompt-injection payload in MCP server '{server_name}' metadata",
                        description=(
                            f"Line {idx_l} embeds instruction-override / file-exfiltration directives inside "
                            "MCP metadata read into the LLM's system prompt."
                        ),
                        remediation="Quarantine the MCP server and sanitize untrusted tool descriptions before binding.",
                        requires_pro_escalation=True,
                    )
                )
                break

        # 5. Missing least-privilege tool_filter
        if not tool_filter and any("filesystem" in a or "shell" in a or "bash" in a for a in args):
            ln, c1, c2 = _locate_token_in_lines(lines, server_name)
            b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-SEC-005",
                    category=FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
                    severity=FindingSeverity.MEDIUM,
                    file_path=str(file_path),
                    line_number=ln,
                    column_start=c1,
                    column_end=c2,
                    leak_type="Unrestricted Write/Delete MCP Tools",
                    leaked_evidence=f'mcpServers.{server_name} missing "tool_filter" (write_file/move_file exposed)',
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title=f"Missing `tool_filter` on MCP server '{server_name}'",
                    description=(
                        f"Server '{server_name}' exposes all write/delete tools to the agent instead of "
                        "enforcing least-privilege read-only `tool_filter` limits."
                    ),
                    remediation="Add `tool_filter=['list_directory', 'read_file']` inside `McpToolset`.",
                )
            )

    return findings


def _inspect_env_file(file_path: Path) -> list[AuditFinding]:
    """Inspect `.env`, `.env.local`, `.env.production` for real leaked keys (skips `.env.example` templates)."""
    findings: list[AuditFinding] = []
    name_lower = file_path.name.lower()
    if any(s in name_lower for s in ("example", "sample", "template")):
        return findings

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return findings

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        key = key.strip()
        val_clean = val.strip().strip('"').strip("'")
        if not val_clean or val_clean.lower() in PLACEHOLDER_VALUES or val_clean.startswith("${"):
            continue

        secret_hit = _match_secret_type(val_clean)
        if secret_hit:
            provider, literal = secret_hit
            pos = raw_line.find(literal)
            c1 = (pos + 1) if pos != -1 else 1
            c2 = c1 + len(literal)
            b_ctx, s_line, a_ctx = _extract_line_context(lines, idx)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-SEC-003",
                    category=FindingCategory.MCP_SECRET_EXPOSURE,
                    severity=FindingSeverity.CRITICAL,
                    file_path=str(file_path),
                    line_number=idx,
                    column_start=c1,
                    column_end=c2,
                    leak_type=f"{provider} in {file_path.name}",
                    leaked_evidence=f"{key} = {_mask_secret_preview(literal)}",
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title=f"Live {provider} stored in `{file_path.name}` (`{key}`)",
                    description=(
                        f"`{file_path.name}:{idx}` contains an active {provider}. Ensure `{file_path.name}` is "
                        "listed in `.gitignore` and never exposed to client-side `VITE_` / `REACT_APP_` bundles."
                    ),
                    remediation="Verify `.env` is gitignored, rotate if committed, and avoid `VITE_`/`REACT_APP_` prefixes for secret keys.",
                    requires_pro_escalation=True,
                )
            )
    return findings


def _inspect_python_agent_ast(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        source = file_path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source, filename=str(file_path))
    except Exception:
        return findings

    # Ignore Python docstring line spans when checking raw source lines for hardcoded credentials
    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first_stmt = node.body[0]
            if (
                isinstance(first_stmt, ast.Expr)
                and isinstance(first_stmt.value, ast.Constant)
                and isinstance(first_stmt.value.value, str)
            ):
                for d_ln in range(first_stmt.lineno, getattr(first_stmt, "end_lineno", first_stmt.lineno) + 1):
                    docstring_lines.add(d_ln)

    # Also scan Python source lines for hardcoded API keys
    for idx, line in enumerate(lines, start=1):
        if idx in docstring_lines or "re.compile" in line:
            continue
        hit = _match_secret_type(line)
        if hit:
            provider, literal = hit
            pos = line.find(literal)
            b_ctx, s_line, a_ctx = _extract_line_context(lines, idx)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-SEC-003",
                    category=FindingCategory.MCP_SECRET_EXPOSURE,
                    severity=FindingSeverity.CRITICAL,
                    file_path=str(file_path),
                    line_number=idx,
                    column_start=(pos + 1) if pos != -1 else 1,
                    column_end=((pos + 1) if pos != -1 else 1) + len(literal),
                    leak_type=provider,
                    leaked_evidence=_mask_secret_preview(literal),
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title=f"Hardcoded {provider} in `{file_path.name}:{idx}`",
                    description=f"Detected plaintext {provider} literal in Python source code.",
                    remediation="Load credentials via `os.environ.get(...)` or Google Secret Manager.",
                    requires_pro_escalation=True,
                )
            )

    has_mcp_toolset = False
    mcp_toolset_line = 1
    has_agent_tool_wrapper = "AgentTool" in source
    has_tool_filter = "tool_filter" in source

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and getattr(child.func, "id", "") == "McpToolset":
                    ln = getattr(child, "lineno", node.lineno)
                    col = getattr(child, "col_offset", 0) + 1
                    end_col = getattr(child, "end_col_offset", col + 10) + 1
                    b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                    findings.append(
                        AuditFinding(
                            rule_id="MCPG-ADK-001",
                            category=FindingCategory.MCP_ASYNC_RUNTIME_INIT,
                            severity=FindingSeverity.HIGH,
                            file_path=str(file_path),
                            line_number=ln,
                            column_start=col,
                            column_end=end_col,
                            leak_type="Async Runtime MCP Session Leak",
                            leaked_evidence=f"async def {node.name}() -> McpToolset(...)",
                            source_line=s_line,
                            context_before=b_ctx,
                            context_after=a_ctx,
                            title="Asynchronous runtime initialization of `McpToolset` violates ADK deployment rule",
                            description=(
                                f"`McpToolset` is instantiated inside `async def {node.name}()` at line {ln}. "
                                "ADK production deployments require synchronous `McpToolset` declaration in `agent.py`."
                            ),
                            remediation="Move `McpToolset(connection_params=StdioConnectionParams(...), tool_filter=[...])` to module top-level in `agent.py`.",
                        )
                    )

        if isinstance(node, ast.Call):
            func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if func_name == "McpToolset":
                has_mcp_toolset = True
                mcp_toolset_line = getattr(node, "lineno", 1)
                kw_names = {kw.arg for kw in node.keywords if kw.arg}
                if "tool_filter" not in kw_names:
                    ln = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0) + 1
                    end_col = getattr(node, "end_col_offset", col + 10) + 1
                    b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                    findings.append(
                        AuditFinding(
                            rule_id="MCPG-ADK-002",
                            category=FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
                            severity=FindingSeverity.HIGH,
                            file_path=str(file_path),
                            line_number=ln,
                            column_start=col,
                            column_end=end_col,
                            leak_type="Unfiltered Tool Schema Bloat (>20 Tools)",
                            leaked_evidence="McpToolset(...) called without `tool_filter`",
                            source_line=s_line,
                            context_before=b_ctx,
                            context_after=a_ctx,
                            title="`McpToolset` attached without `tool_filter` causes >20-tool context bloat",
                            description=(
                                "`McpToolset` is instantiated without `tool_filter`, pushing every external MCP tool "
                                "schema and raw file blob into the orchestrator's context window."
                            ),
                            remediation="Pass `tool_filter=['list_directory', 'read_file']` and encapsulate inside `AgentTool(agent=...)`.",
                        )
                    )

            if func_name in {"LlmAgent", "Agent"}:
                for kw in node.keywords:
                    if kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)) and len(kw.value.elts) > 20:
                        ln = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0) + 1
                        b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                        findings.append(
                            AuditFinding(
                                rule_id="MCPG-ADK-004",
                                category=FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
                                severity=FindingSeverity.HIGH,
                                file_path=str(file_path),
                                line_number=ln,
                                column_start=col,
                                column_end=col + len(func_name),
                                leak_type="Agent Schema Overload",
                                leaked_evidence=f"{func_name}(tools=[{len(kw.value.elts)} tools])",
                                source_line=s_line,
                                context_before=b_ctx,
                                context_after=a_ctx,
                                title=f"`{func_name}` binds {len(kw.value.elts)} tools (>20 schema accuracy threshold)",
                                description=f"Binding {len(kw.value.elts)} tools directly degrades tool-selection precision.",
                                remediation="Partition tools into domain-specific `AgentTool` sub-agents (<10 tools each).",
                            )
                        )

        if isinstance(node, (ast.While, ast.For)):
            loop_segment = ast.get_source_segment(source, node) or ""
            is_string_sanitizer = ".replace(" in loop_segment or "orig_lines" in loop_segment
            if (
                not is_string_sanitizer
                and any(m in loop_segment for m in ("gemini-3.1-pro", "gemini-4-argon", "gemini-4-carbon"))
                and "compact" not in loop_segment.lower()
                and "summarize" not in loop_segment.lower()
            ):
                ln = getattr(node, "lineno", 1)
                col = getattr(node, "col_offset", 0) + 1
                b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-COST-001",
                        category=FindingCategory.COST_CLIFF_200K_UNCOMPACTED,
                        severity=FindingSeverity.HIGH,
                        file_path=str(file_path),
                        line_number=ln,
                        column_start=col,
                        column_end=len(s_line) + 1,
                        leak_type="Token Spend Leak (>200K 2x Pro Cliff)",
                        leaked_evidence="Unbounded loop -> gemini-3.1-pro-preview ($4.00/1M in, $18.00/1M out)",
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title="Uncompacted Pro agent loop liable to cross the >200,000-token pricing cliff",
                        description=(
                            "Loop appends raw blobs on a Pro-tier model without compaction or `AgentTool` isolation "
                            "($1,144 vs $52.15 per 1,000 PRs)."
                        ),
                        remediation="Convert into an ADK 2.0 Graph Workflow with `gemini-3.1-flash-lite` triage and `AgentTool` sub-agents.",
                        estimated_monthly_cost_impact_usd=1091.85,
                    )
                )

    if has_mcp_toolset and not has_agent_tool_wrapper and has_tool_filter:
        b_ctx, s_line, a_ctx = _extract_line_context(lines, mcp_toolset_line)
        findings.append(
            AuditFinding(
                rule_id="MCPG-ADK-003",
                category=FindingCategory.MCP_CONTEXT_BLOAT_ROOT_TOOLSET,
                severity=FindingSeverity.MEDIUM,
                file_path=str(file_path),
                line_number=mcp_toolset_line,
                source_line=s_line,
                context_before=b_ctx,
                context_after=a_ctx,
                leak_type="Root Context Pollution",
                leaked_evidence="McpToolset bound without AgentTool wrapper",
                title="`McpToolset` attached directly to root agent instead of isolated `AgentTool`",
                description="Attaching `McpToolset` directly to root agent dumps raw file blobs into main history.",
                remediation="Wrap the MCP-enabled sub-agent with `AgentTool(agent=security_sub_agent)`.",
            )
        )

    return findings


def _inspect_package_json(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        raw = file_path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        data = json.loads(raw)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    has_workspaces = bool(data.get("workspaces"))
    root_name = str(data.get("name", ""))
    own_scope = root_name.split("/", 1)[0] + "/" if root_name.startswith("@") and "/" in root_name else ""

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for pkg, ver in deps.items():
            ver_str = str(ver).strip()
            # Skip npm/yarn/pnpm monorepo workspace sibling links (`"@scope/sibling": "*"` inside `workspaces`)
            if ver_str == "*" and has_workspaces and (
                (own_scope and pkg.startswith(own_scope)) or pkg.startswith("@modelcontextprotocol/")
            ):
                continue
            if ver_str in {"*", "latest", "next"} or ver_str.startswith("http:") or ver_str.startswith("git+http:"):
                ln, c1, c2 = _locate_token_in_lines(lines, f'"{pkg}"', fallback_key=pkg)
                b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-PKG-001",
                        category=FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
                        severity=FindingSeverity.HIGH,
                        file_path=str(file_path),
                        line_number=ln,
                        column_start=c1,
                        column_end=c2,
                        leak_type="Unpinned npm Dependency",
                        leaked_evidence=f'"{pkg}": "{ver_str}"',
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Unpinned or insecure dependency `{pkg}: {ver_str}` in `{section}`",
                        description=f"`{file_path.name}` declares `{pkg}` with mutable version `{ver_str}`.",
                        remediation=f"Pin `{pkg}` to a specific semantic version and commit a lockfile.",
                    )
                )
    return findings


def _inspect_pyproject_toml(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        raw = file_path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        data = tomllib.loads(raw)
    except Exception:
        return findings

    project = data.get("project", {})
    dep_lists: list[str] = list(project.get("dependencies", []))
    for opt_group in project.get("optional-dependencies", {}).values():
        if isinstance(opt_group, list):
            dep_lists.extend(opt_group)

    for spec in dep_lists:
        spec_str = str(spec).strip()
        if "http://" in spec_str or spec_str.endswith("*"):
            ln, c1, c2 = _locate_token_in_lines(lines, spec_str)
            b_ctx, s_line, a_ctx = _extract_line_context(lines, ln)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-PKG-002",
                    category=FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
                    severity=FindingSeverity.HIGH,
                    file_path=str(file_path),
                    line_number=ln,
                    column_start=c1,
                    column_end=c2,
                    leak_type="Insecure PyPI Dependency",
                    leaked_evidence=spec_str,
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title=f"Insecure or wildcard Python dependency `{spec_str}` in `pyproject.toml`",
                    description="Wildcard or cleartext HTTP dependency URL in `pyproject.toml`.",
                    remediation="Pin minimum/compatible release versions over HTTPS and commit `uv.lock`.",
                )
            )
    return findings


def _inspect_go_mod(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return findings

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("replace ") and ("../" in stripped or "./" in stripped):
            b_ctx, s_line, a_ctx = _extract_line_context(lines, idx)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-PKG-003",
                    category=FindingCategory.MCP_UNPINNED_SUPPLY_CHAIN,
                    severity=FindingSeverity.MEDIUM,
                    file_path=str(file_path),
                    line_number=idx,
                    column_start=1,
                    column_end=len(line) + 1,
                    leak_type="Local Go Module Override",
                    leaked_evidence=stripped,
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title="Local filesystem `replace` directive in `go.mod`",
                    description=f"`{stripped}` overrides module resolution with an unverified local directory.",
                    remediation="Remove local `replace` directives before merging to main.",
                )
            )
    return findings


def _inspect_js_ts_react_file(file_path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return findings

    for idx, line in enumerate(lines, start=1):
        secret_hit = _match_secret_type(line)
        if secret_hit:
            provider, literal = secret_hit
            pos = line.find(literal)
            c1 = (pos + 1) if pos != -1 else 1
            c2 = c1 + len(literal)
            b_ctx, s_line, a_ctx = _extract_line_context(lines, idx)
            findings.append(
                AuditFinding(
                    rule_id="MCPG-SEC-003",
                    category=FindingCategory.MCP_SECRET_EXPOSURE,
                    severity=FindingSeverity.CRITICAL,
                    file_path=str(file_path),
                    line_number=idx,
                    column_start=c1,
                    column_end=c2,
                    leak_type=f"Client-Bundle {provider}",
                    leaked_evidence=_mask_secret_preview(literal),
                    source_line=s_line,
                    context_before=b_ctx,
                    context_after=a_ctx,
                    title=f"Leaked {provider} in `{file_path.name}:{idx}`",
                    description=f"Detected plaintext {provider} in client-side file `{file_path.name}:{idx}`.",
                    remediation="Move secret to backend server environment variables; never ship keys in React bundles.",
                    requires_pro_escalation=True,
                )
            )

        for sink in ("dangerouslySetInnerHTML", "eval("):
            pos = line.find(sink)
            if pos != -1:
                c1 = pos + 1
                c2 = c1 + len(sink)
                b_ctx, s_line, a_ctx = _extract_line_context(lines, idx)
                findings.append(
                    AuditFinding(
                        rule_id="MCPG-SEC-004",
                        category=FindingCategory.MCP_PROMPT_INJECTION_SURFACE,
                        severity=FindingSeverity.HIGH,
                        file_path=str(file_path),
                        line_number=idx,
                        column_start=c1,
                        column_end=c2,
                        leak_type=f"Unescaped DOM/JS Sink (`{sink.rstrip('(')}`)",
                        leaked_evidence=line.strip()[:72],
                        source_line=s_line,
                        context_before=b_ctx,
                        context_after=a_ctx,
                        title=f"Unsafe `{sink.rstrip('(')}` execution sink in `{file_path.name}`",
                        description=(
                            f"Line {idx} column {c1} invokes `{sink.rstrip('(')}`, allowing untrusted HTML/CSS/LLM "
                            "output to execute scripts in the browser."
                        ),
                        remediation="Sanitize untrusted strings with DOMPurify or render as escaped React text.",
                    )
                )
                break

    return findings


def _resolve_git_changed_files(target_dir: Path) -> set[Path] | None:
    try:
        top_proc = subprocess.run(
            ["git", "-C", str(target_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if top_proc.returncode != 0:
            return None
        repo_root = Path(top_proc.stdout.strip()).resolve()
        changed: set[Path] = set()

        def _collect_diff_paths(args: list[str]) -> bool:
            p = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if p.returncode != 0:
                return False
            for line in p.stdout.splitlines():
                rel_p = line.strip().strip('"')
                if not rel_p:
                    continue
                full_p = (repo_root / rel_p).resolve()
                if full_p.is_file():
                    changed.add(full_p)
            return True

        # 1. Uncommitted / staged / untracked working-tree modifications
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            for raw in proc.stdout.splitlines():
                if len(raw) < 4:
                    continue
                rel = raw[3:].strip().strip('"')
                if " -> " in rel:
                    rel = rel.split(" -> ", 1)[1].strip('"')
                full = (repo_root / rel).resolve()
                if full.is_file():
                    changed.add(full)

        # 2. GitHub Actions pull_request base branch diff (when working tree is clean on checkout)
        base_ref = os.environ.get("GITHUB_BASE_REF", "").strip()
        if base_ref:
            if not _collect_diff_paths(["diff", "--name-only", f"origin/{base_ref}...HEAD"]):
                if not _collect_diff_paths(["diff", "--name-only", f"{base_ref}...HEAD"]):
                    _collect_diff_paths(["diff", "--name-only", "HEAD^1", "HEAD^2"])

        # 3. Local committed feature-branch fallback when working tree has 0 dirty files
        if not changed:
            if not _collect_diff_paths(["diff", "--name-only", "origin/main...HEAD"]):
                _collect_diff_paths(["diff", "--name-only", "HEAD~1..HEAD"])

        return changed
    except Exception:
        return None


def _walk_candidate_files(target_path: Path, git_diff_only: bool = False) -> list[Path]:
    if target_path.is_file():
        return [target_path]
    if not target_path.is_dir():
        return []

    git_filter = _resolve_git_changed_files(target_path) if git_diff_only else None

    collected: list[Path] = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        root_path = Path(root)
        for fname in sorted(files):
            fpath = (root_path / fname).resolve()
            if git_filter is not None and fpath not in git_filter:
                continue
            collected.append(fpath)
    return collected


def run_manifest_and_ast_prefilter(
    target: str | Path,
    git_diff_only: bool = False,
) -> PrefilterResult:
    """Execute Stage 1 deterministic pre-filtering (0 LLM tokens consumed)."""
    target_path = Path(target).resolve()
    result = PrefilterResult(target_path=str(target_path), llm_tokens_consumed=0)

    candidate_files = _walk_candidate_files(target_path, git_diff_only=git_diff_only)

    for fpath in candidate_files:
        name_lower = fpath.name.lower()
        rel_str = str(fpath)
        result.scanned_files.append(rel_str)

        if name_lower.startswith(".env"):
            env_findings = _inspect_env_file(fpath)
            if env_findings:
                result.deterministic_findings.extend(env_findings)
            else:
                result.skipped_clean_files.append(rel_str)
            continue

        if name_lower in {"package.json", "pyproject.toml", "go.mod"}:
            result.manifests_found.append(rel_str)
            manifest_findings: list[AuditFinding] = []
            if name_lower == "package.json":
                manifest_findings = _inspect_package_json(fpath)
            elif name_lower == "pyproject.toml":
                manifest_findings = _inspect_pyproject_toml(fpath)
            elif name_lower == "go.mod":
                manifest_findings = _inspect_go_mod(fpath)

            if manifest_findings:
                result.deterministic_findings.extend(manifest_findings)
            else:
                result.skipped_clean_files.append(rel_str)
            continue

        if name_lower.endswith(".json") and (
            "mcp" in name_lower or "claude_desktop_config" in name_lower
        ):
            result.mcp_configs_found.append(rel_str)
            file_findings = _inspect_mcp_config_file(fpath)
            if file_findings:
                result.deterministic_findings.extend(file_findings)
            else:
                result.skipped_clean_files.append(rel_str)
            continue

        if name_lower.endswith(".py"):
            result.agent_sources_found.append(rel_str)
            file_findings = _inspect_python_agent_ast(fpath)
            if file_findings:
                result.deterministic_findings.extend(file_findings)
            else:
                result.skipped_clean_files.append(rel_str)
            continue

        if (
            name_lower.endswith((".js", ".jsx", ".ts", ".tsx"))
            and not name_lower.endswith((".min.js", ".bundle.js", ".chunk.js"))
            and not re.search(r"-[a-z0-9]{6,}\.js$", name_lower)
        ):
            js_findings = _inspect_js_ts_react_file(fpath)
            if js_findings:
                result.deterministic_findings.extend(js_findings)
            else:
                result.skipped_clean_files.append(rel_str)
            continue

        result.skipped_clean_files.append(rel_str)

    return result
