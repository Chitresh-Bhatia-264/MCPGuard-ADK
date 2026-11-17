"""Reproducible 10-Repository Public MCP & Google ADK Benchmark + Gitleaks Comparison.

Clones 10 public MCP and Google ADK repositories (shallow `--depth 1`) into a temporary
directory, runs `MCPGuard-ADK` Stage 1 deterministic pre-filter alongside `gitleaks`
(if installed on `PATH`), and prints the side-by-side summary table.

Usage:
    python scripts/benchmark_public_repos.py
    python scripts/benchmark_public_repos.py --workdir ./reports/bench_cache
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcpguard_adk.nodes.prefilter import run_manifest_and_ast_prefilter

PUBLIC_BENCHMARK_REPOS: list[tuple[str, str]] = [
    ("cloudflare/mcp-server-cloudflare", "https://github.com/cloudflare/mcp-server-cloudflare.git"),
    ("evalstate/fast-agent", "https://github.com/evalstate/fast-agent.git"),
    ("google/adk-python", "https://github.com/google/adk-python.git"),
    ("idosal/git-mcp", "https://github.com/idosal/git-mcp.git"),
    ("jlowin/fastmcp", "https://github.com/jlowin/fastmcp.git"),
    ("lastmile-ai/mcp-agent", "https://github.com/lastmile-ai/mcp-agent.git"),
    ("mcp-use/mcp-use", "https://github.com/mcp-use/mcp-use.git"),
    ("modelcontextprotocol/inspector", "https://github.com/modelcontextprotocol/inspector.git"),
    ("modelcontextprotocol/python-sdk", "https://github.com/modelcontextprotocol/python-sdk.git"),
    ("modelcontextprotocol/servers", "https://github.com/modelcontextprotocol/servers.git"),
]


def _head_sha(repo_dir: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def _run_gitleaks_count(repo_dir: Path, gitleaks_bin: str | None) -> int | None:
    if not gitleaks_bin:
        return None
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)
    try:
        subprocess.run(
            [
                gitleaks_bin,
                "detect",
                "--source",
                str(repo_dir),
                "--no-git",
                "--max-target-megabytes",
                "2",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--exit-code",
                "0",
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if report_path.is_file():
            data = json.loads(report_path.read_text(encoding="utf-8") or "[]")
            return len(data)
    except Exception:
        return None
    finally:
        report_path.unlink(missing_ok=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run 10-repo MCPGuard-ADK vs Gitleaks benchmark.")
    parser.add_argument("--workdir", default="", help="Directory to cache shallow clones.")
    parser.add_argument("--gitleaks-bin", default="", help="Optional path to gitleaks binary.")
    args = parser.parse_args()

    workdir = Path(args.workdir).resolve() if args.workdir else Path(tempfile.mkdtemp(prefix="mcpguard_bench_"))
    workdir.mkdir(parents=True, exist_ok=True)
    gitleaks_bin = args.gitleaks_bin or shutil.which("gitleaks")

    print(f"Benchmark workspace: {workdir}")
    print(f"{'Repository':36s} | {'SHA':8s} | {'Files':>6s} | {'Time':>8s} | {'MCPGuard':>8s} | {'Gitleaks':>8s}")
    print("-" * 88)

    for slug, url in PUBLIC_BENCHMARK_REPOS:
        dest = workdir / slug.replace("/", "__")
        if not (dest / ".git").is_dir():
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
                capture_output=True,
                text=True,
                check=True,
            )
        sha = _head_sha(dest)
        t0 = time.perf_counter()
        pf = run_manifest_and_ast_prefilter(dest)
        ms = (time.perf_counter() - t0) * 1000.0
        gl_count = _run_gitleaks_count(dest, gitleaks_bin)
        gl_str = str(gl_count) if gl_count is not None else "n/a"
        print(f"{slug:36s} | {sha:8s} | {len(pf.scanned_files):6d} | {ms:6.1f}ms | {len(pf.deterministic_findings):8d} | {gl_str:>8s}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
