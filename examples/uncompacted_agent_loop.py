"""Deliberately flawed ADK agent demonstrating anti-patterns caught by MCPGuard-ADK:
1. Asynchronous runtime initialization of `McpToolset` inside an `async def` function.
2. `McpToolset` instantiated without `tool_filter` or `AgentTool` isolation (>20 tool context bloat).
3. Uncompacted `while` loop on `gemini-3.1-pro-preview` that crosses the >200,000-token pricing cliff
   ($2.00 -> $4.00/1M input, $12.00 -> $18.00/1M output).
"""

from __future__ import annotations

from typing import Any


def McpToolset(**kwargs: Any) -> dict[str, Any]:  # noqa: N802
    return kwargs


async def bad_runtime_mcp_setup() -> dict[str, Any]:
    # Anti-pattern #1 & #2: async runtime init + missing tool_filter
    toolset = McpToolset(connection_params={"command": "npx", "args": ["-y", "server-everything"]})
    return toolset


def run_uncompacted_pro_loop(repo_blobs: list[str]) -> list[str]:
    history: list[str] = []
    # Anti-pattern #3: uncompacted loop on gemini-3.1-pro-preview crossing 200K token pricing cliff
    for blob in repo_blobs:
        model = "gemini-3.1-pro-preview"
        history.append(f"[{model}] Auditing raw blob ({len(blob)} chars): {blob}")
    return history
