---
name: "Good First Issue"
about: "Approachable starter ticket with clear acceptance criteria for new contributors"
title: "[Good First Issue]: "
labels: ["good first issue", "help wanted"]
---

## Summary
Describe the deterministic rule, MCP server check, or ADK evaluation fixture to add.

## Curated Starter Ideas (Pick One!)
1. **`MCPG-SEC-006` (`go.mod` & `pyproject.toml` MCP SDK version checker)**: Flag outdated `mcp` / `google-adk` SDK pins in Stage 1 (`mcpguard_adk/nodes/prefilter.py`) with 0 LLM tokens.
2. **Cursor & Windsurf IDE config auto-discovery**: Extend `run_manifest_and_ast_prefilter` to auto-discover `.windsurf/mcp.json` and `.vscode/mcp.json` alongside `.cursor/mcp.json` and `claude_desktop_config.json`.
3. **Gemini 4 Argon/Carbon Dec 1, 2026 Step-Up CLI Flag**: Add `--pricing-window=2026-dec` to `mcpguard cost-sim` to compare November 2026 introductory rates ($2/$10) against December 1, 2026 rates ($4/$20-$22).
4. **Additional `.evalset.json` User Simulation Personas**: Add an adversarial prompt-injection persona in `evals/mcpguard_suite.evalset.json`.

## Acceptance Criteria
- [ ] Unit test added in `tests/` passing `pytest -v`
- [ ] Zero LLM tokens consumed in Stage 1 deterministic pre-filter
- [ ] Adheres to Apache 2.0 license and `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT='EVENT_ONLY'`
