# Contributing to MCPGuard-ADK

Thank you for contributing to **MCPGuard-ADK**! This project is licensed under the **Apache License 2.0** and engineered on Google Agent Development Kit (ADK) 2.0, Agent2Agent (A2A) Protocol v1.0, and OpenTelemetry.

## Quick Local Setup ($0 Cost)

1. Clone the repository and install in editable mode (Python 3.11+):
   ```bash
   pip install -e ".[dev]"
   cp .env.example .env
   ```
2. Run the deterministic pre-filter, A2A v1.0 protocol, and rate-card test suite (requires **0 LLM tokens** and no credit card):
   ```bash
   pytest -v
   ```
3. To test live Gemini sub-agent escalation, add a free Google AI Studio `GEMINI_API_KEY` to `.env` (Gemini 3.8 Flash & 3.1 Flash-Lite free tier provides ~10 RPM and 1,500 RPD resetting at midnight PT).

## Architectural Guardrails for Pull Requests

1. **Never pay LLM tokens for deterministic checks**: New manifest, secret, or AST checks belong in Stage 1 (`mcpguard_adk/nodes/prefilter.py`).
2. **Zero Context Bloat (`AgentTool` + synchronous `McpToolset`)**: Never attach `McpToolset` directly to `root_agent` or initialize it inside an `async def` runtime function. Always instantiate `McpToolset` synchronously in `mcpguard_adk/agent.py` with explicit `tool_filter` limits and wrap sub-agents in `AgentTool`.
3. **A2A Protocol v1.0 Strict Compliance**:
   - Declare `streaming`, `pushNotifications`, and `extendedAgentCard` inside `AgentCapabilities` (never use deprecated `supportsExtendedAgentCard`).
   - Encode payloads with unified `Part` member-based `oneof` (`text`, `raw`, `url`, `data`) without `kind` discriminators.
   - Return errors as `google.rpc.Status` with `google.rpc.ErrorInfo` (`domain: "a2a-protocol.org"`).
4. **OpenTelemetry Safety**: Keep `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT='EVENT_ONLY'` and `ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS='false'`.

## License
By contributing to MCPGuard-ADK, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
