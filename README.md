# MCPGuard-ADK

**Open-source multi-agent Model Context Protocol (MCP) supply-chain, secret-leak, >200K token cost-cliff, and tool-trajectory auditor engineered on Google Agent Development Kit (ADK) 2.0, Agent2Agent (A2A) Protocol v1.0, and OpenTelemetry.**

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ▄████▄    ███╗   ███╗ ██████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██╔═══╝    ████╗ ████║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║  ███╗  ██╔████╔██║██║     ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║   ██║  ██║╚██╔╝██║██║     ██╔═══╝ ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╔╝  ██║ ╚═╝ ██║╚██████╗██║     ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ✦ ADK 2    ╚═╝     ╚═╝ ╚═════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
   Google ADK 2.0 Hybrid Graph • A2A v1.0 Ed25519/JCS • Gemini FinOps • Cloud Trace OTLP v0.3.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╭─ ✦ 0-TOK AST ──────╮  ╭─ ◆ RISK ALERTS ────╮  ╭─ ● FINOPS SAVED ───╮  ╭─ ▸ A2A v1.0 JWS ───╮
│ 1/3 Clean          │  │ 8 Findings         │  │ -95.4% Spend       │  │ Ed25519 OK         │
│ $0.00 (0 Tokens)   │  │ 3 Crit • 4 High    │  │ $52.15 vs $1,144   │  │ ID 97987d35a53     │
╰────────────────────╯  ╰────────────────────╯  ╰────────────────────╯  ╰────────────────────╯

╭── ◆ Security & >200K Cost-Cliff Alerts (Pinpoint Leak View) ────────────── ACTION REQUIRED ──╮
│  4.  CRITICAL  MCPG-SEC-003 ▸ vulnerable_mcp_config.json:11:41                               │
│     WHAT LEAKED : GitHub Personal Access Token: GITHUB_PERSONAL_ACCESS_TOKEN = ghp_1234••••  │
│     WHERE (FILE): examples/vulnerable_mcp_config.json (Line 11, Col 41)                      │
│     ┌── Source Pinpoint ──────────────────────────────────────────────────────────────────   │
│     │   10 │       "env": {                                                                  │
│     │   11 │         "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_1234567890abcdef1234567890abcdef1  │
│     │      │                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  │
│     │   12 │       },                                                                        │
│     └─────────────────────────────────────────────────────────────────────────────────────   │
│     ✔ FIX: Replace literal value with `${GITHUB_PERSONAL_ACCESS_TOKEN}` and load from `.env` │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

## 30-Second Quickstart ($0 Cost — Zero API Key Required for Stage 1)

Run on Python 3.11+ against your own codebase or the deliberately vulnerable `./examples` suite:

```bash
pip install -e ".[dev]"
python -m mcpguard_adk.cli scan ./examples --live
python -m mcpguard_adk.cli shell    # Interactive Gemini CLI / Claude Code style slash-command shell
```

---

## Hybrid Graph Architecture (ADK 2.0 + A2A v1.0 + OpenTelemetry)

Most multi-agent repositories fail production review because they burn LLM tokens on deterministic checks, attach `McpToolset` directly to the root orchestrator (dumping >20 tool schemas and raw file blobs into global history), and lack cross-framework protocol boundaries. **MCPGuard-ADK** solves all three using ADK 2.0 Graph Workflows:

```mermaid
flowchart TD
    A["Stage 1: AST, TOML, .env & Manifest Pre-Filter<br/>(Deterministic Code Node • 0 LLM Tokens)"] -->|Clean / Unchanged| Z["Skip LLM Invocation ($0.00)"]
    A -->|Anomalies Detected| B["Stage 2: Diff & Risk Triage Router<br/>(Gemini 3.1 Flash-Lite • $0.25/$1.50 per 1M)"]
    B -->|SECURITY| C["Stage 3: Security & MCP Auditor<br/>(AgentTool + Sync McpToolset [RO] • Gemini 3.8 Flash / 3.1 Pro)"]
    B -->|COST_CLIFF / TRAJECTORY_DRIFT| D["Stage 4: Cost & Trajectory Optimizer<br/>(AgentTool Isolated Context • Gemini 3.8 Flash)"]
    C --> E["Stage 5: HITL Confirmation Gate & Patch Emitter<br/>(difflib Patch + SARIF v2.1.0 + ADK .test.json)"]
    D --> E
    E -.->|--live flag| F["Stage 6: Live Voice Incident Debrief<br/>(runner.run_live() + LiveRequestQueue Barge-In)"]
```

### Key Production Engineering Guarantees
1. **Pinpoint Secret & Scope Leak Inspector (`WHAT` + `WHERE` + `^^^ ◂ HERE`)**: Identifies exact credential types (`Google Cloud / Gemini API Key`, `GitHub PAT`, `OpenAI / Anthropic Secret`, `AWS Access Key`, `Database URI`, `.env` leaks, `dangerouslySetInnerHTML`) with exact `line:column` carets in [`mcpguard_adk/nodes/prefilter.py`](mcpguard_adk/nodes/prefilter.py).
2. **Zero Context Bloat (`AgentTool` + Synchronous `McpToolset`)**: `McpToolset` is instantiated synchronously at module load inside [`mcpguard_adk/agent.py`](mcpguard_adk/agent.py) with `tool_filter=["list_directory", "read_file"]` strictly inside isolated `AgentTool` sub-agents.
3. **Real JSON-RPC 2.0 MCP Stdio Server (`serve-mcp`)**: Mount MCPGuard-ADK inside AI IDEs via `python -m mcpguard_adk.cli serve-mcp` ([`mcpguard_adk/mcp_server.py`](mcpguard_adk/mcp_server.py)).
4. **Asymmetric Ed25519 (`EdDSA`) + RFC 8785 (JCS) A2A v1.0 Server**: Serves `/.well-known/agent-card.json` and `/.well-known/jwks.json` with mathematical tamper detection, SSE chunked artifacts, `google.rpc.ErrorInfo`, and SSRF/`jti`-protected webhooks ([`mcpguard_adk/a2a/protocol.py`](mcpguard_adk/a2a/protocol.py)).
5. **Official OpenTelemetry SDK + Cloud Trace Safety**: Records real W3C 128-bit `traceId` / `resourceSpans` via `opentelemetry.sdk.trace` while enforcing `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT='EVENT_ONLY'` ([`mcpguard_adk/telemetry/otel.py`](mcpguard_adk/telemetry/otel.py)).

---

## Late-2026 Gemini Rate-Card & Cost-Cliff Benchmark

| Architecture Pattern | Assumed Workload per PR Audit | Published Rate Card Applied (per 1M Tokens) | Transparent Per-PR Math | Estimated Cost per 1,000 PR Audits |
| :--- | :--- | :--- | :--- | :--- |
| **Naive Single-Agent Loop (>200K Cliff)** | Uncompacted context reaches 250K in, 8K out on Gemini 3.1 Pro Preview | \$4.00 input / \$18.00 output (>200K tier) | `(0.25 × $4.00) + (0.008 × $18.00) = $1.144` | **\$1,144.00** |
| **Naive Single-Agent Loop (≤200K)** | Compaction holds context at 120K in, 8K out on Gemini 3.1 Pro Preview | \$2.00 input / \$12.00 output (≤200K tier) | `(0.12 × $2.00) + (0.008 × $12.00) = $0.336` | **\$336.00** |
| **MCPGuard-ADK Tiered Hybrid (2026 Promo)** | Stage 1 skips clean files (0 tokens); 3.1 Flash-Lite triage (40K in / 2K out); 3.8 Flash audit (25K in / 4K out); 3.1 Pro escalation on 10% of PRs | 3.1 Flash-Lite: \$0.25/\$1.50; 3.8 Flash: \$0.75/\$3.75; 3.1 Pro: \$2.00/\$12.00 | `$0.013 + $0.03375 + $0.0054 = $0.05215` | **\$52.15** *(84.5%–95.4% lower)* |
| **MCPGuard-ADK Async Batch (2027 Post-Promo)** | Overnight Batch API (50% off Standard; 3.8 Flash at \$1.50/\$7.50 list rate) | Batch: 3.1 Flash-Lite \$0.125/\$0.75; 3.8 Flash \$0.75/\$3.75; 3.1 Pro \$1.00/\$6.00 | `$0.0065 + $0.03375 + $0.0027 = $0.04295` | **\$42.95** |

---

## CLI Command Reference

```bash
# 1. Interactive Gemini CLI / Claude Code style terminal shell
python -m mcpguard_adk.cli shell

# 2. Full scan + Live Voice Debrief + Git Patch + SARIF v2.1.0 + OTLP Trace JSON
python -m mcpguard_adk.cli scan ./examples --live --approve-patches \
  --emit-sarif reports/mcpguard.sarif.json \
  --export-otel reports/otel_traces.json

# 3. CI/CD Pull Request Gate (scan only git-modified files and fail on CRITICAL/HIGH)
python -m mcpguard_adk.cli scan . --git-diff --fail-on high

# 4. Verify Ed25519 (EdDSA) + RFC 8785 (JCS) signed A2A v1.0 AgentCard & public JWKS
python -m mcpguard_adk.cli agent-card --jwks

# 5. Start MCP Stdio Server (for AI IDEs) or A2A v1.0 HTTP/SSE Server
python -m mcpguard_adk.cli serve-mcp
python -m mcpguard_adk.cli serve-a2a --host 127.0.0.1 --port 8080

# 6. Launch Google Material 3 Browser Studio
python -m mcpguard_adk.cli ui ./examples
```

---

## Deployment & Community

- **Cloud Run & CI/CD**: [`Dockerfile`](Dockerfile) • [`cloudbuild.yaml`](cloudbuild.yaml) • [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- **AI Editor Context**: [`llms.txt`](llms.txt)
- **Contributing & Starter Issues**: [`CONTRIBUTING.md`](CONTRIBUTING.md) • [`.github/ISSUE_TEMPLATE/good_first_issue.md`](.github/ISSUE_TEMPLATE/good_first_issue.md)
- **License**: [Apache License 2.0](LICENSE)

![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)
![Google ADK: v2.0.0](https://img.shields.io/badge/Google_ADK-v2.0.0-4285F4.svg)
![A2A Protocol: v1.0 Ed25519](https://img.shields.io/badge/A2A_Protocol-v1.0_Ed25519-EA4335.svg)
![OpenTelemetry: OTLP v1/traces](https://img.shields.io/badge/OpenTelemetry-OTLP_v1%2Ftraces-34A853.svg)

*If MCPGuard-ADK caught a misconfiguration or saved token spend, a star helps others discover it.*
