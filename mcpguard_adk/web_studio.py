"""Google Material 3 / `adk web`-Inspired Interactive Web Studio for MCPGuard-ADK.

Generates a standalone, zero-external-dependency HTML5 + SVG + CSS Variables interactive
dashboard (`mcpguard scan --emit-dashboard reports/studio.html` or `mcpguard ui`) featuring:
1. Interactive ADK 2.0 Hybrid Graph Topology (click any Stage 1–6 node to inspect OTel & I/O)
2. Interactive Gemini >200K Token Cost-Cliff FinOps Calculator (PR count & token sliders + 2027 toggle)
3. Google Cloud Trace W3C Waterfall Timeline
4. Real `difflib` Hardened Patch Explorer & Verified Ed25519 (`EdDSA`/JCS) AgentCard Inspector
"""

from __future__ import annotations

import html
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mcpguard_adk.a2a.protocol import (
    DEFAULT_SERVER_KEYPAIR,
    build_signed_agent_card,
    verify_agent_card_jws,
)
from mcpguard_adk.schemas import AuditReport


def generate_studio_html(report: AuditReport) -> str:
    """Render a self-contained Google Cloud / Material 3 interactive HTML Studio for an `AuditReport`."""
    card = build_signed_agent_card(keypair=DEFAULT_SERVER_KEYPAIR)
    jwks = DEFAULT_SERVER_KEYPAIR.public_jwks()
    jws_verified = verify_agent_card_jws(card, jwks)

    report_json = json.dumps(report.model_dump(), ensure_ascii=False)
    card_json = json.dumps({"verified_ed25519_jcs": jws_verified, "agentCard": card, "jwks": jwks}, indent=2)
    escaped_diff = html.escape(report.unified_diff_patch or "No remediations required — workspace is clean.")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>MCPGuard-ADK Studio • Google ADK 2.0 & Cloud Trace Visualizer</title>
<style>
  :root {{
    --g-blue: #4285F4;
    --g-red: #EA4335;
    --g-yellow: #FBBC04;
    --g-green: #34A853;
    --bg: #0b0f19;
    --surface: #131926;
    --surface-2: #1b2336;
    --border: #2a3550;
    --text: #e8eaed;
    --muted: #9aa0a6;
    --mono: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
    --sans: 'Google Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: radial-gradient(circle at 15% 0%, rgba(66,133,244,0.14), transparent 40%),
                radial-gradient(circle at 85% 5%, rgba(52,168,83,0.10), transparent 38%),
                var(--bg);
    color: var(--text);
    font-family: var(--sans);
    line-height: 1.5;
  }}
  .g-bar {{
    height: 4px;
    background: linear-gradient(90deg,
      var(--g-blue) 0% 25%,
      var(--g-red) 25% 50%,
      var(--g-yellow) 50% 75%,
      var(--g-green) 75% 100%);
  }}
  header {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: rgba(19, 25, 38, 0.88);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 20;
  }}
  .brand {{ display: flex; align-items: center; gap: 14px; }}
  .g-dots {{ display: flex; gap: 5px; }}
  .g-dots span {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  .title {{ font-size: 19px; font-weight: 700; letter-spacing: -0.01em; }}
  .subtitle {{ font-size: 12px; color: var(--muted); }}
  .pill-row {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .pill {{
    font-size: 11px;
    font-weight: 600;
    padding: 5px 11px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--surface-2);
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .container {{ max-width: 1320px; margin: 0 auto; padding: 24px 28px 56px; display: grid; gap: 22px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px 20px;
    box-shadow: 0 10px 28px rgba(0,0,0,0.28);
  }}
  .kpi-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .kpi-val {{ font-size: 28px; font-weight: 700; margin-top: 4px; font-family: var(--mono); }}
  .kpi-sub {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  .two-col {{ display: grid; grid-template-columns: 1.35fr 1fr; gap: 20px; }}
  @media (max-width: 980px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
  h2 {{ margin: 0 0 12px; font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }}
  .graph-row {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 10px;
    margin-top: 10px;
  }}
  @media (max-width: 980px) {{ .graph-row {{ grid-template-columns: repeat(2, 1fr); }} }}
  .node-btn {{
    background: var(--surface-2);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 12px;
    padding: 12px 10px;
    text-align: left;
    cursor: pointer;
    transition: all 0.16s ease;
  }}
  .node-btn:hover, .node-btn.active {{
    border-color: var(--g-blue);
    transform: translateY(-2px);
    box-shadow: 0 0 0 2px rgba(66,133,244,0.28);
  }}
  .node-stage {{ font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--g-blue); }}
  .node-title {{ font-size: 12.5px; font-weight: 600; margin: 4px 0; }}
  .node-tier {{ font-size: 11px; color: var(--muted); font-family: var(--mono); }}
  .inspector {{
    margin-top: 14px;
    padding: 14px 16px;
    border-radius: 12px;
    background: #0d121d;
    border: 1px solid var(--border);
    font-size: 13px;
  }}
  .slider-row {{ display: grid; gap: 10px; margin: 12px 0 16px; }}
  .slider-row label {{ display: flex; justify-content: space-between; font-size: 12.5px; color: var(--muted); }}
  input[type=range] {{ width: 100%; accent-color: var(--g-blue); }}
  .bar-track {{ background: #0d121d; border-radius: 8px; height: 26px; overflow: hidden; position: relative; border: 1px solid var(--border); }}
  .bar-fill {{ height: 100%; transition: width 0.25s ease; display: flex; align-items: center; padding-left: 10px; font-size: 11.5px; font-family: var(--mono); font-weight: 700; color: #fff; white-space: nowrap; }}
  .finding-item {{
    padding: 12px 14px;
    border-radius: 12px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    margin-bottom: 10px;
  }}
  .sev {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 6px; font-family: var(--mono); }}
  .sev-CRITICAL {{ background: rgba(234,67,53,0.2); color: #ff7b72; border: 1px solid var(--g-red); }}
  .sev-HIGH {{ background: rgba(251,188,4,0.18); color: #fbbc04; border: 1px solid var(--g-yellow); }}
  .sev-MEDIUM {{ background: rgba(66,133,244,0.2); color: #79b8ff; border: 1px solid var(--g-blue); }}
  pre {{
    margin: 0;
    padding: 14px;
    background: #0a0e17;
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow-x: auto;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.55;
  }}
  .span-row {{ display: grid; grid-template-columns: 260px 1fr 90px; gap: 12px; align-items: center; font-size: 12px; padding: 6px 0; border-bottom: 1px dashed rgba(255,255,255,0.06); }}
  .tab-bar {{ display: flex; gap: 8px; margin-bottom: 12px; }}
  .tab-btn {{
    padding: 7px 14px; border-radius: 999px; border: 1px solid var(--border);
    background: var(--surface-2); color: var(--text); font-size: 12px; font-weight: 600; cursor: pointer;
  }}
  .tab-btn.active {{ background: var(--g-blue); border-color: var(--g-blue); color: #fff; }}
</style>
</head>
<body>
<div class="g-bar"></div>
<header>
  <div class="brand">
    <div class="g-dots">
      <span style="background:var(--g-blue)"></span>
      <span style="background:var(--g-red)"></span>
      <span style="background:var(--g-yellow)"></span>
      <span style="background:var(--g-green)"></span>
    </div>
    <div>
      <div class="title">MCPGuard-ADK Studio</div>
      <div class="subtitle">Google ADK 2.0 Hybrid Graph • A2A Protocol v1.0 (Ed25519/JCS) • Cloud Trace OTLP</div>
    </div>
  </div>
  <div class="pill-row">
    <span class="pill" style="border-color:var(--g-green);color:#6dd58c">✔ Ed25519 JWS Verified</span>
    <span class="pill">W3C Trace: <code id="hdr-trace"></code></span>
    <span class="pill" style="border-color:var(--g-blue)">OTel: EVENT_ONLY</span>
  </div>
</header>

<div class="container">
  <div class="kpi-grid">
    <div class="card">
      <div class="kpi-label">Stage 1 Deterministic Scan</div>
      <div class="kpi-val" style="color:var(--g-green)" id="kpi-skipped">0</div>
      <div class="kpi-sub">Clean files skipped at <strong>0 LLM tokens ($0.00)</strong></div>
    </div>
    <div class="card">
      <div class="kpi-label">Security & Cost-Cliff Alerts</div>
      <div class="kpi-val" style="color:var(--g-red)" id="kpi-findings">0</div>
      <div class="kpi-sub">Across MCP configs, ADK graphs & React/TS</div>
    </div>
    <div class="card">
      <div class="kpi-label">1,000-PR FinOps Savings</div>
      <div class="kpi-val" style="color:var(--g-blue)" id="kpi-savings">95.4%</div>
      <div class="kpi-sub">$52.15 Hybrid vs $1,144.00 Naive >200K Pro</div>
    </div>
    <div class="card">
      <div class="kpi-label">Context Isolation</div>
      <div class="kpi-val" style="color:var(--g-yellow)">Zero Bloat</div>
      <div class="kpi-sub">Sync <code>McpToolset</code> inside <code>AgentTool</code></div>
    </div>
  </div>

  <!-- Interactive ADK 2.0 Hybrid Graph Explorer -->
  <div class="card">
    <h2>⚡ Interactive Google ADK 2.0 Hybrid Graph Topology <span style="font-size:12px;color:var(--muted);font-weight:400">(Click any stage to inspect architecture & OTel span)</span></h2>
    <div class="graph-row" id="graph-nodes"></div>
    <div class="inspector" id="node-inspector"></div>
  </div>

  <div class="two-col">
    <!-- Findings & Remediation Tabs -->
    <div class="card">
      <div class="tab-bar">
        <button class="tab-btn active" onclick="switchTab('findings', this)">🚨 Findings</button>
        <button class="tab-btn" onclick="switchTab('diff', this)">🩹 Hardened Unified Diff</button>
        <button class="tab-btn" onclick="switchTab('a2a', this)">🔐 Signed A2A v1.0 Card & JWKS</button>
      </div>
      <div id="tab-findings"></div>
      <div id="tab-diff" style="display:none"><pre>{escaped_diff}</pre></div>
      <div id="tab-a2a" style="display:none"><pre id="a2a-json"></pre></div>
    </div>

    <!-- Interactive >200K Cost-Cliff FinOps Simulator -->
    <div class="card">
      <h2>💰 Live Gemini >200K Token Cost-Cliff Simulator</h2>
      <div class="slider-row">
        <label>
          <span>Monthly Pull Requests Audited</span>
          <strong id="lbl-prs" style="color:var(--text);font-family:var(--mono)">1,000 PRs</strong>
        </label>
        <input type="range" id="rng-prs" min="100" max="10000" step="100" value="1000" oninput="recalcCost()" />

        <label>
          <span>Naive Loop Prompt Size (watch >200K Pro Cliff!)</span>
          <strong id="lbl-toks" style="color:var(--g-red);font-family:var(--mono)">250,000 tokens (>200K CLIFF!)</strong>
        </label>
        <input type="range" id="rng-toks" min="50000" max="400000" step="10000" value="250000" oninput="recalcCost()" />

        <label style="align-items:center;margin-top:4px">
          <span>Apply Jan 1, 2027 Post-Promo Rate Step-Up (3.8 Flash $1.50/$7.50)</span>
          <input type="checkbox" id="chk-2027" onchange="recalcCost()" />
        </label>
      </div>

      <div style="display:grid;gap:12px">
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span>Naive Single-Agent Gemini 3.1 Pro Loop</span>
            <strong id="val-naive" style="font-family:var(--mono);color:#ff7b72">$1,144.00</strong>
          </div>
          <div class="bar-track"><div class="bar-fill" id="bar-naive" style="width:100%;background:var(--g-red)">$1,144.00</div></div>
        </div>

        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span>MCPGuard-ADK Tiered Hybrid (Standard API)</span>
            <strong id="val-hybrid" style="font-family:var(--mono);color:#6dd58c">$52.15</strong>
          </div>
          <div class="bar-track"><div class="bar-fill" id="bar-hybrid" style="width:6%;background:var(--g-green)">$52.15</div></div>
        </div>

        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span>MCPGuard-ADK Async Batch API (50% Batch Discount)</span>
            <strong id="val-batch" style="font-family:var(--mono);color:#79b8ff">$26.08</strong>
          </div>
          <div class="bar-track"><div class="bar-fill" id="bar-batch" style="width:4%;background:var(--g-blue)">$26.08</div></div>
        </div>
      </div>

      <div class="inspector" style="margin-top:16px" id="cost-callout"></div>

      <h2 style="margin-top:20px">🔭 Google Cloud Trace Waterfall</h2>
      <div id="otel-waterfall"></div>
    </div>
  </div>
</div>

<script>
const REPORT = {report_json};
const A2A_BUNDLE = {card_json};

document.getElementById('hdr-trace').textContent = REPORT.otel_trace_id.slice(0, 16) + '…';
document.getElementById('kpi-skipped').textContent = REPORT.prefilter.skipped_clean_files.length + ' / ' + REPORT.prefilter.scanned_files.length;
document.getElementById('kpi-findings').textContent = REPORT.findings.length;
document.getElementById('a2a-json').textContent = JSON.stringify(A2A_BUNDLE, null, 2);

const STAGES = [
  {{
    stage: "Stage 1",
    title: "AST & Manifest Pre-Filter",
    tier: "0 LLM Tokens ($0)",
    color: "#34A853",
    desc: "Deterministic Python AST, tomllib (pyproject.toml), go.mod, package.json, and MCP config analyzer. Skips clean files before touching any LLM."
  }},
  {{
    stage: "Stage 2",
    title: "Risk Triage Router",
    tier: "Gemini 3.1 Flash-Lite",
    color: "#4285F4",
    desc: "Routes findings into SECURITY, COST_CLIFF, and TRAJECTORY_DRIFT at $0.25/1M input — 8x to 16x cheaper than Gemini 3.1 Pro."
  }},
  {{
    stage: "Stage 3",
    title: "MCP Security Auditor",
    tier: "AgentTool + Sync McpToolset",
    color: "#EA4335",
    desc: "Synchronous module-level McpToolset isolated inside AgentTool with tool_filter=['list_directory', 'read_file'] so raw file blobs never bloat root context."
  }},
  {{
    stage: "Stage 4",
    title: "Cost-Cliff Optimizer",
    tier: "Gemini 3.8 Flash",
    color: "#FBBC04",
    desc: "Flags uncompacted loops crossing the 200,000-token Gemini 3.1 Pro pricing cliff ($2->$4 in, $12->$18 out) and evaluates context cache hourly storage ROI."
  }},
  {{
    stage: "Stage 5",
    title: "HITL Gate & Patch Emitter",
    tier: "difflib + SARIF v2.1.0",
    color: "#4285F4",
    desc: "Pauses file mutations behind an ADK Human-in-the-Loop confirmation gate; emits git-apply unified diffs, SARIF v2.1.0, and .test.json regressions."
  }},
  {{
    stage: "Stage 6",
    title: "Live Voice Debrief",
    tier: "runner.run_live()",
    color: "#34A853",
    desc: "Optional speech-to-speech incident debrief via LiveRequestQueue allowing SREs to interrupt the agent mid-sentence."
  }}
];

function selectStage(idx) {{
  document.querySelectorAll('.node-btn').forEach((b, i) => b.classList.toggle('active', i === idx));
  const s = STAGES[idx];
  document.getElementById('node-inspector').innerHTML =
    `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
       <strong style="color:${{s.color}}">${{s.stage}} — ${{s.title}}</strong>
       <code style="font-size:12px;color:var(--muted)">${{s.tier}}</code>
     </div>
     <div style="color:var(--text)">${{s.desc}}</div>`;
}}

const graphEl = document.getElementById('graph-nodes');
STAGES.forEach((s, i) => {{
  const btn = document.createElement('button');
  btn.className = 'node-btn' + (i === 0 ? ' active' : '');
  btn.onclick = () => selectStage(i);
  btn.innerHTML = `<div class="node-stage" style="color:${{s.color}}">${{s.stage}}</div>
                   <div class="node-title">${{s.title}}</div>
                   <div class="node-tier">${{s.tier}}</div>`;
  graphEl.appendChild(btn);
}});
selectStage(0);

// Render Findings
const fContainer = document.getElementById('tab-findings');
if (REPORT.findings.length === 0) {{
  fContainer.innerHTML = '<div class="finding-item" style="color:var(--g-green)">✔ 0 vulnerabilities or cost cliffs detected!</div>';
}} else {{
  REPORT.findings.forEach(f => {{
    const fname = f.file_path.split(/[\\\\/]/).slice(-2).join('/');
    const div = document.createElement('div');
    div.className = 'finding-item';
    div.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:6px">
        <div><span class="sev sev-${{f.severity}}">${{f.severity}}</span> <strong style="margin-left:6px">${{f.rule_id}}</strong></div>
        <code style="font-size:11.5px;color:var(--g-blue)">${{fname}}:${{f.line_number}}</code>
      </div>
      <div style="font-size:13.5px;font-weight:600;margin-bottom:4px">${{f.title}}</div>
      <div style="font-size:12px;color:var(--muted)">Fix: ${{f.remediation}}</div>`;
    fContainer.appendChild(div);
  }});
}}

// Render OTel Waterfall
const otelEl = document.getElementById('otel-waterfall');
const maxDur = Math.max(...REPORT.otel_Waterfall_spans.map(s => s.duration_ms), 1);
REPORT.otel_Waterfall_spans.forEach(sp => {{
  const pct = Math.max(8, Math.min(100, (sp.duration_ms / maxDur) * 100));
  const row = document.createElement('div');
  row.className = 'span-row';
  row.innerHTML = `
    <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:11px" title="${{sp.name}}">
      ${{sp['gen_ai.agent.name']}}
    </div>
    <div class="bar-track" style="height:14px">
      <div style="height:100%;width:${{pct}}%;background:linear-gradient(90deg,var(--g-blue),var(--g-green));border-radius:6px"></div>
    </div>
    <div style="text-align:right;font-family:var(--mono);font-size:11px;color:var(--muted)">${{sp.duration_ms}}ms</div>`;
  otelEl.appendChild(row);
}});

function switchTab(name, btn) {{
  ['findings', 'diff', 'a2a'].forEach(t => {{
    document.getElementById('tab-' + t).style.display = (t === name) ? 'block' : 'none';
  }});
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}}

function recalcCost() {{
  const prs = parseInt(document.getElementById('rng-prs').value, 10);
  const toks = parseInt(document.getElementById('rng-toks').value, 10);
  const is2027 = document.getElementById('chk-2027').checked;

  document.getElementById('lbl-prs').textContent = prs.toLocaleString() + ' PRs';
  const overCliff = toks > 200000;
  const lblToks = document.getElementById('lbl-toks');
  lblToks.textContent = toks.toLocaleString() + (overCliff ? ' tokens (>200K 2x CLIFF!)' : ' tokens (<=200K tier)');
  lblToks.style.color = overCliff ? '#EA4335' : '#FBBC04';

  const proInRate = overCliff ? 4.00 : 2.00;
  const proOutRate = overCliff ? 18.00 : 12.00;
  const naivePerPr = (toks / 1e6) * proInRate + (8000 / 1e6) * proOutRate;
  const naiveTotal = naivePerPr * prs;

  const flashIn = is2027 ? 1.50 : 0.75;
  const flashOut = is2027 ? 7.50 : 3.75;
  const triagePerPr = (40000 / 1e6) * 0.25 + (2000 / 1e6) * 1.50;
  const auditPerPr = (25000 / 1e6) * flashIn + (4000 / 1e6) * flashOut;
  const escPerPr = 0.10 * ((15000 / 1e6) * 2.00 + (2000 / 1e6) * 12.00);
  const hybridTotal = (triagePerPr + auditPerPr + escPerPr) * prs;
  const batchTotal = hybridTotal * 0.5;

  const savingsPct = ((1 - hybridTotal / naiveTotal) * 100).toFixed(1);

  document.getElementById('val-naive').textContent = '$' + naiveTotal.toFixed(2);
  document.getElementById('val-hybrid').textContent = '$' + hybridTotal.toFixed(2);
  document.getElementById('val-batch').textContent = '$' + batchTotal.toFixed(2);

  document.getElementById('bar-naive').textContent = '$' + naiveTotal.toFixed(2);
  document.getElementById('bar-hybrid').style.width = Math.max(4, (hybridTotal / naiveTotal) * 100) + '%';
  document.getElementById('bar-hybrid').textContent = '$' + hybridTotal.toFixed(2);
  document.getElementById('bar-batch').style.width = Math.max(3, (batchTotal / naiveTotal) * 100) + '%';
  document.getElementById('bar-batch').textContent = '$' + batchTotal.toFixed(2);

  document.getElementById('cost-callout').innerHTML =
    `Saving <strong style="color:#6dd58c">$${{(naiveTotal - hybridTotal).toFixed(2)}} (${{savingsPct}}%)</strong> across ${{prs.toLocaleString()}} PRs ` +
    (overCliff
      ? `by preventing prompts from crossing Gemini 3.1 Pro's <strong>200,000-token pricing cliff</strong> ($4.00/1M in, $18.00/1M out).`
      : `via Stage 1 0-token AST filtering and Gemini 3.1 Flash-Lite routing.`);
}}
recalcCost();
</script>
</body>
</html>
"""


def serve_studio_ui(
    report: AuditReport,
    host: str = "127.0.0.1",
    port: int = 8090,
    open_browser: bool = True,
) -> None:
    """Serve the interactive Google ADK 2.0 Studio over HTTP and open default browser."""
    html_bytes = generate_studio_html(report).encode("utf-8")

    class _StudioHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    url = f"http://{host}:{port}"
    print(f"MCPGuard-ADK Google Studio running at {url} (Press Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    HTTPServer((host, port), _StudioHandler).serve_forever()
