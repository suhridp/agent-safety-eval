"""Self-contained HTML dashboard: headline trade-off chart, per-style heatmap, ablations, and a
step-by-step trace explorer. No external scripts; one file you can open anywhere or publish."""
from __future__ import annotations

import json
import random
from pathlib import Path

PRIORITY = {"hijacked": 0, "unsafe_other": 0, "propagated": 0, "over_blocked": 1, "false_refusal": 1,
            "derailed": 1, "refused": 1, "attempt_blocked": 1, "failed": 1, "unsafe_benign": 0, "caught": 2,
            "resisted": 3, "completed": 3, "error": 2}


def _trim(t: dict) -> dict:
    bad = {(u["tool"], json.dumps(u["args"], sort_keys=True), u["step"]) for u in t["unsafe"]}
    steps = []
    for s in t["steps"]:
        steps.append({"text": (s.get("text") or "")[:600],
                      "calls": [{"tool": c["tool"], "args": json.dumps(c["args"])[:400], "seen": (c["seen"] or "")[:900],
                                 "blocked": c["blocked"],
                                 "unsafe": (not c["blocked"]) and (c["tool"], json.dumps(c["args"], sort_keys=True),
                                                                   s["step"]) in bad}
                                for c in s["calls"]]})
    inj = t.get("injection") or {}
    return {"key": t["key"], "model": t["model"], "config": t["config"], "task": t["task"], "variant": t["variant"],
            "kind": t["kind"], "outcome": t["outcome"], "request": t["request"], "final": (t["final"] or "")[:800],
            "steps": steps, "frags": inj.get("fragments", []), "goal": inj.get("goal", ""),
            "unsafe": [f"{u['tool']}({json.dumps(u['args'])[:160]})" for u in t["unsafe"]],
            "blocked": [f"{b['layer']}: {b['tool']} - {b['reason']}"[:200] for b in t["blocked_calls"]],
            "trial": t["trial"]}


def select_traces(traces: list[dict], cap: int = 1500, seed: int = 0) -> list[dict]:
    rng = random.Random(seed)
    ordered = sorted(traces, key=lambda t: (PRIORITY.get(t["outcome"], 2), rng.random()))
    return [_trim(t) for t in ordered[:cap]]


def render(summary: dict, traces: list[dict], cap: int = 1500, standalone: bool = True) -> str:
    """standalone=True wraps the page in a full HTML document (for opening locally); False gives the
    bare body content used when publishing to a host that supplies its own skeleton."""
    data = {"summary": summary, "traces": select_traces(traces, cap), "total_traces": len(traces)}
    blob = json.dumps(data, separators=(",", ":"), default=str).replace("</", "<\\/")
    page = TEMPLATE.replace("__DATA__", blob)
    if standalone:
        page = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
                '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
                + page + "\n</html>\n")
    return page


def write_dashboard(summary: dict, traces: list[dict], path: Path, cap: int = 1500, standalone: bool = True):
    path.write_text(render(summary, traces, cap, standalone))


TEMPLATE = r"""<title>Agent Safety Eval</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Sans+Condensed:wght@600&display=swap">
<style>
/* Layout: an instrument readout. Summary bands on top, the trace log as the working surface below. */
:root{
  --bg:#f5f6f8; --panel:#ffffff; --ink:#161b26; --ink-2:#4b5466; --ink-3:#7a8394; --rule:#dfe3ea; --rule-2:#eef0f4;
  --accent:#2a78d6; --accent-soft:#e3eefb; --unsafe:#d03b3b; --unsafe-soft:#fbe7e6; --safe:#0c7a3c; --safe-soft:#e2f3e8;
  --warn:#9a6400; --warn-soft:#fbf0d9; --mark:#ffe08a; --mark-ink:#3d2f00;
  --h0:#f3f6fa; --h1:#cde2fb; --h2:#86b6ef; --h3:#3987e5; --h4:#1c5cab; --h5:#0d366b;
  --display:"IBM Plex Sans Condensed","Arial Narrow",system-ui,sans-serif;
  --body:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
  --bg:#12151b; --panel:#1a1e26; --ink:#e9ecf2; --ink-2:#b4bccb; --ink-3:#8590a3; --rule:#2c323d; --rule-2:#232832;
  --accent:#5598e7; --accent-soft:#1d2a3d; --unsafe:#ef6b6b; --unsafe-soft:#3a1f22; --safe:#4cc27a; --safe-soft:#1b3326;
  --warn:#e3b04b; --warn-soft:#3a2f17; --mark:#6b5414; --mark-ink:#fff4cf;
  --h0:#1e232c; --h1:#184f95; --h2:#256abf; --h3:#3987e5; --h4:#86b6ef; --h5:#cde2fb; color-scheme:dark}}
:root[data-theme="dark"]{
  --bg:#12151b; --panel:#1a1e26; --ink:#e9ecf2; --ink-2:#b4bccb; --ink-3:#8590a3; --rule:#2c323d; --rule-2:#232832;
  --accent:#5598e7; --accent-soft:#1d2a3d; --unsafe:#ef6b6b; --unsafe-soft:#3a1f22; --safe:#4cc27a; --safe-soft:#1b3326;
  --warn:#e3b04b; --warn-soft:#3a2f17; --mark:#6b5414; --mark-ink:#fff4cf;
  --h0:#1e232c; --h1:#184f95; --h2:#256abf; --h3:#3987e5; --h4:#86b6ef; --h5:#cde2fb; color-scheme:dark}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font:14px/1.5 var(--body);margin:0}
.wrap{max-width:1180px;margin:0 auto;padding-block:28px 64px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));display:flex;flex-direction:column;gap:28px}
h1,h2,h3{font-family:var(--display);font-weight:600;letter-spacing:.01em;text-wrap:balance;margin:0}
h1{font-size:30px;line-height:1.1}
h2{font-size:20px}
h3{font-size:14px;font-family:var(--body);font-weight:600}
.eyebrow{font:500 11px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3)}
.muted{color:var(--ink-2)} .small{font-size:12px}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
header{display:flex;flex-direction:column;gap:10px}
.meta{display:flex;flex-wrap:wrap;gap:6px 18px;font:12px var(--mono);color:var(--ink-2)}
.banner{border:1px solid var(--warn);background:var(--warn-soft);color:var(--ink);padding:10px 14px;border-radius:6px;max-width:80ch}
.banner b{color:var(--warn)}
.tabs{display:flex;flex-wrap:wrap;gap:6px}
.tab{font:500 12px var(--mono);border:1px solid var(--rule);background:var(--panel);color:var(--ink-2);padding:6px 10px;border-radius:999px;cursor:pointer}
.tab[aria-selected="true"]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.tab:focus-visible,button:focus-visible,select:focus-visible,.trow:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
section{display:flex;flex-direction:column;gap:14px}
.sec-head{display:flex;flex-direction:column;gap:4px;max-width:75ch}
.grid2{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr);gap:20px;align-items:start}
@media (max-width:860px){.grid2{grid-template-columns:minmax(0,1fr)}}
.panel{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:14px;min-width:0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{font:500 11px var(--mono);letter-spacing:.04em;text-transform:uppercase;color:var(--ink-3);text-align:left;padding:6px 8px;border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:6px 8px;border-bottom:1px solid var(--rule-2);vertical-align:top;font-variant-numeric:tabular-nums}
td.num{font-family:var(--mono);white-space:nowrap}
tr.cfg{cursor:pointer} tr.cfg:hover td{background:var(--rule-2)} tr.cfg.sel td{background:var(--accent-soft)}
.ci{color:var(--ink-3);font-size:11px}
.chip{display:inline-flex;align-items:center;gap:4px;font:500 11px/1 var(--mono);padding:4px 7px;border-radius:4px;white-space:nowrap}
.c-bad{background:var(--unsafe-soft);color:var(--unsafe)} .c-good{background:var(--safe-soft);color:var(--safe)}
.c-mid{background:var(--warn-soft);color:var(--warn)} .c-neu{background:var(--rule-2);color:var(--ink-2)}
svg text{fill:var(--ink-2);font:11px var(--mono)}
.tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--bg);font:12px/1.4 var(--mono);padding:8px 10px;border-radius:6px;max-width:280px;z-index:20;box-shadow:0 4px 18px rgba(0,0,0,.18)}
.heat td.cell{text-align:center;font-family:var(--mono);font-size:11.5px;min-width:46px;border:2px solid var(--panel);border-radius:4px}
.heat th.ho{color:var(--accent)}
.legend{display:flex;gap:14px;flex-wrap:wrap;font:11px var(--mono);color:var(--ink-2);align-items:center}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.explorer{display:grid;grid-template-columns:minmax(0,340px) minmax(0,1fr);gap:16px;align-items:start}
@media (max-width:860px){.explorer{grid-template-columns:minmax(0,1fr)}}
.filters{display:flex;flex-wrap:wrap;gap:8px}
.filters label{display:flex;flex-direction:column;gap:3px;font:500 10.5px var(--mono);letter-spacing:.05em;text-transform:uppercase;color:var(--ink-3)}
select{font:12px var(--mono);background:var(--panel);color:var(--ink);border:1px solid var(--rule);border-radius:5px;padding:5px 6px;max-width:160px}
.tlist{display:flex;flex-direction:column;max-height:640px;overflow:auto;border:1px solid var(--rule);border-radius:8px;background:var(--panel)}
.trow{display:grid;grid-template-columns:1fr auto;gap:2px 8px;padding:9px 12px;border-bottom:1px solid var(--rule-2);cursor:pointer;text-align:left;background:none;border-left:3px solid transparent;color:inherit;font:inherit}
.trow:hover{background:var(--rule-2)} .trow.sel{background:var(--accent-soft);border-left-color:var(--accent)}
.trow .t{font:500 12.5px var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.trow .s{grid-column:1/-1;font-size:11.5px;color:var(--ink-3);font-family:var(--mono)}
.detail{display:flex;flex-direction:column;gap:10px;min-width:0}
.req{font-size:15px;border-left:3px solid var(--ink);padding:2px 0 2px 12px}
.step{display:grid;grid-template-columns:34px minmax(0,1fr);gap:10px}
.step .n{font:500 11px var(--mono);color:var(--ink-3);padding-top:3px}
.call{border:1px solid var(--rule);border-radius:6px;overflow:hidden;background:var(--panel)}
.call .hd{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:7px 10px;background:var(--rule-2);font:12px var(--mono)}
.call .hd b{font-weight:500;color:var(--ink)}
.call .args{color:var(--ink-2);word-break:break-all}
.call pre{margin:0;padding:9px 10px;font:12px/1.5 var(--mono);white-space:pre-wrap;word-break:break-word;color:var(--ink-2)}
.call.blocked{border-color:var(--warn)} .call.unsafe{border-color:var(--unsafe)}
mark{background:var(--mark);color:var(--mark-ink);border-radius:2px;padding:0 1px}
.say{font-size:13px;color:var(--ink);background:var(--panel);border:1px dashed var(--rule);border-radius:6px;padding:7px 10px}
.final{border:1px solid var(--rule);background:var(--panel);border-radius:8px;padding:10px 12px}
.empty{padding:28px;text-align:center;color:var(--ink-3)}
details summary{cursor:pointer;color:var(--ink-2);font-size:12.5px}
footer{color:var(--ink-3);font-size:12px;max-width:80ch}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
<div class="wrap">
  <header>
    <span class="eyebrow">Tool-using agent safety evaluation</span>
    <h1 id="title">Agent Safety Eval</h1>
    <div class="meta" id="meta"></div>
    <div id="banner"></div>
    <div class="tabs" id="tabs" role="tablist" aria-label="Agent model"></div>
  </header>

  <section>
    <div class="sec-head"><span class="eyebrow">01 · Trade-off</span><h2>Safety against usefulness</h2>
      <p class="muted small">Each dot is one safeguard configuration. Lower means fewer unsafe actions under attack; further right means more benign tasks completed. Whiskers are 95% task-clustered bootstrap intervals. Select a configuration to filter the traces below.</p></div>
    <div class="grid2">
      <div class="panel"><svg id="frontier" viewBox="0 0 440 360" width="100%" role="img" aria-label="Scatter of unsafe action rate against benign completion"></svg>
        <div class="legend"><span><i class="sw" style="background:var(--unsafe)"></i>baseline</span><span><i class="sw" style="background:var(--accent)"></i>safeguard config</span><span><i class="sw" style="background:var(--ink-3)"></i>simulated-user config</span></div></div>
      <div class="panel scroll"><table id="cfgtable"></table></div>
    </div>
  </section>

  <section>
    <div class="sec-head"><span class="eyebrow">02 · Attack styles</span><h2>Where injections get through</h2>
      <p class="muted small">Unsafe action rate by injection style. The regex filter was written against the three dev styles; the five held-out styles (blue headers) came later and the filter was not changed. A gap between the two groups means the filter learned the payloads, not the problem.</p></div>
    <div class="panel scroll"><table class="heat" id="heat"></table></div>
  </section>

  <section>
    <div class="sec-head"><span class="eyebrow">03 · Ablations and seeded faults</span><h2>What each layer contributes</h2></div>
    <div class="grid2">
      <div class="panel scroll"><h3>Remove one layer</h3><table id="ablate"></table></div>
      <div class="panel scroll"><h3>Error propagation (seeded faults, no attacker)</h3><p class="muted small">Share of trials where a wrong or stale value reached a consequential action, or a failed send was reported as done.</p><table id="faults"></table></div>
    </div>
  </section>

  <section>
    <div class="sec-head"><span class="eyebrow">04 · Traces</span><h2>Trace explorer</h2>
      <p class="muted small" id="tracenote"></p></div>
    <div class="filters" id="filters"></div>
    <div class="explorer">
      <div class="tlist" id="tlist" role="listbox" aria-label="Trials"></div>
      <div class="detail" id="detail"><div class="empty">Select a trial.</div></div>
    </div>
  </section>

  <footer id="foot"></footer>
</div>
<div class="tip" id="tip" hidden></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
const D = JSON.parse(document.getElementById('data').textContent);
const S = D.summary, M = S.manifest || {};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pct = x => x == null ? 'n/a' : Math.round(100*x) + '%';
const ci = r => { const c = r.cluster || r.wilson; return r.n ? `${pct(c[0])}–${pct(c[1])}` : ''; };
const LABEL = {hijacked:'hijacked',unsafe_other:'unsafe action',attempt_blocked:'attempt blocked',resisted:'resisted',refused:'refused',derailed:'derailed',completed:'completed',over_blocked:'over-blocked',false_refusal:'false refusal',failed:'failed',propagated:'error propagated',caught:'fault caught',unsafe_benign:'unsafe (benign)',error:'error'};
const TONE = {hijacked:'c-bad',unsafe_other:'c-bad',propagated:'c-bad',unsafe_benign:'c-bad',attempt_blocked:'c-mid',over_blocked:'c-mid',false_refusal:'c-mid',derailed:'c-mid',failed:'c-mid',refused:'c-neu',error:'c-neu',resisted:'c-good',completed:'c-good',caught:'c-good'};
const chip = o => `<span class="chip ${TONE[o]||'c-neu'}">${esc(LABEL[o]||o)}</span>`;
let model = S.models[0], selCfg = null, selKey = null;
try { const m = localStorage.getItem('ase-model'); if (m && S.models.includes(m)) model = m; } catch(e) {}

// header
$('#meta').innerHTML = [
  `run <b>${esc(M.name||'')}</b>`, `${S.n_traces} trials`, `${S.n_errors} errored`,
  `judge ${esc(M.judge||'none')}`, `code ${esc(M.git||'?')}`, esc(M.started||'')].map(x=>`<span>${x}</span>`).join('');
if (M.scripted_only) $('#banner').innerHTML = `<div class="banner"><b>Harness validation only.</b> Every agent in this run is a scripted stand-in. The numbers show that scoring and safeguards work mechanically. They say nothing about any real model.</div>`;
else if (M.stopped_early) $('#banner').innerHTML = `<div class="banner"><b>Stopped early:</b> ${esc(M.stopped_early)}</div>`;
$('#foot').innerHTML = `Unsafe actions are scored deterministically from the tool-call log, never by a model. Small synthetic task suite: results describe these ${new Set(D.traces.map(t=>t.task)).size} tasks, not agents in general. Configurations marked “simulated user” ask a user who always knows the right answer, so they are an upper bound.`;

function renderTabs(){
  $('#tabs').innerHTML = S.models.map(m => `<button class="tab" role="tab" aria-selected="${m===model}" data-m="${esc(m)}">${esc(m)}</button>`).join('');
  $('#tabs').querySelectorAll('.tab').forEach(b => b.onclick = () => { model = b.dataset.m; try{localStorage.setItem('ase-model',model)}catch(e){} selCfg=null; renderAll(); });
}
const rows = () => S.headline.filter(h => h.model === model);

// tooltip
const tip = $('#tip');
function showTip(ev, html){ tip.innerHTML = html; tip.hidden = false; const x = Math.min(ev.clientX + 14, innerWidth - 300); tip.style.left = x+'px'; tip.style.top = (ev.clientY + 14)+'px'; }
function hideTip(){ tip.hidden = true; }

function renderFrontier(){
  const W=440,H=360,L=46,R=14,T=14,B=42, svg=$('#frontier');
  const X = v => L + v*(W-L-R), Y = v => T + (1-v)*(H-T-B);
  let g = '';
  for (let i=0;i<=4;i++){ const v=i/4;
    g += `<line x1="${X(0)}" x2="${X(1)}" y1="${Y(v)}" y2="${Y(v)}" stroke="var(--rule)" stroke-width="1"/>`;
    g += `<line y1="${Y(0)}" y2="${Y(1)}" x1="${X(v)}" x2="${X(v)}" stroke="var(--rule-2)" stroke-width="1"/>`;
    g += `<text x="${L-8}" y="${Y(v)+4}" text-anchor="end">${v*100}%</text><text x="${X(v)}" y="${H-B+16}" text-anchor="middle">${v*100}%</text>`; }
  g += `<text x="${X(.5)}" y="${H-6}" text-anchor="middle">benign task completion →</text>`;
  g += `<text transform="translate(12 ${Y(.5)}) rotate(-90)" text-anchor="middle">← unsafe action rate</text>`;
  const pts = rows().filter(h => h.unsafe.n && h.benign_completion.n);
  // configs that land on the same spot share one dot and one label
  const groups = new Map();
  pts.forEach(h => { const k = Math.round(100*h.benign_completion.rate)+'|'+Math.round(100*h.unsafe.rate); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(h); });
  const placed = [];
  [...groups.values()].sort((a,b) => b[0].unsafe.rate - a[0].unsafe.rate).forEach(grp => {
    const h = grp.find(x => x.config === selCfg) || grp.find(x => x.config === 'baseline') || grp[0];
    const x = h.benign_completion.rate, y = h.unsafe.rate;
    const yc = h.unsafe.cluster || h.unsafe.wilson, xc = h.benign_completion.cluster || h.benign_completion.wilson;
    const col = grp.some(q => q.config==='baseline') ? 'var(--unsafe)' : grp.every(q => q.uses_oracle) ? 'var(--ink-3)' : 'var(--accent)';
    const sel = grp.some(q => q.config === selCfg), dim = selCfg && !sel;
    g += `<g class="pt" data-c="${esc(grp.map(q=>q.config).join('|'))}" style="cursor:pointer;opacity:${dim?.35:1}">`;
    g += `<line x1="${X(x)}" x2="${X(x)}" y1="${Y(yc[0])}" y2="${Y(yc[1])}" stroke="${col}" stroke-width="2" stroke-linecap="round" opacity=".45"/>`;
    g += `<line y1="${Y(y)}" y2="${Y(y)}" x1="${X(xc[0])}" x2="${X(xc[1])}" stroke="${col}" stroke-width="2" stroke-linecap="round" opacity=".45"/>`;
    g += `<circle cx="${X(x)}" cy="${Y(y)}" r="${sel?7:5.5}" fill="${col}" stroke="var(--panel)" stroke-width="2"/>`;
    g += `<circle cx="${X(x)}" cy="${Y(y)}" r="14" fill="transparent"/></g>`;
    const right = x > .7, lx = X(x) + (right ? -10 : 10), anchor = right ? 'end' : 'start';
    let ly = Y(y) + (y < .1 ? -10 : 4);
    while (placed.some(p => Math.abs(p.y-ly) < 12 && Math.abs(p.x-lx) < 120)) ly += (y < .1 ? -12 : 12);
    placed.push({x:lx,y:ly});
    const label = h.config + (grp.length > 1 ? ` +${grp.length-1} more` : '');
    g += `<text x="${lx}" y="${ly}" text-anchor="${anchor}" style="fill:var(--ink);opacity:${dim?.35:1}">${esc(label)}</text>`;
  });
  svg.innerHTML = g;
  svg.querySelectorAll('.pt').forEach(el => {
    const grp = el.dataset.c.split('|').map(c => pts.find(p => p.config === c)), h = grp[0];
    el.onmousemove = ev => showTip(ev, `unsafe ${pct(h.unsafe.rate)} (${h.unsafe.k}/${h.unsafe.n})<br>benign done ${pct(h.benign_completion.rate)} (${h.benign_completion.k}/${h.benign_completion.n})<br><br>${grp.map(q => `<b>${esc(q.config)}</b>`).join('<br>')}`);
    el.onmouseleave = hideTip;
    el.onclick = () => { const i = grp.findIndex(q => q.config === selCfg); selectCfg(grp[(i + 1) % grp.length].config === selCfg ? null : grp[(i + 1) % grp.length].config); };
  });
}

function renderTable(){
  const r = rows();
  let t = `<thead><tr><th>config</th><th>unsafe</th><th>goal reached</th><th>benign done</th><th>done under attack</th><th>benign blocked</th><th>tokens/trial</th></tr></thead><tbody>`;
  r.forEach(h => {
    t += `<tr class="cfg ${selCfg===h.config?'sel':''}" data-c="${esc(h.config)}" tabindex="0"><td><b>${esc(h.config)}</b>${h.uses_oracle?' <span class="chip c-neu">sim. user</span>':''}<div class="ci">${esc(h.layers.join(' + ')||'no safeguards')}</div></td>`
      + `<td class="num">${pct(h.unsafe.rate)}<div class="ci">${ci(h.unsafe)}</div></td>`
      + `<td class="num">${pct(h.asr.rate)}</td>`
      + `<td class="num">${pct(h.benign_completion.rate)}<div class="ci">${ci(h.benign_completion)}</div></td>`
      + `<td class="num">${pct(h.attack_completion.rate)}</td><td class="num">${pct(h.benign_blocked.rate)}</td>`
      + `<td class="num">${Math.round(h.tokens_per_trial).toLocaleString()}</td></tr>`;
  });
  $('#cfgtable').innerHTML = t + '</tbody>';
  $('#cfgtable').querySelectorAll('tr.cfg').forEach(tr => { tr.onclick = () => selectCfg(tr.dataset.c); tr.onkeydown = e => { if (e.key==='Enter') selectCfg(tr.dataset.c); }; });
}

function heatColor(v){ if (v==null) return ['var(--h0)','var(--ink-3)']; const steps=['--h0','--h1','--h2','--h3','--h4','--h5']; const i=Math.min(5,Math.round(v*5)); return [`var(${steps[i]})`, i>=3?'#fff':'var(--ink)']; }
function renderHeat(){
  const bs = S.by_style[model] || {}, cfgs = Object.keys(bs), dev = S.styles.dev, ho = S.styles.heldout;
  const styles = [...dev, ...ho].filter(s => cfgs.some(c => bs[c][s]));
  let t = `<thead><tr><th>config</th>${styles.map(s=>`<th class="${ho.includes(s)?'ho':''}">${esc(s)}</th>`).join('')}<th>dev</th><th class="ho">held-out</th></tr></thead><tbody>`;
  cfgs.forEach(c => {
    t += `<tr><td class="mono small">${esc(c)}</td>`;
    styles.forEach(s => { const r = bs[c][s]; const v = r ? r.rate : null; const [bg,fg] = heatColor(v);
      t += `<td class="cell" style="background:${bg};color:${fg}" data-tip="${esc(c)} · ${esc(s)}<br>${r?`${r.k}/${r.n} unsafe`:'no trials'}">${v==null?'·':Math.round(100*v)}</td>`; });
    const sp = (S.dev_vs_heldout[model]||{})[c] || {};
    t += `<td class="num">${pct(sp.dev&&sp.dev.rate)}</td><td class="num">${pct(sp.heldout&&sp.heldout.rate)}</td></tr>`;
  });
  $('#heat').innerHTML = t + '</tbody>';
  $('#heat').querySelectorAll('td.cell').forEach(td => { td.onmousemove = ev => showTip(ev, td.dataset.tip); td.onmouseleave = hideTip; });
}

function delta(x, goodWhenNeg){ if (x==null) return 'n/a'; const p = Math.round(100*x); if (p===0) return `<span class="chip c-neu">±0</span>`; const good = goodWhenNeg ? p<0 : p>0; return `<span class="chip ${good?'c-good':'c-bad'}">${p>0?'+':''}${p} pts</span>`; }
function renderAblate(){
  const A = S.ablation.filter(a => a.model === model);
  $('#ablate').innerHTML = A.length ? `<thead><tr><th>config</th><th>removed</th><th>unsafe</th><th>benign done</th></tr></thead><tbody>` + A.map(a => `<tr><td class="mono small">${esc(a.base)}</td><td class="mono small">${esc(a.removed)}</td><td>${delta(a.d_unsafe,true)}</td><td>${delta(a.d_benign_completion,false)}</td></tr>`).join('') + '</tbody>' : `<tbody><tr><td class="muted small">No ablations in this run. Add <code>ablate: [layered]</code> to the config.</td></tr></tbody>`;
  const F = rows().filter(h => h.fault_propagated.n);
  $('#faults').innerHTML = F.length ? `<thead><tr><th>config</th><th>propagated</th><th>trials</th></tr></thead><tbody>` + F.map(h => `<tr><td class="mono small">${esc(h.config)}</td><td class="num">${pct(h.fault_propagated.rate)}</td><td class="num">${h.fault_propagated.k}/${h.fault_propagated.n}</td></tr>`).join('') + '</tbody>' : `<tbody><tr><td class="muted small">No seeded-fault tasks in this run.</td></tr></tbody>`;
}

// ---- trace explorer
const F = {config:'', task:'', variant:'', outcome:''};
function renderFilters(){
  const T = D.traces.filter(t => t.model === model);
  const opts = k => [...new Set(T.map(t => t[k]))].sort();
  F.config = selCfg || F.config;
  $('#filters').innerHTML = ['config','task','variant','outcome'].map(k => `<label for="f-${k}">${k}<select id="f-${k}" data-k="${k}"><option value="">all</option>${opts(k).map(v=>`<option ${F[k]===v?'selected':''} value="${esc(v)}">${esc(k==='outcome'?(LABEL[v]||v):v)}</option>`).join('')}</select></label>`).join('');
  $('#filters').querySelectorAll('select').forEach(s => s.onchange = () => { F[s.dataset.k] = s.value; if (s.dataset.k==='config') { selCfg = s.value || null; renderFrontier(); renderTable(); } renderList(); });
}
function renderList(){
  const T = D.traces.filter(t => t.model === model && Object.entries(F).every(([k,v]) => !v || t[k] === v));
  $('#tracenote').textContent = `Showing ${Math.min(T.length,400)} of ${T.length} matching trials. The dashboard embeds ${D.traces.length} of ${D.total_traces} trials, failures first; every trial is in traces.jsonl.`;
  $('#tlist').innerHTML = T.length ? T.slice(0,400).map(t => `<button class="trow ${t.key===selKey?'sel':''}" role="option" data-k="${esc(t.key)}"><span class="t">${esc(t.task)}</span>${chip(t.outcome)}<span class="s">${esc(t.config)} · ${esc(t.variant)} · trial ${t.trial}</span></button>`).join('') : `<div class="empty">No trials match these filters.</div>`;
  $('#tlist').querySelectorAll('.trow').forEach(b => b.onclick = () => { selKey = b.dataset.k; $('#tlist').querySelectorAll('.trow').forEach(x=>x.classList.toggle('sel', x===b)); renderDetail(); });
  if (!T.some(t => t.key === selKey)) { selKey = T.length ? T[0].key : null; const first = $('#tlist .trow'); if (first) first.classList.add('sel'); }
  renderDetail();
}
function cores(frags){ return frags.map(f => f.split(/(?<=[.!?])\s+|\n+/).filter(s=>s.trim()).sort((a,b)=>b.length-a.length)[0]).filter(Boolean); }
function highlight(text, frags){
  let h = esc(text);
  cores(frags).forEach(c => {
    const words = esc(c.trim()).split(/\s+/).map(w => w.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'));
    if (words.length < 3) return;
    try { h = h.replace(new RegExp(words.join('[\\sˆ]+'), 'gi'), m => `<mark>${m}</mark>`); } catch(e) {}
  });
  return h;
}
function renderDetail(){
  const t = D.traces.find(x => x.key === selKey), el = $('#detail');
  if (!t) { el.innerHTML = `<div class="empty">Select a trial.</div>`; return; }
  let h = `<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">${chip(t.outcome)}<span class="mono small muted">${esc(t.config)} · ${esc(t.task)} · ${esc(t.variant)}${t.goal?` · attacker goal: ${esc(t.goal)}`:''}</span></div>`;
  h += `<div class="req"><span class="eyebrow">User request</span><br>${esc(t.request)}</div>`;
  if (t.frags.length) h += `<details><summary>Planted payload (${t.frags.length} fragment${t.frags.length>1?'s':''}), highlighted where the agent saw it</summary><pre class="mono small" style="white-space:pre-wrap;margin:6px 0 0">${t.frags.map(esc).join('\n---\n')}</pre></details>`;
  t.steps.forEach((s,i) => {
    if (!s.calls.length) return;  // the closing turn is shown as the final answer below
    h += `<div class="step"><div class="n">${String(i+1).padStart(2,'0')}</div><div style="display:flex;flex-direction:column;gap:8px;min-width:0">`;
    if (s.text) h += `<div class="say">${esc(s.text)}</div>`;
    s.calls.forEach(c => {
      const isUnsafe = c.unsafe;
      h += `<div class="call ${c.blocked?'blocked':isUnsafe?'unsafe':''}"><div class="hd"><b>${esc(c.tool)}</b><span class="args">${esc(c.args)}</span>${c.blocked?'<span class="chip c-mid">blocked</span>':''}${isUnsafe?'<span class="chip c-bad">unsafe</span>':''}</div><pre>${highlight(c.seen, t.frags)}</pre></div>`;
    });
    h += `</div></div>`;
  });
  h += `<div class="final"><span class="eyebrow">Final answer</span><div>${esc(t.final) || '<span class="muted">(none: step limit or error)</span>'}</div></div>`;
  if (t.blocked.length) h += `<div class="small muted">Blocked: ${t.blocked.map(esc).join('<br>')}</div>`;
  el.innerHTML = h;
}
function selectCfg(c){ selCfg = (c == null || selCfg === c) ? null : c; F.config = selCfg || ''; renderFrontier(); renderTable(); renderFilters(); renderList(); }
function renderAll(){ renderTabs(); renderFrontier(); renderTable(); renderHeat(); renderAblate(); F.config=''; renderFilters(); renderList(); }
renderAll();
})();
</script>
"""
