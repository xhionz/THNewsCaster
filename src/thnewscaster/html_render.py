"""Render a HuntPackage as a self-contained static HTML site.

We emit two files:

* ``index.html`` — a card grid of briefings, grouped by criticality and
  collapsed by default so the page is glanceable; each card expands to the
  full hypotheses / objectives / Sigma on click.
* ``hunt_package.json`` — the structured package (also linked from the page)

All CSS and JS is inlined so the page hosts cleanly on GitHub Pages with
no build step or runtime dependencies.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import analytics
from .analytics import TIERS as _TIERS, criticality as _criticality
from .intel import KILLCHAIN_STAGES
from .models import HuntBriefing, HuntPackage


_CSS = """
:root{
  --bg:#0b1020; --panel:#141b34; --panel2:#1b2548; --ink:#e7ecf7; --muted:#93a0c2;
  --accent:#7cc4ff; --border:#243160; --code:#0a1024;
  --crit:#ff5d6c; --high:#ff9f43; --med:#ffd866; --low:#5fd0c5;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif}
a{color:var(--accent);text-decoration:none}
header{padding:24px 24px 16px;border-bottom:1px solid var(--border);
  background:linear-gradient(180deg,#0e1430,#0b1020)}
header h1{margin:0 0 6px;font-size:23px}
header .meta{color:var(--muted);font-size:13px}
header .meta strong{color:var(--ink)}
main{max-width:1240px;margin:0 auto;padding:20px 24px 60px}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:6px 0 20px}
.controls input,.controls select{background:var(--panel);color:var(--ink);
  border:1px solid var(--border);padding:9px 12px;border-radius:9px;font:inherit}
.controls input{flex:1;min-width:240px}
.tier-h{display:flex;align-items:center;gap:10px;margin:26px 0 12px;font-size:14px;
  text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.tier-h .dot{width:11px;height:11px;border-radius:50%}
.tier-h .count{color:var(--muted);font-weight:400}
.dot.crit{background:var(--crit)} .dot.high{background:var(--high)}
.dot.med{background:var(--med)} .dot.low{background:var(--low)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;
  overflow:hidden;border-left:4px solid var(--border)}
.card.crit{border-left-color:var(--crit)} .card.high{border-left-color:var(--high)}
.card.med{border-left-color:var(--med)} .card.low{border-left-color:var(--low)}
.card>summary{list-style:none;cursor:pointer;padding:15px 16px;
  display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.card>summary::-webkit-details-marker{display:none}
.pill{order:1;font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;letter-spacing:.04em}
.score{order:2;margin-left:auto}
.card h2{order:3;flex-basis:100%}
.glance{order:4;flex-basis:100%}
.chips{order:5;flex-basis:100%}
.foot{order:6;flex-basis:100%}
.pill.crit{background:rgba(255,93,108,.16);color:var(--crit)}
.pill.high{background:rgba(255,159,67,.16);color:var(--high)}
.pill.med{background:rgba(255,216,102,.16);color:var(--med)}
.pill.low{background:rgba(95,208,197,.16);color:var(--low)}
.score{font-size:12px;color:var(--muted)}
.card h2{margin:0 0 8px;font-size:16px;line-height:1.35}
.glance{color:var(--muted);font-size:13.5px;margin:0 0 10px;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{font-size:11px;padding:2px 8px;border-radius:6px;border:1px solid var(--border);
  background:var(--panel2);color:var(--ink)}
.chip.kev{background:rgba(255,93,108,.16);color:var(--crit);border-color:transparent;font-weight:700}
.chip.cve{color:#ff9aa6} .chip.actor{color:#ffd09a} .chip.mal{color:#d3acff}
.foot{margin-top:11px;font-size:12px;color:var(--muted);display:flex;gap:10px}
.body{padding:0 16px 16px;border-top:1px solid var(--border);margin-top:4px}
.hyp{background:var(--panel2);border:1px solid var(--border);border-radius:10px;
  padding:12px 14px;margin:12px 0}
.hyp h3{margin:0 0 6px;font-size:14.5px;color:var(--accent)}
.hyp .conf{font-size:11px;color:var(--muted);margin-left:6px;font-weight:400}
.hyp .stmt{margin:6px 0;font-size:13.5px}
.obj{border-left:3px solid var(--border);padding:7px 11px;margin:7px 0;
  background:rgba(0,0,0,.18);border-radius:0 7px 7px 0;font-size:13px}
.obj.easy{border-left-color:var(--low)} .obj.medium{border-left-color:var(--med)}
.obj.hard{border-left-color:var(--crit)}
.obj h4{margin:0 0 3px;font-size:13px}
.obj .ml{color:var(--muted);font-size:11px;margin-bottom:4px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);
  border:1px solid var(--border);border-radius:6px;font-size:12px;color:#d6e1ff}
pre{padding:9px 11px;overflow-x:auto;white-space:pre-wrap}
details.sub>summary{cursor:pointer;color:var(--accent);font-size:12px;margin:6px 0}
.trace{color:var(--muted);font-size:11.5px;margin:8px 0 0}
/* compact one-line-per-briefing view */
main[data-view=compact] .grid{grid-template-columns:1fr;gap:5px}
main[data-view=compact] .card{border-radius:8px}
main[data-view=compact] .card>summary{padding:8px 12px;flex-wrap:nowrap;gap:10px}
main[data-view=compact] .card h2{order:2;flex:1;flex-basis:auto;margin:0;font-size:14px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
main[data-view=compact] .score{order:3}
main[data-view=compact] .glance,main[data-view=compact] .chips,main[data-view=compact] .foot{display:none}
.btn{background:var(--panel);color:var(--ink);border:1px solid var(--border);
  padding:9px 12px;border-radius:9px;font:inherit;cursor:pointer}
.btn.on{background:var(--accent);color:#06203a;border-color:var(--accent);font-weight:700}
.vbtns{display:flex;gap:4px}
/* dashboard */
.dash{display:grid;grid-template-columns:1fr;gap:14px;margin:4px 0 22px}
@media(min-width:900px){.dash{grid-template-columns:1.4fr 1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px 18px}
.panel h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.brief{font-size:15.5px;line-height:1.6}
.kc{display:flex;flex-direction:column;gap:5px;margin-top:8px}
.kcrow{display:flex;align-items:center;gap:8px;font-size:11px}
.kcrow .nm{flex:0 0 120px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kcrow .nm.zero{opacity:.45}
.kcrow .track{flex:1;height:12px;background:var(--panel2);border-radius:4px;overflow:hidden}
.kcrow .fill{height:100%;background:var(--accent);border-radius:4px}
.kcrow .ct{flex:0 0 22px;text-align:right;color:var(--ink)}
.matrix{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}
.q{border:1px solid var(--border);border-radius:8px;padding:9px;min-height:62px;
  display:flex;flex-direction:column;gap:4px;font-size:10px;color:var(--muted)}
.q.hot{border-color:var(--crit);background:rgba(255,93,108,.08)}
.q .qn{font-size:18px;font-weight:700;color:var(--ink)}
.q .ql{text-transform:uppercase;letter-spacing:.04em;line-height:1.3}
.mxcap{margin-top:7px;font-size:10px;color:var(--muted);text-align:center}
/* by data source */
#bysource{display:none}
.srcgroup{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  margin:10px 0;padding:6px 14px}
.srcgroup>summary{cursor:pointer;font-size:15px;font-weight:600;padding:9px 2px;list-style:none}
.srcgroup>summary::-webkit-details-marker{display:none}
.srcgroup .cnt{color:var(--muted);font-weight:400;font-size:13px;margin-left:6px}
.srow{border-left:3px solid var(--border);padding:8px 11px;margin:7px 0;
  background:rgba(0,0,0,.18);border-radius:0 7px 7px 0;font-size:13px}
.srow.crit{border-left-color:var(--crit)} .srow.high{border-left-color:var(--high)}
.srow.med{border-left-color:var(--med)} .srow.low{border-left-color:var(--low)}
.srow .meta{color:var(--muted);font-size:11px;margin:2px 0 4px}
main[data-view=source] .tier-section{display:none}
main[data-view=source] #bysource{display:block}
.hidden{display:none!important}
footer{color:var(--muted);font-size:12px;padding:30px 24px;text-align:center;
  border-top:1px solid var(--border)}
"""

_JS = """
(function(){
  const q=document.getElementById('q'), ms=document.getElementById('minScore');
  const crit=document.getElementById('critOnly');
  const vbtns=[...document.querySelectorAll('.vbtn')];
  const main=document.querySelector('main');
  const filterable=[...document.querySelectorAll('.card,.srow')];
  const sections=[...document.querySelectorAll('.tier-section')];
  const groups=[...document.querySelectorAll('.srcgroup')];
  let critOnly=false;
  function apply(){
    const n=(q.value||'').toLowerCase().trim(), m=parseInt(ms.value||'0',10);
    let shown=0;
    filterable.forEach(c=>{
      let ok=(!n||(c.dataset.haystack||'').includes(n))&&(parseInt(c.dataset.score||'0',10)>=m);
      if(critOnly && c.dataset.tier!=='crit') ok=false;
      c.classList.toggle('hidden',!ok);
      if(ok && c.classList.contains('card')) shown++;
    });
    sections.forEach(s=>s.classList.toggle('hidden',
      ![...s.querySelectorAll('.card')].some(c=>!c.classList.contains('hidden'))));
    groups.forEach(g=>g.classList.toggle('hidden',
      ![...g.querySelectorAll('.srow')].some(r=>!r.classList.contains('hidden'))));
    document.getElementById('shown').textContent=shown;
  }
  function setView(v){
    main.dataset.view=v;
    vbtns.forEach(b=>b.classList.toggle('on',b.dataset.v===v));
    try{localStorage.setItem('thnc_view',v);}catch(e){}
  }
  crit.addEventListener('click',()=>{critOnly=!critOnly;crit.classList.toggle('on',critOnly);apply();});
  vbtns.forEach(b=>b.addEventListener('click',()=>setView(b.dataset.v)));
  try{const v=localStorage.getItem('thnc_view'); if(v) setView(v);}catch(e){}
  q.addEventListener('input',apply); ms.addEventListener('input',apply); apply();
})();
"""


def _h(text: str) -> str:
    return html.escape(text or "", quote=True)


def _chip(text: str, cls: str = "") -> str:
    return f'<span class="chip {cls}">{_h(text)}</span>'


def _glance(b: HuntBriefing) -> str:
    """One-line 'what is this about' for the card face."""
    if b.article.summary:
        return b.article.summary
    if b.hypotheses and b.hypotheses[0].statement:
        return b.hypotheses[0].statement
    return "Security news item flagged for threat hunting."


def _card(b: HuntBriefing) -> str:
    a, e = b.article, b.extraction
    label, cls = _criticality(b)
    kev = any(t.startswith("kev:") for t in b.agent_trace)
    n_obj = sum(len(h.objectives) for h in b.hypotheses)

    haystack = " ".join([
        a.title, a.summary, a.source, " ".join(e.cves), " ".join(e.threat_actors),
        " ".join(e.malware_families), " ".join(e.products), " ".join(e.sectors),
        " ".join(e.mitre_techniques),
    ]).lower()

    p = [f'<details class="card {cls}" data-tier="{cls}" data-haystack="{_h(haystack)}" data-score="{b.scoring.score}">']

    # ---- glanceable face (flex row; reflows to compact view via CSS) ----
    p.append("<summary>")
    p.append(f"<span class='pill {cls}'>{label}</span>")
    p.append(f"<span class='score'>score {b.scoring.score} &middot; {len(b.hypotheses)} hyp &middot; {n_obj} obj</span>")
    p.append(f"<h2>{_h(a.title)}</h2>")
    p.append(f"<p class='glance'>{_h(_glance(b))}</p>")

    chips = []
    if kev:
        chips.append(_chip("CISA KEV", "kev"))
    chips += [_chip(c, "cve") for c in e.cves[:3]]
    chips += [_chip(x, "actor") for x in e.threat_actors[:2]]
    chips += [_chip(m, "mal") for m in e.malware_families[:2]]
    chips += [_chip(s) for s in e.sectors[:2]]
    if chips:
        p.append("<div class='chips'>" + "".join(chips) + "</div>")
    p.append(f"<div class='foot'><span>{_h(a.source)}</span><span>{_h(a.published)}</span></div>")
    p.append("</summary>")

    # ---- expanded detail ----
    p.append("<div class='body'>")
    if a.link:
        p.append(f"<p><a href='{_h(a.link)}' target='_blank' rel='noopener noreferrer'>Read source &rarr;</a></p>")
    if b.agent_trace:
        p.append(f"<p class='trace'><strong>agent:</strong> {' &rarr; '.join(_h(t) for t in b.agent_trace)}</p>")

    for h_ in b.hypotheses:
        p.append("<div class='hyp'>")
        p.append(f"<h3>{_h(h_.title)}<span class='conf'>{_h(h_.confidence)} confidence</span></h3>")
        p.append(f"<p class='stmt'>{_h(h_.statement)}</p>")
        for o in h_.objectives:
            p.append(f"<div class='obj {_h(o.difficulty)}'>")
            p.append(f"<h4>{_h(o.title)}</h4>")
            p.append(f"<div class='ml'>{_h(o.difficulty)} &middot; {o.points} pts &middot; {_h(', '.join(o.mitre_attack) or 'n/a')}</div>")
            p.append(f"<div>{_h(o.falsification_criterion)}</div>")
            p.append(f"<pre>{_h(o.suggested_query)}</pre>")
            p.append("</div>")
        if h_.sigma_rule.strip():
            p.append("<details class='sub'><summary>Sigma rule</summary>")
            p.append(f"<pre>{_h(h_.sigma_rule.strip())}</pre></details>")
        p.append("</div>")

    p.append("</div></details>")
    return "".join(p)


def _dashboard(pkg: HuntPackage) -> str:
    p = ["<div class='dash'>"]

    # Intel brief + kill-chain (left column)
    p.append("<div class='panel'>")
    if pkg.brief:
        p.append("<h3>Today's brief</h3>")
        p.append(f"<p class='brief'>{_h(pkg.brief)}</p>")
    cov = analytics.killchain_coverage(pkg)
    mx = max((c for _, c in cov), default=0) or 1
    p.append("<h3 style='margin-top:14px'>Kill-chain coverage</h3>")
    p.append("<div class='kc'>")
    for stage, n in cov:
        pct = int((n / mx) * 100) if n else 0
        zero = " zero" if not n else ""
        p.append("<div class='kcrow'>")
        p.append(f"<span class='nm{zero}'>{_h(stage)}</span>")
        p.append(f"<span class='track'><span class='fill' style='width:{pct}%'></span></span>")
        p.append(f"<span class='ct'>{n}</span>")
        p.append("</div>")
    p.append("</div></div>")

    # Likelihood x impact matrix (right column)
    quad = analytics.likelihood_impact(pkg)

    def cell(key, label, hot=False):
        items = quad[key]
        titles = " · ".join(b.article.title for b in items[:6])
        cls = "q hot" if hot else "q"
        return (f"<div class='{cls}' title='{_h(titles)}'>"
                f"<span class='qn'>{len(items)}</span><span class='ql'>{label}</span></div>")

    p.append("<div class='panel'><h3>Likelihood × impact</h3>")
    p.append("<div class='matrix'>")
    p.append(cell("hi_lo", "high likely · low impact"))
    p.append(cell("hi_hi", "high likely · high impact", hot=True))
    p.append(cell("lo_lo", "low likely · low impact"))
    p.append(cell("lo_hi", "low likely · high impact"))
    p.append("</div>")
    p.append("<div class='mxcap'>top row = more likely &middot; right column = higher impact</div>")
    p.append("</div>")

    p.append("</div>")
    return "".join(p)


def _by_source(pkg: HuntPackage) -> str:
    groups = analytics.objectives_by_source(pkg)
    p = ["<div id='bysource'>"]
    p.append("<p class='meta'>Every objective from today's news, grouped by the telemetry it needs — "
             "open one log source and work the list.</p>")
    for source, refs in groups:
        p.append("<details class='srcgroup' open>")
        p.append(f"<summary>{_h(source)}<span class='cnt'>{len(refs)} check(s)</span></summary>")
        for b, h_, o in refs:
            _, cls = _criticality(b)
            hay = f"{b.article.title} {h_.title} {o.title} {' '.join(b.extraction.cves)}".lower()
            p.append(f"<div class='srow {cls}' data-tier='{cls}' data-haystack='{_h(hay)}' "
                     f"data-score='{b.scoring.score}'>")
            p.append(f"<div>{_h(o.title)} <span class='meta'>— {_h(o.difficulty)} · {o.points} pts</span></div>")
            p.append(f"<div class='meta'>{_h(b.article.title)}</div>")
            p.append(f"<div>{_h(o.falsification_criterion)}</div>")
            p.append(f"<pre>{_h(o.suggested_query)}</pre>")
            p.append("</div>")
        p.append("</details>")
    p.append("</div>")
    return "".join(p)


def render_html(pkg: HuntPackage, *, json_filename: str = "hunt_package.json") -> str:
    # Group briefings by criticality tier (already score-sorted in the package).
    by_tier: dict[str, list[HuntBriefing]] = {label: [] for label, _, _ in _TIERS}
    for b in pkg.briefings:
        by_tier[_criticality(b)[0]].append(b)

    p: list[str] = []
    p.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    p.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    p.append("<title>THNewsCaster — Threat Hunting</title>")
    p.append(f"<style>{_CSS}</style></head><body>")

    p.append("<header><h1>THNewsCaster &middot; Threat Hunting</h1>")
    p.append("<div class='meta'>")
    p.append(f"Generated <strong>{_h(pkg.generated_at)}</strong> &middot; ")
    p.append(f"<strong>{pkg.total_seen}</strong> seen &middot; <strong>{len(pkg.briefings)}</strong> briefings &middot; ")
    p.append(f"<a href='{_h(json_filename)}'>JSON</a> &middot; <a href='iocs.csv'>IOCs</a> &middot; ")
    p.append("<a href='iocs_stix.json'>STIX</a> &middot; <a href='archive/index.html'>archive</a>")
    p.append("</div></header><main data-view='cards'>")

    if pkg.briefings:
        p.append(_dashboard(pkg))

    p.append("<div class='controls'>")
    p.append("<input id='q' type='search' placeholder='Filter by actor, CVE, malware, product…'>")
    p.append("<label class='meta' for='minScore'>Min score</label>")
    p.append("<select id='minScore'>")
    for v in (0, 45, 65, 85):
        sel = " selected" if v == 0 else ""
        p.append(f"<option value='{v}'{sel}>{v}</option>")
    p.append("</select>")
    p.append("<label class='meta'>View</label>")
    p.append("<div class='vbtns'>")
    for val, lbl in (("cards", "Cards"), ("compact", "Compact"), ("source", "By data source")):
        on = " on" if val == "cards" else ""
        p.append(f"<button class='btn vbtn{on}' data-v='{val}'>{lbl}</button>")
    p.append("</div>")
    p.append("<button id='critOnly' class='btn'>Critical only</button>")
    p.append(f"<span class='meta'>Showing <span id='shown'>{len(pkg.briefings)}</span> of {len(pkg.briefings)}</span>")
    p.append("</div>")

    p.append(_by_source(pkg))

    for label, cls, _ in _TIERS:
        items = by_tier[label]
        if not items:
            continue
        p.append("<section class='tier-section'>")
        p.append(f"<div class='tier-h'><span class='dot {cls}'></span>{label}"
                 f"<span class='count'>({len(items)})</span></div>")
        p.append("<div class='grid'>")
        for b in items:
            p.append(_card(b))
        p.append("</div></section>")

    if not pkg.briefings:
        p.append("<p class='meta'>No hunt-worthy articles in this run.</p>")

    p.append("</main><footer>")
    p.append("Built with <a href='https://github.com/xhionz/thnewscaster'>THNewsCaster</a>. ")
    p.append("Hypotheses are starting points — adapt queries to your SIEM and validate before acting.")
    p.append("</footer>")
    p.append(f"<script>{_JS}</script></body></html>")
    return "".join(p)


def write_site(pkg: HuntPackage, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hunt_package.json").write_text(json.dumps(pkg.to_dict(), indent=2, ensure_ascii=False))
    (out_dir / "index.html").write_text(render_html(pkg))
    # Disable Jekyll on GitHub Pages so files are served as-is.
    (out_dir / ".nojekyll").write_text("")
