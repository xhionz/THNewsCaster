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

from .models import HuntBriefing, HuntPackage


# Criticality tiers, highest first. (label, css class, min score)
_TIERS = [
    ("Critical", "crit", 85),
    ("High", "high", 65),
    ("Medium", "med", 45),
    ("Low", "low", 0),
]


def _criticality(b: HuntBriefing) -> tuple[str, str]:
    score = b.scoring.score
    kev = any(t.startswith("kev:") for t in b.agent_trace)
    # Actively-exploited (CISA KEV) never ranks below High.
    if kev and score < 65:
        score = 65
    for label, cls, threshold in _TIERS:
        if score >= threshold:
            return label, cls
    return "Low", "low"


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
.card>summary{list-style:none;cursor:pointer;padding:15px 16px;display:block}
.card>summary::-webkit-details-marker{display:none}
.card .toprow{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px}
.pill{font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;letter-spacing:.04em}
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
.hidden{display:none!important}
footer{color:var(--muted);font-size:12px;padding:30px 24px;text-align:center;
  border-top:1px solid var(--border)}
"""

_JS = """
(function(){
  const q=document.getElementById('q'), ms=document.getElementById('minScore');
  const cards=[...document.querySelectorAll('.card')];
  const sections=[...document.querySelectorAll('.tier-section')];
  function apply(){
    const n=(q.value||'').toLowerCase().trim(), m=parseInt(ms.value||'0',10);
    let shown=0;
    cards.forEach(c=>{
      const ok=(!n||(c.dataset.haystack||'').includes(n))&&(parseInt(c.dataset.score||'0',10)>=m);
      c.classList.toggle('hidden',!ok); if(ok)shown++;
    });
    sections.forEach(s=>{
      const vis=[...s.querySelectorAll('.card')].some(c=>!c.classList.contains('hidden'));
      s.classList.toggle('hidden',!vis);
    });
    document.getElementById('shown').textContent=shown;
  }
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

    p = [f'<details class="card {cls}" data-haystack="{_h(haystack)}" data-score="{b.scoring.score}">']

    # ---- glanceable face ----
    p.append("<summary>")
    p.append("<div class='toprow'>")
    p.append(f"<span class='pill {cls}'>{label}</span>")
    p.append(f"<span class='score'>score {b.scoring.score} &middot; {len(b.hypotheses)} hyp &middot; {n_obj} obj</span>")
    p.append("</div>")
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
    p.append("</div></header><main>")

    p.append("<div class='controls'>")
    p.append("<input id='q' type='search' placeholder='Filter by actor, CVE, malware, product…'>")
    p.append("<label class='meta' for='minScore'>Min score</label>")
    p.append("<select id='minScore'>")
    for v in (0, 45, 65, 85):
        sel = " selected" if v == 0 else ""
        p.append(f"<option value='{v}'{sel}>{v}</option>")
    p.append("</select>")
    p.append(f"<span class='meta'>Showing <span id='shown'>{len(pkg.briefings)}</span> of {len(pkg.briefings)}</span>")
    p.append("</div>")

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
