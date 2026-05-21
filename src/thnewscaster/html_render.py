"""Render a HuntPackage as a self-contained static HTML site.

We emit two files:

* ``index.html`` — landing page with a filterable list of briefings
* ``hunt_package.json`` — the structured package (also linked from the page)

All CSS and JS is inlined so the page hosts cleanly on GitHub Pages with
no build step or runtime dependencies.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .models import HuntPackage


_CSS = """
:root {
  --bg: #0b1020;
  --panel: #131a33;
  --panel-2: #1a2347;
  --ink: #e7ecf7;
  --muted: #93a0c2;
  --accent: #7cc4ff;
  --accent-2: #ffb86b;
  --danger: #ff6b81;
  --ok: #7ee787;
  --warn: #ffd866;
  --code-bg: #0a1024;
  --border: #243160;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, sans-serif; }
header { padding: 28px 24px 18px; border-bottom: 1px solid var(--border); background: linear-gradient(180deg, #0e1430 0%, #0b1020 100%); }
header h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: 0.2px; }
header .meta { color: var(--muted); font-size: 13px; }
header .meta strong { color: var(--ink); }
main { max-width: 1180px; margin: 0 auto; padding: 24px; }
.controls { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 18px; }
.controls input, .controls select {
  background: var(--panel); color: var(--ink); border: 1px solid var(--border);
  padding: 8px 12px; border-radius: 8px; font: inherit;
}
.controls input { min-width: 260px; flex: 1; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; background: var(--panel-2); color: var(--ink); border: 1px solid var(--border); margin-right: 4px; }
.badge.score { background: #1a3a2a; color: var(--ok); border-color: #2a5a3a; }
.badge.cve { background: #3a1a1a; color: var(--danger); border-color: #5a2a2a; }
.badge.actor { background: #3a2a1a; color: var(--accent-2); border-color: #5a3a2a; }
.badge.malware { background: #2a1a3a; color: #c89cff; border-color: #3a2a5a; }
.badge.product { background: #1a2a3a; color: var(--accent); border-color: #2a3a5a; }
.badge.sector { background: #2a2a3a; color: var(--muted); }
.briefing { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 18px; }
.briefing h2 { margin: 0 0 4px; font-size: 19px; }
.briefing h2 a { color: var(--ink); text-decoration: none; }
.briefing h2 a:hover { color: var(--accent); }
.briefing .src { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
.briefing summary { cursor: pointer; color: var(--accent); margin: 10px 0 4px; font-weight: 600; }
.briefing summary:hover { color: var(--accent-2); }
.summary-text { color: var(--muted); margin: 8px 0 12px; font-size: 14px; }
.signals { margin: 8px 0 4px; line-height: 2.2; }
.hyps { margin-top: 12px; }
.hyp { background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; margin: 10px 0; }
.hyp h3 { margin: 0 0 6px; font-size: 16px; color: var(--accent); }
.hyp .conf { font-size: 12px; color: var(--muted); margin-left: 8px; }
.hyp .stmt { margin: 6px 0 8px; }
.hyp .rationale { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
.obj { border-left: 3px solid var(--border); padding: 10px 12px; margin: 8px 0; background: rgba(0,0,0,0.18); border-radius: 0 8px 8px 0; }
.obj h4 { margin: 0 0 4px; font-size: 14px; }
.obj .meta-line { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
.obj.easy { border-left-color: var(--ok); }
.obj.medium { border-left-color: var(--warn); }
.obj.hard { border-left-color: var(--danger); }
.obj p { margin: 4px 0; font-size: 14px; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1px 6px; font-size: 13px; color: #d6e1ff; }
pre { padding: 10px 12px; overflow-x: auto; }
footer { color: var(--muted); font-size: 12px; padding: 30px 24px; text-align: center; border-top: 1px solid var(--border); margin-top: 30px; }
a { color: var(--accent); }
.hidden { display: none !important; }
"""

_JS = """
(function () {
  const q = document.getElementById('q');
  const minScore = document.getElementById('minScore');
  const cards = Array.from(document.querySelectorAll('.briefing'));
  function apply() {
    const needle = (q.value || '').toLowerCase().trim();
    const min = parseInt(minScore.value || '0', 10);
    let shown = 0;
    cards.forEach(c => {
      const hay = c.dataset.haystack || '';
      const score = parseInt(c.dataset.score || '0', 10);
      const ok = (!needle || hay.includes(needle)) && score >= min;
      c.classList.toggle('hidden', !ok);
      if (ok) shown += 1;
    });
    document.getElementById('shown').textContent = shown;
  }
  q.addEventListener('input', apply);
  minScore.addEventListener('input', apply);
  apply();
})();
"""


def _h(text: str) -> str:
    return html.escape(text or "", quote=True)


def _badges(items: list[str], cls: str) -> str:
    return "".join(f'<span class="badge {cls}">{_h(x)}</span>' for x in items)


def render_html(pkg: HuntPackage, *, json_filename: str = "hunt_package.json") -> str:
    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='en'><head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>THNewsCaster — Threat Hunting News Package</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body>")

    parts.append("<header>")
    parts.append("<h1>THNewsCaster &middot; Threat Hunting News Package</h1>")
    parts.append("<div class='meta'>")
    parts.append(f"Generated <strong>{_h(pkg.generated_at)}</strong> by {_h(pkg.generator)} v{_h(pkg.version)} &middot; ")
    parts.append(f"<strong>{pkg.total_seen}</strong> articles seen &middot; ")
    parts.append(f"<strong>{pkg.skipped}</strong> below threshold &middot; ")
    parts.append(f"<strong>{len(pkg.briefings)}</strong> hunt briefings")
    parts.append("</div>")
    parts.append("<div class='meta'>Downloads: ")
    parts.append(f"<a href='{_h(json_filename)}'>package JSON</a> &middot; ")
    parts.append("<a href='iocs.csv'>IOCs CSV</a> &middot; ")
    parts.append("<a href='iocs.json'>IOCs JSON</a> &middot; ")
    parts.append("<a href='iocs_stix.json'>STIX</a> &middot; ")
    parts.append("<a href='archive/index.html'>archive</a>")
    parts.append("</div></header>")

    parts.append("<main>")
    parts.append("<div class='controls'>")
    parts.append("<input id='q' type='search' placeholder='Filter by actor, CVE, malware, product, technique…'>")
    parts.append("<label class='meta' for='minScore'>Min score</label>")
    parts.append("<select id='minScore'>")
    for v in (0, 30, 50, 70, 90):
        sel = " selected" if v == 0 else ""
        parts.append(f"<option value='{v}'{sel}>{v}</option>")
    parts.append("</select>")
    parts.append(f"<span class='meta'>Showing <span id='shown'>{len(pkg.briefings)}</span> of {len(pkg.briefings)}</span>")
    parts.append("</div>")

    for b in pkg.briefings:
        a, e, s = b.article, b.extraction, b.scoring
        haystack = " ".join([
            a.title, a.summary, a.source,
            " ".join(e.cves), " ".join(e.threat_actors), " ".join(e.malware_families),
            " ".join(e.products), " ".join(e.vectors), " ".join(e.actions),
            " ".join(e.sectors), " ".join(e.mitre_techniques),
        ]).lower()

        parts.append(f"<article class='briefing' data-haystack=\"{_h(haystack)}\" data-score='{s.score}'>")
        title_html = _h(a.title)
        if a.link:
            parts.append(f"<h2><a href='{_h(a.link)}' target='_blank' rel='noopener noreferrer'>{title_html}</a></h2>")
        else:
            parts.append(f"<h2>{title_html}</h2>")
        seen = f" &middot; first seen {_h(b.first_seen)}" if b.first_seen else ""
        parts.append(f"<div class='src'>{_h(a.source)} &middot; {_h(a.published)}{seen}</div>")

        parts.append(f"<span class='badge score'>score {s.score}</span>")
        parts.append(_badges(e.cves, "cve"))
        parts.append(_badges(e.threat_actors, "actor"))
        parts.append(_badges(e.malware_families, "malware"))
        parts.append(_badges(e.products, "product"))
        parts.append(_badges(e.sectors, "sector"))

        if a.summary:
            parts.append(f"<p class='summary-text'>{_h(a.summary)}</p>")

        signal_rows: list[tuple[str, list[str]]] = [
            ("Vectors", e.vectors), ("Actions", e.actions),
            ("MITRE ATT&CK", e.mitre_techniques),
            ("IP IOCs", e.ips), ("Domain IOCs", e.domains),
            ("SHA256", e.hashes_sha256), ("SHA1", e.hashes_sha1), ("MD5", e.hashes_md5),
        ]
        rows_html = [
            f"<div><strong>{label}:</strong> {_h(', '.join(values))}</div>"
            for label, values in signal_rows if values
        ]
        if rows_html:
            parts.append("<details><summary>Extracted signals</summary>")
            parts.append("<div class='signals'>" + "".join(rows_html) + "</div>")
            parts.append("</details>")

        parts.append("<div class='hyps'>")
        parts.append(f"<details open><summary>Hypotheses ({len(b.hypotheses)})</summary>")
        for h_ in b.hypotheses:
            parts.append("<section class='hyp'>")
            parts.append(f"<h3>{_h(h_.id)} &middot; {_h(h_.title)}<span class='conf'>confidence: {_h(h_.confidence)}</span></h3>")
            parts.append(f"<p class='stmt'><strong>Statement.</strong> {_h(h_.statement)}</p>")
            parts.append(f"<p class='rationale'>{_h(h_.rationale)}</p>")
            if h_.mitre_attack:
                parts.append("<div>" + _badges(h_.mitre_attack, "sector") + "</div>")
            parts.append(f"<p><em>CTF objectives ({len(h_.objectives)}) — find evidence that disproves the hypothesis:</em></p>")
            for o in h_.objectives:
                parts.append(f"<div class='obj {_h(o.difficulty)}'>")
                parts.append(f"<h4>[{_h(o.id)}] {_h(o.title)}</h4>")
                parts.append(f"<div class='meta-line'>difficulty: {_h(o.difficulty)} &middot; {o.points} pts &middot; MITRE: {_h(', '.join(o.mitre_attack) or 'n/a')}</div>")
                parts.append(f"<p><strong>Falsification criterion.</strong> {_h(o.falsification_criterion)}</p>")
                parts.append(f"<p><strong>Data sources.</strong> {_h(', '.join(o.data_sources))}</p>")
                parts.append(f"<p><strong>Suggested query.</strong></p><pre>{_h(o.suggested_query)}</pre>")
                parts.append("</div>")
            if h_.sigma_rule.strip():
                parts.append("<details><summary>Sigma rule</summary>")
                parts.append(f"<pre>{_h(h_.sigma_rule.strip())}</pre>")
                parts.append("</details>")
            parts.append("</section>")
        parts.append("</details></div>")

        parts.append("</article>")

    if not pkg.briefings:
        parts.append("<p class='summary-text'>No hunt-worthy articles in this run.</p>")

    parts.append("</main>")
    parts.append("<footer>")
    parts.append("Built with <a href='https://github.com/xhionz/thnewscaster'>THNewsCaster</a>. ")
    parts.append("Hypotheses are starting points — adapt queries to your SIEM and validate findings before raising incidents.")
    parts.append("</footer>")
    parts.append(f"<script>{_JS}</script>")
    parts.append("</body></html>")
    return "".join(parts)


def write_site(pkg: HuntPackage, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hunt_package.json").write_text(json.dumps(pkg.to_dict(), indent=2, ensure_ascii=False))
    (out_dir / "index.html").write_text(render_html(pkg))
    # Disable Jekyll on GitHub Pages so underscore-prefixed files (none here, but safe) are served as-is.
    (out_dir / ".nojekyll").write_text("")
