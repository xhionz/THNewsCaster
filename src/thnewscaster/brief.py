"""Generate a 3-sentence executive intel brief for a run.

Uses the LLM when configured; otherwise composes a deterministic summary
from the package so the brief is always present.
"""
from __future__ import annotations

import logging

from .analytics import criticality, is_kev
from .config import LLMConfig
from .llm import chat_raw, coerce_json
from .models import HuntPackage

log = logging.getLogger(__name__)

_SYSTEM = (
    "You are a threat-intelligence lead writing the top-of-report brief for "
    "threat hunters. Given today's hunt-worthy items, write EXACTLY THREE "
    "sentences: (1) the dominant theme/threat, (2) what to prioritise and why, "
    "(3) any notable actor/CVE/sector. Be concrete and terse. "
    'Respond as JSON: {"brief":"<three sentences>"}.'
)


def _deterministic(pkg: HuntPackage) -> str:
    n = len(pkg.briefings)
    if n == 0:
        return "No hunt-worthy security news in this run. Nothing to prioritise right now."
    crit = sum(1 for b in pkg.briefings if criticality(b)[0] == "Critical")
    kev = sum(1 for b in pkg.briefings if is_kev(b))
    top = "; ".join(b.article.title for b in pkg.briefings[:3])
    s1 = f"{n} hunt-worthy item(s) today, {crit} rated critical."
    s2 = (f"{kev} are CISA-KEV (actively exploited) — prioritise those first."
          if kev else "Prioritise the highest-scored items first.")
    s3 = f"Top of the list: {top}."
    return f"{s1} {s2} {s3}"


def generate_brief(pkg: HuntPackage, llm_cfg: LLMConfig | None) -> str:
    if not pkg.briefings:
        return _deterministic(pkg)
    if llm_cfg is None or not llm_cfg.is_usable:
        return _deterministic(pkg)

    items = [
        {
            "title": b.article.title,
            "criticality": criticality(b)[0],
            "kev": is_kev(b),
            "cves": b.extraction.cves[:3],
            "actors": b.extraction.threat_actors[:2],
            "sectors": b.extraction.sectors[:2],
        }
        for b in pkg.briefings[:12]
    ]
    import json
    try:
        out = coerce_json(chat_raw(llm_cfg, [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": json.dumps({"items": items}, ensure_ascii=False)},
        ]))
        brief = str(out.get("brief", "")).strip()
        if brief:
            return brief
    except (ValueError, KeyError, OSError) as exc:
        log.warning("brief generation failed (%s); using deterministic summary", exc)
    return _deterministic(pkg)
