"""Model-driven triage: let the LLM decide which news warrants a hunt.

Instead of the heuristic relevance score choosing what to investigate, a
triage agent receives the new articles (title + summary + extracted
signals) in batches and returns, per article, whether it's hunt-worthy and
a 0-100 priority with a reason. Selection then keeps the hunt-worthy ones,
ranked by the model's priority, capped at ``max_briefings`` (the safety
ceiling).

Fail-safe: if the endpoint errors or returns junk, we fall back to the
heuristic score so a run never fails.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Callable

from .config import LLMConfig
from .criteria import FocusCriteria
from .llm import chat_raw, coerce_json
from .models import Article, Extraction, Scoring
from .relevance import score as heuristic_score

log = logging.getLogger(__name__)

Pair = tuple[Article, Extraction]
Candidate = tuple[Article, Extraction, Scoring]
Selector = Callable[[list[Pair]], list[Candidate]]


@dataclass
class TriageConfig:
    enabled: bool = False
    batch_size: int = 20


_SYSTEM = (
    "You are the triage lead for an enterprise threat-hunting team. You are given "
    "a batch of security news items with pre-extracted indicators. For EACH item "
    "decide whether it warrants a proactive threat hunt in a typical enterprise, "
    "and assign a priority 0-100. Weigh: active in-the-wild exploitation, "
    "exploitability and blast radius, actor capability, whether defenders can "
    "realistically hunt for it, and the operator priorities provided. Ignore "
    "vendor marketing, opinion, and low-signal items.\n"
    'Respond with a SINGLE JSON object: {"decisions":[{"id":"<id>",'
    '"hunt_worthy":true|false,"priority":0-100,"reason":"short"}]}. '
    "Include every id from the batch exactly once."
)


def _signals(ext: Extraction) -> dict:
    out = {
        "cves": ext.cves, "threat_actors": ext.threat_actors,
        "malware": ext.malware_families, "products": ext.products,
        "vectors": ext.vectors, "actions": ext.actions, "sectors": ext.sectors,
    }
    return {k: v for k, v in out.items() if v}


def _focus_hint(criteria: FocusCriteria) -> str:
    bits = []
    for label, vals in (
        ("sectors", criteria.sectors), ("actors", criteria.actors),
        ("malware", criteria.malware), ("vectors", criteria.vectors),
        ("products", criteria.products), ("keywords", criteria.keywords),
    ):
        if vals:
            bits.append(f"{label}: {', '.join(vals)}")
    if not bits:
        return "Operator priorities: none specified — use general enterprise relevance."
    return "Operator priorities (favour these): " + "; ".join(bits)


def _triage_batch(llm_cfg: LLMConfig, batch: list[Pair], focus_hint: str) -> dict[str, dict]:
    items = [
        {"id": a.id, "title": a.title, "summary": a.summary[:600], "signals": _signals(e)}
        for a, e in batch
    ]
    user = f"{focus_hint}\n\nITEMS (JSON):\n{json.dumps(items, ensure_ascii=False)}"
    content = chat_raw(llm_cfg, [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": user},
    ])
    parsed = coerce_json(content)
    decisions = parsed.get("decisions", [])
    out: dict[str, dict] = {}
    if isinstance(decisions, list):
        for d in decisions:
            if isinstance(d, dict) and d.get("id"):
                out[str(d["id"])] = d
    return out


def _heuristic_candidates(pairs: list[Pair], source_kinds: dict[str, str],
                          threshold: int, max_briefings: int) -> list[Candidate]:
    scored: list[Candidate] = []
    for art, ext in pairs:
        sc = heuristic_score(ext, source_kind=source_kinds.get(art.source, "news"),
                             threshold=threshold)
        if sc.is_hunt_worthy:
            scored.append((art, ext, sc))
    scored.sort(key=lambda c: c[2].score, reverse=True)
    return scored[:max_briefings]


def make_selector(
    llm_cfg: LLMConfig,
    triage_cfg: TriageConfig,
    criteria: FocusCriteria,
    *,
    source_kinds: dict[str, str],
    threshold: int,
    max_briefings: int,
) -> Selector:
    def _select(pairs: list[Pair]) -> list[Candidate]:
        # Operator hard rules first: exclude_keywords / require still apply.
        kept: list[Pair] = []
        for art, ext in pairs:
            if criteria.active:
                probe = Scoring(score=0)
                if not criteria.apply(art, ext, probe):
                    continue
            kept.append((art, ext))

        if not kept:
            return []

        focus_hint = _focus_hint(criteria)
        decisions: dict[str, dict] = {}
        try:
            for i in range(0, len(kept), triage_cfg.batch_size):
                batch = kept[i : i + triage_cfg.batch_size]
                decisions.update(_triage_batch(llm_cfg, batch, focus_hint))
            log.info("model triage decided on %d/%d articles", len(decisions), len(kept))
        except Exception as exc:  # noqa: BLE001 — any transport/parse failure
            log.warning("model triage failed (%s); falling back to heuristic scoring", exc)
            return _heuristic_candidates(kept, source_kinds, threshold, max_briefings)

        candidates: list[Candidate] = []
        for art, ext in kept:
            d = decisions.get(art.id)
            if not d or not d.get("hunt_worthy"):
                continue
            try:
                pri = max(0, min(100, int(d.get("priority", 50))))
            except (TypeError, ValueError):
                pri = 50
            reason = str(d.get("reason", "")).strip() or "model-selected"
            sc = Scoring(score=pri, rationale=[f"triage: {reason}"], is_hunt_worthy=True)
            candidates.append((art, ext, sc))

        candidates.sort(key=lambda c: c[2].score, reverse=True)
        return candidates[:max_briefings]

    return _select
