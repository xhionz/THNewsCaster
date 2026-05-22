"""Tests for model-driven triage selection (transport mocked)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster import triage  # noqa: E402
from thnewscaster.cli import DEFAULT_SAMPLE  # noqa: E402
from thnewscaster.config import LLMConfig  # noqa: E402
from thnewscaster.criteria import FocusCriteria  # noqa: E402
from thnewscaster.extraction import extract  # noqa: E402
from thnewscaster.feeds import load_local_feed  # noqa: E402
from thnewscaster.package import build_package  # noqa: E402
from thnewscaster.triage import TriageConfig, make_selector  # noqa: E402


def _pairs():
    arts = load_local_feed(DEFAULT_SAMPLE, "OfflineSample")
    return [(a, extract(a)) for a in arts]


def _llm():
    return LLMConfig(enabled=True, base_url="https://fake/v1", api_key="k", model="m")


def test_triage_selects_and_ranks_by_model_priority(monkeypatch):
    pairs = _pairs()

    def fake_chat(cfg, messages, json_mode=True):
        # Echo back a decision for every id in the batch; give the first a
        # high priority, mark one as not hunt-worthy.
        user = messages[-1]["content"]
        items = json.loads(user.split("ITEMS (JSON):\n", 1)[1])
        decisions = []
        for n, it in enumerate(items):
            decisions.append({
                "id": it["id"],
                "hunt_worthy": n != 0,                 # drop the first item
                "priority": 90 - n,
                "reason": "test",
            })
        return json.dumps({"decisions": decisions})

    monkeypatch.setattr(triage, "chat_raw", fake_chat)
    sel = make_selector(_llm(), TriageConfig(enabled=True, batch_size=20),
                        FocusCriteria(), source_kinds={}, threshold=30, max_briefings=3)
    cands = sel(pairs)
    assert len(cands) == 3, "should respect the safety cap"
    scores = [c[2].score for c in cands]
    assert scores == sorted(scores, reverse=True), "ranked by model priority"
    assert all("triage:" in c[2].rationale[0] for c in cands)


def test_triage_falls_back_to_heuristic_on_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("endpoint down")

    monkeypatch.setattr(triage, "chat_raw", boom)
    sel = make_selector(_llm(), TriageConfig(enabled=True), FocusCriteria(),
                        source_kinds={}, threshold=30, max_briefings=5)
    cands = sel(_pairs())
    # Heuristic fallback still selects hunt-worthy sample articles.
    assert cands, "fallback should still select via heuristic score"


def test_triage_respects_exclude_keyword(monkeypatch):
    def fake_chat(cfg, messages, json_mode=True):
        items = json.loads(messages[-1]["content"].split("ITEMS (JSON):\n", 1)[1])
        # Everything passed to the model is hunt-worthy.
        return json.dumps({"decisions": [
            {"id": it["id"], "hunt_worthy": True, "priority": 70, "reason": "x"}
            for it in items
        ]})

    seen_titles = {"n": []}
    orig = triage._triage_batch

    monkeypatch.setattr(triage, "chat_raw", fake_chat)
    crit = FocusCriteria(exclude_keywords=["bumblebee"])
    sel = make_selector(_llm(), TriageConfig(enabled=True), crit,
                        source_kinds={}, threshold=30, max_briefings=50)
    cands = sel(_pairs())
    assert not any("BumbleBee" in c[0].title for c in cands), "excluded topic must be pre-dropped"


def test_build_package_uses_triage_selector():
    # A trivial selector that keeps exactly one article proves wiring works.
    pairs_seen = {}

    def selector(pairs):
        from thnewscaster.models import Scoring
        a, e = pairs[0]
        return [(a, e, Scoring(score=77, rationale=["triage: test"], is_hunt_worthy=True))]

    arts = load_local_feed(DEFAULT_SAMPLE, "OfflineSample")
    pkg = build_package(arts, triage_selector=selector)
    assert len(pkg.briefings) == 1
    assert pkg.briefings[0].scoring.score == 77
    assert pkg.briefings[0].hypotheses  # generator still ran
