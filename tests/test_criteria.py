"""Tests for configurable focus criteria (boost / require / exclude)."""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster.cli import DEFAULT_SAMPLE  # noqa: E402
from thnewscaster.criteria import FocusCriteria  # noqa: E402
from thnewscaster.extraction import extract  # noqa: E402
from thnewscaster.feeds import load_local_feed  # noqa: E402
from thnewscaster.package import build_package  # noqa: E402
from thnewscaster.relevance import score  # noqa: E402


def _arts():
    return load_local_feed(DEFAULT_SAMPLE, "OfflineSample")


def _healthcare_article():
    # The Akira/Cisco ASA sample mentions healthcare + manufacturing sectors.
    return next(a for a in _arts() if "Akira" in a.title)


def test_boost_raises_score_for_matching_sector():
    art = _healthcare_article()
    ext = extract(art)
    base = score(ext).score

    crit = FocusCriteria(sectors=["healthcare"], boost_points=25)
    sc = score(ext)
    kept = crit.apply(art, ext, sc)
    assert kept is True
    assert sc.score == base + 25
    assert any("focus match" in r for r in sc.rationale)


def test_exclude_keyword_drops_article():
    art = _healthcare_article()
    ext = extract(art)
    crit = FocusCriteria(exclude_keywords=["ransomware"])
    sc = score(ext)
    assert crit.apply(art, ext, sc) is False


def test_require_drops_non_matching():
    crit = FocusCriteria(sectors=["aviation"], require=True)
    # No sample article is about aviation, so require-mode drops them all.
    pkg = build_package(_arts(), criteria=crit)
    assert pkg.briefings == []


def test_require_keeps_matching_only():
    crit = FocusCriteria(actors=["volt typhoon"], require=True, boost_points=30)
    pkg = build_package(_arts(), criteria=crit)
    assert pkg.briefings, "the Volt Typhoon article should survive require-mode"
    for b in pkg.briefings:
        assert any("volt typhoon" in a.lower() for a in b.extraction.threat_actors)


def test_inactive_criteria_is_noop():
    crit = FocusCriteria()  # nothing configured
    before = build_package(_arts())
    after = build_package(_arts(), criteria=crit)
    assert len(before.briefings) == len(after.briefings)
