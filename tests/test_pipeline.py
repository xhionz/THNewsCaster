"""End-to-end tests over the bundled sample feed.

We deliberately only use the offline sample so tests are network-free and
deterministic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster.cli import DEFAULT_SAMPLE  # noqa: E402
from thnewscaster.extraction import extract  # noqa: E402
from thnewscaster.feeds import load_local_feed  # noqa: E402
from thnewscaster.hypotheses import generate  # noqa: E402
from thnewscaster.models import Article  # noqa: E402
from thnewscaster.package import build_package, render_markdown  # noqa: E402
from thnewscaster.relevance import score  # noqa: E402


def _sample_articles() -> list[Article]:
    return load_local_feed(DEFAULT_SAMPLE, source_name="OfflineSample")


def test_sample_feed_parses() -> None:
    arts = _sample_articles()
    assert len(arts) >= 6, "expected at least 6 sample items"
    for a in arts:
        assert a.title
        assert a.id


def test_extraction_finds_iocs_and_entities() -> None:
    arts = _sample_articles()
    by_title = {a.title.lower(): a for a in arts}
    fortios = next(a for t, a in by_title.items() if "volt typhoon" in t)
    ext = extract(fortios)
    assert "CVE-2024-21762" in ext.cves
    assert any("Volt Typhoon" in x for x in ext.threat_actors)
    assert any("Fortinet" in p for p in ext.products)
    assert "185.225.74.10" in ext.ips
    assert any(d.endswith("login-portal-update.com") for d in ext.domains)
    assert any(len(h) == 64 for h in ext.hashes_sha256)


def test_scoring_filters_marketing_fluff() -> None:
    arts = _sample_articles()
    pkg = build_package(arts)
    titles = [b.article.title for b in pkg.briefings]
    assert not any("Beer-and-pretzels" in t for t in titles), (
        "marketing fluff article must not be promoted to a hunt briefing"
    )
    assert len(pkg.briefings) >= 5, "expect most sample articles to be hunt-worthy"


def test_every_briefing_has_at_least_three_hypotheses_each_with_3_to_5_objectives() -> None:
    arts = _sample_articles()
    pkg = build_package(arts)
    assert pkg.briefings, "expected at least one briefing"
    for b in pkg.briefings:
        assert len(b.hypotheses) >= 3, f"{b.article.title} has only {len(b.hypotheses)} hypotheses"
        for h in b.hypotheses:
            n = len(h.objectives)
            assert 3 <= n <= 5, f"hypothesis {h.id} has {n} objectives (need 3-5)"
            for o in h.objectives:
                assert o.falsification_criterion
                assert o.suggested_query
                assert o.data_sources


def test_package_serialises_to_json_and_markdown(tmp_path: Path) -> None:
    pkg = build_package(_sample_articles())
    blob = json.dumps(pkg.to_dict())
    parsed = json.loads(blob)
    assert parsed["briefings"], "json blob should contain briefings"
    md = render_markdown(pkg)
    assert "# Threat Hunting News Package" in md
    assert "CTF objectives" in md


def test_hypothesis_archetypes_are_diverse() -> None:
    arts = _sample_articles()
    pkg = build_package(arts)
    # Across the whole package we should see at least three distinct hypothesis
    # titles — otherwise the generator is collapsing to a single archetype.
    titles = {h.title for b in pkg.briefings for h in b.hypotheses}
    assert len(titles) >= 3, f"hypothesis diversity too low: {titles}"
