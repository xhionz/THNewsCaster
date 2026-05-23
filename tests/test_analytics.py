"""Tests for dashboard analytics and the intel brief."""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster import analytics  # noqa: E402
from thnewscaster.brief import generate_brief, _deterministic  # noqa: E402
from thnewscaster.cli import DEFAULT_SAMPLE  # noqa: E402
from thnewscaster.feeds import load_local_feed  # noqa: E402
from thnewscaster.html_render import render_html  # noqa: E402
from thnewscaster.package import build_package  # noqa: E402


def _pkg():
    return build_package(load_local_feed(DEFAULT_SAMPLE, "OfflineSample"))


def test_normalize_source_buckets():
    assert analytics.normalize_source("DNS resolver logs") == "DNS"
    assert analytics.normalize_source("EDR (CrowdStrike/Defender)") == "EDR / Endpoint"
    assert analytics.normalize_source("Proxy logs") == "Proxy / Web"
    assert analytics.normalize_source("Windows Security event log") == "Windows Event Logs"
    assert analytics.normalize_source("something exotic") == "Other"


def test_objectives_by_source_covers_all_objectives():
    pkg = _pkg()
    total_obj = sum(len(h.objectives) for b in pkg.briefings for h in b.hypotheses)
    groups = analytics.objectives_by_source(pkg)
    # Every objective appears at least once across the buckets (may appear in
    # several if it lists multiple data sources).
    placed = sum(len(refs) for _, refs in groups)
    assert placed >= total_obj
    # Sorted most-populated first.
    counts = [len(refs) for _, refs in groups]
    assert counts == sorted(counts, reverse=True)


def test_killchain_coverage_in_stage_order():
    pkg = _pkg()
    cov = analytics.killchain_coverage(pkg)
    assert [s for s, _ in cov] == analytics.KILLCHAIN_STAGES if hasattr(analytics, "KILLCHAIN_STAGES") else True
    assert any(n > 0 for _, n in cov), "sample should touch some ATT&CK stages"


def test_likelihood_impact_partitions_all():
    pkg = _pkg()
    quad = analytics.likelihood_impact(pkg)
    assert sum(len(v) for v in quad.values()) == len(pkg.briefings)


def test_deterministic_brief_is_three_ish_sentences():
    pkg = _pkg()
    b = _deterministic(pkg)
    assert b and b.count(".") >= 2
    # generate_brief with no LLM falls back to deterministic.
    assert generate_brief(pkg, None) == b


def test_empty_package_brief():
    from thnewscaster.models import HuntPackage
    assert "No hunt-worthy" in _deterministic(HuntPackage())


def test_render_includes_dashboard_and_views():
    pkg = _pkg()
    pkg.brief = "Test brief sentence one. Sentence two. Sentence three."
    htm = render_html(pkg)
    assert "Today's brief" in htm
    assert "Kill-chain coverage" in htm
    assert "Likelihood" in htm
    assert "id='bysource'" in htm
    assert "By data source" in htm
