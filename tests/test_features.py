"""Tests for dedup store, IOC export ordering, Sigma export, and the pipeline."""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster import iocs, sigma_export  # noqa: E402
from thnewscaster.cli import DEFAULT_SAMPLE  # noqa: E402
from thnewscaster.config import AppConfig  # noqa: E402
from thnewscaster.feeds import load_local_feed  # noqa: E402
from thnewscaster.hypotheses import generate as gen_heuristic  # noqa: E402
from thnewscaster.models import Hypothesis  # noqa: E402
from thnewscaster.package import build_package  # noqa: E402
from thnewscaster.pipeline import run as run_pipeline  # noqa: E402
from thnewscaster.store import BriefingStore  # noqa: E402


def _arts():
    return load_local_feed(DEFAULT_SAMPLE, "OfflineSample")


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = AppConfig.from_env()
    cfg.out_dir = tmp_path / "site"
    cfg.state_db = tmp_path / "state.db"
    cfg.llm.enabled = False
    cfg.slack_webhook = ""
    cfg.smtp_host = ""
    return cfg


def test_ioc_export_grouped_and_sorted(tmp_path: Path) -> None:
    pkg = build_package(_arts())
    grouped = iocs.aggregate(pkg)
    # Types present and in canonical order.
    assert list(grouped.keys()) == iocs.IOC_ORDER
    # IPs sorted numerically, not lexically.
    ips = [h.value for h in grouped["ips"]]
    assert ips == sorted(ips, key=iocs._ip_sort_key)
    counts = iocs.export_all(pkg, tmp_path)
    assert (tmp_path / "iocs.csv").exists()
    assert (tmp_path / "iocs.json").exists()
    stix = json.loads((tmp_path / "iocs_stix.json").read_text())
    assert stix["type"] == "bundle"
    # CVEs become vulnerability SDOs; IPs/domains become indicators.
    types = {o["type"] for o in stix["objects"]}
    assert "indicator" in types or "vulnerability" in types
    assert sum(counts.values()) > 0


def test_store_dedup_roundtrip(tmp_path: Path) -> None:
    store = BriefingStore(tmp_path / "s.db")
    pkg = build_package(_arts(), max_briefings=3)
    for b in pkg.briefings:
        b.first_seen = "2026-05-21T00:00:00+00:00"
        store.save_briefing(b)
        store.mark_seen(b.article.id, b.article.title, b.scoring.score, b.first_seen)
    store.commit()
    known = store.known_ids()
    assert len(known) == len(pkg.briefings)
    assert all(store.is_seen(b.article.id) for b in pkg.briefings)
    recent = store.recent_briefings(within_days=3650)
    assert len(recent) == len(pkg.briefings)
    # Round-trips back into real dataclasses with objectives intact.
    assert recent[0].hypotheses[0].objectives
    store.close()


def test_sigma_export_writes_only_valid_rules(tmp_path: Path) -> None:
    pkg = build_package(_arts(), max_briefings=2)
    # Inject a sigma rule into one hypothesis; leave others empty.
    pkg.briefings[0].hypotheses[0].sigma_rule = (
        "title: Test\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel"
    )
    n = sigma_export.export_all(pkg, tmp_path)
    assert n == 1
    files = list((tmp_path / "sigma").glob("*.yml"))
    assert len(files) == 1
    assert "detection" in files[0].read_text()


def test_pipeline_dedup_second_run_processes_nothing_new(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    calls = {"n": 0}

    def counting_gen(article, ext) -> list[Hypothesis]:
        calls["n"] += 1
        return gen_heuristic(article, ext)

    arts = _arts()
    pkg1 = run_pipeline(cfg, arts, source_kinds={}, generator=counting_gen)
    first_calls = calls["n"]
    assert first_calls > 0
    assert (cfg.out_dir / "index.html").exists()
    assert (cfg.out_dir / "iocs.csv").exists()
    assert (cfg.out_dir / "archive").is_dir()

    # Second run with identical articles: nothing new, so the generator is
    # never invoked, but the site is still rebuilt from the store.
    pkg2 = run_pipeline(cfg, arts, source_kinds={}, generator=counting_gen)
    assert calls["n"] == first_calls, "no new articles should mean no new generation"
    assert len(pkg2.briefings) == len(pkg1.briefings)


def test_concurrent_generation_preserves_order_and_count() -> None:
    arts = _arts()

    # Tag each briefing's first hypothesis with the article id so we can verify
    # results line up with their source article regardless of thread timing.
    def tagging_gen(article, ext):
        hyps = gen_heuristic(article, ext)
        hyps[0].title = f"TAG::{article.id}::{hyps[0].title}"
        return hyps

    seq = build_package(arts, hypothesis_generator=tagging_gen, concurrency=1)
    par = build_package(arts, hypothesis_generator=tagging_gen, concurrency=4)
    assert len(par.briefings) == len(seq.briefings)
    seq_ids = [b.article.id for b in seq.briefings]
    par_ids = [b.article.id for b in par.briefings]
    assert par_ids == seq_ids, "concurrency must preserve briefing order"
    for b in par.briefings:
        assert b.hypotheses[0].title.startswith(f"TAG::{b.article.id}::")


def test_pipeline_no_dedup_builds_over_all(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.dedup = False
    pkg = run_pipeline(cfg, _arts(), source_kinds={}, generator=gen_heuristic)
    assert pkg.briefings
    assert (cfg.out_dir / "hunt_package.json").exists()
