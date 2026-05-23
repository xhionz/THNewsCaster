"""End-to-end run orchestration.

Flow (with dedup enabled):

1. Filter the collected articles down to ones we haven't processed before.
2. Build a package over only those NEW articles (score -> cap top-N ->
   generate hypotheses, which is where any LLM cost is incurred).
3. Persist the new briefings and mark every collected article as seen.
4. Assemble the SITE package from a rolling window of stored briefings so
   the published page stays populated even on quiet days.
5. Write JSON / Markdown / HTML, IOC exports, Sigma rules, a dated archive
   snapshot, and send notifications about the new briefings.

With dedup disabled it degrades to the original behaviour: build over all
articles and publish that.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from . import iocs as ioc_export
from . import llm
from . import sigma_export
from .brief import generate_brief
from .config import AppConfig
from .models import Article, HuntPackage
from .notify import notify_new
from .package import HypothesisGenerator, build_package, to_json, to_markdown
from .html_render import write_site
from .store import BriefingStore
from .triage import TriageConfig, make_selector

log = logging.getLogger(__name__)


def _write_status(cfg: AppConfig, *, seen: int, new: int, published: int,
                  elapsed: float) -> None:
    """One-line run summary to the log + a status.json for polling."""
    calls = llm.get_call_count()
    log.info(
        "RUN SUMMARY: seen=%d new=%d hunted=%d published=%d model_calls=%d elapsed=%.1fs",
        seen, new, published, published, calls, elapsed,
    )
    status = {
        "last_run": _now(),
        "elapsed_seconds": round(elapsed, 1),
        "articles_seen": seen,
        "new_articles": new,
        "briefings_published": published,
        "model_calls": calls,
        "triage_enabled": cfg.triage_enabled,
        "agent_enabled": cfg.agent_enabled,
    }
    try:
        cfg.out_dir.mkdir(parents=True, exist_ok=True)
        (cfg.out_dir / "status.json").write_text(json.dumps(status, indent=2))
    except OSError as exc:
        log.warning("could not write status.json: %s", exc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_outputs(cfg: AppConfig, pkg: HuntPackage, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    to_json(pkg, out_dir / "hunt_package.json")
    if cfg.write_markdown:
        to_markdown(pkg, out_dir / "hunt_package.md")
    if cfg.write_html:
        write_site(pkg, out_dir)
    if cfg.write_iocs:
        counts = ioc_export.export_all(pkg, out_dir)
        log.info("IOC export: %s", ", ".join(f"{k}={v}" for k, v in counts.items()))
    if cfg.write_sigma:
        n = sigma_export.export_all(pkg, out_dir)
        log.info("wrote %d Sigma rule(s)", n)


def run(
    cfg: AppConfig,
    articles: list[Article],
    *,
    source_kinds: dict[str, str],
    generator: HypothesisGenerator,
) -> HuntPackage:
    started = time.monotonic()
    llm.reset_call_count()
    if cfg.criteria.active:
        log.info(
            "focus criteria active (require=%s, exclude=%d terms)",
            cfg.criteria.require, len(cfg.criteria.exclude_keywords),
        )

    selector = None
    if cfg.triage_enabled and cfg.llm.is_usable:
        log.info("model-driven triage enabled (batch=%d)", cfg.triage_batch_size)
        selector = make_selector(
            cfg.llm,
            TriageConfig(enabled=True, batch_size=cfg.triage_batch_size),
            cfg.criteria,
            source_kinds=source_kinds,
            threshold=cfg.threshold,
            max_briefings=cfg.max_briefings,
            offline=cfg.offline,
        )

    if not cfg.dedup or cfg.state_db is None:
        log.info("dedup disabled; building over all %d articles", len(articles))
        pkg = build_package(
            articles, source_kinds=source_kinds,
            threshold=cfg.threshold, max_briefings=cfg.max_briefings,
            hypothesis_generator=generator, criteria=cfg.criteria,
            triage_selector=selector, concurrency=cfg.concurrency,
        )
        for b in pkg.briefings:
            b.first_seen = _now()
        pkg.brief = generate_brief(pkg, cfg.llm if cfg.llm.is_usable else None)
        _write_outputs(cfg, pkg, cfg.out_dir)
        if cfg.archive:
            _archive(cfg, pkg)
        notify_new(cfg, pkg.briefings)
        _write_status(cfg, seen=len(articles), new=len(pkg.briefings),
                      published=len(pkg.briefings), elapsed=time.monotonic() - started)
        return pkg

    store = BriefingStore(cfg.state_db)
    try:
        known = store.known_ids()
        new_articles = [a for a in articles if a.id not in known]
        log.info("%d new of %d collected articles", len(new_articles), len(articles))

        new_pkg = build_package(
            new_articles, source_kinds=source_kinds,
            threshold=cfg.threshold, max_briefings=cfg.max_briefings,
            hypothesis_generator=generator, criteria=cfg.criteria,
            triage_selector=selector, concurrency=cfg.concurrency,
        )

        when = _now()
        for b in new_pkg.briefings:
            b.first_seen = when
            store.save_briefing(b)
        # Mark every collected article seen so we never reprocess it.
        for a in articles:
            store.mark_seen(a.id, a.title, 0, when)
        store.commit()

        # Build the published site from the rolling window of stored briefings.
        site_pkg = HuntPackage()
        site_pkg.briefings = store.recent_briefings(cfg.retention_days, cfg.site_max)
        site_pkg.total_seen = len(articles)
        site_pkg.skipped = len(articles) - len(new_pkg.briefings)
        log.info(
            "site package: %d briefing(s) in last %d days (%d new this run)",
            len(site_pkg.briefings), cfg.retention_days, len(new_pkg.briefings),
        )

        site_pkg.brief = generate_brief(site_pkg, cfg.llm if cfg.llm.is_usable else None)
        _write_outputs(cfg, site_pkg, cfg.out_dir)
        if cfg.archive:
            _archive(cfg, site_pkg)
        notify_new(cfg, new_pkg.briefings)
        _write_status(cfg, seen=len(articles), new=len(new_articles),
                      published=len(new_pkg.briefings), elapsed=time.monotonic() - started)
        return site_pkg
    finally:
        store.close()


def _archive(cfg: AppConfig, pkg: HuntPackage) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    snap = cfg.out_dir / "archive" / stamp
    snap.mkdir(parents=True, exist_ok=True)
    to_json(pkg, snap / "hunt_package.json")
    if cfg.write_markdown:
        to_markdown(pkg, snap / "hunt_package.md")
    if cfg.write_iocs:
        ioc_export.export_all(pkg, snap)
    _write_archive_index(cfg.out_dir / "archive")
    log.info("archived snapshot to %s", snap)


def _write_archive_index(archive_dir: Path) -> None:
    snaps = sorted(
        (p.name for p in archive_dir.iterdir() if p.is_dir()),
        reverse=True,
    )
    rows = "\n".join(
        f'<li><a href="{name}/hunt_package.md">{name}</a> '
        f'(<a href="{name}/hunt_package.json">json</a>, '
        f'<a href="{name}/iocs.csv">iocs</a>)</li>'
        for name in snaps
    )
    html = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>THNewsCaster — Archive</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e7ecf7;"
        "max-width:900px;margin:0 auto;padding:24px}a{color:#7cc4ff}li{margin:6px 0}</style>"
        "</head><body><h1>THNewsCaster — Archive</h1>"
        "<p><a href='../index.html'>&larr; Back to latest</a></p>"
        f"<ul>{rows}</ul></body></html>"
    )
    (archive_dir / "index.html").write_text(html)
