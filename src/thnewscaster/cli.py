"""Command-line entry point for THNewsCaster.

Examples
--------
Live pull from default feeds + write JSON+Markdown package::

    python -m thnewscaster --out-dir out/

Offline run using the bundled sample feed::

    python -m thnewscaster --offline --out-dir out/

Pipe arbitrary RSS/Atom file::

    python -m thnewscaster --feed-file path/to/feed.xml
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .feeds import collect, load_local_feed
from .package import build_package, render_markdown, to_json, to_markdown
from .relevance import DEFAULT_THRESHOLD
from .sources import DEFAULT_FEEDS

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_SAMPLE = DATA_DIR / "sample_feed.xml"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="thnewscaster", description="Threat-hunting news platform")
    p.add_argument("--version", action="version", version=f"thnewscaster {__version__}")
    p.add_argument("--offline", action="store_true", help="Use bundled sample feed instead of network")
    p.add_argument("--feed-file", action="append", default=[], help="Local RSS/Atom file to ingest (repeatable)")
    p.add_argument("--out-dir", type=Path, default=Path("out"), help="Where to write the package")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Minimum relevance score to keep an article")
    p.add_argument("--max-briefings", type=int, default=25, help="Cap on briefings in the package")
    p.add_argument("--no-markdown", action="store_true", help="Skip Markdown render")
    p.add_argument("--print", action="store_true", help="Also print Markdown to stdout")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger("thnewscaster")

    articles = []
    source_kinds = {name: kind for name, _, kind in DEFAULT_FEEDS}

    if args.feed_file:
        for f in args.feed_file:
            path = Path(f)
            log.info("loading local feed %s", path)
            articles.extend(load_local_feed(path))
    elif args.offline:
        if not DEFAULT_SAMPLE.exists():
            log.error("offline sample missing at %s", DEFAULT_SAMPLE)
            return 2
        log.info("offline mode: loading bundled sample %s", DEFAULT_SAMPLE)
        articles.extend(load_local_feed(DEFAULT_SAMPLE, source_name="OfflineSample"))
    else:
        log.info("collecting %d feeds", len(DEFAULT_FEEDS))
        articles = collect(DEFAULT_FEEDS, offline_fallback=DEFAULT_SAMPLE)

    log.info("collected %d articles", len(articles))

    pkg = build_package(
        articles,
        source_kinds=source_kinds,
        threshold=args.threshold,
        max_briefings=args.max_briefings,
    )
    log.info("built package: %d briefings (%d seen, %d skipped)", len(pkg.briefings), pkg.total_seen, pkg.skipped)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "hunt_package.json"
    to_json(pkg, json_path)
    log.info("wrote %s", json_path)
    if not args.no_markdown:
        md_path = args.out_dir / "hunt_package.md"
        to_markdown(pkg, md_path)
        log.info("wrote %s", md_path)

    if args.print:
        sys.stdout.write(render_markdown(pkg))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
