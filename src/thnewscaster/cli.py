"""Command-line entry point for THNewsCaster.

Examples
--------
Live pull from default feeds + write the full site (JSON + Markdown + HTML)::

    python -m thnewscaster --out-dir out/ --html

Offline run using the bundled sample feed::

    python -m thnewscaster --offline --out-dir out/

Daily daemon run driven entirely by environment (see deploy/)::

    THNC_OUT_DIR=/var/lib/thnewscaster/site \
    THNC_OPENAI_BASE_URL=https://my-endpoint/v1 \
    THNC_OPENAI_API_KEY=sk-... \
    python -m thnewscaster --from-env
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .agent import AgentConfig, generate_agentic
from .config import AppConfig, LLMConfig
from .feeds import collect, load_local_feed
from .hypotheses import generate as generate_heuristic
from .llm import generate_llm
from .models import Article, Extraction, GenResult, Hypothesis
from .package import render_markdown
from .pipeline import run as run_pipeline
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
    p.add_argument("--from-env", action="store_true",
                   help="Take all settings from THNC_* environment variables (for the daemon)")
    p.add_argument("--offline", action="store_true", help="Use bundled sample feed instead of network")
    p.add_argument("--feed-file", action="append", default=[], help="Local RSS/Atom file to ingest (repeatable)")
    p.add_argument("--out-dir", type=Path, default=None, help="Where to write the package (default: out/)")
    p.add_argument("--threshold", type=int, default=None, help="Minimum relevance score to keep an article")
    p.add_argument("--max-briefings", type=int, default=None, help="Cap on briefings in the package")
    p.add_argument("--html", action="store_true", help="Render a static HTML site (index.html) into --out-dir")
    p.add_argument("--no-markdown", action="store_true", help="Skip Markdown render")
    p.add_argument("--no-dedup", action="store_true", help="Disable the cross-run dedup/archive store")
    p.add_argument("--print", action="store_true", help="Also print Markdown to stdout")
    # LLM controls (override environment).
    p.add_argument("--agent", action="store_true",
                   help="Use the agentic generator (tools + critic) instead of single-shot LLM")
    p.add_argument("--triage", action="store_true",
                   help="Let the model decide which articles are hunt-worthy (batched triage)")
    p.add_argument("--llm", choices=["auto", "on", "off"], default="auto",
                   help="auto: use endpoint if configured; on: require it; off: heuristic only")
    p.add_argument("--llm-base-url", default=None, help="OpenAI-compatible base URL (…/v1)")
    p.add_argument("--llm-model", default=None, help="Model name for the endpoint")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def _resolve_config(args: argparse.Namespace) -> AppConfig:
    cfg = AppConfig.from_env()

    # CLI overrides win over environment.
    if args.out_dir is not None:
        cfg.out_dir = args.out_dir
    if args.threshold is not None:
        cfg.threshold = args.threshold
    if args.max_briefings is not None:
        cfg.max_briefings = args.max_briefings
    if args.offline:
        cfg.offline = True
    if args.html:
        cfg.write_html = True
    if args.no_markdown:
        cfg.write_markdown = False
    if args.no_dedup:
        cfg.dedup = False
    if args.agent:
        cfg.agent_enabled = True
    if args.triage:
        cfg.triage_enabled = True

    if args.llm_base_url is not None:
        cfg.llm.base_url = args.llm_base_url.rstrip("/")
    if args.llm_model is not None:
        cfg.llm.model = args.llm_model
    if args.llm == "on":
        cfg.llm.enabled = True
    elif args.llm == "off":
        cfg.llm.enabled = False
    else:  # auto
        cfg.llm.enabled = bool(cfg.llm.base_url)
    return cfg


def _make_generator(cfg: AppConfig, log: logging.Logger):
    """Return a generator with graceful per-article fallback.

    Chain: agent (if enabled) -> single-shot LLM -> heuristic engine.
    """
    if not cfg.llm.is_usable:
        log.info("LLM disabled or unconfigured; using heuristic generator")
        return generate_heuristic

    agent_cfg = AgentConfig(
        enabled=cfg.agent_enabled, max_steps=cfg.agent_max_steps,
        critic=cfg.agent_critic, critic_always=cfg.agent_critic_always,
        tools=cfg.agent_tools,
    )
    if agent_cfg.enabled:
        log.info("agent enabled: %s (model=%s, tools=%s, critic=%s)",
                 cfg.llm.base_url, cfg.llm.model, ",".join(agent_cfg.tools), agent_cfg.critic)
    else:
        log.info("LLM enabled: %s (model=%s)", cfg.llm.base_url, cfg.llm.model)

    def _gen(article: Article, ext: Extraction) -> GenResult:
        if agent_cfg.enabled:
            trace: list[str] = []
            hyps = generate_agentic(article, ext, cfg.llm, agent_cfg,
                                    offline=cfg.offline, trace=trace)
            if hyps is not None:
                return GenResult(hypotheses=hyps, trace=trace)
        hyps = generate_llm(article, ext, cfg.llm)
        if hyps is None:
            return GenResult(hypotheses=generate_heuristic(article, ext))
        return GenResult(hypotheses=hyps, trace=["single-shot LLM (no agent loop)"])

    return _gen


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger("thnewscaster")

    cfg = _resolve_config(args)
    if cfg.out_dir is None:
        cfg.out_dir = Path("out")

    source_kinds = {name: kind for name, _, kind in DEFAULT_FEEDS}

    articles: list[Article] = []
    if args.feed_file:
        for f in args.feed_file:
            path = Path(f)
            log.info("loading local feed %s", path)
            articles.extend(load_local_feed(path))
    elif cfg.offline:
        if not DEFAULT_SAMPLE.exists():
            log.error("offline sample missing at %s", DEFAULT_SAMPLE)
            return 2
        log.info("offline mode: loading bundled sample %s", DEFAULT_SAMPLE)
        articles.extend(load_local_feed(DEFAULT_SAMPLE, source_name="OfflineSample"))
    else:
        log.info("collecting %d feeds", len(DEFAULT_FEEDS))
        articles = collect(DEFAULT_FEEDS, offline_fallback=DEFAULT_SAMPLE)

    log.info("collected %d articles", len(articles))

    if args.llm == "on" and not cfg.llm.is_usable:
        log.error("--llm on requires THNC_OPENAI_BASE_URL / --llm-base-url to be set")
        return 2

    generator = _make_generator(cfg, log)

    pkg = run_pipeline(cfg, articles, source_kinds=source_kinds, generator=generator)
    log.info("published %d briefing(s) to %s", len(pkg.briefings), cfg.out_dir)

    if args.print:
        sys.stdout.write(render_markdown(pkg))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
