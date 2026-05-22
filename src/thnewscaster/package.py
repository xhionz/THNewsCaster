"""Assemble the end-to-end hunt package and render it to JSON / Markdown."""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Iterable

from .extraction import extract
from .hypotheses import generate
from .criteria import FocusCriteria
from .models import Article, Extraction, GenResult, Hypothesis, HuntBriefing, HuntPackage
from .relevance import DEFAULT_THRESHOLD, score
from .sources import SOURCE_WEIGHTS

log = logging.getLogger(__name__)

HypothesisGenerator = Callable[[Article, Extraction], list[Hypothesis]]


def _source_kind(source_name: str, source_map: dict[str, str]) -> str:
    return source_map.get(source_name, "news")


def build_package(
    articles: Iterable[Article],
    *,
    source_kinds: dict[str, str] | None = None,
    threshold: int = DEFAULT_THRESHOLD,
    max_briefings: int | None = 25,
    hypothesis_generator: HypothesisGenerator = generate,
    criteria: FocusCriteria | None = None,
    triage_selector: "Callable[[list[tuple[Article, Extraction]]], list[tuple[Article, Extraction, Scoring]]] | None" = None,
    concurrency: int = 1,
) -> HuntPackage:
    pkg = HuntPackage()
    source_kinds = source_kinds or {}
    total = 0
    skipped = 0

    if triage_selector is not None:
        # Model-driven selection: extract everything, hand the (article, ext)
        # pairs to the selector, which decides what's hunt-worthy, the ranking,
        # and applies the cap. Hypothesis generation runs only on the result.
        pairs = [(art, extract(art)) for art in articles]
        total = len(pairs)
        candidates = triage_selector(pairs)
        skipped = total - len(candidates)
    else:
        # First pass: score everything. Hypothesis generation (which may call an
        # LLM, one request per article) is deferred until after we've ranked and
        # capped, so we only pay that cost for the briefings we actually keep.
        candidates = []
        for art in articles:
            total += 1
            ext = extract(art)
            sc = score(ext, source_kind=_source_kind(art.source, source_kinds), threshold=threshold)
            # Focus criteria can boost the score, drop excluded topics, or (in
            # require mode) drop anything that doesn't match a focus value.
            if criteria is not None:
                if not criteria.apply(art, ext, sc):
                    skipped += 1
                    continue
                sc.is_hunt_worthy = sc.score >= threshold
            if not sc.is_hunt_worthy:
                skipped += 1
                continue
            candidates.append((art, ext, sc))

        candidates.sort(key=lambda c: c[2].score, reverse=True)
        if max_briefings is not None:
            candidates = candidates[:max_briefings]

    # Generation is the expensive part (LLM/agent calls). Optionally run it
    # across briefings concurrently — useful when the endpoint batches requests
    # (e.g. vLLM continuous batching). Order is preserved.
    if concurrency > 1 and len(candidates) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            results = list(ex.map(lambda c: hypothesis_generator(c[0], c[1]), candidates))
    else:
        results = [hypothesis_generator(art, ext) for art, ext, _ in candidates]

    briefings: list[HuntBriefing] = []
    for (art, ext, sc), result in zip(candidates, results):
        # Generators may return a bare list or a GenResult carrying a trace.
        if isinstance(result, GenResult):
            hyps, trace = result.hypotheses, result.trace
        else:
            hyps, trace = result, []
        briefings.append(HuntBriefing(
            article=art, scoring=sc, extraction=ext, hypotheses=hyps, agent_trace=trace,
        ))

    pkg.briefings = briefings
    pkg.total_seen = total
    pkg.skipped = skipped
    return pkg


def to_json(pkg: HuntPackage, path: Path) -> None:
    path.write_text(json.dumps(pkg.to_dict(), indent=2, ensure_ascii=False))


def to_markdown(pkg: HuntPackage, path: Path) -> None:
    path.write_text(render_markdown(pkg))


def render_markdown(pkg: HuntPackage) -> str:
    lines: list[str] = []
    lines.append("# Threat Hunting News Package")
    lines.append("")
    lines.append(f"- Generated: `{pkg.generated_at}`")
    lines.append(f"- Generator: `{pkg.generator} v{pkg.version}`")
    lines.append(f"- Articles seen: **{pkg.total_seen}**  ·  Skipped (below threshold): **{pkg.skipped}**  ·  Briefings: **{len(pkg.briefings)}**")
    lines.append("- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`")
    lines.append("")
    lines.append("---")
    lines.append("")

    for i, b in enumerate(pkg.briefings, start=1):
        a = b.article
        lines.append(f"## {i}. {a.title}")
        lines.append("")
        lines.append(f"- **Source**: {a.source}")
        if a.link:
            lines.append(f"- **Link**: <{a.link}>")
        if a.published:
            lines.append(f"- **Published**: {a.published}")
        if b.first_seen:
            lines.append(f"- **First seen**: {b.first_seen}")
        lines.append(f"- **Relevance score**: {b.scoring.score}")
        lines.append(f"- **Score rationale**: {', '.join(b.scoring.rationale)}")
        if b.agent_trace:
            lines.append(f"- **Agent trace**: {' → '.join(b.agent_trace)}")
        lines.append("")
        if a.summary:
            lines.append(f"> {a.summary}")
            lines.append("")

        e = b.extraction
        ext_lines = []
        if e.cves: ext_lines.append(f"- CVEs: {', '.join(e.cves)}")
        if e.threat_actors: ext_lines.append(f"- Threat actors: {', '.join(e.threat_actors)}")
        if e.malware_families: ext_lines.append(f"- Malware families: {', '.join(e.malware_families)}")
        if e.products: ext_lines.append(f"- Products: {', '.join(e.products)}")
        if e.vectors: ext_lines.append(f"- Vectors: {', '.join(e.vectors)}")
        if e.actions: ext_lines.append(f"- Actions: {', '.join(e.actions)}")
        if e.sectors: ext_lines.append(f"- Sectors: {', '.join(e.sectors)}")
        if e.mitre_techniques: ext_lines.append(f"- MITRE ATT&CK: {', '.join(e.mitre_techniques)}")
        if e.ips: ext_lines.append(f"- IP IOCs: {', '.join(e.ips)}")
        if e.domains: ext_lines.append(f"- Domain IOCs: {', '.join(e.domains)}")
        if e.hashes_sha256: ext_lines.append(f"- SHA256: {', '.join(e.hashes_sha256)}")
        if e.hashes_sha1: ext_lines.append(f"- SHA1: {', '.join(e.hashes_sha1)}")
        if e.hashes_md5: ext_lines.append(f"- MD5: {', '.join(e.hashes_md5)}")
        if ext_lines:
            lines.append("**Extracted signals**")
            lines.extend(ext_lines)
            lines.append("")

        lines.append(f"### Hypotheses ({len(b.hypotheses)})")
        lines.append("")
        for h in b.hypotheses:
            lines.append(f"#### {h.id} · {h.title}  _(confidence: {h.confidence})_")
            lines.append("")
            lines.append(f"**Statement.** {h.statement}")
            lines.append("")
            lines.append(f"**Why this hypothesis?** {h.rationale}")
            lines.append("")
            if h.mitre_attack:
                lines.append(f"**MITRE ATT&CK**: {', '.join(h.mitre_attack)}")
                lines.append("")
            lines.append(f"**CTF objectives ({len(h.objectives)}) — find evidence that disproves the hypothesis:**")
            lines.append("")
            for o in h.objectives:
                lines.append(f"- **[{o.id}] {o.title}** _(difficulty: {o.difficulty} · {o.points} pts · MITRE: {', '.join(o.mitre_attack) or 'n/a'})_")
                lines.append(f"  - Falsification criterion: {o.falsification_criterion}")
                lines.append(f"  - Data sources: {', '.join(o.data_sources)}")
                lines.append(f"  - Suggested query: `{o.suggested_query}`")
            lines.append("")
            if h.sigma_rule.strip():
                lines.append("**Sigma rule:**")
                lines.append("")
                lines.append("```yaml")
                lines.append(h.sigma_rule.strip())
                lines.append("```")
                lines.append("")
        lines.append("---")
        lines.append("")

    if not pkg.briefings:
        lines.append("_No hunt-worthy articles in this run._")
    return "\n".join(lines)
