"""Assemble the end-to-end hunt package and render it to JSON / Markdown."""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .extraction import extract
from .hypotheses import generate
from .models import Article, HuntBriefing, HuntPackage
from .relevance import DEFAULT_THRESHOLD, score
from .sources import SOURCE_WEIGHTS

log = logging.getLogger(__name__)


def _source_kind(source_name: str, source_map: dict[str, str]) -> str:
    return source_map.get(source_name, "news")


def build_package(
    articles: Iterable[Article],
    *,
    source_kinds: dict[str, str] | None = None,
    threshold: int = DEFAULT_THRESHOLD,
    max_briefings: int | None = 25,
) -> HuntPackage:
    pkg = HuntPackage()
    source_kinds = source_kinds or {}
    briefings: list[HuntBriefing] = []
    total = 0
    skipped = 0
    for art in articles:
        total += 1
        ext = extract(art)
        sc = score(ext, source_kind=_source_kind(art.source, source_kinds), threshold=threshold)
        if not sc.is_hunt_worthy:
            skipped += 1
            continue
        hyps = generate(art, ext)
        briefings.append(HuntBriefing(article=art, scoring=sc, extraction=ext, hypotheses=hyps))

    briefings.sort(key=lambda b: b.scoring.score, reverse=True)
    if max_briefings is not None:
        briefings = briefings[:max_briefings]
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
        lines.append(f"- **Relevance score**: {b.scoring.score}")
        lines.append(f"- **Score rationale**: {', '.join(b.scoring.rationale)}")
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
        lines.append("---")
        lines.append("")

    if not pkg.briefings:
        lines.append("_No hunt-worthy articles in this run._")
    return "\n".join(lines)
