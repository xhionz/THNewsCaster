"""Core data structures for THNewsCaster.

Everything is a plain dataclass so the whole pipeline serialises cleanly to JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Article:
    id: str
    source: str
    title: str
    link: str
    published: str
    summary: str
    raw_text: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class Extraction:
    cves: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes_md5: list[str] = field(default_factory=list)
    hashes_sha1: list[str] = field(default_factory=list)
    hashes_sha256: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    vectors: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)


@dataclass
class Scoring:
    score: int
    rationale: list[str] = field(default_factory=list)
    is_hunt_worthy: bool = False


@dataclass
class Objective:
    id: str
    title: str
    falsification_criterion: str
    data_sources: list[str]
    suggested_query: str
    mitre_attack: list[str]
    difficulty: str  # easy | medium | hard
    points: int


@dataclass
class Hypothesis:
    id: str
    title: str
    statement: str
    rationale: str
    confidence: str  # low | medium | high
    mitre_attack: list[str]
    objectives: list[Objective] = field(default_factory=list)


@dataclass
class HuntBriefing:
    article: Article
    scoring: Scoring
    extraction: Extraction
    hypotheses: list[Hypothesis]


@dataclass
class HuntPackage:
    generated_at: str = field(default_factory=_iso_now)
    generator: str = "THNewsCaster"
    version: str = "0.1.0"
    briefings: list[HuntBriefing] = field(default_factory=list)
    skipped: int = 0
    total_seen: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
