"""Configurable focus criteria for the news feed.

Lets an operator express what they care about across several dimensions
(sectors, threat actors, malware, vectors, products, free-text keywords).
Two effects, both env-driven:

* **Boost** — any article matching a focus value gets a score bump per
  matched dimension, so relevant stories rank higher. Non-matching
  articles are still kept if they clear the threshold.
* **Require** (optional, ``THNC_FOCUS_REQUIRE=true``) — when focus values
  are configured, an article must match at least one of them or it is
  dropped. Turns the boost list into a hard filter.

Independently, ``THNC_EXCLUDE_KEYWORDS`` always drops matching articles.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .models import Article, Extraction, Scoring


def _csv_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def _matches(focus: list[str], values: list[str]) -> list[str]:
    """Return the focus tokens that match any of the extracted values."""
    hits = []
    vlower = [v.lower() for v in values]
    for token in focus:
        if any(token in v or v in token for v in vlower):
            hits.append(token)
    return hits


@dataclass
class FocusCriteria:
    sectors: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    vectors: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)        # boost (free text)
    exclude_keywords: list[str] = field(default_factory=list)  # always drop
    boost_points: int = 20
    require: bool = False

    @property
    def has_focus(self) -> bool:
        return any([
            self.sectors, self.actors, self.malware,
            self.vectors, self.products, self.keywords,
        ])

    @property
    def active(self) -> bool:
        return self.has_focus or bool(self.exclude_keywords)

    @classmethod
    def from_env(cls) -> "FocusCriteria":
        try:
            boost = int(os.environ.get("THNC_FOCUS_BOOST", "20"))
        except ValueError:
            boost = 20
        return cls(
            sectors=_csv_env("THNC_FOCUS_SECTORS"),
            actors=_csv_env("THNC_FOCUS_ACTORS"),
            malware=_csv_env("THNC_FOCUS_MALWARE"),
            vectors=_csv_env("THNC_FOCUS_VECTORS"),
            products=_csv_env("THNC_FOCUS_PRODUCTS"),
            keywords=_csv_env("THNC_FOCUS_KEYWORDS"),
            exclude_keywords=_csv_env("THNC_EXCLUDE_KEYWORDS"),
            boost_points=boost,
            require=os.environ.get("THNC_FOCUS_REQUIRE", "").strip().lower()
            in ("1", "true", "yes", "on"),
        )

    def _keyword_hits(self, article: Article, focus: list[str]) -> list[str]:
        text = f"{article.title} {article.summary} {article.raw_text}".lower()
        return [k for k in focus if k in text]

    def apply(self, article: Article, ext: Extraction, scoring: Scoring) -> bool:
        """Mutate ``scoring`` (boost + rationale) and return False to drop.

        Does not touch ``is_hunt_worthy`` thresholding — the caller still
        applies the score threshold afterwards.
        """
        if not self.active:
            return True

        # Hard exclude always wins.
        if self.exclude_keywords and self._keyword_hits(article, self.exclude_keywords):
            return False

        matched: list[str] = []
        dim_hits = {
            "sector": _matches(self.sectors, ext.sectors),
            "actor": _matches(self.actors, ext.threat_actors),
            "malware": _matches(self.malware, ext.malware_families),
            "vector": _matches(self.vectors, ext.vectors),
            "product": _matches(self.products, ext.products),
            "keyword": self._keyword_hits(article, self.keywords),
        }
        for dim, hits in dim_hits.items():
            if hits:
                matched.append(f"{dim}:{'/'.join(hits)}")

        if matched:
            gain = self.boost_points * len(matched)
            scoring.score += gain
            scoring.rationale.append(f"focus match [{', '.join(matched)}]=+{gain}")

        if self.require and self.has_focus and not matched:
            return False
        return True
