"""Score articles for threat-hunting relevance.

A hunt-worthy story typically combines:

* a concrete vulnerability or exploit (CVE, RCE, edge device);
* an actor or malware family the hunter can pivot on;
* one or more actions (ransomware, exfil, espionage) that map to MITRE.

Articles below a configurable threshold are still passed through but
flagged ``is_hunt_worthy=False`` so they can be filtered out of the
final package.
"""
from __future__ import annotations

from .models import Extraction, Scoring
from .sources import SOURCE_WEIGHTS

DEFAULT_THRESHOLD = 30


def score(extraction: Extraction, source_kind: str = "news", threshold: int = DEFAULT_THRESHOLD) -> Scoring:
    pts = 0
    rationale: list[str] = []

    base = SOURCE_WEIGHTS.get(source_kind, 5)
    pts += base
    rationale.append(f"source weight ({source_kind})=+{base}")

    if extraction.cves:
        gain = min(30, 15 + 5 * len(extraction.cves))
        pts += gain
        rationale.append(f"{len(extraction.cves)} CVE(s)=+{gain}")

    if extraction.malware_families:
        gain = min(30, 15 + 5 * len(extraction.malware_families))
        pts += gain
        rationale.append(f"{len(extraction.malware_families)} malware family hit(s)=+{gain}")

    if extraction.threat_actors:
        gain = min(25, 15 + 5 * len(extraction.threat_actors))
        pts += gain
        rationale.append(f"{len(extraction.threat_actors)} threat actor hit(s)=+{gain}")

    if extraction.mitre_techniques:
        gain = min(20, 5 + 3 * len(extraction.mitre_techniques))
        pts += gain
        rationale.append(f"{len(extraction.mitre_techniques)} MITRE technique hit(s)=+{gain}")

    if extraction.vectors:
        gain = min(15, 5 + 2 * len(extraction.vectors))
        pts += gain
        rationale.append(f"{len(extraction.vectors)} initial-access vector(s)=+{gain}")

    if extraction.actions:
        gain = min(15, 5 + 3 * len(extraction.actions))
        pts += gain
        rationale.append(f"{len(extraction.actions)} impact action(s)=+{gain}")

    if extraction.products:
        gain = min(10, 3 * len(extraction.products))
        pts += gain
        rationale.append(f"{len(extraction.products)} product mention(s)=+{gain}")

    ioc_count = (
        len(extraction.ips) + len(extraction.domains)
        + len(extraction.hashes_md5) + len(extraction.hashes_sha1) + len(extraction.hashes_sha256)
    )
    if ioc_count:
        gain = min(15, 2 + 2 * ioc_count)
        pts += gain
        rationale.append(f"{ioc_count} IOC(s)=+{gain}")

    return Scoring(score=pts, rationale=rationale, is_hunt_worthy=pts >= threshold)
