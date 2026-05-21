"""Aggregate and export IOCs from a hunt package.

IOCs are collected across all briefings, de-duplicated, and grouped by
type in a fixed, analyst-friendly order (CVEs, IPs, domains, then hashes
by strength). Each IOC tracks which articles referenced it. We emit:

* ``iocs.json`` — grouped + sorted, with provenance
* ``iocs.csv``  — flat ``type,value,article_count,sources`` for spreadsheets/SIEM
* ``iocs_stix.json`` — STIX 2.1 bundle (indicators + vulnerabilities)
"""
from __future__ import annotations

import csv
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .models import HuntPackage

# Display/sort order for IOC types.
IOC_ORDER = ["cves", "ips", "domains", "sha256", "sha1", "md5"]

IOC_LABELS = {
    "cves": "CVEs",
    "ips": "IP addresses",
    "domains": "Domains",
    "sha256": "SHA256 hashes",
    "sha1": "SHA1 hashes",
    "md5": "MD5 hashes",
}


@dataclass
class IOCHit:
    value: str
    sources: set[str] = field(default_factory=set)  # article links/titles


def _ip_sort_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _cve_sort_key(cve: str):
    # CVE-YYYY-NNN -> sort newest year, highest number first.
    try:
        _, year, num = cve.split("-")
        return (-int(year), -int(num))
    except (ValueError, IndexError):
        return (0, 0)


def _sorted_values(ioc_type: str, hits: dict[str, IOCHit]) -> list[IOCHit]:
    values = list(hits.values())
    if ioc_type == "ips":
        values.sort(key=lambda h: _ip_sort_key(h.value))
    elif ioc_type == "cves":
        values.sort(key=lambda h: _cve_sort_key(h.value))
    else:
        values.sort(key=lambda h: h.value.lower())
    return values


def aggregate(pkg: HuntPackage) -> dict[str, list[IOCHit]]:
    buckets: dict[str, dict[str, IOCHit]] = {t: {} for t in IOC_ORDER}
    for b in pkg.briefings:
        src = b.article.link or b.article.title
        e = b.extraction
        type_map = {
            "cves": e.cves,
            "ips": e.ips,
            "domains": e.domains,
            "sha256": e.hashes_sha256,
            "sha1": e.hashes_sha1,
            "md5": e.hashes_md5,
        }
        for ioc_type, values in type_map.items():
            for v in values:
                hit = buckets[ioc_type].setdefault(v, IOCHit(value=v))
                hit.sources.add(src)
    return {t: _sorted_values(t, buckets[t]) for t in IOC_ORDER}


def write_json(grouped: dict[str, list[IOCHit]], path: Path) -> None:
    out = {
        t: [{"value": h.value, "sources": sorted(h.sources)} for h in grouped[t]]
        for t in IOC_ORDER
    }
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False))


def write_csv(grouped: dict[str, list[IOCHit]], path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "article_count", "sources"])
        for t in IOC_ORDER:
            for h in grouped[t]:
                w.writerow([t, h.value, len(h.sources), " | ".join(sorted(h.sources))])


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ips":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domains":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{value}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    return None


def write_stix(grouped: dict[str, list[IOCHit]], path: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict] = []
    for t in IOC_ORDER:
        for h in grouped[t]:
            if t == "cves":
                objects.append({
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": h.value,
                    "external_references": [
                        {"source_name": "cve", "external_id": h.value}
                    ],
                })
                continue
            pattern = _stix_pattern(t, h.value)
            if pattern is None:
                continue
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"{IOC_LABELS[t]}: {h.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))


def export_all(pkg: HuntPackage, out_dir: Path) -> dict[str, int]:
    grouped = aggregate(pkg)
    write_json(grouped, out_dir / "iocs.json")
    write_csv(grouped, out_dir / "iocs.csv")
    write_stix(grouped, out_dir / "iocs_stix.json")
    return {t: len(grouped[t]) for t in IOC_ORDER}
