"""Extract threat-hunting signals from article text.

Pulls IOCs (CVE/IP/domain/hash) by regex and entities (malware, actors,
techniques, vectors, sectors, products) by case-insensitive alias lookup
from :mod:`thnewscaster.intel`.
"""
from __future__ import annotations

import re

from .intel import (
    ACTION_KEYWORDS,
    MALWARE_FAMILIES,
    MITRE_TECHNIQUES,
    PRODUCT_KEYWORDS,
    SECTOR_KEYWORDS,
    THREAT_ACTORS,
    VECTOR_KEYWORDS,
)
from .models import Article, Extraction

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
# Domains: must contain a dot and a 2+ letter TLD. Refanged forms (foo[.]bar) handled below.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_REFANG_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}")

# Filter out obvious non-IOC domains (news sites, common platforms).
_DOMAIN_DENYLIST = {
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
    "darkreading.com", "securityweek.com", "cisa.gov", "ncsc.gov.uk",
    "microsoft.com", "google.com", "blogspot.com", "talosintelligence.com",
    "crowdstrike.com", "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "reddit.com", "infosec.exchange", "twitter.com", "x.com", "mastodon.social",
    "github.com", "youtube.com", "medium.com", "wordpress.com", "feedburner.com",
    "example.com", "example.org",
}


def _dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        k = x.lower() if isinstance(x, str) else x
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def _refang(text: str) -> str:
    return _REFANG_RE.sub(".", text)


def _match_aliases(text_lower: str, table: dict[str, list[str]]) -> list[str]:
    hits = []
    for canonical, aliases in table.items():
        for alias in aliases:
            if alias in text_lower:
                hits.append(canonical)
                break
    return hits


def extract(article: Article) -> Extraction:
    text = _refang(f"{article.title}\n{article.summary}\n{article.raw_text}")
    lower = text.lower()

    cves = _dedupe(m.upper() for m in _CVE_RE.findall(text))
    ips = _dedupe(_IP_RE.findall(text))
    # Drop IPs that look like CVE byproducts or non-routable noise
    ips = [ip for ip in ips if not ip.startswith(("0.", "255.255.255."))]

    raw_domains = _dedupe(d.lower() for d in _DOMAIN_RE.findall(text))
    domains = [
        d for d in raw_domains
        if d not in _DOMAIN_DENYLIST
        and not d.endswith(".png")
        and not d.endswith(".jpg")
        and not d.endswith(".svg")
    ]

    md5 = _dedupe(h.lower() for h in _MD5_RE.findall(text))
    sha1 = _dedupe(h.lower() for h in _SHA1_RE.findall(text))
    sha256 = _dedupe(h.lower() for h in _SHA256_RE.findall(text))
    # SHA256 matches will also match against MD5/SHA1 substrings under the
    # regex above when overlapping; ensure mutually exclusive buckets:
    md5 = [h for h in md5 if h not in sha1 and h not in sha256]
    sha1 = [h for h in sha1 if h not in sha256]

    malware = _match_aliases(lower, MALWARE_FAMILIES)
    actors = _match_aliases(lower, THREAT_ACTORS)
    techniques = _match_aliases(lower, MITRE_TECHNIQUES)
    vectors = _match_aliases(lower, VECTOR_KEYWORDS)
    sectors = _match_aliases(lower, SECTOR_KEYWORDS)
    actions = _match_aliases(lower, ACTION_KEYWORDS)
    products = _match_aliases(lower, PRODUCT_KEYWORDS)

    return Extraction(
        cves=cves,
        ips=ips,
        domains=domains,
        hashes_md5=md5,
        hashes_sha1=sha1,
        hashes_sha256=sha256,
        malware_families=malware,
        threat_actors=actors,
        mitre_techniques=techniques,
        vectors=vectors,
        sectors=sectors,
        actions=actions,
        products=products,
    )
