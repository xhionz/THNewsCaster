"""Aggregations that power the site dashboard and the 'by data source' view.

Pure functions over a HuntPackage so they're easy to unit-test without a
browser.
"""
from __future__ import annotations

from .intel import KILLCHAIN_STAGES, TECHNIQUE_TACTIC
from .models import HuntBriefing, HuntPackage, Hypothesis, Objective

# Criticality tiers, highest first: (label, css class, min score).
TIERS = [("Critical", "crit", 85), ("High", "high", 65), ("Medium", "med", 45), ("Low", "low", 0)]


def is_kev(b: HuntBriefing) -> bool:
    return any(t.startswith("kev:") for t in b.agent_trace)


def criticality(b: HuntBriefing) -> tuple[str, str]:
    score = b.scoring.score
    if is_kev(b) and score < 65:  # actively exploited never ranks below High
        score = 65
    for label, cls, threshold in TIERS:
        if score >= threshold:
            return label, cls
    return "Low", "low"


# --- "By data source" inversion --------------------------------------------

_SOURCE_BUCKETS: list[tuple[str, list[str]]] = [
    ("EDR / Endpoint", ["edr", "sysmon", "crowdstrike", "defender", "sentinelone", "process",
                         "autorun", "endpoint", "file integrity", "yara", "memory", "volatility",
                         "av ", "quarantine", "4688"]),
    ("DNS", ["dns", "passive dns", "resolver"]),
    ("Proxy / Web", ["proxy", "casb", "url", "web filter", "secure web"]),
    ("Firewall / Network", ["firewall", "netflow", "zeek", "conn.log", "ids", "ips", "waf",
                            "ndr", "suricata", "tls", "ja3", "edge", "cdn", "egress"]),
    ("Windows Event Logs", ["security event", "4624", "4625", "4769", "5145", "domain controller",
                            "windows security", "event log", "kerberos"]),
    ("Identity / Cloud", ["entra", "azure ad", "okta", "sign-in", "signin", "mfa", "oauth",
                          "cloud", "aws", "gcp", "google workspace", "duo"]),
    ("Email", ["email", "mail", "exchange", "owa"]),
    ("Asset / Vuln mgmt", ["cmdb", "asset", "scanner", "patch", "sccm", "intune", "tanium",
                           "kandji", "vulnerability", "attack-surface"]),
    ("Threat Intel / SIEM", ["siem", "threat intel", "threat-intel", "tip", "ti "]),
    ("File shares", ["file-share", "file share", "share auditing"]),
    ("Honeypot / Canary", ["honeypot", "canary"]),
    ("ITSM / Help desk", ["ticket", "itsm", "help-desk", "help desk", "recording"]),
]


def normalize_source(raw: str) -> str:
    low = raw.lower()
    for bucket, keys in _SOURCE_BUCKETS:
        if any(k in low for k in keys):
            return bucket
    return "Other"


ObjRef = tuple[HuntBriefing, Hypothesis, Objective]


def objectives_by_source(pkg: HuntPackage) -> list[tuple[str, list[ObjRef]]]:
    """Invert the package: data source -> the objectives that use it.

    Each (briefing, hypothesis, objective) is bucketed by every normalized
    data source it lists. Buckets are returned most-populated first.
    """
    buckets: dict[str, list[ObjRef]] = {}
    for b in pkg.briefings:
        for h in b.hypotheses:
            for o in h.objectives:
                seen: set[str] = set()
                for ds in (o.data_sources or ["Other"]):
                    name = normalize_source(ds)
                    if name in seen:
                        continue
                    seen.add(name)
                    buckets.setdefault(name, []).append((b, h, o))
    ordered = sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)
    return ordered


# --- Kill-chain coverage ----------------------------------------------------

def killchain_coverage(pkg: HuntPackage) -> list[tuple[str, int]]:
    """Count hypotheses touching each ATT&CK stage, in kill-chain order."""
    counts = {s: 0 for s in KILLCHAIN_STAGES}
    for b in pkg.briefings:
        for h in b.hypotheses:
            stages = set()
            ids = list(h.mitre_attack) + [m for o in h.objectives for m in o.mitre_attack]
            for tid in ids:
                stage = TECHNIQUE_TACTIC.get(tid.strip())
                if stage:
                    stages.add(stage)
            for s in stages:
                counts[s] += 1
    return [(s, counts[s]) for s in KILLCHAIN_STAGES]


# --- Likelihood x Impact matrix ---------------------------------------------

def _high_likelihood(b: HuntBriefing) -> bool:
    if is_kev(b):
        return True
    cues = set(b.extraction.vectors) | set(b.extraction.actions)
    return "exploit" in cues


def likelihood_impact(pkg: HuntPackage) -> dict[str, list[HuntBriefing]]:
    """Bucket briefings into the 4 quadrants of a likelihood x impact 2x2."""
    quad = {"hi_hi": [], "hi_lo": [], "lo_hi": [], "lo_lo": []}
    for b in pkg.briefings:
        impact_high = criticality(b)[0] in ("Critical", "High")
        like_high = _high_likelihood(b)
        key = ("hi" if like_high else "lo") + "_" + ("hi" if impact_high else "lo")
        quad[key].append(b)
    return quad
