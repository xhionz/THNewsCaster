"""Hypothesis generator.

For each hunt-worthy article we emit **at least 3** hypotheses. Selection
is driven by what the extractor saw:

* CVE / vector / product   -> "initial_access_cve"
* malware family           -> "malware_execution"
* IOC IPs / domains        -> "c2_beacon"
* ransomware / APT actor   -> "lateral_movement"
* data-breach / exfil cue  -> "exfiltration"
* credential / MFA / OAuth -> "identity_compromise"

If fewer than three archetypes match, we top up with sensible defaults
(``c2_beacon``, ``identity_compromise``) so every relevant article gets a
complete hunt package.
"""
from __future__ import annotations

from .models import Article, Extraction, Hypothesis
from .objectives import ARCHETYPES, build_objectives


def _hyp_id(article_id: str, n: int) -> str:
    return f"H-{article_id[:8]}-{n}"


def _statement_and_rationale(archetype: str, art: Article, ext: Extraction) -> tuple[str, str, str, list[str]]:
    """Return (title, statement, confidence, mitre_attack) for an archetype."""
    if archetype == "initial_access_cve":
        cve = ext.cves[0] if ext.cves else "the disclosed vulnerability"
        product = ext.products[0] if ext.products else "the affected product/service"
        title = f"Initial access via {cve} affecting {product}"
        stmt = (
            f"A threat actor has attempted to obtain initial access to our environment "
            f"by exploiting {cve} in {product} within the last 30 days."
        )
        conf = "high" if ext.cves and ext.products else "medium"
        return title, stmt, conf, ["T1190", "T1133"]

    if archetype == "malware_execution":
        family = ext.malware_families[0] if ext.malware_families else "the referenced malware family"
        title = f"Endpoint execution of {family}"
        stmt = (
            f"One or more endpoints in the estate have executed or attempted to execute "
            f"{family} payloads since the reporting date."
        )
        conf = "high" if ext.malware_families else "low"
        return title, stmt, conf, ["T1204", "T1059", "T1547"]

    if archetype == "c2_beacon":
        title = "Outbound C2 beaconing to reported infrastructure"
        stmt = (
            "Hosts in the estate are beaconing to the command-and-control infrastructure "
            "reported in this article (domains, IPs, TLS fingerprints, or RMM tooling)."
        )
        conf = "high" if (ext.domains or ext.ips) else "medium"
        return title, stmt, conf, ["T1071", "T1573", "T1219"]

    if archetype == "lateral_movement":
        actor = ext.threat_actors[0] if ext.threat_actors else "the reported actor"
        title = f"Post-foothold lateral movement consistent with {actor}"
        stmt = (
            f"An attacker who matched the TTPs of {actor} has moved laterally inside the "
            "estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse."
        )
        conf = "medium"
        return title, stmt, conf, ["T1021.001", "T1021.002", "T1021.006", "T1003"]

    if archetype == "exfiltration":
        title = "Data staging and exfiltration to attacker-controlled storage"
        stmt = (
            "Sensitive data has been staged (archived) and exfiltrated to attacker-controlled "
            "endpoints or cloud-storage tenants in the reporting window."
        )
        conf = "medium"
        return title, stmt, conf, ["T1560", "T1041", "T1567", "T1567.002"]

    if archetype == "identity_compromise":
        title = "Identity compromise of privileged users"
        stmt = (
            "Privileged identities have been compromised through phishing, MFA fatigue, "
            "help-desk social engineering, or OAuth illicit-consent grants."
        )
        conf = "medium"
        return title, stmt, conf, ["T1078", "T1621", "T1528", "T1556"]

    return ("Generic threat hunt", "Indicators in the article warrant a generic hunt.", "low", [])


def _select_archetypes(ext: Extraction) -> list[str]:
    picked: list[str] = []

    if ext.cves or "exploit" in ext.vectors or ext.products:
        picked.append("initial_access_cve")
    if ext.malware_families:
        picked.append("malware_execution")
    if ext.domains or ext.ips or "credential-theft" in ext.vectors:
        picked.append("c2_beacon")
    if ext.threat_actors or "ransomware" in ext.actions:
        picked.append("lateral_movement")
    if "data-breach" in ext.actions or "espionage" in ext.actions:
        picked.append("exfiltration")
    if "social-engineering" in ext.vectors or "cloud-misconfig" in ext.vectors:
        picked.append("identity_compromise")

    # Ensure at least 3 archetypes.
    defaults = ["c2_beacon", "identity_compromise", "lateral_movement", "malware_execution", "initial_access_cve"]
    for d in defaults:
        if len(picked) >= 3:
            break
        if d not in picked:
            picked.append(d)

    # De-duplicate while preserving order, cap at 4 to keep packages tight.
    seen: set[str] = set()
    out: list[str] = []
    for a in picked:
        if a in seen:
            continue
        seen.add(a)
        out.append(a)
        if len(out) >= 4:
            break
    return out


def generate(article: Article, ext: Extraction) -> list[Hypothesis]:
    archetypes = _select_archetypes(ext)
    hyps: list[Hypothesis] = []
    for n, arch in enumerate(archetypes, start=1):
        if arch not in ARCHETYPES:
            continue
        hid = _hyp_id(article.id, n)
        title, stmt, conf, mitre = _statement_and_rationale(arch, article, ext)
        rationale = _rationale(arch, ext)
        objs = build_objectives(arch, ext, hid, min_count=3, max_count=5)
        hyps.append(
            Hypothesis(
                id=hid,
                title=title,
                statement=stmt,
                rationale=rationale,
                confidence=conf,
                mitre_attack=mitre,
                objectives=objs,
            )
        )
    return hyps


def _rationale(archetype: str, ext: Extraction) -> str:
    bits = []
    if ext.cves:
        bits.append(f"CVEs cited: {', '.join(ext.cves[:3])}")
    if ext.malware_families:
        bits.append(f"malware families: {', '.join(ext.malware_families[:3])}")
    if ext.threat_actors:
        bits.append(f"threat actors: {', '.join(ext.threat_actors[:3])}")
    if ext.vectors:
        bits.append(f"vectors: {', '.join(ext.vectors[:3])}")
    if ext.actions:
        bits.append(f"impact: {', '.join(ext.actions[:3])}")
    if ext.products:
        bits.append(f"products: {', '.join(ext.products[:3])}")
    if not bits:
        bits.append("article extraction yielded only weak signals; treat as exploratory")
    return f"Archetype '{archetype}' selected based on " + "; ".join(bits) + "."
