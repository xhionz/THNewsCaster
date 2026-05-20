"""CTF-style disproof objectives.

Each objective is a *falsification test* — a concrete, finite check whose
**absence of evidence** would invalidate (or substantially weaken) the
parent hypothesis. We frame them like CTF goals so a hunter can score
themselves as they go.

Objectives are organised by hypothesis archetype. The hypothesis layer
selects an archetype and asks this module for a freshly numbered set of
3-5 objectives.
"""
from __future__ import annotations

from typing import Callable

from .models import Extraction, Objective

# Each builder returns a list of (title, falsification_criterion, data_sources,
# suggested_query, mitre_attack, difficulty, points) tuples.
ObjectiveSpec = tuple[str, str, list[str], str, list[str], str, int]


def _initial_access_cve(ext: Extraction) -> list[ObjectiveSpec]:
    cve = ext.cves[0] if ext.cves else "the referenced CVE"
    product = ext.products[0] if ext.products else "the affected product"
    return [
        (
            f"Inventory exposure to {product}",
            f"If zero internet-facing assets run a vulnerable build of {product}, the external-exploitation hypothesis is disproven for {cve}.",
            ["Asset CMDB", "External attack-surface scanner", "Vulnerability scanner"],
            f"asset_inventory | where product == '{product}' and exposure == 'internet' and version in (vulnerable_versions)",
            ["T1190"],
            "easy",
            100,
        ),
        (
            "Hunt for exploit attempts at the edge",
            f"If WAF / firewall / IDS show no exploit-signature hits for {cve} in the last 30 days, in-the-wild exploitation against us is unsupported.",
            ["WAF logs", "IDS/IPS", "Edge firewall", "CDN logs"],
            f"edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-{cve}/ | summarize count() by src_ip, dst_host",
            ["T1190", "T1133"],
            "medium",
            200,
        ),
        (
            "Patch-status correlation",
            f"If MDM / patch-management shows 100% deployment of the {cve} fix across exposed hosts, the hypothesis is disproven by remediation.",
            ["SCCM/Intune", "Patch management", "Tanium / Kandji"],
            f"patch_state | where kb in (fixes_for('{cve}')) | summarize coverage = avg(installed) by host_role",
            ["T1190"],
            "easy",
            100,
        ),
        (
            "Post-exploit web-shell sweep",
            f"If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on {product} hosts, post-exploit foothold is unsupported.",
            ["EDR process telemetry", "File integrity monitoring"],
            "process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')",
            ["T1505.003", "T1059"],
            "medium",
            250,
        ),
        (
            "Honeypot / canary check",
            "If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.",
            ["Honeypot logs", "Canary tokens"],
            "canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip",
            ["T1190"],
            "hard",
            300,
        ),
    ]


def _malware_execution(ext: Extraction) -> list[ObjectiveSpec]:
    family = ext.malware_families[0] if ext.malware_families else "the referenced malware family"
    return [
        (
            f"EDR hash sweep for {family}",
            f"If a search of EDR file/process telemetry for known {family} SHA256s returns zero hits in the last 90 days, payload presence is disproven.",
            ["EDR (CrowdStrike/Defender/SentinelOne)", "Threat-intel feed"],
            "process_events | where sha256 in (ti_lookup('" + family + "', 'sha256')) | summarize count() by host",
            ["T1204", "T1059"],
            "easy",
            150,
        ),
        (
            f"Behavioural pattern hunt for {family}",
            "If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.",
            ["Sysmon EID 1", "EDR process tree"],
            "process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')",
            ["T1059.001", "T1059.005", "T1218.011"],
            "medium",
            200,
        ),
        (
            "Persistence-key inspection",
            f"If autoruns, scheduled tasks, services, and WMI subscriptions show no {family}-aligned artifacts, post-execution persistence is disproven.",
            ["Sysmon EID 13/12", "Autoruns sweep", "EDR persistence module"],
            "registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/",
            ["T1547.001", "T1053.005"],
            "medium",
            200,
        ),
        (
            "AV / quarantine retrospective",
            "If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.",
            ["AV management console", "Defender ATP detections"],
            "av_events | where signature contains '" + family + "' | summarize by host, action",
            ["T1204"],
            "easy",
            100,
        ),
        (
            "Memory-resident loader check",
            "If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.",
            ["YARA via EDR", "Volatility on a sampled host"],
            "memory_scan | yara_rule == 'rule_" + family.replace(' ', '_').lower() + "' | summarize by host",
            ["T1620", "T1055"],
            "hard",
            300,
        ),
    ]


def _c2_beacon(ext: Extraction) -> list[ObjectiveSpec]:
    domains = ext.domains[:3] or ["the published C2 domains"]
    ips = ext.ips[:3] or ["the published C2 IPs"]
    return [
        (
            "DNS resolution sweep for published C2 domains",
            "If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.",
            ["DNS resolver logs", "Passive DNS"],
            "dns | where query in (" + ",".join(f"'{d}'" for d in domains) + ") | summarize count() by client_ip",
            ["T1071.004"],
            "easy",
            100,
        ),
        (
            "Egress connections to published C2 IPs",
            "If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.",
            ["Proxy logs", "NetFlow", "Firewall accept logs"],
            "egress | where dst_ip in (" + ",".join(f"'{i}'" for i in ips) + ") | summarize bytes_out = sum(bytes_sent) by src_ip",
            ["T1071", "T1573"],
            "medium",
            200,
        ),
        (
            "Beacon periodicity / jitter analysis",
            "If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.",
            ["NetFlow", "Zeek conn.log"],
            "conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s",
            ["T1071", "T1095"],
            "hard",
            300,
        ),
        (
            "TLS / JA3 fingerprint pivot",
            "If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.",
            ["Zeek ssl.log", "Suricata TLS", "NDR"],
            "tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni",
            ["T1573.002"],
            "hard",
            250,
        ),
        (
            "Remote-monitoring tooling abuse check",
            "If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.",
            ["EDR installed-software", "Process telemetry"],
            "process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'",
            ["T1219"],
            "medium",
            200,
        ),
    ]


def _lateral_movement(ext: Extraction) -> list[ObjectiveSpec]:
    return [
        (
            "Anomalous remote logons (Type 3 / Type 10)",
            "If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.",
            ["Windows Security event log", "Domain Controller logs"],
            "security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10",
            ["T1021.001", "T1021.002"],
            "medium",
            200,
        ),
        (
            "Admin-tool usage outside baseline",
            "If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.",
            ["Sysmon EID 1", "EDR", "4688"],
            "process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)",
            ["T1021.002", "T1021.006", "T1059"],
            "medium",
            200,
        ),
        (
            "Kerberos abuse telemetry",
            "If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.",
            ["Domain Controller security log"],
            "security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name",
            ["T1558.003", "T1110.003"],
            "hard",
            300,
        ),
        (
            "Lateral file-copy staging",
            "If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.",
            ["File-share auditing (5145)", "EDR file events"],
            "file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\\\\\.*\\\\(C\\$|admin\\$)/",
            ["T1570", "T1021.002"],
            "medium",
            200,
        ),
    ]


def _exfiltration(ext: Extraction) -> list[ObjectiveSpec]:
    return [
        (
            "Cloud-storage exfil to non-corp tenants",
            "If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.",
            ["Proxy logs", "CASB / DLP"],
            "proxy | where host matches /mega\\.nz|anonfiles\\.com|transfer\\.sh|filebin\\.net/ | summarize bytes = sum(bytes_out) by user",
            ["T1567.002", "T1567"],
            "easy",
            100,
        ),
        (
            "Archive-then-egress pattern",
            "If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.",
            ["EDR process+file events", "NetFlow"],
            "file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m",
            ["T1560", "T1041"],
            "medium",
            250,
        ),
        (
            "Outbound volume to rare ASNs",
            "If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.",
            ["NetFlow", "Firewall logs"],
            "netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB",
            ["T1041", "T1567"],
            "medium",
            200,
        ),
        (
            "DNS-tunnelling search",
            "If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.",
            ["DNS resolver logs"],
            "dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000",
            ["T1071.004", "T1048.003"],
            "hard",
            300,
        ),
    ]


def _identity_compromise(ext: Extraction) -> list[ObjectiveSpec]:
    return [
        (
            "Impossible-travel / atypical sign-ins",
            "If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.",
            ["Entra ID sign-in logs", "Okta system log"],
            "signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip",
            ["T1078.004"],
            "easy",
            100,
        ),
        (
            "MFA-fatigue / push-bombing",
            "If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.",
            ["MFA provider logs (Duo / Entra)"],
            "mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0",
            ["T1621", "T1078"],
            "medium",
            200,
        ),
        (
            "Help-desk social-engineering pivot",
            "If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.",
            ["ITSM ticket data", "Help-desk recordings"],
            "tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id",
            ["T1078", "T1556"],
            "hard",
            250,
        ),
        (
            "OAuth illicit-consent grants",
            "If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.",
            ["Entra ID audit log", "Google Workspace audit"],
            "audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'",
            ["T1528"],
            "medium",
            200,
        ),
    ]


ARCHETYPES: dict[str, Callable[[Extraction], list[ObjectiveSpec]]] = {
    "initial_access_cve": _initial_access_cve,
    "malware_execution": _malware_execution,
    "c2_beacon": _c2_beacon,
    "lateral_movement": _lateral_movement,
    "exfiltration": _exfiltration,
    "identity_compromise": _identity_compromise,
}


def build_objectives(archetype: str, ext: Extraction, hyp_id: str, min_count: int = 3, max_count: int = 5) -> list[Objective]:
    spec_fn = ARCHETYPES.get(archetype)
    if spec_fn is None:
        return []
    specs = spec_fn(ext)
    # Always emit between min_count and max_count objectives.
    chosen = specs[:max(min_count, min(max_count, len(specs)))]
    out: list[Objective] = []
    for idx, (title, crit, ds, query, mitre, diff, points) in enumerate(chosen, start=1):
        out.append(
            Objective(
                id=f"{hyp_id}-O{idx}",
                title=title,
                falsification_criterion=crit,
                data_sources=ds,
                suggested_query=query,
                mitre_attack=mitre,
                difficulty=diff,
                points=points,
            )
        )
    return out
