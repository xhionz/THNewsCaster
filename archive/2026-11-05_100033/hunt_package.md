# Threat Hunting News Package

- Generated: `2026-11-05T10:00:30+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **385**  ·  Skipped (below threshold): **385**  ·  Briefings: **50**
- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`

---

## 1. IR trends Q3 2026: Actors impersonate IT help desks in vishing attacks as ransomware activity increases

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/ir-trends-q3-2026/>
- **Published**: Thu, 29 Oct 2026 14:00:00 GMT
- **First seen**: 2026-10-29T14:19:36+00:00
- **Relevance score**: 133
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 malware family hit(s)=+20, 1 threat actor hit(s)=+20, 17 MITRE technique hit(s)=+20, 7 initial-access vector(s)=+15, 3 impact action(s)=+14, 6 IOC(s)=+14

> Phishing remained the leading initial access technique, while percentage of ransomware and pre-ransomware cases increased. Finance and public administration tied as the top-targeted industries.

**Extracted signals**
- CVEs: CVE-2023-20198
- Threat actors: Salt Typhoon
- Malware families: Rhysida
- Vectors: phishing, exploit, vpn-edge, rdp, smb, credential-theft, social-engineering
- Actions: ransomware, data-breach, espionage
- Sectors: finance, energy, manufacturing, telecom
- MITRE ATT&CK: T1566, T1190, T1133, T1078, T1059, T1059.001, T1053, T1055, T1021.001, T1021.002, T1486, T1041, T1219, T1218.011, T1098, T1110, T1505.003
- Domain IOCs: psexec.exe, taskkill.exe, cscm.exe, sfc.exe, fly.exe, node.js

### Hypotheses (4)

#### H-c6dbd2d4-1 · Initial access via CVE-2023-20198 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2023-20198 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2023-20198; malware families: Rhysida; threat actors: Salt Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, espionage.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6dbd2d4-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2023-20198.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c6dbd2d4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2023-20198 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2023-20198/ | summarize count() by src_ip, dst_host`
- **[H-c6dbd2d4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2023-20198 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2023-20198')) | summarize coverage = avg(installed) by host_role`
- **[H-c6dbd2d4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c6dbd2d4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c6dbd2d4-2 · Endpoint execution of Rhysida  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Rhysida payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on CVEs cited: CVE-2023-20198; malware families: Rhysida; threat actors: Salt Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, espionage.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6dbd2d4-2-O1] EDR hash sweep for Rhysida** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Rhysida SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Rhysida', 'sha256')) | summarize count() by host`
- **[H-c6dbd2d4-2-O2] Behavioural pattern hunt for Rhysida** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-c6dbd2d4-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Rhysida-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-c6dbd2d4-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Rhysida' | summarize by host, action`
- **[H-c6dbd2d4-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_rhysida' | summarize by host`

#### H-c6dbd2d4-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2023-20198; malware families: Rhysida; threat actors: Salt Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, espionage.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6dbd2d4-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('psexec.exe','taskkill.exe','cscm.exe') | summarize count() by client_ip`
- **[H-c6dbd2d4-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c6dbd2d4-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c6dbd2d4-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c6dbd2d4-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c6dbd2d4-4 · Post-foothold lateral movement consistent with Salt Typhoon  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Salt Typhoon has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2023-20198; malware families: Rhysida; threat actors: Salt Typhoon; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, espionage.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c6dbd2d4-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-c6dbd2d4-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-c6dbd2d4-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-c6dbd2d4-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 2. Inside KeyDrift: Analyzing historical UAT-11473 activity on Cisco SD-WAN

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/uat-11473-keydrift/>
- **Published**: Wed, 28 Oct 2026 21:32:02 GMT
- **First seen**: 2026-10-28T21:49:09+00:00
- **Relevance score**: 103
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 malware family hit(s)=+20, 1 threat actor hit(s)=+20, 2 MITRE technique hit(s)=+11, 1 initial-access vector(s)=+7, 1 product mention(s)=+3, 5 IOC(s)=+12

> Talos has identified UAT-11473, a highly sophisticated APT, who exploited CVE-2026-20127, an authentication bypass vulnerability in Cisco SD-WAN Catalyst Controller instances to bypass authentication and gain unauthorized access to affected systems to deploy KeyDrift.

**Extracted signals**
- CVEs: CVE-2026-20127
- Threat actors: Volt Typhoon
- Malware families: Cobalt Strike
- Products: Microsoft Exchange
- Vectors: exploit
- Sectors: manufacturing
- MITRE ATT&CK: T1055, T1573
- Domain IOCs: rootfs.rw, libdssl.so, libcommon.so, vdaemon.bin, vdaemon.conf

### Hypotheses (4)

#### H-f05bad2a-1 · Initial access via CVE-2026-20127 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-20127 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-20127; malware families: Cobalt Strike; threat actors: Volt Typhoon; vectors: exploit; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f05bad2a-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-20127.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-f05bad2a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-20127 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-20127/ | summarize count() by src_ip, dst_host`
- **[H-f05bad2a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-20127 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-20127')) | summarize coverage = avg(installed) by host_role`
- **[H-f05bad2a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-f05bad2a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-f05bad2a-2 · Endpoint execution of Cobalt Strike  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cobalt Strike payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on CVEs cited: CVE-2026-20127; malware families: Cobalt Strike; threat actors: Volt Typhoon; vectors: exploit; products: Microsoft Exchange.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f05bad2a-2-O1] EDR hash sweep for Cobalt Strike** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cobalt Strike SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cobalt Strike', 'sha256')) | summarize count() by host`
- **[H-f05bad2a-2-O2] Behavioural pattern hunt for Cobalt Strike** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-f05bad2a-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cobalt Strike-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-f05bad2a-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cobalt Strike' | summarize by host, action`
- **[H-f05bad2a-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cobalt_strike' | summarize by host`

#### H-f05bad2a-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-20127; malware families: Cobalt Strike; threat actors: Volt Typhoon; vectors: exploit; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f05bad2a-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('rootfs.rw','libdssl.so','libcommon.so') | summarize count() by client_ip`
- **[H-f05bad2a-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-f05bad2a-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-f05bad2a-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-f05bad2a-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-f05bad2a-4 · Post-foothold lateral movement consistent with Volt Typhoon  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Volt Typhoon has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-20127; malware families: Cobalt Strike; threat actors: Volt Typhoon; vectors: exploit; products: Microsoft Exchange.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f05bad2a-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-f05bad2a-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-f05bad2a-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-f05bad2a-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 3. NIK C2: The new AI-enabled command-and-control framework

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/>
- **Published**: Thu, 29 Oct 2026 10:00:00 GMT
- **First seen**: 2026-10-29T10:05:07+00:00
- **Relevance score**: 90
- **Score rationale**: source weight (vendor)=+10, 1 malware family hit(s)=+20, 7 MITRE technique hit(s)=+20, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 1 product mention(s)=+3, 24 IOC(s)=+15

> Cisco Talos observed a new AI-integrated command-and-control (C2) framework in the wild called “NIK C2.”

**Extracted signals**
- Malware families: Cobalt Strike
- Products: Microsoft Exchange
- Vectors: phishing, exploit, rdp
- Actions: ransomware, fraud
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1059, T1059.001, T1547, T1003, T1021.001, T1486, T1219
- IP IOCs: 87.120.196.120
- Domain IOCs: main.go, total-sitevv.lol, api.openai.com, svchost.exe, simvol.exe, mshta.exe, bootkit.bin, exec.command, key4.db, logins.json, places.sqlite, formhistory.sqlite, exodus.wallet, wallet.dat, browserdata.zip, csrss.exe, os.exit, fodhelper.exe, system.management.automation.dll, win.trojan.godiscorder
- SHA256: d791dd0ff3228ed29a8d7333d4567be829159c5632ea347780992006f91c5295, 4887afc0a574e9419a9695ef083460f58e4ef9a1c40793523ce112251273bdf9
- SHA1: 7d16381a9de823943b5a0987dbd0f26edf22052b

### Hypotheses (4)

#### H-bd3a7393-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, rdp; impact: ransomware, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bd3a7393-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-bd3a7393-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-bd3a7393-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-bd3a7393-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-bd3a7393-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-bd3a7393-2 · Endpoint execution of Cobalt Strike  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cobalt Strike payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, rdp; impact: ransomware, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bd3a7393-2-O1] EDR hash sweep for Cobalt Strike** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cobalt Strike SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cobalt Strike', 'sha256')) | summarize count() by host`
- **[H-bd3a7393-2-O2] Behavioural pattern hunt for Cobalt Strike** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-bd3a7393-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cobalt Strike-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-bd3a7393-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cobalt Strike' | summarize by host, action`
- **[H-bd3a7393-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cobalt_strike' | summarize by host`

#### H-bd3a7393-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, rdp; impact: ransomware, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bd3a7393-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('main.go','total-sitevv.lol','api.openai.com') | summarize count() by client_ip`
- **[H-bd3a7393-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('87.120.196.120') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bd3a7393-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bd3a7393-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bd3a7393-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bd3a7393-4 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on malware families: Cobalt Strike; vectors: phishing, exploit, rdp; impact: ransomware, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bd3a7393-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-bd3a7393-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-bd3a7393-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-bd3a7393-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 4. Inside a malicious Claude Code-branded extension and its persistent SSH backdoor

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/>
- **Published**: Sat, 31 Oct 2026 01:02:57 +0000
- **First seen**: 2026-10-31T02:40:58+00:00
- **Relevance score**: 82
- **Score rationale**: source weight (vendor)=+10, 1 malware family hit(s)=+20, 4 MITRE technique hit(s)=+17, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 10 IOC(s)=+15

> Microsoft analyzes a malicious Claude Code–branded extension, its persistent SSH backdoor, and guidance to detect and remediate it. The post Inside a malicious Claude Code-branded extension and its persistent SSH backdoor appeared first on Microsoft Security Blog .

**Extracted signals**
- Malware families: Cobalt Strike
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, supply-chain
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053, T1547
- IP IOCs: 134.209.82.225
- Domain IOCs: anthropic.claude, node.js, com.apple.sysmond.plist, smt.cmd, sysmon.cmd, com.apple.sysmond, credtheft.ms
- SHA256: ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15, 7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278

### Hypotheses (3)

#### H-b29d72f0-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on malware families: Cobalt Strike; vectors: phishing, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b29d72f0-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-b29d72f0-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-b29d72f0-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-b29d72f0-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-b29d72f0-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-b29d72f0-2 · Endpoint execution of Cobalt Strike  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cobalt Strike payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: Cobalt Strike; vectors: phishing, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b29d72f0-2-O1] EDR hash sweep for Cobalt Strike** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cobalt Strike SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cobalt Strike', 'sha256')) | summarize count() by host`
- **[H-b29d72f0-2-O2] Behavioural pattern hunt for Cobalt Strike** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-b29d72f0-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cobalt Strike-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-b29d72f0-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cobalt Strike' | summarize by host, action`
- **[H-b29d72f0-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cobalt_strike' | summarize by host`

#### H-b29d72f0-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: Cobalt Strike; vectors: phishing, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b29d72f0-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('anthropic.claude','node.js','com.apple.sysmond.plist') | summarize count() by client_ip`
- **[H-b29d72f0-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('134.209.82.225') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-b29d72f0-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-b29d72f0-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-b29d72f0-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 5. EPICS Base

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01>
- **Published**: Tue, 27 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-27T15:50:42+00:00
- **Relevance score**: 78
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to cause a denial-of-service condition, corrupt memory, disclose sensitive information, or potentially execute arbitrary code. The following versions of EPICS Base are affected: EPICS Base release CVSS Vendor Equipment v3 9.8 The EPICS Community EPICS Base release 3 Vulnerabilities Integer Overflow or Wraparound, Improper Handling of Length Parameter Inconsistency, Access of Resource Using Incompatible Type ('Type Confusion') Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Global Vulnerabilities Expand All + CVE-2026-114595 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution. Read More 1 Affected Product The EPICS Community EPICS Base release: Product Status: known_affected Remediations Mitigation The EPICS Community has made available updates to the epics-base GitHub repositories. Affected users should update to the 7.0.11 release. For more information, users should contact the EPICS Controls team https://epics-controls.org/support/. Mitigation https://github.com/epics-base/epics-base/pull/934 Mitigation https://github.com/epics-base/epics-base/pull/937 Mitigation https://githu

**Extracted signals**
- CVEs: CVE-2026-114595, CVE-2026-114596, CVE-2026-114597, CVE-2026-114598
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Actions: ddos
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: epics-controls.org

### Hypotheses (3)

#### H-87b173e0-1 · Initial access via CVE-2026-114595 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-114595 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-114595, CVE-2026-114596, CVE-2026-114597; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87b173e0-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-114595.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-87b173e0-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-114595 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-114595/ | summarize count() by src_ip, dst_host`
- **[H-87b173e0-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-114595 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-114595')) | summarize coverage = avg(installed) by host_role`
- **[H-87b173e0-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-87b173e0-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-87b173e0-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-114595, CVE-2026-114596, CVE-2026-114597; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87b173e0-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('epics-controls.org') | summarize count() by client_ip`
- **[H-87b173e0-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-87b173e0-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-87b173e0-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-87b173e0-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-87b173e0-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-114595, CVE-2026-114596, CVE-2026-114597; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-87b173e0-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-87b173e0-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-87b173e0-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-87b173e0-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 6. From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/>
- **Published**: Fri, 30 Oct 2026 16:11:44 +0000
- **First seen**: 2026-10-30T19:04:55+00:00
- **Relevance score**: 75
- **Score rationale**: source weight (vendor)=+10, 5 MITRE technique hit(s)=+20, 4 initial-access vector(s)=+13, 2 impact action(s)=+11, 2 product mention(s)=+6, 10 IOC(s)=+15

> Teams support impersonation led to remote access, malicious runtime execution, and Certificate Services abuse through authentication relay and Kerberos. The post From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID, Active Directory
- Vectors: phishing, exploit, smb, social-engineering
- Actions: data-breach, fraud
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1566, T1059, T1059.003, T1021.002, T1219
- Domain IOCs: onmicrosoft.com, searchapp.exe, support.microsoft.com, learn.microsoft.com, bun.exe, java.exe, javaw.exe
- SHA256: 85b6c424117494d3056e88689dbc94c75e9afdb187a339714043aec0da109f17, f326201269f1ee2f803ae435317507263bb6e0dbfdeb70bd1bb5446e2e46f001, 06c5c14f043aee3bcc5843b5f50909623d5c9a6239a7c1fba9cddad4111469e7

### Hypotheses (4)

#### H-97541fcf-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, smb; impact: data-breach, fraud; products: Microsoft 365 / Entra ID, Active Directory.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-97541fcf-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-97541fcf-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-97541fcf-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-97541fcf-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-97541fcf-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-97541fcf-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, smb; impact: data-breach, fraud; products: Microsoft 365 / Entra ID, Active Directory.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-97541fcf-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('onmicrosoft.com','searchapp.exe','support.microsoft.com') | summarize count() by client_ip`
- **[H-97541fcf-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-97541fcf-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-97541fcf-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-97541fcf-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-97541fcf-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit, smb; impact: data-breach, fraud; products: Microsoft 365 / Entra ID, Active Directory.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-97541fcf-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-97541fcf-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-97541fcf-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-97541fcf-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

#### H-97541fcf-4 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, smb; impact: data-breach, fraud; products: Microsoft 365 / Entra ID, Active Directory.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-97541fcf-4-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-97541fcf-4-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-97541fcf-4-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-97541fcf-4-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 7. Siemens RUGGEDCOM CROSSBOW

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-12>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 74
- **Score rationale**: source weight (advisory)=+15, 11 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 IOC(s)=+4

> View CSAF Summary RUGGEDCOM CROSSBOW contains multiple vulnerabilities that could allow an attacker to execute arbitrary SQL commands on the underlying database, retrieve sensitive administrative credentials, escalate privileges, and perform unauthorized operations such as modifying system configurations or causing a denial of service. Siemens has released a new version for RUGGEDCOM CROSSBOW and recommends to update to the latest version. The following versions of Siemens RUGGEDCOM CROSSBOW are affected: RUGGEDCOM CROSSBOW vers:intdot/ CVSS Vendor Equipment v3 8.8 Siemens RUGGEDCOM CROSSBOW 4 Vulnerabilities Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'), Authorization Bypass Through User-Controlled Key, Insertion of Sensitive Information Into Sent Data, Client-Side Enforcement of Server-Side Security Background Critical Infrastructure Sectors: Critical Manufacturing, Transportation Systems, Energy, Healthcare and Public Health, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-89196 Affected devices do not properly validate or sanitize input in facility names processed during the Bulk Import/Export workflow. This could allow an authenticated attacker with specific privileges to execute arbitrary SQL commands on the underlying database. Read More 1 Affected Product RUGGEDCOM CROSSBOW Product Status: known_affected Remedia

**Extracted signals**
- CVEs: CVE-2026-89196, CVE-2026-89197, CVE-2026-89198, CVE-2026-89199, CVE-2026-89200, CVE-2026-89201, CVE-2026-89202, CVE-2026-89203, CVE-2026-89204, CVE-2026-89205, CVE-2026-89206
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: healthcare, finance, government, energy, manufacturing
- MITRE ATT&CK: T1053
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-5042a03f-1 · Initial access via CVE-2026-89196 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-89196 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-89196, CVE-2026-89197, CVE-2026-89198; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5042a03f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-89196.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5042a03f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-89196 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-89196/ | summarize count() by src_ip, dst_host`
- **[H-5042a03f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-89196 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-89196')) | summarize coverage = avg(installed) by host_role`
- **[H-5042a03f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5042a03f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5042a03f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-89196, CVE-2026-89197, CVE-2026-89198; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5042a03f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-5042a03f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5042a03f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5042a03f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5042a03f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5042a03f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-89196, CVE-2026-89197, CVE-2026-89198; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5042a03f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-5042a03f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-5042a03f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-5042a03f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 8. Kiloview E3 NDI Encoder

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-01>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 9 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this these vulnerabilities could allow an attacker to fully compromise the device. The following versions of Kiloview E3 NDI Encoder are affected: E3 Firmware CVSS Vendor Equipment v3 9.9 Kiloview E3 Firmware 6 Vulnerabilities Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'), Missing Authentication for Critical Function, Insufficient Session Expiration, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'), NULL Pointer Dereference, Use of Hard-coded Credentials Background Critical Infrastructure Sectors: Communications, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: China Vulnerabilities Expand All + CVE-2026-109122 The network management service on affected Kiloview E3 NDI encoder firmware fails to sanitize one field used when configuring static routes via the web management API. An authenticated web user with permission to configure static routes can exploit this to execute arbitrary operating system commands as root, and the malicious configuration persists across reboots. Successful exploitation could result in full device compromise, including exposure of stored credentials and cryptographic material. Read More 1 Affected Product Kiloview E3 Firmware: Product Status: known_affected Remediations Mitigation KiloView recommends users update to V1.30: https://www.kiloview.com/en/download/e3-firmware-downloadlatest-12/ Add

**Extracted signals**
- CVEs: CVE-2026-109122, CVE-2026-111100, CVE-2026-96616, CVE-2026-105265, CVE-2026-110491, CVE-2026-107861, CVE-2026-110243, CVE-2026-92450, CVE-2026-110825
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.kiloview.com

### Hypotheses (3)

#### H-c129dd82-1 · Initial access via CVE-2026-109122 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109122 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109122, CVE-2026-111100, CVE-2026-96616; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c129dd82-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109122.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c129dd82-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109122 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109122/ | summarize count() by src_ip, dst_host`
- **[H-c129dd82-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109122 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109122')) | summarize coverage = avg(installed) by host_role`
- **[H-c129dd82-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c129dd82-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c129dd82-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109122, CVE-2026-111100, CVE-2026-96616; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c129dd82-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.kiloview.com') | summarize count() by client_ip`
- **[H-c129dd82-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c129dd82-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c129dd82-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c129dd82-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c129dd82-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109122, CVE-2026-111100, CVE-2026-96616; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c129dd82-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c129dd82-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c129dd82-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c129dd82-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 9. Mitsubishi Electric GENESIS, GENESIS64, ICONICS Suite, Hyper Historian, AnalytiX, MobileHMI, IoTWorX, MC Works64, GENESIS32 and BizViz

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-02>
- **Published**: Tue, 27 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-27T15:50:42+00:00
- **Relevance score**: 69
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 2 initial-access vector(s)=+9, 8 IOC(s)=+15

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to execute arbitrary code (CVE-2023-4863), bypass authentication (CVE-2026-16436 and CVE-2026-16437), or perform arbitrary operations (CVE-2026-16438), resulting in information disclosure, tampering with, destruction, or deletion of information, and a denial-of-service (DoS) condition of the system. The following versions of Mitsubishi Electric GENESIS, GENESIS64, ICONICS Suite, Hyper Historian, AnalytiX, MobileHMI, IoTWorX, MC Works64, GENESIS32 and BizViz are affected: Mitsubishi Electric GENESIS64 >=10.97| Mitsubishi Electric ICONICS Suite >=10.97| Mitsubishi Electric GENESIS Mitsubishi Electric GENESIS64 Mitsubishi Electric ICONICS Suite Mitsubishi Electric Hyper Historian Mitsubishi Electric AnalytiX Mitsubishi Electric MobileHMI Mitsubishi Electric IoTWorX Mitsubishi Electric MC Works64 vers:all/* (CVE-2026-16436, CVE-2026-16437, CVE-2026-16438) Mitsubishi Electric GENESIS32 vers:all/* (CVE-2026-16436, CVE-2026-16437) Mitsubishi Electric BizViz vers:all/* (CVE-2026-16436, CVE-2026-16437) CVSS Vendor Equipment v3 9.1 Mitsubishi Electric Mitsubishi Electric GENESIS64 3 Vulnerabilities Out-of-bounds Write, Weak Password Recovery Mechanism for Forgotten Password, Incorrect Privilege Assignment Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2023-4863 Out

**Extracted signals**
- CVEs: CVE-2023-4863, CVE-2026-16436, CVE-2026-16437, CVE-2026-16438
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: iconicsinc.my.site.com, www.mitsubishielectric.com, iconics.com, clientchallengetable.dat, securitychallenges.dat, hub.docker.com, www.mitsubishielectric.co.jp, bcnp59991459a.pdf

### Hypotheses (3)

#### H-490e8d46-1 · Initial access via CVE-2023-4863 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2023-4863 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2023-4863, CVE-2026-16436, CVE-2026-16437; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-490e8d46-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2023-4863.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-490e8d46-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2023-4863 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2023-4863/ | summarize count() by src_ip, dst_host`
- **[H-490e8d46-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2023-4863 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2023-4863')) | summarize coverage = avg(installed) by host_role`
- **[H-490e8d46-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-490e8d46-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-490e8d46-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2023-4863, CVE-2026-16436, CVE-2026-16437; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-490e8d46-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('iconicsinc.my.site.com','www.mitsubishielectric.com','iconics.com') | summarize count() by client_ip`
- **[H-490e8d46-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-490e8d46-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-490e8d46-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-490e8d46-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-490e8d46-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2023-4863, CVE-2026-16436, CVE-2026-16437; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-490e8d46-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-490e8d46-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-490e8d46-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-490e8d46-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 10. A quiet week in infosec <.<

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/a-quiet-week-in-infosec/>
- **Published**: Thu, 29 Oct 2026 18:00:00 GMT
- **First seen**: 2026-10-29T18:21:27+00:00
- **Relevance score**: 68
- **Score rationale**: source weight (vendor)=+10, 4 MITRE technique hit(s)=+17, 2 initial-access vector(s)=+9, 3 impact action(s)=+14, 1 product mention(s)=+3, 18 IOC(s)=+15

> In this edition of the Threat Source newsletter, William explores how PHP has taken over the conversation, Node.js has joined in, but underneath it all, there are still good people doing good work.

**Extracted signals**
- Products: Microsoft Exchange
- Vectors: phishing, exploit
- Actions: ransomware, data-breach, fraud
- Sectors: finance, government, manufacturing
- MITRE ATT&CK: T1566, T1059, T1059.001, T1486
- Domain IOCs: node.js, sample.exe, w32.9f1f11a708-100.sbx.tg, cca616647db9370c88998ae25da6997f.exe, win.tool.kmsauto, net.exe, w32.58d6fec4ba-95.sbx.tg, w32.fed979f93b-95.sbx.tg
- SHA256: 73a25ff8893260418c2271b863c567e40e842adbab3c57023cb72de590ea377d, 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, 7fc50b69b56bfdfa9fc0a3e088ff13904587d6336a51e9edcc7919cba83d4e3f, 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681, fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
- MD5: 0cf0271c3564881fce95f44c649bd745, 2915b3f8b703eb744fc54c81f4a9c67f, cca616647db9370c88998ae25da6997f, f1fe671bcefd4630e5ed8b87c9283534, 207d9d891ac756b2bfad88aba5682c65

### Hypotheses (4)

#### H-5b5abb0d-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5b5abb0d-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5b5abb0d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-5b5abb0d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-5b5abb0d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5b5abb0d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5b5abb0d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5b5abb0d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('node.js','sample.exe','w32.9f1f11a708-100.sbx.tg') | summarize count() by client_ip`
- **[H-5b5abb0d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5b5abb0d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5b5abb0d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5b5abb0d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5b5abb0d-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5b5abb0d-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-5b5abb0d-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-5b5abb0d-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-5b5abb0d-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-5b5abb0d-4 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5b5abb0d-4-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-5b5abb0d-4-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-5b5abb0d-4-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-5b5abb0d-4-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 11. Siemens RUGGEDCOM CROSSBOW Station Access Controller

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-15>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 68
- **Score rationale**: source weight (advisory)=+15, 5 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 2 IOC(s)=+6

> View CSAF Summary RUGGEDCOM CROSSBOW Station Access Controller (SAC) contains multiple vulnerabilities in the integrated SQLite component that could allow an attacker to execute arbitrary code, cause a denial of service, or obtain sensitive information. Siemens has released a new version for RUGGEDCOM CROSSBOW Station Access Controller (SAC) and recommends to update to the latest version. The following versions of Siemens RUGGEDCOM CROSSBOW Station Access Controller are affected: RUGGEDCOM CROSSBOW Station Access Controller (SAC) vers:intdot/ CVSS Vendor Equipment v3 9.8 Siemens RUGGEDCOM CROSSBOW Station Access Controller (SAC) 4 Vulnerabilities Numeric Truncation Error, Improper Clearing of Heap Memory Before Release ('Heap Inspection'), Improper Handling of Unicode Encoding, Heap-based Buffer Overflow Background Critical Infrastructure Sectors: Critical Manufacturing, Transportation Systems, Energy, Healthcare and Public Health, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2025-6965 There exists a vulnerability in SQLite versions before 3.50.2 where the number of aggregate terms could exceed the number of columns available. This could lead to a memory corruption issue. We recommend upgrading to version 3.50.2 or above. Read More 1 Affected Product RUGGEDCOM CROSSBOW Station Access Controller (SAC) Product Status: known_affected Remediations Vendor fix Updat

**Extracted signals**
- CVEs: CVE-2025-6965, CVE-2025-70873, CVE-2025-71316, CVE-2026-11822, CVE-2026-11824
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: sqldiff.exe, www.siemens.com

### Hypotheses (3)

#### H-0e28f63d-1 · Initial access via CVE-2025-6965 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-6965 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-6965, CVE-2025-70873, CVE-2025-71316; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0e28f63d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2025-6965.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0e28f63d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-6965 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-6965/ | summarize count() by src_ip, dst_host`
- **[H-0e28f63d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-6965 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-6965')) | summarize coverage = avg(installed) by host_role`
- **[H-0e28f63d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0e28f63d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0e28f63d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-6965, CVE-2025-70873, CVE-2025-71316; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0e28f63d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sqldiff.exe','www.siemens.com') | summarize count() by client_ip`
- **[H-0e28f63d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0e28f63d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0e28f63d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0e28f63d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-0e28f63d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-6965, CVE-2025-70873, CVE-2025-71316; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0e28f63d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0e28f63d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0e28f63d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0e28f63d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 12. Apple Patches for October 2026, (Mon, Oct 26th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33458>
- **Published**: Mon, 26 Oct 2026 23:34:37 GMT
- **First seen**: 2026-10-27T00:11:29+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 304 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 IOC(s)=+4

> Apple today released patches for 304 vulnerabilties. This number is still in line with prior Apple updates, and comes just about a month after the last apple update.

**Extracted signals**
- CVEs: CVE-2026-86950, CVE-2026-86990, CVE-2026-28864, CVE-2022-26704, CVE-2026-112410, CVE-2026-112413, CVE-2026-112414, CVE-2026-112415, CVE-2026-112416, CVE-2026-112417, CVE-2026-112421, CVE-2026-112423, CVE-2026-112424, CVE-2026-112425, CVE-2026-112427, CVE-2026-112428, CVE-2026-112429, CVE-2026-112430, CVE-2026-112432, CVE-2026-112434, CVE-2026-112438, CVE-2026-112441, CVE-2026-112442, CVE-2026-112443, CVE-2026-112444, CVE-2026-112446, CVE-2026-112447, CVE-2026-112449, CVE-2026-112451, CVE-2026-112453, CVE-2026-112454, CVE-2026-112455, CVE-2026-112456, CVE-2026-112457, CVE-2026-112459, CVE-2026-112461, CVE-2026-112462, CVE-2026-112464, CVE-2026-112466, CVE-2026-112467, CVE-2026-112468, CVE-2026-112469, CVE-2026-112470, CVE-2026-112471, CVE-2026-112473, CVE-2026-112474, CVE-2026-112475, CVE-2026-112476, CVE-2026-112477, CVE-2026-112478, CVE-2026-112479, CVE-2026-112480, CVE-2026-112481, CVE-2026-112482, CVE-2026-112483, CVE-2026-112484, CVE-2026-112485, CVE-2026-112486, CVE-2026-112487, CVE-2026-112488, CVE-2026-112491, CVE-2026-112492, CVE-2026-112493, CVE-2026-112494, CVE-2026-112495, CVE-2026-112497, CVE-2026-112498, CVE-2026-112501, CVE-2026-112502, CVE-2026-112504, CVE-2026-112505, CVE-2026-112506, CVE-2026-112507, CVE-2026-112508, CVE-2026-112510, CVE-2026-112511, CVE-2026-112512, CVE-2026-112513, CVE-2026-112514, CVE-2026-112515, CVE-2026-112516, CVE-2026-112517, CVE-2026-112518, CVE-2026-112519, CVE-2026-112521, CVE-2026-112522, CVE-2026-112523, CVE-2026-112524, CVE-2026-112525, CVE-2026-112526, CVE-2026-112529, CVE-2026-112530, CVE-2026-112531, CVE-2026-112532, CVE-2026-112533, CVE-2026-112534, CVE-2026-112535, CVE-2026-112536, CVE-2026-112537, CVE-2026-112539, CVE-2026-112540, CVE-2026-112541, CVE-2026-112542, CVE-2026-112543, CVE-2026-112544, CVE-2026-112545, CVE-2026-112546, CVE-2026-112547, CVE-2026-112548, CVE-2026-112550, CVE-2026-112551, CVE-2026-112552, CVE-2026-112553, CVE-2026-112554, CVE-2026-112555, CVE-2026-112556, CVE-2026-112557, CVE-2026-112558, CVE-2026-112560, CVE-2026-112562, CVE-2026-112563, CVE-2026-112566, CVE-2026-112567, CVE-2026-112568, CVE-2026-112570, CVE-2026-112571, CVE-2026-112575, CVE-2026-112576, CVE-2026-112577, CVE-2026-112593, CVE-2026-112595, CVE-2026-112596, CVE-2026-112599, CVE-2026-112601, CVE-2026-112604, CVE-2026-112606, CVE-2026-112607, CVE-2026-112609, CVE-2026-112610, CVE-2026-112611, CVE-2026-112612, CVE-2026-112614, CVE-2026-112615, CVE-2026-112616, CVE-2026-112617, CVE-2026-112618, CVE-2026-112619, CVE-2026-112620, CVE-2026-112621, CVE-2026-112622, CVE-2026-112623, CVE-2026-112624, CVE-2026-112625, CVE-2026-112626, CVE-2026-112627, CVE-2026-112628, CVE-2026-112629, CVE-2026-112630, CVE-2026-112632, CVE-2026-112633, CVE-2026-112634, CVE-2026-112637, CVE-2026-112638, CVE-2026-112639, CVE-2026-112640, CVE-2026-112642, CVE-2026-112646, CVE-2026-112647, CVE-2026-112652, CVE-2026-112655, CVE-2026-112656, CVE-2026-112658, CVE-2026-112659, CVE-2026-112660, CVE-2026-112665, CVE-2026-112669, CVE-2026-112670, CVE-2026-112671, CVE-2026-112672, CVE-2026-112673, CVE-2026-112675, CVE-2026-112676, CVE-2026-112677, CVE-2026-112678, CVE-2026-112679, CVE-2026-112680, CVE-2026-112681, CVE-2026-112682, CVE-2026-112683, CVE-2026-112684, CVE-2026-112685, CVE-2026-112686, CVE-2026-112687, CVE-2026-112688, CVE-2026-112689, CVE-2026-112690, CVE-2026-112691, CVE-2026-112692, CVE-2026-112693, CVE-2026-112696, CVE-2026-112698, CVE-2026-112701, CVE-2026-112704, CVE-2026-112705, CVE-2026-112706, CVE-2026-112707, CVE-2026-112708, CVE-2026-113896, CVE-2026-113897, CVE-2026-113898, CVE-2026-113899, CVE-2026-113900, CVE-2026-113901, CVE-2026-113903, CVE-2026-113904, CVE-2026-113906, CVE-2026-113907, CVE-2026-113908, CVE-2026-113909, CVE-2026-113910, CVE-2026-113912, CVE-2026-113913, CVE-2026-113914, CVE-2026-113915, CVE-2026-113934, CVE-2026-113935, CVE-2026-113939, CVE-2026-113941, CVE-2026-113946, CVE-2026-113947, CVE-2026-113948, CVE-2026-113949, CVE-2026-113950, CVE-2026-113952, CVE-2026-20648, CVE-2026-20649, CVE-2026-28991, CVE-2026-43736, CVE-2026-64750, CVE-2026-64759, CVE-2026-64767, CVE-2026-64789, CVE-2026-65327, CVE-2026-65339, CVE-2026-65350, CVE-2026-65363, CVE-2026-65368, CVE-2026-65373, CVE-2026-65384, CVE-2026-65385, CVE-2026-65392, CVE-2026-65397, CVE-2026-84493, CVE-2026-84494, CVE-2026-84495, CVE-2026-84496, CVE-2026-84498, CVE-2026-84528, CVE-2026-84539, CVE-2026-84542, CVE-2026-84545, CVE-2026-84590, CVE-2026-84594, CVE-2026-84595, CVE-2026-84599, CVE-2026-84604, CVE-2026-84605, CVE-2026-84610, CVE-2026-84614, CVE-2026-84627, CVE-2026-86880, CVE-2026-86896, CVE-2026-86916, CVE-2026-86920, CVE-2026-86923, CVE-2026-86925, CVE-2026-86929, CVE-2026-86931, CVE-2026-86937, CVE-2026-86939, CVE-2026-86941, CVE-2026-86942, CVE-2026-86943, CVE-2026-86945, CVE-2026-86946, CVE-2026-86958, CVE-2026-86964, CVE-2026-86966, CVE-2026-86968, CVE-2026-86969, CVE-2026-86970, CVE-2026-86971, CVE-2026-86972, CVE-2026-86973, CVE-2026-86974, CVE-2026-86978, CVE-2026-86984, CVE-2026-86985, CVE-2026-86986, CVE-2026-86987, CVE-2026-86988, CVE-2026-86989, CVE-2026-86991, CVE-2026-86992
- Vectors: exploit, smb
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1021.002
- Domain IOCs: isc.sans.edu

### Hypotheses (3)

#### H-241eceff-1 · Initial access via CVE-2026-86950 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-86950 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-86950, CVE-2026-86990, CVE-2026-28864; vectors: exploit, smb.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-241eceff-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-86950.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-241eceff-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-86950 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-86950/ | summarize count() by src_ip, dst_host`
- **[H-241eceff-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-86950 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-86950')) | summarize coverage = avg(installed) by host_role`
- **[H-241eceff-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-241eceff-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-241eceff-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-86950, CVE-2026-86990, CVE-2026-28864; vectors: exploit, smb.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-241eceff-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('isc.sans.edu') | summarize count() by client_ip`
- **[H-241eceff-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-241eceff-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-241eceff-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-241eceff-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-241eceff-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-86950, CVE-2026-86990, CVE-2026-28864; vectors: exploit, smb.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-241eceff-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-241eceff-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-241eceff-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-241eceff-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 13. Siemens APOGEE, TALON and Desigo PXC/PXM Products

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-08>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 5 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 IOC(s)=+4

> View CSAF Summary The products listed below contain multiple vulnerabilities that could allow an attacker to cause a denial of service and potentially impact the availability of the affected device. Siemens has released new versions for several affected products and recommends to update to the latest versions. Siemens recommends specific mitigations for products where fixes are not or not yet available. The following versions of Siemens APOGEE, TALON and Desigo PXC/PXM Products are affected: APOGEE MBC (PPC) (BACnet) vers:all/* (CVE-2026-102073, CVE-2026-102074, CVE-2026-102075, CVE-2026-102076) APOGEE MBC (PPC) (P2 Ethernet) vers:all/* (CVE-2026-102073, CVE-2026-102074, CVE-2026-102075, CVE-2026-102076) APOGEE MEC (PPC) (BACnet) vers:all/* (CVE-2026-102073, CVE-2026-102074, CVE-2026-102075, CVE-2026-102076) APOGEE MEC (PPC) (P2 Ethernet) vers:all/* (CVE-2026-102073, CVE-2026-102074, CVE-2026-102075, CVE-2026-102076) APOGEE PXC Compact (BACnet) vers:intdot/ APOGEE PXC Compact (P2 Ethernet) vers:intdot/ APOGEE PXC Modular (BACnet) vers:intdot/ APOGEE PXC Modular (P2 Ethernet) vers:intdot/ Desigo PXC00-E.D vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC00-U vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC001-E.D vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC100-E.D vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC12-E.D vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC128-U vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC200-E.D vers:intdot/>=2.3 (CVE-2026-89208) Desigo PXC22-E.D vers:intdot/>=

**Extracted signals**
- CVEs: CVE-2026-102073, CVE-2026-102074, CVE-2026-102075, CVE-2026-102076, CVE-2026-89208
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-16e9c9c8-1 · Initial access via CVE-2026-102073 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-102073 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-102073, CVE-2026-102074, CVE-2026-102075; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-16e9c9c8-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-102073.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-16e9c9c8-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-102073 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-102073/ | summarize count() by src_ip, dst_host`
- **[H-16e9c9c8-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-102073 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-102073')) | summarize coverage = avg(installed) by host_role`
- **[H-16e9c9c8-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-16e9c9c8-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-16e9c9c8-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-102073, CVE-2026-102074, CVE-2026-102075; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-16e9c9c8-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-16e9c9c8-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-16e9c9c8-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-16e9c9c8-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-16e9c9c8-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-16e9c9c8-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-102073, CVE-2026-102074, CVE-2026-102075; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-16e9c9c8-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-16e9c9c8-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-16e9c9c8-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-16e9c9c8-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 14. Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-11>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 428 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 IOC(s)=+4

> View CSAF Summary Multiple vulnerabilities have been identified in the additional GNU/Linux subsystem of the firmware version V3.1.7 for the SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP (incl. SIPLUS variant). Siemens is preparing fixes and recommends specific mitigations for products where fixes are not or not yet available. The following versions of Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP are affected: SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0) vers:intdot/>=3.1.7 SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AC0) vers:intdot/>=3.1.7 SIMATIC S7-1500 CPU 1518F-4 PN/DP MFP (6ES7518-4FX00-1AB0) vers:intdot/>=3.1.7 SIMATIC S7-1500 CPU 1518F-4 PN/DP MFP (6ES7518-4FX00-1AC0) vers:intdot/>=3.1.7 SIPLUS S7-1500 CPU 1518-4 PN/DP MFP (6AG1518-4AX00-4AC0) vers:intdot/>=3.1.7 CVSS Vendor Equipment v3 10 Siemens SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0) 428 Vulnerabilities Access of Resource Using Incompatible Type ('Type Confusion'), Access of Uninitialized Pointer, Active Debug Code, Buffer Access with Incorrect Length Value, Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'), Buffer Underwrite ('Buffer Underflow'), Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'), Deadlock, Divide By Zero, Expired Pointer Dereference, Exposure of Sensitive Information Due to Incompatible Policies, Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution, 

**Extracted signals**
- CVEs: CVE-2021-41617, CVE-2023-28531, CVE-2023-51384, CVE-2023-52927, CVE-2023-53292, CVE-2024-26783, CVE-2024-27056, CVE-2024-28956, CVE-2024-36903, CVE-2024-36927, CVE-2024-42079, CVE-2024-46786, CVE-2024-47736, CVE-2024-47809, CVE-2024-49968, CVE-2024-49994, CVE-2024-49998, CVE-2024-50014, CVE-2024-50063, CVE-2024-50164, CVE-2024-50298, CVE-2024-53124, CVE-2024-53170, CVE-2024-54458, CVE-2024-56631, CVE-2024-56703, CVE-2024-56719, CVE-2024-57917, CVE-2024-57924, CVE-2024-57973, CVE-2024-57977, CVE-2024-57979, CVE-2024-58011, CVE-2024-58016, CVE-2024-58020, CVE-2024-58056, CVE-2024-58058, CVE-2024-58061, CVE-2024-58086, CVE-2025-21645, CVE-2025-21648, CVE-2025-21655, CVE-2025-21676, CVE-2025-21682, CVE-2025-21702, CVE-2025-21705, CVE-2025-21706, CVE-2025-21707, CVE-2025-21718, CVE-2025-21731, CVE-2025-21745, CVE-2025-21758, CVE-2025-21760, CVE-2025-21764, CVE-2025-21765, CVE-2025-21780, CVE-2025-21795, CVE-2025-21796, CVE-2025-21802, CVE-2025-21814, CVE-2025-21846, CVE-2025-21853, CVE-2025-21861, CVE-2025-21863, CVE-2025-21864, CVE-2025-21867, CVE-2025-21875, CVE-2025-21887, CVE-2025-21913, CVE-2025-21919, CVE-2025-21925, CVE-2025-21926, CVE-2025-21938, CVE-2025-21959, CVE-2025-21999, CVE-2025-22005, CVE-2025-22015, CVE-2025-22055, CVE-2025-22056, CVE-2025-22060, CVE-2025-22083, CVE-2025-22090, CVE-2025-22095, CVE-2025-22107, CVE-2025-22111, CVE-2025-22121, CVE-2025-23136, CVE-2025-23143, CVE-2025-37785, CVE-2025-37909, CVE-2025-37917, CVE-2025-37945, CVE-2025-37959, CVE-2025-37964, CVE-2025-37972, CVE-2025-37980, CVE-2025-38125, CVE-2025-38162, CVE-2025-38192, CVE-2025-38201, CVE-2025-38232, CVE-2025-38322, CVE-2025-38591, CVE-2025-38614, CVE-2025-38681, CVE-2025-38704, CVE-2025-38721, CVE-2025-38725, CVE-2025-38727, CVE-2025-38732, CVE-2025-38736, CVE-2025-39681, CVE-2025-39691, CVE-2025-39721, CVE-2025-39748, CVE-2025-39756, CVE-2025-39764, CVE-2025-39770, CVE-2025-39773, CVE-2025-39782, CVE-2025-39795, CVE-2025-39826, CVE-2025-39827, CVE-2025-39845, CVE-2025-39866, CVE-2025-39871, CVE-2025-39931, CVE-2025-39953, CVE-2025-39955, CVE-2025-39964, CVE-2025-39977, CVE-2025-39978, CVE-2025-39980, CVE-2025-40022, CVE-2025-40070, CVE-2025-40078, CVE-2025-40080, CVE-2025-40105, CVE-2025-40135, CVE-2025-40149, CVE-2025-40196, CVE-2025-40219, CVE-2025-40261, CVE-2025-40300, CVE-2025-61984, CVE-2025-61985, CVE-2025-68206, CVE-2025-68261, CVE-2025-68264, CVE-2025-68265, CVE-2025-68266, CVE-2025-68291, CVE-2025-68337, CVE-2025-68349, CVE-2025-68363, CVE-2025-68371, CVE-2025-68724, CVE-2025-68725, CVE-2025-68742, CVE-2025-68764, CVE-2025-68773, CVE-2025-68776, CVE-2025-68782, CVE-2025-68787, CVE-2025-68788, CVE-2025-68798, CVE-2025-68803, CVE-2025-68814, CVE-2025-68816, CVE-2025-68818, CVE-2025-68820, CVE-2025-71064, CVE-2025-71075, CVE-2025-71079, CVE-2025-71085, CVE-2025-71086, CVE-2025-71088, CVE-2025-71095, CVE-2025-71097, CVE-2025-71098, CVE-2025-71104, CVE-2025-71112, CVE-2025-71113, CVE-2025-71114, CVE-2025-71120, CVE-2025-71123, CVE-2025-71131, CVE-2025-71161, CVE-2025-71162, CVE-2025-71163, CVE-2025-71185, CVE-2025-71186, CVE-2025-71189, CVE-2025-71190, CVE-2025-71191, CVE-2025-71197, CVE-2025-71221, CVE-2025-71265, CVE-2025-71266, CVE-2025-71267, CVE-2026-3497, CVE-2026-22977, CVE-2026-22979, CVE-2026-22980, CVE-2026-22982, CVE-2026-22992, CVE-2026-22994, CVE-2026-23003, CVE-2026-23005, CVE-2026-23010, CVE-2026-23011, CVE-2026-23019, CVE-2026-23026, CVE-2026-23038, CVE-2026-23054, CVE-2026-23060, CVE-2026-23083, CVE-2026-23084, CVE-2026-23086, CVE-2026-23087, CVE-2026-23095, CVE-2026-23100, CVE-2026-23103, CVE-2026-23110, CVE-2026-23111, CVE-2026-23113, CVE-2026-23154, CVE-2026-23204, CVE-2026-23231, CVE-2026-23242, CVE-2026-23243, CVE-2026-23245, CVE-2026-23255, CVE-2026-23270, CVE-2026-23271, CVE-2026-23273, CVE-2026-23274, CVE-2026-23277, CVE-2026-23284, CVE-2026-23287, CVE-2026-23290, CVE-2026-23293, CVE-2026-23300, CVE-2026-23304, CVE-2026-23319, CVE-2026-23321, CVE-2026-23335, CVE-2026-23340, CVE-2026-23343, CVE-2026-23351, CVE-2026-23359, CVE-2026-23365, CVE-2026-23368, CVE-2026-23370, CVE-2026-23378, CVE-2026-23379, CVE-2026-23381, CVE-2026-23391, CVE-2026-23392, CVE-2026-23397, CVE-2026-23398, CVE-2026-23399, CVE-2026-23414, CVE-2026-23422, CVE-2026-23434, CVE-2026-23438, CVE-2026-23439, CVE-2026-23446, CVE-2026-23449, CVE-2026-23450, CVE-2026-23452, CVE-2026-23454, CVE-2026-23455, CVE-2026-23456, CVE-2026-23457, CVE-2026-23458, CVE-2026-23463, CVE-2026-23474, CVE-2026-23475, CVE-2026-27135, CVE-2026-31389, CVE-2026-31391, CVE-2026-31396, CVE-2026-31402, CVE-2026-31403, CVE-2026-31411, CVE-2026-31414, CVE-2026-31415, CVE-2026-31416, CVE-2026-31417, CVE-2026-31418, CVE-2026-31421, CVE-2026-31422, CVE-2026-31423, CVE-2026-31424, CVE-2026-31427, CVE-2026-31428, CVE-2026-31441, CVE-2026-31446, CVE-2026-31447, CVE-2026-31448, CVE-2026-31449, CVE-2026-31450, CVE-2026-31452, CVE-2026-31466, CVE-2026-31469, CVE-2026-31485, CVE-2026-31494, CVE-2026-31495, CVE-2026-31496, CVE-2026-31503, CVE-2026-31504, CVE-2026-31507, CVE-2026-31508, CVE-2026-31515, CVE-2026-31518, CVE-2026-31521, CVE-2026-31533, CVE-2026-31546, CVE-2026-31555, CVE-2026-31563, CVE-2026-31565, CVE-2026-31628, CVE-2026-31634, CVE-2026-31649, CVE-2026-31651, CVE-2026-31658, CVE-2026-31664, CVE-2026-31665, CVE-2026-31669, CVE-2026-31670, CVE-2026-31671, CVE-2026-31674, CVE-2026-31680, CVE-2026-31681, CVE-2026-31682, CVE-2026-31700, CVE-2026-31737, CVE-2026-31752, CVE-2026-31761, CVE-2026-31768, CVE-2026-40355, CVE-2026-41989, CVE-2026-43011, CVE-2026-43024, CVE-2026-43025, CVE-2026-43026, CVE-2026-43027, CVE-2026-43028, CVE-2026-43030, CVE-2026-43033, CVE-2026-43035, CVE-2026-43038, CVE-2026-43040, CVE-2026-43057, CVE-2026-43071, CVE-2026-43085, CVE-2026-43089, CVE-2026-43116, CVE-2026-43216, CVE-2026-43303, CVE-2026-43492, CVE-2026-43499, CVE-2026-43501, CVE-2026-45841, CVE-2026-46015, CVE-2026-46021, CVE-2026-46033, CVE-2026-46037, CVE-2026-46040, CVE-2026-46046, CVE-2026-46086, CVE-2026-46101, CVE-2026-46116, CVE-2026-46132, CVE-2026-46172, CVE-2026-46173, CVE-2026-46174, CVE-2026-46193, CVE-2026-46303, CVE-2026-46306, CVE-2026-46323, CVE-2026-46333, CVE-2026-52910, CVE-2026-52912, CVE-2026-52930, CVE-2026-52933, CVE-2026-52942, CVE-2026-52943, CVE-2026-52946, CVE-2026-52970, CVE-2026-52986, CVE-2026-52998, CVE-2026-52999, CVE-2026-53001, CVE-2026-53002, CVE-2026-53006, CVE-2026-53012, CVE-2026-53050, CVE-2026-53134, CVE-2026-53218, CVE-2026-53219, CVE-2026-53223, CVE-2026-53236, CVE-2026-53239, CVE-2026-53249, CVE-2026-53268, CVE-2026-53269, CVE-2026-53275, CVE-2026-53295, CVE-2026-53352, CVE-2026-53400, CVE-2026-63810, CVE-2026-64279, CVE-2026-64317, CVE-2026-64370, CVE-2026-64371, CVE-2026-64375, CVE-2026-64411, CVE-2026-64412, CVE-2026-64413, CVE-2026-64422, CVE-2026-64423, CVE-2026-64425, CVE-2026-64538, CVE-2026-64545, CVE-2026-64552, CVE-2026-64560
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-0734dad4-1 · Initial access via CVE-2021-41617 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2021-41617 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2021-41617, CVE-2023-28531, CVE-2023-51384; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0734dad4-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2021-41617.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0734dad4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2021-41617 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2021-41617/ | summarize count() by src_ip, dst_host`
- **[H-0734dad4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2021-41617 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2021-41617')) | summarize coverage = avg(installed) by host_role`
- **[H-0734dad4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0734dad4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0734dad4-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2021-41617, CVE-2023-28531, CVE-2023-51384; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0734dad4-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-0734dad4-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0734dad4-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0734dad4-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0734dad4-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-0734dad4-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2021-41617, CVE-2023-28531, CVE-2023-51384; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0734dad4-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0734dad4-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0734dad4-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0734dad4-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 15. Subnet Solutions PowerSYSTEM Center

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01>
- **Published**: Tue, 03 Nov 26 12:00:00 +0000
- **First seen**: 2026-11-03T17:24:11+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to execute unauthorized SQL commands and gain access to unauthorized resources. The following versions of Subnet Solutions PowerSYSTEM Center are affected: PowerSYSTEM Center 2020 PowerSYSTEM Center 2024 >=6.0.x| PowerSYSTEM Center 2026 >=7.0.x| CVSS Vendor Equipment v3 9 Subnet Solutions PowerSYSTEM Center 2 Vulnerabilities Incorrect Authorization, Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') Background Critical Infrastructure Sectors: Critical Manufacturing, Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Canada Vulnerabilities Expand All + CVE-2026-63017 Incorrect authorization in PowerSYSTEM Center allows a low-privileged, authenticated user to access resources normally limited to administrators. Read More 3 Affected Products Subnet Solutions PowerSYSTEM Center 2024 >=6.0.x| Product Status: known_affected Remediations Mitigation For users who are currently using PowerSYSTEM Center 2024, Subnet Solutions recommends users upgrade to PowerSYSTEM Center 2026 Update 1.1. For assistance in upgrading, users should contact the Subnet Solutions System Integration team or customer support team at (403) 270-8885 or by email at support@subnet.com. If unable to update to the latest version, Subnet Solutions recommends users monitor user activity records to ensure users are following acceptable usage policies of the application. Su

**Extracted signals**
- CVEs: CVE-2026-63017, CVE-2026-63774
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: subnet.com

### Hypotheses (3)

#### H-52dddf55-1 · Initial access via CVE-2026-63017 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-63017 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-63017, CVE-2026-63774; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-52dddf55-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-63017.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-52dddf55-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-63017 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-63017/ | summarize count() by src_ip, dst_host`
- **[H-52dddf55-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-63017 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-63017')) | summarize coverage = avg(installed) by host_role`
- **[H-52dddf55-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-52dddf55-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-52dddf55-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-63017, CVE-2026-63774; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-52dddf55-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('subnet.com') | summarize count() by client_ip`
- **[H-52dddf55-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-52dddf55-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-52dddf55-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-52dddf55-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-52dddf55-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-63017, CVE-2026-63774; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-52dddf55-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-52dddf55-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-52dddf55-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-52dddf55-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 16. I spun up a free, read-only script to check WordPress sites for signs of PHP2Shell compromise. Looking for feedback

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1xeirws/i_spun_up_a_free_readonly_script_to_check/>
- **Published**: 2026-10-24T20:19:15+00:00
- **First seen**: 2026-10-25T19:03:24+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (social)=+2, 2 CVE(s)=+25, 2 MITRE technique hit(s)=+11, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 4 IOC(s)=+10

> Patching PHP fixes PHP2Shell (CVE-2026-109618 / 109619), but it does nothing about a backdoor someone planted before the patch. Amazon's honeypots caught an exploitation attempt on Oct 17, four days before disclosure, and Amazon's advice is to investigate from at least that date. So I used Claude Code to spin up a bash script to triage WordPress sites. It checks: * PHP CLI version vs. the fixed releases * Core and plugin checksums (via WP-CLI) * PHP files in uploads * Files modified since Oct 17 (adjustable) * auto_prepend_file hooks in .user.ini / .htaccess / php.ini * mu-plugins * Common web-shell patterns in wp-content * Admin accounts and any users created in the window * Injected scripts in options and posts * WP-Cron, the site user's crontab, and SSH authorized_keys It's read-only and never modifies or deletes anything. It runs WP-CLI with --skip-plugins --skip-themes so a backdoored plugin can't execute during the check. It works on one site, every site on a server, or a list of remote servers over SSH, and it writes a Markdown report per site plus a summary. Repo (MIT): https://github.com/brentmartinmiller/php2shell-check Caveats: a clean report lowers the odds of compromise but doesn't prove a site is clean. It doesn't parse web server logs, so pull those separately before rotation eats the Oct 17+ window. A few false positives are expected, like Wordfence's prepend file, header-script plugins, and obfuscated premium plugins. The README covers how to read them. I'd a

**Extracted signals**
- CVEs: CVE-2026-109618, CVE-2026-115560
- Vectors: exploit, rdp
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1053, T1021.001
- Domain IOCs: user.ini, php.ini, l10n.php, php.net

### Hypotheses (3)

#### H-6b465130-1 · Initial access via CVE-2026-109618 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109618 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109618, CVE-2026-115560; vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6b465130-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109618.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6b465130-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109618 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109618/ | summarize count() by src_ip, dst_host`
- **[H-6b465130-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109618 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109618')) | summarize coverage = avg(installed) by host_role`
- **[H-6b465130-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6b465130-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6b465130-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109618, CVE-2026-115560; vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6b465130-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('user.ini','php.ini','l10n.php') | summarize count() by client_ip`
- **[H-6b465130-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6b465130-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6b465130-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6b465130-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6b465130-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109618, CVE-2026-115560; vectors: exploit, rdp; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6b465130-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6b465130-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6b465130-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6b465130-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 17. InterSystems Corporation InterSystems IRIS for Health

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-295-01>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 3 IOC(s)=+8

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to view transmitted data and use that data to log into the device. The following versions of InterSystems Corporation InterSystems IRIS for Health are affected: InterSystems IRIS for Health 2026.2.0.221, 2026.1.0.235, 2025.3.0.226 (CVE-2026-111594, CVE-2026-111594, CVE-2026-111594) CVSS Vendor Equipment v3 8.1 InterSystems Corporation InterSystems IRIS for Health 1 Vulnerability Cleartext Transmission of Sensitive Information Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities CVE-2026-111594 InterSystems IRIS for Health has TLS/SSL encryption turned off by default, which may enable an attacker to view transmitted data and use that data to log into the device. Read More 3 Affected Products InterSystems Corporation InterSystems IRIS for Health: 2026.2.0.221 Product Status: known_affected Remediations Mitigation InterSystems recommends users configure IRIS superserver to require SSL/TLS: https://docs.intersystems.com/irislatest/csp/docbook/DocBook.UI.Page.cls?KEY=ROARS_gsecuring_checklist Note that there are three settings: "Disabled", which means that client communications do not use TLS. "Enabled", which means that client communications may use TLS (but they also may not) and "Required", which forces all client communications to use TLS. Mitigation InterSystems documentatio

**Extracted signals**
- CVEs: CVE-2026-111594
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: docs.intersystems.com, docbook.ui.page.cls, wrc.intersystems.com

### Hypotheses (3)

#### H-b519b100-1 · Initial access via CVE-2026-111594 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-111594 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-111594; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b519b100-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-111594.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-b519b100-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-111594 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-111594/ | summarize count() by src_ip, dst_host`
- **[H-b519b100-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-111594 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-111594')) | summarize coverage = avg(installed) by host_role`
- **[H-b519b100-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-b519b100-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-b519b100-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-111594; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b519b100-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('docs.intersystems.com','docbook.ui.page.cls','wrc.intersystems.com') | summarize count() by client_ip`
- **[H-b519b100-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-b519b100-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-b519b100-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-b519b100-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-b519b100-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-111594; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b519b100-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-b519b100-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-b519b100-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-b519b100-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 18. Siemens Industrial Edge App Publisher

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-02>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 63
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 2 IOC(s)=+6

> View CSAF Summary The Industrial Edge App Publisher contains a vulnerability chain involving improper certificate validation and the rendering of unescaped data from backend responses. These issues can be combined to allow an attacker on the network to impersonate the management server and execute arbitrary code (RCE) on the local machine through Node.js integration. Siemens has released an update for the Industrial Edge App Publisher and recommends to update to the latest version. The following versions of Siemens Industrial Edge App Publisher are affected: Industrial Edge App Publisher vers:intdot/ CVSS Vendor Equipment v3 8.3 Siemens Industrial Edge App Publisher 2 Vulnerabilities Improper Certificate Validation, Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Background Critical Infrastructure Sectors: Critical Manufacturing, Transportation Systems, Energy, Healthcare and Public Health, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-78556 The affected software does not properly validate the server certificate when initiating a TLS connection. This allows an attacker to intercept and relay communication (Man-in-the-Middle attack) and to spoof a trusted entity by interfering in the communication path between the client and the intended server. Read More 1 Affected Product Industrial Edge App Publisher Product Status: k

**Extracted signals**
- CVEs: CVE-2026-78556, CVE-2026-78557
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: node.js, www.siemens.com

### Hypotheses (3)

#### H-7cbe0b42-1 · Initial access via CVE-2026-78556 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-78556 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-78556, CVE-2026-78557; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7cbe0b42-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-78556.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7cbe0b42-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-78556 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-78556/ | summarize count() by src_ip, dst_host`
- **[H-7cbe0b42-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-78556 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-78556')) | summarize coverage = avg(installed) by host_role`
- **[H-7cbe0b42-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7cbe0b42-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7cbe0b42-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-78556, CVE-2026-78557; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7cbe0b42-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('node.js','www.siemens.com') | summarize count() by client_ip`
- **[H-7cbe0b42-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7cbe0b42-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7cbe0b42-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7cbe0b42-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7cbe0b42-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-78556, CVE-2026-78557; vectors: exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7cbe0b42-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7cbe0b42-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7cbe0b42-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7cbe0b42-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 19. I had plans for that second

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/i-had-plans-for-that-second/>
- **Published**: Thu, 22 Oct 2026 18:04:32 GMT
- **First seen**: 2026-10-22T18:23:03+00:00
- **Relevance score**: 63
- **Score rationale**: source weight (vendor)=+10, 3 MITRE technique hit(s)=+14, 4 initial-access vector(s)=+13, 2 impact action(s)=+11, 15 IOC(s)=+15

> The Earth is speeding up, the leap second is being abolished, oh, and there's critical vulnerabilities in PHP.

**Extracted signals**
- Vectors: phishing, exploit, rdp, credential-theft
- Actions: ransomware, fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1078, T1021.001, T1486
- Domain IOCs: sample.exe, w32.9f1f11a708-100.sbx.tg, cca616647db9370c88998ae25da6997f.exe, win.tool.kmsauto, 485055033bcddfde56325c0d2feea4f2.exe, win.worm.zard, 95.sbx.tg
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, 7fc50b69b56bfdfa9fc0a3e088ff13904587d6336a51e9edcc7919cba83d4e3f, 985c3972712218c62d2418b41056dba5fe883ca5104d8ec12041f8611db344f9, d921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, cca616647db9370c88998ae25da6997f, 485055033bcddfde56325c0d2feea4f2, 0c883b1d66afce606d9830f48d69d74b

### Hypotheses (3)

#### H-2a076e19-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a076e19-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2a076e19-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-2a076e19-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-2a076e19-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2a076e19-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2a076e19-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a076e19-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sample.exe','w32.9f1f11a708-100.sbx.tg','cca616647db9370c88998ae25da6997f.exe') | summarize count() by client_ip`
- **[H-2a076e19-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2a076e19-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2a076e19-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2a076e19-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2a076e19-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2a076e19-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-2a076e19-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-2a076e19-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-2a076e19-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 20. Hitachi Energy TRO600 series products

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-02>
- **Published**: Thu, 29 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-29T15:00:21+00:00
- **Relevance score**: 61
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 5 IOC(s)=+12

> View CSAF Summary Hitachi Energy is aware of multiple vulnerabilities that affect the TRO600 series product versions listed in this document. These vulnerabilities can be exploited for remote code execution (RCE) to carry out further attacks and disclosure of sensitive information. Please refer to the Recommended Immediate Actions section for information about the mitigation/remediation. The following versions of Hitachi Energy TRO600 series products are affected: TRO600 vers:TRO600/ CVSS Vendor Equipment v3 7.5 Hitachi Energy TRO600 2 Vulnerabilities Improper Restriction of Communication Channel to Intended Endpoints, Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-10756 TRO600 contains a vulnerability that allows an authenticated attacker to bypass network access restrictions and access services intended to be reachable only from localhost. By leveraging port forwarding, an attacker can interact with locally bound ports and services, resulting in unauthorized access to sensitive functionality and confidential information, and causing availability impact. Read More 1 Affected Product TRO600 version 9.2.1.6 and prior Product Status: fixed, known_affected, recommended Remediations Vendor fix Update to version 9.2.2.1 Additional Metrics Relevant CWE: CWE-923 Improper Restriction of Communication Channel to Intended 

**Extracted signals**
- CVEs: CVE-2026-10756, CVE-2026-106087
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- IP IOCs: 9.2.1.6, 9.2.2.1, 9.1.1.0, 9.1.2.0
- Domain IOCs: www.hitachienergy.com

### Hypotheses (3)

#### H-67769fd6-1 · Initial access via CVE-2026-10756 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-10756 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-10756, CVE-2026-106087; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-67769fd6-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-10756.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-67769fd6-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-10756 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-10756/ | summarize count() by src_ip, dst_host`
- **[H-67769fd6-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-10756 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-10756')) | summarize coverage = avg(installed) by host_role`
- **[H-67769fd6-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-67769fd6-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-67769fd6-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-10756, CVE-2026-106087; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-67769fd6-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com') | summarize count() by client_ip`
- **[H-67769fd6-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('9.2.1.6','9.2.2.1','9.1.1.0') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-67769fd6-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-67769fd6-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-67769fd6-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-67769fd6-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-10756, CVE-2026-106087; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-67769fd6-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-67769fd6-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-67769fd6-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-67769fd6-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 21. Siemens SIMATIC S7-1500 TM MFP

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-16>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 61
- **Score rationale**: source weight (advisory)=+15, 377 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 1 IOC(s)=+4

> View CSAF Summary Multiple vulnerabilities have been identified in the additional GNU/Linux subsystem of the SIMATIC S7-1500 TM MFP V1.1.1. Siemens is preparing fixes and recommends specific mitigations for products where fixes are not or not yet available. The following versions of Siemens SIMATIC S7-1500 TM MFP are affected: SIMATIC S7-1500 TM MFP - GNU/Linux subsystem vers:all/* CVSS Vendor Equipment v3 10 Siemens SIMATIC S7-1500 TM MFP - GNU/Linux subsystem 377 Vulnerabilities Access of Uninitialized Pointer, Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'), Deadlock, Detection of Error Condition Without Action, Double Free, Expired Pointer Dereference, Heap-based Buffer Overflow, Improper Control of Resource Identifiers ('Resource Injection'), Improper Control of a Resource Through its Lifetime, Improper Handling of Length Parameter Inconsistency, Improper Handling of Missing Special Element, Improper Handling of Structural Elements, Improper Input Validation, Improper Locking, Improper Resource Locking, Improper Restriction of Operations within the Bounds of a Memory Buffer, Improper Update of Reference Count, Improper Validation of Array Index, Improper Validation of Consistency within Input, Improper Validation of Specified Index, Position, or Offset in Input, Improper Validation of Specified Quantity in Input, Improper Validation of Specified Type of Input, Incorrect Synchronization, Integer Overflow or Wraparound, Integer Underflow (Wrap or Wra

**Extracted signals**
- CVEs: CVE-2023-52927, CVE-2023-53292, CVE-2023-54271, CVE-2024-26982, CVE-2024-36922, CVE-2024-40945, CVE-2024-47809, CVE-2024-49998, CVE-2024-53166, CVE-2024-56647, CVE-2024-56657, CVE-2024-56719, CVE-2024-57977, CVE-2024-57979, CVE-2024-57980, CVE-2024-57981, CVE-2024-57986, CVE-2024-57993, CVE-2024-57996, CVE-2024-58002, CVE-2024-58005, CVE-2024-58009, CVE-2024-58013, CVE-2024-58014, CVE-2024-58017, CVE-2024-58020, CVE-2024-58058, CVE-2024-58061, CVE-2024-58063, CVE-2024-58068, CVE-2024-58071, CVE-2024-58072, CVE-2024-58077, CVE-2024-58079, CVE-2024-58083, CVE-2025-21682, CVE-2025-21700, CVE-2025-21702, CVE-2025-21703, CVE-2025-21704, CVE-2025-21705, CVE-2025-21706, CVE-2025-21707, CVE-2025-21708, CVE-2025-21716, CVE-2025-21719, CVE-2025-21724, CVE-2025-21725, CVE-2025-21726, CVE-2025-21727, CVE-2025-21728, CVE-2025-21731, CVE-2025-21735, CVE-2025-21738, CVE-2025-21744, CVE-2025-21745, CVE-2025-21753, CVE-2025-21756, CVE-2025-21758, CVE-2025-21760, CVE-2025-21761, CVE-2025-21762, CVE-2025-21763, CVE-2025-21764, CVE-2025-21765, CVE-2025-21766, CVE-2025-21767, CVE-2025-21776, CVE-2025-21779, CVE-2025-21787, CVE-2025-21790, CVE-2025-21791, CVE-2025-21795, CVE-2025-21796, CVE-2025-21806, CVE-2025-21814, CVE-2025-21830, CVE-2025-21832, CVE-2025-21835, CVE-2025-21838, CVE-2025-21844, CVE-2025-21846, CVE-2025-21858, CVE-2025-21859, CVE-2025-21862, CVE-2025-21863, CVE-2025-21864, CVE-2025-21865, CVE-2025-22105, CVE-2025-23131, CVE-2025-38105, CVE-2025-38162, CVE-2025-38192, CVE-2025-38250, CVE-2025-38584, CVE-2025-38704, CVE-2025-39748, CVE-2025-39863, CVE-2025-39997, CVE-2025-40135, CVE-2025-68206, CVE-2025-68239, CVE-2025-68265, CVE-2026-23066, CVE-2026-23100, CVE-2026-23113, CVE-2026-23141, CVE-2026-23154, CVE-2026-23157, CVE-2026-23204, CVE-2026-23231, CVE-2026-23245, CVE-2026-23253, CVE-2026-23255, CVE-2026-23270, CVE-2026-23271, CVE-2026-23272, CVE-2026-23273, CVE-2026-23274, CVE-2026-23277, CVE-2026-23278, CVE-2026-23279, CVE-2026-23281, CVE-2026-23290, CVE-2026-23291, CVE-2026-23292, CVE-2026-23296, CVE-2026-23300, CVE-2026-23302, CVE-2026-23303, CVE-2026-23304, CVE-2026-23310, CVE-2026-23312, CVE-2026-23315, CVE-2026-23317, CVE-2026-23318, CVE-2026-23319, CVE-2026-23321, CVE-2026-23336, CVE-2026-23339, CVE-2026-23340, CVE-2026-23343, CVE-2026-23351, CVE-2026-23352, CVE-2026-23356, CVE-2026-23357, CVE-2026-23359, CVE-2026-23364, CVE-2026-23365, CVE-2026-23367, CVE-2026-23368, CVE-2026-23370, CVE-2026-23372, CVE-2026-23378, CVE-2026-23379, CVE-2026-23381, CVE-2026-23382, CVE-2026-23388, CVE-2026-23389, CVE-2026-23391, CVE-2026-23392, CVE-2026-23395, CVE-2026-23396, CVE-2026-23397, CVE-2026-23398, CVE-2026-23399, CVE-2026-23442, CVE-2026-23444, CVE-2026-31407, CVE-2026-31449, CVE-2026-31451, CVE-2026-31488, CVE-2026-31500, CVE-2026-31532, CVE-2026-31580, CVE-2026-31583, CVE-2026-31586, CVE-2026-31611, CVE-2026-31612, CVE-2026-31613, CVE-2026-31617, CVE-2026-31622, CVE-2026-31624, CVE-2026-31625, CVE-2026-31629, CVE-2026-31630, CVE-2026-31637, CVE-2026-31642, CVE-2026-31673, CVE-2026-31676, CVE-2026-31681, CVE-2026-31685, CVE-2026-31694, CVE-2026-31696, CVE-2026-31697, CVE-2026-31698, CVE-2026-31699, CVE-2026-31700, CVE-2026-31704, CVE-2026-31705, CVE-2026-31708, CVE-2026-31709, CVE-2026-31711, CVE-2026-31712, CVE-2026-43052, CVE-2026-43071, CVE-2026-43074, CVE-2026-43080, CVE-2026-43085, CVE-2026-43089, CVE-2026-43093, CVE-2026-43094, CVE-2026-43099, CVE-2026-43110, CVE-2026-43111, CVE-2026-43112, CVE-2026-43114, CVE-2026-43116, CVE-2026-43117, CVE-2026-43303, CVE-2026-43350, CVE-2026-43421, CVE-2026-43492, CVE-2026-43493, CVE-2026-43496, CVE-2026-43499, CVE-2026-43502, CVE-2026-43503, CVE-2026-45834, CVE-2026-45835, CVE-2026-45836, CVE-2026-45838, CVE-2026-45839, CVE-2026-45840, CVE-2026-45841, CVE-2026-45842, CVE-2026-45843, CVE-2026-45844, CVE-2026-45850, CVE-2026-45991, CVE-2026-45997, CVE-2026-46003, CVE-2026-46015, CVE-2026-46018, CVE-2026-46021, CVE-2026-46022, CVE-2026-46023, CVE-2026-46026, CVE-2026-46033, CVE-2026-46037, CVE-2026-46038, CVE-2026-46040, CVE-2026-46044, CVE-2026-46046, CVE-2026-46047, CVE-2026-46050, CVE-2026-46051, CVE-2026-46056, CVE-2026-46064, CVE-2026-46065, CVE-2026-46069, CVE-2026-46070, CVE-2026-46083, CVE-2026-46086, CVE-2026-46088, CVE-2026-46092, CVE-2026-46099, CVE-2026-46101, CVE-2026-46102, CVE-2026-46107, CVE-2026-46110, CVE-2026-46113, CVE-2026-46116, CVE-2026-46120, CVE-2026-46122, CVE-2026-46124, CVE-2026-46125, CVE-2026-46128, CVE-2026-46136, CVE-2026-46137, CVE-2026-46146, CVE-2026-46149, CVE-2026-46150, CVE-2026-46151, CVE-2026-46159, CVE-2026-46161, CVE-2026-46163, CVE-2026-46165, CVE-2026-46167, CVE-2026-46168, CVE-2026-46172, CVE-2026-46173, CVE-2026-46177, CVE-2026-46180, CVE-2026-46185, CVE-2026-46187, CVE-2026-46190, CVE-2026-46191, CVE-2026-46193, CVE-2026-46195, CVE-2026-46196, CVE-2026-46209, CVE-2026-46214, CVE-2026-46227, CVE-2026-46234, CVE-2026-46243, CVE-2026-46275, CVE-2026-46294, CVE-2026-46303, CVE-2026-46304, CVE-2026-46306, CVE-2026-46307, CVE-2026-46320, CVE-2026-46321, CVE-2026-46322, CVE-2026-46323, CVE-2026-46331, CVE-2026-52909, CVE-2026-52910, CVE-2026-52917, CVE-2026-52918, CVE-2026-52923, CVE-2026-52928, CVE-2026-52929, CVE-2026-52930, CVE-2026-52942, CVE-2026-52943, CVE-2026-52946, CVE-2026-52947, CVE-2026-52948, CVE-2026-53080, CVE-2026-53131, CVE-2026-53146, CVE-2026-53147, CVE-2026-53148, CVE-2026-53149, CVE-2026-53150, CVE-2026-53167, CVE-2026-53168, CVE-2026-53177, CVE-2026-53181, CVE-2026-53183, CVE-2026-53184, CVE-2026-53192, CVE-2026-53198, CVE-2026-53208, CVE-2026-53212, CVE-2026-53218, CVE-2026-53219, CVE-2026-53221, CVE-2026-53225, CVE-2026-53227, CVE-2026-53228, CVE-2026-53236, CVE-2026-53239, CVE-2026-53242, CVE-2026-53245, CVE-2026-53249, CVE-2026-53253, CVE-2026-53254, CVE-2026-53255, CVE-2026-53256, CVE-2026-53263, CVE-2026-53264, CVE-2026-53265, CVE-2026-53268, CVE-2026-53269, CVE-2026-53275, CVE-2026-53325, CVE-2026-53337, CVE-2026-53349, CVE-2026-53350, CVE-2026-53352, CVE-2026-53356, CVE-2026-53358, CVE-2026-53362, CVE-2026-64560
- Products: Linux kernel
- Vectors: exploit, vpn-edge
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-35d42093-1 · Initial access via CVE-2023-52927 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2023-52927 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2023-52927, CVE-2023-53292, CVE-2023-54271; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-35d42093-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2023-52927.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-35d42093-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2023-52927 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2023-52927/ | summarize count() by src_ip, dst_host`
- **[H-35d42093-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2023-52927 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2023-52927')) | summarize coverage = avg(installed) by host_role`
- **[H-35d42093-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-35d42093-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-35d42093-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2023-52927, CVE-2023-53292, CVE-2023-54271; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-35d42093-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-35d42093-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-35d42093-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-35d42093-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-35d42093-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-35d42093-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2023-52927, CVE-2023-53292, CVE-2023-54271; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-35d42093-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-35d42093-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-35d42093-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-35d42093-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 22. Fake-download campaign uses trojanized installers to deliver monetization payloads

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/>
- **Published**: Tue, 03 Nov 2026 17:32:47 +0000
- **First seen**: 2026-11-03T19:28:37+00:00
- **Relevance score**: 59
- **Score rationale**: source weight (vendor)=+10, 3 MITRE technique hit(s)=+14, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 46 IOC(s)=+15

> Microsoft Threat Intelligence tracks a fake-download campaign that uses trojanized Inno installers to deliver multiple monetization offers and provides detection and investigation guidance across the complete installer session. The post Fake-download campaign uses trojanized installers to deliver monetization payloads appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053
- Domain IOCs: client.exe, client.tmp, eld0.exe, eld1.exe, eld3.exe, eld4.exe, eld5.exe, sdk-agent.exe, sdk-agent.updater.exe, boinc.exe, charityengine.exe, ce11.exe, virtualbox-7.2.8-r173730.msi, johan.msi, advancedwindowsmanager.exe, updater.exe, schtasks.exe, svchost.exe, 7.2.8.exe, boinctray.exe, boinc.scr, boincscr.exe, offerloader.da, offerloader.db, orbittrack.cfd, prairielink.cfd, willowbox.xyz, stonestation.cfd, foldlodge.xyz, friendsanchor.xyz, fallport.cfd, wishcourt.cfd, cratebase.cfd, belieftrack.cfd, beliefdesk.xyz, companyharbor.xyz, signalpane.cfd, inkact.xyz, wishgrove.cfd
- SHA256: 006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c, 21306fc5716f95e252388f920314b42f1c8bcc7df67cb4d39da30217b96f4044, 72750d32b440e9f2b6d05ff3d218a561a75d3d75fb976b461fa59897674a7f70, ab2c2dd37fdcfe1e7620a57f98c80bd063258bea145adc0cc6a0f8b1e24c6a8f, 452a210bba4c8d08f7cb7733a816d7220a7fa570a469aea0a997cfc8b594b6a0, 523fb81fae0c7beba7b5171243cc0dee7a4d04ae0483be9172eef2394a5a2152, 55cd3d36fdcc58016a64398357b2c9724a060da9f0d09266e537a61ec9552e4f

### Hypotheses (3)

#### H-ee54f94a-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ee54f94a-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ee54f94a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-ee54f94a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-ee54f94a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ee54f94a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ee54f94a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ee54f94a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('client.exe','client.tmp','eld0.exe') | summarize count() by client_ip`
- **[H-ee54f94a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ee54f94a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ee54f94a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ee54f94a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ee54f94a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ee54f94a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ee54f94a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ee54f94a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ee54f94a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 23. Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/>
- **Published**: Fri, 23 Oct 2026 18:12:19 +0000
- **First seen**: 2026-10-23T21:12:23+00:00
- **Relevance score**: 59
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 5 initial-access vector(s)=+15, 1 impact action(s)=+8, 1 product mention(s)=+3, 27 IOC(s)=+15

> Microsoft Threat Intelligence analyzes the LiteLLM 1.107.0 compromise, including Python startup hooks, credential theft, remote code loading, detections, and mitigations. The post Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, supply-chain, cloud-misconfig, credential-theft
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1059
- Domain IOCs: cook.pth, cook.py, sitecustomize.py, litellm-1.107.0.data, data.bin, key.bin, hdr.json, www.litellm.dev, domain.txt, stealer.sa, www.litellm.dev.example, litellm.dev, openssl.exe, raw.githubusercontent.com
- SHA256: 9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25, 03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea, 34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa, b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465, 7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb, 84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d, 7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d, 0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a, 668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6, 462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7, c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054, 1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00, 12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484

### Hypotheses (3)

#### H-d4c495fc-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d4c495fc-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d4c495fc-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-d4c495fc-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-d4c495fc-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d4c495fc-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d4c495fc-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d4c495fc-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('cook.pth','cook.py','sitecustomize.py') | summarize count() by client_ip`
- **[H-d4c495fc-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d4c495fc-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d4c495fc-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d4c495fc-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d4c495fc-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d4c495fc-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d4c495fc-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d4c495fc-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d4c495fc-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 24. Siemens RUGGEDCOM APE1808 Devices

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-18>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 58
- **Score rationale**: source weight (advisory)=+15, 5 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 IOC(s)=+4

> View CSAF Summary Nozomi Networks has published information on vulnerabilities in Nozomi Guardian/CMC. This advisory lists the related Siemens Industrial products affected by these vulnerabilities. Siemens recommends to contact customer support to receive patch and update information. The following versions of Siemens RUGGEDCOM APE1808 Devices are affected: RUGGEDCOM APE1808 vers:all/* (CVE-2026-33387, CVE-2026-33388, CVE-2026-33389, CVE-2026-33391, CVE-2026-33920) CVSS Vendor Equipment v3 7.5 Siemens RUGGEDCOM APE1808 4 Vulnerabilities Improper Neutralization of Special Elements Used in a Template Engine, Incorrect Authorization, Lack of Administrator Control over Security, Cross-Site Request Forgery (CSRF) Background Critical Infrastructure Sectors: Critical Manufacturing, Transportation Systems, Energy, Healthcare and Public Health, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-33387 A template injection vulnerability was discovered in the Dashboards functionality due to improper validation of an input parameter. An authenticated user with the required privileges can define a dashboard containing a malicious payload, or a victim can be socially engineered into importing a malicious dashboard. When the victim views or imports the dashboard, the payload executes in their browser context, allowing the attacker to modify application data or disrupt applicat

**Extracted signals**
- CVEs: CVE-2026-33387, CVE-2026-33388, CVE-2026-33389, CVE-2026-33391, CVE-2026-33920
- Vectors: exploit, vpn-edge
- Sectors: healthcare, finance, government, energy, manufacturing
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-df2495c9-1 · Initial access via CVE-2026-33387 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-33387 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-33387, CVE-2026-33388, CVE-2026-33389; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-df2495c9-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-33387.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-df2495c9-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-33387 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-33387/ | summarize count() by src_ip, dst_host`
- **[H-df2495c9-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-33387 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-33387')) | summarize coverage = avg(installed) by host_role`
- **[H-df2495c9-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-df2495c9-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-df2495c9-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-33387, CVE-2026-33388, CVE-2026-33389; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-df2495c9-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-df2495c9-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-df2495c9-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-df2495c9-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-df2495c9-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-df2495c9-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-33387, CVE-2026-33388, CVE-2026-33389; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-df2495c9-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-df2495c9-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-df2495c9-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-df2495c9-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 25. Siemens SIMATIC S7 PLCs Web Server

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-14>
- **Published**: Thu, 22 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-22T19:03:32+00:00
- **Relevance score**: 58
- **Score rationale**: source weight (advisory)=+15, 8 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 IOC(s)=+4

> View CSAF Summary SIMATIC S7-1500 devices contain multiple vulnerabilities in the web server that could allow an attacker to execute malicious code in an authorized user’s browser session and perform PLC operations within the scope of that user’s authorization. Siemens is preparing fixes and recommends specific mitigations for products where fixes are not or not yet available. The following versions of Siemens SIMATIC S7 PLCs Web Server are affected: SIMATIC Drive Controller CPU 1504D TF (6ES7615-4DF10-0AB0) vers:all/* (CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357) SIMATIC Drive Controller CPU 1507D TF (6ES7615-7DF10-0AB0) vers:all/* (CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357) SIMATIC ET 200SP CPU 1510SP F-1 PN (6ES7510-1SJ01-0AB0) vers:all/* (CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357) SIMATIC ET 200SP CPU 1510SP F-1 PN (6ES7510-1SK03-0AB0) vers:all/* (CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357) SIMATIC ET 200SP CPU 1510SP-1 PN (6ES7510-1DJ01-0AB0) vers:all/* (CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357) SIMATIC ET 200SP CPU 1510SP-1 PN (6ES7510-1DK03-0AB0) vers:al

**Extracted signals**
- CVEs: CVE-2026-63350, CVE-2026-63351, CVE-2026-63352, CVE-2026-63353, CVE-2026-63354, CVE-2026-63355, CVE-2026-63356, CVE-2026-63357
- Vectors: exploit, vpn-edge
- Sectors: healthcare, finance, government, energy, manufacturing, telecom
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-1280d5f2-1 · Initial access via CVE-2026-63350 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-63350 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-63350, CVE-2026-63351, CVE-2026-63352; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1280d5f2-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-63350.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-1280d5f2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-63350 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-63350/ | summarize count() by src_ip, dst_host`
- **[H-1280d5f2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-63350 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-63350')) | summarize coverage = avg(installed) by host_role`
- **[H-1280d5f2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-1280d5f2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-1280d5f2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-63350, CVE-2026-63351, CVE-2026-63352; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1280d5f2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-1280d5f2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-1280d5f2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-1280d5f2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-1280d5f2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-1280d5f2-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-63350, CVE-2026-63351, CVE-2026-63352; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1280d5f2-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-1280d5f2-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-1280d5f2-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-1280d5f2-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 26. Tracking AI adoption in North Korean threat actor tradecraft

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/29/tracking-ai-adoption-in-north-korean-threat-actor-tradecraft/>
- **Published**: Thu, 29 Oct 2026 16:00:00 +0000
- **First seen**: 2026-10-29T16:59:56+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (vendor)=+10, 4 MITRE technique hit(s)=+17, 6 initial-access vector(s)=+15, 2 impact action(s)=+11, 1 product mention(s)=+3

> As Microsoft Threat Intelligence continues to track how threat actors operationalize AI to increase the speed and efficiency of attacks, we’ve identified North Korean threat actors expanding their use of AI with varying levels of adoption. This blog breaks down how North Korean threat actors are utilizing AI across their operations, reflecting a broader trend of threat actors incorporating AI into their attack chains. The post Tracking AI adoption in North Korean threat actor tradecraft appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, supply-chain, vpn-edge, cloud-misconfig, social-engineering
- Actions: ransomware, fraud
- Sectors: finance, government, energy, manufacturing, education, telecom
- MITRE ATT&CK: T1566, T1059, T1059.001, T1486

### Hypotheses (3)

#### H-03cfadf3-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, supply-chain; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-03cfadf3-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-03cfadf3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-03cfadf3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-03cfadf3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-03cfadf3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-03cfadf3-2 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit, supply-chain; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-03cfadf3-2-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-03cfadf3-2-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-03cfadf3-2-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-03cfadf3-2-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-03cfadf3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, supply-chain; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-03cfadf3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-03cfadf3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-03cfadf3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-03cfadf3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 27. Hitachi Energy CoreTec Product

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-03>
- **Published**: Thu, 29 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-29T15:00:21+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 1 IOC(s)=+4

> View CSAF Summary Hitachi Energy is aware of OS command injection and Dirty Frag vulnerabilities that affect CoreTec product versions listed in this document. Successful exploitation of these vulnerabilities could result in impact on confidentiality, integrity and availability of the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy CoreTec Product are affected: CoreTec5 vers:CoreTec5/ CoreTec4 vers:CoreTec4/ CVSS Vendor Equipment v3 8.8 Hitachi Energy CoreTec5 2 Vulnerabilities Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'), Write-what-where Condition Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-13162 An OS command vulnerability exists in CoreTec product that allows authenticated users with certain roles to execute arbitrary system commands with full control over the device. The vulnerability exists in the configuration daemon's time synchronization handler, which is responsible for setting the system timezone. When processing timezone configuration updates, the daemon constructs a shell command by concatenating user-supplied input without any sanitization or validation. Read More 2 Affected Products CoreTec5 versions 3.4.0 and prior Product Status: fixed, known_affected, recommended Remediations Vendor fix Updat

**Extracted signals**
- CVEs: CVE-2026-13162, CVE-2026-43284
- Products: Linux kernel
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.hitachienergy.com

### Hypotheses (3)

#### H-63705a45-1 · Initial access via CVE-2026-13162 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-13162 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-13162, CVE-2026-43284; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-63705a45-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2026-13162.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-63705a45-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-13162 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-13162/ | summarize count() by src_ip, dst_host`
- **[H-63705a45-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-13162 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-13162')) | summarize coverage = avg(installed) by host_role`
- **[H-63705a45-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-63705a45-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-63705a45-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-13162, CVE-2026-43284; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-63705a45-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com') | summarize count() by client_ip`
- **[H-63705a45-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-63705a45-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-63705a45-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-63705a45-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-63705a45-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-13162, CVE-2026-43284; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-63705a45-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-63705a45-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-63705a45-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-63705a45-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 28. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Thu, 29 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-29T21:05:04+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 2 product mention(s)=+6

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-111357 Ivanti Connect Secure Missing Authentication for Critical Function Vulnerability CVE-2026-97229 GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Awa

**Extracted signals**
- CVEs: CVE-2026-111357, CVE-2026-97229
- Products: Ivanti Connect Secure, GitLab
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-2e658dfc-1 · Initial access via CVE-2026-111357 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-111357 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-111357, CVE-2026-97229; vectors: exploit, vpn-edge; products: Ivanti Connect Secure, GitLab.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2e658dfc-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-111357.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2e658dfc-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-111357 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-111357/ | summarize count() by src_ip, dst_host`
- **[H-2e658dfc-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-111357 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-111357')) | summarize coverage = avg(installed) by host_role`
- **[H-2e658dfc-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2e658dfc-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2e658dfc-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-111357, CVE-2026-97229; vectors: exploit, vpn-edge; products: Ivanti Connect Secure, GitLab.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2e658dfc-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-2e658dfc-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2e658dfc-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2e658dfc-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2e658dfc-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2e658dfc-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-111357, CVE-2026-97229; vectors: exploit, vpn-edge; products: Ivanti Connect Secure, GitLab.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2e658dfc-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2e658dfc-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2e658dfc-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2e658dfc-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 29. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/11/03/cisa-adds-one-known-exploited-vulnerability-catalog>
- **Published**: Tue, 03 Nov 26 12:00:00 +0000
- **First seen**: 2026-11-03T22:15:03+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-119977 WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it for potential addition through C

**Extracted signals**
- CVEs: CVE-2026-119977
- Vectors: exploit, rdp
- Sectors: government, manufacturing
- MITRE ATT&CK: T1021.001

### Hypotheses (3)

#### H-51649279-1 · Initial access via CVE-2026-119977 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-119977 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-51649279-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-119977.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-51649279-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-119977 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-119977/ | summarize count() by src_ip, dst_host`
- **[H-51649279-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-119977 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-119977')) | summarize coverage = avg(installed) by host_role`
- **[H-51649279-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-51649279-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-51649279-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-51649279-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-51649279-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-51649279-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-51649279-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-51649279-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-51649279-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-51649279-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-51649279-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-51649279-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-51649279-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 30. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/30/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Fri, 30 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-30T18:22:52+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-111357 Ivanti Connect Secure Missing Authentication for Critical Function Vulnerability CVE-2026-118527 Ivanti Connect Secure Generation of Predictable Numbers or Identifiers Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of a

**Extracted signals**
- CVEs: CVE-2026-111357, CVE-2026-118527
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-78d77efc-1 · Initial access via CVE-2026-111357 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-111357 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-78d77efc-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-111357.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-78d77efc-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-111357 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-111357/ | summarize count() by src_ip, dst_host`
- **[H-78d77efc-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-111357 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-111357')) | summarize coverage = avg(installed) by host_role`
- **[H-78d77efc-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-78d77efc-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-78d77efc-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-78d77efc-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-78d77efc-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-78d77efc-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-78d77efc-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-78d77efc-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-78d77efc-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-78d77efc-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-78d77efc-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-78d77efc-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-78d77efc-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 31. The Classics Return: Vulnerable E-Mail Scripts, (Wed, Nov 4th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33488>
- **Published**: Wed, 04 Nov 2026 13:24:13 GMT
- **First seen**: 2026-11-04T13:45:47+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 9 IOC(s)=+15

> One of the early web application vulnerabilities I remember was CVE-2000-0411 [CVE]. This was a simple vulnerability in a CGI-bin script used to send e-mail. The vulnerability was pretty straightforward: Adding additional parameters to the URL leaked environment variables. Other vulnerabilities allowed setting the "To" address and were heavily abused by spammers. And if parameters were passed directly to the sendmail binary, similar vulnerabilities could allow arbitrary code execution.

**Extracted signals**
- CVEs: CVE-2000-0411
- Sectors: manufacturing, telecom
- Domain IOCs: sendmail.php, test-mail.php, testemail.php, email-test.php, mailtest.php, nvd.nist.gov, gist.github.com, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-0d477490-1 · Initial access via CVE-2000-0411 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2000-0411 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2000-0411.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0d477490-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2000-0411.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0d477490-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2000-0411 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2000-0411/ | summarize count() by src_ip, dst_host`
- **[H-0d477490-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2000-0411 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2000-0411')) | summarize coverage = avg(installed) by host_role`
- **[H-0d477490-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0d477490-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0d477490-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2000-0411.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0d477490-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sendmail.php','test-mail.php','testemail.php') | summarize count() by client_ip`
- **[H-0d477490-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0d477490-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0d477490-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0d477490-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-0d477490-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2000-0411.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0d477490-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0d477490-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0d477490-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0d477490-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 32. Mutipath TCP: Use and Detection, (Mon, Nov 2nd)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33482>
- **Published**: Mon, 02 Nov 2026 14:52:05 GMT
- **First seen**: 2026-11-02T15:36:18+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 7 IOC(s)=+15

> Last week, an often-ignored&#;x26;#;xc2;&#;x26;#;xa0;TCP option, introduced in 2020, made the news due to a new vulnerability in Linux&#;x26;#;39;s implementation (RFC&#;x26;#;xc2;&#;x26;#;xa0;8684, &#;x26;#;xc2;&#;x26;#;xa0;CVE-2026-98432)

**Extracted signals**
- CVEs: CVE-2026-98432
- Sectors: manufacturing, telecom
- IP IOCs: 17.0.0.0
- Domain IOCs: tcp.hdr, support.apple.com, www.rfc-editor.org, www.openwall.com, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-8d6d4c88-1 · Initial access via CVE-2026-98432 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-98432 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-98432.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8d6d4c88-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-98432.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-8d6d4c88-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-98432 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-98432/ | summarize count() by src_ip, dst_host`
- **[H-8d6d4c88-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-98432 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-98432')) | summarize coverage = avg(installed) by host_role`
- **[H-8d6d4c88-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-8d6d4c88-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-8d6d4c88-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-98432.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8d6d4c88-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('tcp.hdr','support.apple.com','www.rfc-editor.org') | summarize count() by client_ip`
- **[H-8d6d4c88-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('17.0.0.0') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-8d6d4c88-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-8d6d4c88-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-8d6d4c88-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-8d6d4c88-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-98432.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8d6d4c88-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-8d6d4c88-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-8d6d4c88-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-8d6d4c88-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 33. Deploying a Local Ghidra Server for Your Malware Analysis Lab, (Thu, Oct 29th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33470>
- **Published**: Thu, 29 Oct 2026 06:17:41 GMT
- **First seen**: 2026-10-29T06:38:23+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 7 IOC(s)=+15

> Building your malware analysis lab is a key point before playing with malware. Today, thanks to virtualization, it&#;x26;#;39;s convenient to play with snapshots in your lab. Start a new investigation from a clean snapshot and take some more when you reached a critical step. But, if you need to revert to a previous snapshot, all changes applied to the VM are... lost! Therefore, it&#;x26;#;39;s important to store important data outside the VM.

**Extracted signals**
- Products: Active Directory
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: government, manufacturing, telecom
- Domain IOCs: server.conf, ghidra.repositories.dir, wrapper.app.account, wrapper.app.parameter, ghidra.lab.local, ghidra-server.org, isc.sans.edu

### Hypotheses (3)

#### H-1027c56d-1 · Initial access via the disclosed vulnerability affecting Active Directory  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Active Directory within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1027c56d-1-O1] Inventory exposure to Active Directory** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Active Directory, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Active Directory' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-1027c56d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-1027c56d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-1027c56d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Active Directory hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-1027c56d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-1027c56d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1027c56d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('server.conf','ghidra.repositories.dir','wrapper.app.account') | summarize count() by client_ip`
- **[H-1027c56d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-1027c56d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-1027c56d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-1027c56d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-1027c56d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1027c56d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-1027c56d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-1027c56d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-1027c56d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 34. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 28 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-28T21:07:44+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 initial-access vector(s)=+7, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-41709 Broadcom VMWare ESX Insufficient Logging Vulnerability CVE-2026-46300 Linux Kernel Missing Initialization of a Variable Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in

**Extracted signals**
- CVEs: CVE-2026-41709, CVE-2026-46300
- Products: Linux kernel
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-6af95b5c-1 · Initial access via CVE-2026-41709 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-41709 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-41709, CVE-2026-46300; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6af95b5c-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2026-41709.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6af95b5c-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-41709 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-41709/ | summarize count() by src_ip, dst_host`
- **[H-6af95b5c-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-41709 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-41709')) | summarize coverage = avg(installed) by host_role`
- **[H-6af95b5c-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6af95b5c-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6af95b5c-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-41709, CVE-2026-46300; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6af95b5c-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-6af95b5c-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6af95b5c-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6af95b5c-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6af95b5c-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6af95b5c-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-41709, CVE-2026-46300; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6af95b5c-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6af95b5c-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6af95b5c-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6af95b5c-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 35. Looking for a Language [Guest Diary], (Wed, Oct 21st)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33442>
- **Published**: Mon, 26 Oct 2026 09:38:03 GMT
- **First seen**: 2026-10-26T09:55:20+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 27 IOC(s)=+15

> [This is a Guest Diary by Jeffray Spence, an ISC intern as part of the SANS.edu BACS program]

**Extracted signals**
- Products: Fortinet FortiOS
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: manufacturing, telecom
- IP IOCs: 165.154.36.91, 165.154.29.93, 165.154.11.140, 165.154.120.226, 165.154.33.72, 165.154.182.221
- Domain IOCs: sans.edu, host.ip, host.mac, source.geo, http.request.connection, http.request, source.geo.as.number, http.request.accept, http.request.body.content, config.json, sitemap.xml, robots.txt, favicon.ico, tzrhxln.cn, source.domain, leheedu.cn, brossy.com.cn, mail.brossy.com.cn, www.fortinet.com, www.sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-ab7c842e-1 · Initial access via the disclosed vulnerability affecting Fortinet FortiOS  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Fortinet FortiOS within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ab7c842e-1-O1] Inventory exposure to Fortinet FortiOS** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Fortinet FortiOS, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Fortinet FortiOS' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ab7c842e-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-ab7c842e-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-ab7c842e-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Fortinet FortiOS hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ab7c842e-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ab7c842e-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ab7c842e-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sans.edu','host.ip','host.mac') | summarize count() by client_ip`
- **[H-ab7c842e-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('165.154.36.91','165.154.29.93','165.154.11.140') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ab7c842e-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ab7c842e-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ab7c842e-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ab7c842e-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ab7c842e-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ab7c842e-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ab7c842e-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ab7c842e-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 36. Siemens Mendix SAML Module

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01>
- **Published**: Thu, 29 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-29T15:00:21+00:00
- **Relevance score**: 48
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 IOC(s)=+4

> View CSAF Summary Mendix SAML module contains an authentication bypass vulnerability that could allow an unauthenticated remote attacker to gain unauthorized access by replaying a valid SAML assertion in IdP-initiated authentication flows. Siemens has released new versions for the affected products and recommends to update to the latest versions. The following versions of Siemens Mendix SAML Module are affected: Mendix SAML (Mendix 10 compatible) vers:intdot/ Mendix SAML (Mendix 11 compatible) vers:intdot/ Mendix SAML (Mendix 9 compatible) vers:intdot/ CVSS Vendor Equipment v3 6.8 Siemens Mendix SAML (Mendix 10 compatible) 1 Vulnerability Authentication Bypass by Capture-replay Background Critical Infrastructure Sectors: Critical Manufacturing, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities CVE-2026-89209 Affected versions of the module do not properly protect against SAML assertion replay in IdP-initiated authentication flows. This could allow unauthenticated remote attackers to gain unauthorized access to the application by replaying a valid SAML response. Read More 3 Affected Products Mendix SAML (Mendix 10 compatible) Product Status: known_affected Remediations Mitigation Disable IdP-initiated SSO Vendor fix Update to V4.2.4 or later version Mendix SAML (Mendix 11 compatible) Product Status: known_affected Remediations Mitigation Disable IdP-initiated SSO Vendor fix Update to V4.2.4 or later version Mendix

**Extracted signals**
- CVEs: CVE-2026-89209
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: www.siemens.com

### Hypotheses (3)

#### H-cbb26294-1 · Initial access via CVE-2026-89209 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-89209 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-89209; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-cbb26294-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-89209.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-cbb26294-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-89209 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-89209/ | summarize count() by src_ip, dst_host`
- **[H-cbb26294-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-89209 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-89209')) | summarize coverage = avg(installed) by host_role`
- **[H-cbb26294-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-cbb26294-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-cbb26294-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-89209; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-cbb26294-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com') | summarize count() by client_ip`
- **[H-cbb26294-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-cbb26294-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-cbb26294-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-cbb26294-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-cbb26294-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-89209; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-cbb26294-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-cbb26294-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-cbb26294-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-cbb26294-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 37. In Other News: Tor Exit Relays Hijacked, Banks Spot Rogue AI Agents, Self-Rebuilding macOS Ransomware

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/in-other-news-tor-exit-relays-hijacked-banks-spot-rogue-ai-agents-self-rebuilding-macos-ransomware/>
- **Published**: Fri, 23 Oct 2026 14:23:37 +0000
- **First seen**: 2026-10-23T14:29:38+00:00
- **Relevance score**: 48
- **Score rationale**: source weight (news)=+5, 1 threat actor hit(s)=+20, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 impact action(s)=+8

> Noteworthy stories that might have slipped under the radar: Russia’s APT28 hit NATO defense firms, PingCAP source code stolen, ShinyHunters negotiator probe. The post In Other News: Tor Exit Relays Hijacked, Banks Spot Rogue AI Agents, Self-Rebuilding macOS Ransomware appeared first on SecurityWeek .

**Extracted signals**
- Threat actors: APT28 (Fancy Bear)
- Vectors: exploit
- Actions: ransomware
- Sectors: finance, manufacturing
- MITRE ATT&CK: T1486

### Hypotheses (3)

#### H-84e4fa62-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on threat actors: APT28 (Fancy Bear); vectors: exploit; impact: ransomware.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-84e4fa62-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-84e4fa62-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-84e4fa62-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-84e4fa62-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-84e4fa62-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-84e4fa62-2 · Post-foothold lateral movement consistent with APT28 (Fancy Bear)  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of APT28 (Fancy Bear) has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on threat actors: APT28 (Fancy Bear); vectors: exploit; impact: ransomware.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-84e4fa62-2-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-84e4fa62-2-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-84e4fa62-2-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-84e4fa62-2-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-84e4fa62-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on threat actors: APT28 (Fancy Bear); vectors: exploit; impact: ransomware.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-84e4fa62-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-84e4fa62-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-84e4fa62-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-84e4fa62-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-84e4fa62-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 38. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/27/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Tue, 27 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-27T19:54:18+00:00
- **Relevance score**: 47
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 initial-access vector(s)=+7

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-48356 Adobe Commerce and Magento Unrestricted Upload of File with Dangerous Type Vulnerability CVE-2026-111497 Google Brotli Unchecked Return Value Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability n

**Extracted signals**
- CVEs: CVE-2026-48356, CVE-2026-111497
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-eb02d7eb-1 · Initial access via CVE-2026-48356 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-48356 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-48356, CVE-2026-111497; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb02d7eb-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-48356.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-eb02d7eb-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-48356 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-48356/ | summarize count() by src_ip, dst_host`
- **[H-eb02d7eb-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-48356 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-48356')) | summarize coverage = avg(installed) by host_role`
- **[H-eb02d7eb-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-eb02d7eb-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-eb02d7eb-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-48356, CVE-2026-111497; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb02d7eb-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-eb02d7eb-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-eb02d7eb-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-eb02d7eb-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-eb02d7eb-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-eb02d7eb-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-48356, CVE-2026-111497; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-eb02d7eb-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-eb02d7eb-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-eb02d7eb-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-eb02d7eb-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 39. The Gentlemen: A closer look at a not-so-gentle ransomware-as-a-service operation

- **Source**: /r/netsec
- **Link**: <https://www.reddit.com/r/netsec/comments/1xgxdk8/the_gentlemen_a_closer_look_at_a_notsogentle/>
- **Published**: 2026-10-27T16:33:17+00:00
- **First seen**: 2026-10-27T17:12:18+00:00
- **Relevance score**: 47
- **Score rationale**: source weight (social)=+2, 1 malware family hit(s)=+20, 2 MITRE technique hit(s)=+11, 1 impact action(s)=+8, 2 IOC(s)=+6

> Our Threat Research Unit published a breakdown of “The Gentlemen” - a Russian-speaking ransomware-as-a-service group that emerged in mid-2025, reportedly after affiliates split off from established groups like LockBit and Qilin. A few things that stood out from the research: They’re offering affiliates up to 90% of ransom revenue - aggressive even by RaaS standards Claimed 800+ victims across the US and Europe, making them one of the top RaaS groups this year Cross-platform ransomware variants targeting Windows, Linux, NAS, and BSD Active use of EDR-killing tooling - one recent incident involved a custom dropper abusing vulnerable Safetica ProcessMonitor and Lenovo BootRepair.sys drivers (BYOVD) A breach of the group’s own infrastructure gave researchers rare visibility into their affiliate network, tooling, and ties to the broader ransomware ecosystem Full technical writeup linked below for anyone who wants to dig into the IOCs and affiliate details. https://www.acronis.com/en/tru/posts/the-gentlemen-a-closer-look-at-a-not-so-gentle-ransomware-as-a-service-operation/ submitted by /u/acronis [link] [comments]

**Extracted signals**
- Malware families: LockBit
- Actions: ransomware
- Sectors: manufacturing
- MITRE ATT&CK: T1053, T1486
- Domain IOCs: bootrepair.sys, www.acronis.com

### Hypotheses (3)

#### H-a6dbce3e-1 · Endpoint execution of LockBit  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute LockBit payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: LockBit; impact: ransomware.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a6dbce3e-1-O1] EDR hash sweep for LockBit** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known LockBit SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('LockBit', 'sha256')) | summarize count() by host`
- **[H-a6dbce3e-1-O2] Behavioural pattern hunt for LockBit** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-a6dbce3e-1-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no LockBit-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-a6dbce3e-1-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'LockBit' | summarize by host, action`
- **[H-a6dbce3e-1-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_lockbit' | summarize by host`

#### H-a6dbce3e-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: LockBit; impact: ransomware.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a6dbce3e-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('bootrepair.sys','www.acronis.com') | summarize count() by client_ip`
- **[H-a6dbce3e-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a6dbce3e-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a6dbce3e-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a6dbce3e-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a6dbce3e-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on malware families: LockBit; impact: ransomware.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a6dbce3e-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-a6dbce3e-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-a6dbce3e-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-a6dbce3e-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 40. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Mon, 26 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-26T23:31:58+00:00
- **Relevance score**: 47
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 initial-access vector(s)=+7

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog and updated the PHP Alert, Critical Vulnerabilities in PHP Require Immediate Patching : CVE-2026-109618 – PHP Memory Corruption Vulnerability CVE-2026-109619 – PHP Stale Internal Request-State Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not curre

**Extracted signals**
- CVEs: CVE-2026-109618, CVE-2026-109619
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-07547193-1 · Initial access via CVE-2026-109618 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109618 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-07547193-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109618.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-07547193-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109618 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109618/ | summarize count() by src_ip, dst_host`
- **[H-07547193-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109618 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109618')) | summarize coverage = avg(installed) by host_role`
- **[H-07547193-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-07547193-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-07547193-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-07547193-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-07547193-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-07547193-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-07547193-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-07547193-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-07547193-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-07547193-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-07547193-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-07547193-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-07547193-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 41. Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/>
- **Published**: Sat, 31 Oct 2026 12:00:00 GMT
- **First seen**: 2026-10-31T12:22:42+00:00
- **Relevance score**: 46
- **Score rationale**: source weight (vendor)=+10, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 6 IOC(s)=+14

> The self-deleting VOLTA infostealer steals credentials, sessions, and cryptocurrency wallets. Then, it uses LLMs to profile victims and rank their most valuable assets.

**Extracted signals**
- Vectors: phishing, vpn-edge, credential-theft
- Actions: data-breach, fraud
- Sectors: manufacturing, telecom
- Domain IOCs: battle.net, hide.me, rolimons.com, 9by0tjwoc3ut.exe, ylp9m5j3i2aw.exe
- SHA256: 57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279

### Hypotheses (3)

#### H-bce3d8b3-1 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, vpn-edge, credential-theft; impact: data-breach, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bce3d8b3-1-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('battle.net','hide.me','rolimons.com') | summarize count() by client_ip`
- **[H-bce3d8b3-1-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bce3d8b3-1-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bce3d8b3-1-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bce3d8b3-1-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bce3d8b3-2 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, vpn-edge, credential-theft; impact: data-breach, fraud.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bce3d8b3-2-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-bce3d8b3-2-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-bce3d8b3-2-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-bce3d8b3-2-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

#### H-bce3d8b3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, vpn-edge, credential-theft; impact: data-breach, fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bce3d8b3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-bce3d8b3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-bce3d8b3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-bce3d8b3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 42. PHP Vulnerability Wrap-Up, (Fri, Oct 23rd)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33450>
- **Published**: Fri, 23 Oct 2026 13:02:54 GMT
- **First seen**: 2026-10-23T13:07:56+00:00
- **Relevance score**: 45
- **Score rationale**: source weight (advisory)=+15, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 4 IOC(s)=+10

> This morning, we returned to Infocon Green. As usual, we are raising the Infocon to alert you to emerging situations requiring immediate attention. PHP fit that description. By now, you either know about it, or you probably never will, so it is time to go back to "business as usual".

**Extracted signals**
- Products: Fortinet FortiOS
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: php.net, node.js, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-4bfc31ec-1 · Initial access via the disclosed vulnerability affecting Fortinet FortiOS  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Fortinet FortiOS within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4bfc31ec-1-O1] Inventory exposure to Fortinet FortiOS** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Fortinet FortiOS, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Fortinet FortiOS' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-4bfc31ec-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-4bfc31ec-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-4bfc31ec-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Fortinet FortiOS hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-4bfc31ec-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-4bfc31ec-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4bfc31ec-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('php.net','node.js','sans.edu') | summarize count() by client_ip`
- **[H-4bfc31ec-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-4bfc31ec-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-4bfc31ec-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-4bfc31ec-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-4bfc31ec-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit, vpn-edge; impact: fraud; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4bfc31ec-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-4bfc31ec-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-4bfc31ec-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-4bfc31ec-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 43. IDC MarketScape names Microsoft a Leader in the 2026 Worldwide Modern Endpoint Security for Enterprises Vendor Assessment

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/29/idc-marketscape-names-microsoft-a-leader-in-the-2026-worldwide-modern-endpoint-security-for-enterprises-vendor-assessment/>
- **Published**: Thu, 29 Oct 2026 16:00:00 +0000
- **First seen**: 2026-10-29T19:01:50+00:00
- **Relevance score**: 44
- **Score rationale**: source weight (vendor)=+10, 3 MITRE technique hit(s)=+14, 2 initial-access vector(s)=+9, 2 impact action(s)=+11

> IDC has named Microsoft a Leader in the 2026 IDC MarketScape for Worldwide Modern Endpoint Security for Enterprises. The post IDC MarketScape names Microsoft a Leader in the 2026 Worldwide Modern Endpoint Security for Enterprises Vendor Assessment appeared first on Microsoft Security Blog .

**Extracted signals**
- Vectors: exploit, credential-theft
- Actions: ransomware, fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1078, T1486, T1219

### Hypotheses (3)

#### H-c6f79b90-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit, credential-theft; impact: ransomware, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6f79b90-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c6f79b90-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-c6f79b90-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-c6f79b90-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c6f79b90-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c6f79b90-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit, credential-theft; impact: ransomware, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6f79b90-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-c6f79b90-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c6f79b90-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c6f79b90-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c6f79b90-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c6f79b90-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: exploit, credential-theft; impact: ransomware, fraud.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c6f79b90-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-c6f79b90-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-c6f79b90-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-c6f79b90-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 44. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/11/04/cisa-adds-one-known-exploited-vulnerability-catalog>
- **Published**: Wed, 04 Nov 26 12:00:00 +0000
- **First seen**: 2026-11-04T21:26:52+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 initial-access vector(s)=+7

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2024-27834 Apple Multiple Products Improper Authentication Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it for potential addition through CISA’s KEV Nominati

**Extracted signals**
- CVEs: CVE-2024-27834
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-c6d22823-1 · Initial access via CVE-2024-27834 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2024-27834 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2024-27834; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6d22823-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2024-27834.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c6d22823-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2024-27834 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2024-27834/ | summarize count() by src_ip, dst_host`
- **[H-c6d22823-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2024-27834 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2024-27834')) | summarize coverage = avg(installed) by host_role`
- **[H-c6d22823-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c6d22823-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c6d22823-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2024-27834; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c6d22823-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-c6d22823-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c6d22823-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c6d22823-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c6d22823-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c6d22823-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2024-27834; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c6d22823-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c6d22823-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c6d22823-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c6d22823-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 45. CISA Confirms Hackers Exploiting WordPress Core Flaw During Software Upgrades

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/11/cisa-confirms-hackers-exploiting.html>
- **Published**: Wed, 04 Nov 2026 11:13:11 +0530
- **First seen**: 2026-11-04T07:21:17+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9

> The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added a security flaw in WordPress Core to the Known Exploited Vulnerabilities (KEV) catalog, citing evidence of active exploitation. The high-severity vulnerability, tracked as CVE-2026-119977 (CVSS score: 8.1), is a case of Time-of-check Time-of-use (TOCTOU) race condition that could be exploited to achieve arbitrary code

**Extracted signals**
- CVEs: CVE-2026-119977
- Vectors: exploit, rdp
- Sectors: government
- MITRE ATT&CK: T1021.001

### Hypotheses (3)

#### H-25a989e1-1 · Initial access via CVE-2026-119977 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-119977 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-25a989e1-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-119977.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-25a989e1-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-119977 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-119977/ | summarize count() by src_ip, dst_host`
- **[H-25a989e1-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-119977 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-119977')) | summarize coverage = avg(installed) by host_role`
- **[H-25a989e1-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-25a989e1-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-25a989e1-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-25a989e1-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-25a989e1-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-25a989e1-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-25a989e1-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-25a989e1-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-25a989e1-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-119977; vectors: exploit, rdp.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-25a989e1-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-25a989e1-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-25a989e1-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-25a989e1-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 46. Attackers Target Unpatched CryptoPayment Gateway Flaw That Can Expose Wallet Credentials

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/11/attackers-target-unpatched.html>
- **Published**: Tue, 03 Nov 2026 11:04:37 +0530
- **First seen**: 2026-11-03T06:14:45+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9

> Threat actors are attempting to exploit an unpatched maximum-severity security vulnerability in the CryptoPayment Gateway WordPress plugin, according to findings from Defused Cyber. The vulnerability in question is CVE-2026-81648, which carries a CVSS score of 10.0. Successful exploitation of the flaw could permit unauthenticated users to delete arbitrary files on the server and extract

**Extracted signals**
- CVEs: CVE-2026-81648
- Vectors: exploit, rdp
- MITRE ATT&CK: T1021.001

### Hypotheses (3)

#### H-399f3911-1 · Initial access via CVE-2026-81648 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-81648 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-81648; vectors: exploit, rdp.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-399f3911-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-81648.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-399f3911-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-81648 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-81648/ | summarize count() by src_ip, dst_host`
- **[H-399f3911-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-81648 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-81648')) | summarize coverage = avg(installed) by host_role`
- **[H-399f3911-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-399f3911-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-399f3911-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-81648; vectors: exploit, rdp.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-399f3911-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-399f3911-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-399f3911-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-399f3911-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-399f3911-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-399f3911-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-81648; vectors: exploit, rdp.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-399f3911-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-399f3911-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-399f3911-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-399f3911-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 47. Ivanti Patches Two More Zero-Days Exploited in Connect Secure Attack Chain

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/ivanti-patches-two-more-zero-days-exploited-in-connect-secure-attack-chain/>
- **Published**: Mon, 02 Nov 2026 07:57:49 +0000
- **First seen**: 2026-11-02T08:37:36+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (news)=+5, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added CVE-2026-111357 and CVE-2026-118527 to its KEV catalog after the Ivanti VPN flaws were chained in zero-day attacks. The post Ivanti Patches Two More Zero-Days Exploited in Connect Secure Attack Chain appeared first on SecurityWeek .

**Extracted signals**
- CVEs: CVE-2026-111357, CVE-2026-118527
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge

### Hypotheses (3)

#### H-ad0b9cfd-1 · Initial access via CVE-2026-111357 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-111357 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ad0b9cfd-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-111357.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ad0b9cfd-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-111357 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-111357/ | summarize count() by src_ip, dst_host`
- **[H-ad0b9cfd-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-111357 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-111357')) | summarize coverage = avg(installed) by host_role`
- **[H-ad0b9cfd-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ad0b9cfd-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ad0b9cfd-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ad0b9cfd-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-ad0b9cfd-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ad0b9cfd-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ad0b9cfd-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ad0b9cfd-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ad0b9cfd-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-111357, CVE-2026-118527; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ad0b9cfd-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ad0b9cfd-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ad0b9cfd-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ad0b9cfd-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 48. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog-0>
- **Published**: Fri, 23 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-23T21:12:23+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 initial-access vector(s)=+7

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-110447 Collabora Online – Built-in CODE Server OS Command Injection Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it for potential addition through CISA’

**Extracted signals**
- CVEs: CVE-2026-110447
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-9976a00b-1 · Initial access via CVE-2026-110447 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-110447 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-110447; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9976a00b-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-110447.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9976a00b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-110447 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-110447/ | summarize count() by src_ip, dst_host`
- **[H-9976a00b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-110447 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-110447')) | summarize coverage = avg(installed) by host_role`
- **[H-9976a00b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9976a00b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9976a00b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-110447; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9976a00b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-9976a00b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9976a00b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9976a00b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9976a00b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9976a00b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-110447; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9976a00b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-9976a00b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-9976a00b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-9976a00b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 49. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog>
- **Published**: Fri, 23 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-23T19:12:00+00:00
- **Relevance score**: 42
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 initial-access vector(s)=+7

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-114625 Arista VeloCloud Orchestrator SQL Injection Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it for potential addition through CISA’s KEV Nomination 

**Extracted signals**
- CVEs: CVE-2026-114625
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-7800423a-1 · Initial access via CVE-2026-114625 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-114625 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-114625; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7800423a-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-114625.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7800423a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-114625 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-114625/ | summarize count() by src_ip, dst_host`
- **[H-7800423a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-114625 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-114625')) | summarize coverage = avg(installed) by host_role`
- **[H-7800423a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7800423a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7800423a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-114625; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7800423a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-7800423a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7800423a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7800423a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7800423a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7800423a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-114625; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7800423a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7800423a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7800423a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7800423a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 50. Volt Typhoon Used Covert Silent Train Network in Four Zero-Day Exploitation Campaigns

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html>
- **Published**: Wed, 28 Oct 2026 23:38:33 +0530
- **First seen**: 2026-10-28T19:06:35+00:00
- **Relevance score**: 40
- **Score rationale**: source weight (news)=+5, 1 threat actor hit(s)=+20, 1 initial-access vector(s)=+7, 1 impact action(s)=+8

> The China-nexus cyber espionage group known as Volt Typhoon has been attributed to a now-disrupted covert access network dubbed Silent Train that has been put to use for zero-day exploitation and strategic access. "First identified in late 2023, Silent Train uses rotating chains of compromised SOHO, IoT, and enterprise infrastructure," Lumen Technologies Black Lotus Labs said in a report shared

**Extracted signals**
- Threat actors: Volt Typhoon
- Vectors: exploit
- Actions: espionage
- Sectors: manufacturing

### Hypotheses (3)

#### H-66e5fd2a-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on threat actors: Volt Typhoon; vectors: exploit; impact: espionage.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-66e5fd2a-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-66e5fd2a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-66e5fd2a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-66e5fd2a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-66e5fd2a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-66e5fd2a-2 · Post-foothold lateral movement consistent with Volt Typhoon  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Volt Typhoon has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on threat actors: Volt Typhoon; vectors: exploit; impact: espionage.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-66e5fd2a-2-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-66e5fd2a-2-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-66e5fd2a-2-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-66e5fd2a-2-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-66e5fd2a-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on threat actors: Volt Typhoon; vectors: exploit; impact: espionage.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-66e5fd2a-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-66e5fd2a-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-66e5fd2a-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-66e5fd2a-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---
