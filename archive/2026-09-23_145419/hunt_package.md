# Threat Hunting News Package

- Generated: `2026-09-23T14:54:16+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **430**  ·  Skipped (below threshold): **430**  ·  Briefings: **50**
- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`

---

## 1. Active exploitation of Cisco Secure Firewall Management Center vulnerabilities

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/fmc-ongoing-exploitation/>
- **Published**: Wed, 09 Sep 2026 16:08:59 GMT
- **First seen**: 2026-09-09T16:17:40+00:00
- **Relevance score**: 132
- **Score rationale**: source weight (vendor)=+10, 2 CVE(s)=+25, 1 malware family hit(s)=+20, 1 threat actor hit(s)=+20, 4 MITRE technique hit(s)=+17, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 1 product mention(s)=+3, 27 IOC(s)=+15

> Cisco Talos is actively tracking the exploitation of two vulnerabilities in Cisco’s Secure Firewall Management Center (FMC) Software.

**Extracted signals**
- CVEs: CVE-2026-20079, CVE-2026-20316
- Threat actors: Sandworm
- Malware families: Cl0p
- Products: Active Directory
- Vectors: exploit, smb, credential-theft
- Actions: ransomware, data-breach
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1021.002, T1021.006, T1486, T1505.003
- IP IOCs: 208.123.119.215, 89.34.96.56, 104.218.165.253, 91.214.78.118, 43.204.2.142
- Domain IOCs: request.getparameter, this.getclass, cmd.jar, omniquery.pl, java.io.bufferedreader, java.io.inputstreamreader, args.length, system.out.println, exploit.jar, system.exit, pb.redirecterrorstream, pb.start, process.getinputstream, reader.readline, process.waitfor, e.printstacktrace, license.tmp, socks5.py, home.jsp
- SHA256: b037f45e02a289325a1a5eb0d4db6a9fce9954fd0fdfd07162cb4eb2acbef77d, db491181ece3f319de6567ab6f6daa90c6879911cd890155e6b7d8cc7a1a8c8e, 6f98add5d1a7729192b6ad8491d85c505c64836f7881742d6b93bd8e3d2fe461

### Hypotheses (4)

#### H-8fec7501-1 · Initial access via CVE-2026-20079 affecting Active Directory  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-20079 in Active Directory within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; malware families: Cl0p; threat actors: Sandworm; vectors: exploit, smb, credential-theft; impact: ransomware, data-breach; products: Active Directory.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8fec7501-1-O1] Inventory exposure to Active Directory** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Active Directory, the external-exploitation hypothesis is disproven for CVE-2026-20079.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Active Directory' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-8fec7501-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-20079 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-20079/ | summarize count() by src_ip, dst_host`
- **[H-8fec7501-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-20079 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-20079')) | summarize coverage = avg(installed) by host_role`
- **[H-8fec7501-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Active Directory hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-8fec7501-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-8fec7501-2 · Endpoint execution of Cl0p  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cl0p payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; malware families: Cl0p; threat actors: Sandworm; vectors: exploit, smb, credential-theft; impact: ransomware, data-breach; products: Active Directory.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8fec7501-2-O1] EDR hash sweep for Cl0p** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cl0p SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cl0p', 'sha256')) | summarize count() by host`
- **[H-8fec7501-2-O2] Behavioural pattern hunt for Cl0p** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-8fec7501-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cl0p-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-8fec7501-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cl0p' | summarize by host, action`
- **[H-8fec7501-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cl0p' | summarize by host`

#### H-8fec7501-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; malware families: Cl0p; threat actors: Sandworm; vectors: exploit, smb, credential-theft; impact: ransomware, data-breach; products: Active Directory.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8fec7501-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('request.getparameter','this.getclass','cmd.jar') | summarize count() by client_ip`
- **[H-8fec7501-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('208.123.119.215','89.34.96.56','104.218.165.253') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-8fec7501-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-8fec7501-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-8fec7501-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-8fec7501-4 · Post-foothold lateral movement consistent with Sandworm  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of Sandworm has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; malware families: Cl0p; threat actors: Sandworm; vectors: exploit, smb, credential-theft; impact: ransomware, data-breach; products: Active Directory.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8fec7501-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-8fec7501-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-8fec7501-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-8fec7501-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 2. Ransomware incidents in Japan in the first half of 2026: Investigation of The Gentlemen’s infrastructure and evidence of Qilin's AI use

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/ransomware-incidents-in-japan-in-the-first-half-of-2026/>
- **Published**: Thu, 17 Sep 2026 10:00:43 GMT
- **First seen**: 2026-09-17T10:14:19+00:00
- **Relevance score**: 131
- **Score rationale**: source weight (vendor)=+10, 3 CVE(s)=+30, 1 malware family hit(s)=+20, 9 MITRE technique hit(s)=+20, 6 initial-access vector(s)=+15, 4 impact action(s)=+15, 3 product mention(s)=+9, 5 IOC(s)=+12

> Ransomware incidents in Japan rose 4.7% year over year. The Gentlemen was the most active group, with leak-site listings more than doubling from January to July. Qilin ranked second and appeared to use AI, while SMEs with capital under JPY 1 billion represented 80% of victims.

**Extracted signals**
- CVEs: CVE-2025-2479, CVE-2025-24799, CVE-2020-1472
- Malware families: LockBit
- Products: Microsoft Exchange, Active Directory, VMware ESXi
- Vectors: phishing, exploit, vpn-edge, rdp, smb, credential-theft
- Actions: ransomware, data-breach, wiper, fraud
- Sectors: manufacturing, education, retail
- MITRE ATT&CK: T1078, T1059, T1059.001, T1003, T1021.001, T1021.002, T1021.006, T1486, T1219
- Domain IOCs: ntds.dit, secretsdump.py, ntds.txt, sam.txt, deadman.py

### Hypotheses (4)

#### H-ec6e4789-1 · Initial access via CVE-2025-2479 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-2479 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-2479, CVE-2025-24799, CVE-2020-1472; malware families: LockBit; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, wiper; products: Microsoft Exchange, Active Directory, VMware ESXi.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ec6e4789-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2025-2479.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ec6e4789-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-2479 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-2479/ | summarize count() by src_ip, dst_host`
- **[H-ec6e4789-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-2479 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-2479')) | summarize coverage = avg(installed) by host_role`
- **[H-ec6e4789-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ec6e4789-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ec6e4789-2 · Endpoint execution of LockBit  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute LockBit payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on CVEs cited: CVE-2025-2479, CVE-2025-24799, CVE-2020-1472; malware families: LockBit; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, wiper; products: Microsoft Exchange, Active Directory, VMware ESXi.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ec6e4789-2-O1] EDR hash sweep for LockBit** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known LockBit SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('LockBit', 'sha256')) | summarize count() by host`
- **[H-ec6e4789-2-O2] Behavioural pattern hunt for LockBit** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-ec6e4789-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no LockBit-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-ec6e4789-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'LockBit' | summarize by host, action`
- **[H-ec6e4789-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_lockbit' | summarize by host`

#### H-ec6e4789-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-2479, CVE-2025-24799, CVE-2020-1472; malware families: LockBit; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, wiper; products: Microsoft Exchange, Active Directory, VMware ESXi.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ec6e4789-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('ntds.dit','secretsdump.py','ntds.txt') | summarize count() by client_ip`
- **[H-ec6e4789-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ec6e4789-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ec6e4789-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ec6e4789-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ec6e4789-4 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2025-2479, CVE-2025-24799, CVE-2020-1472; malware families: LockBit; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach, wiper; products: Microsoft Exchange, Active Directory, VMware ESXi.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ec6e4789-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-ec6e4789-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-ec6e4789-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-ec6e4789-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 3. We've got one word for it, and it's usually the wrong one

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/weve-got-one-word-for-it-and-its-usually-the-wrong-one/>
- **Published**: Thu, 10 Sep 2026 18:00:15 GMT
- **First seen**: 2026-09-10T18:10:51+00:00
- **Relevance score**: 86
- **Score rationale**: source weight (vendor)=+10, 2 CVE(s)=+25, 3 MITRE technique hit(s)=+14, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 20 IOC(s)=+15

> In this week's Threat Source newsletter, Joe explores why the word "burnout" often fails to capture the true toll of working in the cybersecurity industry and why we need better language to address it.

**Extracted signals**
- CVEs: CVE-2026-20079, CVE-2026-20316
- Vectors: phishing, exploit, vpn-edge
- Actions: espionage, fraud
- Sectors: healthcare, government, manufacturing
- MITRE ATT&CK: T1566, T1219, T1218.011
- Domain IOCs: cybr.sec.con, rundll32.exe, vid001.exe, w32.9f1f11a708-100.sbx.tg, tmp00055df5.dll, sample.exe, w32.c4dd71e347-95.sbx.tg, secoh-qad.exe, win.tool.procpatcher, win.dropper.suloc
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, 90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59, c4dd71e347a076ba24bdd2d0ee532ef991c1ef25a2431a19f850942ba2ab16b2, 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f, 5bb86c1cd08fe5e1516cba35c85fc03e503bd1b5469113ffa1f1b9e10897f811
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, c2efb2dcacba6d3ccc175b6ce1b7ed0a, 9a47c4d379998ade2f8f99e23a630c06, 38de5b216c33833af710e88f7f64fc98, f3e82419a43220a7a222fc01b7607adc

### Hypotheses (3)

#### H-2964d1f7-1 · Initial access via CVE-2026-20079 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-20079 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; vectors: phishing, exploit, vpn-edge; impact: espionage, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2964d1f7-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-20079.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2964d1f7-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-20079 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-20079/ | summarize count() by src_ip, dst_host`
- **[H-2964d1f7-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-20079 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-20079')) | summarize coverage = avg(installed) by host_role`
- **[H-2964d1f7-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2964d1f7-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2964d1f7-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; vectors: phishing, exploit, vpn-edge; impact: espionage, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2964d1f7-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('cybr.sec.con','rundll32.exe','vid001.exe') | summarize count() by client_ip`
- **[H-2964d1f7-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2964d1f7-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2964d1f7-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2964d1f7-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2964d1f7-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on CVEs cited: CVE-2026-20079, CVE-2026-20316; vectors: phishing, exploit, vpn-edge; impact: espionage, fraud.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2964d1f7-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-2964d1f7-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-2964d1f7-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-2964d1f7-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 4. Apple Updates Everything, (Mon, Sep 14th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33336>
- **Published**: Mon, 14 Sep 2026 18:33:44 GMT
- **First seen**: 2026-09-14T18:53:03+00:00
- **Relevance score**: 76
- **Score rationale**: source weight (advisory)=+15, 261 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 2 IOC(s)=+6

> Today, Apple released its annual update across all its operating systems. With that, Apple not only released new features but also patched 261 different vulnerabilities. This is the most vulnerabilities Apple has ever patched, but the increase is not as significant as other vendors&#;x26;#;39; "post-AI" patch releases.

**Extracted signals**
- CVEs: CVE-2022-3437, CVE-2026-20683, CVE-2026-28899, CVE-2026-28930, CVE-2026-28934, CVE-2026-28935, CVE-2026-28937, CVE-2026-28966, CVE-2026-28968, CVE-2026-28969, CVE-2026-34979, CVE-2026-43661, CVE-2026-43664, CVE-2026-43674, CVE-2026-43677, CVE-2026-43683, CVE-2026-43684, CVE-2026-43686, CVE-2026-43687, CVE-2026-43688, CVE-2026-43689, CVE-2026-43690, CVE-2026-43691, CVE-2026-43692, CVE-2026-43695, CVE-2026-43696, CVE-2026-43697, CVE-2026-43698, CVE-2026-43702, CVE-2026-43715, CVE-2026-43719, CVE-2026-43737, CVE-2026-43738, CVE-2026-43741, CVE-2026-43743, CVE-2026-43760, CVE-2026-43763, CVE-2026-43785, CVE-2026-43786, CVE-2026-43787, CVE-2026-43788, CVE-2026-43789, CVE-2026-43790, CVE-2026-43791, CVE-2026-43794, CVE-2026-64712, CVE-2026-64714, CVE-2026-64715, CVE-2026-64718, CVE-2026-64736, CVE-2026-64752, CVE-2026-64753, CVE-2026-64756, CVE-2026-64758, CVE-2026-64760, CVE-2026-64761, CVE-2026-64778, CVE-2026-64779, CVE-2026-64780, CVE-2026-64781, CVE-2026-64782, CVE-2026-64784, CVE-2026-64787, CVE-2026-64788, CVE-2026-64790, CVE-2026-65329, CVE-2026-65331, CVE-2026-65334, CVE-2026-65338, CVE-2026-65339, CVE-2026-65341, CVE-2026-65342, CVE-2026-65343, CVE-2026-65344, CVE-2026-65345, CVE-2026-65346, CVE-2026-65347, CVE-2026-65348, CVE-2026-65349, CVE-2026-65354, CVE-2026-65358, CVE-2026-65359, CVE-2026-65360, CVE-2026-65361, CVE-2026-65362, CVE-2026-65364, CVE-2026-65365, CVE-2026-65369, CVE-2026-65371, CVE-2026-65374, CVE-2026-65375, CVE-2026-65376, CVE-2026-65377, CVE-2026-65378, CVE-2026-65380, CVE-2026-65381, CVE-2026-65382, CVE-2026-65383, CVE-2026-65390, CVE-2026-65391, CVE-2026-65393, CVE-2026-65395, CVE-2026-65398, CVE-2026-65399, CVE-2026-65400, CVE-2026-65401, CVE-2026-65402, CVE-2026-65403, CVE-2026-65404, CVE-2026-65405, CVE-2026-65406, CVE-2026-65407, CVE-2026-65408, CVE-2026-65409, CVE-2026-65410, CVE-2026-65411, CVE-2026-65412, CVE-2026-65413, CVE-2026-65415, CVE-2026-84487, CVE-2026-84489, CVE-2026-84491, CVE-2026-84492, CVE-2026-84497, CVE-2026-84505, CVE-2026-84506, CVE-2026-84507, CVE-2026-84509, CVE-2026-84510, CVE-2026-84511, CVE-2026-84512, CVE-2026-84513, CVE-2026-84514, CVE-2026-84515, CVE-2026-84516, CVE-2026-84517, CVE-2026-84518, CVE-2026-84519, CVE-2026-84520, CVE-2026-84521, CVE-2026-84522, CVE-2026-84523, CVE-2026-84524, CVE-2026-84525, CVE-2026-84526, CVE-2026-84527, CVE-2026-84530, CVE-2026-84531, CVE-2026-84532, CVE-2026-84533, CVE-2026-84534, CVE-2026-84535, CVE-2026-84536, CVE-2026-84537, CVE-2026-84538, CVE-2026-84540, CVE-2026-84541, CVE-2026-84543, CVE-2026-84544, CVE-2026-84548, CVE-2026-84549, CVE-2026-84550, CVE-2026-84551, CVE-2026-84552, CVE-2026-84553, CVE-2026-84554, CVE-2026-84555, CVE-2026-84556, CVE-2026-84558, CVE-2026-84559, CVE-2026-84560, CVE-2026-84561, CVE-2026-84563, CVE-2026-84564, CVE-2026-84565, CVE-2026-84566, CVE-2026-84567, CVE-2026-84568, CVE-2026-84569, CVE-2026-84570, CVE-2026-84571, CVE-2026-84572, CVE-2026-84573, CVE-2026-84574, CVE-2026-84575, CVE-2026-84576, CVE-2026-84577, CVE-2026-84578, CVE-2026-84580, CVE-2026-84581, CVE-2026-84583, CVE-2026-84584, CVE-2026-84585, CVE-2026-84586, CVE-2026-84587, CVE-2026-84588, CVE-2026-84589, CVE-2026-84593, CVE-2026-84596, CVE-2026-84597, CVE-2026-84598, CVE-2026-84600, CVE-2026-84601, CVE-2026-84602, CVE-2026-84603, CVE-2026-84606, CVE-2026-84607, CVE-2026-84609, CVE-2026-84611, CVE-2026-84612, CVE-2026-84615, CVE-2026-84616, CVE-2026-84617, CVE-2026-84618, CVE-2026-84619, CVE-2026-84620, CVE-2026-84621, CVE-2026-84622, CVE-2026-84623, CVE-2026-84624, CVE-2026-84625, CVE-2026-84626, CVE-2026-84628, CVE-2026-84629, CVE-2026-84631, CVE-2026-84632, CVE-2026-84635, CVE-2026-84636, CVE-2026-86869, CVE-2026-86870, CVE-2026-86876, CVE-2026-86878, CVE-2026-86879, CVE-2026-86881, CVE-2026-86882, CVE-2026-86883, CVE-2026-86884, CVE-2026-86885, CVE-2026-86886, CVE-2026-86887, CVE-2026-86888, CVE-2026-86889, CVE-2026-86890, CVE-2026-86891, CVE-2026-86892, CVE-2026-86893, CVE-2026-86894, CVE-2026-86895, CVE-2026-86897, CVE-2026-86898, CVE-2026-86900, CVE-2026-86901, CVE-2026-86902, CVE-2026-86903, CVE-2026-86904, CVE-2026-86905, CVE-2026-86909, CVE-2026-86910, CVE-2026-86911, CVE-2026-86917, CVE-2026-86924
- Vectors: exploit, smb
- Actions: ddos
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1021.002
- Domain IOCs: sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-bfb7e66d-1 · Initial access via CVE-2022-3437 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2022-3437 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2022-3437, CVE-2026-20683, CVE-2026-28899; vectors: exploit, smb; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bfb7e66d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2022-3437.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-bfb7e66d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2022-3437 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2022-3437/ | summarize count() by src_ip, dst_host`
- **[H-bfb7e66d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2022-3437 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2022-3437')) | summarize coverage = avg(installed) by host_role`
- **[H-bfb7e66d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-bfb7e66d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-bfb7e66d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2022-3437, CVE-2026-20683, CVE-2026-28899; vectors: exploit, smb; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bfb7e66d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sans.edu','isc.sans.edu') | summarize count() by client_ip`
- **[H-bfb7e66d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bfb7e66d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bfb7e66d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bfb7e66d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bfb7e66d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2022-3437, CVE-2026-20683, CVE-2026-28899; vectors: exploit, smb; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bfb7e66d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-bfb7e66d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-bfb7e66d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-bfb7e66d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 5. From guidance to action: Security fundamentals that materially reduce risk

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/09/17/from-guidance-to-action-security-fundamentals-that-materially-reduce-risk/>
- **Published**: Thu, 17 Sep 2026 17:00:00 +0000
- **First seen**: 2026-09-17T18:33:41+00:00
- **Relevance score**: 74
- **Score rationale**: source weight (vendor)=+10, 1 threat actor hit(s)=+20, 5 MITRE technique hit(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 1 IOC(s)=+4

> AI has made fundamental changes to the operating environment for cybersecurity. Explore exposure management guidance on recommended controls and take action and stay ahead of cyberthreats. The post From guidance to action: Security fundamentals that materially reduce risk appeared first on Microsoft Security Blog .

**Extracted signals**
- Threat actors: APT29 (Cozy Bear)
- Products: Active Directory
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566, T1059, T1059.001, T1021.006, T1219
- Domain IOCs: node.js

### Hypotheses (3)

#### H-d248788a-1 · Initial access via the disclosed vulnerability affecting Active Directory  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Active Directory within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on threat actors: APT29 (Cozy Bear); vectors: phishing, exploit; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d248788a-1-O1] Inventory exposure to Active Directory** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Active Directory, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Active Directory' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d248788a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-d248788a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-d248788a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Active Directory hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d248788a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d248788a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on threat actors: APT29 (Cozy Bear); vectors: phishing, exploit; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d248788a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('node.js') | summarize count() by client_ip`
- **[H-d248788a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d248788a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d248788a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d248788a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d248788a-3 · Post-foothold lateral movement consistent with APT29 (Cozy Bear)  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of APT29 (Cozy Bear) has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on threat actors: APT29 (Cozy Bear); vectors: phishing, exploit; impact: fraud; products: Active Directory.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d248788a-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-d248788a-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-d248788a-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-d248788a-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 6. AVEVA Pipeline Integrity Monitor

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-253-01>
- **Published**: Thu, 10 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-10T16:17:47+00:00
- **Relevance score**: 74
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 3 IOC(s)=+8

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to disclose information, brute-force hashes, or run arbitrary code in a browser session. The following versions of AVEVA Pipeline Integrity Monitor are affected: AVEVA Pipeline Integrity Monitor CVSS Vendor Equipment Vulnerabilities v3 8.4 AVEVA AVEVA Pipeline Integrity Monitor Use of Hard-coded Cryptographic Key, Use of a Broken or Risky Cryptographic Algorithm, Missing Authorization, Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: United Kingdom Vulnerabilities Expand All + CVE-2026-81821 The vulnerability, if exploited, could allow a miscreant with read access to PIMBoards project files to decrypt and view sensitive information. View CVE Details Affected Products AVEVA Pipeline Integrity Monitor Vendor: AVEVA Product Version: AVEVA AVEVA Pipeline Integrity Monitor: Product Status: known_affected Remediations Vendor fix AVEVA recommends that organizations evaluate the impact of these vulnerabilities based on their operational environment, architecture, and product implementation. Customers using affected product versions or affected PIMBoards project files should take the following actions to mitigate the risk of exploit: Apply AVEVA Pipeline Integrity Monitor 2025 SP1 P2 Security Update and migrate old project files

**Extracted signals**
- CVEs: CVE-2026-81821, CVE-2026-81822, CVE-2026-81823, CVE-2026-81824
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.aveva.com, 2026-006.pdf, www.cisa.gov

### Hypotheses (3)

#### H-431c4f99-1 · Initial access via CVE-2026-81821 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-81821 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-81821, CVE-2026-81822, CVE-2026-81823; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-431c4f99-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-81821.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-431c4f99-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-81821 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-81821/ | summarize count() by src_ip, dst_host`
- **[H-431c4f99-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-81821 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-81821')) | summarize coverage = avg(installed) by host_role`
- **[H-431c4f99-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-431c4f99-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-431c4f99-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-81821, CVE-2026-81822, CVE-2026-81823; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-431c4f99-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.aveva.com','2026-006.pdf','www.cisa.gov') | summarize count() by client_ip`
- **[H-431c4f99-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-431c4f99-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-431c4f99-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-431c4f99-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-431c4f99-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-81821, CVE-2026-81822, CVE-2026-81823; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-431c4f99-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-431c4f99-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-431c4f99-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-431c4f99-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 7. Hitachi Energy FACTS Control Platform (FCP)

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-03>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 73
- **Score rationale**: source weight (advisory)=+15, 5 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 3 initial-access vector(s)=+11, 1 product mention(s)=+3, 2 IOC(s)=+6

> View CSAF Summary Hitachi Energy is aware of vulnerabilities that affect the FACTS Control systems with GWS component listed in this document. An attacker exploiting these vulnerabilities can cause impact on confidentiality, integrity and availability of the product. Following FACTS Control systems with GWS component deployed from year 2020 onwards are likely affected by the above vulnerabilities. Product deployments without GWS component are not affected. • SVC Light (STATCOM) • Fixed Series Capacitor • Thyristor Controlled Series Capacitor • Static Var Compensator • Static Watt Compensator • Hybrid Synchronous Condensers Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The affected FCP versions are only applicable if GWS component is present. The following versions of Hitachi Energy FACTS Control Platform (FCP) are affected: FACTS Control Platform (FCP) 3.4.0, 3.7.0, 3.8.0, 3.10.0, 3.12.0, 3.14.0, 3.15.0, 4.0.0, 4.0.1, 4.1.0, 4.1.1 (CVE-2024-4872, CVE-2024-3980, CVE-2024-3982, CVE-2024-7940, CVE-2024-7941) CVSS Vendor Equipment Vulnerabilities v3 9.9 Hitachi Energy Hitachi Energy FACTS Control Platform (FCP) Improper Neutralization of Special Elements in Data Query Logic, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'), Authentication Bypass by Capture-replay, Missing Authentication for Critical Function, URL Redirection to Untrusted Site ('Open Redirect') Background Critical Infrastructure Se

**Extracted signals**
- CVEs: CVE-2024-4872, CVE-2024-3980, CVE-2024-3982, CVE-2024-7940, CVE-2024-7941
- Products: Microsoft Exchange
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.hitachienergy.com, www.cisa.gov

### Hypotheses (3)

#### H-d71a06e5-1 · Initial access via CVE-2024-4872 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2024-4872 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2024-4872, CVE-2024-3980, CVE-2024-3982; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d71a06e5-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2024-4872.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d71a06e5-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2024-4872 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2024-4872/ | summarize count() by src_ip, dst_host`
- **[H-d71a06e5-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2024-4872 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2024-4872')) | summarize coverage = avg(installed) by host_role`
- **[H-d71a06e5-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d71a06e5-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d71a06e5-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2024-4872, CVE-2024-3980, CVE-2024-3982; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d71a06e5-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-d71a06e5-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d71a06e5-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d71a06e5-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d71a06e5-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d71a06e5-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2024-4872, CVE-2024-3980, CVE-2024-3982; vectors: phishing, exploit, vpn-edge; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d71a06e5-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d71a06e5-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d71a06e5-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d71a06e5-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 8. Digital Watchdog VMAX DVR and NVR Product Lineups

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-01>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 72
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could grant full administrative control of the device, allowing an attacker to view live and recorded surveillance, alter device configurations, and use the device as a network pivot point. The following versions of Digital Watchdog VMAX DVR and NVR Product Lineups are affected: VMAX A1 G4 DVRs vers:all/* (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) VMAX IP G4 NVRs vers:all/* (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) VMAX A1 PLUS vers:all/* (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) VA1G4 Recorder vers:all/* (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) VG4 Recorder vers:all/* (CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372) CVSS Vendor Equipment Vulnerabilities v3 9.6 Digital Watchdog Digital Watchdog VMAX DVR and NVR Product Lineups Missing Authentication for Critical Function, Use of Hard-coded Credentials, Missing Authorization, Predictable Seed in Pseudo-Random Number Generator (PRNG) Background Critical Infrastructure Sectors: Commercial Facilities, Government Services and Facilities, Healthcare and Public Health, Transportation Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-

**Extracted signals**
- CVEs: CVE-2026-68953, CVE-2026-66890, CVE-2026-68070, CVE-2026-68950, CVE-2026-66887, CVE-2026-66372
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, government, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: digital-watchdog.com, www.cisa.gov

### Hypotheses (3)

#### H-2715899f-1 · Initial access via CVE-2026-68953 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-68953 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-68953, CVE-2026-66890, CVE-2026-68070; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2715899f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-68953.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2715899f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-68953 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-68953/ | summarize count() by src_ip, dst_host`
- **[H-2715899f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-68953 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-68953')) | summarize coverage = avg(installed) by host_role`
- **[H-2715899f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2715899f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2715899f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-68953, CVE-2026-66890, CVE-2026-68070; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2715899f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('digital-watchdog.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-2715899f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2715899f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2715899f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2715899f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2715899f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-68953, CVE-2026-66890, CVE-2026-68070; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2715899f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2715899f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2715899f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2715899f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 9. Bransys ELD

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-01>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow unauthorized access to telemetry data and firmware. The following versions of Bransys ELD are affected: Android iOS CVSS Vendor Equipment Vulnerabilities v3 7.5 Bransys Bransys ELD Use of Hard-coded Credentials, Cleartext Transmission of Sensitive Information Background Critical Infrastructure Sectors: Transportation Systems Countries/Areas Deployed: United States Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-86520 The affected product is shipped with hardcoded MQTT credentials, which will grant read access to real-time data for every active device across a subset of carriers that were connected to the affected MQTT broker. View CVE Details Affected Products Bransys ELD Vendor: Bransys Product Version: Bransys Android: Product Status: known_affected Remediations Vendor fix Bransys recommends that users update their system through the app store. Android users should be on version 11.00.00 or newer. iOS users should be on version 1.1.54 or newer. Relevant CWE: CWE-798 Use of Hard-coded Credentials Metrics CVSS Version Base Score Base Severity Vector String 3.1 7.5 HIGH CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N 4.0 8.7 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N CVE-2026-86689 The affected product is susceptible to cleartext transmission of sensitive information, which could allow an attacker to connect to the broker and read all data. V

**Extracted signals**
- CVEs: CVE-2026-86520, CVE-2026-86689, CVE-2026-77960
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-0b73b3af-1 · Initial access via CVE-2026-86520 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-86520 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-86520, CVE-2026-86689, CVE-2026-77960; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0b73b3af-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-86520.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0b73b3af-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-86520 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-86520/ | summarize count() by src_ip, dst_host`
- **[H-0b73b3af-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-86520 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-86520')) | summarize coverage = avg(installed) by host_role`
- **[H-0b73b3af-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0b73b3af-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0b73b3af-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-86520, CVE-2026-86689, CVE-2026-77960; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0b73b3af-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-0b73b3af-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0b73b3af-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0b73b3af-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0b73b3af-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-0b73b3af-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-86520, CVE-2026-86689, CVE-2026-77960; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0b73b3af-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0b73b3af-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0b73b3af-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0b73b3af-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 10. CareCam CM2507

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-08>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 7 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to access live video and sensitive device information, enable unauthorized services, execute arbitrary code, modify device operation, and recover stored credentials. The following versions of CareCam CM2507 are affected: HMT.CM2507 Firmware v251211.1507 (CVE-2026-88259, CVE-2026-84398, CVE-2026-84400, CVE-2026-81305, CVE-2026-85478, CVE-2026-85497, CVE-2026-81321) CVSS Vendor Equipment Vulnerabilities v3 7.5 CareCam CareCam CM2507 Missing Authentication for Critical Function, Empty Password in Configuration File, Inclusion of Functionality from Untrusted Control Sphere, Use of Password Hash With Insufficient Computational Effort, Cleartext Storage of Sensitive Information Background Critical Infrastructure Sectors: Commercial Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: China Vulnerabilities Expand All + CVE-2026-88259 CareCam CM2507 IP cameras do not require authentication for access to its network video streaming service. An unauthenticated attacker with network access to the affected device could retrieve live camera video. View CVE Details Affected Products CareCam CM2507 Vendor: CareCam Product Version: CareCam HMT.CM2507 Firmware: v251211.1507 Product Status: known_affected Remediations Mitigation CareCam has not responded to CISA's attempts to coordinate. Users are encouraged to reach out to CareCam for more information. Relevant CWE: CWE-306 Miss

**Extracted signals**
- CVEs: CVE-2026-88259, CVE-2026-84398, CVE-2026-84400, CVE-2026-81305, CVE-2026-85478, CVE-2026-85497, CVE-2026-81321
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-626ad618-1 · Initial access via CVE-2026-88259 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-88259 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-88259, CVE-2026-84398, CVE-2026-84400; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-626ad618-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-88259.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-626ad618-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-88259 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-88259/ | summarize count() by src_ip, dst_host`
- **[H-626ad618-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-88259 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-88259')) | summarize coverage = avg(installed) by host_role`
- **[H-626ad618-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-626ad618-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-626ad618-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-88259, CVE-2026-84398, CVE-2026-84400; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-626ad618-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-626ad618-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-626ad618-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-626ad618-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-626ad618-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-626ad618-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-88259, CVE-2026-84398, CVE-2026-84400; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-626ad618-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-626ad618-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-626ad618-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-626ad618-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 11. NextGen Healthcare Mirth Connect

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-01>
- **Published**: Thu, 10 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-10T16:17:47+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to exfiltrate date or cause a denial-of-service condition. The following versions of NextGen Healthcare Mirth Connect are affected: Mirth Connect CVSS Vendor Equipment Vulnerabilities v3 8.3 NextGen Healthcare NextGen Healthcare Mirth Connect Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'), Improper Restriction of XML External Entity Reference Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-82583 NextGen Connect (Mirth Connect) versions 4.7.1 and earlier allow an authenticated user to execute arbitrary SQL through a Database Connector API, which could result in disclosure of stored credentials for connected systems, arbitrary file write, and a denial-of-service condition. View CVE Details Affected Products NextGen Healthcare Mirth Connect Vendor: NextGen Healthcare Product Version: NextGen Healthcare Mirth Connect: Product Status: known_affected Remediations Vendor fix NextGen recommends users update Mirth Connect v4.7.2 or later. Users can download the latest version from the NextGen Healthcare customer portal. Relevant CWE: CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') Metrics CVSS Version Base Score Base Severity Vector String 3.1 8.3 HIGH CVSS:3.1/AV:N/AC:L/PR

**Extracted signals**
- CVEs: CVE-2026-82583, CVE-2026-78224, CVE-2026-82578
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-2a27b41d-1 · Initial access via CVE-2026-82583 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-82583 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-82583, CVE-2026-78224, CVE-2026-82578; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a27b41d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-82583.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2a27b41d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-82583 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-82583/ | summarize count() by src_ip, dst_host`
- **[H-2a27b41d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-82583 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-82583')) | summarize coverage = avg(installed) by host_role`
- **[H-2a27b41d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2a27b41d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2a27b41d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-82583, CVE-2026-78224, CVE-2026-82578; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2a27b41d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-2a27b41d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2a27b41d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2a27b41d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2a27b41d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2a27b41d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-82583, CVE-2026-78224, CVE-2026-82578; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2a27b41d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2a27b41d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2a27b41d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2a27b41d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 12. LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33348>
- **Published**: Thu, 17 Sep 2026 15:06:44 GMT
- **First seen**: 2026-09-17T15:20:04+00:00
- **Relevance score**: 69
- **Score rationale**: source weight (advisory)=+15, 5 MITRE technique hit(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 66 IOC(s)=+15

> At the end of August, a malspam message was caught in the quarantine of a mail gateway operated by one of my customers. The message was not especially remarkable â;€;“; it asked the recipient to review some attached requirements and provide a price quotation for a fiber optic system and appeared to impersonate an employee of a legitimate company. ; ; The receiving gateway quarantined the message because it detected malicious content in the attachment, though even if it didnâ;€;™t, the e-mail would not have gotten much further due to failed SPF and DMARC checks. ;

**Extracted signals**
- Vectors: phishing, exploit, supply-chain
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566, T1059, T1059.001, T1053, T1055
- Domain IOCs: string.fromcharcode, v9719.folderexists, v8593.run, adodb.stream, s.type, s.charset, s.open, s.writetext, s.savetofile, output.txt, s.close, conhost.exe, powershell.exe, io.file, math.floor, math.random, v8593.expandenvironmentstrings, v9719.createfolder, v3560.type, v3560.charset, v3560.open, v3560.writetext, v3560.position, v3560.savetofile, v3560.close, v8593.environment, system.security, cryptography.aesm, enmcjw.mode, enmcjw.padding, enmcjw.key, enmcjw.iv, system.io.compres, sion.gzips, system.io.compression.compressionmode, zfqnba.read, sljdsq.length, ocxwzw.write, system.reflection.assemb, bjmnsj.invoke, photostudio.js, wscript.createobject, wscript.shell, scripting.filesystemobject, v9719.copyfile, wscript.scriptfullname, schedule.service, wscript.network, v6116.userdomain, v6116.username, wscript.exe, v5178.connect, v5178.getfolder, v8825.registertask, yapw.life, www.virustotal.com, isc.sans.edu, learn.microsoft.com, www.w3.org, assembly.load
- SHA256: 408b2df6e81824fa5bdf4f0fbd185a7e6db06e2be98fbeebce416f66954b9fa9, e4130bf8769a50106a963b6a43dfd4fe5b56c70eae76a0de971d25993159acfe, be73e8b06c4356b5b4644d69b4f426bb3b32b4bf9f14cc5743f17532799f760b
- MD5: 7acd5c5f1689332615c03357e143f51e, 5d92d1fb5d5fbd79a588f22e994a4aff, f351968c76eefc80d4e292a3f179b7b9

### Hypotheses (3)

#### H-13ae0225-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, supply-chain; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-13ae0225-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-13ae0225-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-13ae0225-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-13ae0225-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-13ae0225-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-13ae0225-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, supply-chain; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-13ae0225-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('string.fromcharcode','v9719.folderexists','v8593.run') | summarize count() by client_ip`
- **[H-13ae0225-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-13ae0225-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-13ae0225-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-13ae0225-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-13ae0225-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, supply-chain; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-13ae0225-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-13ae0225-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-13ae0225-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-13ae0225-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 13. Metasploit Wrap Up: This One Goes to Sixteen!

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen>
- **Published**: Fri, 11 Sep 2026 13:35:11 GMT
- **First seen**: 2026-09-11T13:50:01+00:00
- **Relevance score**: 69
- **Score rationale**: source weight (vendor)=+10, 13 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 3 initial-access vector(s)=+11, 4 IOC(s)=+10

> This One Goes to Sixteen! Another banger from Metasploit with sixteen new modules, including ten exploit modules, with five on the CISA KEV list. Cisco, Papercut, Sonicwall, Jetbrains, and Langflow all have exploit modules, and not to be outdone, we even have a Metasploit scanner to watch the watchers! New module content (16) Elasticsearch ingest-attachment Apache Tika XFA XXE Local File Read Authors: Bourbon Offensive Security Services and Jean-Marie Bourbon Type: Auxiliary Pull request: #21739 contributed by kmkz Path: scanner/http/elasticsearch_tika_xfa_xxe CVE reference: CVE-2025-66516 Description: Adds an auxiliary scanner module for CVE-2025-54988/CVE-2025-66516. The module validates an XML External Entity (XXE) vulnerability in Apache Tika's XFA parser exposed through the Elasticsearch attachment ingest processor. SPIP Unauthenticated Blind SQLi via Date Field Escaping Bypass Authors: Benoit Hua, Franck Chevalier, Julien Voisin, and ka3n1x Type: Auxiliary Pull request: #21791 contributed by jvoisin Path: scanner/http/spip_annee_sqli Description: Adds modules/auxiliary/scanner/http/spip_annee_sqli.rb which exploits a blind SQL injection in SPIP's date column escaping logic. Metasploit Payload Handler Detection (TCP/UDP/HTTP/HTTPS) Author: h00die Type: Auxiliary Pull request: #21551 contributed by h00die Path: scanner/msf/handler_detect Description: Adds a scanner module to enumerate ports on a host and determine if they're a Metasploit Reverse Handler or not, and if the

**Extracted signals**
- CVEs: CVE-2025-66516, CVE-2025-54988, CVE-2026-20929, CVE-2026-20079, CVE-2026-83549, CVE-2026-83548, CVE-2026-63077, CVE-2026-19295, CVE-2026-23744, CVE-2026-81578, CVE-2026-82078, CVE-2026-48558, CVE-2026-75604
- Vectors: exploit, vpn-edge, smb
- Sectors: manufacturing
- MITRE ATT&CK: T1021.002
- Domain IOCs: cmssnmptrap.sh, horizon3.ai, next.js, docs.metasploit.com

### Hypotheses (3)

#### H-bddeb925-1 · Initial access via CVE-2025-66516 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-66516 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-66516, CVE-2025-54988, CVE-2026-20929; vectors: exploit, vpn-edge, smb.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bddeb925-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2025-66516.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-bddeb925-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-66516 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-66516/ | summarize count() by src_ip, dst_host`
- **[H-bddeb925-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-66516 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-66516')) | summarize coverage = avg(installed) by host_role`
- **[H-bddeb925-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-bddeb925-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-bddeb925-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-66516, CVE-2025-54988, CVE-2026-20929; vectors: exploit, vpn-edge, smb.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bddeb925-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('cmssnmptrap.sh','horizon3.ai','next.js') | summarize count() by client_ip`
- **[H-bddeb925-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bddeb925-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bddeb925-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bddeb925-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bddeb925-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-66516, CVE-2025-54988, CVE-2026-20929; vectors: exploit, vpn-edge, smb.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bddeb925-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-bddeb925-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-bddeb925-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-bddeb925-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 14. Passkey-themed social engineering leads to identity and cloud compromise

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/>
- **Published**: Wed, 09 Sep 2026 17:41:18 +0000
- **First seen**: 2026-09-09T18:49:18+00:00
- **Relevance score**: 69
- **Score rationale**: source weight (vendor)=+10, 3 MITRE technique hit(s)=+14, 4 initial-access vector(s)=+13, 2 impact action(s)=+11, 2 product mention(s)=+6, 32 IOC(s)=+15

> Passkey-themed social engineering is being used to compromise identities and enable broader cloud attacks. Learn how threat actors establish MFA persistence, abuse Microsoft Graph for reconnaissance, and access SharePoint, OneDrive, and email data, along with key detection and mitigation guidance. The post Passkey-themed social engineering leads to identity and cloud compromise appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft Exchange, Microsoft 365 / Entra ID
- Vectors: phishing, exploit, credential-theft, social-engineering
- Actions: data-breach, fraud
- Sectors: manufacturing, education, telecom
- MITRE ATT&CK: T1566, T1078, T1567
- Domain IOCs: company-name.integratedsso.com, company-name.secure-passkey.com, companyname.maliciousdomain.com, contoso.add-passkey.com, passkeyhelpdesk.com, secure-passkey.com, setupmypasskey.com, add-passkey.com, integratedsso.com, oktasession.com, keysyncos.com, oskeysync.com, oskeysetup.com, oskeyregister.com, syncmykey.com, myconnectkey.com, oskeyconnect.com, validationsetupac.com, portalsetuphub.com, node.js, raweventdata.resultstatus, raweventdata.target, raweventdata.modifiedproperties, modifiedprop.name, modifiedprop.oldvalue, modifiedprop.newvalue, targetid.usertype, raweventdata.tokenobjectid, raweventdata.filesizebytes, mail.read, files.read.all, directory.read.all

### Hypotheses (4)

#### H-6f256b27-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, credential-theft; impact: data-breach, fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6f256b27-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6f256b27-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-6f256b27-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-6f256b27-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6f256b27-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6f256b27-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, credential-theft; impact: data-breach, fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6f256b27-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('company-name.integratedsso.com','company-name.secure-passkey.com','companyname.maliciousdomain.com') | summarize count() by client_ip`
- **[H-6f256b27-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6f256b27-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6f256b27-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6f256b27-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6f256b27-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit, credential-theft; impact: data-breach, fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6f256b27-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-6f256b27-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-6f256b27-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-6f256b27-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

#### H-6f256b27-4 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, credential-theft; impact: data-breach, fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6f256b27-4-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6f256b27-4-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6f256b27-4-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6f256b27-4-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 15. The Closed Quorum: Inside the first reported autonomous AI C2 implant

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/>
- **Published**: Tue, 22 Sep 2026 10:00:58 GMT
- **First seen**: 2026-09-22T10:32:10+00:00
- **Relevance score**: 67
- **Score rationale**: source weight (vendor)=+10, 11 MITRE technique hit(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 24 IOC(s)=+15

> CLOSEDQUORUM, a malware binary discovered through Cisco Talos’ CAIRN project, exhibits fully autonomous command and control (C2). It represents a shift in effort displacement for attackers, in which expanding portions of the attack chain can be executed without operator involvement.

**Extracted signals**
- Products: Microsoft Exchange
- Vectors: phishing, exploit, credential-theft
- Actions: fraud
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1566, T1078, T1059, T1059.001, T1053, T1547, T1055, T1003, T1567, T1573, T1497
- Domain IOCs: main.intermodeldiscussion, main.queryllm, main.main, exodus.wallet, schtasks.exe, powershell.exe, logins.json, api.deepseek.com, openrouter.ai, api.mistral.ai, gohno-final.exe, earlyburb.exe, cdn.discordapp.com, main.modelorchestrator, main.lsassdump, main.extractcryptowallets, main.sendtodiscord, main.earlybirdinject
- SHA256: 250d4fa37488af9b025333fa17705573d721467b203765bc360890b4f5a90cd7, c4dc171f2513fcaf9d5ecc815a94aee4063b213ab380f80bd3ac422dee5205a7, c13cea04f598e2b0c248d603a6e31bd13aabb64d8149c1b6a77b64e0b983a86f, f5f1f8c3e7b883793800ab6ccf21b3e60bd0730f300b4595fe74a33adc17a63c, 5191cf625dfc209a347f137b50aea199e82040fd5ee9086fb3e2de73c133f3cb, eddbd0ecf7195d38fefae5b9d393abfa79e6f3f94bde19308ecef130a05a42e5

### Hypotheses (3)

#### H-e72561c4-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e72561c4-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-e72561c4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-e72561c4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-e72561c4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-e72561c4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-e72561c4-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e72561c4-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('main.intermodeldiscussion','main.queryllm','main.main') | summarize count() by client_ip`
- **[H-e72561c4-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-e72561c4-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-e72561c4-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-e72561c4-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-e72561c4-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e72561c4-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-e72561c4-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-e72561c4-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-e72561c4-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 16. mySCADA myPRO Manager

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-03>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 67
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to access privileged management functions or send arbitrary SMS messages through the connected GSM modem. The following versions of mySCADA myPRO Manager are affected: mySCADA myPRO Manager CVSS Vendor Equipment Vulnerabilities v3 9.8 mySCADA Technologies mySCADA myPRO Manager Missing Authorization, Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Food and Agriculture, Transportation Systems, Water and Wastewater Countries/Areas Deployed: Worldwide Company Headquarters Location: Czechia Vulnerabilities Expand All + CVE-2026-73807 The mySCADA myPRO Manager command API does not properly enforce authentication for privileged functions. An unauthenticated attacker with network access to the affected API could exploit this vulnerability to access privileged management functions. View CVE Details Affected Products mySCADA myPRO Manager Vendor: mySCADA Technologies Product Version: mySCADA Technologies mySCADA myPRO Manager: Product Status: known_affected Remediations Mitigation mySCADA Technologies has addressed these issues in Version 2.2 and recommends that users update to the latest version. Users are notified in mySCADA Pro Manager about the availability of a new version if the device is connected to the internet. Otherwise, users can download the mySCADA Pro Manager from the webpage. https://www.myscada.org/downloads

**Extracted signals**
- CVEs: CVE-2026-73807, CVE-2026-82567
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.myscada.org, www.cisa.gov

### Hypotheses (3)

#### H-c61b8c87-1 · Initial access via CVE-2026-73807 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-73807 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-73807, CVE-2026-82567; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c61b8c87-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-73807.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c61b8c87-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-73807 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-73807/ | summarize count() by src_ip, dst_host`
- **[H-c61b8c87-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-73807 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-73807')) | summarize coverage = avg(installed) by host_role`
- **[H-c61b8c87-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c61b8c87-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c61b8c87-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-73807, CVE-2026-82567; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c61b8c87-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.myscada.org','www.cisa.gov') | summarize count() by client_ip`
- **[H-c61b8c87-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c61b8c87-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c61b8c87-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c61b8c87-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c61b8c87-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-73807, CVE-2026-82567; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c61b8c87-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c61b8c87-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c61b8c87-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c61b8c87-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 17. Wärtsilä FOS-Onboard

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 67
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to deliver an unauthorized update, execute code, or extract credentials to allow the attacker to impersonate a privileged client. The following versions of Wärtsilä FOS-Onboard are affected: FOS-Onboard 5.07.0923.01 (CVE-2026-78225, CVE-2026-81855) CVSS Vendor Equipment Vulnerabilities v3 9.1 Wärtsilä Wärtsilä FOS-Onboard Use of Hard-coded Cryptographic Key Background Critical Infrastructure Sectors: Transportation Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Finland Vulnerabilities Expand All + CVE-2026-78225 A hardcoded cryptographic server key vulnerability exists in the deployer-ng Update Controller component of Wärtsilä FOS-Onboard. View CVE Details Affected Products Wärtsilä FOS-Onboard Vendor: Wärtsilä Product Version: Wärtsilä FOS-Onboard: 5.07.0923.01 Product Status: known_affected Remediations Mitigation Wärtsilä states that the vulnerabilities are not exploitable when the product is installed as recommended, and has developed a security patch. Users are also directed to contact Wärtsilä to obtain and install the patch. To obtain and install the latest patch, contact Wärtsilä: https://www.wartsila.com/services-catalogue/engine-services-4-stroke/wartsila-ics-patch-deployment#contact Relevant CWE: CWE-321 Use of Hard-coded Cryptographic Key Metrics CVSS Version Base Score Base Severity Vector String 3.1 9 CRITICAL CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:

**Extracted signals**
- CVEs: CVE-2026-78225, CVE-2026-81855
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.wartsila.com, www.cisa.gov

### Hypotheses (3)

#### H-2934f6f2-1 · Initial access via CVE-2026-78225 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-78225 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-78225, CVE-2026-81855; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2934f6f2-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-78225.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2934f6f2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-78225 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-78225/ | summarize count() by src_ip, dst_host`
- **[H-2934f6f2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-78225 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-78225')) | summarize coverage = avg(installed) by host_role`
- **[H-2934f6f2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2934f6f2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2934f6f2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-78225, CVE-2026-81855; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2934f6f2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.wartsila.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-2934f6f2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2934f6f2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2934f6f2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2934f6f2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2934f6f2-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-78225, CVE-2026-81855; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2934f6f2-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2934f6f2-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2934f6f2-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2934f6f2-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 18. lwIP (Lightweight IP)

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-02>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 4 IOC(s)=+10

> View CSAF Summary Successful exploitation of this vulnerability could result in a system crash, a DoS, or memory corruption, which could lead to code execution on the victim system. The following versions of lwIP (Lightweight IP) are affected: API >=2.0.1| CVSS Vendor Equipment Vulnerabilities v3 8.8 lwIP lwIP (Lightweight IP) Double Free Background Critical Infrastructure Sectors: Chemical, Communications, Critical Manufacturing, Energy, Financial Services, Healthcare and Public Health, Transportation Systems, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Sweden Vulnerabilities Expand All + CVE-2026-91018 The affected product has a double free vulnerability, which could crash the system, cause a DoS, memory corruption, or allow code execution on the victim system. View CVE Details Affected Products lwIP (Lightweight IP) Vendor: lwIP Product Version: lwIP API: >=2.0.1| Product Status: known_affected Remediations Mitigation Users of lwIP are encouraged to update their version of lwIP using the repository found at https://cgit.git.savannah.gnu.org/cgit/lwip.git . The commit identifier that contains the fix is f873b6295933e4149a2132adf3e9a2d2a676a5ec. Relevant CWE: CWE-415 Double Free Metrics CVSS Version Base Score Base Severity Vector String 3.1 8.8 HIGH CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 4.0 8.7 HIGH CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N Acknowledgments Eric Evenchick of Tetrel Security repo

**Extracted signals**
- CVEs: CVE-2026-91018
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, finance, energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: cgit.git.savannah.gnu.org, lwip.git, www.cisa.gov
- SHA1: f873b6295933e4149a2132adf3e9a2d2a676a5ec

### Hypotheses (3)

#### H-711d3139-1 · Initial access via CVE-2026-91018 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-91018 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-91018; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-711d3139-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-91018.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-711d3139-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-91018 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-91018/ | summarize count() by src_ip, dst_host`
- **[H-711d3139-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-91018 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-91018')) | summarize coverage = avg(installed) by host_role`
- **[H-711d3139-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-711d3139-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-711d3139-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-91018; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-711d3139-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('cgit.git.savannah.gnu.org','lwip.git','www.cisa.gov') | summarize count() by client_ip`
- **[H-711d3139-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-711d3139-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-711d3139-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-711d3139-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-711d3139-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-91018; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-711d3139-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-711d3139-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-711d3139-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-711d3139-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 19. Unmasking EvilTokens: Getting to the root of device code phishing

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/>
- **Published**: Tue, 22 Sep 2026 15:00:00 +0000
- **First seen**: 2026-09-22T15:47:45+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (vendor)=+10, 2 MITRE technique hit(s)=+11, 5 initial-access vector(s)=+15, 1 impact action(s)=+8, 2 product mention(s)=+6, 9 IOC(s)=+15

> EvilTokens has quickly become one of the top PhaaS platforms, enabling device code phishing attacks through AI-assisted lures, automated infrastructure, and token theft. In collaboration with partners, Microsoft Digital Crimes Unit (DCU) facilitated a disruption of EvilTokens infrastructure and operations. The post Unmasking EvilTokens: Getting to the root of device code phishing appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft Exchange, Microsoft 365 / Entra ID
- Vectors: phishing, exploit, cloud-misconfig, credential-theft, social-engineering
- Actions: fraud
- Sectors: healthcare, finance, manufacturing, education, telecom
- MITRE ATT&CK: T1566, T1219
- Domain IOCs: node.js, vercel.app, workers.dev, left.recipientobjectid, right.accountobjectid, left.onpremsid, left.remoteurl, right.urlclickedbyusersid, railway.com

### Hypotheses (3)

#### H-31134d55-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-31134d55-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-31134d55-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-31134d55-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-31134d55-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-31134d55-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-31134d55-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-31134d55-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('node.js','vercel.app','workers.dev') | summarize count() by client_ip`
- **[H-31134d55-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-31134d55-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-31134d55-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-31134d55-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-31134d55-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-31134d55-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-31134d55-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-31134d55-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-31134d55-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 20. HTTP QUERY Method: The Grey Zone Between GET And POST., (Fri, Sep 18th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33352>
- **Published**: Fri, 18 Sep 2026 06:05:26 GMT
- **First seen**: 2026-09-18T06:36:46+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (advisory)=+15, 1 malware family hit(s)=+20, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 7 IOC(s)=+15

> In June 2026 the IETF published RFC 10008[ 1 ], defining a new HTTP method: "QUERY". The HTTP protocol faced already by changes (HTTP/2, HTTP/2) but it's the first new standard HTTP verb since "PATCH" in 2010!

**Extracted signals**
- Malware families: Cobalt Strike
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: target.com, node.js, http.jl, http.method, www.rfc-editor.org, dev.to, isc.sans.edu

### Hypotheses (3)

#### H-efc5ef28-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on malware families: Cobalt Strike; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-efc5ef28-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-efc5ef28-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-efc5ef28-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-efc5ef28-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-efc5ef28-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-efc5ef28-2 · Endpoint execution of Cobalt Strike  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute Cobalt Strike payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: Cobalt Strike; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-efc5ef28-2-O1] EDR hash sweep for Cobalt Strike** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known Cobalt Strike SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('Cobalt Strike', 'sha256')) | summarize count() by host`
- **[H-efc5ef28-2-O2] Behavioural pattern hunt for Cobalt Strike** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-efc5ef28-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no Cobalt Strike-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-efc5ef28-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'Cobalt Strike' | summarize by host, action`
- **[H-efc5ef28-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_cobalt_strike' | summarize by host`

#### H-efc5ef28-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: Cobalt Strike; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-efc5ef28-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('target.com','node.js','http.jl') | summarize count() by client_ip`
- **[H-efc5ef28-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-efc5ef28-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-efc5ef28-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-efc5ef28-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 21. ABB Ability Edgenius

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-06>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3, 4 IOC(s)=+10

> View CSAF Summary ABB is aware of public reports of a vulnerability CVE‑2026‑31431 (Copy Fail) in the product versions listed as affected in the advisory. An update is available that resolves a publicly reported vulnerability. CVE‑2026‑31431 (Copy Fail) is a Linux kernel vulnerability that may allow a locally authenticated user or compromised container workload to gain elevated (root) privileges on affected systems. Once root access is obtained, the attacker can effectively gain complete control of the system The following versions of ABB Ability Edgenius are affected: Ability Edgenius >=3.2.0.0| CVSS Vendor Equipment Vulnerabilities v3 7.8 ABB ABB Ability Edgenius Incorrect Resource Transfer Between Spheres Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Water and Wastewater, Chemical Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-31431 A Linux kernel vulnerability that may allow a locally authenticated user or compromised container workload to gain elevated (root) privileges on affected systems. The issue originates in the Linux kernel’s cryptographic subsystem and impacts kernels used by most major Linux distributions released since 2017.Successful exploitation requires local code execution, however, in shared, containerized, or multi‑tenant environments this may increase the security risk. View CVE Details Affected Products ABB Ability Edgenius Vendor: ABB Product Version: AB

**Extracted signals**
- CVEs: CVE-2026-31431
- Products: Linux kernel
- Vectors: exploit, vpn-edge
- Actions: fraud
- Sectors: energy, manufacturing
- IP IOCs: 3.2.0.0, 3.2.4.1
- Domain IOCs: 2017.successful, www.cisa.gov

### Hypotheses (3)

#### H-54eaa077-1 · Initial access via CVE-2026-31431 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-31431 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; impact: fraud; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-54eaa077-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2026-31431.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-54eaa077-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-31431 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-31431/ | summarize count() by src_ip, dst_host`
- **[H-54eaa077-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-31431 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-31431')) | summarize coverage = avg(installed) by host_role`
- **[H-54eaa077-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-54eaa077-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-54eaa077-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; impact: fraud; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-54eaa077-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('2017.successful','www.cisa.gov') | summarize count() by client_ip`
- **[H-54eaa077-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('3.2.0.0','3.2.4.1') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-54eaa077-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-54eaa077-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-54eaa077-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-54eaa077-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; impact: fraud; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-54eaa077-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-54eaa077-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-54eaa077-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-54eaa077-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 22. lwIP TCP/IP Stack MQTT Client Application

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-01>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 3 IOC(s)=+8

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to gain full code execution on the device. The following versions of lwIP TCP/IP Stack MQTT Client Application are affected: MQTT Client Application >=2.0.1| CVSS Vendor Equipment Vulnerabilities v3 9.8 lwIP lwIP TCP/IP Stack MQTT Client Application Out-of-bounds Write Background Critical Infrastructure Sectors: Chemical, Communications, Critical Manufacturing, Energy, Financial Services, Healthcare and Public Health, Transportation Systems, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Sweden Vulnerabilities Expand All + CVE-2026-87121 The affected product is vulnerable to an out-of-bounds write, which may allow an attacker to gain full code execution on the device. View CVE Details Affected Products lwIP TCP/IP Stack MQTT Client Application Vendor: lwIP Product Version: lwIP MQTT Client Application: >=2.0.1| Product Status: known_affected Remediations Mitigation Users of lwIP are encouraged to update their version of lwIP using the repository found at https://savannah.nongnu.org/projects/lwip . The commit identifier that contains the fix is f89407ea711879c04d91c92b35d67be78bbaf0f1. Relevant CWE: CWE-787 Out-of-bounds Write Metrics CVSS Version Base Score Base Severity Vector String 3.1 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 4.0 9.3 CRITICAL CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N Acknowledgments 

**Extracted signals**
- CVEs: CVE-2026-87121
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, finance, energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: savannah.nongnu.org, www.cisa.gov
- SHA1: f89407ea711879c04d91c92b35d67be78bbaf0f1

### Hypotheses (3)

#### H-af6aacab-1 · Initial access via CVE-2026-87121 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-87121 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-87121; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-af6aacab-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-87121.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-af6aacab-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-87121 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-87121/ | summarize count() by src_ip, dst_host`
- **[H-af6aacab-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-87121 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-87121')) | summarize coverage = avg(installed) by host_role`
- **[H-af6aacab-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-af6aacab-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-af6aacab-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-87121; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-af6aacab-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('savannah.nongnu.org','www.cisa.gov') | summarize count() by client_ip`
- **[H-af6aacab-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-af6aacab-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-af6aacab-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-af6aacab-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-af6aacab-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-87121; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-af6aacab-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-af6aacab-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-af6aacab-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-af6aacab-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 23. Orthanc DICOM Server

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02>
- **Published**: Thu, 10 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-10T16:17:47+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 3 IOC(s)=+8

> View CSAF Summary Successful exploitation of this vulnerability could allow an authenticated remote attacker to write past the end of a heap allocation when Orthanc decodes an attacker-supplied PNG or JPEG image, resulting in a crash of the Orthanc process and a denial-of-service condition. The following versions of Orthanc DICOM Server are affected: Orthanc DICOM Server CVSS Vendor Equipment Vulnerabilities v3 8.1 Orthanc Orthanc DICOM Server Integer Overflow or Wraparound Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: Belgium Vulnerabilities Expand All + CVE-2026-87020 An integer overflow in a specified pitch and buffer-size computation leads to a heap out-of-bounds write when Orthanc decodes an attacker-supplied PNG. View CVE Details Affected Products Orthanc DICOM Server Vendor: Orthanc Product Version: Orthanc Orthanc DICOM Server: Product Status: known_affected Remediations Mitigation Orthanc recommends users update to v1.13.0. https://orthanc.uclouvain.be/downloads/index.html Relevant CWE: CWE-190 Integer Overflow or Wraparound Metrics CVSS Version Base Score Base Severity Vector String 3.1 8.1 HIGH CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H 4.0 7.2 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N Acknowledgments Andrej Tomci reported this vulnerability to CISA. Legal Notice and Terms of Use This product is provided subject to this Notification ( https://w

**Extracted signals**
- CVEs: CVE-2026-87020
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: orthanc.uclouvain.be, index.html, www.cisa.gov

### Hypotheses (3)

#### H-149008b3-1 · Initial access via CVE-2026-87020 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-87020 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-87020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-149008b3-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-87020.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-149008b3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-87020 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-87020/ | summarize count() by src_ip, dst_host`
- **[H-149008b3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-87020 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-87020')) | summarize coverage = avg(installed) by host_role`
- **[H-149008b3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-149008b3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-149008b3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-87020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-149008b3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('orthanc.uclouvain.be','index.html','www.cisa.gov') | summarize count() by client_ip`
- **[H-149008b3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-149008b3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-149008b3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-149008b3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-149008b3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-87020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-149008b3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-149008b3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-149008b3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-149008b3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 24. CISA Adds Three Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-three-known-exploited-vulnerabilities-catalog>
- **Published**: Fri, 11 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-11T20:08:00+00:00
- **Relevance score**: 63
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 product mention(s)=+3

> CISA has added three new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-42016 JFrog Artifactory Incorrect Authorization Vulnerability CVE-2026-42018 JFrog Artifactory Improper Authentication Vulnerability CVE-2026-84869 ConnectWise ScreenConnect Improper Privilege Management and Missing Authorization Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to 

**Extracted signals**
- CVEs: CVE-2026-42016, CVE-2026-42018, CVE-2026-84869
- Products: ConnectWise ScreenConnect
- Vectors: exploit
- Sectors: government, manufacturing
- MITRE ATT&CK: T1219

### Hypotheses (3)

#### H-4a7be2e7-1 · Initial access via CVE-2026-42016 affecting ConnectWise ScreenConnect  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-42016 in ConnectWise ScreenConnect within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-42016, CVE-2026-42018, CVE-2026-84869; vectors: exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4a7be2e7-1-O1] Inventory exposure to ConnectWise ScreenConnect** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of ConnectWise ScreenConnect, the external-exploitation hypothesis is disproven for CVE-2026-42016.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'ConnectWise ScreenConnect' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-4a7be2e7-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-42016 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-42016/ | summarize count() by src_ip, dst_host`
- **[H-4a7be2e7-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-42016 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-42016')) | summarize coverage = avg(installed) by host_role`
- **[H-4a7be2e7-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on ConnectWise ScreenConnect hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-4a7be2e7-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-4a7be2e7-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-42016, CVE-2026-42018, CVE-2026-84869; vectors: exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4a7be2e7-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-4a7be2e7-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-4a7be2e7-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-4a7be2e7-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-4a7be2e7-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-4a7be2e7-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-42016, CVE-2026-42018, CVE-2026-84869; vectors: exploit; products: ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4a7be2e7-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-4a7be2e7-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-4a7be2e7-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-4a7be2e7-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 25. Schneider Electric Modicon M340 Controller and Communication Modules

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-04>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 62
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 3 IOC(s)=+8

> View CSAF Summary Schneider Electric is aware of a vulnerability in its Modicon M340 https://www.se.com/ww/en/product-range/1468-modicon-m340-pac/ , BMXNOR0200H https://www.se.com/us/en/product/BMXNOR0200H/communication-module-modicon-m340-iec-608705101-104-dnp3-for-severe-environments/ : Modicon M340 X80 Ethernet Communication Modules, BMXNGD0100 https://www.se.com/us/en/product/BMXNGD0100/communication-module-modicon-m580-global-data-service/ : M580 Global Data module, BMXNOC0401 https://www.se.com/us/en/product/BMXNOC0401/network-module-modicon-m340-ethernet-ip-and-modbus-tcp-4-x-rj45/?pageType=product&sourceId=BMXNOC0401 : Modicon M340 X80 Ethernet Communication modules, BMXNOE0100 https://www.se.com/ww/en/product/BMXNOE0100/network-module-modicon-m340-modbus-tcp-1-x-rj45-flash-memory-card/?pageType=product&sourceId=BMXNOE0100 : Modbus/TCP Ethernet Modicon M340 module, BMXNOE0110 https://www.se.com/ww/en/product/BMXNOE0110/ethernet-tcp-ip-network-module-modicon-m340-automation-platform-flash-memory-card-internal-ram-16-mb-1-x-rj45-10-100/ : Modbus/TCP Ethernet Modicon M340 FactoryCast module product(s). Failure to apply the fix provided below may risk Denial Of Service attack, which could result in the unavailability of the devices. The following versions of Schneider Electric Modicon M340 Controller and Communication Modules are affected: Schneider Electric Ethernet/Serial RTU Module: vers:generic/ Schneider Electric M580 Global Data module: vers:all/* Schneider Electric

**Extracted signals**
- CVEs: CVE-2025-6625
- Vectors: phishing, exploit, vpn-edge
- Actions: ddos
- Sectors: energy, manufacturing
- Domain IOCs: www.se.com, overview.jsp, www.cisa.gov

### Hypotheses (3)

#### H-427b265f-1 · Initial access via CVE-2025-6625 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-6625 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-6625; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-427b265f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2025-6625.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-427b265f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-6625 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-6625/ | summarize count() by src_ip, dst_host`
- **[H-427b265f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-6625 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-6625')) | summarize coverage = avg(installed) by host_role`
- **[H-427b265f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-427b265f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-427b265f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-6625; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-427b265f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.se.com','overview.jsp','www.cisa.gov') | summarize count() by client_ip`
- **[H-427b265f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-427b265f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-427b265f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-427b265f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-427b265f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-6625; vectors: phishing, exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-427b265f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-427b265f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-427b265f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-427b265f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 26. Siemens Reyrolle 7SR5

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-05>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 62
- **Score rationale**: source weight (advisory)=+15, 14 CVE(s)=+30, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary Siemens Reyrolle 7SR5 Before V2.70 is affected by multiple vulnerabilities. Siemens has released a new version for Reyrolle 7SR5 and recommends to update to the latest version. The following versions of Siemens Reyrolle 7SR5 are affected: Reyrolle 7SR5 vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 9.8 Siemens Siemens Reyrolle 7SR5 Integer Overflow or Wraparound, Improper Neutralization of Delimiters, Use of Out-of-range Pointer Offset, Missing Authentication for Critical Function, Insufficient Entropy, Improper Input Validation, Out-of-bounds Write, Allocation of Resources Without Limits or Throttling, Authentication Bypass Using an Alternate Path or Channel, Insertion of Sensitive Information Into Debugging Code, Download of Code Without Integrity Check Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2024-42384 Integer Overflow or Wraparound vulnerability in Cesanta Mongoose Web Server v7.14 allows an attacker to send an unexpected TLS packet and produce a segmentation fault on the application. View CVE Details Affected Products Siemens Reyrolle 7SR5 Vendor: Siemens Product Version: Reyrolle 7SR5 Product Status: known_affected Remediations Vendor fix Update to V2.70 or later version https://support.industry.siemens.com/cs/ww/en/view/109772413/ Relevant CWE: CWE-190 Integer Overflow or Wraparound Metrics CVSS Version Base Score Base Severity

**Extracted signals**
- CVEs: CVE-2024-42384, CVE-2024-42385, CVE-2024-42386, CVE-2024-42391, CVE-2024-42392, CVE-2026-62645, CVE-2026-62646, CVE-2026-62647, CVE-2026-62648, CVE-2026-62649, CVE-2026-62650, CVE-2026-62652, CVE-2026-62653, CVE-2026-62654
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: support.industry.siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-5ad98e3d-1 · Initial access via CVE-2024-42384 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2024-42384 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2024-42384, CVE-2024-42385, CVE-2024-42386; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5ad98e3d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2024-42384.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5ad98e3d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2024-42384 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2024-42384/ | summarize count() by src_ip, dst_host`
- **[H-5ad98e3d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2024-42384 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2024-42384')) | summarize coverage = avg(installed) by host_role`
- **[H-5ad98e3d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5ad98e3d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5ad98e3d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2024-42384, CVE-2024-42385, CVE-2024-42386; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5ad98e3d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.industry.siemens.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-5ad98e3d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5ad98e3d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5ad98e3d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5ad98e3d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5ad98e3d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2024-42384, CVE-2024-42385, CVE-2024-42386; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5ad98e3d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-5ad98e3d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-5ad98e3d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-5ad98e3d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 27. Schneider Electric NetBotz 5 750/755

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-05>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 61
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 3 initial-access vector(s)=+11, 4 IOC(s)=+10

> View CSAF Summary Schneider Electric is aware of multiple vulnerabilities in its NetBotz 5 – 750/755 products.The NetBotz 5 – 750/755 products are security and environmental monitors providing temperature, humidity, leak, smoke, vibration, door contact, and video monitoring capabilities. Failure to apply the remediation provided below may risk arbitrary or remote code execution over the local network, which could result in device manipulation and unauthorized data access. The following versions of Schneider Electric NetBotz 5 750/755 are affected: NetBotz 5 750 vers:intdot/ NetBotz 5 755 vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 6.4 Schneider Electric Schneider Electric NetBotz 5 750/755 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'), SQL Injection: Hibernate Background Critical Infrastructure Sectors: Commercial Facilities, Critical Manufacturing, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: France Vulnerabilities Expand All + CVE-2026-13336 CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability exists that could cause execution of Linux Operating system commands when a system back up is restored that has been maliciously modified. View CVE Details Affected Products Schneider Electric NetBotz 5 750/755 Vendor: Schneider Electric Product Version: NetBotz 5 750 versions 5.5.2 and prior, NetBotz 5 755 Versions 5.5.2 and p

**Extracted signals**
- CVEs: CVE-2026-13336, CVE-2026-13337
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: products.the, www.se.com, overview.jsp, www.cisa.gov

### Hypotheses (3)

#### H-7bd80f2a-1 · Initial access via CVE-2026-13336 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-13336 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-13336, CVE-2026-13337; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7bd80f2a-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-13336.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7bd80f2a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-13336 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-13336/ | summarize count() by src_ip, dst_host`
- **[H-7bd80f2a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-13336 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-13336')) | summarize coverage = avg(installed) by host_role`
- **[H-7bd80f2a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7bd80f2a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7bd80f2a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-13336, CVE-2026-13337; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7bd80f2a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('products.the','www.se.com','overview.jsp') | summarize count() by client_ip`
- **[H-7bd80f2a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7bd80f2a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7bd80f2a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7bd80f2a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7bd80f2a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-13336, CVE-2026-13337; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7bd80f2a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7bd80f2a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7bd80f2a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7bd80f2a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 28. OpenPLC Runtime v3

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-09>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to hijack session cookies and issue state-changing requests as an operator which would allow the attacker to control the programmable logic controller and the physical processes it drives. The following versions of OpenPLC Runtime v3 are affected: OpenPLC 3 (CVE-2026-88020) CVSS Vendor Equipment Vulnerabilities v3 6.1 Autonomy Logic OpenPLC Runtime v3 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Transportation Systems, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-88020 The affected product is susceptible to an improper neutralization of input during web page generation vulnerability when the web interface attempts to route the program based on a query string parameter with no encoding. View CVE Details Affected Products OpenPLC Runtime v3 Vendor: Autonomy Logic Product Version: Autonomy Logic OpenPLC: 3 Product Status: known_affected Remediations Vendor fix Autonomy Logic recommends users upgrade to OpenPLC v4 as OpenPLC v3 is end-of-life and is no longer receiving patches, bug fixes, or security updates. Relevant CWE: CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Metrics CVSS Version Base Score Base Severity Vector String 3.1 6.

**Extracted signals**
- CVEs: CVE-2026-88020
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-f2491713-1 · Initial access via CVE-2026-88020 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-88020 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-88020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f2491713-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-88020.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-f2491713-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-88020 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-88020/ | summarize count() by src_ip, dst_host`
- **[H-f2491713-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-88020 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-88020')) | summarize coverage = avg(installed) by host_role`
- **[H-f2491713-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-f2491713-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-f2491713-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-88020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f2491713-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-f2491713-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-f2491713-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-f2491713-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-f2491713-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-f2491713-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-88020; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f2491713-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-f2491713-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-f2491713-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-f2491713-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 29. Siemens WTV676 and WTV776

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-08>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 3 IOC(s)=+8

> View CSAF Summary The products listed below contain a denial of service vulnerability that could allow an attacker to force the devices into protection mode under certain conditions. This disables remote connectivity functions (Web Access) to the devices. Siemens has released new versions for the affected products and recommends to update to the latest versions. The following versions of Siemens WTV676 and WTV776 are affected: WTV676-HB6035 Web Interface vers:intdot/ WTV776-HB6035 Web Interface vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 6.5 Siemens Siemens WTV676 and WTV776 Improper Validation of Specified Type of Input Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-89207 Affected devices do not properly validate input received from backend services. This could allow an unauthenticated remote attacker to force the device into protection mode, which results in losing remote connectivity functions (Web Access). View CVE Details Affected Products Siemens WTV676 and WTV776 Vendor: Siemens Product Version: WTV676-HB6035 Web Interface Product Status: known_affected Remediations Vendor fix Update to V3.94 or later version https://support.industry.siemens.com/cs/ww/en/view/109480838/ Vendor fix Update to V4.17 or later version https://support.industry.siemens.com/cs/ww/en/view/109480838/ Mitigation For more information see the associated Siemens security adv

**Extracted signals**
- CVEs: CVE-2026-89207
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: energy, manufacturing
- Domain IOCs: support.industry.siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-a855684b-1 · Initial access via CVE-2026-89207 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-89207 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-89207; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a855684b-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-89207.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a855684b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-89207 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-89207/ | summarize count() by src_ip, dst_host`
- **[H-a855684b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-89207 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-89207')) | summarize coverage = avg(installed) by host_role`
- **[H-a855684b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a855684b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a855684b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-89207; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a855684b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.industry.siemens.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-a855684b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a855684b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a855684b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a855684b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a855684b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-89207; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a855684b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-a855684b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-a855684b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-a855684b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 30. CISA Adds Four Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/09/09/cisa-adds-four-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 09 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-09T20:42:59+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 2 initial-access vector(s)=+9, 2 product mention(s)=+6

> CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2025-25249 Fortinet Multiple Products Heap-based Buffer Overflow Vulnerability CVE-2026-19490 Citrix NetScaler Authentication Bypass Using an Alternate Path or Channel Vulnerability CVE-2026-87491 Google Chromium V8 Out of Bounds Write Vulnerability CVE-2026-20079 Cisco Firewall Management Center Authentication Bypass Using an Alternate Path or Channel Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerabili

**Extracted signals**
- CVEs: CVE-2025-25249, CVE-2026-19490, CVE-2026-87491, CVE-2026-20079
- Products: Fortinet FortiOS, Citrix NetScaler
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-1625123f-1 · Initial access via CVE-2025-25249 affecting Fortinet FortiOS  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-25249 in Fortinet FortiOS within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-25249, CVE-2026-19490, CVE-2026-87491; vectors: exploit, vpn-edge; products: Fortinet FortiOS, Citrix NetScaler.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1625123f-1-O1] Inventory exposure to Fortinet FortiOS** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Fortinet FortiOS, the external-exploitation hypothesis is disproven for CVE-2025-25249.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Fortinet FortiOS' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-1625123f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-25249 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-25249/ | summarize count() by src_ip, dst_host`
- **[H-1625123f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-25249 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-25249')) | summarize coverage = avg(installed) by host_role`
- **[H-1625123f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Fortinet FortiOS hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-1625123f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-1625123f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-25249, CVE-2026-19490, CVE-2026-87491; vectors: exploit, vpn-edge; products: Fortinet FortiOS, Citrix NetScaler.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1625123f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-1625123f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-1625123f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-1625123f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-1625123f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-1625123f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-25249, CVE-2026-19490, CVE-2026-87491; vectors: exploit, vpn-edge; products: Fortinet FortiOS, Citrix NetScaler.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1625123f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-1625123f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-1625123f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-1625123f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 31. Siemens Desigo CC family

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-05>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 58
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 2 IOC(s)=+6

> View CSAF Summary A Client Code Execution (CCE) vulnerability has been identified in Desigo CC, potentially allowing malicious actors to execute arbitrary code on client devices through specially crafted graphics documents. This vulnerability leverages user-defined graphics containing embedded scripts that are executed on client application instances. Successful exploitation could lead to compromise of the client operating system and potential lateral movement within the organization. The following versions of Siemens Desigo CC family are affected: Desigo CC family V6 vers:all/* (CVE-2026-34223) Desigo CC family V7 vers:all/* (CVE-2026-34223) CVSS Vendor Equipment Vulnerabilities v3 8.2 Siemens Siemens Desigo CC family Improper Control of Generation of Code ('Code Injection') Background Critical Infrastructure Sectors: Critical Manufacturing, Commercial Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-34223 The affected application is vulnerable to Client Code Execution (CCE) due to insufficient input validation when handling scripts embedded within user-defined graphics documents. Specifically, when the script within a graphics document is designed or modified by an attacker to include malicious commands. When a user opens a compromised graphics document, the embedded script is executed on the client application instance, allowing an attacker to write arbitrary files to the client's operating system. 

**Extracted signals**
- CVEs: CVE-2026-34223
- Vectors: exploit, vpn-edge
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1219
- Domain IOCs: www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-51651d7f-1 · Initial access via CVE-2026-34223 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-34223 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-34223; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-51651d7f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-34223.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-51651d7f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-34223 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-34223/ | summarize count() by src_ip, dst_host`
- **[H-51651d7f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-34223 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-34223')) | summarize coverage = avg(installed) by host_role`
- **[H-51651d7f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-51651d7f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-51651d7f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-34223; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-51651d7f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-51651d7f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-51651d7f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-51651d7f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-51651d7f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-51651d7f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-34223; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-51651d7f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-51651d7f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-51651d7f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-51651d7f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 32. Should you care about an “AI slowdown?”

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/should-you-care-about-an-ai-slowdown/>
- **Published**: Thu, 17 Sep 2026 18:00:23 GMT
- **First seen**: 2026-09-17T18:33:41+00:00
- **Relevance score**: 58
- **Score rationale**: source weight (vendor)=+10, 2 MITRE technique hit(s)=+11, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 19 IOC(s)=+15

> In this week's Threat Source, David talks about why focusing on your security basics is still your best bet, even in a world with rapid AI advancements.

**Extracted signals**
- Vectors: phishing, exploit, vpn-edge
- Actions: ransomware, data-breach
- Sectors: finance, manufacturing
- MITRE ATT&CK: T1486, T1219
- Domain IOCs: vid001.exe, w32.9f1f11a708-100.sbx.tg, w32.c4dd71e347-95.sbx.tg, secoh-qad.exe, win.tool.procpatcher, content.js, w32.38d053135d-95.sbx.tg, aact.exe, w32.fed979f93b-95.sbx.tg
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, c4dd71e347a076ba24bdd2d0ee532ef991c1ef25a2431a19f850942ba2ab16b2, 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f, 38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55, fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, 9a47c4d379998ade2f8f99e23a630c06, 38de5b216c33833af710e88f7f64fc98, 41444d7018601b599beac0c60ed1bf83, 207d9d891ac756b2bfad88aba5682c65

### Hypotheses (4)

#### H-a42ae1e1-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a42ae1e1-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a42ae1e1-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-a42ae1e1-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-a42ae1e1-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a42ae1e1-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a42ae1e1-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a42ae1e1-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('vid001.exe','w32.9f1f11a708-100.sbx.tg','w32.c4dd71e347-95.sbx.tg') | summarize count() by client_ip`
- **[H-a42ae1e1-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a42ae1e1-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a42ae1e1-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a42ae1e1-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a42ae1e1-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a42ae1e1-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-a42ae1e1-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-a42ae1e1-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-a42ae1e1-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-a42ae1e1-4 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a42ae1e1-4-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-a42ae1e1-4-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-a42ae1e1-4-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-a42ae1e1-4-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 33. Siemens SIMOVE Fleetmanager and SIPLANT

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-07>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 5 IOC(s)=+12

> View CSAF Summary SIMOVE Fleetmanager and SIPLANT contain a path traversal vulnerability that could allow an attacker to access files outside of intended scope. Siemens has released new versions for the affected products and recommends to update to the latest versions. The following versions of Siemens SIMOVE Fleetmanager and SIPLANT are affected: SIMOVE Fleetmanager V3.1 vers:intdot/ SIMOVE Fleetmanager V3.2 vers:intdot/ SIMOVE Fleetmanager V3.3 vers:intdot/ SIMOVE Fleetmanager V4.0 vers:intdot/ SIPLANT V1.7 vers:all/* (CVE-2026-67367) SIPLANT V2.2 vers:all/* (CVE-2026-67367) SIPLANT V3.0 vers:all/* (CVE-2026-67367) SIPLANT V3.1 vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 8.6 Siemens Siemens SIMOVE Fleetmanager and SIPLANT Relative Path Traversal Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-67367 Affected devices do not properly validate and neutralize directory traversal sequences in the file-serving endpoint of the embedded HTTP server. This could allow an unauthenticated remote attacker to read arbitrary files from the underlying operating system without any credentials, potentially exposing sensitive data such as credential stores, private keys, and configuration secrets. View CVE Details Affected Products Siemens SIMOVE Fleetmanager and SIPLANT Vendor: Siemens Product Version: SIMOVE Fleetmanager V3.1 Product Status: known_affe

**Extracted signals**
- CVEs: CVE-2026-67367
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: support.industry.siemens.com, siplant-support.de, siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-e3beab50-1 · Initial access via CVE-2026-67367 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-67367 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-67367; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e3beab50-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-67367.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-e3beab50-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-67367 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-67367/ | summarize count() by src_ip, dst_host`
- **[H-e3beab50-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-67367 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-67367')) | summarize coverage = avg(installed) by host_role`
- **[H-e3beab50-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-e3beab50-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-e3beab50-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-67367; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e3beab50-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.industry.siemens.com','siplant-support.de','siemens.com') | summarize count() by client_ip`
- **[H-e3beab50-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-e3beab50-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-e3beab50-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-e3beab50-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-e3beab50-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-67367; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e3beab50-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-e3beab50-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-e3beab50-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-e3beab50-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 34. Redtail Payload Analysis [Guest Diary], (Wed, Sep 9th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33326>
- **Published**: Thu, 10 Sep 2026 12:58:10 GMT
- **First seen**: 2026-09-10T13:06:03+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (advisory)=+15, 2 MITRE technique hit(s)=+11, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 23 IOC(s)=+15

> [This is a Guest Diary by Aaron Ng, an ISC intern as part of the SANS.edu BACS program]

**Extracted signals**
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1053, T1497
- IP IOCs: 10.66.66.10, 10.66.66.2, 8.8.8.8, 1.1.1.1, 1.0.0.1, 8.8.4.4, 9.9.9.9, 9.9.9.10, 80.152.203.134, 109.91.184.21
- Domain IOCs: sans.edu, event.code, setup.sh, clean.sh, vm610-baseline-pre-redtail.elf, vm610-post-redtail.elf, mail3.kekew.info, ip-109-091-184-021.um37.pools.vodafone-ip.de, www.inetsim.org, index.html, www.sans.edu, isc.sans.edu
- SHA256: 63be5f38b520b3143732962a5f8fec1f9abd1f483dbc741ed324e58f955dd35e

### Hypotheses (3)

#### H-6d75e11a-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6d75e11a-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6d75e11a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-6d75e11a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-6d75e11a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6d75e11a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6d75e11a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6d75e11a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sans.edu','event.code','setup.sh') | summarize count() by client_ip`
- **[H-6d75e11a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('10.66.66.10','10.66.66.2','8.8.8.8') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6d75e11a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6d75e11a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6d75e11a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6d75e11a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6d75e11a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6d75e11a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6d75e11a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6d75e11a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 35. Siemens SIPLUS and SIMATIC Products

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-04>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 3 IOC(s)=+8

> View CSAF Summary Multiple Siemens products are vulnerable to the "Copy Fail" vulnerability. Siemens has released new versions for several affected products and recommends to update to the latest versions. Siemens is preparing further fix versions and recommends specific countermeasures for products where fixes are not, or not yet available. The following versions of Siemens SIPLUS and SIMATIC Products are affected: SIMATIC AX Runtime Core Linux Common Debian vers:all/* (CVE-2026-31431) SIMATIC AX Runtime Core Linux Common Debian arm64 vers:all/* (CVE-2026-31431) SIMATIC AX Runtime Core Linux Platform Container Common Debian Development vers:all/* (CVE-2026-31431) SIMATIC AX Runtime Core Linux VMWare Development vers:all/* (CVE-2026-31431) SIMATIC CN 4100 vers:intdot/ SIMATIC HMI MTP1000 Unified Basic (6AV2123-3KB32-0AW0) vers:intdot/ SIMATIC HMI MTP1000 Unified Comfort Panel (6AV2128-3KB06-0AX1) vers:intdot/ SIMATIC HMI MTP1000 Unified Comfort Panel hygienic (6AV2128-3KB40-0AX0) vers:intdot/ SIMATIC HMI MTP1000 Unified Comfort Panel hygienic neutral design (6AV2128-3KB70-0AX0) vers:intdot/ SIMATIC HMI MTP1000, Unified Comfort Panel neutral (6AV2128-3KB36-0AX1) vers:intdot/ SIMATIC HMI MTP1200 Comfort Pro for stand (expandable, flange at the bottom) (6AV2128-3MB27-1BX0) vers:intdot/ SIMATIC HMI MTP1200 Comfort Pro for support arm (expandable, round tube) and extension unit (6AV2128-3MB27-0BX0) vers:intdot/ SIMATIC HMI MTP1200 Comfort Pro for support arm (not extendable, flang

**Extracted signals**
- CVEs: CVE-2026-31431
- Products: Linux kernel
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: support.industry.siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-300f7164-1 · Initial access via CVE-2026-31431 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-31431 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-300f7164-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2026-31431.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-300f7164-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-31431 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-31431/ | summarize count() by src_ip, dst_host`
- **[H-300f7164-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-31431 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-31431')) | summarize coverage = avg(installed) by host_role`
- **[H-300f7164-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-300f7164-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-300f7164-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-300f7164-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.industry.siemens.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-300f7164-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-300f7164-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-300f7164-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-300f7164-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-300f7164-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-31431; vectors: exploit, vpn-edge; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-300f7164-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-300f7164-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-300f7164-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-300f7164-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 36. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/09/16/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 16 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-16T20:23:39+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-76460 Cisco Identity Services Engine Incorrect Use of Privileged APIs Vulnerability CVE-2026-87886 Acronis Backup Incorrect Default Permissions Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not c

**Extracted signals**
- CVEs: CVE-2026-76460, CVE-2026-87886
- Vectors: exploit
- Sectors: government, manufacturing
- MITRE ATT&CK: T1053

### Hypotheses (3)

#### H-7856a437-1 · Initial access via CVE-2026-76460 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-76460 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-76460, CVE-2026-87886; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7856a437-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-76460.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7856a437-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-76460 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-76460/ | summarize count() by src_ip, dst_host`
- **[H-7856a437-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-76460 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-76460')) | summarize coverage = avg(installed) by host_role`
- **[H-7856a437-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7856a437-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7856a437-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-76460, CVE-2026-87886; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7856a437-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-7856a437-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7856a437-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7856a437-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7856a437-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7856a437-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-76460, CVE-2026-87886; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7856a437-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7856a437-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7856a437-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7856a437-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 37. CVE-2026-76461: Critical Cisco Secure Email Gateway Vulnerability Exploited in the Wild

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild>
- **Published**: Tue, 15 Sep 2026 12:22:50 GMT
- **First seen**: 2026-09-15T13:13:04+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 impact action(s)=+8

> Overview On September 14, 2026, Cisco published a security advisory for CVE-2026-76461 , a critical SQL injection vulnerability affecting Cisco AsyncOS Software for Cisco Secure Email Gateway. The vulnerability has a reported CVSS v3.1 base score of 9.8 and could allow an unauthenticated, remote attacker to execute arbitrary commands with root privileges on an affected appliance. Cisco Secure Email Gateway, formerly known as IronPort Email Security Appliance, is an enterprise email security product that inspects inbound and outbound email for threats including phishing, malware, spam, and business email compromise. Because affected gateways process externally delivered email as part of their normal operation, exploitation does not require access to an administrative interface or authentication. An attacker can reportedly trigger the vulnerability by sending a specially crafted email through a vulnerable gateway. CVE-2026-76461 was added to CISA's Known Exploited Vulnerabilities ( KEV ) catalog on the same day as the vendor disclosed the vulnerability, indicating that CVE-2026-76461 was exploited as a zero-day prior to disclosure. Cisco noted that their PSIRT became aware of active exploitation in September 2026. At the time of publication, there is no public proof-of-concept exploit code available, and no attribution for the current threat actor activity. Mitigation guidance Organizations running Cisco Secure Email Gateway should prioritize upgrading to a vendor-supplied fixe

**Extracted signals**
- CVEs: CVE-2026-76461
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-53ebfbb6-1 · Initial access via CVE-2026-76461 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-76461 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-76461; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53ebfbb6-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-76461.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-53ebfbb6-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-76461 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-76461/ | summarize count() by src_ip, dst_host`
- **[H-53ebfbb6-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-76461 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-76461')) | summarize coverage = avg(installed) by host_role`
- **[H-53ebfbb6-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-53ebfbb6-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-53ebfbb6-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-76461; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53ebfbb6-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-53ebfbb6-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-53ebfbb6-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-53ebfbb6-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-53ebfbb6-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-53ebfbb6-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-76461; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-53ebfbb6-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-53ebfbb6-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-53ebfbb6-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-53ebfbb6-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 38. Protecting organizations from AI-assisted executive impersonation and invoice fraud

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/>
- **Published**: Thu, 10 Sep 2026 17:23:05 +0000
- **First seen**: 2026-09-10T18:48:39+00:00
- **Relevance score**: 55
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 11 IOC(s)=+15

> Microsoft examines an AI-assisted business email compromise campaign that used executive impersonation and fake invoices to target finance teams with ACH payment fraud. The post Protecting organizations from AI-assisted executive impersonation and invoice fraud appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, social-engineering
- Actions: fraud
- Sectors: finance, manufacturing, telecom
- MITRE ATT&CK: T1566
- Domain IOCs: service-nowinc.com, domainlify.net, uinsure.co.uk, tivityhealth.com, lumalisboa.com, mctci.com, nuf.co.jp, lohnsteuerhilfe-aktuell-verein.de, tovimbatista.pt, eemusicclass.co.uk, lifeones.com

### Hypotheses (3)

#### H-6c186677-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, social-engineering; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6c186677-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-6c186677-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-6c186677-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-6c186677-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-6c186677-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-6c186677-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, social-engineering; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-6c186677-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('service-nowinc.com','domainlify.net','uinsure.co.uk') | summarize count() by client_ip`
- **[H-6c186677-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-6c186677-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-6c186677-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-6c186677-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-6c186677-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, social-engineering; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6c186677-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-6c186677-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-6c186677-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-6c186677-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 39. Schneider Electric PowerChute Serial Shutdown

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 54
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 3 IOC(s)=+8

> View CSAF Summary Schneider Electric is aware of vulnerabilities in its PowerChute Serial Shutdown product. The PowerChute Serial Shutdown product is a UPS management software enabling graceful system shutdown and energy management capabilities for desktops, servers and workstations. Failure to apply the remediation provided below may risk improper authentication validation which could result in disruption of operations and access to system data. The following versions of Schneider Electric PowerChute Serial Shutdown are affected: PowerChute Serial Shutdown vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 5.3 Schneider Electric Schneider Electric PowerChute Serial Shutdown Improper Restriction of Excessive Authentication Attempts Background Critical Infrastructure Sectors: Commercial Facilities, Critical Manufacturing, Energy, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: France Vulnerabilities Expand All + CVE-2026-13348 CWE-307: Improper Restriction of Excessive Authentication Attempts vulnerability exists that could allow an attacker to gain unauthorized access to a user account by performing an arbitrary number of authentication attempts when redirect handling is disabled. View CVE Details Affected Products Schneider Electric PowerChute Serial Shutdown Vendor: Schneider Electric Product Version: PowerChute Serial Shutdown Version 1.5 and prior Product Status: fixed, known_affected Remediations Vendor fix Version v1.6 of Pow

**Extracted signals**
- CVEs: CVE-2026-13348
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.se.com, overview.jsp, www.cisa.gov

### Hypotheses (3)

#### H-d9251638-1 · Initial access via CVE-2026-13348 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-13348 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-13348; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d9251638-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-13348.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d9251638-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-13348 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-13348/ | summarize count() by src_ip, dst_host`
- **[H-d9251638-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-13348 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-13348')) | summarize coverage = avg(installed) by host_role`
- **[H-d9251638-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d9251638-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d9251638-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-13348; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d9251638-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.se.com','overview.jsp','www.cisa.gov') | summarize count() by client_ip`
- **[H-d9251638-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d9251638-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d9251638-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d9251638-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d9251638-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-13348; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d9251638-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d9251638-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d9251638-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d9251638-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 40. Schneider Electric SCADAPack x70 Products

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-04>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 54
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 3 IOC(s)=+8

> View CSAF Summary Schneider Electric is aware of a vulnerability in its SCADAPack x70 products. The SCADAPack 47x, SCADAPack 47xi, SCADAPack 47xd, SCADAPack 470R and SCADAPack 57x products are Remote Terminal Units that provide communication capabilities for remote monitoring and control. Failure to apply the mitigations provided below may increase the risk of unauthorized access to RTU configuration through the Secure Lock functionality, potentially resulting in a loss of confidentiality. The following versions of Schneider Electric SCADAPack x70 Products are affected: SCADAPack 47x vers:all/* (CVE-2026-81861) SCADAPack 47xi vers:all/* (CVE-2026-81861) SCADAPack 47xd vers:all/* (CVE-2026-81861) SCADAPack 470R vers:all/* (CVE-2026-81861) SCADAPack 57x vers:all/* (CVE-2026-81861) SCADAPack 3xx vers:all/* (CVE-2026-81861) SCADAPack 32 vers:all/* (CVE-2026-81861) CVSS Vendor Equipment Vulnerabilities v3 6.5 Schneider Electric Schneider Electric SCADAPack x70 Products Insufficiently Protected Credentials Background Critical Infrastructure Sectors: Critical Manufacturing, Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: France Vulnerabilities Expand All + CVE-2026-81861 There is an insufficiently protected credentials vulnerability that could result in exposure of authentication information and unauthorized access to RTU functionality. View CVE Details Affected Products Schneider Electric SCADAPack x70 Products Vendor: Schneider Electric Product Version: S

**Extracted signals**
- CVEs: CVE-2026-81861
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.se.com, overview.js, www.cisa.gov

### Hypotheses (3)

#### H-7e3577ae-1 · Initial access via CVE-2026-81861 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-81861 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-81861; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7e3577ae-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-81861.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7e3577ae-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-81861 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-81861/ | summarize count() by src_ip, dst_host`
- **[H-7e3577ae-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-81861 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-81861')) | summarize coverage = avg(installed) by host_role`
- **[H-7e3577ae-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7e3577ae-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7e3577ae-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-81861; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7e3577ae-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.se.com','overview.js','www.cisa.gov') | summarize count() by client_ip`
- **[H-7e3577ae-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7e3577ae-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7e3577ae-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7e3577ae-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7e3577ae-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-81861; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7e3577ae-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7e3577ae-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7e3577ae-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7e3577ae-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 41. CVE-2026-94127: Critical Unauthenticated RCE in F5 BIG-IP APM

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm>
- **Published**: Wed, 23 Sep 2026 08:43:39 GMT
- **First seen**: 2026-09-23T09:43:44+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 3 IOC(s)=+8

> Overview On September 22, 2026, F5 published a security advisory for CVE-2026-94127 , a critical heap-based buffer overflow vulnerability affecting F5 BIG-IP Access Policy Manager (APM). The vulnerability has a CVSS v3.1 score of 9.8. An unauthenticated attacker with network access to an affected virtual server may be able to achieve remote code execution (RCE) by sending specifically crafted traffic. BIG-IP APM provides identity-aware access control for applications and other corporate resources and can integrate with authentication technologies including OAuth, OpenID Connect, and SAML. CVE-2026-94127 is not exposed in a default configuration: exploitation requires a BIG-IP virtual server with both an APM access policy and an OAuth profile configured. Because affected BIG-IP systems may process traffic at an organization's network edge, organizations using this configuration should prioritize remediation. The vulnerability affects the data plane and does not expose the BIG-IP control plane. BIG-IP systems operating in Appliance mode are also affected. F5 lists the following affected release trains and corresponding fixed hotfixes: BIG-IP 21.1.0: versions prior to Hotfix-BIGIP-21.1.0.2.0.30.22-ENG BIG-IP 17.5.0: versions prior to Hotfix-BIGIP-17.5.1.9.0.160.12-ENG BIG-IP 17.1.0: versions prior to Hotfix-BIGIP-17.1.3.5.0.41.14-ENG As of September 22, 2026, CVE-2026-94127 has been added to the CISA KEV while a publicly available proof of concept was not confirmed. Mitigation g

**Extracted signals**
- CVEs: CVE-2026-94127
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- IP IOCs: 21.1.0.2, 17.5.1.9, 17.1.3.5

### Hypotheses (3)

#### H-1cb3f33d-1 · Initial access via CVE-2026-94127 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-94127 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-94127; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1cb3f33d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-94127.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-1cb3f33d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-94127 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-94127/ | summarize count() by src_ip, dst_host`
- **[H-1cb3f33d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-94127 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-94127')) | summarize coverage = avg(installed) by host_role`
- **[H-1cb3f33d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-1cb3f33d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-1cb3f33d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-94127; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1cb3f33d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-1cb3f33d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('21.1.0.2','17.5.1.9','17.1.3.5') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-1cb3f33d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-1cb3f33d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-1cb3f33d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-1cb3f33d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-94127; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1cb3f33d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-1cb3f33d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-1cb3f33d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-1cb3f33d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 42. The Fraud Ecosystem: A Transition From Known Marketplaces to a Fragmented Environment

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/tr-fraud-ecosystem-fragmenting-marketplaces>
- **Published**: Fri, 11 Sep 2026 13:33:33 GMT
- **First seen**: 2026-09-11T15:06:22+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (vendor)=+10, 4 MITRE technique hit(s)=+17, 6 initial-access vector(s)=+15, 1 impact action(s)=+8, 1 product mention(s)=+3

> Introduction The surge in emerging threat actors directly correlates with the rapid escalation of victim counts and stolen financial resources. Simultaneously, this growth has spurred the proliferation of specialized supply storefronts across social media platforms, dark web channels, and various smaller niche marketplaces. Security teams today face evolving challenges, requiring them to continuously refine monitoring channels, adjust operational strategies, and foster cross-functional internal collaboration to capture actionable intelligence. With fraud damages anticipated to approach hundreds of billions of USD , security teams must navigate numerous non-compliant channels while ingesting and processing diverse data formats—such as documents, imagery, video, and unformatted text—linked to organizational assets. The recent introduction of a new Fraud framework by the MITRE organization underscores the critical need to combat fraud and highlights the significant danger these threat actors pose to all organizations. The MITRE organization has been taking a positive step towards standardizing the fight against fraud, while helping organizations target the relevant directions to look at. These marketplaces supply a range of services in need for the novice fraudster, encompassing server infrastructure, targeted lists, and even support for money laundering facilitated through compromised accounts across various platforms. As larger, well-known marketplaces have been dismantled, sm

**Extracted signals**
- Products: Microsoft Exchange
- Vectors: phishing, exploit, supply-chain, vpn-edge, rdp, credential-theft
- Actions: fraud
- Sectors: finance, manufacturing, telecom
- MITRE ATT&CK: T1566, T1078, T1021.001, T1505.003

### Hypotheses (3)

#### H-c07d2c4d-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c07d2c4d-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c07d2c4d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-c07d2c4d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-c07d2c4d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c07d2c4d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c07d2c4d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c07d2c4d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-c07d2c4d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c07d2c4d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c07d2c4d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c07d2c4d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c07d2c4d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, supply-chain; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c07d2c4d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c07d2c4d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c07d2c4d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c07d2c4d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 43. CISA Adds Four Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/09/22/cisa-adds-four-known-exploited-vulnerabilities-catalog>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T20:56:37+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 1 initial-access vector(s)=+7

> CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-85102 Check Point Multiple Products Improper Certificate Validation Vulnerability CVE-2026-93616 Check Point Multiple Products Path Traversal Vulnerability CVE-2026-93952 Arista VeloCloud Orchestrator Improper Input Validation Vulnerability CVE-2026-94127 F5 BIG-IP APM Heap-based Buffer Overflow Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catal

**Extracted signals**
- CVEs: CVE-2026-85102, CVE-2026-93616, CVE-2026-93952, CVE-2026-94127
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-bb6230f7-1 · Initial access via CVE-2026-85102 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-85102 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-85102, CVE-2026-93616, CVE-2026-93952; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bb6230f7-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-85102.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-bb6230f7-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-85102 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-85102/ | summarize count() by src_ip, dst_host`
- **[H-bb6230f7-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-85102 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-85102')) | summarize coverage = avg(installed) by host_role`
- **[H-bb6230f7-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-bb6230f7-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-bb6230f7-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-85102, CVE-2026-93616, CVE-2026-93952; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bb6230f7-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-bb6230f7-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bb6230f7-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bb6230f7-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bb6230f7-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bb6230f7-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-85102, CVE-2026-93616, CVE-2026-93952; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bb6230f7-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-bb6230f7-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-bb6230f7-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-bb6230f7-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 44. Siemens Industrial Edge Management

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-06>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary Industrial Edge Management contains an authentication bypass vulnerability that could allow an unauthenticated remote attacker to perform full account takeover by resetting user credentials without completing email verification. Siemens has released new versions for the affected products and recommends to update to the latest versions. The following versions of Siemens Industrial Edge Management are affected: Industrial Edge Management Cloud vers:all/* (CVE-2026-18963) Industrial Edge Management Pro V1 vers:intdot/>=1.14.9| Industrial Edge Management Pro V2 vers:intdot/>=2.2.0| Industrial Edge Management Virtual vers:intdot/>=2.6.0| CVSS Vendor Equipment Vulnerabilities v3 9.1 Siemens Siemens Industrial Edge Management Weak Password Recovery Mechanism for Forgotten Password Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-18963 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials. View CVE Details Affected Products Siemens Industrial Edge Manage

**Extracted signals**
- CVEs: CVE-2026-18963
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: iehub.eu1.edge.siemens.cloud, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-9681194f-1 · Initial access via CVE-2026-18963 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-18963 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-18963; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9681194f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-18963.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9681194f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-18963 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-18963/ | summarize count() by src_ip, dst_host`
- **[H-9681194f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-18963 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-18963')) | summarize coverage = avg(installed) by host_role`
- **[H-9681194f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9681194f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9681194f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-18963; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9681194f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('iehub.eu1.edge.siemens.cloud','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-9681194f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9681194f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9681194f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9681194f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9681194f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-18963; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9681194f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-9681194f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-9681194f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-9681194f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 45. Siemens Siveillance Control

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-03>
- **Published**: Tue, 22 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-22T16:26:11+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary A vulnerability has been identified in the Open Interface Services (OIS) web module affecting Siveillance Control and Siveillance Control Pro (versions OIS 3.x.y and OIS 4.x.y) . This vulnerability allows an attacker to upload arbitrary files, which can lead to unauthorized root-level access on the OIS server. Siemens has released patches and updates for Siveillance OIS to apply to the products that incorporate the OIS service, and recommends to update to the latest versions. The following versions of Siemens Siveillance Control are affected: Siveillance Control Pro V3.0 vers:intdot/ Siveillance Control Pro V4.0 vers:intdot/ Siveillance Control V3.0 vers:intdot/ Siveillance Control V4.0 vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 9 Siemens Siemens Siveillance Control Unrestricted Upload of File with Dangerous Type Background Critical Infrastructure Sectors: Critical Manufacturing, Communications, Commercial Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-50093 A vulnerability in the OIS web module allows an attacker to upload arbitrary files to the server. Successful exploitation of this vulnerability could allow an attacker to gain root access on the host system, potentially leading to a full compromise of the affected OIS environment. View CVE Details Affected Products Siemens Siveillance Control Vendor: Siemens Product Version: Siveillance Control Pro V3.0 Product Status

**Extracted signals**
- CVEs: CVE-2026-50093
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: support.industry.siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-c84d7f4b-1 · Initial access via CVE-2026-50093 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-50093 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-50093; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c84d7f4b-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-50093.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c84d7f4b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-50093 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-50093/ | summarize count() by src_ip, dst_host`
- **[H-c84d7f4b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-50093 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-50093')) | summarize coverage = avg(installed) by host_role`
- **[H-c84d7f4b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c84d7f4b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c84d7f4b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-50093; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c84d7f4b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.industry.siemens.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-c84d7f4b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c84d7f4b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c84d7f4b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c84d7f4b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c84d7f4b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-50093; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c84d7f4b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c84d7f4b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c84d7f4b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c84d7f4b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 46. Mitsubishi Electric GX Works3 and Motion Control Settings

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-02>
- **Published**: Thu, 17 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-17T17:17:05+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary Successful exploitation of this vulnerability could allow a local attacker to successfully authenticate even with an invalid block password by executing the affected product and modify part of the executable module in memory, and thereby allows the attacker to view, tamper with, destroy, or delete control programs. The following versions of Mitsubishi Electric GX Works3 and Motion Control Settings are affected: Mitsubishi Electric GX Works3 vers:all/* (CVE-2026-15688) Mitsubishi Electric Motion Control Settings (Software packaged with GX Works3) vers:all/* (CVE-2026-15688) CVSS Vendor Equipment Vulnerabilities v3 8.8 Mitsubishi Electric Mitsubishi Electric GX Works3 and Motion Control Settings Incorrect Implementation of Authentication Algorithm Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Japan Vulnerabilities Expand All + CVE-2026-15688 Incorrect Implementation of Authentication Algorithm (CWE-303) vulnerability in the affected products allows a local attacker to successfully authenticate even with an invalid block password by executing the affected product and modify part of the executable module in memory, and thereby allows the attacker to view, tamper with, destroy, or delete control programs. View CVE Details Affected Products Mitsubishi Electric GX Works3 and Motion Control Settings Vendor: Mitsubishi Electric Product Version: Mitsubishi Electric GX Works3: vers:

**Extracted signals**
- CVEs: CVE-2026-15688
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: www.mitsubishielectric.com, detailsearch.page, www.cisa.gov

### Hypotheses (3)

#### H-8ac2983e-1 · Initial access via CVE-2026-15688 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-15688 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-15688; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8ac2983e-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-15688.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-8ac2983e-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-15688 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-15688/ | summarize count() by src_ip, dst_host`
- **[H-8ac2983e-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-15688 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-15688')) | summarize coverage = avg(installed) by host_role`
- **[H-8ac2983e-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-8ac2983e-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-8ac2983e-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-15688; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8ac2983e-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.mitsubishielectric.com','detailsearch.page','www.cisa.gov') | summarize count() by client_ip`
- **[H-8ac2983e-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-8ac2983e-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-8ac2983e-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-8ac2983e-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-8ac2983e-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-15688; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8ac2983e-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-8ac2983e-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-8ac2983e-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-8ac2983e-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 47. Siemens Teamcenter

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-07>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary A reflected cross site scripting vulnerability in the authentication redirect flow (/auth/) of Teamcenter allows an unauthenticated remote attacker to inject JavaScript into an authenticated user's session by crafting a malicious URL. Successful exploitation may enable the attacker to read data or perform actions within the victim's Teamcenter session. Siemens has released new versions for the affected products and recommends to update to the latest versions. The following versions of Siemens Teamcenter are affected: Teamcenter V2412 vers:intdot/ Teamcenter V2506 vers:intdot/ Teamcenter V2512 vers:intdot/ Teamcenter V2606 vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 6.1 Siemens Siemens Teamcenter Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') Background Critical Infrastructure Sectors: Critical Manufacturing, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-58113 Affected applications do not properly encode user-supplied input reflected into HTML attribute contexts within the authentication redirect flow (/auth/ endpoint). This could allow an unauthenticated remote attacker to inject arbitrary JavaScript into the browser of an authenticated user who loads a crafted URL, enabling the attacker to perform actions within the victim's Teamcenter session. View CVE Details Affected Products Siemens Teamcenter Vendor: Siemens Product 

**Extracted signals**
- CVEs: CVE-2026-58113
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: support.sw.siemens.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-bb5aa620-1 · Initial access via CVE-2026-58113 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-58113 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-58113; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bb5aa620-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-58113.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-bb5aa620-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-58113 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-58113/ | summarize count() by src_ip, dst_host`
- **[H-bb5aa620-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-58113 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-58113')) | summarize coverage = avg(installed) by host_role`
- **[H-bb5aa620-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-bb5aa620-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-bb5aa620-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-58113; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-bb5aa620-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.sw.siemens.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-bb5aa620-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-bb5aa620-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-bb5aa620-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-bb5aa620-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-bb5aa620-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-58113; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-bb5aa620-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-bb5aa620-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-bb5aa620-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-bb5aa620-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 48. Siemens Mendix SAML

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-06>
- **Published**: Tue, 15 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-15T16:23:49+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 3 IOC(s)=+8

> View CSAF Summary Mendix SAML module contains a vulnerability that could allow unauthenticated remote attackers to hijack an account in specific SSO configurations. Mendix has provided fix releases for the Mendix SAML module and recommends to update to the latest version. The following versions of Siemens Mendix SAML are affected: Mendix SAML (Mendix 10 compatible) vers:intdot/ Mendix SAML (Mendix 11 compatible) vers:intdot/ Mendix SAML (Mendix 9.24 compatible) vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 8.7 Siemens Siemens Mendix SAML Improper Verification of Cryptographic Signature Background Critical Infrastructure Sectors: Critical Manufacturing, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-80465 Affected versions of the module do not properly validate the SAML response signature. This could allow unauthenticated remote attackers to hijack an account (session) in specific SSO configurations. View CVE Details Affected Products Siemens Mendix SAML Vendor: Siemens Product Version: Mendix SAML (Mendix 10 compatible) Product Status: known_affected Remediations Vendor fix Update to V3.6.27 or later version https://marketplace.mendix.com/link/component/1174 Vendor fix Update to V4.2.3 or later version https://marketplace.mendix.com/link/component/1174 Vendor fix Update to V4.2.3 or later version https://marketplace.mendix.com/link/component/1174 Relevant CWE: CWE-347 Improper Ver

**Extracted signals**
- CVEs: CVE-2026-80465
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: marketplace.mendix.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-390bf247-1 · Initial access via CVE-2026-80465 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-80465 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-80465; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-390bf247-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-80465.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-390bf247-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-80465 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-80465/ | summarize count() by src_ip, dst_host`
- **[H-390bf247-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-80465 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-80465')) | summarize coverage = avg(installed) by host_role`
- **[H-390bf247-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-390bf247-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-390bf247-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-80465; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-390bf247-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('marketplace.mendix.com','www.siemens.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-390bf247-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-390bf247-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-390bf247-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-390bf247-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-390bf247-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-80465; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-390bf247-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-390bf247-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-390bf247-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-390bf247-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 49. Detect and disrupt AI-themed attacks with Microsoft Defender

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/>
- **Published**: Thu, 10 Sep 2026 16:00:00 +0000
- **First seen**: 2026-09-10T18:10:51+00:00
- **Relevance score**: 51
- **Score rationale**: source weight (vendor)=+10, 3 MITRE technique hit(s)=+14, 4 initial-access vector(s)=+13, 2 impact action(s)=+11, 1 product mention(s)=+3

> See how Microsoft Defender detects and disrupts AI-themed phishing, malware, and multi-stage attacks across the attack chain. The post Detect and disrupt AI-themed attacks with Microsoft Defender appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, credential-theft, social-engineering
- Actions: ransomware, fraud
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1566, T1486, T1219

### Hypotheses (4)

#### H-d2a9951a-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, credential-theft; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d2a9951a-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d2a9951a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-d2a9951a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-d2a9951a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d2a9951a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d2a9951a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, credential-theft; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d2a9951a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d2a9951a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d2a9951a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d2a9951a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d2a9951a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d2a9951a-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on vectors: phishing, exploit, credential-theft; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d2a9951a-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-d2a9951a-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-d2a9951a-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-d2a9951a-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-d2a9951a-4 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, credential-theft; impact: ransomware, fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d2a9951a-4-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d2a9951a-4-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d2a9951a-4-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d2a9951a-4-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 50. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/09/18/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Fri, 18 Sep 26 12:00:00 +0000
- **First seen**: 2026-09-18T16:09:12+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 initial-access vector(s)=+7, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2025-39964 Linux Kernel Race Condition Vulnerability CVE-2026-53266 Linux Kernel Out-of-Bounds Write Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed in the KEV Catalog? Submit it fo

**Extracted signals**
- CVEs: CVE-2025-39964, CVE-2026-53266
- Products: Linux kernel
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-cd6d338c-1 · Initial access via CVE-2025-39964 affecting Linux kernel  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-39964 in Linux kernel within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-39964, CVE-2026-53266; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-cd6d338c-1-O1] Inventory exposure to Linux kernel** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Linux kernel, the external-exploitation hypothesis is disproven for CVE-2025-39964.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Linux kernel' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-cd6d338c-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-39964 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-39964/ | summarize count() by src_ip, dst_host`
- **[H-cd6d338c-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-39964 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-39964')) | summarize coverage = avg(installed) by host_role`
- **[H-cd6d338c-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Linux kernel hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-cd6d338c-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-cd6d338c-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-39964, CVE-2026-53266; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-cd6d338c-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-cd6d338c-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-cd6d338c-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-cd6d338c-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-cd6d338c-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-cd6d338c-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-39964, CVE-2026-53266; vectors: exploit; products: Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-cd6d338c-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-cd6d338c-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-cd6d338c-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-cd6d338c-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---
