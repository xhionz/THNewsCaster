# Threat Hunting News Package

- Generated: `2026-10-23T13:07:56+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **385**  ·  Skipped (below threshold): **384**  ·  Briefings: **50**
- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`

---

## 1. #StopRansomware: SafePay Ransomware

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T18:51:46+00:00
- **Relevance score**: 112
- **Score rationale**: source weight (advisory)=+15, 5 CVE(s)=+30, 16 MITRE technique hit(s)=+20, 6 initial-access vector(s)=+15, 2 impact action(s)=+11, 2 product mention(s)=+6, 52 IOC(s)=+15

> Advisory at a Glance Title #StopRansomware: SafePay Ransomware Original Publication October 20, 2026 Executive Summary This advisory details recent activity by the SafePay ransomware group. SafePay actors have been highly active since August 2024, targeting businesses and critical infrastructure across North America, South America, Europe, and Australia. SafePay actors typically gain access to networks by stealing or guessing passwords, exploiting vulnerabilities in security systems, and using phishing tactics. Once inside the network, SafePay actors establish control by creating new accounts or taking over existing ones. They then use legitimate system tools to move through the network, identify valuable files, and disable security protections to avoid detection. Following, they encrypt the victim’s files, making them inaccessible, and leave a ransom note demanding payment in cryptocurrency. This advisory urges organizations to follow recommended security measures to reduce the risk and impact of SafePay ransomware attacks. Affected Products CVE-2020-3259 [ Common Weakness Enumeration (CWE)-200: Exposure of Sensitive Information to an Unauthorized Actor ] CVE-2023-20269 [ CWE-288: Authentication Bypass Using an Alternate Path or Channel ] CVE-2023-27532 [ CWE-306: Missing Authentication for Critical Function ] CVE-2024-40711 [ CWE-502: Deserialization of Untrusted Data ] CVE-2024-40766 [ CWE-284: Improper Access Control ] Key Actions Regularly patch and update systems, espec

**Extracted signals**
- CVEs: CVE-2020-3259, CVE-2023-20269, CVE-2023-27532, CVE-2024-40711, CVE-2024-40766
- Products: Active Directory, ConnectWise ScreenConnect
- Vectors: phishing, exploit, vpn-edge, rdp, smb, credential-theft
- Actions: ransomware, data-breach
- Sectors: healthcare, government, energy, manufacturing
- MITRE ATT&CK: T1566, T1190, T1133, T1059, T1059.001, T1059.003, T1053, T1003, T1021.001, T1021.002, T1021.006, T1486, T1567, T1219, T1098, T1110
- IP IOCs: 104.26.2.223, 140.82.114.4, 185.199.108.133, 77.37.49.40, 173.194.194.94, 167.235.225.149, 5.255.11.134, 88.119.167.239, 37.10.71.188
- Domain IOCs: stopransomware.gov, sharpshares.exe, b2.exe, soc.dll, copy.bat, ccleaner.exe, ccleaner64.exe, dcsync.exe, domains.txt, dyraswtb.exe, libsmb2.dll, license.txt, locker.dll, netscan.exe, netscan.lic, netscan.xml, netscannew.zip, nltest.exe, oui.txt, ping.txt, portable.dat, scan.xml, socks.exe, subs.txt, svchost.exe, winrar.exe, anydesk.exe, acro.exe, diskdirector.exe, acronis.exe, nxc.exe, 1.exe, cisa.dhs.gov
- SHA256: 921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae, 6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a, e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346, 327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917, a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526, bbdd3620a67aedec4b9a68b2c9cc880b6631215e129816aea19902a6f4bc6f41
- SHA1: 07353237350c35d6dc2c8f143b649cd07c71f62b, b498a2683640c983bb069fa2ea9e67cef4a3797d, bbfed53e3bb1f306f4da97d995cf4ae5b73ad081, d711a5af5aed48a3b36b98f4fcf52809aebef7a2

### Hypotheses (4)

#### H-e57c548a-1 · Initial access via CVE-2020-3259 affecting Active Directory  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2020-3259 in Active Directory within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2020-3259, CVE-2023-20269, CVE-2023-27532; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach; products: Active Directory, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e57c548a-1-O1] Inventory exposure to Active Directory** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Active Directory, the external-exploitation hypothesis is disproven for CVE-2020-3259.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Active Directory' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-e57c548a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2020-3259 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2020-3259/ | summarize count() by src_ip, dst_host`
- **[H-e57c548a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2020-3259 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2020-3259')) | summarize coverage = avg(installed) by host_role`
- **[H-e57c548a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Active Directory hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-e57c548a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-e57c548a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2020-3259, CVE-2023-20269, CVE-2023-27532; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach; products: Active Directory, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-e57c548a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('stopransomware.gov','sharpshares.exe','b2.exe') | summarize count() by client_ip`
- **[H-e57c548a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('104.26.2.223','140.82.114.4','185.199.108.133') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-e57c548a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-e57c548a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-e57c548a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-e57c548a-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2020-3259, CVE-2023-20269, CVE-2023-27532; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach; products: Active Directory, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e57c548a-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-e57c548a-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-e57c548a-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-e57c548a-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-e57c548a-4 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on CVEs cited: CVE-2020-3259, CVE-2023-20269, CVE-2023-27532; vectors: phishing, exploit, vpn-edge; impact: ransomware, data-breach; products: Active Directory, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e57c548a-4-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-e57c548a-4-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-e57c548a-4-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-e57c548a-4-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 2. October 2026 Microsoft Patch Tuesday, (Tue, Oct 13th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33422>
- **Published**: Tue, 13 Oct 2026 19:25:52 GMT
- **First seen**: 2026-10-13T20:07:52+00:00
- **Relevance score**: 108
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 5 MITRE technique hit(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 3 product mention(s)=+9, 11 IOC(s)=+15

> Microsoft today released patches for 1,417 vulnerabilities. 76 of these vulnerabilities are rated critical, with 7 critical vulnerabiilties requiring no customer actions. One vulnerability was disclosed before today&#;x26;#;39;s patch Tuesday, and one is already exploited.

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571
- Products: Microsoft Exchange, Active Directory, Linux kernel
- Vectors: exploit, rdp, smb
- Actions: ddos
- Sectors: manufacturing, telecom
- MITRE ATT&CK: T1059, T1059.001, T1003, T1021.001, T1021.002
- Domain IOCs: asp.net, fdwsd.dll, http.sys, csc.sys, unionfs.sys, wininet.dll, spaceport.sys, kernel32.dll, rndismp6.sys, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-92bf2972-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-92bf2972-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-92bf2972-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-92bf2972-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-92bf2972-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-92bf2972-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('asp.net','fdwsd.dll','http.sys') | summarize count() by client_ip`
- **[H-92bf2972-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-92bf2972-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-92bf2972-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-92bf2972-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-92bf2972-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70571; vectors: exploit, rdp, smb; impact: ddos; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-92bf2972-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-92bf2972-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-92bf2972-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-92bf2972-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 3. The Q3 Vulnerability Pulse: Discovery ≠ Exploitation

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/the-q3-vulnerability-pulse-discovery-exploitation/>
- **Published**: Thu, 15 Oct 2026 18:00:00 GMT
- **First seen**: 2026-10-15T18:21:27+00:00
- **Relevance score**: 95
- **Score rationale**: source weight (vendor)=+10, 3 CVE(s)=+30, 4 MITRE technique hit(s)=+17, 2 initial-access vector(s)=+9, 2 impact action(s)=+11, 1 product mention(s)=+3, 15 IOC(s)=+15

> Is the cybersecurity world really facing a "Bugmageddon?" Thor breaks down the latest CVE and KEV trends in the latest Threat Source newsletter.

**Extracted signals**
- CVEs: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Actions: espionage, fraud
- Sectors: government, manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053, T1547
- Domain IOCs: sample.exe, w32.9f1f11a708-100.sbx.tg, w32.pup, pulsebrowser.29kh.in12.talos, net.exe, w32.58d6fec4ba-95.sbx.tg, w32.fed979f93b-95.sbx.tg
- SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507, 73ac1bbfaee6c76c34f655ac0477a4cd930f2aa55e658c8e312ff81aac9a741f, 58d6fec4ba24c32d38c9a0c7c39df3cb0e91f500b323e841121d703c7b718681, fed979f93bcaf4e73ebd25748093a92095d5109cbd01d55f97bdc50ce509ad2f
- MD5: 2915b3f8b703eb744fc54c81f4a9c67f, 63f3351cfdf618bec6045f60203e7978, f1fe671bcefd4630e5ed8b87c9283534, 207d9d891ac756b2bfad88aba5682c65

### Hypotheses (3)

#### H-eb0c40b2-1 · Initial access via CVE-2014-125110 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2014-125110 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2014-125110.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-eb0c40b2-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2014-125110 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2014-125110/ | summarize count() by src_ip, dst_host`
- **[H-eb0c40b2-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2014-125110 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2014-125110')) | summarize coverage = avg(installed) by host_role`
- **[H-eb0c40b2-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-eb0c40b2-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-eb0c40b2-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sample.exe','w32.9f1f11a708-100.sbx.tg','w32.pup') | summarize count() by client_ip`
- **[H-eb0c40b2-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-eb0c40b2-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-eb0c40b2-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-eb0c40b2-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-eb0c40b2-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on CVEs cited: CVE-2014-125110, CVE-2015-1000013, CVE-2026-104935; vectors: exploit, vpn-edge; impact: espionage, fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-eb0c40b2-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-eb0c40b2-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-eb0c40b2-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-eb0c40b2-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 4. CISA Malcolm

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-280-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 89
- **Score rationale**: source weight (advisory)=+15, 7 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 7 IOC(s)=+15

> View CSAF Summary The following versions of CISA Malcolm are affected: Malcolm Malcolm CVSS Vendor Equipment v3 8.1 CISA Malcolm 5 Vulnerabilities Authentication Bypass by Spoofing, Incorrect Authorization, Server-Side Request Forgery (SSRF), Authentication Bypass Using an Alternate Path or Channel, Cross-Site Request Forgery (CSRF) Background Critical Infrastructure Sectors: Energy, Information Technology, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities Expand All + CVE-2026-107336 Malcolm's front nginx reverse proxy defines a "Dashboards → Arkime shortcut" location using a case-insensitive regex matcher but a case-sensitive rewrite. A request whose path segment is not exact-lowercase (for example /IDDASH2ARK/...) enters the location (the matcher fires) but evades the rewrite (no redirect is issued), so nginx falls through to the location's proxy_pass to the Arkime backend. That location is the one proxied location in the shipped config that does not include the per-location authentication file, so the request reaches Arkime unauthenticated. The same location also forwards a client-supplied X-Forwarded-User header un-overwritten, and Arkime is configured to trust X-Forwarded-User as the authenticated username — so an unauthenticated network caller can reach the Arkime backend while supplying a forged, auto-provisioned identity. Read More 1 Affected Product CISA Malcolm Product Status: known_affecte

**Extracted signals**
- CVEs: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362, CVE-2026-107361, CVE-2026-107337, CVE-2026-107335, CVE-2026-107334
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Actions: fraud
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: config.php, submit.php, index.php, control.py, safe-extract.py, 68tadmin.php, www.cisa.gov

### Hypotheses (3)

#### H-87c8a64d-1 · Initial access via CVE-2026-107336 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107336 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107336.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-87c8a64d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107336 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107336/ | summarize count() by src_ip, dst_host`
- **[H-87c8a64d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107336 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107336')) | summarize coverage = avg(installed) by host_role`
- **[H-87c8a64d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-87c8a64d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-87c8a64d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('config.php','submit.php','index.php') | summarize count() by client_ip`
- **[H-87c8a64d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-87c8a64d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-87c8a64d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-87c8a64d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-87c8a64d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107336, CVE-2026-107333, CVE-2026-107362; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-87c8a64d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-87c8a64d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-87c8a64d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-87c8a64d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 5. Break the silence: Kazakhstan-nexus UAT-6275 targets CIS government organizations

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/>
- **Published**: Wed, 14 Oct 2026 14:00:00 GMT
- **First seen**: 2026-10-14T14:13:57+00:00
- **Relevance score**: 86
- **Score rationale**: source weight (vendor)=+10, 2 CVE(s)=+25, 5 MITRE technique hit(s)=+20, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 6 IOC(s)=+14

> Talos and Recorded Future identified UAT-6275 activity targeting government organizations across the Commonwealth of Independent States. Recovered artifacts show additional interest in water resources and energy.

**Extracted signals**
- CVEs: CVE-2025-8088, CVE-2025-25257
- Vectors: phishing, exploit
- Actions: fraud
- Sectors: government, energy, manufacturing
- MITRE ATT&CK: T1059, T1059.001, T1053, T1547, T1219
- Domain IOCs: bi.zone, win.backdoor.pickleshell, win.backdoor.chvost, win.malware.generic, win.malware.laplas, win.proxy.generic

### Hypotheses (3)

#### H-7fae382b-1 · Initial access via CVE-2025-8088 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-8088 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2025-8088.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-7fae382b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-8088 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-8088/ | summarize count() by src_ip, dst_host`
- **[H-7fae382b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-8088 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-8088')) | summarize coverage = avg(installed) by host_role`
- **[H-7fae382b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-7fae382b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-7fae382b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('bi.zone','win.backdoor.pickleshell','win.backdoor.chvost') | summarize count() by client_ip`
- **[H-7fae382b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-7fae382b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-7fae382b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-7fae382b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-7fae382b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-8088, CVE-2025-25257; vectors: phishing, exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7fae382b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-7fae382b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-7fae382b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-7fae382b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 6. Swann Communications SWIFI-SE2KIC

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-286-02>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T16:09:59+00:00
- **Relevance score**: 80
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to view video information without authentication. The following versions of Swann Communications SWIFI-SE2KIC are affected: SWIFI-SE2KIC firmware CVSS Vendor Equipment v3 6.2 Swann Communications SWIFI-SE2KIC firmware 1 Vulnerability Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Commercial Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: Australia Vulnerabilities Expand All + CVE-2026-107605 SWIFI-SE2KIC firmware versions 2.0.22 and prior are vulnerable to a Missing Authentication for Critical Function vulnerability that could allow an attacker on the local network to view live video feed without authentication. Read More 1 Affected Product Swann Communications SWIFI-SE2KIC firmware: Product Status: known_affected Remediations Mitigation Swann Communications has provided the following interim security measures. For more information, contact Swann Communications https://support.swann.com/hc/en-us/requests/new. Mitigation Keep the camera behind a secured router and firewall. Mitigation Avoid exposing RTSP services to the internet through port forwarding, DMZ configurations, or direct public IP access. Mitigation Ensure the router and associated accounts use strong, unique passwords. Mitigation Keep device firmware updated when new releases become available. Additional Metrics Relevant CWE: CWE-306 Missing Authenticati

**Extracted signals**
- CVEs: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: support.swann.com, www.cisa.gov

### Hypotheses (3)

#### H-09aab570-1 · Initial access via CVE-2026-107605 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107605 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-09aab570-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107605.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-09aab570-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107605 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107605/ | summarize count() by src_ip, dst_host`
- **[H-09aab570-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107605 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107605')) | summarize coverage = avg(installed) by host_role`
- **[H-09aab570-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-09aab570-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-09aab570-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-09aab570-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('support.swann.com','www.cisa.gov') | summarize count() by client_ip`
- **[H-09aab570-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-09aab570-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-09aab570-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-09aab570-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-09aab570-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107605, CVE-2026-107606, CVE-2026-107607; vectors: phishing, exploit, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-09aab570-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-09aab570-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-09aab570-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-09aab570-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 7. Feds Suspect Ransom Negotiator Ran ShinyHunters Extortion Site

- **Source**: KrebsOnSecurity
- **Link**: <https://krebsonsecurity.com/2026/10/feds-suspect-ransom-negotiator-ran-shinyhunters-extortion-site/>
- **Published**: Mon, 19 Oct 2026 13:48:56 +0000
- **First seen**: 2026-10-19T13:53:31+00:00
- **Relevance score**: 79
- **Score rationale**: source weight (news)=+5, 1 malware family hit(s)=+20, 3 MITRE technique hit(s)=+14, 2 initial-access vector(s)=+9, 3 impact action(s)=+14, 1 product mention(s)=+3, 6 IOC(s)=+14

> U.S. federal investigators pursuing the ShinyHunters hacking group that recently stole highly sensitive data from the FBI have identified executives at two different ransomware negotiation firms who maintained unusually close relations with the extortion group, KrebsOnSecurity has learned. Sources close to the investigation say one of the executives in the United States even helped ShinyHunters operate a website that pressured victims into paying a ransom.

**Extracted signals**
- Malware families: BlackCat / ALPHV
- Products: Microsoft Exchange
- Vectors: phishing, exploit
- Actions: ransomware, data-breach, fraud
- Sectors: healthcare, finance, government, manufacturing, education
- MITRE ATT&CK: T1566, T1486, T1219
- Domain IOCs: fbijobs.gov, shinywire.com, urlscan.io, tutanota.com, me.com, tuta.io

### Hypotheses (4)

#### H-f5dd0145-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on malware families: BlackCat / ALPHV; vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f5dd0145-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-f5dd0145-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-f5dd0145-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-f5dd0145-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-f5dd0145-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-f5dd0145-2 · Endpoint execution of BlackCat / ALPHV  _(confidence: high)_

**Statement.** One or more endpoints in the estate have executed or attempted to execute BlackCat / ALPHV payloads since the reporting date.

**Why this hypothesis?** Archetype 'malware_execution' selected based on malware families: BlackCat / ALPHV; vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1204, T1059, T1547

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f5dd0145-2-O1] EDR hash sweep for BlackCat / ALPHV** _(difficulty: easy · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If a search of EDR file/process telemetry for known BlackCat / ALPHV SHA256s returns zero hits in the last 90 days, payload presence is disproven.
  - Data sources: EDR (CrowdStrike/Defender/SentinelOne), Threat-intel feed
  - Suggested query: `process_events | where sha256 in (ti_lookup('BlackCat / ALPHV', 'sha256')) | summarize count() by host`
- **[H-f5dd0145-2-O2] Behavioural pattern hunt for BlackCat / ALPHV** _(difficulty: medium · 200 pts · MITRE: T1059.001, T1059.005, T1218.011)_
  - Falsification criterion: If parent/child anomalies typical of the family (e.g. Office spawning script hosts, rundll32 chains) are absent across the estate, execution chain is unsupported.
  - Data sources: Sysmon EID 1, EDR process tree
  - Suggested query: `process | where parent in ('winword.exe','excel.exe','outlook.exe') and child in ('rundll32.exe','wscript.exe','mshta.exe','powershell.exe')`
- **[H-f5dd0145-2-O3] Persistence-key inspection** _(difficulty: medium · 200 pts · MITRE: T1547.001, T1053.005)_
  - Falsification criterion: If autoruns, scheduled tasks, services, and WMI subscriptions show no BlackCat / ALPHV-aligned artifacts, post-execution persistence is disproven.
  - Data sources: Sysmon EID 13/12, Autoruns sweep, EDR persistence module
  - Suggested query: `registry_set | where key matches /Run|RunOnce|Image File Execution Options/ and value matches /unusual-path/`
- **[H-f5dd0145-2-O4] AV / quarantine retrospective** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: If retrospective AV / quarantine logs show no detections for related signatures over the last 30 days, the family is unlikely to have landed in-environment.
  - Data sources: AV management console, Defender ATP detections
  - Suggested query: `av_events | where signature contains 'BlackCat / ALPHV' | summarize by host, action`
- **[H-f5dd0145-2-O5] Memory-resident loader check** _(difficulty: hard · 300 pts · MITRE: T1620, T1055)_
  - Falsification criterion: If a memory scan (YARA via EDR / Volatility) finds none of the published loader patterns on a sampled set of high-risk hosts, in-memory residency is unsupported.
  - Data sources: YARA via EDR, Volatility on a sampled host
  - Suggested query: `memory_scan | yara_rule == 'rule_blackcat_/_alphv' | summarize by host`

#### H-f5dd0145-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on malware families: BlackCat / ALPHV; vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-f5dd0145-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('fbijobs.gov','shinywire.com','urlscan.io') | summarize count() by client_ip`
- **[H-f5dd0145-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-f5dd0145-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-f5dd0145-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-f5dd0145-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-f5dd0145-4 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on malware families: BlackCat / ALPHV; vectors: phishing, exploit; impact: ransomware, data-breach, fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f5dd0145-4-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-f5dd0145-4-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-f5dd0145-4-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-f5dd0145-4-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 8. Siemens RUGGEDCOM CROSSBOW

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

## 9. AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/>
- **Published**: Wed, 21 Oct 2026 18:23:55 +0000
- **First seen**: 2026-10-21T21:00:59+00:00
- **Relevance score**: 74
- **Score rationale**: source weight (vendor)=+10, 5 MITRE technique hit(s)=+20, 5 initial-access vector(s)=+15, 1 impact action(s)=+8, 2 product mention(s)=+6, 13 IOC(s)=+15

> Storm-0940 used ARTEX agentic AI to accelerate a ConnectWise supply chain compromise, enabling application credential abuse across Microsoft 365 environments. The post AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID, ConnectWise ScreenConnect
- Vectors: phishing, exploit, supply-chain, vpn-edge, credential-theft
- Actions: data-breach
- Sectors: finance, government, energy, manufacturing, telecom
- MITRE ATT&CK: T1566, T1078, T1219, T1098, T1110
- IP IOCs: 144.172.64.99, 144.172.64.128, 144.172.64.60, 187.15.88.186, 187.15.90.217, 187.15.89.186
- Domain IOCs: next.js, permission.permissionname, permission.targetappdisplayname, permission.targetappid, permission.permissiontype, permission.privilegelevel, permission.usagestatus

### Hypotheses (3)

#### H-480410d4-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, supply-chain; impact: data-breach; products: Microsoft 365 / Entra ID, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-480410d4-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-480410d4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-480410d4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-480410d4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-480410d4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-480410d4-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, supply-chain; impact: data-breach; products: Microsoft 365 / Entra ID, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-480410d4-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('next.js','permission.permissionname','permission.targetappdisplayname') | summarize count() by client_ip`
- **[H-480410d4-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('144.172.64.99','144.172.64.128','144.172.64.60') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-480410d4-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-480410d4-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-480410d4-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-480410d4-3 · Data staging and exfiltration to attacker-controlled storage  _(confidence: medium)_

**Statement.** Sensitive data has been staged (archived) and exfiltrated to attacker-controlled endpoints or cloud-storage tenants in the reporting window.

**Why this hypothesis?** Archetype 'exfiltration' selected based on vectors: phishing, exploit, supply-chain; impact: data-breach; products: Microsoft 365 / Entra ID, ConnectWise ScreenConnect.

**MITRE ATT&CK**: T1560, T1041, T1567, T1567.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-480410d4-3-O1] Cloud-storage exfil to non-corp tenants** _(difficulty: easy · 100 pts · MITRE: T1567.002, T1567)_
  - Falsification criterion: If DLP / proxy show no uploads to mega.nz, anonfiles, transfer.sh, or personal Dropbox/OneDrive tenants, cloud exfil is disproven.
  - Data sources: Proxy logs, CASB / DLP
  - Suggested query: `proxy | where host matches /mega\.nz|anonfiles\.com|transfer\.sh|filebin\.net/ | summarize bytes = sum(bytes_out) by user`
- **[H-480410d4-3-O2] Archive-then-egress pattern** _(difficulty: medium · 250 pts · MITRE: T1560, T1041)_
  - Falsification criterion: If user/host telemetry shows no archive creation (rar/7z) within minutes of a large outbound transfer, the stage-then-exfil pattern is absent.
  - Data sources: EDR process+file events, NetFlow
  - Suggested query: `file_create | where ext in ('.rar','.7z','.zip') | join (egress | where bytes_out > 50MB) on host within 30m`
- **[H-480410d4-3-O3] Outbound volume to rare ASNs** _(difficulty: medium · 200 pts · MITRE: T1041, T1567)_
  - Falsification criterion: If outbound bytes-by-ASN over the last 30 days show no first-seen / low-reputation destination receiving >1GB, bulk exfil is unsupported.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `netflow | summarize bytes = sum(bytes_out) by asn | where asn !in (corp_known_asns) and bytes > 1GB`
- **[H-480410d4-3-O4] DNS-tunnelling search** _(difficulty: hard · 300 pts · MITRE: T1071.004, T1048.003)_
  - Falsification criterion: If DNS query-length and txt-record distributions show no entropy / volume anomalies per source, DNS-tunnelled exfil is unsupported.
  - Data sources: DNS resolver logs
  - Suggested query: `dns | summarize avg(query_length), p99(query_length), count() by client_ip | where p99 > 200 and count() > 1000`

---

## 10. Two critical RCEs in PHP core

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/two-critical-rces-in-php-core/>
- **Published**: Wed, 21 Oct 2026 15:10:53 GMT
- **First seen**: 2026-10-21T15:39:09+00:00
- **Relevance score**: 74
- **Score rationale**: source weight (vendor)=+10, 2 CVE(s)=+25, 2 MITRE technique hit(s)=+11, 3 initial-access vector(s)=+11, 2 impact action(s)=+11, 2 IOC(s)=+6

> Cisco Talos is tracking the disclosure of two unauthenticated remote code execution (RCE) flaws in PHP core, dubbed “php2shell”, triggered by a plain HTTP request and exploitable before any application code runs, affecting every PHP build since 5.4. Based on the entities involved in the disclosure, artificial

**Extracted signals**
- CVEs: CVE-2026-109618, CVE-2026-109619
- Vectors: phishing, exploit, rdp
- Actions: ransomware, fraud
- Sectors: finance, manufacturing, telecom
- MITRE ATT&CK: T1021.001, T1486
- Domain IOCs: php.ini, user.ini

### Hypotheses (3)

#### H-efe58590-1 · Initial access via CVE-2026-109618 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109618 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-efe58590-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109618.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-efe58590-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109618 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109618/ | summarize count() by src_ip, dst_host`
- **[H-efe58590-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109618 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109618')) | summarize coverage = avg(installed) by host_role`
- **[H-efe58590-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-efe58590-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-efe58590-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-efe58590-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('php.ini','user.ini') | summarize count() by client_ip`
- **[H-efe58590-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-efe58590-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-efe58590-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-efe58590-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-efe58590-3 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: phishing, exploit, rdp; impact: ransomware, fraud.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-efe58590-3-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-efe58590-3-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-efe58590-3-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-efe58590-3-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

---

## 11. Guangzhou Juan IoT Technology EseeCloud

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-02>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 72
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to gain control over affected IP cameras. The following versions of Guangzhou Juan IoT Technology EseeCloud are affected: EseeCloud App EseeCloud Firmware CVSS Vendor Equipment v3 9.8 Guangzhou Juan IoT Technology Co., Ltd. EseeCloud App 3 Vulnerabilities Use of Hard-coded Credentials, Improperly Controlled Modification of Dynamically-Determined Object Attributes, Observable Response Discrepancy Background Critical Infrastructure Sectors: Energy, Communications, Transportation Systems, Financial Services, Government Services and Facilities Countries/Areas Deployed: Worldwide Company Headquarters Location: China Vulnerabilities Expand All + CVE-2026-107617 An attacker can use a hard-coded credential to log in to EseeCloud devices. Read More 2 Affected Products Guangzhou Juan IoT Technology Co., Ltd. EseeCloud App: Product Status: known_affected Remediations Mitigation Guangzhou Juan IoT Technology Co., Ltd. did not respond to CISA's coordination attempts. EseeCloud users are advised to contact Guangzhou Juan IoT Technology Co., Ltd. for support https://eseecloud.app/. Guangzhou Juan IoT Technology Co., Ltd. EseeCloud Firmware: Product Status: known_affected Remediations Mitigation Guangzhou Juan IoT Technology Co., Ltd. did not respond to CISA's coordination attempts. EseeCloud users are advised to contact Guangzhou Juan IoT Technology Co., Ltd. for support https://eseecloud.app/. Additi

**Extracted signals**
- CVEs: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: finance, government, energy, manufacturing, education
- MITRE ATT&CK: T1566
- Domain IOCs: eseecloud.app, www.cisa.gov

### Hypotheses (3)

#### H-08e65857-1 · Initial access via CVE-2026-107617 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107617 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-08e65857-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107617.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-08e65857-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107617 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107617/ | summarize count() by src_ip, dst_host`
- **[H-08e65857-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107617 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107617')) | summarize coverage = avg(installed) by host_role`
- **[H-08e65857-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-08e65857-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-08e65857-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-08e65857-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('eseecloud.app','www.cisa.gov') | summarize count() by client_ip`
- **[H-08e65857-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-08e65857-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-08e65857-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-08e65857-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-08e65857-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107617, CVE-2026-97858, CVE-2026-105664; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-08e65857-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-08e65857-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-08e65857-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-08e65857-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 12. Kiloview E3 NDI Encoder

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

## 13. Critical PHP Vulnerability (CVE-2026-109618, CVE-2026-109619) [infocon yellow], (Wed, Oct 21st)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33440>
- **Published**: Wed, 21 Oct 2026 12:44:16 GMT
- **First seen**: 2026-10-21T12:58:24+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 7 IOC(s)=+15

> PHP.net announced that it will release a critical update today. We decided to change the infoCon to YELLOW due to the widespread use of PHP, the expected severity of the flaw (CVSS 9.4), and the availability of early PoC exploits ahead of the patch becoming available.

**Extracted signals**
- CVEs: CVE-2026-109618, CVE-2026-109619
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing
- Domain IOCs: php.net, jackalsyn.com, php-up-2026.html, www.php.net, 2026.php, sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-573a82df-1 · Initial access via CVE-2026-109618 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109618 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-573a82df-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109618.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-573a82df-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109618 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109618/ | summarize count() by src_ip, dst_host`
- **[H-573a82df-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109618 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109618')) | summarize coverage = avg(installed) by host_role`
- **[H-573a82df-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-573a82df-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-573a82df-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-573a82df-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('php.net','jackalsyn.com','php-up-2026.html') | summarize count() by client_ip`
- **[H-573a82df-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-573a82df-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-573a82df-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-573a82df-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-573a82df-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-573a82df-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-573a82df-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-573a82df-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-573a82df-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 14. Two hardening tools (AD+Windows) in ps1

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1x7hvhz/two_hardening_tools_adwindows_in_ps1/>
- **Published**: 2026-10-16T14:34:23+00:00
- **First seen**: 2026-10-17T02:24:11+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (social)=+2, 2 CVE(s)=+25, 4 MITRE technique hit(s)=+17, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 1 IOC(s)=+4

> Hey, i'm working on those two little tools, any feedback is appreciated. ->>HostBadger, an open-source Windows hardening auditor in pure PowerShell. One read-only script takes a snapshot of each host, and you can push it through your EDR (CrowdStrike RTR or any tool that runs scripts) to a whole fleet in about 15 seconds per host. The analyzer then works offline and writes a clean HTML report with A–F scores, plus CSV and JSON Lines for your SIEM. - 138 checks: credentials, Defender and EDR, network exposure and NTLM relay paths, privilege escalation, logging, BitLocker - 1475 DISA STIG rules plus the CIS benchmark of each host's own Windows version, with the value found next to the value required - Vulnerable drivers (LOLDrivers), end-of-life and outdated software (endoflife.date), CISA KEV matches - Read-only by design, with a safety script that checks this from the code. No network unless you ask. What it can't read is "not evaluated", never clean. - Reversible fix scripts with rollback, and an optional AI summary where names become tokens before anything is sent Nothing to install (PowerShell 5.1 or 7): https://github.com/g4bri-3l3/HostBadger & ->>IDWolf: my own AD/Entra ID hardening tool that tells you whether your domain can be taken, and through which real-world attacks. Open-source, pure PowerShell, read-only collection (native cmdlets only), offline analysis. Recent attacks mapped to checks: BadSuccessor, Golden dMSA, coercion + NTLM relay to LDAP and AD CS (CVE-2025

**Extracted signals**
- CVEs: CVE-2025-24054, CVE-2025-33073
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, cloud-misconfig
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566, T1059, T1059.001, T1110
- Domain IOCs: endoflife.date

### Hypotheses (3)

#### H-046f10c8-1 · Initial access via CVE-2025-24054 affecting Microsoft 365 / Entra ID  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-24054 in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for CVE-2025-24054.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-046f10c8-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-24054 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-24054/ | summarize count() by src_ip, dst_host`
- **[H-046f10c8-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-24054 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-24054')) | summarize coverage = avg(installed) by host_role`
- **[H-046f10c8-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-046f10c8-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-046f10c8-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('endoflife.date') | summarize count() by client_ip`
- **[H-046f10c8-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-046f10c8-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-046f10c8-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-046f10c8-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-046f10c8-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-24054, CVE-2025-33073; vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-046f10c8-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-046f10c8-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-046f10c8-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-046f10c8-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 15. J4Care dcm4che

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-02>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to delete stored medical images, disclose patient information, inject forged studies, reassign patient records, overwrite files, and cause a denial-of-service condition. The following versions of J4Care dcm4che are affected: dcm4chee-arc-light 5.35.1 (CVE-2026-97851, CVE-2026-107621, CVE-2026-105273, CVE-2026-101021, CVE-2026-105279, CVE-2026-105667) CVSS Vendor Equipment v3 9.1 J4Care dcm4chee-arc-light 4 Vulnerabilities Missing Authorization, Loop with Unreachable Exit Condition ('Infinite Loop'), Inefficient Algorithmic Complexity, Missing Authentication for Critical Function Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: Austria Vulnerabilities Expand All + CVE-2026-97851 The storage status-change REST service allows location records still associated with DICOM instances to be changed to deletion-related states. Changing a location to TO_DELETE causes PurgeStorageScheduler to delete the referenced object from storage even though the corresponding instance record remains in the database. Read More 1 Affected Product J4Care dcm4chee-arc-light: 5.35.1 Product Status: known_affected Remediations Mitigation J4Care has provided a fix for the vulnerabilities. J4Care recommends users implement release 5.35.2 or later. Additional Metrics Relevant CWE: CWE-862 Missing Authorization CVSS Version Base S

**Extracted signals**
- CVEs: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273, CVE-2026-101021, CVE-2026-105279, CVE-2026-105667
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-a0effe20-1 · Initial access via CVE-2026-97851 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-97851 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-97851.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a0effe20-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-97851 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-97851/ | summarize count() by src_ip, dst_host`
- **[H-a0effe20-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-97851 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-97851')) | summarize coverage = avg(installed) by host_role`
- **[H-a0effe20-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a0effe20-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a0effe20-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-a0effe20-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a0effe20-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a0effe20-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a0effe20-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a0effe20-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-97851, CVE-2026-107621, CVE-2026-105273; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a0effe20-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-a0effe20-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-a0effe20-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-a0effe20-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 16. Microsoft Patch Tuesday for October 2026 — Snort rules and prominent vulnerabilities

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/microsoft-patch-tuesday-for-october-2026/>
- **Published**: Tue, 13 Oct 2026 20:37:58 GMT
- **First seen**: 2026-10-13T20:48:54+00:00
- **Relevance score**: 70
- **Score rationale**: source weight (vendor)=+10, 193 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 3 product mention(s)=+9, 1 IOC(s)=+4

> Blog post covering the vulnerabilities disclosed during Microsoft Patch Tuesday.

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571, CVE-2026-105733, CVE-2026-102214, CVE-2026-108399, CVE-2026-100202, CVE-2026-100209, CVE-2026-100210, CVE-2026-100211, CVE-2026-97739, CVE-2026-97745, CVE-2026-97755, CVE-2026-97759, CVE-2026-97765, CVE-2026-97778, CVE-2026-97741, CVE-2026-97742, CVE-2026-97753, CVE-2026-97756, CVE-2026-97758, CVE-2026-97761, CVE-2026-97767, CVE-2026-97776, CVE-2026-97780, CVE-2026-100215, CVE-2026-100219, CVE-2026-105016, CVE-2026-100220, CVE-2026-102211, CVE-2026-88074, CVE-2026-108130, CVE-2026-108471, CVE-2026-96914, CVE-2026-102225, CVE-2026-97814, CVE-2026-102855, CVE-2026-102856, CVE-2026-102857, CVE-2026-102866, CVE-2026-62840, CVE-2026-69802, CVE-2026-70147, CVE-2026-70153, CVE-2026-108467, CVE-2026-70187, CVE-2026-70250, CVE-2026-83934, CVE-2026-88073, CVE-2026-88117, CVE-2026-88119, CVE-2026-88120, CVE-2026-88171, CVE-2026-96934, CVE-2026-96222, CVE-2026-108131, CVE-2026-96913, CVE-2026-96952, CVE-2026-105718, CVE-2026-108400, CVE-2026-108457, CVE-2026-108460, CVE-2026-70215, CVE-2026-88144, CVE-2026-88178, CVE-2026-88207, CVE-2026-70242, CVE-2026-70291, CVE-2026-88156, CVE-2026-97016, CVE-2026-97749, CVE-2026-70269, CVE-2026-70300, CVE-2026-83917, CVE-2026-94510, CVE-2026-96202, CVE-2026-96943, CVE-2026-96207, CVE-2026-69789, CVE-2026-88174, CVE-2026-88185, CVE-2026-69435, CVE-2026-77900, CVE-2026-83943, CVE-2026-83947, CVE-2026-88131, CVE-2026-100214, CVE-2026-102217, CVE-2026-69673, CVE-2026-69718, CVE-2026-69733, CVE-2026-69783, CVE-2026-69882, CVE-2026-69923, CVE-2026-69926, CVE-2026-70054, CVE-2026-70060, CVE-2026-70076, CVE-2026-70104, CVE-2026-70108, CVE-2026-70117, CVE-2026-70132, CVE-2026-70144, CVE-2026-70156, CVE-2026-70218, CVE-2026-70223, CVE-2026-70233, CVE-2026-70236, CVE-2026-70237, CVE-2026-70241, CVE-2026-70245, CVE-2026-70249, CVE-2026-70253, CVE-2026-70255, CVE-2026-70271, CVE-2026-70273, CVE-2026-70286, CVE-2026-70303, CVE-2026-72955, CVE-2026-81971, CVE-2026-83505, CVE-2026-83509, CVE-2026-83510, CVE-2026-83580, CVE-2026-83669, CVE-2026-83699, CVE-2026-83704, CVE-2026-83717, CVE-2026-83724, CVE-2026-83732, CVE-2026-83735, CVE-2026-83738, CVE-2026-83750, CVE-2026-83761, CVE-2026-83763, CVE-2026-83768, CVE-2026-83769, CVE-2026-83793, CVE-2026-83830, CVE-2026-83834, CVE-2026-83840, CVE-2026-83842, CVE-2026-83848, CVE-2026-83867, CVE-2026-83886, CVE-2026-83896, CVE-2026-83899, CVE-2026-83902, CVE-2026-83921, CVE-2026-84014, CVE-2026-85355, CVE-2026-85791, CVE-2026-85802, CVE-2026-85804, CVE-2026-85832, CVE-2026-85843, CVE-2026-85848, CVE-2026-85849, CVE-2026-85850, CVE-2026-85855, CVE-2026-85870, CVE-2026-85901, CVE-2026-85908, CVE-2026-85941, CVE-2026-85945, CVE-2026-88118, CVE-2026-88133, CVE-2026-88147, CVE-2026-88152, CVE-2026-88159, CVE-2026-88191, CVE-2026-96858, CVE-2026-96911, CVE-2026-96929, CVE-2026-96940, CVE-2026-69452, CVE-2026-69880, CVE-2026-69918, CVE-2026-70103, CVE-2026-70106, CVE-2026-70151, CVE-2026-70176, CVE-2026-70279, CVE-2026-83785, CVE-2026-83927, CVE-2026-85884, CVE-2026-85902, CVE-2026-85906, CVE-2026-88093, CVE-2026-96939, CVE-2026-97798, CVE-2026-97799, CVE-2026-97800
- Products: Microsoft Exchange, Active Directory, Linux kernel
- Vectors: exploit, rdp
- Sectors: manufacturing
- MITRE ATT&CK: T1021.001
- Domain IOCs: snort.org

### Hypotheses (3)

#### H-4df1bd97-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-4df1bd97-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-4df1bd97-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-4df1bd97-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-4df1bd97-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-4df1bd97-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('snort.org') | summarize count() by client_ip`
- **[H-4df1bd97-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-4df1bd97-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-4df1bd97-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-4df1bd97-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-4df1bd97-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-70229, CVE-2026-70571; vectors: exploit, rdp; products: Microsoft Exchange, Active Directory, Linux kernel.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4df1bd97-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-4df1bd97-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-4df1bd97-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-4df1bd97-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 17. Siemens RUGGEDCOM CROSSBOW Station Access Controller

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

## 18. Siemens APOGEE, TALON and Desigo PXC/PXM Products

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

## 19. Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP

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

## 20. HMS Networks PEAK-System PCAN Windows drivers

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-01>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13

> View CSAF Summary Successful exploitation of these vulnerabilities could crash the Windows kernel. The following versions of HMS Networks PEAK-System PCAN Windows drivers are affected: PEAK-System Device Driver Setup PCAN Windows CAN device drivers CVSS Vendor Equipment v3 7.1 HMS Networks PEAK-System Device Driver Setup 5 Vulnerabilities Out-of-bounds Write, Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'), Improper Validation of Array Index, Untrusted Pointer Dereference, Improper Handling of Length Parameter Inconsistency Background Critical Infrastructure Sectors: Transportation Systems, Healthcare and Public Health, Energy, Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Sweden Vulnerabilities Expand All + CVE-2026-109576 The parser in PEAK-System PCAN driver correctly detected the malformed record, but the loop iterating the record list advanced its processed-bytes counter even when a record had been rejected as invalid. Read More 2 Affected Products HMS Networks PEAK-System Device Driver Setup: Product Status: known_affected Remediations Mitigation HMS Networks AB has addressed the issue in version 5.1.4 and recommends that users upgrade to the newest available version. Users can find software updates for PEAK-System PCAN on the software download page. Mitigation For more information see the associated HMS security advisory. HMS Networks PCAN Windows CAN device drivers: Product Status: known_affected Remed

**Extracted signals**
- CVEs: CVE-2026-109576, CVE-2026-101103, CVE-2026-94188, CVE-2026-103672, CVE-2026-110322, CVE-2026-105960
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, energy, manufacturing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-555aab69-1 · Initial access via CVE-2026-109576 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109576 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109576, CVE-2026-101103, CVE-2026-94188; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-555aab69-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109576.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-555aab69-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109576 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109576/ | summarize count() by src_ip, dst_host`
- **[H-555aab69-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109576 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109576')) | summarize coverage = avg(installed) by host_role`
- **[H-555aab69-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-555aab69-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-555aab69-2 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109576, CVE-2026-101103, CVE-2026-94188; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-555aab69-2-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-555aab69-2-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-555aab69-2-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-555aab69-2-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

#### H-555aab69-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109576, CVE-2026-101103, CVE-2026-94188; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-555aab69-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-555aab69-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-555aab69-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-555aab69-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-555aab69-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 21. Hitachi Energy RTU500 Product

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-05>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 66
- **Score rationale**: source weight (advisory)=+15, 9 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 IOC(s)=+4

> View CSAF Summary Hitachi Energy is aware of vulnerabilities that affect RTU500 product versions listed in this document. These vulnerabilities if exploited can have impact on confidentiality, integrity and availability of the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy RTU500 Product are affected: RTU500 series CMU Firmware vers:RTU500_series_CMU_Firmware/>=13.5.1| =13.6.1| =13.7.1| =13.8.1| =12.7.1| CVSS Vendor Equipment v3 8.8 Hitachi Energy RTU500 series CMU Firmware 7 Vulnerabilities NULL Pointer Dereference, Access of Resource Using Incompatible Type ('Type Confusion'), Use After Free, Cleartext Transmission of Sensitive Information, Insufficiently Protected Credentials, Authentication Bypass by Capture-replay, Authentication Bypass by Primary Weakness Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-17539 RTU500 has a vulnerability, where high-load scenarios, such as sending GI requests at short intervals, may cause a NULL pointer dereference in the last entry of the enhanced message queue. This can cause a BCI_IEC104 fatal write error, resulting in connection interruption and restart, and ultimately a denial of service for bidirectional IEC 60870-5-104 communication. Read More 5 Affected Products RTU500 series CMU Firmware version 13.5.1 – 13.5.4 

**Extracted signals**
- CVEs: CVE-2026-17539, CVE-2026-28388, CVE-2026-6732, CVE-2026-6653, CVE-2026-6276, CVE-2026-9079, CVE-2026-11856, CVE-2026-8927, CVE-2026-8932
- Vectors: exploit, vpn-edge
- Actions: ddos
- Sectors: energy, manufacturing
- Domain IOCs: www.hitachienergy.com

### Hypotheses (3)

#### H-c934e572-1 · Initial access via CVE-2026-17539 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-17539 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-17539, CVE-2026-28388, CVE-2026-6732; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c934e572-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-17539.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c934e572-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-17539 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-17539/ | summarize count() by src_ip, dst_host`
- **[H-c934e572-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-17539 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-17539')) | summarize coverage = avg(installed) by host_role`
- **[H-c934e572-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c934e572-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c934e572-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-17539, CVE-2026-28388, CVE-2026-6732; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c934e572-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com') | summarize count() by client_ip`
- **[H-c934e572-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c934e572-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c934e572-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c934e572-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c934e572-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-17539, CVE-2026-28388, CVE-2026-6732; vectors: exploit, vpn-edge; impact: ddos.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c934e572-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c934e572-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c934e572-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c934e572-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 22. Widespread PHP Flaw May Cause Many Site Outages Today

- **Source**: KrebsOnSecurity
- **Link**: <https://krebsonsecurity.com/2026/10/widespread-php-flaw-may-cause-many-site-outages-today/>
- **Published**: Wed, 21 Oct 2026 15:26:07 +0000
- **First seen**: 2026-10-21T15:39:09+00:00
- **Relevance score**: 65
- **Score rationale**: source weight (news)=+5, 2 CVE(s)=+25, 2 MITRE technique hit(s)=+11, 2 initial-access vector(s)=+9, 2 impact action(s)=+11, 1 IOC(s)=+4

> Expect to see quite a few websites serving "404" or "Page Not Found" errors today: Nearly 70 percent of websites need to update their core software to fix a pair of vulnerabilities that allow an attacker to seize full control over affected servers. Experts say there are working exploits for the flaws, and that these critical bugs are already being exploited in the wild.

**Extracted signals**
- CVEs: CVE-2026-109618, CVE-2026-109619
- Vectors: exploit, rdp
- Actions: ddos, fraud
- Sectors: government, manufacturing
- MITRE ATT&CK: T1021.001, T1505.003
- Domain IOCs: shutterstock.com

### Hypotheses (3)

#### H-fd4a29f5-1 · Initial access via CVE-2026-109618 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109618 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit, rdp; impact: ddos, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd4a29f5-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109618.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-fd4a29f5-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109618 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109618/ | summarize count() by src_ip, dst_host`
- **[H-fd4a29f5-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109618 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109618')) | summarize coverage = avg(installed) by host_role`
- **[H-fd4a29f5-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-fd4a29f5-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-fd4a29f5-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit, rdp; impact: ddos, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd4a29f5-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('shutterstock.com') | summarize count() by client_ip`
- **[H-fd4a29f5-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-fd4a29f5-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-fd4a29f5-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-fd4a29f5-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-fd4a29f5-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109618, CVE-2026-109619; vectors: exploit, rdp; impact: ddos, fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fd4a29f5-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-fd4a29f5-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-fd4a29f5-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-fd4a29f5-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 23. InterSystems Corporation InterSystems IRIS for Health

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

## 24. Compromised eMudhra intermediate certificates

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/compromised-intermediate-certificates/>
- **Published**: Wed, 21 Oct 2026 20:43:29 GMT
- **First seen**: 2026-10-21T21:00:59+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 8 IOC(s)=+15

> Cisco Talos is aware of eight intermediate certificates belonging to the intermediate certificate authority, eMudhra.

**Extracted signals**
- CVEs: CVE-2026-111943
- Vectors: exploit, supply-chain, vpn-edge
- Actions: fraud
- Sectors: manufacturing
- SHA256: e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838, 98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b, 42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493, 432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3, cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f, 0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19, 9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4, 4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1

### Hypotheses (3)

#### H-820932a3-1 · Initial access via CVE-2026-111943 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-111943 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-111943; vectors: exploit, supply-chain, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-820932a3-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-111943.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-820932a3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-111943 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-111943/ | summarize count() by src_ip, dst_host`
- **[H-820932a3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-111943 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-111943')) | summarize coverage = avg(installed) by host_role`
- **[H-820932a3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-820932a3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-820932a3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-111943; vectors: exploit, supply-chain, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-820932a3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-820932a3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-820932a3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-820932a3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-820932a3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-820932a3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-111943; vectors: exploit, supply-chain, vpn-edge; impact: fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-820932a3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-820932a3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-820932a3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-820932a3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 25. Patch Tuesday - October 2026

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026>
- **Published**: Tue, 13 Oct 2026 21:40:27 GMT
- **First seen**: 2026-10-13T22:50:12+00:00
- **Relevance score**: 64
- **Score rationale**: source weight (vendor)=+10, 8 CVE(s)=+30, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> Microsoft is publishing 1,413 own-product vulnerabilities on October 2026 Patch Tuesday , including 1,102 vulnerabilities in Windows. Anyone who enjoyed last month’s record-setting Patch Tuesday will love the October 2026 edition, because it’s much bigger still. As Rapid7 has noted over the course of 2026, there is every reason to suppose that vulnerability volumes will continue to rise. Microsoft is aware of exploitation in the wild for just one of the vulnerabilities published today, as well as public disclosure for two others. Windows Shell: zero-day security feature bypass The Windows Shell is Microsoft’s term for the GUI interaction logic for the entire OS provided by explorer.exe and associated libraries and APIs, and for the second time this year , the Windows Shell is the site of an exploited-in-the-wild zero-day vulnerability. Today’s specimen is CVE-2026-96951 . Once again, the immediate prize for an attacker is a Mark of the Web (MOTW) bypass. What this means is that Windows won’t provide the user with a dialog explaining that Windows protected their PC, because in this case, it didn’t. Exploitation requires that a user opens a specially crafted malicious file or visits an attacker-controlled site, so the evergreen advice about being careful what you click remains valid. Fans of vintage operating systems should note that Windows Server 2012 doesn’t receive a patch, although Server 2012 R2 does. The advisory acknowledges reporters from multiple organizations, althou

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242, CVE-2026-97749, CVE-2026-97016, CVE-2026-88156, CVE-2026-70291, CVE-2023-23397
- Products: Microsoft Exchange
- Vectors: exploit
- Actions: fraud
- Sectors: manufacturing, telecom
- Domain IOCs: explorer.exe, outlook.com

### Hypotheses (3)

#### H-516d995a-1 · Initial access via CVE-2026-96951 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-516d995a-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-516d995a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-516d995a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-516d995a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-516d995a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-516d995a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-516d995a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('explorer.exe','outlook.com') | summarize count() by client_ip`
- **[H-516d995a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-516d995a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-516d995a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-516d995a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-516d995a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-108398, CVE-2026-70242; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-516d995a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-516d995a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-516d995a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-516d995a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 26. Siemens Industrial Edge App Publisher

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

## 27. I had plans for that second

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

## 28. CISA Urges Patching Newly Exploited Vulnerability in Ivanti Connect Secure

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T22:09:51+00:00
- **Relevance score**: 63
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 3 initial-access vector(s)=+11, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> CISA is aware of Ivanti’s disclosure of a newly exploited vulnerability, CVE-2026-104935 , affecting Ivanti Connect Secure versions 25.1.1.1 and prior, 25.1.2.2 and prior, and 22.8R2.4 and prior. CISA is aware of cyber threat actors exploiting this zero-day authentication bypass vulnerability, which allows remote, unauthenticated execution of arbitrary commands, to conduct credential theft and data exfiltration. CISA added CVE-2026-104935 to its Known Exploited Vulnerabilities (KEV) Catalog on Oct. 13, 2026. CISA urges organizations with affected Ivanti Connect Secure appliances and deployments to immediately update to the latest version, as outlined in Ivanti’s Security Advisory Ivanti Connect Secure (CVE-2026-104935) . Organizations should also review the Ivanti Connect Secure 25.x Upgrade and Migration Compatibility Guide for detailed patching guidance for hardware and virtual appliance deployments. Ivanti Connect Secure version 22.8 reaches end of life on Jan. 31, 2027. Organizations seeking to determine whether they were compromised will need to conduct network and memory forensics to identify evidence of exploitation. Note: Ivanti’s Integrity Checker Tool may not detect evidence of exploitation of CVE-2026-104935 because threat actor commands execute in memory. If your organization suspects a compromise, CISA recommends implementing the following actions from Ivanti Connect Secure Recovery Procedures : Create a backup of the appliance configuration. Review Ivanti’s How 

**Extracted signals**
- CVEs: CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge, credential-theft
- Actions: fraud
- Sectors: manufacturing
- IP IOCs: 25.1.1.1, 25.1.2.2

### Hypotheses (3)

#### H-d0f754be-1 · Initial access via CVE-2026-104935 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-104935 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-104935.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d0f754be-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-104935 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-104935/ | summarize count() by src_ip, dst_host`
- **[H-d0f754be-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-104935 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-104935')) | summarize coverage = avg(installed) by host_role`
- **[H-d0f754be-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d0f754be-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d0f754be-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d0f754be-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('25.1.1.1','25.1.2.2') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d0f754be-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d0f754be-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d0f754be-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d0f754be-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge, credential-theft; impact: fraud; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d0f754be-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d0f754be-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d0f754be-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d0f754be-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 29. Eclipse Foundation Eclipse Milo

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 62
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 3 initial-access vector(s)=+11, 2 IOC(s)=+6

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to delete protected data, recover user credentials and impersonate legitimate users, or cause the server to stop responding to all clients. The following versions of Eclipse Foundation Eclipse Milo are affected: Eclipse Milo >=0.6.0| Eclipse Milo >=1.0.0| CVSS Vendor Equipment v3 8.2 Eclipse Foundation Eclipse Milo 5 Vulnerabilities Incorrect Authorization, Missing Release of Memory after Effective Lifetime, Missing Authorization, Observable Response Discrepancy, Missing Release of Resource after Effective Lifetime Background Critical Infrastructure Sectors: Chemical, Critical Manufacturing, Energy, Water and Wastewater Countries/Areas Deployed: Worldwide Company Headquarters Location: Belgium Vulnerabilities Expand All + CVE-2026-62927 In Eclipse Milo versions 1.0.0 through 1.1.4, the Call service dispatches the original mixed batch to address-space handlers after calculating authorization, allowing an anonymous or otherwise low-privileged client to execute a denied method by batching it with an allowed method. Read More 1 Affected Product Eclipse Foundation Eclipse Milo: >=1.0.0| Product Status: known_affected Remediations Vendor fix The Eclipse Foundation recommends users upgrade to Eclipse Milo 1.1.5 https://github.com/eclipse-milo/milo/releases/tag/v1.1.5. Mitigation For users on Milo 0.6.x, there are no 0.6.x releases with the fixes, which requires users to migrate to Milo 1.1.5 o

**Extracted signals**
- CVEs: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080, CVE-2026-63248, CVE-2026-60007, CVE-2026-61387
- Vectors: phishing, exploit, vpn-edge
- Sectors: energy, manufacturing, telecom
- Domain IOCs: opcuaserverconfig.copy, www.cisa.gov

### Hypotheses (3)

#### H-53d267ac-1 · Initial access via CVE-2026-62927 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-62927 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-62927.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-53d267ac-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-62927 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-62927/ | summarize count() by src_ip, dst_host`
- **[H-53d267ac-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-62927 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-62927')) | summarize coverage = avg(installed) by host_role`
- **[H-53d267ac-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-53d267ac-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-53d267ac-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('opcuaserverconfig.copy','www.cisa.gov') | summarize count() by client_ip`
- **[H-53d267ac-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-53d267ac-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-53d267ac-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-53d267ac-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-53d267ac-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-53d267ac-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-53d267ac-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-53d267ac-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-53d267ac-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 30. Siemens SIMATIC S7-1500 TM MFP

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

## 31. Moxa AIG-302 ThingsPro Edge

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-03>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 61
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13

> View CSAF Summary Successful exploitation of these vulnerabilities could allow an attacker to obtain and disclose sensitive information. The following versions of Moxa AIG-302 ThingsPro Edge are affected: Moxa AIG-302 ThingsPro Edge firmware CVSS Vendor Equipment v3 8.1 Moxa Moxa AIG-302 ThingsPro Edge firmware 2 Vulnerabilities Missing Authorization, Use of Hard-coded Cryptographic Key Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Water and Wastewater Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Taiwan Vulnerabilities Expand All + CVE-2026-109812 A missing authorization vulnerability exists in the internal API /api/v1/secrets/ for some of Moxa's industrial computing products. A privileged authenticated attacker with adjacent network access could exploit this vulnerability to access sensitive information, potentially resulting in the disclosure of confidential data, including cryptographic key material. Read More 1 Affected Product Moxa Moxa AIG-302 ThingsPro Edge firmware: Product Status: known_affected Remediations Mitigation Moxa has provided a fix for the vulnerability in v1.4.1. Users are encouraged to obtain and apply the update through one of the following methods: Mitigation If the AIG-302 has Internet access, login to the AIG-302 Web Console, go to Maintenance > Software Upgrades, and click Check for upgrades to check for and obtain the update. Mitigation Users can download the v1.4.1 patch manually from eit

**Extracted signals**
- CVEs: CVE-2026-109812, CVE-2026-109813
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-0d6c9f7f-1 · Initial access via CVE-2026-109812 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-109812 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-109812, CVE-2026-109813; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0d6c9f7f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-109812.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-0d6c9f7f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-109812 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-109812/ | summarize count() by src_ip, dst_host`
- **[H-0d6c9f7f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-109812 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-109812')) | summarize coverage = avg(installed) by host_role`
- **[H-0d6c9f7f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-0d6c9f7f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-0d6c9f7f-2 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-109812, CVE-2026-109813; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0d6c9f7f-2-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-0d6c9f7f-2-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-0d6c9f7f-2-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-0d6c9f7f-2-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

#### H-0d6c9f7f-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-109812, CVE-2026-109813; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-0d6c9f7f-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-0d6c9f7f-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-0d6c9f7f-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-0d6c9f7f-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-0d6c9f7f-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 32. Hitachi Energy MicroSCADA X SYS600 Product

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-04>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 3 CVE(s)=+30, 2 initial-access vector(s)=+9, 2 IOC(s)=+6

> View CSAF Summary Hitachi Energy is aware of multiple vulnerabilities that affect MicroSCADA X SYS600 product versions listed in this document. These vulnerabilities can be exploited to carry out various attacks on the product. Please refer to the Recommended Immediate Actions for information about the mitigation/remediation. The following versions of Hitachi Energy MicroSCADA X SYS600 Product are affected: MicroSCADA X SYS600 vers:MicroSCADA_X_SYS600/ CVSS Vendor Equipment v3 7.8 Hitachi Energy MicroSCADA X SYS600 2 Vulnerabilities Improper Neutralization of Formula Elements in a CSV File, Incorrect Implementation of Authentication Algorithm Background Critical Infrastructure Sectors: Energy Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2026-9852 A CSV injection vulnerability exists in SYS600. Injected malicious formulas can add or modify data to the spreadsheet, insert links, exfiltrate data, and in some cases, depending on how the user has their environment configured, execute malicious code on the user’s machine. To exploit this issue attackers would need a way to create arbitrary log messages. This could be achieved through normal functionality via SCIL scripts, a log injection vulnerability, or via the SYS600 broker. This vulnerability affects all Windows users regardless of their privilege level who can run the Notify service and export the log. Read More 1 Affected Product MicroSCADA X SYS600 versions 1

**Extracted signals**
- CVEs: CVE-2026-9852, CVE-2026-9853, CVE-2026-9854
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- IP IOCs: 2.1.7.5
- Domain IOCs: www.hitachienergy.com

### Hypotheses (3)

#### H-41397794-1 · Initial access via CVE-2026-9852 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-9852 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-9852, CVE-2026-9853, CVE-2026-9854; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-41397794-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-9852.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-41397794-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-9852 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-9852/ | summarize count() by src_ip, dst_host`
- **[H-41397794-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-9852 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-9852')) | summarize coverage = avg(installed) by host_role`
- **[H-41397794-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-41397794-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-41397794-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-9852, CVE-2026-9853, CVE-2026-9854; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-41397794-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.hitachienergy.com') | summarize count() by client_ip`
- **[H-41397794-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('2.1.7.5') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-41397794-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-41397794-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-41397794-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-41397794-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-9852, CVE-2026-9853, CVE-2026-9854; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-41397794-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-41397794-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-41397794-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-41397794-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 33. Thermo Fisher Torrent Suite Software

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-01>
- **Published**: Thu, 15 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-15T17:01:00+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to read arbitrary files on the Torrent Server. The following versions of Thermo Fisher Torrent Suite Software are affected: Torrent Suite Software CVSS Vendor Equipment v3 6.5 Thermo Fisher Torrent Suite Software 1 Vulnerability Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities CVE-2026-107777 The affected product is vulnerable to a path traversal, which could allow an authenticated attacker to read arbitrary files on the Torrent Server that are accessible to the web service account. Read More 1 Affected Product Thermo Fisher Torrent Suite Software: Product Status: known_affected Remediations Vendor fix Thermo Fisher has fixed the vulnerability and recommends users update Torrent Suite Software to version 5.22 or later. Mitigation For more information, refer to Thermo Fisher's Security bulletin. Additional Metrics Relevant CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') CVSS Version Base Score Base Severity Vector String 3.1 6.5 MEDIUM CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N 4.0 7.1 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N View CVE Details Acknowledgments Akanksha Raghvesh and Abhinav Agarwal reported this vulnerability

**Extracted signals**
- CVEs: CVE-2026-107777
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-faea1ddd-1 · Initial access via CVE-2026-107777 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-107777 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-107777.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-faea1ddd-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-107777 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-107777/ | summarize count() by src_ip, dst_host`
- **[H-faea1ddd-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-107777 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-107777')) | summarize coverage = avg(installed) by host_role`
- **[H-faea1ddd-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-faea1ddd-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-faea1ddd-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-faea1ddd-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-faea1ddd-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-faea1ddd-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-faea1ddd-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-faea1ddd-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-107777; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-faea1ddd-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-faea1ddd-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-faea1ddd-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-faea1ddd-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 34. Inductive Automation Ignition Software

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-286-01>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-14T00:09:50+00:00
- **Relevance score**: 60
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 IOC(s)=+4

> View CSAF Summary Successful exploitation of this vulnerability could allow an authenticated low-level user to escalate their privileges to a higher level. The following versions of Inductive Automation Ignition Software are affected: Ignition >=8.1.0| Ignition >=8.3.0| CVSS Vendor Equipment v3 8.8 Inductive Automation Ignition 1 Vulnerability Incorrect Authorization Background Critical Infrastructure Sectors: Critical Manufacturing, Energy, Information Technology Countries/Areas Deployed: Worldwide Company Headquarters Location: United States Vulnerabilities CVE-2026-92817 The Ignition Perspective module does not properly validate session privileges when determining Designer-level access. An authenticated user with access to a Vision project could provide their valid Vision session identifier and gain Designer-level privileges. An attacker could exploit these elevated privileges to execute arbitrary code in the context of the Ignition Gateway process. Read More 2 Affected Products Inductive Automation Ignition: >=8.1.0| Product Status: known_affected Remediations Mitigation Inductive Automation released version 8.3.9 in August 2025 and version 8.1.55 in September 2026 to address this issue. Users are recommended to update to the newest version available. Mitigation For more information, see the publication at the Inductive Automation Trust Center. Inductive Automation Ignition: >=8.3.0| Product Status: known_affected Remediations Mitigation Inductive Automation released vers

**Extracted signals**
- CVEs: CVE-2026-92817
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: energy, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-ecf019df-1 · Initial access via CVE-2026-92817 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-92817 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-92817.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ecf019df-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-92817 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-92817/ | summarize count() by src_ip, dst_host`
- **[H-ecf019df-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-92817 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-92817')) | summarize coverage = avg(installed) by host_role`
- **[H-ecf019df-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ecf019df-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ecf019df-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.cisa.gov') | summarize count() by client_ip`
- **[H-ecf019df-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ecf019df-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ecf019df-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ecf019df-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ecf019df-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-92817; vectors: phishing, exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ecf019df-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ecf019df-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ecf019df-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ecf019df-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 35. Siemens RUGGEDCOM APE1808 Devices

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

## 36. Siemens SIMATIC S7 PLCs Web Server

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

## 37. CISA Adds Four Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/14/cisa-adds-four-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 14 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-14T20:57:13+00:00
- **Relevance score**: 57
- **Score rationale**: source weight (advisory)=+15, 4 CVE(s)=+30, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-0322 Palo Alto Networks PAN-OS Code Injection Vulnerability CVE-2026-76519 Cisco Secure Email Gateway Relative Path Traversal Vulnerability CVE-2026-105133 Ahsay AhsayCBS Improper Authentication Vulnerability CVE-2026-105134 Ahsay AhsayCBS Command Injection Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue

**Extracted signals**
- CVEs: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, CVE-2026-105134
- Products: Palo Alto GlobalProtect
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-2c4da70b-1 · Initial access via CVE-2026-0322 affecting Palo Alto GlobalProtect  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-0322 in Palo Alto GlobalProtect within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-1-O1] Inventory exposure to Palo Alto GlobalProtect** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Palo Alto GlobalProtect, the external-exploitation hypothesis is disproven for CVE-2026-0322.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Palo Alto GlobalProtect' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-2c4da70b-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-0322 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-0322/ | summarize count() by src_ip, dst_host`
- **[H-2c4da70b-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-0322 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-0322')) | summarize coverage = avg(installed) by host_role`
- **[H-2c4da70b-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Palo Alto GlobalProtect hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-2c4da70b-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-2c4da70b-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-2c4da70b-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-2c4da70b-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-2c4da70b-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-2c4da70b-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-2c4da70b-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133; vectors: exploit, vpn-edge; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2c4da70b-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-2c4da70b-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-2c4da70b-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-2c4da70b-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 38. Panchan's Mining Island [Guest Diary], (Wed, Oct 14th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33426>
- **Published**: Thu, 15 Oct 2026 01:10:57 GMT
- **First seen**: 2026-10-15T01:35:08+00:00
- **Relevance score**: 56
- **Score rationale**: source weight (advisory)=+15, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 2 impact action(s)=+11, 7 IOC(s)=+15

> [This is a Guest Diary by Zachary Norwood, an ISC intern as part of the SANS.edu BACS program]

**Extracted signals**
- Vectors: exploit
- Actions: cryptomining, fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1110
- Domain IOCs: sans.edu, www.akamai.com, attack.mitre.org, developer.hashicorp.com, www.hashicorp.com, www.sans.edu, isc.sans.edu

### Hypotheses (3)

#### H-a7a13664-1 · Initial access via the disclosed vulnerability affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-a7a13664-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-a7a13664-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-a7a13664-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-a7a13664-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-a7a13664-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('sans.edu','www.akamai.com','attack.mitre.org') | summarize count() by client_ip`
- **[H-a7a13664-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-a7a13664-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-a7a13664-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-a7a13664-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-a7a13664-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: exploit; impact: cryptomining, fraud.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a7a13664-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-a7a13664-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-a7a13664-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-a7a13664-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 39. Ivanti Connect Secure zero-day exploited in the wild (CVE-2026-104935)

- **Source**: Rapid7
- **Link**: <https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935>
- **Published**: Tue, 13 Oct 2026 17:06:05 GMT
- **First seen**: 2026-10-13T17:27:47+00:00
- **Relevance score**: 54
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 2 initial-access vector(s)=+9, 1 product mention(s)=+3, 5 IOC(s)=+12

> Overview On October 13, 2026, Ivanti published a security advisory for CVE-2026-104935 , a high-severity authentication bypass by spoofing ( CWE-290 ) affecting Ivanti Connect Secure (ICS). The vulnerability has a CVSSv3.0 score of 8.6 and allows a remote, unauthenticated attacker to execute arbitrary commands. Ivanti reports that exploitation in the wild has already occurred prior to disclosure, affecting a limited number of customers. This indicates that exploitation has been occurring as a zero-day vulnerability. The U.S. Cybersecurity and Infrastructure Security Agency (CISA) confirms exploitation in the wild, and added CVE-2026-104935 to its Known Exploited Vulnerabilities (KEV) catalog on the same day as the vendor's public disclosure. The digital forensics firm Volexity has published a detailed blog post describing the threat actor activity, which was detected in early October 2026. Volexity notes that in addition to leveraging CVE-2026-104935 as a zero-day, the threat actor also leveraged an as-yet unpatched privilege escalation vulnerability which Ivanti are planning to patch at a later date. According to the vendor, a portion of the vulnerability was initially discovered through its product security program and patched in the July 2026 release of 25.1.3.0 . Exploitation occurred while Ivanti was working to backport the fix to the remaining supported versions. Ivanti Connect Secure is a popular enterprise VPN solution and naturally sits on the edge of a corporate env

**Extracted signals**
- CVEs: CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing
- IP IOCs: 25.1.3.0, 25.1.1.1, 25.1.1.2, 25.1.2.2, 25.1.3.1

### Hypotheses (3)

#### H-c8cfbaf1-1 · Initial access via CVE-2026-104935 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-104935 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-104935.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-c8cfbaf1-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-104935 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-104935/ | summarize count() by src_ip, dst_host`
- **[H-c8cfbaf1-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-104935 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-104935')) | summarize coverage = avg(installed) by host_role`
- **[H-c8cfbaf1-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-c8cfbaf1-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-c8cfbaf1-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-c8cfbaf1-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('25.1.3.0','25.1.1.1','25.1.1.2') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-c8cfbaf1-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-c8cfbaf1-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-c8cfbaf1-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-c8cfbaf1-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-c8cfbaf1-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-c8cfbaf1-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-c8cfbaf1-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-c8cfbaf1-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 40. Qilin and INC Ransomware Groups Exploit Palo Alto Networks Flaw to Bypass MFA

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/qilin-and-inc-ransomware-groups-exploit.html>
- **Published**: Tue, 20 Oct 2026 21:02:27 +0530
- **First seen**: 2026-10-20T16:50:44+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 2 initial-access vector(s)=+9, 1 impact action(s)=+8, 1 product mention(s)=+3

> Palo Alto Networks has disclosed that it's continuing to observe exploitation of a now-patched security flaw impacting PAN-OS and Prisma Access by ransomware actors. The activity relates to CVE-2026-0257 (CVSS score: 7.8), an authentication bypass flaw that could be exploited by bad actors to set up unauthorized VPN connections. It was patched by Palo Alto Networks in May 2026 and was

**Extracted signals**
- CVEs: CVE-2026-0257
- Products: Palo Alto GlobalProtect
- Vectors: exploit, vpn-edge
- Actions: ransomware
- MITRE ATT&CK: T1486

### Hypotheses (3)

#### H-d9bd97a8-1 · Initial access via CVE-2026-0257 affecting Palo Alto GlobalProtect  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-0257 in Palo Alto GlobalProtect within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-0257; vectors: exploit, vpn-edge; impact: ransomware; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d9bd97a8-1-O1] Inventory exposure to Palo Alto GlobalProtect** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Palo Alto GlobalProtect, the external-exploitation hypothesis is disproven for CVE-2026-0257.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Palo Alto GlobalProtect' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d9bd97a8-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-0257 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-0257/ | summarize count() by src_ip, dst_host`
- **[H-d9bd97a8-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-0257 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-0257')) | summarize coverage = avg(installed) by host_role`
- **[H-d9bd97a8-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Palo Alto GlobalProtect hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d9bd97a8-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d9bd97a8-2 · Post-foothold lateral movement consistent with the reported actor  _(confidence: medium)_

**Statement.** An attacker who matched the TTPs of the reported actor has moved laterally inside the estate using RDP/SMB/WinRM, admin tooling, or Kerberos abuse.

**Why this hypothesis?** Archetype 'lateral_movement' selected based on CVEs cited: CVE-2026-0257; vectors: exploit, vpn-edge; impact: ransomware; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1021.001, T1021.002, T1021.006, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d9bd97a8-2-O1] Anomalous remote logons (Type 3 / Type 10)** _(difficulty: medium · 200 pts · MITRE: T1021.001, T1021.002)_
  - Falsification criterion: If 4624 logon-type 3/10 events show no bursts from a single source to many destinations, lateral movement via RDP/SMB is unsupported.
  - Data sources: Windows Security event log, Domain Controller logs
  - Suggested query: `security | where event_id in (4624) and logon_type in (3,10) | summarize dests = dcount(dst_host) by src_user, src_host | where dests > 10`
- **[H-d9bd97a8-2-O2] Admin-tool usage outside baseline** _(difficulty: medium · 200 pts · MITRE: T1021.002, T1021.006, T1059)_
  - Falsification criterion: If PsExec / WMIC / PowerShell remoting / Impacket-style usage is absent outside known admin jump-hosts, the lateral-tool hypothesis is disproven.
  - Data sources: Sysmon EID 1, EDR, 4688
  - Suggested query: `process | where name in ('psexec.exe','psexesvc.exe','wmic.exe','wsmprovhost.exe') and host !in (admin_jumphosts)`
- **[H-d9bd97a8-2-O3] Kerberos abuse telemetry** _(difficulty: hard · 300 pts · MITRE: T1558.003, T1110.003)_
  - Falsification criterion: If 4769 ticket requests show no anomalous RC4 / odd-SPN patterns and no AS-REP roasting indicators, credential-based lateral movement is unsupported.
  - Data sources: Domain Controller security log
  - Suggested query: `security | where event_id == 4769 and ticket_encryption == 'RC4-HMAC' | summarize by target_spn, account_name`
- **[H-d9bd97a8-2-O4] Lateral file-copy staging** _(difficulty: medium · 200 pts · MITRE: T1570, T1021.002)_
  - Falsification criterion: If SMB writes of archives / executables across multiple hosts from one user/host are absent, lateral staging is unsupported.
  - Data sources: File-share auditing (5145), EDR file events
  - Suggested query: `file | where action == 'write' and ext in ('.7z','.rar','.zip','.exe') and dest matches /\\\\.*\\(C\$|admin\$)/`

#### H-d9bd97a8-3 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-0257; vectors: exploit, vpn-edge; impact: ransomware; products: Palo Alto GlobalProtect.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d9bd97a8-3-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d9bd97a8-3-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d9bd97a8-3-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d9bd97a8-3-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d9bd97a8-3-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

---

## 41. WAGO OS Linux

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-02>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 IOC(s)=+4

> View CSAF Summary Two vulnerabilities in the Web-Based Management (WBM) interface of WAGO CC100, PFC100 G2, PFC200 G2, TP600, Edge Controller and WP400 devices allow an authenticated low-privileged user to bypass intended privilege boundaries. The issues affect both the routing configuration functionality and the authorization model for PROFIBUS configuration management. The following versions of WAGO OS Linux are affected: WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| WAGO Firmware (vers:semver/>=1.0.0| CVSS Vendor Equipment v3 8.8 WAGO WAGO Firmware (vers:semver/>=1.0.0| 2 Vulnerabilities Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'), Missing Authorization Background Critical Infrastructure Sectors: Chemical, Critical Manufacturing, 

**Extracted signals**
- CVEs: CVE-2026-80466, CVE-2026-88850
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.wago.com

### Hypotheses (3)

#### H-30d4b1f4-1 · Initial access via CVE-2026-80466 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-80466 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-80466, CVE-2026-88850; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-30d4b1f4-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-80466.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-30d4b1f4-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-80466 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-80466/ | summarize count() by src_ip, dst_host`
- **[H-30d4b1f4-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-80466 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-80466')) | summarize coverage = avg(installed) by host_role`
- **[H-30d4b1f4-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-30d4b1f4-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-30d4b1f4-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-80466, CVE-2026-88850; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-30d4b1f4-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('www.wago.com') | summarize count() by client_ip`
- **[H-30d4b1f4-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-30d4b1f4-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-30d4b1f4-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-30d4b1f4-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-30d4b1f4-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-80466, CVE-2026-88850; vectors: exploit, vpn-edge.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-30d4b1f4-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-30d4b1f4-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-30d4b1f4-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-30d4b1f4-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 42. AhsayCBS Flaws Exploited to Deploy Web Shells Get New Fixes After Incomplete Patches

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/ahsaycbs-flaws-exploited-to-deploy-web.html>
- **Published**: Thu, 15 Oct 2026 12:13:08 +0530
- **First seen**: 2026-10-15T09:36:50+00:00
- **Relevance score**: 53
- **Score rationale**: source weight (news)=+5, 2 CVE(s)=+25, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 impact action(s)=+8

> Singapore-based Ahsay Backup has released security updates to address two security flaws in AhsayCBS that have been exploited by bad actors to drop web shells and XMRig cryptocurrency miners. The vulnerabilities in question are CVE-2026-105133 and CVE-2026-105134, which could be chained to sidestep authentication and execute arbitrary commands on affected systems. In a report published earlier

**Extracted signals**
- CVEs: CVE-2026-105133, CVE-2026-105134
- Vectors: exploit
- Actions: cryptomining
- MITRE ATT&CK: T1505.003

### Hypotheses (3)

#### H-d6860c3f-1 · Initial access via CVE-2026-105133 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-105133 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-105133.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-d6860c3f-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-105133 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-105133/ | summarize count() by src_ip, dst_host`
- **[H-d6860c3f-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-105133 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-105133')) | summarize coverage = avg(installed) by host_role`
- **[H-d6860c3f-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-d6860c3f-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-d6860c3f-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-d6860c3f-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-d6860c3f-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-d6860c3f-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-d6860c3f-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-d6860c3f-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-105133, CVE-2026-105134; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d6860c3f-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-d6860c3f-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-d6860c3f-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-d6860c3f-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 43. CISA Adds Six Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/20/cisa-adds-six-known-exploited-vulnerabilities-catalog>
- **Published**: Tue, 20 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-20T20:51:44+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 6 CVE(s)=+30, 1 initial-access vector(s)=+7

> CISA has added six new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-96652 Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability CVE-2026-96654 Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability CVE-2026-96655 Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability CVE-2026-96656 Plex Media Server External Control of File Name or Path Vulnerability CVE-2026-106931 EG Secure Solutions SiteGuard Server Edition OS Command Injection Vulnerability CVE-2026-110936 Siemens Software Center Uncontrolled Search Path Element Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors

**Extracted signals**
- CVEs: CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656, CVE-2026-106931, CVE-2026-110936
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-9c29f626-1 · Initial access via CVE-2026-96652 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96652 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96652, CVE-2026-96654, CVE-2026-96655; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9c29f626-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-96652.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9c29f626-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96652 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96652/ | summarize count() by src_ip, dst_host`
- **[H-9c29f626-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96652 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96652')) | summarize coverage = avg(installed) by host_role`
- **[H-9c29f626-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9c29f626-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9c29f626-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96652, CVE-2026-96654, CVE-2026-96655; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9c29f626-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-9c29f626-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9c29f626-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9c29f626-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9c29f626-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9c29f626-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96652, CVE-2026-96654, CVE-2026-96655; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9c29f626-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-9c29f626-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-9c29f626-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-9c29f626-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 44. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Fri, 16 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-16T19:02:39+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2025-61624 Fortinet Multiple Products Path Traversal Vulnerability CVE-2026-102764 BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not curren

**Extracted signals**
- CVEs: CVE-2025-61624, CVE-2026-102764
- Products: Fortinet FortiOS
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-fd52c4f3-1 · Initial access via CVE-2025-61624 affecting Fortinet FortiOS  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2025-61624 in Fortinet FortiOS within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-1-O1] Inventory exposure to Fortinet FortiOS** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Fortinet FortiOS, the external-exploitation hypothesis is disproven for CVE-2025-61624.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Fortinet FortiOS' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-fd52c4f3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2025-61624 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2025-61624/ | summarize count() by src_ip, dst_host`
- **[H-fd52c4f3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2025-61624 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2025-61624')) | summarize coverage = avg(installed) by host_role`
- **[H-fd52c4f3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Fortinet FortiOS hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-fd52c4f3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-fd52c4f3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-fd52c4f3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-fd52c4f3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-fd52c4f3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-fd52c4f3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-fd52c4f3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2025-61624, CVE-2026-102764; vectors: exploit, vpn-edge; products: Fortinet FortiOS.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fd52c4f3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-fd52c4f3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-fd52c4f3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-fd52c4f3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 45. CISA Adds Two Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-adds-two-known-exploited-vulnerabilities-catalog>
- **Published**: Tue, 13 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-13T20:48:54+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (advisory)=+15, 2 CVE(s)=+25, 2 initial-access vector(s)=+9, 1 product mention(s)=+3

> CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-96951 Microsoft Windows Command Injection Vulnerability CVE-2026-104935 Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 26-04: Prioritizing Security Updates Based on Risk establishes vulnerability management requirements for Federal Civilian Executive Branch (FCEB) agencies. BOD 26-04 reinforces the importance of the KEV Catalog and requires federal agencies to prioritize rapid remediation of high-risk vulnerabilities, specifically those identified by Common Vulnerabilities and Exposures (CVEs) listed in CISA’s KEV Catalog on publicly exposed assets that grant total control of the asset post-exploitation, while deferring action for lower-risk vulnerabilities. BOD 26-04 further establishes basic expectations for when agencies must check whether threat actors compromised the system before the patch was applied. While BOD 26-04 applies only to FCEB agencies, CISA encourages all organizations to adopt risk-based vulnerability management and prioritize remediation of KEV Catalog vulnerabilities . CISA will continue to add vulnerabilities to the catalog that meet the specified criteria . Aware of an exploited vulnerability not currently listed 

**Extracted signals**
- CVEs: CVE-2026-96951, CVE-2026-104935
- Products: Ivanti Connect Secure
- Vectors: exploit, vpn-edge
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-8786243a-1 · Initial access via CVE-2026-96951 affecting Ivanti Connect Secure  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-96951 in Ivanti Connect Secure within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8786243a-1-O1] Inventory exposure to Ivanti Connect Secure** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Ivanti Connect Secure, the external-exploitation hypothesis is disproven for CVE-2026-96951.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Ivanti Connect Secure' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-8786243a-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-96951 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-96951/ | summarize count() by src_ip, dst_host`
- **[H-8786243a-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-96951 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-96951')) | summarize coverage = avg(installed) by host_role`
- **[H-8786243a-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Ivanti Connect Secure hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-8786243a-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-8786243a-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-8786243a-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-8786243a-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-8786243a-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-8786243a-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-8786243a-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-8786243a-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-96951, CVE-2026-104935; vectors: exploit, vpn-edge; products: Ivanti Connect Secure.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8786243a-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-8786243a-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-8786243a-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-8786243a-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 46. Attackers Exploit AhsayCBS Flaws to Deploy XMRig Miners Disguised as Microsoft Edge

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/10/attackers-exploit-ahsaycbs-flaws-to.html>
- **Published**: Fri, 09 Oct 2026 18:17:26 +0530
- **First seen**: 2026-10-09T14:58:26+00:00
- **Relevance score**: 52
- **Score rationale**: source weight (news)=+5, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 IOC(s)=+4

> Threat actors have been observed exploiting two recently disclosed flaws in the AhsayCBS backup utility to seize control of affected devices and deploy web shells and XMRig cryptocurrency miners. Details of the flaws are below - CVE-2026-105133 (CVSS v4 score: 5.5) - An improper authentication vulnerability in the checkSysPwd() function in the "com/ahsay/obs/api/ApiStructsAction.java"

**Extracted signals**
- CVEs: CVE-2026-105133
- Vectors: exploit
- Actions: cryptomining
- Sectors: energy
- MITRE ATT&CK: T1505.003
- Domain IOCs: apistructsaction.java

### Hypotheses (3)

#### H-5dc3760d-1 · Initial access via CVE-2026-105133 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-105133 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-105133.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-5dc3760d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-105133 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-105133/ | summarize count() by src_ip, dst_host`
- **[H-5dc3760d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-105133 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-105133')) | summarize coverage = avg(installed) by host_role`
- **[H-5dc3760d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-5dc3760d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-5dc3760d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('apistructsaction.java') | summarize count() by client_ip`
- **[H-5dc3760d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-5dc3760d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-5dc3760d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-5dc3760d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-5dc3760d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-105133; vectors: exploit; impact: cryptomining.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5dc3760d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-5dc3760d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-5dc3760d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-5dc3760d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 47. Parasitizing trust: How legitimate infrastructure becomes a delivery pipeline for attackers

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/parasitizing-trust-how-legitimate-infrastructure-becomes-a-delivery-pipeline-for-attackers/>
- **Published**: Wed, 21 Oct 2026 10:00:00 GMT
- **First seen**: 2026-10-21T10:17:21+00:00
- **Relevance score**: 51
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 2 product mention(s)=+6, 2 IOC(s)=+6

> Adversaries are turning the tools businesses trust into delivery mechanisms for malicious activity. Cisco Talos observed abuse of more than 25 legitimate platforms over the past year, exploiting the built-in trust of collaboration, file-sharing, payment and other services to reach their targets.

**Extracted signals**
- Products: Microsoft Exchange, Microsoft 365 / Entra ID
- Vectors: phishing, exploit, credential-theft, social-engineering
- Actions: fraud
- Sectors: manufacturing, retail, telecom
- MITRE ATT&CK: T1566
- Domain IOCs: orders.staples.com, order.dell.com

### Hypotheses (3)

#### H-9b28c0e3-1 · Initial access via the disclosed vulnerability affecting Microsoft Exchange  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9b28c0e3-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-9b28c0e3-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-9b28c0e3-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-9b28c0e3-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-9b28c0e3-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-9b28c0e3-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-9b28c0e3-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('orders.staples.com','order.dell.com') | summarize count() by client_ip`
- **[H-9b28c0e3-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-9b28c0e3-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-9b28c0e3-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-9b28c0e3-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-9b28c0e3-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, credential-theft; impact: fraud; products: Microsoft Exchange, Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9b28c0e3-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-9b28c0e3-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-9b28c0e3-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-9b28c0e3-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 48. CISA Urges Patching Critical Vulnerability in BeyondTrust Remote Support

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/10/16/cisa-urges-patching-critical-vulnerability-beyondtrust-remote-support>
- **Published**: Fri, 16 Oct 26 12:00:00 +0000
- **First seen**: 2026-10-16T21:44:58+00:00
- **Relevance score**: 50
- **Score rationale**: source weight (advisory)=+15, 1 CVE(s)=+20, 1 MITRE technique hit(s)=+8, 1 initial-access vector(s)=+7

> CISA is aware of critical authentication bypass vulnerability CVE-2026-102764 , affecting BeyondTrust Remote Support (formerly Bomgar) versions 26.2.3 and earlier. Patches are available for supported versions (24.3.1 and later); organizations using older versions must upgrade first. Cyber threat actors are actively exploiting the vulnerability to gain initial access, then establishing persistence, escalating privileges, and moving laterally. CISA added CVE-2026-102764 to its Known Exploited Vulnerabilities (KEV) catalog on Oct. 16, 2026. CISA urges organizations with affected self-hosted Remote Support appliances to immediately take the following actions: Apply the BT26-05-RS patch, as outlined in BeyondTrust’s Security Advisory BT26-05 . Organizations on a self-hosted Remote Support version older than 24.3.1 will need to upgrade to a newer version to apply the patch. Organizations using BeyondTrust-hosted (SaaS) Remote Support deployments have already been patched. Review BeyondTrust’s blog ARMORY CASTLE and BT26-05: What Security Teams Need to Know for detailed information on the vulnerability and recommended response and mitigation actions. Limit external access to the Remote Support appliance to the services needed to support users and customers. Restrict access to administrative interfaces to trusted networks. Review BeyondTrust’s B Series Appliance on-premises security for additional guidance on securing network connectivity for self-hosted Remote Support appliances. Or

**Extracted signals**
- CVEs: CVE-2026-102764
- Vectors: exploit
- Sectors: manufacturing
- MITRE ATT&CK: T1219

### Hypotheses (3)

#### H-40c2793d-1 · Initial access via CVE-2026-102764 affecting the affected product/service  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2026-102764 in the affected product/service within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-1-O1] Inventory exposure to the affected product** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of the affected product, the external-exploitation hypothesis is disproven for CVE-2026-102764.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'the affected product' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-40c2793d-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2026-102764 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2026-102764/ | summarize count() by src_ip, dst_host`
- **[H-40c2793d-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2026-102764 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2026-102764')) | summarize coverage = avg(installed) by host_role`
- **[H-40c2793d-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on the affected product hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-40c2793d-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-40c2793d-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-40c2793d-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-40c2793d-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-40c2793d-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-40c2793d-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-40c2793d-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2026-102764; vectors: exploit.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-40c2793d-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-40c2793d-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-40c2793d-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-40c2793d-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 49. There's only so much code: the rise in vulnerability numbers

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/theres-only-so-much-code-the-rise-in-vulnerability-numbers/>
- **Published**: Tue, 20 Oct 2026 15:31:22 GMT
- **First seen**: 2026-10-20T16:10:43+00:00
- **Relevance score**: 48
- **Score rationale**: source weight (vendor)=+10, 1 CVE(s)=+20, 1 initial-access vector(s)=+7, 1 impact action(s)=+8, 1 product mention(s)=+3

> The September Microsoft Tuesday release included 975 vulnerability advisories. This month, 1,415 vulnerabilities were just dropped. Compared to a pre-June average of 100 a month, that increase is staggering. Where did they come from? And what does the future look like?

**Extracted signals**
- CVEs: CVE-2021-44228
- Products: Microsoft Exchange
- Vectors: exploit
- Actions: fraud
- Sectors: energy, manufacturing

### Hypotheses (3)

#### H-ee228c55-1 · Initial access via CVE-2021-44228 affecting Microsoft Exchange  _(confidence: high)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting CVE-2021-44228 in Microsoft Exchange within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on CVEs cited: CVE-2021-44228; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ee228c55-1-O1] Inventory exposure to Microsoft Exchange** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft Exchange, the external-exploitation hypothesis is disproven for CVE-2021-44228.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft Exchange' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-ee228c55-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for CVE-2021-44228 in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-CVE-2021-44228/ | summarize count() by src_ip, dst_host`
- **[H-ee228c55-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the CVE-2021-44228 fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('CVE-2021-44228')) | summarize coverage = avg(installed) by host_role`
- **[H-ee228c55-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft Exchange hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-ee228c55-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-ee228c55-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: medium)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on CVEs cited: CVE-2021-44228; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ee228c55-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('the published C2 domains') | summarize count() by client_ip`
- **[H-ee228c55-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-ee228c55-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-ee228c55-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-ee228c55-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-ee228c55-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on CVEs cited: CVE-2021-44228; vectors: exploit; impact: fraud; products: Microsoft Exchange.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ee228c55-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-ee228c55-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-ee228c55-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-ee228c55-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---

## 50. The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

- **Source**: Microsoft Security
- **Link**: <https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/>
- **Published**: Wed, 14 Oct 2026 13:00:00 +0000
- **First seen**: 2026-10-14T13:32:49+00:00
- **Relevance score**: 48
- **Score rationale**: source weight (vendor)=+10, 1 MITRE technique hit(s)=+8, 4 initial-access vector(s)=+13, 1 impact action(s)=+8, 1 product mention(s)=+3, 2 IOC(s)=+6

> Microsoft uncovered a Chinese-language cybercriminal ecosystem, an interconnected network of phishing kit operators (tracked as Storm-2990), and an illicit marketplace (tracked as Storm-3119) selling tools and infrastructure for large-scale phishing. In collaboration with law enforcement agencies and other partners worldwide, Microsoft’s Digital Crimes Unit (DCU) facilitated a disruption of the ecosystem. The post The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime appeared first on Microsoft Security Blog .

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing, exploit, cloud-misconfig, social-engineering
- Actions: fraud
- Sectors: healthcare, finance, government, manufacturing, education, retail
- MITRE ATT&CK: T1566
- Domain IOCs: appcatalog.readwrite.all, jewishchoice.org

### Hypotheses (3)

#### H-580c9660-1 · Initial access via the disclosed vulnerability affecting Microsoft 365 / Entra ID  _(confidence: medium)_

**Statement.** A threat actor has attempted to obtain initial access to our environment by exploiting the disclosed vulnerability in Microsoft 365 / Entra ID within the last 30 days.

**Why this hypothesis?** Archetype 'initial_access_cve' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1190, T1133

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-580c9660-1-O1] Inventory exposure to Microsoft 365 / Entra ID** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If zero internet-facing assets run a vulnerable build of Microsoft 365 / Entra ID, the external-exploitation hypothesis is disproven for the referenced CVE.
  - Data sources: Asset CMDB, External attack-surface scanner, Vulnerability scanner
  - Suggested query: `asset_inventory | where product == 'Microsoft 365 / Entra ID' and exposure == 'internet' and version in (vulnerable_versions)`
- **[H-580c9660-1-O2] Hunt for exploit attempts at the edge** _(difficulty: medium · 200 pts · MITRE: T1190, T1133)_
  - Falsification criterion: If WAF / firewall / IDS show no exploit-signature hits for the referenced CVE in the last 30 days, in-the-wild exploitation against us is unsupported.
  - Data sources: WAF logs, IDS/IPS, Edge firewall, CDN logs
  - Suggested query: `edge_logs | where signature contains 'CVE' or uri matches /exploit-pattern-for-the referenced CVE/ | summarize count() by src_ip, dst_host`
- **[H-580c9660-1-O3] Patch-status correlation** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If MDM / patch-management shows 100% deployment of the the referenced CVE fix across exposed hosts, the hypothesis is disproven by remediation.
  - Data sources: SCCM/Intune, Patch management, Tanium / Kandji
  - Suggested query: `patch_state | where kb in (fixes_for('the referenced CVE')) | summarize coverage = avg(installed) by host_role`
- **[H-580c9660-1-O4] Post-exploit web-shell sweep** _(difficulty: medium · 250 pts · MITRE: T1505.003, T1059)_
  - Falsification criterion: If a sweep of webroots and IIS/Apache process trees finds no anomalous children (cmd, powershell, /bin/sh) on Microsoft 365 / Entra ID hosts, post-exploit foothold is unsupported.
  - Data sources: EDR process telemetry, File integrity monitoring
  - Suggested query: `process | where parent in ('w3wp.exe','httpd','nginx','java') and child in ('cmd.exe','powershell.exe','/bin/sh','/bin/bash')`
- **[H-580c9660-1-O5] Honeypot / canary check** _(difficulty: hard · 300 pts · MITRE: T1190)_
  - Falsification criterion: If exposed canary instances of the same product show no probing or exploitation telemetry, opportunistic mass-exploitation against the org is unlikely.
  - Data sources: Honeypot logs, Canary tokens
  - Suggested query: `canary_events | where product == '<product>' | where event_type in ('probe','exploit') | summarize by src_ip`

#### H-580c9660-2 · Outbound C2 beaconing to reported infrastructure  _(confidence: high)_

**Statement.** Hosts in the estate are beaconing to the command-and-control infrastructure reported in this article (domains, IPs, TLS fingerprints, or RMM tooling).

**Why this hypothesis?** Archetype 'c2_beacon' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1071, T1573, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-580c9660-2-O1] DNS resolution sweep for published C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If recursive DNS logs show zero resolutions for the IOC domains in the last 90 days, active beaconing is disproven.
  - Data sources: DNS resolver logs, Passive DNS
  - Suggested query: `dns | where query in ('appcatalog.readwrite.all','jewishchoice.org') | summarize count() by client_ip`
- **[H-580c9660-2-O2] Egress connections to published C2 IPs** _(difficulty: medium · 200 pts · MITRE: T1071, T1573)_
  - Falsification criterion: If proxy / firewall egress logs show no connections to the IOC IPs or matching ASNs, network-level C2 is unsupported.
  - Data sources: Proxy logs, NetFlow, Firewall accept logs
  - Suggested query: `egress | where dst_ip in ('the published C2 IPs') | summarize bytes_out = sum(bytes_sent) by src_ip`
- **[H-580c9660-2-O3] Beacon periodicity / jitter analysis** _(difficulty: hard · 300 pts · MITRE: T1071, T1095)_
  - Falsification criterion: If beacon-style periodic outbound connections (low jitter, small payloads) to uncategorised destinations are absent, covert C2 is unlikely.
  - Data sources: NetFlow, Zeek conn.log
  - Suggested query: `conn | summarize stddev_interval = stdev(diff(ts)), count() by src_ip, dst_host | where count() > 50 and stddev_interval < 5s`
- **[H-580c9660-2-O4] TLS / JA3 fingerprint pivot** _(difficulty: hard · 250 pts · MITRE: T1573.002)_
  - Falsification criterion: If JA3/JA3S fingerprints associated with the reported family are absent in TLS telemetry, encrypted C2 attribution is weakened.
  - Data sources: Zeek ssl.log, Suricata TLS, NDR
  - Suggested query: `tls | where ja3 in (ti_lookup('family','ja3')) | summarize by src_ip, sni`
- **[H-580c9660-2-O5] Remote-monitoring tooling abuse check** _(difficulty: medium · 200 pts · MITRE: T1219)_
  - Falsification criterion: If unmanaged AnyDesk / TeamViewer / ScreenConnect / Atera installs are absent, RMM-based C2 is disproven.
  - Data sources: EDR installed-software, Process telemetry
  - Suggested query: `process | where name in ('anydesk.exe','teamviewer.exe','screenconnect.exe','atera*.exe') and signer != 'corp_managed'`

#### H-580c9660-3 · Identity compromise of privileged users  _(confidence: medium)_

**Statement.** Privileged identities have been compromised through phishing, MFA fatigue, help-desk social engineering, or OAuth illicit-consent grants.

**Why this hypothesis?** Archetype 'identity_compromise' selected based on vectors: phishing, exploit, cloud-misconfig; impact: fraud; products: Microsoft 365 / Entra ID.

**MITRE ATT&CK**: T1078, T1621, T1528, T1556

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-580c9660-3-O1] Impossible-travel / atypical sign-ins** _(difficulty: easy · 100 pts · MITRE: T1078.004)_
  - Falsification criterion: If Entra ID / Okta risky-sign-in detections show no impossible-travel hits on privileged identities, account compromise is unsupported.
  - Data sources: Entra ID sign-in logs, Okta system log
  - Suggested query: `signin | where risk_level in ('high','medium') and user in (privileged_users) | summarize by country, ip`
- **[H-580c9660-3-O2] MFA-fatigue / push-bombing** _(difficulty: medium · 200 pts · MITRE: T1621, T1078)_
  - Falsification criterion: If MFA telemetry shows no bursts of denied pushes followed by a successful one for the same user, MFA-fatigue compromise is disproven.
  - Data sources: MFA provider logs (Duo / Entra)
  - Suggested query: `mfa | summarize denies = countif(result=='deny'), accepts = countif(result=='accept') by user, bin(ts,1h) | where denies > 5 and accepts > 0`
- **[H-580c9660-3-O3] Help-desk social-engineering pivot** _(difficulty: hard · 250 pts · MITRE: T1078, T1556)_
  - Falsification criterion: If ticketing / call-recording shows no recent password-reset or MFA-reset requests for privileged users without proper verification, help-desk vector is unsupported.
  - Data sources: ITSM ticket data, Help-desk recordings
  - Suggested query: `tickets | where action in ('password_reset','mfa_reset') and target in (privileged_users) | join (verifications) on ticket_id`
- **[H-580c9660-3-O4] OAuth illicit-consent grants** _(difficulty: medium · 200 pts · MITRE: T1528)_
  - Falsification criterion: If Entra/Workspace audit logs show no recently consented third-party apps with high-impact scopes, OAuth abuse is disproven.
  - Data sources: Entra ID audit log, Google Workspace audit
  - Suggested query: `audit | where action == 'Consent to application' and scopes contains 'Mail.Read' or 'files.read.all'`

---
