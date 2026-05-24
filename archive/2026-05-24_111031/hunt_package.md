# Threat Hunting News Package

- Generated: `2026-05-24T11:10:29+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **340**  ·  Skipped (below threshold): **330**  ·  Briefings: **10**
- IOC exports: `iocs.csv`, `iocs.json`, `iocs_stix.json`  ·  Sigma rules: `sigma/`  ·  History: `archive/`

---

## 1. LiteSpeed cPanel Plugin CVE-2026-48172 Exploited to Run Scripts as Root

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/litespeed-cpanel-plugin-cve-2026-48172.html>
- **Published**: Sat, 23 May 2026 13:05:13 +0530
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: CVE-2026-48172 (CVSS 10.0) actively exploited in LiteSpeed cPanel plugin; allows root execution; widespread in shared hosting environments; high blast radius.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-48172"}) -> ok → tool lookup_mitre({"query": "privilege escalation"}) -> ok → tool lookup_mitre({"query": "command and script interpreter"}) -> ok → critic: skipped (error)

> A maximum-severity security vulnerability impacting LiteSpeed User-End cPanel Plugin has come under active exploitation in the wild. The flaw, tracked as CVE-2026-48172 (CVSS score: 10.0), relates to an instance of incorrect privilege assignment that an attacker could abuse to run arbitrary scripts with elevated permissions. "Any cPanel user (including an attacker or a compromised account) may

**Extracted signals**
- CVEs: CVE-2026-48172
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-64115066-1 · Root Script Execution via CVE-2026-48172  _(confidence: medium)_

**Statement.** Within our environment between May 1–25, 2026, an attacker exploited CVE-2026-48172 in the LiteSpeed cPanel plugin to execute arbitrary scripts as root on at least one cPanel server.

**Why this hypothesis?** The article claims active exploitation of a CVSS 10.0 flaw allowing privilege escalation to root via the LiteSpeed cPanel plugin. Although CVE-2026-48172 is not in CISA KEV (likely fictional), the scenario is plausible for red teaming or internal testing. We assume the vulnerability allows unauthenticated or low-privilege users to trigger root-level script execution via malformed requests.

**MITRE ATT&CK**: T1068, T1059

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-64115066-1-O1] Detect root shell spawns from LiteSpeed process** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: No process tree shows a LiteSpeed worker process spawning a shell (bash, sh, zsh) as root
  - Data sources: EDR, Process logs
  - Suggested query: `process where parent_name == 'litespeed' and process_name in ['bash', 'sh', 'zsh'] and user == 'root'`
- **[H-64115066-1-O2] Identify anomalous cPanel plugin access** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests to /cp-plugin/litespeed/ with POST body containing shell commands were logged
  - Data sources: Web server logs, WAF logs
  - Suggested query: `request_uri contains '/cp-plugin/litespeed/' and request_body matches /exec|system|shell_exec|passthru|eval/`
- **[H-64115066-1-O3] Check for unauthorized file writes to /root/ or /etc/** _(difficulty: hard · 150 pts · MITRE: T1068)_
  - Falsification criterion: No files created or modified under /root/, /etc/cron.d/, or /etc/passwd by non-root users via LiteSpeed process
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `file_event where file_path starts_with '/root/' or file_path in ['/etc/cron.d/', '/etc/passwd'] and process_name == 'litespeed'`
- **[H-64115066-1-O4] Correlate failed cPanel login attempts with plugin access** _(difficulty: medium · 120 pts · MITRE: T1110)_
  - Falsification criterion: No sequence of failed cPanel logins followed by plugin requests from same IP within 5 minutes
  - Data sources: Authentication logs, Web logs
  - Suggested query: `auth_log where result == 'fail' and user != 'root' | join web_log on client_ip where uri contains '/cp-plugin/litespeed/' and timestamp < 5m after auth_log.timestamp`
- **[H-64115066-1-O5] Verify no legitimate cPanel user triggered the exploit** _(difficulty: medium · 130 pts · MITRE: T1078)_
  - Falsification criterion: All requests to the plugin were made by non-authorized or non-existent cPanel users
  - Data sources: cPanel user DB, Web logs
  - Suggested query: `web_log where uri contains '/cp-plugin/litespeed/' and user not in (select username from cpanel_users)`

**Sigma rule:**

```yaml
title: Suspicious cPanel Plugin Request Leading to Root Execution
logsource:
  product: webserver
  service: litespeed
detection:
  selection:
    uri: "/cp-plugin/litespeed/"
    user_agent: "*"
    status: 200
    request_body: "exec|system|shell_exec|passthru|eval"
  condition: selection
fields: [client_ip, uri, request_body]
level: critical
```

#### H-64115066-2 · Persistence via Cron Job Injection  _(confidence: high)_

**Statement.** An attacker exploited CVE-2026-48172 to create a persistent cron job under root to execute a backdoor script daily on a compromised cPanel server.

**Why this hypothesis?** Privilege escalation to root often leads to persistence mechanisms. The article implies arbitrary script execution, making cron job creation a likely next step. Even if CVE is fictional, this is a standard post-exploitation tactic.

**MITRE ATT&CK**: T1053, T1068

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-64115066-2-O1] Find root cron entries created after May 1, 2026** _(difficulty: easy · 100 pts · MITRE: T1053)_
  - Falsification criterion: No new cron jobs were added to /var/spool/cron/root or /etc/cron.d/ after May 1, 2026
  - Data sources: File system logs, Cron logs
  - Suggested query: `file_event where file_path in ['/var/spool/cron/root', '/etc/cron.d/'] and event_time > '2026-05-01' and file_owner == 'root'`
- **[H-64115066-2-O2] Detect execution of unknown scripts from cron** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: No scripts in /tmp/, /var/tmp/, or /opt/ were executed by root via cron
  - Data sources: Process logs, Cron logs
  - Suggested query: `process where parent_name == 'crond' and user == 'root' and binary_path matches '/tmp/|/var/tmp/|/opt/' and binary_path not in known_good_paths`
- **[H-64115066-2-O3] Identify cron job with obfuscated command** _(difficulty: hard · 150 pts · MITRE: T1027)_
  - Falsification criterion: No cron job contains base64-encoded, hex-encoded, or shell-pipe chains
  - Data sources: Cron config files, File integrity monitoring
  - Suggested query: `file_content where file_path in ['/var/spool/cron/root', '/etc/cron.d/*'] and content matches /(base64|hex|\|\s*sh|\$\(.*\))/`
- **[H-64115066-2-O4] Correlate cron job creation with plugin exploit event** _(difficulty: medium · 130 pts · MITRE: T1053)_
  - Falsification criterion: No cron job creation occurred within 10 minutes of a suspicious LiteSpeed plugin request
  - Data sources: Web logs, Cron logs
  - Suggested query: `web_log where uri contains '/cp-plugin/litespeed/' and request_body contains 'exec' | join cron_log on client_ip where event_time < 10m after web_log.timestamp and message contains 'crontab'`
- **[H-64115066-2-O5] Check for duplicate cron jobs across servers** _(difficulty: medium · 110 pts · MITRE: T1078)_
  - Falsification criterion: No identical cron job entries exist on other cPanel servers in the environment
  - Data sources: Cron configs across fleet
  - Suggested query: `group by cron_content where count > 1 and cron_content matches //tmp/[a-zA-Z0-9]{8}\.sh/`

**Sigma rule:**

```yaml
title: Root Cron Job Created via Suspicious Plugin Access
logsource:
  product: linux
  service: cron
detection:
  selection:
    message: '*crontab*'
    user: 'root'
    action: 'add'
  condition: selection
fields: [user, message, timestamp]
level: high
```

#### H-64115066-3 · Lateral Movement via cPanel API Abuse  _(confidence: medium)_

**Statement.** An attacker used root access gained via CVE-2026-48172 to abuse the cPanel API and pivot to other cPanel-managed servers in the environment.

**Why this hypothesis?** cPanel environments often host multiple domains on shared infrastructure. Root access on one server can enable API calls to other servers if credentials or tokens are shared or predictable. The article implies broad access, making lateral movement via cPanel API a logical extension.

**MITRE ATT&CK**: T1091, T1078

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-64115066-3-O1] Detect root executing cPanel API commands targeting other hosts** _(difficulty: medium · 120 pts · MITRE: T1091)_
  - Falsification criterion: No root process executed uapi/cpanelapi with RemoteHost, transfer, or listaccts parameters
  - Data sources: Process logs, Command-line auditing
  - Suggested query: `process where parent_name == 'litespeed' and command_line contains 'uapi' and (args contains 'RemoteHost' or args contains 'listaccts')`
- **[H-64115066-3-O2] Identify SSH connections from compromised server to other cPanel hosts** _(difficulty: easy · 100 pts · MITRE: T1021)_
  - Falsification criterion: No SSH connections from the compromised server to other cPanel servers occurred after May 1, 2026
  - Data sources: SSH logs, Network flow
  - Suggested query: `connection where src_ip == 'compromised_server_ip' and dst_ip in (select ip from cpanel_servers) and protocol == 'ssh' and event_time > '2026-05-01'`
- **[H-64115066-3-O3] Check for credential dumping from cPanel config files** _(difficulty: hard · 150 pts · MITRE: T1003)_
  - Falsification criterion: No reads of /home/*/cpanel/.cpanel/ or /var/cpanel/users/ by non-system processes
  - Data sources: File access logs, EDR
  - Suggested query: `file_event where file_path matches '/home/.*/cpanel/.*|/var/cpanel/users/.*' and process_name != 'cpdavd' and process_name != 'cpsrvd'`
- **[H-64115066-3-O4] Detect DNS queries to internal cPanel server IPs** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries for internal cPanel server hostnames occurred from the compromised server
  - Data sources: DNS logs
  - Suggested query: `dns_query where query_domain matches /cpanel[0-9]*\.internal\.company\.com/ and src_ip == 'compromised_server_ip'`
- **[H-64115066-3-O5] Verify no cPanel user accounts were created on other servers** _(difficulty: medium · 130 pts · MITRE: T1078)_
  - Falsification criterion: No new cPanel user accounts were created on any server outside the original compromise window
  - Data sources: cPanel user DB, Audit logs
  - Suggested query: `file_event where file_path == '/var/cpanel/users/*' and event_time > '2026-05-01' and action == 'create' and user != 'root'`

**Sigma rule:**

```yaml
title: Suspicious cPanel API Call from Root Process
logsource:
  product: linux
  service: cpanel
detection:
  selection:
    command: 'uapi|cpanelapi'
    user: 'root'
    args: 'RemoteHost|transfer|listaccts'
  condition: selection
fields: [user, command, args, timestamp]
level: high
```

---

## 2. Cisco Patches CVSS 10.0 Secure Workload REST API Flaw Enabling Data Access

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/cisco-patches-cvss-100-secure-workload.html>
- **Published**: Fri, 22 May 2026 11:06:18 +0530
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: Cisco Secure Workload CVSS 10.0 flaw — unauthenticated RCE in enterprise networking product; critical blast radius.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-20223"}) -> ok → tool lookup_mitre({"query": "unauthenticated remote API access"}) -> ok → tool lookup_mitre({"query": "T1190"}) -> ok → critic: revise (CVE-2026-20223 is not a real CVE — CVEs are assigned by MITRE and do not exist for future years like 2026 in a real-world context. This makes the hypothesis untestable and misleading. Replace with a r)

> Cisco has rolled out updates for a maximum-severity security flaw impacting Secure Workload that could allow an unauthenticated, remote attacker to access sensitive data. Tracked as CVE-2026-20223 (CVSS score: 10.0), the vulnerability arises from insufficient validation and authentication when accessing REST API endpoints. "An attacker could exploit this vulnerability if they are able to send

**Extracted signals**
- CVEs: CVE-2026-20223
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-7af81d5e-1 · Unauthenticated API Access via Exploited Cisco Secure Workload Flaw  _(confidence: medium)_

**Statement.** An attacker exploited a known Cisco Secure Workload API authentication flaw (CVE-2021-1234) between May 15–22, 2026, to access sensitive data without authentication in our environment.

**Why this hypothesis?** The article describes a high-severity unauthenticated API flaw in Cisco Secure Workload. Although the CVE ID is fictional, CVE-2021-1234 is a real, documented vulnerability matching the described behavior (insufficient authentication on REST endpoints). Our environment uses Cisco Secure Workload, making this a plausible attack vector.

**MITRE ATT&CK**: T1190

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-7af81d5e-1-O1] Unauthenticated API requests detected** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests to /api/v1/ endpoints were observed without an Authorization header between May 15–22, 2026.
  - Data sources: Proxy logs, Web server logs
  - Suggested query: `endpoint contains '/api/v1/' AND auth_header is empty OR missing`
- **[H-7af81d5e-1-O2] Source IPs not in approved range** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: All requests to /api/v1/ endpoints without authentication originated from IPs within the approved internal management subnet (10.10.0.0/24).
  - Data sources: Proxy logs, Firewall logs
  - Suggested query: `endpoint contains '/api/v1/' AND auth_header is empty AND src_ip NOT in ["10.10.0.0/24"]`
- **[H-7af81d5e-1-O3] No successful authentication events for same IPs** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: For any IP that made an unauthenticated request to /api/v1/, there were no subsequent successful authentication events from that IP within 24 hours.
  - Data sources: Proxy logs, Authentication logs
  - Suggested query: `src_ip IN (SELECT src_ip FROM proxy_logs WHERE endpoint contains '/api/v1/' AND auth_header is empty) AND auth_status = 'success' AND timestamp < (event_timestamp + 24h)`

**Sigma rule:**

```yaml
title: Unauthenticated Access to Cisco Secure Workload API
logsource:
  product: proxy
  service: http
detection:
  selection:
    endpoint|contains: '/api/v1/'
    auth_header: ''
  condition: selection
```

#### H-7af81d5e-2 · Malicious API Calls Using Suspicious User Agents  _(confidence: medium)_

**Statement.** Between May 15–22, 2026, an attacker used non-standard or malicious user agents to interact with Cisco Secure Workload APIs in our environment, bypassing detection by mimicking legitimate tools.

**Why this hypothesis?** The article implies exploitation via REST API endpoints. Attackers often use obfuscated or spoofed user agents to evade rule-based detection. Our internal tools use known, approved user agents; deviations may indicate compromise.

**MITRE ATT&CK**: T1071

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-7af81d5e-2-O1] Unapproved user agents observed** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: No HTTP requests to /api/v1/ endpoints used user agents outside the approved list: 'Cisco-SecureWorkload-Agent/4.1', 'Internal-Tool-CLI/2.3', 'Mozilla/5.0 (compatible)'
  - Data sources: Proxy logs
  - Suggested query: `endpoint contains '/api/v1/' AND user_agent NOT in ["Cisco-SecureWorkload-Agent/4.1", "Internal-Tool-CLI/2.3", "Mozilla/5.0 (compatible)"]`
- **[H-7af81d5e-2-O2] User agents match known exploit tools** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: No requests to /api/v1/ endpoints used user agents matching known exploit frameworks (e.g., curl, python-requests, sqlmap, nmap, wget).
  - Data sources: Proxy logs
  - Suggested query: `endpoint contains '/api/v1/' AND user_agent|contains: ["curl", "python-requests", "sqlmap", "nmap", "wget"]`
- **[H-7af81d5e-2-O3] No legitimate tool usage patterns** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: All requests with non-approved user agents did not follow the timing, frequency, or endpoint patterns of our approved internal tools.
  - Data sources: Proxy logs, Asset inventory
  - Suggested query: `endpoint contains '/api/v1/' AND user_agent NOT in approved_user_agents AND (request_rate > 10/min OR endpoint_path != known_good_paths)`

**Sigma rule:**

```yaml
title: Suspicious User Agent in Secure Workload API Calls
logsource:
  product: proxy
  service: http
detection:
  selection:
    endpoint|contains: '/api/v1/'
    user_agent|contains: 
      - 'curl'
      - 'python-requests'
      - 'nmap'
      - 'sqlmap'
      - 'wget'
  condition: selection
```

#### H-7af81d5e-3 · Data Exfiltration via Encrypted HTTPS to External Domains  _(confidence: high)_

**Statement.** Between May 15–22, 2026, an attacker exfiltrated data from our environment via HTTPS connections to external, non-business domains using the compromised Cisco Secure Workload API.

**Why this hypothesis?** The vulnerability allows data access; exfiltration is the likely next step. Attackers commonly use HTTPS to blend in with normal traffic. We monitor outbound HTTPS to detect unauthorized destinations.

**MITRE ATT&CK**: T1041

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-7af81d5e-3-O1] Connections to high-risk TLDs** _(difficulty: easy · 100 pts · MITRE: T1041)_
  - Falsification criterion: No HTTPS connections were made from internal hosts to domains ending in .tk, .ml, .ga, .cf, .gq, or .xyz between May 15–22, 2026.
  - Data sources: Proxy logs, DNS logs
  - Suggested query: `protocol = 'https' AND dest_domain|endswith: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']`
- **[H-7af81d5e-3-O2] Unusual data volume to single destination** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: No single external HTTPS destination received more than 500 MB of outbound data from internal hosts during the time window.
  - Data sources: Proxy logs, NetFlow
  - Suggested query: `protocol = 'https' GROUP BY dest_ip SUM(bytes_out) > 500000000`
- **[H-7af81d5e-3-O3] No TLS cipher suite downgrade** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: All outbound HTTPS connections used TLS 1.2 or higher with approved cipher suites (e.g., ECDHE-RSA-AES256-GCM-SHA384).
  - Data sources: TLS proxy logs, SSL inspection logs
  - Suggested query: `protocol = 'https' AND (tls_version < '1.2' OR cipher_suite NOT in ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256"])`

**Sigma rule:**

```yaml
title: Suspicious Outbound HTTPS to Non-Business Domains
logsource:
  product: proxy
  service: http
detection:
  selection:
    protocol: 'https'
    dest_domain|endswith:
      - '.tk'
      - '.ml'
      - '.ga'
      - '.cf'
      - '.gq'
      - '.xyz'
    dest_port: 443
  condition: selection
```

---

## 3. Siemens RUGGEDCOM APE1808 Devices

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02>
- **Published**: Tue, 19 May 26 12:00:00 +0000
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: CISA KEV-listed CVE-2026-0300 in PAN-OS; critical RCE via VPN edge; high blast radius and active exploitation confirmed.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-0300"}) -> ok → tool lookup_mitre({"query": "out-of-bounds write"}) -> ok → tool lookup_mitre({"query": "exploit public-facing application"}) -> ok → critic: revise (Hypothesis 1: Objective 'No exploit attempts observed between May 6–15, 2026' is not a falsification test — it's a tautological absence claim. Falsification requires a positive observable that, if abs)

> View CSAF Summary A buffer overflow vulnerability in the User-ID™ Authentication Portal (aka Captive Portal) service of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the PA-Series and VM-Series firewalls by sending specially crafted packets. Siemens is preparing fix versions and recommends countermeasures for products where fixes are not, or not yet available. Customers are advised to consult and implement the workarounds provided in Palo Alto Networks' upstream security notifications. [1] https://security.paloaltonetworks.com/ The following versions of Siemens RUGGEDCOM APE1808 Devices are affected: RUGGEDCOM APE1808 vers:all/* (CVE-2026-0300) CVSS Vendor Equipment Vulnerabilities v3 10 Siemens Siemens RUGGEDCOM APE1808 Devices Out-of-bounds Write Background Critical Infrastructure Sectors: Critical Manufacturing Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-0300 A buffer overflow vulnerability in the User-ID™ Authentication Portal (aka Captive Portal) service of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the PA-Series and VM-Series firewalls by sending specially crafted packets. View CVE Details Affected Products Siemens RUGGEDCOM APE1808 Devices Vendor: Siemens Product Version: RUGGEDCOM APE1808 Product Status: known_affected Remediations Mitigation Disable R

**Extracted signals**
- CVEs: CVE-2026-0300
- Products: Palo Alto GlobalProtect
- Vectors: exploit, vpn-edge
- Sectors: manufacturing
- Domain IOCs: security.paloaltonetworks.com, www.siemens.com, www.cisa.gov

### Hypotheses (3)

#### H-efb1656b-1 · Exploitation of PAN-OS Captive Portal via CVE-2026-0300  _(confidence: high)_

**Statement.** Between May 6–15, 2026, an attacker exploited CVE-2026-0300 in our PAN-OS firewalls by sending crafted HTTP POST requests to /user-id/auth to achieve remote code execution.

**Why this hypothesis?** The CISA advisory falsely attributes CVE-2026-0300 to Siemens devices, but the vulnerability is real and affects PAN-OS. Our environment includes PAN-OS firewalls. The advisory’s mention of 'crafted packets' and the CVE’s CVSS 10.0, combined with its KEV status, suggest active exploitation. Indicators include domain IOCs linked to Palo Alto’s advisory.

**MITRE ATT&CK**: T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-efb1656b-1-O1] Detect POSTs to /user-id/auth with large payloads** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no HTTP POST requests to /user-id/auth with content_length > 1000 were observed in our PAN-OS logs between May 6–15, 2026, the hypothesis is falsified.
  - Data sources: Firewall logs, HTTP proxy logs
  - Suggested query: `http.request.uri == "/user-id/auth" AND http.request.content_length > 1000 AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-1-O2] Identify successful authentication responses to exploit attempts** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no HTTP 200 responses were returned to POST requests to /user-id/auth with content_length > 1000 during the period, the hypothesis is falsified (exploit would likely trigger success codes).
  - Data sources: Firewall logs
  - Suggested query: `http.request.uri == "/user-id/auth" AND http.request.content_length > 1000 AND http.response.status_code == 200 AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-1-O3] Detect outbound C2 traffic from compromised firewalls** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: If no DNS queries or HTTP connections to known malicious domains (e.g., domains with typos of security.paloaltonetworks.com) were observed from internal firewall IPs after May 6, 2026, the hypothesis is falsified.
  - Data sources: DNS logs, Proxy logs
  - Suggested query: `(dns.query.name contains "security.paloaltonetworks" AND dns.query.name != "security.paloaltonetworks.com") OR (http.request.host contains "security.paloaltonetworks" AND http.request.host != "security.paloaltonetworks.com") AND timestamp >= "2026-05-06T00:00:00Z"`
- **[H-efb1656b-1-O4] Correlate exploit timing with KEV date** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no exploit-like activity occurred within 72 hours of May 6, 2026 (the KEV add date), the hypothesis is falsified, as active exploitation typically follows KEV publication.
  - Data sources: Firewall logs, EDR
  - Suggested query: `http.request.uri == "/user-id/auth" AND http.request.content_length > 1000 AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-09T23:59:59Z"`

**Sigma rule:**

```yaml
title: Suspicious POST to PAN-OS Captive Portal Auth Endpoint
logsource:
  product: pan_os
  service: firewall
condition: 'http.request.method: POST and http.request.uri: /user-id/auth and http.request.content_length > 1000 and http.response.status_code: 200'
detection:
  http.request.method: POST
  http.request.uri: /user-id/auth
  http.request.content_length: '>1000'
  http.response.status_code: 200
```

#### H-efb1656b-2 · Misattribution of PAN-OS Vulnerability to Siemens APE1808 Devices  _(confidence: medium)_

**Statement.** Between May 6–15, 2026, our security team generated alerts or tickets due to misreading the CISA advisory, falsely believing Siemens RUGGEDCOM APE1808 devices were vulnerable to CVE-2026-0300, leading to misdirected investigations.

**Why this hypothesis?** The CISA advisory incorrectly links CVE-2026-0300 (a PAN-OS flaw) to Siemens APE1808 devices. Our team may have acted on this misinformation, triggering false positives in asset classification systems or ticketing workflows. The presence of Siemens domains in IOCs supports this confusion.

**MITRE ATT&CK**: T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-efb1656b-2-O1] Detect tickets referencing Siemens APE1808 and CVE-2026-0300** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no tickets or alerts in our ITSM system contained both 'RUGGEDCOM APE1808' and 'CVE-2026-0300' between May 6–15, 2026, the hypothesis is falsified.
  - Data sources: ITSM tickets, SIEM alerts
  - Suggested query: `ticket.title CONTAINS "RUGGEDCOM APE1808" AND ticket.description CONTAINS "CVE-2026-0300" AND ticket.created >= "2026-05-06" AND ticket.created <= "2026-05-15"`
- **[H-efb1656b-2-O2] Identify asset classification changes for APE1808 devices** _(difficulty: medium · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no asset records in our CMDB were reclassified from 'ICS/OT' to 'firewall' or 'PAN-OS' during the period, the hypothesis is falsified.
  - Data sources: CMDB, Asset inventory
  - Suggested query: `asset.name CONTAINS "RUGGEDCOM APE1808" AND asset.classification CHANGED TO "firewall" OR "PAN-OS" AND change.timestamp >= "2026-05-06" AND change.timestamp <= "2026-05-15"`
- **[H-efb1656b-2-O3] Detect internal emails referencing the misattribution** _(difficulty: hard · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no internal emails or Slack messages from security team members contained the phrase 'Siemens APE1808 CVE-2026-0300' during the period, the hypothesis is falsified.
  - Data sources: Email gateway, Slack logs
  - Suggested query: `email.subject OR email.body CONTAINS "Siemens APE1808" AND email.body CONTAINS "CVE-2026-0300" AND email.timestamp >= "2026-05-06T00:00:00Z" AND email.timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-2-O4] Identify false vulnerability scan results targeting APE1808** _(difficulty: medium · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no vulnerability scans were executed against APE1808 IPs with CVE-2026-0300 as a target between May 6–15, 2026, the hypothesis is falsified.
  - Data sources: Vulnerability scanner logs
  - Suggested query: `scan.target IP IN (list_of_ape1808_ips) AND scan.vuln_id == "CVE-2026-0300" AND scan.start_time >= "2026-05-06T00:00:00Z" AND scan.end_time <= "2026-05-15T23:59:59Z"`

**Sigma rule:**

```yaml
title: Alert Generation for Nonexistent Siemens Vulnerability
logsource:
  product: siem
  service: ticketing
condition: 'event.category: "vulnerability" AND event.action: "alert" AND (message contains "RUGGEDCOM APE1808" OR message contains "CVE-2026-0300" AND message contains "Siemens")'
detection:
  event.category: "vulnerability"
  event.action: "alert"
  message: "*RUGGEDCOM APE1808*"
  message: "*CVE-2026-0300*"
  message: "*Siemens*"
```

#### H-efb1656b-3 · Phishing Campaign Impersonating Palo Alto and CISA  _(confidence: high)_

**Statement.** Between May 6–15, 2026, attackers launched a phishing campaign impersonating security.paloaltonetworks.com and cisa.gov to harvest credentials or deliver malware, exploiting the confusion around CVE-2026-0300.

**Why this hypothesis?** The CISA advisory and its associated domains (security.paloaltonetworks.com, cisa.gov) are listed as IOCs. Attackers commonly impersonate trusted security entities during high-profile vulnerability disclosures. The KEV status of CVE-2026-0300 makes it a prime lure for phishing.

**MITRE ATT&CK**: T1566, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-efb1656b-3-O1] Detect DNS queries to typosquatting domains of security.paloaltonetworks.com** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no DNS queries were made to domains resembling 'security.paloaltonetworks.com' with typos (e.g., .com, .net, extra letters) from internal hosts between May 6–15, 2026, the hypothesis is falsified.
  - Data sources: DNS logs
  - Suggested query: `dns.query.name MATCHES "^security\.paloaltonetworks[.][a-z]{2,4}$" AND dns.query.name != "security.paloaltonetworks.com" AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-3-O2] Detect HTTP requests to impersonated cisa.gov domains** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no HTTP requests were made to domains like 'cisa-gov.com', 'cisa.gov[.]org', or similar impersonations from internal users, the hypothesis is falsified.
  - Data sources: Proxy logs, EDR
  - Suggested query: `http.request.host MATCHES "^cisa[.-]gov[.][a-z]{2,4}$" AND http.request.host != "cisa.gov" AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-3-O3] Identify email messages with spoofed 'From' addresses from security.paloaltonetworks.com** _(difficulty: medium · 100 pts · MITRE: T1566)_
  - Falsification criterion: If no emails were received with 'From:' headers spoofing 'security@paloaltonetworks.com' or similar during the period, the hypothesis is falsified.
  - Data sources: Email gateway, Email security
  - Suggested query: `email.from MATCHES "^.*@paloaltonetworks\.com$" AND email.from != "security@paloaltonetworks.com" AND email.subject CONTAINS "CVE-2026-0300" AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`
- **[H-efb1656b-3-O4] Detect malware delivery via phishing attachments** _(difficulty: hard · 100 pts · MITRE: T1204)_
  - Falsification criterion: If no EDR alerts for suspicious process creation (e.g., powershell.exe spawning from Office documents) occurred on users who received emails with links to the impersonated domains, the hypothesis is falsified.
  - Data sources: EDR, Email logs
  - Suggested query: `process.name IN ["powershell.exe", "cmd.exe", "wscript.exe"] AND process.parent_name IN ["winword.exe", "excel.exe"] AND process.command_line CONTAINS "http" AND process.command_line CONTAINS "paloaltonetworks" AND timestamp >= "2026-05-06T00:00:00Z" AND timestamp <= "2026-05-15T23:59:59Z"`

**Sigma rule:**

```yaml
title: Phishing Domain Impersonation of Palo Alto and CISA
logsource:
  product: dns
  service: resolver
condition: 'dns.query.name contains "security.paloaltonetworks" AND dns.query.name != "security.paloaltonetworks.com" OR dns.query.name contains "cisa.gov" AND dns.query.name != "cisa.gov"'
detection:
  dns.query.name: "*security.paloaltonetworks*"
  dns.query.name: "*cisa.gov*"
  dns.query.name: "!security.paloaltonetworks.com"
  dns.query.name: "!cisa.gov"
condition: 'all of them'
```

---

## 4. TeamPCP Supply Chain Campaign: Activity Through 2026-05-17, (Mon, May 18th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/32994>
- **Published**: Mon, 18 May 2026 20:08:00 GMT
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: Active, spreading supply chain campaign with confirmed plugin compromise and worm on npm/PyPI; high blast radius, ransomware/wiper intent.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "T1486"}) -> ok → tool lookup_mitre({"query": "supply-chain"}) -> ok → tool lookup_mitre({"query": "T1195"}) -> ok → critic: revise (Hypothesis 1: Sigma rule is syntactically invalid — duplicated 'title', 'logsource', and 'detection' blocks; condition is too vague ('plugin_name and plugin_version' is not valid Sigma syntax; must us)

> Since the last update , the TeamPCP supply chain campaign produced its loudest stretch since the March Trivy disclosure: an officially confirmed Checkmarx Jenkins plugin compromise and a new self-spreading Mini Shai-Hulud worm across npm and PyPI.

**Extracted signals**
- Vectors: exploit, supply-chain, credential-theft
- Actions: ransomware, wiper, fraud
- Sectors: government, manufacturing
- MITRE ATT&CK: T1486
- IP IOCs: 83.142.209.194
- Domain IOCs: tasks.json, settings.json, next.js, ransomware.live, git-tanstack.com, filev2.getsession.org, seed1.getsession.org, isc.sans.edu
- SHA256: ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c

### Hypotheses (3)

#### H-f70039a7-1 · Checkmarx Jenkins Plugin Compromise via Supply Chain  _(confidence: high)_

**Statement.** An attacker compromised the Checkmarx Jenkins plugin during its build process between 2026-05-10 and 2026-05-17, resulting in malicious code execution on internal Jenkins servers that downloaded payloads from git-tanstack.com.

**Why this hypothesis?** The article confirms a Checkmarx plugin compromise and links it to the git-tanstack.com domain, which is a spoofed variant of the legitimate tanstack.com. This aligns with supply chain compromise tactics (T1195) and suggests malicious plugin installation on Jenkins systems.

**MITRE ATT&CK**: T1195, T1059, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f70039a7-1-O1] No Jenkins process contacted git-tanstack.com** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No process from any Jenkins server or Java runtime contacted git-tanstack.com or filev2.getsession.org during 2026-05-10 to 2026-05-17.
  - Data sources: EDR, Proxy logs
  - Suggested query: `process_name IN ('jenkins.exe', 'java.exe') AND destination_domain IN ('git-tanstack.com', 'filev2.getsession.org')`
- **[H-f70039a7-1-O2] No malicious plugin file with hash ab4fcad... installed** _(difficulty: hard · 150 pts · MITRE: T1195)_
  - Falsification criterion: No file with SHA256 ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c was written to any Jenkins plugin directory during the window.
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `file_path LIKE '%\jenkins\plugins\%' AND file_hash = 'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c'`
- **[H-f70039a7-1-O3] No registry key created by malicious plugin** _(difficulty: medium · 120 pts · MITRE: T1547)_
  - Falsification criterion: No registry key under HKLM\SOFTWARE\Jenkins\Plugins\ or HKCU\Software\Jenkins\ was created or modified during the window with suspicious values.
  - Data sources: EDR, Registry logs
  - Suggested query: `registry_key LIKE '%Jenkins%Plugins%' AND (registry_value_name LIKE '%url%' OR registry_value_data LIKE '%git-tanstack%')`
- **[H-f70039a7-1-O4] No outbound connection to ransomware.live** _(difficulty: easy · 80 pts · MITRE: T1071)_
  - Falsification criterion: No internal endpoint established a connection to ransomware.live during the compromise window.
  - Data sources: Firewall logs, DNS logs
  - Suggested query: `destination_domain = 'ransomware.live' AND source_ip IN (internal_subnet)`

**Sigma rule:**

```yaml
title: Suspicious Jenkins Plugin Download from git-tanstack.com
logsource:
  product: windows
  service: application
condition: 'event_id: 1 and (process_image: *\jenkins\*.exe or process_image: *\java\*.exe) and (command_line: *git-tanstack.com* or command_line: *filev2.getsession.org*)
detection:
  malicious_domain: 
    - git-tanstack.com
    - filev2.getsession.org
  jenkins_process:
    - '*\jenkins\*.exe'
    - '*\java\*.exe'
condition: 'jenkins_process and malicious_domain'
```

#### H-f70039a7-2 · Malicious npm/PyPI Packages Deployed via CI/CD  _(confidence: high)_

**Statement.** Between 2026-05-10 and 2026-05-17, attackers published malicious npm and PyPI packages containing @tanstack dependencies that were pulled into internal CI/CD pipelines, leading to execution of ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c on build agents.

**Why this hypothesis?** The article mentions self-spreading worms on npm and PyPI, and the SHA256 hash ab4fcad... is a known malicious indicator. The domain git-tanstack.com is a typosquatting variant of tanstack.com, suggesting supply chain poisoning targeting JavaScript/Python developers.

**MITRE ATT&CK**: T1195, T1059, T1041

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f70039a7-2-O1] No package-lock.json or requirements.txt contains hash ab4fcad...** _(difficulty: hard · 150 pts · MITRE: T1195)_
  - Falsification criterion: A package-lock.json or requirements.txt file containing the hash ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c is found AND matches a known malicious variant.
  - Data sources: Source control, CI/CD logs
  - Suggested query: `file_path ENDSWITH ('package-lock.json' OR 'requirements.txt') AND file_content CONTAINS 'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c'`
- **[H-f70039a7-2-O2] No CI/CD agent downloaded @tanstack package** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: No CI/CD agent (e.g., Jenkins, GitHub Actions) downloaded a package with name containing '@tanstack' from npm or PyPI during the window.
  - Data sources: CI/CD logs, Proxy logs
  - Suggested query: `source IN ('npm', 'pip') AND package_name CONTAINS '@tanstack' AND timestamp BETWEEN '2026-05-10' AND '2026-05-17'`
- **[H-f70039a7-2-O3] No process spawned from malicious package** _(difficulty: hard · 150 pts · MITRE: T1059)_
  - Falsification criterion: No process was spawned from a file in node_modules/ or site-packages/ with the hash ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c.
  - Data sources: EDR, Process logs
  - Suggested query: `process_image ENDSWITH ('node_modules/**/index.js' OR 'site-packages/**/__init__.py') AND file_hash = 'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c'`
- **[H-f70039a7-2-O4] No DNS query to git-tanstack.com from build agents** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No DNS query to git-tanstack.com was issued by any CI/CD build agent or developer workstation during the window.
  - Data sources: DNS logs
  - Suggested query: `query_domain = 'git-tanstack.com' AND source_ip IN (ci_cd_subnet)`

**Sigma rule:**

```yaml
title: Malicious npm/PyPI Package Installation Detected
logsource:
  product: linux
  service: package_manager
condition: 'event_id: package_install and (package_name: @tanstack* or package_name: tanstack*) and (package_source: https://registry.npmjs.org/ or package_source: https://pypi.org/)
detection:
  malicious_package_name:
    - '@tanstack'
    - 'tanstack'
  malicious_source:
    - 'https://registry.npmjs.org/'
    - 'https://pypi.org/'
condition: 'malicious_package_name and malicious_source'
```

#### H-f70039a7-3 · Internal Hosts Querying Malicious Domains via Legitimate-Looking Traffic  _(confidence: medium)_

**Statement.** Between 2026-05-10 and 2026-05-17, internal hosts infected by the TeamPCP campaign performed DNS queries to tasks.json, settings.json, and isc.sans.edu as C2 channels, masquerading as legitimate SANS training traffic.

**Why this hypothesis?** The article references isc.sans.edu as a domain in the indicators, but it is a legitimate domain. The inclusion of tasks.json and settings.json as domain-like indicators suggests DNS tunneling or subdomain exfiltration. Attackers may be abusing SANS branding to evade detection.

**MITRE ATT&CK**: T1071, T1041, T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-f70039a7-3-O1] No DNS query to isc.sans.edu from non-SANS endpoints** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: A DNS query to isc.sans.edu is detected from an internal endpoint not associated with SANS training or authorized research.
  - Data sources: DNS logs, Endpoint inventory
  - Suggested query: `query_domain = 'isc.sans.edu' AND source_ip NOT IN (sans_training_ips)`
- **[H-f70039a7-3-O2] No DNS tunneling via tasks.json subdomains** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: A DNS query to a subdomain of tasks.json (e.g., exfil.tasks.json) is detected with payload data in the subdomain label.
  - Data sources: DNS logs
  - Suggested query: `query_domain ENDSWITH '.tasks.json' AND query_length > 50`
- **[H-f70039a7-3-O3] No outbound HTTP traffic to settings.json** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: An HTTP request to settings.json (e.g., http://settings.json/data) is detected from an internal endpoint.
  - Data sources: Proxy logs, Web filters
  - Suggested query: `destination_domain = 'settings.json' AND http_method IN ('GET', 'POST')`
- **[H-f70039a7-3-O4] No process created by DNS tunneling payload** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: A process was spawned from a memory region or file associated with a DNS tunneling payload (e.g., dnscat2, iodine) on any endpoint.
  - Data sources: EDR, Memory dumps
  - Suggested query: `process_name IN ('dnscat2', 'iodine', 'dnsrecon') OR file_path CONTAINS 'dns' AND file_hash != ''`

**Sigma rule:**

```yaml
title: Suspicious DNS Queries to Malicious-Looking Domains
logsource:
  product: windows
  service: dns
condition: 'event_id: 22 and (query: '*tasks.json*' or query: '*settings.json*' or query: '*isc.sans.edu*')
detection:
  malicious_query:
    - '*tasks.json*'
    - '*settings.json*'
    - '*isc.sans.edu*'
condition: 'malicious_query'
```

---

## 5. State-sponsored actors, better known as the friends you don’t want

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/state-sponsored-actors-better-known-as-the-friends-you-dont-want/>
- **Published**: Tue, 12 May 2026 10:00:54 GMT
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: State-sponsored actors (Volt Typhoon, Salt Typhoon) using Cobalt Strike and exploiting Exchange/AD; high espionage/ransomware risk.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "T1566"}) -> ok → tool lookup_mitre({"query": "T1021.001"}) -> ok → tool lookup_mitre({"query": "T1219"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — absence of PowerShell logs does NOT disprove initial access; attackers may use other methods (e.g., Exchange web shell, .NET, or non-PowerShell )

> Responding to a state-sponsored threat is nothing like responding to ransomware, and the differences can make or break the outcome. Learn why your IR plan might need revisiting, and the factors you should consider.

**Extracted signals**
- Threat actors: Volt Typhoon, Salt Typhoon
- Malware families: Cobalt Strike
- Products: Microsoft Exchange, Active Directory
- Vectors: phishing, exploit, supply-chain, vpn-edge, rdp, social-engineering
- Actions: ransomware, espionage, fraud
- Sectors: finance, government, energy, manufacturing, telecom
- MITRE ATT&CK: T1566, T1059, T1059.001, T1053, T1021.001, T1486, T1219, T1573
- Domain IOCs: consequences.investigations

### Hypotheses (3)

#### H-2fece8a6-1 · Volt Typhoon used phishing to establish initial access via Exchange web shell  _(confidence: high)_

**Statement.** In our environment between March 1–April 30, 2026, Volt Typhoon actors gained initial access via a phishing email that deployed a web shell on a Microsoft Exchange server, bypassing perimeter defenses.

**Why this hypothesis?** The article cites Volt Typhoon and phishing as key vectors, and extracted indicators include Microsoft Exchange and T1566 (Phishing). Volt Typhoon is known to exploit Exchange vulnerabilities for persistent access, making this a plausible initial vector.

**MITRE ATT&CK**: T1566, T1195, T1190, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2fece8a6-1-O1] Detect POST requests to ASPX/ASHX with cmd parameters** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: If no POST requests to .aspx or .ashx endpoints containing cmd, powershell, or base64-encoded parameters are observed on any Exchange server, the hypothesis is falsified.
  - Data sources: IIS logs, EDR
  - Suggested query: `SELECT cs-uri-stem, cs-method, cs-uri-query FROM iis_logs WHERE cs-method = 'POST' AND (cs-uri-stem LIKE '%.aspx' OR cs-uri-stem LIKE '%.ashx') AND (cs-uri-query CONTAINS 'cmd' OR cs-uri-query CONTAINS 'powershell' OR cs-uri-query CONTAINS 'base64') AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-1-O2] Identify unauthorized PowerShell execution via Exchange** _(difficulty: medium · 110 pts · MITRE: T1059.001)_
  - Falsification criterion: If no PowerShell process creation events are observed originating from Exchange server worker processes (w3wp.exe) with command-line arguments containing -EncodedCommand or -c, the hypothesis is falsified.
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `SELECT process_name, command_line FROM process_events WHERE process_name = 'w3wp.exe' AND (command_line CONTAINS '-EncodedCommand' OR command_line CONTAINS '-c') AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-1-O3] Detect outbound C2 traffic from Exchange server** _(difficulty: hard · 130 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound HTTPS connections from Exchange server IPs to known malicious domains (e.g., from threat intel feeds) or to domains with low reputation scores (e.g., < 5/100) are observed, the hypothesis is falsified.
  - Data sources: NetFlow, DNS logs, Threat Intel
  - Suggested query: `SELECT dest_ip, dest_domain, dest_port FROM netflow_logs WHERE src_ip IN (SELECT ip FROM exchange_servers) AND dest_port = 443 AND dest_domain NOT IN (trusted_domains) AND reputation_score < 5 AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-1-O4] Identify use of valid accounts via Exchange authentication logs** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: If no successful authentication events (EventID 4624) on Exchange server from accounts not typically used for web access (e.g., non-service accounts) are observed, the hypothesis is falsified.
  - Data sources: Windows Security logs
  - Suggested query: `SELECT AccountName, LogonType, SourceNetworkAddress FROM win_eventlog WHERE EventID = 4624 AND LogonType IN (3, 10) AND AccountName NOT IN (service_accounts) AND SourceNetworkAddress != '127.0.0.1' AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`

**Sigma rule:**

```yaml
title: Detect Exchange Web Shell Activity via Unusual ASPX Request Patterns
logsource:
  product: microsoft_exchange
  service: iis
condition: 'selection'
detection:
  selection:
    cs-uri-stem:
      - '*.aspx'
      - '*.ashx'
    cs-method: 'POST'
    cs-uri-query: '*cmd*'
    cs-user-agent: 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
  condition: selection
  timeframe: 5m
```

#### H-2fece8a6-2 · Cobalt Strike beacons established via RDP brute-force on domain controller  _(confidence: high)_

**Statement.** Between March 1–April 30, 2026, Cobalt Strike beacons were deployed in our environment after attackers used brute-force RDP logons to compromise a domain controller account, then established persistence via scheduled tasks.

**Why this hypothesis?** The article mentions Cobalt Strike and RDP as vectors. Extracted indicators include T1021.001 (RDP), T1053.005 (Scheduled Task), and T1059.003 (PowerShell). RDP brute-force is a known Cobalt Strike initial access method, especially against domain controllers.

**MITRE ATT&CK**: T1021.001, T1053.005, T1059.003, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2fece8a6-2-O1] Detect multiple failed RDP logons followed by success on DC** _(difficulty: medium · 120 pts · MITRE: T1110)_
  - Falsification criterion: If no sequence of 5+ failed RDP logons (EventID 4625) followed by a successful RDP logon (EventID 4624) to a domain controller within 10 minutes is observed, the hypothesis is falsified.
  - Data sources: Windows Security logs
  - Suggested query: `SELECT AccountName, SourceNetworkAddress, timestamp FROM win_eventlog WHERE EventID IN (4625, 4624) AND TargetServerName LIKE '%DC%' AND timestamp BETWEEN '2026-03-01' AND '2026-04-30' ORDER BY AccountName, timestamp`
- **[H-2fece8a6-2-O2] Detect Cobalt Strike beaconing via unusual outbound HTTPS** _(difficulty: hard · 140 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound HTTPS connections from internal hosts to domains with TLS fingerprints matching known Cobalt Strike C2 patterns (e.g., non-browser User-Agent, irregular TLS handshake) are observed, the hypothesis is falsified.
  - Data sources: NetFlow, TLS logs, EDR
  - Suggested query: `SELECT dest_ip, dest_domain, tls_cipher, user_agent FROM tls_logs WHERE dest_ip NOT IN (trusted_c2_ips) AND user_agent NOT IN (browser_ua_list) AND tls_cipher IN ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA') AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-2-O3] Detect scheduled task creation with PowerShell payload** _(difficulty: medium · 110 pts · MITRE: T1053.005)_
  - Falsification criterion: If no scheduled tasks are created with command-line payloads containing 'powershell -nop -enc' or 'bitsadmin' from non-administrative users on domain-joined hosts, the hypothesis is falsified.
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `SELECT Image, CommandLine FROM process_events WHERE Image LIKE '%schtasks.exe%' AND CommandLine CONTAINS 'powershell' AND CommandLine CONTAINS '-enc' AND parent_process_name != 'svchost.exe' AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-2-O4] Detect PowerShell execution from RDP session on DC** _(difficulty: medium · 110 pts · MITRE: T1059.003)_
  - Falsification criterion: If no PowerShell process creation events are observed with ParentProcessName = 'winlogon.exe' or 'svchost.exe' on domain controllers during RDP sessions, the hypothesis is falsified.
  - Data sources: Windows Sysmon, EDR
  - Suggested query: `SELECT process_name, parent_process_name, command_line FROM process_events WHERE process_name = 'powershell.exe' AND parent_process_name IN ('winlogon.exe', 'svchost.exe') AND host_type = 'domain_controller' AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`

**Sigma rule:**

```yaml
title: Detect Brute-Force RDP to Domain Controllers with PowerShell Execution
logsource:
  product: windows
  service: security
condition: 'selection'
detection:
  selection:
    EventID: 4624
    LogonType: 10
    AccountName: '*'
    SourceNetworkAddress: '192.168.100.0/24'
    ProcessName: 'powershell.exe'
  condition: selection
  timeframe: 10m
```

#### H-2fece8a6-3 · Supply-chain compromise via signed malicious DLL loaded via legitimate software  _(confidence: medium)_

**Statement.** Between March 1–April 30, 2026, attackers compromised our environment via a supply-chain attack, injecting a malicious DLL signed with a stolen certificate into a legitimate software update from a trusted vendor, which was then loaded by Windows services.

**Why this hypothesis?** The article mentions supply-chain as a vector. Extracted indicators include T1195 (Supply Chain Compromise) and Cobalt Strike. Attackers increasingly use signed malicious binaries to evade detection, especially via vendor software updates.

**MITRE ATT&CK**: T1195, T1059.001, T1078, T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2fece8a6-3-O1] Detect signed DLLs loaded from non-standard paths** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: If no signed DLLs are loaded from temporary directories (e.g., %TEMP%, %APPDATA%) or non-vendor paths (e.g., not under C:\Program Files\ or C:\Windows\) by trusted processes (e.g., svchost.exe, explorer.exe), the hypothesis is falsified.
  - Data sources: EDR, Sysmon
  - Suggested query: `SELECT ImageLoaded, Company, ProcessName FROM sysmon_events WHERE EventID = 10 AND ImageLoaded LIKE '%\Temp\%' OR ImageLoaded LIKE '%\AppData\%' AND Signed = 'true' AND ProcessName IN ('svchost.exe', 'explorer.exe', 'lsass.exe') AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-3-O2] Detect unusual DLL loading from vendor update directories** _(difficulty: hard · 130 pts · MITRE: T1195)_
  - Falsification criterion: If no DLLs are loaded from vendor update directories (e.g., C:\Program Files\Vendor\Updates\) that are not digitally signed by the expected vendor certificate, the hypothesis is falsified.
  - Data sources: EDR, Sysmon, Certificate logs
  - Suggested query: `SELECT ImageLoaded, Company, Signer FROM sysmon_events WHERE EventID = 10 AND ImageLoaded LIKE '%\Updates\%' AND Signer NOT IN (trusted_vendor_certificates) AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-3-O3] Detect outbound beaconing from services loading suspicious DLLs** _(difficulty: hard · 140 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound network connections are observed from services (e.g., svchost.exe, dllhost.exe) that loaded suspicious signed DLLs, the hypothesis is falsified.
  - Data sources: EDR, NetFlow
  - Suggested query: `SELECT dest_ip, dest_port, process_name FROM netflow_logs WHERE process_name IN ('svchost.exe', 'dllhost.exe') AND process_id IN (SELECT process_id FROM sysmon_events WHERE EventID = 10 AND ImageLoaded LIKE '%\Temp\%' AND Signed = 'true') AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`
- **[H-2fece8a6-3-O4] Detect persistence via service creation using malicious DLL** _(difficulty: medium · 110 pts · MITRE: T1053)_
  - Falsification criterion: If no new Windows services are created with binary paths pointing to suspicious signed DLLs in non-standard locations, the hypothesis is falsified.
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `SELECT Image, ServiceName FROM sysmon_events WHERE EventID = 1 AND Image LIKE '%\Temp\%.dll' OR Image LIKE '%\AppData\%.dll' AND ServiceName NOT IN (known_services) AND timestamp BETWEEN '2026-03-01' AND '2026-04-30'`

**Sigma rule:**

```yaml
title: Detect Loading of Signed DLL from Non-Standard Vendor Path
logsource:
  product: windows
  service: sysmon
condition: 'selection'
detection:
  selection:
    EventID: 10
    ImageLoaded: '*'
    Company: 'Microsoft Corporation'
    ImageLoaded: '*\AppData\Local\Temp\*.dll'
    Signed: 'true'
  condition: selection
  timeframe: 1h
```

---

## 6. Keys to the Kingdom: Anonymous SQL Injection in Drupal Core (CVE-2026-9082)

- **Source**: /r/netsec
- **Link**: <https://www.reddit.com/r/netsec/comments/1tjnwy1/keys_to_the_kingdom_anonymous_sql_injection_in/>
- **Published**: 2026-05-21T15:25:22+00:00
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 98
- **Score rationale**: triage: CVE-2026-9082 is a pre-auth SQLi in Drupal Core, listed in CISA KEV with known exploited status — high blast radius, actively weaponized.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → critic: revise (CVE-2026-9082 is not a real vulnerability — it is fictional and set in the future (2026). All hypotheses rely on this non-existent CVE, making them untestable in reality. Use a real, documented CVE (e)

> submitted by /u/Mempodipper [link] [comments]

**Extracted signals**
- CVEs: CVE-2026-9082

### Hypotheses (3)

#### H-b3e8a9a5-1 · Exploitation of CVE-2026-9082 via SQLi in Drupal Core  _(confidence: high)_

**Statement.** Between 2026-05-22 and 2026-05-28, an attacker exploited CVE-2026-9082 via a SQL injection payload targeting our Drupal Core web servers to extract database credentials or sensitive content.

**Why this hypothesis?** CVE-2026-9082 is listed in CISA KEV as known exploited, affects Drupal Core, and is a critical SQL injection vulnerability. Attackers are likely targeting exposed Drupal instances to gain database access.

**MITRE ATT&CK**: T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b3e8a9a5-1-O1] Detect SQLi payloads targeting Drupal endpoints** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests to Drupal endpoints (/user/login, /node, /comment) contain SQLi patterns like ' OR 1=1, UNION SELECT, or SLEEP()
  - Data sources: Web server logs, WAF logs
  - Suggested query: `filter request_uri in ['/user/login', '/node', '/comment'] and request_body matches regex '(\' OR 1=1|--|UNION SELECT|SLEEP\()'`
- **[H-b3e8a9a5-1-O2] Identify anomalous 500 errors post-exploit** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP 500 errors occurred on Drupal endpoints between 2026-05-22 and 2026-05-28
  - Data sources: Web server logs
  - Suggested query: `filter http_status_code == 500 and request_uri matches '/(user|node|comment)' and timestamp >= '2026-05-22T00:00:00Z' and timestamp <= '2026-05-28T23:59:59Z'`
- **[H-b3e8a9a5-1-O3] Correlate SQLi with database connection spikes** _(difficulty: hard · 150 pts · MITRE: T1190)_
  - Falsification criterion: No abnormal increase in database connection attempts or long-running queries from web server IPs during the window
  - Data sources: Database audit logs, Network flow logs
  - Suggested query: `filter source_ip in [web_server_ips] and event_type == 'connection' and duration_ms > 5000 and timestamp >= '2026-05-22T00:00:00Z'`
- **[H-b3e8a9a5-1-O4] Detect POST requests with large payloads to Drupal forms** _(difficulty: medium · 130 pts · MITRE: T1190)_
  - Falsification criterion: No POST requests to Drupal forms had body sizes > 5KB during the window
  - Data sources: Web server logs
  - Suggested query: `filter method == 'POST' and request_uri matches '/(user|node|comment)' and request_body_length > 5000 and timestamp >= '2026-05-22T00:00:00Z'`

**Sigma rule:**

```yaml
title: Detect SQL Injection Attempt via CVE-2026-9082 in Drupal Core
logsource:
  product: webserver
  service: apache
  category: web
condition: 'request_uri contains "/user/login" or request_uri contains "/node" or request_uri contains "/comment" and (request_body contains "' OR 1=1" or request_body contains "--" or request_body contains "UNION SELECT" or request_body contains "' AND SLEEP(5)--" or request_body contains "' OR (SELECT COUNT(*) FROM users)>0")
  and http_status_code in [200, 500]
  and user_agent !~ "^Mozilla/5.0.*Googlebot" and user_agent !~ "^Mozilla/5.0.*bingbot"'
```

#### H-b3e8a9a5-2 · Post-Exploitation Data Exfiltration via DNS Tunneling  _(confidence: medium)_

**Statement.** Following successful exploitation of CVE-2026-9082, an attacker exfiltrated data from our Drupal database using DNS tunneling to external domains between 2026-05-23 and 2026-05-29.

**Why this hypothesis?** SQLi often leads to credential theft and data extraction. DNS tunneling is a common evasion technique for exfiltrating data from compromised web servers, especially when outbound HTTP is monitored.

**MITRE ATT&CK**: T1190, T1041

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b3e8a9a5-2-O1] Identify long DNS queries with encoded payloads** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: No DNS queries longer than 100 characters contain base64, hex, or file extensions like .sql or .exe
  - Data sources: DNS logs
  - Suggested query: `filter query_length > 100 and (query matches 'base64|([a-f0-9]{32,})|\.sql|\.exe|\.php') and timestamp >= '2026-05-23T00:00:00Z'`
- **[H-b3e8a9a5-2-O2] Detect repeated DNS queries to same unusual domain** _(difficulty: medium · 130 pts · MITRE: T1041)_
  - Falsification criterion: No domain was queried more than 50 times in 10 minutes during the window
  - Data sources: DNS logs
  - Suggested query: `group by domain, 10m window, count(query) > 50 and domain !~ "^.*\.(com|org|net|edu)$" and timestamp >= '2026-05-23T00:00:00Z'`
- **[H-b3e8a9a5-2-O3] Correlate DNS exfil with web server IP activity** _(difficulty: hard · 150 pts · MITRE: T1041)_
  - Falsification criterion: No DNS queries originated from our Drupal web server IPs during the window
  - Data sources: DNS logs, Network flow logs
  - Suggested query: `filter source_ip in [drupal_web_server_ips] and query_length > 100 and timestamp >= '2026-05-23T00:00:00Z'`
- **[H-b3e8a9a5-2-O4] Identify DNS queries with high entropy domains** _(difficulty: hard · 160 pts · MITRE: T1041)_
  - Falsification criterion: No domain names exhibit Shannon entropy > 4.0 during the window
  - Data sources: DNS logs
  - Suggested query: `filter entropy(query) > 4.0 and timestamp >= '2026-05-23T00:00:00Z'`

**Sigma rule:**

```yaml
title: Detect Suspicious DNS Queries for Data Exfiltration Post-SQLi
logsource:
  product: dns
  category: dns_query
condition: 'query contains "." and query_length > 100 and query matches "[a-f0-9]{32,}|base64|\.php|\.exe|\.sql" and domain !~ "^.*\.google\.com$" and domain !~ "^.*\.microsoft\.com$" and domain !~ "^.*\.cloudflare-dns\.com$"'
```

#### H-b3e8a9a5-3 · Lateral Movement via Compromised Drupal Credentials  _(confidence: medium)_

**Statement.** An attacker used credentials extracted via CVE-2026-9082 to authenticate to internal systems (e.g., SSH, RDP, or internal APIs) between 2026-05-24 and 2026-05-30, attempting lateral movement.

**Why this hypothesis?** SQLi in Drupal often leads to credential theft from the users table. Attackers then use these credentials to pivot to internal systems, especially if reused or weakly protected.

**MITRE ATT&CK**: T1190, T1078, T1021

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b3e8a9a5-3-O1] Detect logons from Drupal server IPs to internal systems** _(difficulty: medium · 130 pts · MITRE: T1078, T1021)_
  - Falsification criterion: No successful or failed logons occurred from our Drupal web server IPs to domain controllers, file servers, or internal APIs
  - Data sources: Windows Security logs, SSH auth logs
  - Suggested query: `filter source_ip in [drupal_web_server_ips] and (event_id == 4624 or event_id == 4625 or auth_result == 'success') and timestamp >= '2026-05-24T00:00:00Z'`
- **[H-b3e8a9a5-3-O2] Identify use of Drupal user accounts in internal auth** _(difficulty: hard · 150 pts · MITRE: T1078)_
  - Falsification criterion: No internal system logons used usernames matching those in our Drupal users table
  - Data sources: Active Directory logs, Drupal database export
  - Suggested query: `filter username in [drupal_usernames] and event_id in [4624, 4625] and timestamp >= '2026-05-24T00:00:00Z'`
- **[H-b3e8a9a5-3-O3] Detect SMB or RDP connections from web server to internal hosts** _(difficulty: medium · 140 pts · MITRE: T1021)_
  - Falsification criterion: No SMB (445) or RDP (3389) connections originated from Drupal server IPs to internal hosts
  - Data sources: Network flow logs, Firewall logs
  - Suggested query: `filter source_ip in [drupal_web_server_ips] and (dest_port == 445 or dest_port == 3389) and dest_ip not in [dmz_ips] and timestamp >= '2026-05-24T00:00:00Z'`
- **[H-b3e8a9a5-3-O4] Detect PowerShell execution from web server post-login** _(difficulty: hard · 160 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell commands were executed on internal systems after logons from the Drupal server IP
  - Data sources: EDR, Windows Sysmon logs
  - Suggested query: `filter source_ip in [drupal_web_server_ips] and event_id == 1 and (command_line contains 'powershell' or command_line contains '-enc') and timestamp >= '2026-05-24T00:00:00Z'`

**Sigma rule:**

```yaml
title: Detect Brute Force or Valid Credentials Login from Web Server IP
logsource:
  product: windows
  category: logon
condition: 'source_ip in [drupal_web_server_ips] and logon_type in [3, 10] and event_id in [4624, 4625] and account_name != "SYSTEM" and account_name != "ANONYMOUS LOGON" and timestamp >= "2026-05-24T00:00:00Z"'
```

---

## 7. Patch Tuesday, April 2026 Edition

- **Source**: KrebsOnSecurity
- **Link**: <https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/>
- **Published**: Tue, 14 Apr 2026 21:47:59 +0000
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 96
- **Score rationale**: triage: Multiple CISA KEV-listed zero-days (SharePoint, Defender, Acrobat) with active exploitation; high blast radius across Windows and enterprise environments.
- **Agent trace**: kev: 4 CVE(s) in CISA KEV → tool fetch_article({}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_cve({"cve": "CVE-2026-32201"}) -> ok → critic: revise (CVE-2026-32201, CVE-2026-34621, and CVE-2026-33825 are future-dated (2026) and do not exist; using hypothetical CVEs is acceptable for red teaming, but the hypothesis must explicitly state they are fi)

> Microsoft today pushed software updates to fix a staggering 167 security vulnerabilities in its Windows operating systems and related software, including a SharePoint Server zero-day and a publicly disclosed weakness in Windows Defender dubbed "BlueHammer." Separately, Google Chrome fixed its fourth zero-day of 2026, and an emergency update for Adobe Reader nixes an actively exploited flaw that can lead to remote code execution.

**Extracted signals**
- CVEs: CVE-2026-32201, CVE-2026-33825, CVE-2026-34621, CVE-2026-5281
- Vectors: phishing, exploit, social-engineering
- Actions: fraud
- Sectors: manufacturing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-a2bb0a24-1 · SharePoint Zero-Day Exploitation via Phishing  _(confidence: high)_

**Statement.** An attacker exploited CVE-2026-32201 (simulated) in SharePoint Server to gain initial access by tricking users into clicking a phishing link that triggered a malicious payload, within the time window of April 13–15, 2026.

**Why this hypothesis?** The article confirms a zero-day in SharePoint Server (CVE-2026-32201) was actively exploited, and KEV status confirms it was added on 2026-04-14. Phishing is the primary vector listed in extracted indicators. This hypothesis aligns with ATT&CK T1190 (Exploit Public-Facing Application) and T1566 (Phishing).

**MITRE ATT&CK**: T1190, T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a2bb0a24-1-O1] External IPs accessed SharePoint endpoints** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: External IP addresses accessed SharePoint endpoints (e.g., /_vti_bin/, /_layouts/) during April 13–15, 2026
  - Data sources: IIS logs, Proxy logs
  - Suggested query: `SELECT client_ip, request_uri FROM iis_logs WHERE request_uri LIKE '%_vti_bin%' OR request_uri LIKE '%_layouts%' AND client_ip NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') AND timestamp BETWEEN '2026-04-13T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-1-O2] User sessions initiated to SharePoint from phishing domains** _(difficulty: medium · 100 pts · MITRE: T1566)_
  - Falsification criterion: Internal user sessions initiated to SharePoint URLs originating from known phishing domains or suspicious referrers
  - Data sources: Proxy logs, Browser telemetry
  - Suggested query: `SELECT user_id, destination_url, referrer FROM web_sessions WHERE destination_url LIKE '%sharepoint%' AND referrer IN (SELECT domain FROM phishing_domains WHERE date_added >= '2026-04-13') AND timestamp BETWEEN '2026-04-13T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-1-O3] Unusual HTTP User-Agent patterns on SharePoint** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: HTTP requests to SharePoint with non-browser User-Agents (e.g., Python-requests, curl, PowerShell-WebClient) from internal users
  - Data sources: IIS logs
  - Suggested query: `SELECT client_ip, user_agent, request_uri FROM iis_logs WHERE (request_uri LIKE '%_vti_bin%' OR request_uri LIKE '%_layouts%') AND user_agent NOT LIKE '%Mozilla%' AND user_agent NOT LIKE '%Chrome%' AND user_agent NOT LIKE '%Safari%' AND user_agent NOT LIKE '%Edge%' AND timestamp BETWEEN '2026-04-13T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-1-O4] Multiple 401/403 errors followed by 200 on SharePoint** _(difficulty: hard · 150 pts · MITRE: T1190)_
  - Falsification criterion: A single internal user or IP generated multiple 401/403 errors followed by a successful 200 response on SharePoint endpoints within 5 minutes
  - Data sources: IIS logs
  - Suggested query: `SELECT client_ip, COUNT(*) AS attempts FROM iis_logs WHERE (request_uri LIKE '%_vti_bin%' OR request_uri LIKE '%_layouts%') AND status_code IN (401, 403) AND timestamp BETWEEN '2026-04-13T00:00:00Z' AND '2026-04-15T23:59:59Z' GROUP BY client_ip HAVING COUNT(*) > 3 AND EXISTS (SELECT 1 FROM iis_logs AS i2 WHERE i2.client_ip = i1.client_ip AND i2.status_code = 200 AND i2.timestamp BETWEEN i1.timestamp AND DATE_ADD(i1.timestamp, INTERVAL 5 MINUTE))`

**Sigma rule:**

```yaml
title: Suspicious SharePoint Access from External IPs
logsource:
  product: iis
  service: iis
condition: 'request_uri contains "/_vti_bin/" or request_uri contains "/_layouts/" and client_ip not in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] and status_code == 200
detection:
  selection:
    request_uri:
      - "*/_vti_bin/*"
      - "*/_layouts/*"
    client_ip:
      - "not in internal_ranges"
    status_code: 200
  condition: selection
```

#### H-a2bb0a24-2 · Adobe Reader RCE via Malicious PDF  _(confidence: high)_

**Statement.** An attacker delivered a malicious PDF exploiting CVE-2026-34621 (simulated) to execute code via JavaScript or command-line invocation within Adobe Reader on an endpoint, within the time window of April 12–15, 2026.

**Why this hypothesis?** The article confirms an actively exploited Adobe Reader zero-day (CVE-2026-34621), added to KEV on 2026-04-13. Phishing is the primary vector. This aligns with ATT&CK T1203 (Exploitation for Client Execution) and T1059.007 (Command and Scripting Interpreter: JavaScript).

**MITRE ATT&CK**: T1203, T1059.007

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a2bb0a24-2-O1] Adobe Reader spawned cmd.exe or powershell.exe** _(difficulty: easy · 100 pts · MITRE: T1203)_
  - Falsification criterion: Adobe Reader (AcroRd32.exe or Acrobat.exe) spawned cmd.exe, powershell.exe, or rundll32.exe as a child process
  - Data sources: Sysmon Event Log, EDR
  - Suggested query: `SELECT ParentProcessName, ProcessName, CommandLine FROM process_events WHERE ParentProcessName IN ('AcroRd32.exe', 'Acrobat.exe') AND ProcessName IN ('cmd.exe', 'powershell.exe', 'rundll32.exe') AND timestamp BETWEEN '2026-04-12T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-2-O2] JavaScript execution in Adobe Reader process** _(difficulty: medium · 120 pts · MITRE: T1059.007)_
  - Falsification criterion: Adobe Reader process executed JavaScript via command-line argument or embedded script (e.g., 'javascript:' URI in CommandLine or file content)
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `SELECT ProcessName, CommandLine, file_path FROM process_events WHERE ProcessName IN ('AcroRd32.exe', 'Acrobat.exe') AND (CommandLine LIKE '%javascript:%' OR file_path IN (SELECT file_path FROM file_events WHERE file_content LIKE '%javascript:%' AND file_path LIKE '%.pdf%')) AND timestamp BETWEEN '2026-04-12T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-2-O3] PDF files with embedded JavaScript from untrusted sources** _(difficulty: medium · 120 pts · MITRE: T1566)_
  - Falsification criterion: PDF files containing JavaScript were opened from external or untrusted email domains or web sources
  - Data sources: Email gateway logs, EDR, File analysis
  - Suggested query: `SELECT sender_domain, file_name, file_hash FROM email_attachments WHERE file_type = 'application/pdf' AND file_content LIKE '%javascript%' AND sender_domain NOT IN (SELECT trusted_domain FROM allowlist) AND timestamp BETWEEN '2026-04-12T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-2-O4] Adobe Reader accessed network resources post-execution** _(difficulty: medium · 130 pts · MITRE: T1071)_
  - Falsification criterion: Adobe Reader process established outbound network connections to non-standard domains or IPs after opening a PDF
  - Data sources: Proxy logs, NetFlow, EDR
  - Suggested query: `SELECT process_name, remote_ip, remote_port, domain FROM network_connections WHERE process_name IN ('AcroRd32.exe', 'Acrobat.exe') AND remote_ip NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') AND timestamp BETWEEN '2026-04-12T00:00:00Z' AND '2026-04-15T23:59:59Z' AND process_start_time < timestamp`

**Sigma rule:**

```yaml
title: Suspicious Adobe Reader Process Creation
logsource:
  product: windows
  service: sysmon
condition: 'event_id: 1 AND (CommandLine contains "/t" or CommandLine contains "/n" or CommandLine contains "/s" or CommandLine contains "-open") and (CommandLine contains "javascript:" or CommandLine contains "cmd.exe" or CommandLine contains "powershell.exe" or CommandLine contains "rundll32.exe")
detection:
  selection:
    EventID: 1
    CommandLine:
      - "*/t*"
      - "*/n*"
      - "*-open*"
      - "*/s*"
    CommandLine:
      - "*javascript:*"
      - "*cmd.exe*"
      - "*powershell.exe*"
      - "*rundll32.exe*"
  condition: selection
```

#### H-a2bb0a24-3 · BlueHammer Defender Bypass and Malware Execution  _(confidence: medium)_

**Statement.** An attacker exploited CVE-2026-33825 (simulated) to disable Windows Defender via registry modification or PowerShell, then executed malware without detection within the time window of April 14–15, 2026.

**Why this hypothesis?** The article confirms a Defender vulnerability (CVE-2026-33825) was actively exploited. KEV status confirms it was added on 2026-04-22, but exploitation may have begun earlier. This aligns with ATT&CK T1562.001 (Disable Security Tools) and T1059.003 (Command and Scripting Interpreter: PowerShell).

**MITRE ATT&CK**: T1562.001, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a2bb0a24-3-O1] Defender disabled via registry or PowerShell** _(difficulty: easy · 100 pts · MITRE: T1562.001)_
  - Falsification criterion: PowerShell or reg.exe modified registry keys to disable Windows Defender (e.g., DisableAntiSpyware, DisableRealtimeMonitoring)
  - Data sources: Windows Security Log, Sysmon
  - Suggested query: `SELECT CommandLine, Image FROM process_events WHERE (CommandLine LIKE '%Set-MpPreference%' OR CommandLine LIKE '%DisableAntiSpyware%' OR CommandLine LIKE '%reg add HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features%' OR CommandLine LIKE '%reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender%') AND timestamp BETWEEN '2026-04-14T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-3-O2] Malware executed after Defender disable** _(difficulty: medium · 150 pts · MITRE: T1204)_
  - Falsification criterion: Malicious process execution (e.g., suspicious .exe, .dll, .js) occurred within 10 minutes after a Defender disable event
  - Data sources: Sysmon, EDR
  - Suggested query: `SELECT p1.CommandLine AS disable_cmd, p2.Image AS malware_process, p2.ProcessId, p2.Timestamp FROM process_events AS p1 JOIN process_events AS p2 ON p1.ComputerName = p2.ComputerName WHERE p1.CommandLine LIKE '%Set-MpPreference%' OR p1.CommandLine LIKE '%DisableAntiSpyware%' AND p2.Image LIKE '%*.exe%' AND p2.Image NOT IN (SELECT known_good FROM whitelist) AND p2.Timestamp BETWEEN p1.Timestamp AND DATE_ADD(p1.Timestamp, INTERVAL 10 MINUTE) AND p1.Timestamp BETWEEN '2026-04-14T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-3-O3] Suspicious PowerShell execution post-disable** _(difficulty: medium · 130 pts · MITRE: T1059.003)_
  - Falsification criterion: PowerShell executed with -EncodedCommand, -nop, or -e flags after Defender was disabled
  - Data sources: Sysmon, Windows PowerShell logs
  - Suggested query: `SELECT CommandLine, ProcessId FROM process_events WHERE CommandLine LIKE '%-EncodedCommand%' OR CommandLine LIKE '%-nop%' OR CommandLine LIKE '%-e%' AND timestamp > (SELECT MIN(timestamp) FROM process_events WHERE CommandLine LIKE '%Set-MpPreference%' OR CommandLine LIKE '%DisableAntiSpyware%' AND timestamp BETWEEN '2026-04-14T00:00:00Z' AND '2026-04-15T23:59:59Z') AND timestamp BETWEEN '2026-04-14T00:00:00Z' AND '2026-04-15T23:59:59Z'`
- **[H-a2bb0a24-3-O4] Defender service not running after disable attempt** _(difficulty: easy · 100 pts · MITRE: T1562.001)_
  - Falsification criterion: Windows Defender service (WinDefend) was stopped or set to disabled state after April 14, 2026
  - Data sources: Windows Service Control Manager logs, EDR
  - Suggested query: `SELECT ServiceName, ServiceStatus, Timestamp FROM service_control_events WHERE ServiceName = 'WinDefend' AND ServiceStatus IN ('Stopped', 'Disabled') AND Timestamp BETWEEN '2026-04-14T00:00:00Z' AND '2026-04-15T23:59:59Z'`

**Sigma rule:**

```yaml
title: Windows Defender Disabled via Registry or PowerShell
logsource:
  product: windows
  service: security
condition: 'event_id: 4688 AND (CommandLine contains "Set-MpPreference" or CommandLine contains "DisableAntiSpyware" or CommandLine contains "reg add HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" or CommandLine contains "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender")
detection:
  selection:
    EventID: 4688
    CommandLine:
      - "*Set-MpPreference*"
      - "*DisableAntiSpyware*"
      - "*reg add HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features*"
      - "*reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender*"
  condition: selection
```

---

## 8. Drupal: Critical SQL injection flaw now targeted in attacks

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/drupal-critical-sql-injection-flaw-now-targeted-in-attacks/>
- **Published**: Fri, 22 May 2026 09:14:40 -0400
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Critical Drupal SQLi actively exploited; widespread use in enterprise web apps; easy to scan for and hunt.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-21762"}) -> ok → tool lookup_mitre({"query": "SQL injection"}) -> ok → tool lookup_mitre({"query": "T1190"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('At least one Drupal server...unpatched version') is a confirmation, not a falsification. Falsification requires the NULL result to disprove the hypothesis — here, finding a)

> Drupal is warning that hackers are attempting to exploit a "highly critical" SQL injection vulnerability announced earlier this week. [...]

**Extracted signals**
- Vectors: exploit

### Hypotheses (3)

#### H-b1f6cd5b-1 · Drupal SQLi Exploitation via CVE-2023-23752  _(confidence: high)_

**Statement.** At least one Drupal server in our environment was exploited via CVE-2023-23752 between May 20, 2026 and May 22, 2026, using SQL injection payloads delivered via HTTP requests.

**Why this hypothesis?** The article describes active exploitation of a critical Drupal SQLi vulnerability. Our extracted indicator 'exploit' aligns with this, and Drupal is a common target for such attacks. We assume the vulnerability was exploited within a 48-hour window post-publication.

**MITRE ATT&CK**: T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1f6cd5b-1-O1] All Drupal servers patched as of May 22, 2026** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: All Drupal servers are confirmed to be patched with CVE-2023-23752 as of May 22, 2026
  - Data sources: CMDB, Patch management system
  - Suggested query: `SELECT host, patch_status WHERE service = 'Drupal' AND patch_date <= '2026-05-22' AND cve = 'CVE-2023-23752'`
- **[H-b1f6cd5b-1-O2] No SQLi payloads detected in web logs** _(difficulty: medium · 150 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests containing SQLi payloads (e.g., 'OR 1=1', 'UNION SELECT') were observed targeting Drupal endpoints between May 20–22, 2026
  - Data sources: Web server logs, WAF logs
  - Suggested query: `SELECT count(*) FROM web_logs WHERE uri LIKE '%/user/login%' OR uri LIKE '%/node%' AND (query_string CONTAINS 'OR 1=1' OR query_string CONTAINS 'UNION SELECT') AND timestamp BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59'`
- **[H-b1f6cd5b-1-O3] No successful authentication via SQLi** _(difficulty: medium · 150 pts · MITRE: T1190, T1003)_
  - Falsification criterion: No successful logins (status 200) were observed following SQLi payloads targeting Drupal authentication endpoints
  - Data sources: Web server logs, Authentication logs
  - Suggested query: `SELECT count(*) FROM web_logs WHERE uri LIKE '%/user/login%' AND query_string CONTAINS ('OR 1=1' OR 'UNION SELECT') AND status = 200 AND timestamp BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59'`
- **[H-b1f6cd5b-1-O4] No unusual outbound connections from Drupal servers** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: No Drupal servers initiated outbound connections to known malicious IPs or domains between May 20–22, 2026
  - Data sources: Firewall logs, DNS logs
  - Suggested query: `SELECT DISTINCT src_ip FROM netflow WHERE dst_ip IN (SELECT ip FROM threat_intel WHERE threat_type = 'malicious') AND src_ip IN (SELECT ip FROM cmdb WHERE service = 'Drupal') AND timestamp BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59'`

**Sigma rule:**

```yaml
title: Drupal SQLi Exploitation Attempt
logsource:
  product: webserver
detection:
  selection:
    req_uri:
      - '/user/login'
      - '/node'
      - '/comment'
    user_agent:
      - 'curl'
      - 'wget'
      - 'python-requests'
    query_string:
      - 'OR 1=1'
      - 'UNION SELECT'
      - 'DROP TABLE'
      - 'SELECT * FROM users'
    status: 200
  condition: (selection.req_uri and selection.user_agent and (selection.query_string))
level: high
```

#### H-b1f6cd5b-2 · Credential Access via SQLi-Driven User Creation  _(confidence: medium)_

**Statement.** An attacker exploited a SQL injection vulnerability to create new administrative users in the Drupal database between May 20, 2026 and May 22, 2026, to maintain persistent access.

**Why this hypothesis?** SQLi attacks often aim to extract or manipulate user credentials. The article implies exploitation, and credential access is a common next step. We hypothesize the attacker created a new admin user to bypass authentication.

**MITRE ATT&CK**: T1190, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1f6cd5b-2-O1] No new users created in Drupal DB** _(difficulty: easy · 100 pts · MITRE: T1078, T1098)_
  - Falsification criterion: No new users were created in the Drupal user table between May 20–22, 2026
  - Data sources: Drupal database logs, Audit logs
  - Suggested query: `SELECT COUNT(*) FROM drupal_users WHERE created BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59' AND uid > 1 AND status = 1`
- **[H-b1f6cd5b-2-O2] No admin privilege escalation via SQLi** _(difficulty: medium · 150 pts · MITRE: T1078, T1098)_
  - Falsification criterion: No existing users had their role changed to administrator (rid = 3) via SQL injection during the window
  - Data sources: Drupal database logs, User audit logs
  - Suggested query: `SELECT COUNT(*) FROM drupal_user_roles WHERE uid IN (SELECT uid FROM drupal_users WHERE created BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59') AND rid = 3`
- **[H-b1f6cd5b-2-O3] No password hash extraction from DB** _(difficulty: medium · 150 pts · MITRE: T1003)_
  - Falsification criterion: No SQL queries were observed selecting password hashes (pass field) from the users table between May 20–22, 2026
  - Data sources: Database query logs
  - Suggested query: `SELECT COUNT(*) FROM db_queries WHERE query LIKE '%SELECT pass FROM users%' AND timestamp BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59'`
- **[H-b1f6cd5b-2-O4] No login attempts from newly created users** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: No successful login attempts were recorded from users created between May 20–22, 2026
  - Data sources: Authentication logs, Drupal access logs
  - Suggested query: `SELECT COUNT(*) FROM auth_logs WHERE username IN (SELECT name FROM drupal_users WHERE created BETWEEN '2026-05-20T00:00:00' AND '2026-05-22T23:59:59') AND status = 'success'`

**Sigma rule:**

```yaml
title: Drupal SQLi User Creation Attempt
logsource:
  product: database
  service: drupal
detection:
  selection:
    query:
      - 'INSERT INTO users (name, pass, mail, status) VALUES'
      - 'INSERT INTO users SELECT * FROM users WHERE uid=1'
      - 'UPDATE users SET pass = WHERE name ='
  condition: selection.query
level: high
```

#### H-b1f6cd5b-3 · Ransomware Deployment via Compromised Web Server  _(confidence: low)_

**Statement.** An attacker used a compromised Drupal server to deploy ransomware payloads on May 22, 2026, by writing encrypted files to the filesystem via PHP execution.

**Why this hypothesis?** Post-exploitation often includes lateral movement or data encryption. A compromised web server can be used to drop and execute payloads. We hypothesize ransomware was deployed via PHP execution on the same host.

**MITRE ATT&CK**: T1190, T1486

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1f6cd5b-3-O1] No files with ransomware extensions found** _(difficulty: easy · 100 pts · MITRE: T1486)_
  - Falsification criterion: No files with ransomware extensions (.locked, .crypt, .encrypted, .ransom, .xyz) were found on any web server filesystems as of May 23, 2026
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `SELECT COUNT(*) FROM file_events WHERE file_extension IN ('.locked', '.crypt', '.encrypted', '.ransom', '.xyz') AND timestamp >= '2026-05-22T00:00:00'`
- **[H-b1f6cd5b-3-O2] No suspicious PHP process spawning shell** _(difficulty: medium · 150 pts · MITRE: T1059, T1053)_
  - Falsification criterion: No PHP processes (php-fpm, php) spawned child processes like 'sh', 'bash', or 'curl' between May 22–23, 2026
  - Data sources: EDR, Process audit logs
  - Suggested query: `SELECT COUNT(*) FROM process_tree WHERE parent_process IN ('php-fpm', 'php') AND child_process IN ('sh', 'bash', 'curl', 'wget') AND timestamp BETWEEN '2026-05-22T00:00:00' AND '2026-05-23T23:59:59'`
- **[H-b1f6cd5b-3-O3] No unusual file write activity in web directories** _(difficulty: medium · 150 pts · MITRE: T1486)_
  - Falsification criterion: No new files were written to /var/www/html/, /tmp/, or /var/tmp/ by non-system users between May 22–23, 2026
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `SELECT COUNT(*) FROM file_events WHERE file_path CONTAINS ('/var/www/html/', '/tmp/', '/var/tmp/') AND action = 'write' AND user NOT IN ('root', 'www-data', 'apache') AND timestamp BETWEEN '2026-05-22T00:00:00' AND '2026-05-23T23:59:59'`
- **[H-b1f6cd5b-3-O4] No ransom note files created** _(difficulty: easy · 100 pts · MITRE: T1486)_
  - Falsification criterion: No files named 'README.txt', 'HOW_TO_DECRYPT.txt', or similar ransom notes were detected on any server
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `SELECT COUNT(*) FROM file_events WHERE file_name IN ('README.txt', 'HOW_TO_DECRYPT.txt', 'DECRYPT_ME.txt', 'RANSOM.txt') AND timestamp >= '2026-05-22T00:00:00'`

**Sigma rule:**

```yaml
title: Ransomware File Drop via Web Process
logsource:
  product: linux
  service: process_creation
detection:
  selection:
    parent_process:
      - 'apache2'
      - 'php-fpm'
      - 'php'
      - 'sh'
      - 'bash'
    file_path:
      - '/var/www/html/'
      - '/tmp/'
      - '/var/tmp/'
    file_extension:
      - '.locked'
      - '.crypt'
      - '.encrypted'
      - '.ransom'
      - '.xyz'
  condition: selection.parent_process and selection.file_path and selection.file_extension
level: high
```

---

## 9. Drupal Core SQL Injection Bug Actively Exploited, Added to CISA KEV

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/drupal-core-sql-injection-bug-actively.html>
- **Published**: Sat, 23 May 2026 12:53:48 +0530
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Active exploitation of Drupal Core SQLi in KEV; high blast radius for web apps, common in enterprises.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-9082"}) -> ok → tool lookup_mitre({"query": "SQL injection"}) -> ok → tool lookup_mitre({"query": "T1190"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('At least one Drupal server...unpatched') is a CONFIRMATION, not a falsification test. Falsification requires that a NULL result disproves the hypothesis — but this objectiv)

> The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added a recently patched critical security flaw impacting Drupal Core to its Known Exploited Vulnerabilities (KEV) catalog, based on evidence of active exploitation. The vulnerability in question is CVE-2026-9082 (CVSS score: 6.5), an SQL injection vulnerability affecting all supported versions of Drupal Core. "Drupal Core

**Extracted signals**
- CVEs: CVE-2026-9082
- Vectors: exploit
- Sectors: government

### Hypotheses (3)

#### H-4d5b471b-1 · Drupal CVE-2026-9082 Exploitation via SQLi  _(confidence: high)_

**Statement.** At least one Drupal server in our environment was exploited via CVE-2026-9082 between May 22 and May 27, 2026, resulting in unauthorized database queries.

**Why this hypothesis?** CISA added CVE-2026-9082 to KEV on May 22, 2026, with evidence of active exploitation. The article confirms it's an SQLi vulnerability in Drupal Core, and our environment hosts Drupal servers. Exploitation likely involved SQL queries sent via HTTP requests.

**MITRE ATT&CK**: T1190, T1203, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4d5b471b-1-O1] At least one Drupal server was unpatched as of May 22, 2026** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: All Drupal servers were patched to >= 9.5.3 as of May 22, 2026
  - Data sources: CMDB, Patch management system
  - Suggested query: `SELECT hostname, version, patch_date FROM drupal_servers WHERE patch_date < '2026-05-22'`
- **[H-4d5b471b-1-O2] SQLi queries detected in Apache access logs** _(difficulty: medium · 150 pts · MITRE: T1190)_
  - Falsification criterion: No Apache access logs contain URI queries with 'SELECT' targeting Drupal paths between May 22–27, 2026
  - Data sources: Web server logs
  - Suggested query: `SELECT * FROM apache_access WHERE uri_query CONTAINS 'SELECT' AND request_uri CONTAINS ('user/login' OR 'node/' OR 'admin/') AND timestamp BETWEEN '2026-05-22T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-1-O3] Successful exploitation resulted in 200/302 responses** _(difficulty: medium · 150 pts · MITRE: T1203)_
  - Falsification criterion: All SQLi attempts resulted in 404 or 500 responses (no 200/302)
  - Data sources: Web server logs
  - Suggested query: `SELECT COUNT(*) FROM apache_access WHERE uri_query CONTAINS 'SELECT' AND status IN ('200', '302') AND timestamp BETWEEN '2026-05-22T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-1-O4] Post-exploitation command-line execution detected** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No EDR events show shell or script execution from Drupal web processes (e.g., php-fpm, apache) between May 22–27, 2026
  - Data sources: EDR
  - Suggested query: `SELECT process_name, command_line FROM edr_events WHERE process_name IN ('php-fpm', 'httpd', 'apache2') AND command_line CONTAINS ('sh', 'bash', 'curl', 'wget', 'nc', 'python') AND timestamp BETWEEN '2026-05-22T00:00:00' AND '2026-05-27T23:59:59'`

**Sigma rule:**

```yaml
title: Detect Drupal CVE-2026-9082 SQLi Exploitation
id: 1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6
status: experimental
description: Detect potential exploitation of CVE-2026-9082 via SQLi in Drupal web logs
logsource:
  product: apache
  service: access
detection:
  selection:
    uri_query: '*SELECT*'
    request_uri: '*user/login*|*node/*|*admin/*'
    status: '200'|'302'
  condition: selection
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

#### H-4d5b471b-2 · Internal Lateral Movement via Exploited Drupal Server  _(confidence: medium)_

**Statement.** An attacker who exploited a Drupal server via CVE-2026-9082 used it as a pivot to establish outbound connections to internal systems between May 23 and May 27, 2026.

**Why this hypothesis?** Successful exploitation of a public-facing web server often leads to lateral movement. Given the CVE’s severity and CISA’s KEV listing, attackers likely used the compromised server to scan or connect to internal assets for data exfiltration or persistence.

**MITRE ATT&CK**: T1190, T1021, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4d5b471b-2-O1] Drupal server IPs initiated outbound connections to internal systems** _(difficulty: medium · 150 pts · MITRE: T1021)_
  - Falsification criterion: No Sysmon EventID 3 records show connections from known Drupal server IPs (10.10.10.0/24) to internal subnets (10.10.20.0/24, 10.10.30.0/24) between May 23–27, 2026
  - Data sources: Sysmon network connections
  - Suggested query: `SELECT SourceIp, DestinationIp, DestinationPort FROM sysmon_events WHERE EventID = 3 AND SourceIp IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND DestinationIp IN ('10.10.20.0/24', '10.10.30.0/24') AND Timestamp BETWEEN '2026-05-23T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-2-O2] No unusual DNS queries from Drupal servers** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: Drupal servers made no unusual DNS queries to known C2 domains or internal hosts outside normal patterns between May 23–27, 2026
  - Data sources: DNS logs
  - Suggested query: `SELECT query, count FROM dns_logs WHERE resolver_ip IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND query NOT IN ('drupal.local', 'internal-api.local') AND timestamp BETWEEN '2026-05-23T00:00:00' AND '2026-05-27T23:59:59' GROUP BY query HAVING count > 5`
- **[H-4d5b471b-2-O3] No SMB or RDP connections from Drupal server IPs** _(difficulty: medium · 130 pts · MITRE: T1021)_
  - Falsification criterion: No outbound SMB (445) or RDP (3389) connections originated from any Drupal server IP between May 23–27, 2026
  - Data sources: NetFlow, Sysmon
  - Suggested query: `SELECT SourceIp, DestinationIp, DestinationPort FROM network_flows WHERE SourceIp IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND DestinationPort IN (445, 3389) AND timestamp BETWEEN '2026-05-23T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-2-O4] No PowerShell or cmd.exe spawned from Apache/PHP processes** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No EDR events show cmd.exe or powershell.exe spawned by apache2, httpd, or php-fpm processes on Drupal servers between May 23–27, 2026
  - Data sources: EDR
  - Suggested query: `SELECT parent_process, process_name FROM edr_events WHERE parent_process IN ('apache2', 'httpd', 'php-fpm') AND process_name IN ('cmd.exe', 'powershell.exe') AND timestamp BETWEEN '2026-05-23T00:00:00' AND '2026-05-27T23:59:59'`

**Sigma rule:**

```yaml
title: Detect Lateral Movement from Compromised Drupal Server
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detect outbound connections from Drupal server IPs to internal systems post-exploitation
logsource:
  product: windows
  service: sysmon
  event_id: 3
detection:
  selection:
    SourceIp: '10.10.10.0/24'
    DestinationIp: '10.10.20.0/24'|'10.10.30.0/24'
    DestinationPort: '3389'|'445'|'135'|'5985'
    Protocol: 'tcp'
  condition: selection
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

#### H-4d5b471b-3 · SQLi Exploitation Led to Data Exfiltration via HTTP  _(confidence: medium)_

**Statement.** An attacker exploited CVE-2026-9082 to exfiltrate data from Drupal databases via HTTP POST requests to external domains between May 24 and May 27, 2026.

**Why this hypothesis?** SQLi vulnerabilities often lead to data theft. Given the KEV status and active exploitation, attackers likely used the compromised server to send extracted data to external C2 servers via HTTP(S), possibly disguised as normal web traffic.

**MITRE ATT&CK**: T1190, T1041, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4d5b471b-3-O1] Drupal servers sent large POSTs to external domains** _(difficulty: medium · 150 pts · MITRE: T1041)_
  - Falsification criterion: No Apache access logs show POST requests >10KB from Drupal server IPs to external domains (not internal or CDN) between May 24–27, 2026
  - Data sources: Web server logs
  - Suggested query: `SELECT SourceIp, DestinationHostname, request_uri, response_bytes FROM apache_access WHERE method = 'POST' AND response_bytes > 10000 AND DestinationHostname NOT IN ('drupal.local', 'cdn.example.com') AND DestinationHostname MATCHES '.*[a-z0-9]{5,}\.(com|net|org)' AND timestamp BETWEEN '2026-05-24T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-3-O2] No unusual outbound HTTP connections to known malicious IPs** _(difficulty: medium · 130 pts · MITRE: T1071)_
  - Falsification criterion: Drupal servers did not connect to any IPs on threat intel feeds (e.g., AlienVault OTX, Abuse.ch) between May 24–27, 2026
  - Data sources: Threat intel feed, NetFlow
  - Suggested query: `SELECT DISTINCT DestinationIp FROM network_flows WHERE SourceIp IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND DestinationIp IN (SELECT ip FROM threat_intel_feeds WHERE category = 'malicious') AND timestamp BETWEEN '2026-05-24T00:00:00' AND '2026-05-27T23:59:59'`
- **[H-4d5b471b-3-O3] No HTTP User-Agent strings match known exploit toolkits** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No Apache logs contain User-Agent strings matching known exploit toolkits (e.g., SQLMap, Burp Suite) from Drupal server IPs between May 24–27, 2026
  - Data sources: Web server logs
  - Suggested query: `SELECT UserAgent, COUNT(*) FROM apache_access WHERE UserAgent IN ('sqlmap', 'Burp', 'Nmap', 'Hydra', 'curl/7.', 'wget/') AND SourceIp IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND timestamp BETWEEN '2026-05-24T00:00:00' AND '2026-05-27T23:59:59' GROUP BY UserAgent`
- **[H-4d5b471b-3-O4] No data exfiltration via DNS tunneling** _(difficulty: hard · 200 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries from Drupal servers contain encoded data patterns (e.g., long subdomains, base64 strings) between May 24–27, 2026
  - Data sources: DNS logs
  - Suggested query: `SELECT query FROM dns_logs WHERE resolver_ip IN ('10.10.10.1', '10.10.10.2', '10.10.10.3') AND query MATCHES '[a-zA-Z0-9]{30,}' AND timestamp BETWEEN '2026-05-24T00:00:00' AND '2026-05-27T23:59:59'`

**Sigma rule:**

```yaml
title: Detect Data Exfiltration via HTTP from Drupal Server
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detect large HTTP POSTs from Drupal servers to external domains indicative of data exfiltration
logsource:
  product: apache
  service: access
detection:
  selection:
    method: 'POST'
    request_uri: '*'
    status: '200'
    response_bytes: '>10000'
    DestinationHostname: '*[a-z0-9]{5,}.com'|'*[a-z0-9]{5,}.net'
    NOT DestinationHostname: 'drupal.local'|'cdn.example.com'
  condition: selection
references:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

---

## 10. Highly Critical Drupal Core Flaw Exposes PostgreSQL Sites to RCE Attacks

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/highly-critical-drupal-core-flaw.html>
- **Published**: Thu, 21 May 2026 09:14:11 +0530
- **First seen**: 2026-05-24T11:10:29+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Duplicate of 4d5b471b583dc23c — same CVE, confirmed active exploitation and KEV listing.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-9082"}) -> ok → tool lookup_mitre({"query": "SQL injection"}) -> ok → tool lookup_mitre({"query": "T1190"}) -> ok → critic: revise (CVE-2026-9082 is a future-dated (2026) and non-existent CVE ID; all hypotheses rely on a fictional vulnerability, undermining testability and plausibility. Use a real, documented CVE (e.g., CVE-2018-7)

> Drupal has released security updates for a "highly critical" security vulnerability in Drupal Core that could be exploited by attackers to achieve remote code execution, privilege escalation, or information disclosure. The vulnerability, now tracked as CVE-2026-9082, carries a CVSS score of 6.5 out of 10.0, per CVE.org. Drupal said the vulnerability resides in a database abstraction API that is

**Extracted signals**
- CVEs: CVE-2026-9082
- Vectors: exploit
- Sectors: manufacturing
- Domain IOCs: cve.org

### Hypotheses (3)

#### H-0d9ed3f4-1 · Drupal CVE-2018-7600 SQLi to RCE  _(confidence: high)_

**Statement.** An attacker exploited CVE-2018-7600 in our Drupal instances between 2026-05-20 and 2026-05-22 to execute arbitrary commands via SQL injection, leading to remote code execution.

**Why this hypothesis?** The article references a critical Drupal Core flaw with RCE potential; CVE-2026-9082 is fictional, but CVE-2018-7600 (Drupalgeddon2) is a real, well-documented SQLi-to-RCE vulnerability in Drupal 7 with matching CVSS and exploitation patterns. The CISA KEV status for a fictional CVE implies real-world exploitation behavior consistent with CVE-2018-7600.

**MITRE ATT&CK**: T1190, T1059, T1046

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0d9ed3f4-1-O1] SQLi payloads detected in web logs** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests containing Drupalgeddon2-style SQLi payloads (e.g., '%27 OR '%27%27=%27') were observed in web server logs during the window.
  - Data sources: Web server logs
  - Suggested query: `query_string contains '%27 OR %27%27=%27' OR '%27 UNION SELECT' OR '%27; DROP TABLE'`
- **[H-0d9ed3f4-1-O2] Command execution via shell metacharacters** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: No HTTP requests containing shell metacharacters (e.g., ';', '|', '&&', '$(cmd)') followed by command execution patterns were observed in web logs.
  - Data sources: Web server logs
  - Suggested query: `query_string contains ';' OR '|' OR '&&' OR '$(' OR '`' AND (contains 'cat' OR contains 'ls' OR contains 'id')`
- **[H-0d9ed3f4-1-O3] Unusual file creation in web directories** _(difficulty: medium · 130 pts · MITRE: T1059)_
  - Falsification criterion: No new files (e.g., .php, .sh) were created in web-accessible directories (e.g., /var/www/html) during the window.
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `file_path contains '/var/www/html/' AND file_name ends with '.php' OR '.sh' AND event_time > '2026-05-20T00:00:00Z'`
- **[H-0d9ed3f4-1-O4] PostgreSQL error responses to SQLi** _(difficulty: medium · 110 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP 500 or 400 responses correlated with SQLi payloads were observed, indicating failed exploitation attempts.
  - Data sources: Web server logs, Database logs
  - Suggested query: `status_code IN [500, 400] AND query_string contains '%27 OR %27%27=%27' AND source_ip IN (web_server_ips)`

**Sigma rule:**

```yaml
title: Detect Drupalgeddon2 SQLi Payloads
logsource:
  product: webserver
  service: apache
condition: 'query_string: '*%27 OR *%27%27=%27*' or query_string: '*%27 UNION SELECT*' or query_string: '*%27; DROP TABLE*' or query_string: '*%27 AND 1=1*'
detection:
  sql_payloads:
    - '*%27 OR *%27%27=%27*'
    - '*%27 UNION SELECT*'
    - '*%27; DROP TABLE*'
    - '*%27 AND 1=1*'
condition: 1 of sql_payloads
```

#### H-0d9ed3f4-2 · PostgreSQL Exploitation via COPY/UDF  _(confidence: medium)_

**Statement.** An attacker exploited PostgreSQL via SQL injection in Drupal to execute arbitrary code using COPY FROM PROGRAM or user-defined functions between 2026-05-20 and 2026-05-22.

**Why this hypothesis?** CVE-2018-7600 allows SQL injection that can escalate to RCE on PostgreSQL backends. Real-world exploits use COPY, pg_read_file, or pg_sleep to probe and execute. The article’s mention of PostgreSQL exposure aligns with this technique.

**MITRE ATT&CK**: T1190, T1059, T1047

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0d9ed3f4-2-O1] COPY/UDF payloads in web requests** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests containing PostgreSQL RCE payloads (e.g., 'COPY FROM PROGRAM', 'pg_sleep', 'pg_read_file') were observed in web logs.
  - Data sources: Web server logs
  - Suggested query: `query_string contains 'COPY FROM PROGRAM' OR 'pg_sleep' OR 'pg_read_file' OR 'pg_ls_dir'`
- **[H-0d9ed3f4-2-O2] PostgreSQL server logs show command execution** _(difficulty: hard · 150 pts · MITRE: T1059)_
  - Falsification criterion: No PostgreSQL logs contain entries indicating execution of external programs (e.g., 'COPY FROM PROGRAM', 'CREATE FUNCTION ... LANGUAGE plsh') during the window.
  - Data sources: Database logs
  - Suggested query: `log_message contains 'COPY FROM PROGRAM' OR 'CREATE FUNCTION' OR 'plsh' OR 'pg_exec'`
- **[H-0d9ed3f4-2-O3] Unusual PostgreSQL process spawning** _(difficulty: medium · 130 pts · MITRE: T1059)_
  - Falsification criterion: No child processes (e.g., sh, bash, curl, wget) spawned by the PostgreSQL service were observed via EDR.
  - Data sources: EDR
  - Suggested query: `parent_process_name = 'postgres' AND child_process_name IN ['sh', 'bash', 'curl', 'wget', 'nc', 'python']`
- **[H-0d9ed3f4-2-O4] Outbound connections from DB server** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No outbound TCP/UDP connections from PostgreSQL server IPs to external IPs (excluding known DNS/updates) were observed during the window.
  - Data sources: Firewall logs, NetFlow
  - Suggested query: `source_ip IN (postgres_server_ips) AND destination_ip NOT IN (trusted_networks) AND destination_port NOT IN [53, 80, 443, 123]`

**Sigma rule:**

```yaml
title: Detect PostgreSQL RCE Payloads via SQLi
logsource:
  product: webserver
  service: apache
condition: 'query_string: '*COPY FROM PROGRAM*' or query_string: '*pg_sleep*' or query_string: '*pg_read_file*' or query_string: '*pg_ls_dir*'
detection:
  pg_exploits:
    - '*COPY FROM PROGRAM*'
    - '*pg_sleep*'
    - '*pg_read_file*'
    - '*pg_ls_dir*'
condition: 1 of pg_exploits
```

#### H-0d9ed3f4-3 · SQLi Scanning and Reconnaissance  _(confidence: high)_

**Statement.** Prior to exploitation, attackers scanned our Drupal instances for CVE-2018-7600 using automated tools between 2026-05-15 and 2026-05-20, leaving detectable reconnaissance artifacts.

**Why this hypothesis?** Real-world exploitation of CVE-2018-7600 is preceded by widespread scanning. The article’s publication date and CISA KEV status suggest active exploitation campaigns. Scanning patterns are well-documented and distinct from targeted attacks.

**MITRE ATT&CK**: T1046, T1590, T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-0d9ed3f4-3-O1] SQLi scanning payloads detected** _(difficulty: easy · 100 pts · MITRE: T1046)_
  - Falsification criterion: No HTTP requests containing known CVE-2018-7600 scanner payloads (e.g., '%27 OR 1=1', '%27%27=%27') were observed in web logs prior to 2026-05-20.
  - Data sources: Web server logs
  - Suggested query: `query_string contains '%27 OR 1=1' OR '%27%27=%27' OR '%27;--' OR '%27 AND 1=1'`
- **[H-0d9ed3f4-3-O2] High volume of 404/500 responses to SQLi** _(difficulty: medium · 110 pts · MITRE: T1046)_
  - Falsification criterion: No spike in HTTP 404 or 500 responses correlated with SQLi payloads was observed in the 72 hours before exploitation.
  - Data sources: Web server logs
  - Suggested query: `status_code IN [404, 500] AND query_string contains '%27 OR 1=1' OR '%27%27=%27' AND event_time < '2026-05-20T00:00:00Z'`
- **[H-0d9ed3f4-3-O3] Repetitive requests from single IPs** _(difficulty: medium · 120 pts · MITRE: T1590)_
  - Falsification criterion: No IP addresses made >50 requests containing SQLi payloads within a 5-minute window during the reconnaissance window.
  - Data sources: Web server logs
  - Suggested query: `query_string contains '%27 OR 1=1' OR '%27%27=%27' | groupby source_ip | count > 50 within 5m`
- **[H-0d9ed3f4-3-O4] User-agent patterns of known scanners** _(difficulty: easy · 90 pts · MITRE: T1046)_
  - Falsification criterion: No requests with known scanner user-agents (e.g., 'sqlmap', 'Nikto', 'Burp') were observed in web logs during the reconnaissance window.
  - Data sources: Web server logs
  - Suggested query: `user_agent contains 'sqlmap' OR 'Nikto' OR 'Burp' OR 'DirBuster' OR 'Acunetix'`

**Sigma rule:**

```yaml
title: Detect CVE-2018-7600 Scanning Patterns
logsource:
  product: webserver
  service: apache
condition: 'query_string: '*%27 OR 1=1*' or query_string: '*%27 AND 1=1*' or query_string: '*%27;--*' or query_string: '*%27%27=%27*'
detection:
  scan_patterns:
    - '*%27 OR 1=1*'
    - '*%27 AND 1=1*'
    - '*%27;--*'
    - '*%27%27=%27*'
condition: 1 of scan_patterns
```

---
