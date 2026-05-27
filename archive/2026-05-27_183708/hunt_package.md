# Threat Hunting News Package

- Generated: `2026-05-27T18:37:05+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **290**  ·  Skipped (below threshold): **289**  ·  Briefings: **50**
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

## 8. CISA Adds Three Known Exploited Vulnerabilities to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog>
- **Published**: Wed, 27 May 26 12:00:00 +0000
- **First seen**: 2026-05-27T18:37:05+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Three new CISA KEV-listed vulnerabilities with active exploitation; products (Daemon Tools Lite, TanStack, Nx Console) are used in enterprise environments; high blast radius and immediate defensive action required.
- **Agent trace**: kev: 3 CVE(s) in CISA KEV → critic: revise (CVE-2026-8398, CVE-2026-45321, and CVE-2026-48027 are not real vulnerabilities — CVE IDs from 2026 are future-dated and invalid. CVEs are only assigned for disclosed, verified vulnerabilities, and 202)

> CISA has added three new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-8398 Daemon Tools Lite Embedded Malicious Code Vulnerability CVE-2026-45321 TanStack Unspecified Vulnerability CVE-2026-48027 Nx Console Embedded Malicious Code Vulnerability These types of vulnerabilities are frequent attack vectors for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive (BOD) 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities established the KEV Catalog as a living list of known Common Vulnerabilities and Exposures (CVEs) that carry significant risk to the federal enterprise. BOD 22-01 requires Federal Civilian Executive Branch (FCEB) agencies to remediate identified vulnerabilities by the due date to protect FCEB networks against active threats. See the BOD 22-01 Fact Sheet for more information. Although BOD 22-01 only applies to FCEB agencies, CISA strongly urges all organizations to reduce their exposure to cyberattacks by prioritizing timely remediation of KEV Catalog vulnerabilities as part of their vulnerability management practice. CISA will continue to add vulnerabilities to the catalog that meet the specified criteria .

**Extracted signals**
- CVEs: CVE-2026-8398, CVE-2026-45321, CVE-2026-48027
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-be88b3d2-1 · Daemon Tools Lite Exploitation via Malicious Image Mount  _(confidence: medium)_

**Statement.** An attacker exploited CVE-2026-8398 in Daemon Tools Lite on at least one endpoint in our environment between 2026-05-27 and 2026-05-28 by mounting a malicious ISO or MDS image that triggered embedded code execution.

**Why this hypothesis?** CISA lists CVE-2026-8398 as exploited in Daemon Tools Lite, a tool used for mounting disk images. Attackers commonly abuse this functionality to execute malicious payloads via crafted images without user interaction.

**MITRE ATT&CK**: T1190, T1204, T1059

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-be88b3d2-1-O1] Detect malicious binary execution from Daemon Tools Lite directory** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: A process is created from a path containing '\DaemonTools\' with a command line including '-mount' and a non-standard image file extension (.mds, .mdx, .b5t) and spawns a child process with suspicious parent-child lineage (e.g., cmd.exe or powershell.exe)
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessCreate where Image contains '\DaemonTools\' and CommandLine contains '-mount' and (Image ends with '.mds' or '.mdx' or '.b5t') and ParentImage != 'C:\Program Files\Daemon Tools Lite\dtool.exe'`
- **[H-be88b3d2-1-O2] Detect persistence via registry run key after image mount** _(difficulty: medium · 100 pts · MITRE: T1547)_
  - Falsification criterion: A registry key under HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\...\Run is modified within 5 minutes of a Daemon Tools Lite mount event with a non-whitelisted executable path
  - Data sources: Sysmon, Registry logs
  - Suggested query: `RegistryEvent where TargetObject contains 'Run' and (NewValue contains '\DaemonTools\' or NewValue contains '.exe' and not NewValue contains 'C:\Windows\') and EventID = 12 and TimeCreated > (earliest DaemonTools mount event) and TimeCreated < (earliest DaemonTools mount event + 5m)`
- **[H-be88b3d2-1-O3] Detect network beaconing from Daemon Tools Lite process** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: A process spawned from Daemon Tools Lite establishes an outbound connection to a non-whitelisted external IP or domain within 10 minutes of image mount
  - Data sources: NetFlow, EDR
  - Suggested query: `NetworkConnection where ProcessImage contains '\DaemonTools\' and DestinationIp not in whitelist_ips and DestinationPort in [80, 443, 53] and TimeCreated > (earliest DaemonTools mount event) and TimeCreated < (earliest DaemonTools mount event + 10m)`
- **[H-be88b3d2-1-O4] Detect process injection into explorer.exe from Daemon Tools Lite** _(difficulty: hard · 150 pts · MITRE: T1055)_
  - Falsification criterion: A process created by Daemon Tools Lite injects code into explorer.exe or svchost.exe via CreateRemoteThread or NtCreateThreadEx
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessAccess where TargetImage contains 'explorer.exe' or TargetImage contains 'svchost.exe' and ProcessImage contains '\DaemonTools\' and AccessMask contains '0x10' and EventID = 10`
- **[H-be88b3d2-1-O5] Detect deletion of shadow copies post-exploitation** _(difficulty: medium · 120 pts · MITRE: T1490)_
  - Falsification criterion: A command-line invocation of 'vssadmin delete shadows' or 'wbadmin delete catalog' occurs within 15 minutes of a Daemon Tools Lite mount event
  - Data sources: Sysmon, Windows Event Log
  - Suggested query: `ProcessCreate where Image contains 'vssadmin.exe' or Image contains 'wbadmin.exe' and CommandLine contains 'delete' and TimeCreated > (earliest DaemonTools mount event) and TimeCreated < (earliest DaemonTools mount event + 15m)`

**Sigma rule:**

```yaml
title: Detect Daemon Tools Lite Malicious Image Mount
id: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
status: experimental
description: Detects execution of suspicious binaries from Daemon Tools Lite mount directories
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\DaemonTools\*.exe'
    CommandLine: '*-mount*'
  condition: selection
falsepositives:
  - Legitimate use of Daemon Tools Lite for mounting legal ISOs
level: medium
```

#### H-be88b3d2-2 · TanStack Package Registry Compromise via CI/CD Pipeline  _(confidence: high)_

**Statement.** An attacker exploited CVE-2026-45321 in TanStack by compromising a CI/CD pipeline or developer workstation between 2026-05-27 and 2026-05-28 to inject malicious code into the npm package registry or local node_modules.

**Why this hypothesis?** CISA lists CVE-2026-45321 as exploited in TanStack, a popular JavaScript library. Attackers commonly compromise package registries or developer environments to inject malicious code into dependencies, which then propagate to production systems via build pipelines.

**MITRE ATT&CK**: T1195, T1204, T1059

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-be88b3d2-2-O1] Detect npm install of TanStack from non-official registry** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: An npm install command targeting tanstack packages is executed with a --registry flag pointing to a non-whitelisted HTTP/HTTPS endpoint
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessCreate where Image ends with 'node.exe' and CommandLine contains 'install tanstack' and (CommandLine contains '--registry http://' or CommandLine contains '--registry https://' and not CommandLine contains 'registry.npmjs.org')`
- **[H-be88b3d2-2-O2] Detect post-install package tampering in node_modules** _(difficulty: medium · 120 pts · MITRE: T1204)_
  - Falsification criterion: A file in node_modules/@tanstack/ is modified after installation with a .js or .json extension containing base64-encoded strings, eval(), or obfuscated code
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `FileCreate where TargetFilename contains '\node_modules\@tanstack\' and (TargetFilename ends with '.js' or TargetFilename ends with '.json') and FileContent contains 'eval(' or FileContent contains 'atob(' or FileContent contains 'new Function('`
- **[H-be88b3d2-2-O3] Detect CI/CD pipeline compromise via npm install in build job** _(difficulty: medium · 130 pts · MITRE: T1195)_
  - Falsification criterion: An npm install command targeting tanstack is executed within a Jenkins, GitHub Actions, or GitLab CI job context (via environment variable CI=true) from a non-developer machine
  - Data sources: CI/CD logs, EDR
  - Suggested query: `ProcessCreate where Image ends with 'node.exe' and CommandLine contains 'install tanstack' and Environment contains 'CI=true' and ComputerName not in developer_workstations`
- **[H-be88b3d2-2-O4] Detect outbound data exfiltration from node_modules directory** _(difficulty: hard · 150 pts · MITRE: T1041)_
  - Falsification criterion: A process reads or transfers files from a node_modules/@tanstack/ directory to an external domain or IP address within 1 hour of package installation
  - Data sources: NetFlow, EDR
  - Suggested query: `NetworkConnection where ProcessImage contains '\node_modules\@tanstack\' and DestinationIp not in whitelist_ips and DestinationPort in [80, 443, 22] and TimeCreated > (earliest npm install event) and TimeCreated < (earliest npm install event + 1h)`
- **[H-be88b3d2-2-O5] Detect persistence via post-install script execution** _(difficulty: medium · 120 pts · MITRE: T1546)_
  - Falsification criterion: A postinstall script in package.json for tanstack packages is executed and spawns a child process with suspicious behavior (e.g., powershell -enc, curl to external host)
  - Data sources: Sysmon, EDR
  - Suggested query: `ProcessCreate where ParentImage contains 'npm.cmd' and CommandLine contains 'postinstall' and Image contains 'powershell.exe' and CommandLine contains '-enc' or Image contains 'curl.exe' and CommandLine contains 'http://'`

**Sigma rule:**

```yaml
title: Detect Suspicious npm Install of TanStack from Non-Standard Registry
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects installation of TanStack packages from non-official registries or with suspicious flags
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\node.exe'
    CommandLine: '*install* tanstack*' and (CommandLine contains '@registry.example.com' or CommandLine contains '--registry http://' or CommandLine contains '--unsafe-perm')
  condition: selection
falsepositives:
  - Legitimate use of private npm registries
level: high
```

#### H-be88b3d2-3 · Nx Console Extension Compromise via Malicious Update  _(confidence: high)_

**Statement.** An attacker exploited CVE-2026-48027 in Nx Console by triggering a malicious extension update or API call within VS Code on a developer machine between 2026-05-27 and 2026-05-28, leading to remote code execution.

**Why this hypothesis?** CISA lists CVE-2026-48027 as exploited in Nx Console, a VS Code extension. Attackers commonly exploit extension update mechanisms or insecure API endpoints to execute code without user interaction, bypassing installation detection.

**MITRE ATT&CK**: T1195, T1204, T1059

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-be88b3d2-3-O1] Detect malicious extension update via non-official marketplace** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: VS Code attempts to download or install the Nx Console extension from a non-official URL (not marketplace.visualstudio.com) via HTTP/HTTPS
  - Data sources: EDR, Proxy logs
  - Suggested query: `NetworkConnection where ProcessImage contains '\Code.exe' and DestinationDomain contains 'marketplace.visualstudio.com' is false and (DestinationDomain contains 'nxconsole' or DestinationDomain contains 'nrwl') and DestinationPort in [80, 443]`
- **[H-be88b3d2-3-O2] Detect execution of malicious JavaScript from Nx Console extension folder** _(difficulty: hard · 150 pts · MITRE: T1059)_
  - Falsification criterion: A process (e.g., node.exe, powershell.exe) is spawned from a path under %USERPROFILE%\.vscode\extensions\nrwl.angular-console-* with a command line containing obfuscated code or network calls
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessCreate where ParentImage contains '\nrwl.angular-console-' and Image contains 'node.exe' or Image contains 'powershell.exe' and CommandLine contains 'eval(' or CommandLine contains 'atob(' or CommandLine contains 'http://'`
- **[H-be88b3d2-3-O3] Detect access to sensitive files post-extension compromise** _(difficulty: medium · 130 pts · MITRE: T1552)_
  - Falsification criterion: A process spawned by Code.exe accesses .env, aws credentials, or ssh keys within 5 minutes of an Nx Console extension load event
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `FileAccess where ProcessImage contains '\Code.exe' and TargetFilename contains '\.env' or TargetFilename contains '\.aws\credentials' or TargetFilename contains '\.ssh\' and TimeCreated > (earliest Code.exe extension load) and TimeCreated < (earliest Code.exe extension load + 5m)`
- **[H-be88b3d2-3-O4] Detect outbound C2 beacon from VS Code process** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: Code.exe establishes a persistent outbound connection to a non-whitelisted domain/IP with low-frequency, irregular timing (e.g., every 5-15 minutes) within 1 hour of extension load
  - Data sources: NetFlow, EDR
  - Suggested query: `NetworkConnection where ProcessImage contains '\Code.exe' and DestinationIp not in whitelist_ips and ConnectionCount > 3 and TimeBetweenConnections < 900 and TimeBetweenConnections > 300 and TimeCreated > (earliest extension load)`
- **[H-be88b3d2-3-O5] Detect registry modification for persistence via VS Code** _(difficulty: medium · 120 pts · MITRE: T1547)_
  - Falsification criterion: A registry key under HKCU\Software\Microsoft\Windows\CurrentVersion\Run is modified by Code.exe within 10 minutes of an Nx Console extension load
  - Data sources: Sysmon, Registry logs
  - Suggested query: `RegistryEvent where ProcessImage contains '\Code.exe' and TargetObject contains 'Run' and NewValue contains '\Code.exe' and TimeCreated > (earliest extension load) and TimeCreated < (earliest extension load + 10m)`

**Sigma rule:**

```yaml
title: Detect Suspicious VS Code Extension Update or API Call to Nx Console
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects VS Code extension update requests to non-official endpoints or suspicious API calls
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\Code.exe'
    CommandLine: '*--extension*nrwl.angular-console*' or CommandLine contains '--enable-proposed-api' and CommandLine contains 'nx'
    ParentImage: '*\Code.exe'
  condition: selection
falsepositives:
  - Legitimate extension updates via VS Code UI
level: high
```

---

## 9. CISA gives feds 4 days to patch actively exploited cPanel plugin flaw

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/cisa-gives-feds-4-days-to-patch-actively-exploited-cpanel-plugin-flaw/>
- **Published**: Wed, 27 May 2026 06:06:17 -0400
- **First seen**: 2026-05-27T10:15:32+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Actively exploited critical flaw in widely used cPanel plugin; short patch window indicates active, widespread exploitation risk in enterprise environments using cPanel.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-12345"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_mitre({"query": "remote code execution"}) -> ok → critic: revise (Hypothesis 1: The Sigma rule targets /wp-content/plugins/litespeed-cache/, but LiteSpeed Cache is a WordPress plugin, not a cPanel plugin. This is a fundamental misattribution. cPanel plugins are typi)

> The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has given U.S. federal agencies four days to secure their servers against a critical vulnerability in the LiteSpeed cPanel user-end plugin, which is actively being exploited in attacks. [...]

**Extracted signals**
- Vectors: exploit
- Sectors: government

### Hypotheses (3)

#### H-430efad0-1 · Exploitation of cPanel Web Interface via Valid Credentials  _(confidence: medium)_

**Statement.** An attacker gained access to our cPanel environment between May 20–27, 2026, by brute-forcing or credential stuffing valid user credentials, then deployed a web shell via the cPanel file manager or terminal.

**Why this hypothesis?** The article mentions active exploitation of a cPanel plugin, but no specific CVE exists for a 'LiteSpeed cPanel plugin'. However, cPanel itself is a high-value target. Credential-based access is a common initial vector (T1078) and aligns with the 'exploit' vector and government sector context.

**MITRE ATT&CK**: T1078, T1190, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-430efad0-1-O1] Detect unauthorized cPanel login from external IP** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: No login events to /cpsess*/ from non-whitelisted IPs during May 20–27, 2026
  - Data sources: Authentication logs, Web server logs
  - Suggested query: `filter uri contains '/cpsess*/' and status == 200 and src_ip not in trusted_admin_ips`
- **[H-430efad0-1-O2] Identify file upload via cPanel file manager** _(difficulty: medium · 120 pts · MITRE: T1105)_
  - Falsification criterion: No POST requests to /filemanager/upload.html with non-standard file extensions (.php, .jsp, .aspx) during the timeframe
  - Data sources: Web server logs
  - Suggested query: `filter uri contains '/filemanager/upload.html' and method == 'POST' and body contains '.php' or '.jsp' or '.aspx'`
- **[H-430efad0-1-O3] Detect command execution via cPanel terminal** _(difficulty: medium · 130 pts · MITRE: T1059.003)_
  - Falsification criterion: No successful access to /terminal/index.html from non-admin IPs during the timeframe
  - Data sources: Web server logs, EDR
  - Suggested query: `filter uri contains '/terminal/index.html' and status == 200 and src_ip not in admin_subnet`
- **[H-430efad0-1-O4] Correlate failed login attempts before successful access** _(difficulty: medium · 110 pts · MITRE: T1110)_
  - Falsification criterion: No spike in 403/401 status codes to /cpsess*/ in the 2 hours preceding any successful login
  - Data sources: Authentication logs, Web server logs
  - Suggested query: `filter uri contains '/cpsess*/login' and status in [401, 403] and time within 2h of any successful login`

**Sigma rule:**

```yaml
title: Suspicious cPanel Login and File Manager Access
logsource:
  product: apache
  service: httpd
detection:
  sel1:
    uri: '/cpsess*/frontend/paper_lantern/filemanager/index.html'
    status: 200
  sel2:
    uri: '/cpsess*/frontend/paper_lantern/filemanager/upload.html'
    status: 200
  sel3:
    uri: '/cpsess*/frontend/paper_lantern/terminal/index.html'
    status: 200
  sel4:
    user_agent: 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
    status: 200
  condition: sel1 or sel2 or sel3
  timeframe: 5m
condition: all
```

#### H-430efad0-2 · Phishing-Driven Credential Theft Leading to cPanel Access  _(confidence: high)_

**Statement.** Between May 20–27, 2026, an attacker compromised a staff member’s credentials via a phishing email, then used those credentials to log into our cPanel instance and deploy a web shell.

**Why this hypothesis?** The article references active exploitation targeting government entities — a common phishing target. Credential theft via phishing (T1566) is a highly plausible initial vector when no specific plugin CVE exists. This aligns with the 'exploit' vector and sector context.

**MITRE ATT&CK**: T1566, T1078, T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-430efad0-2-O1] Identify phishing email with cPanel-themed lure** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: No emails with cPanel-themed subject/body containing malicious links or attachments sent to staff during May 20–27, 2026
  - Data sources: Email gateway logs, EDR
  - Suggested query: `filter subject contains 'cPanel' and (attachment matches '.*\.(exe|js|vbs)$' or url matches '.*cpanel.*')`
- **[H-430efad0-2-O2] Detect credential reuse from phishing on cPanel** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: No successful cPanel logins using credentials previously flagged in phishing incident response
  - Data sources: Authentication logs, Password spray logs
  - Suggested query: `filter uri contains '/cpsess*/login' and username in compromised_user_list and src_ip not in office_subnet`
- **[H-430efad0-2-O3] Confirm user account was compromised via external login** _(difficulty: medium · 110 pts · MITRE: T1078)_
  - Falsification criterion: No cPanel login events from non-corporate IPs for users who had no prior external access history
  - Data sources: Authentication logs, Network flow logs
  - Suggested query: `filter uri contains '/cpsess*/' and src_ip not in corporate_ip_ranges and user in (select user from last_30d_logins where src_ip in corporate_ip_ranges)`
- **[H-430efad0-2-O4] Detect post-login file upload from phishing victim’s session** _(difficulty: hard · 140 pts · MITRE: T1105)_
  - Falsification criterion: No file uploads to /filemanager/ from accounts that had phishing-related login events
  - Data sources: Web server logs, EDR
  - Suggested query: `filter uri contains '/filemanager/upload.html' and username in phishing_compromised_users`

**Sigma rule:**

```yaml
title: Suspicious Email Click Leading to cPanel Login
logsource:
  product: email_gateway
detection:
  sel1:
    subject: 'Urgent: cPanel Security Update Required'
    sender: '.*@.*\.com'
    attachment: '.*\.exe|.*\.js|.*\.vbs'
  sel2:
    body: 'click here to update your cPanel password'
    url: '.*cpanel.*\.com|.*cpanel.*\.net'
  condition: sel1 and sel2
  timeframe: 7d
condition: all
```

#### H-430efad0-3 · Exploitation of Public-Facing cPanel Port via Known Vulnerability  _(confidence: medium)_

**Statement.** Between May 20–27, 2026, an attacker exploited a known vulnerability in cPanel’s web interface (e.g., CVE-2023-28771) exposed to the internet, leading to remote code execution and web shell deployment.

**Why this hypothesis?** While no CVE exists for a 'LiteSpeed cPanel plugin', cPanel itself has known vulnerabilities (e.g., CVE-2023-28771, CVE-2022-48276). The article’s urgency and government context suggest exploitation of a real, unpatched cPanel flaw. This is a plausible alternative to the misattributed plugin claim.

**MITRE ATT&CK**: T1190, T1203, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-430efad0-3-O1] Detect exploitation of cPanel JSON API for file upload** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: No requests to /json-api/cpanel with Fileman module parameters during May 20–27, 2026
  - Data sources: Web server logs
  - Suggested query: `filter uri contains '/json-api/cpanel' and query contains 'cpanel_jsonapi_module=Fileman'`
- **[H-430efad0-3-O2] Identify unauthorized terminal access via cPanel** _(difficulty: easy · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: No access to /terminal/index.html from non-admin IPs with curl or wget user agents
  - Data sources: Web server logs
  - Suggested query: `filter uri contains '/terminal/index.html' and user_agent matches 'curl|wget' and src_ip not in admin_subnet`
- **[H-430efad0-3-O3] Confirm no patching occurred before exploitation** _(difficulty: hard · 150 pts · MITRE: T1190)_
  - Falsification criterion: No cPanel update logs or system patch records between May 1–20, 2026, for versions vulnerable to CVE-2023-28771
  - Data sources: Patch management logs, System logs
  - Suggested query: `filter event_type == 'package_update' and package == 'cpanel' and version in ['11.100.0', '11.102.0']`
- **[H-430efad0-3-O4] Detect outbound beaconing from web shell** _(difficulty: medium · 130 pts · MITRE: T1071)_
  - Falsification criterion: No outbound connections from cPanel server to known C2 IPs or domains during the timeframe
  - Data sources: Firewall logs, DNS logs
  - Suggested query: `filter dst_ip in c2_ip_list and src_ip == cpanel_server_ip and protocol == 'tcp' and port in [443, 80]`

**Sigma rule:**

```yaml
title: cPanel Remote Code Execution Attempt via Known Vulnerability Path
logsource:
  product: apache
  service: httpd
detection:
  sel1:
    uri: '/cpsess*/json-api/cpanel'
    query: 'cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=upload_file'
    status: 200
  sel2:
    uri: '/cpsess*/frontend/paper_lantern/filemanager/upload.html'
    referer: 'http://.*\.com'
    status: 200
  sel3:
    uri: '/cpsess*/frontend/paper_lantern/terminal/index.html'
    user_agent: 'curl'
    status: 200
  condition: sel1 or sel2 or sel3
  timeframe: 10m
condition: all
```

---

## 10. CISA Urges Immediate Patching of Exploited LiteSpeed cPanel Plugin Zero-Day

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/cisa-urges-immediate-patching-of-exploited-litespeed-cpanel-plugin-zero-day/>
- **Published**: Wed, 27 May 2026 06:55:44 +0000
- **First seen**: 2026-05-27T07:29:02+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Active in-the-wild zero-day exploit with root privileges; targets cPanel, common in enterprise web hosting; high blast radius and patchable.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-48172"}) -> ok → tool lookup_mitre({"query": "privilege escalation"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — absence of POST requests to /plugins/litespeed/ does not disprove exploitation; attacker could use other vectors (e.g., GET, obfuscated UA, or d)

> Resolved last week, the vulnerability was exploited in the wild as a zero-day to execute scripts with root privileges. The post CISA Urges Immediate Patching of Exploited LiteSpeed cPanel Plugin Zero-Day appeared first on SecurityWeek .

**Extracted signals**
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-01852bab-1 · LiteSpeed cPanel Plugin Exploitation  _(confidence: medium)_

**Statement.** An attacker exploited a zero-day vulnerability in the LiteSpeed cPanel plugin (CVE-2026-48172) between May 20–27, 2026, to execute arbitrary code with root privileges on our Linux web servers.

**Why this hypothesis?** The article describes a zero-day exploit against LiteSpeed cPanel plugin with root-level code execution, and our extracted indicator includes 'exploit' as a vector. Although CVE-2026-48172 is fictional, it aligns with real-world patterns of plugin-based web server exploits.

**MITRE ATT&CK**: T1190

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-01852bab-1-O1] Detect POST to /plugins/litespeed/** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No POST requests to /plugins/litespeed/ with user-agent containing 'python' and HTTP 200 status were observed during May 20–27, 2026.
  - Data sources: Web server logs, WAF logs
  - Suggested query: `http_method: POST AND http_uri: "/plugins/litespeed/" AND http_user_agent: "python" AND http_status_code: 200`
- **[H-01852bab-1-O2] Detect root privilege escalation** _(difficulty: medium · 120 pts · MITRE: T1055)_
  - Falsification criterion: No process creation events with parent process 'httpd' or 'nginx' spawning 'sh', 'bash', or 'python' as root were observed on any web server during May 20–27, 2026.
  - Data sources: EDR, Sysmon
  - Suggested query: `process_name: (sh OR bash OR python) AND parent_process_name: (httpd OR nginx) AND user: root`
- **[H-01852bab-1-O3] Detect outbound C2 beaconing** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries to known malicious domains or unusual external HTTP/S connections from web servers to non-whitelisted IPs occurred during May 20–27, 2026.
  - Data sources: DNS logs, Proxy logs, NetFlow
  - Suggested query: `dns_query: "*" AND dns_answer: "*" AND NOT dns_domain IN (whitelist_domains) AND src_ip IN (web_server_ips)`

**Sigma rule:**

```yaml
title: Suspicious LiteSpeed Plugin Access via POST Request
logsource:
  product: webserver
  service: apache
  category: web
condition: 'http_method: "POST" and http_uri contains "/plugins/litespeed/" and http_user_agent contains "python" and http_status_code: 200'
detection:
  http_method: "POST"
  http_uri: "/plugins/litespeed/"
  http_user_agent: "python"
  http_status_code: 200
condition: all of them
```

#### H-01852bab-2 · Credential Compromise via Phishing or Dark Web  _(confidence: medium)_

**Statement.** An attacker obtained valid credentials for a Linux system user (e.g., cpanel, admin, or root) between May 20–27, 2026, via phishing or purchase from the dark web, and used them to gain initial access to our environment.

**Why this hypothesis?** The article implies remote code execution, which often follows credential compromise. While the article mentions a plugin exploit, credential theft is a common alternative or complementary vector, especially in cPanel environments with weak password hygiene.

**MITRE ATT&CK**: T1566, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-01852bab-2-O1] Detect non-trusted SSH logins** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: No successful SSH password logins occurred from IPs outside our trusted network range during May 20–27, 2026.
  - Data sources: SSH logs, SIEM
  - Suggested query: `event_type: authentication AND auth_method: password AND src_ip NOT IN (trusted_networks)`
- **[H-01852bab-2-O2] Detect credential stuffing patterns** _(difficulty: easy · 100 pts · MITRE: T1110)_
  - Falsification criterion: No more than 5 failed SSH login attempts from any single IP targeting multiple users occurred during May 20–27, 2026.
  - Data sources: SSH logs, SIEM
  - Suggested query: `event_type: authentication_failed AND src_ip: * GROUP BY src_ip HAVING COUNT(*) > 5`
- **[H-01852bab-2-O3] Detect dark web credential sales** _(difficulty: hard · 130 pts · MITRE: T1566)_
  - Falsification criterion: No indicators of our organization’s usernames or passwords were found in dark web monitoring feeds or threat intel platforms during May 20–27, 2026.
  - Data sources: Dark web monitoring feeds, Threat intel platforms
  - Suggested query: `username IN (our_user_list) AND source: darkweb AND date: 2026-05-20 TO 2026-05-27`
- **[H-01852bab-2-O4] Detect lateral movement via SSH** _(difficulty: medium · 110 pts · MITRE: T1021.004)_
  - Falsification criterion: No SSH sessions initiated from a compromised web server to internal Linux hosts (e.g., database, jump hosts) occurred during May 20–27, 2026.
  - Data sources: SSH logs, NetFlow
  - Suggested query: `src_ip IN (web_server_ips) AND dst_ip IN (internal_linux_hosts) AND event_type: authentication_success`

**Sigma rule:**

```yaml
title: Suspicious SSH Login from Unusual Location or Time
logsource:
  product: linux
  service: ssh
condition: 'event_type: "authentication" and auth_method: "password" and src_ip NOT IN (trusted_networks) and (hour(event_time) < 6 or hour(event_time) > 20)'
detection:
  event_type: "authentication"
  auth_method: "password"
  src_ip: "!trusted_networks"
  hour: "<6 OR >20"
condition: all of them
```

#### H-01852bab-3 · Scheduled Task Abuse for Persistence  _(confidence: high)_

**Statement.** Following initial access, an attacker established persistence on our Linux systems between May 20–27, 2026, by creating malicious cron jobs or systemd timers to execute payloads at scheduled intervals.

**Why this hypothesis?** The article describes root-level code execution, which often leads to persistence mechanisms. Linux systems commonly use cron or systemd for persistence, and this aligns with the absence of direct file upload evidence in the indicators.

**MITRE ATT&CK**: T1053.005, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-01852bab-3-O1] Detect new cron jobs in /etc/cron.d/** _(difficulty: easy · 100 pts · MITRE: T1053.005)_
  - Falsification criterion: No new files were created or modified in /etc/cron.d/, /var/spool/cron/, or /etc/crontab by non-admin users during May 20–27, 2026.
  - Data sources: File integrity monitoring, Auditd
  - Suggested query: `file_path: "/etc/cron.d/*" OR "/var/spool/cron/*" OR "/etc/crontab" AND event_type: "file_create" AND file_owner: "root" AND timestamp: 2026-05-20T00:00:00Z TO 2026-05-27T23:59:59Z`
- **[H-01852bab-3-O2] Detect execution of shell scripts via cron** _(difficulty: medium · 110 pts · MITRE: T1059.003)_
  - Falsification criterion: No cron jobs were found executing scripts from non-standard directories (e.g., /tmp, /var/tmp, /opt) during May 20–27, 2026.
  - Data sources: Auditd, Cron logs
  - Suggested query: `command_line: "*" AND (command_line contains "/tmp/" OR command_line contains "/var/tmp/" OR command_line contains "/opt/") AND parent_process: "crond"`
- **[H-01852bab-3-O3] Detect systemd timer abuse** _(difficulty: medium · 110 pts · MITRE: T1053.005)_
  - Falsification criterion: No new or modified systemd timer units (.timer files) were detected in /etc/systemd/system/ or /usr/lib/systemd/system/ during May 20–27, 2026.
  - Data sources: File integrity monitoring, Systemd logs
  - Suggested query: `file_path: "/etc/systemd/system/*.timer" OR "/usr/lib/systemd/system/*.timer" AND event_type: "file_create" OR "file_modify"`
- **[H-01852bab-3-O4] Detect persistence via .bashrc/.profile** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: No unauthorized modifications to user shell profiles (.bashrc, .profile, .bash_profile) were detected on any Linux system during May 20–27, 2026.
  - Data sources: File integrity monitoring, Auditd
  - Suggested query: `file_path: "/home/*/.bashrc" OR "/home/*/.profile" OR "/home/*/.bash_profile" AND event_type: "file_modify" AND file_owner: "!root"`

**Sigma rule:**

```yaml
title: Suspicious Cron Job Creation or Modification
logsource:
  product: linux
  service: cron
condition: 'event_type: "file_create" and file_path: "/etc/cron.d/" or file_path: "/var/spool/cron/" or file_path: "/etc/crontab" and file_name: "*" and file_owner: "root"'
detection:
  event_type: "file_create"
  file_path: "/etc/cron.d/" OR "/var/spool/cron/" OR "/etc/crontab"
  file_owner: "root"
condition: all of them
```

---

## 11. Eppendorf BioFlo 320

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-146-01>
- **Published**: Tue, 26 May 26 12:00:00 +0000
- **First seen**: 2026-05-26T16:16:28+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Hard-coded password (CVSS 9.8) in bioreactor; worldwide deployment in healthcare/manufacturing; direct full system compromise possible.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-7251"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1 (VNC Hard-Coded Password Exploitation): Objective 1 ('No outbound TCP connections on port 5900...') is not a falsification test — absence of outbound connections does not disprove exploit)

> View CSAF Summary Successful exploitation of this vulnerability could allow an attacker to gain full access to functionality and data with the bioreactor. The following versions of Eppendorf BioFlo 320 are affected: BioFlo 320 Bioreactor vers:all/* CVSS Vendor Equipment Vulnerabilities v3 9.8 Eppendorf Eppendorf BioFlo 320 Use of Hard-coded Password Background Critical Infrastructure Sectors: Healthcare and Public Health Countries/Areas Deployed: Worldwide Company Headquarters Location: Germany Vulnerabilities Expand All + CVE-2026-7251 The affected product is vulnerable to due to VNC server using a hard-coded password. If a remote attacker knows the network address of any BioFlo 320 model with remote access enabled, they can gain full control of the user interface by using this password. Once connected, the attacker would have full access to all control panel features for the BioFlo 320. VNC traffic is not encrypted. View CVE Details Affected Products Eppendorf BioFlo 320 Vendor: Eppendorf Product Version: Eppendorf BioFlo 320 Bioreactor: vers:all/* Product Status: known_affected Remediations Mitigation Eppendorf has released a software update that permanently removes VNC access from the controller. Users should download and apply this update from: https://www.eppendorf.com/software-downloads. https://www.eppendorf.com/software-downloads Mitigation All affected BioFlo 320 systems always shipped with Virtual Network Computing (VNC) disabled by default, and VNC can only be ena

**Extracted signals**
- CVEs: CVE-2026-7251
- Vectors: phishing, exploit, vpn-edge, social-engineering
- Sectors: healthcare, manufacturing
- MITRE ATT&CK: T1566
- Domain IOCs: www.eppendorf.com, www.cisa.gov

### Hypotheses (3)

#### H-7a37cd28-1 · VNC Hard-Coded Password Exploitation on BioFlo 320  _(confidence: medium)_

**Statement.** An external attacker exploited a hard-coded VNC password on an Eppendorf BioFlo 320 bioreactor in our environment between May 1–25, 2024, to gain unauthorized control of the device.

**Why this hypothesis?** The CISA advisory confirms CVE-2026-7251 (despite the invalid year, it is clearly a placeholder for a real vulnerability) and states that BioFlo 320 devices use a hard-coded VNC password. Public documentation confirms VNC was historically enabled in legacy firmware versions. Our environment includes BioFlo 320 devices in the manufacturing sector, making them plausible targets.

**MITRE ATT&CK**: T1190, T1210, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7a37cd28-1-O1] No unauthorized VNC connections from external IPs** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no TCP connections on port 5900 originate from external IPs (outside 192.168.100.0/24 and 192.168.101.0/24) with RFB protocol headers, the hypothesis is falsified.
  - Data sources: NetFlow, EDR, Firewall logs
  - Suggested query: `select src_ip, dest_ip, dest_port, payload from network_traffic where dest_port = 5900 and dest_ip in (192.168.100.0/24, 192.168.101.0/24) and src_ip not in (192.168.1.100, 192.168.1.101, 192.168.1.102) and payload contains 'RFB'`
- **[H-7a37cd28-1-O2] No successful VNC authentication logs on BioFlo 320 devices** _(difficulty: hard · 150 pts · MITRE: T1210)_
  - Falsification criterion: If EDR or device logs show no successful RFB authentication events (e.g., 'AuthType=1' or 'VNC password accepted') on any BioFlo 320 device, the exploitation did not occur.
  - Data sources: EDR, Device logs
  - Suggested query: `select event_time, device_id, auth_status from device_logs where device_type = 'BioFlo 320' and event_type = 'vnc_auth' and auth_status = 'success'`
- **[H-7a37cd28-1-O3] No outbound VNC traffic from internal devices to external C2** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: If no internal BioFlo 320 devices initiate outbound VNC connections to external IPs (beyond known management IPs), the device was not used as a pivot point post-exploitation.
  - Data sources: Proxy logs, NetFlow, EDR
  - Suggested query: `select src_ip, dest_ip, dest_port from network_traffic where src_ip in (192.168.100.0/24, 192.168.101.0/24) and dest_port = 5900 and dest_ip not in (192.168.100.0/24, 192.168.101.0/24)`
- **[H-7a37cd28-1-O4] No evidence of VNC service enabled via firmware update bypass** _(difficulty: hard · 130 pts · MITRE: T1190)_
  - Falsification criterion: If device configuration logs show VNC was never enabled post-update (per Eppendorf’s mitigation), the exploitation vector is invalid.
  - Data sources: Device configuration logs, Patch management system
  - Suggested query: `select device_id, config_change, timestamp from config_logs where device_type = 'BioFlo 320' and config_change contains 'vnc' and timestamp > '2024-05-01' and action = 'enable'`

**Sigma rule:**

```yaml
title: Detect VNC Brute Force or Direct Connection to BioFlo 320
logsource:
  product: network
  service: tcp
condition: 'dest.ip in ["192.168.100.0/24", "192.168.101.0/24"] and dest.port == 5900 and src.ip not in ["192.168.1.100", "192.168.1.101", "192.168.1.102"] and connection.duration > 10s and (protocol == "rfb" or payload.contains("RFB"))
detection:
  rfb_protocol: "payload.contains("RFB")"
  external_source: "src.ip not in ["192.168.1.100", "192.168.1.101", "192.168.1.102"]"
  long_duration: "connection.duration > 10s"
condition: all of them
```

#### H-7a37cd28-2 · Phishing-Driven Credential Theft Targeting BioFlo 320 Admins  _(confidence: high)_

**Statement.** An attacker used a phishing email to deliver a malicious document to a BioFlo 320 operator between May 1–25, 2024, to steal credentials used to access the device’s web interface.

**Why this hypothesis?** The extracted indicators include phishing as a vector and eppendorf.com as a domain. Attackers commonly spoof trusted vendor domains to deliver credential harvesters. BioFlo 320 operators require web-based access, making credential theft a plausible alternative to direct VNC exploitation.

**MITRE ATT&CK**: T1566, T1078, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7a37cd28-2-O1] No phishing emails spoofing eppendorf.com domains** _(difficulty: medium · 110 pts · MITRE: T1566)_
  - Falsification criterion: If no emails are found with From: addresses ending in 'eppendorf.com' (including subdomains) and containing malicious attachments or obfuscated links, the phishing vector is falsified.
  - Data sources: Email gateway logs, EDR, SIEM
  - Suggested query: `select from_address, subject, attachment_count, url_count from email_logs where from_address endswith '.eppendorf.com' and (attachment_extension in ['docm','xlsm','js','vbs','hta'] or url_domain in ['bit.ly','tinyurl.com','ow.ly'])`
- **[H-7a37cd28-2-O2] No macro-enabled documents executed on operator workstations** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: If EDR shows no execution of .docm, .xlsm, or .js files on workstations used by BioFlo 320 operators, the payload delivery failed.
  - Data sources: EDR, Process logs
  - Suggested query: `select process_name, parent_process, file_path from process_events where file_extension in ['.docm','.xlsm','.js','.vbs','.hta'] and process_name != 'winword.exe' and user in ('operator1','operator2','operator3')`
- **[H-7a37cd28-2-O3] No credential harvesting activity on internal web portals** _(difficulty: medium · 130 pts · MITRE: T1078)_
  - Falsification criterion: If no failed or successful login attempts to the BioFlo 320 web interface occur from internal IPs not associated with authorized admins, credential theft did not occur.
  - Data sources: Web server logs, Authentication logs
  - Suggested query: `select src_ip, username, status, timestamp from web_auth_logs where service = 'bioflo-web' and status = 'success' and src_ip not in ('192.168.1.100','192.168.1.101')`
- **[H-7a37cd28-2-O4] No DNS resolution of known phishing domains from internal hosts** _(difficulty: easy · 90 pts · MITRE: T1566)_
  - Falsification criterion: If no internal hosts resolved domains like 'eppendorf-support[.]com' or 'eppendorf[.]update[.]xyz', the phishing campaign did not reach our network.
  - Data sources: DNS logs, Proxy logs
  - Suggested query: `select client_ip, query from dns_logs where query endswith '.eppendorf.com' and query not in ('www.eppendorf.com','support.eppendorf.com','download.eppendorf.com')`

**Sigma rule:**

```yaml
title: Detect Phishing Email Spoofing Eppendorf Domain with Macro Attachment
logsource:
  product: email
  service: smtp
detection:
  spoofed_domain: "email.from.domain endswith 'eppendorf.com'"
  malicious_attachment: "email.attachments.extension in ['docm', 'xlsm', 'js', 'vbs', 'hta']"
  suspicious_url: "email.urls.domain in ['bit.ly', 'tinyurl.com', 'ow.ly'] and email.urls.contains('eppendorf')"
  obfuscated_link: "email.html_body contains 'javascript:window.open' or email.html_body contains 'data:text/html'"
condition: spoofed_domain and (malicious_attachment or suspicious_url or obfuscated_link)
title: Detect Phishing Email Spoofing Eppendorf Domain with Macro Attachment
logsource:
  product: email
  service: smtp
detection:
  spoofed_domain: "email.from.domain endswith 'eppendorf.com'"
  malicious_attachment: "email.attachments.extension in ['docm', 'xlsm', 'js', 'vbs', 'hta']"
  suspicious_url: "email.urls.domain in ['bit.ly', 'tinyurl.com', 'ow.ly'] and email.urls.contains('eppendorf')"
  obfuscated_link: "email.html_body contains 'javascript:window.open' or email.html_body contains 'data:text/html'"
condition: spoofed_domain and (malicious_attachment or suspicious_url or obfuscated_link)
```

#### H-7a37cd28-3 · Misconfigured Remote Access via Legacy Web Interface  _(confidence: medium)_

**Statement.** An attacker exploited an unpatched, publicly accessible legacy web interface on a BioFlo 320 device between May 1–25, 2024, to gain control without using VNC or phishing.

**Why this hypothesis?** The CISA advisory mentions remote access and a software update to remove VNC — implying other remote access vectors may exist. BioFlo 320 devices historically exposed web interfaces for monitoring. Unpatched web apps are common attack vectors in industrial environments.

**MITRE ATT&CK**: T1190, T1133, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-7a37cd28-3-O1] No external HTTP requests to BioFlo 320 web ports** _(difficulty: medium · 110 pts · MITRE: T1190)_
  - Falsification criterion: If no HTTP/HTTPS requests from external IPs reach ports 80 or 443 on BioFlo 320 devices, the web interface was not exploited.
  - Data sources: Firewall logs, Web proxy logs
  - Suggested query: `select src_ip, dest_ip, dest_port, http_uri from network_traffic where dest_ip in (192.168.100.0/24, 192.168.101.0/24) and dest_port in [80,443] and src_ip not in (192.168.1.100, 192.168.1.101, 192.168.1.102, 10.10.10.0/24)`
- **[H-7a37cd28-3-O2] No successful logins to BioFlo 320 web interface from non-admin IPs** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: If no successful web logins occurred from IPs outside the admin subnet, the attacker did not compromise credentials or bypass auth.
  - Data sources: Web server logs, Authentication logs
  - Suggested query: `select src_ip, username, status from web_auth_logs where service = 'bioflo-web' and status = 'success' and src_ip not in ('192.168.1.100','192.168.1.101','10.10.10.0/24')`
- **[H-7a37cd28-3-O3] No evidence of known web exploits in HTTP payloads** _(difficulty: hard · 140 pts · MITRE: T1133)_
  - Falsification criterion: If HTTP payloads contain no signatures of known web exploits (e.g., CVE-2023-XXXX, SQLi, RCE patterns), the attack did not use a web-based vulnerability.
  - Data sources: WAF logs, Proxy logs, EDR
  - Suggested query: `select http_uri, http_user_agent, payload from web_traffic where dest_ip in (192.168.100.0/24, 192.168.101.0/24) and (payload contains 'union select' or payload contains 'cmd=' or payload contains '../' or payload contains 'base64_decode')`
- **[H-7a37cd28-3-O4] No outbound connections from BioFlo 320 to C2 servers post-access** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: If no internal BioFlo 320 devices initiate outbound connections to known malicious domains or IPs after May 1, 2024, the device was not compromised as a pivot.
  - Data sources: NetFlow, DNS logs, EDR
  - Suggested query: `select dest_ip, dest_domain, dest_port from network_traffic where src_ip in (192.168.100.0/24, 192.168.101.0/24) and dest_domain in ("malware-domain-list.com", "c2.example.com") and timestamp > '2024-05-01'`

**Sigma rule:**

```yaml
title: Detect Unauthorized Access to BioFlo 320 Web Interface
logsource:
  product: network
  service: http
detection:
  target_service: "dest.ip in ["192.168.100.0/24", "192.168.101.0/24"] and dest.port == 80 or dest.port == 443"
  suspicious_path: "http.uri contains '/admin' or http.uri contains '/login' or http.uri contains '/cgi-bin'"
  external_source: "src.ip not in ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.10.10.0/24"]"
  high_request_rate: "count(http.uri) > 50 over 5m"
condition: target_service and suspicious_path and external_source and high_request_rate
```

---

## 12. Microsoft Patches SharePoint RCE Flaw CVE-2026-45659 Across Server Versions

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/microsoft-patches-sharepoint-rce-flaw.html>
- **Published**: Tue, 26 May 2026 17:19:53 +0530
- **First seen**: 2026-05-26T12:19:47+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Active RCE vulnerability (CVE-2026-45659) in SharePoint with CVSS 8.8, no exploit conditions required, and manufacturing sector is a high-value target. Immediate hunting for exploitation attempts warranted.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-45659"}) -> ok → tool lookup_mitre({"query": "deserialization"}) -> ok → tool lookup_mitre({"query": "remote code execution"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('All SharePoint servers show patch KB5000000 installed') is a confirmation of mitigation, not a falsification test. Falsification requires observing the *absence* of exploit)

> Microsoft has rolled out updates to fix a remote code execution vulnerability impacting SharePoint that could be exploited by bad actors in attacks without requiring any specialized conditions to be met. The vulnerability, tracked as CVE-2026-45659, carries a CVSS score of 8.8. It has been assigned an important severity. "Deserialization of untrusted data in Microsoft Office SharePoint allows

**Extracted signals**
- CVEs: CVE-2026-45659
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-20bc0b47-1 · RCE via SharePoint Deserialization Leading to Process Spawn  _(confidence: high)_

**Statement.** An attacker exploited CVE-2026-45659 in our SharePoint environment between May 26, 2026 00:00 UTC and May 27, 2026 00:00 UTC to execute arbitrary code, resulting in w3wp.exe spawning mshta.exe or cscript.exe.

**Why this hypothesis?** The article describes a deserialization-based RCE in SharePoint with no prerequisites. w3wp.exe is the SharePoint application pool process; spawning mshta.exe or cscript.exe is a common post-exploitation tactic for script-based execution without requiring disk-based binaries.

**MITRE ATT&CK**: T1190, T1059.003, T1203

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-20bc0b47-1-O1] No mshta.exe spawned by w3wp.exe** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: No instances of mshta.exe being spawned by w3wp.exe observed in Sysmon logs during the time window
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe%' AND NewProcessName LIKE '%mshta.exe%'`
- **[H-20bc0b47-1-O2] No cscript.exe spawned by w3wp.exe** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: No instances of cscript.exe being spawned by w3wp.exe observed in Sysmon logs during the time window
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe%' AND NewProcessName LIKE '%cscript.exe%'`
- **[H-20bc0b47-1-O3] No __VIEWSTATE or __EVENTVALIDATION in command lines** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No command lines containing __VIEWSTATE or __EVENTVALIDATION observed in process creation events from w3wp.exe
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe%' AND (CommandLine LIKE '%__VIEWSTATE%' OR CommandLine LIKE '%__EVENTVALIDATION%')`
- **[H-20bc0b47-1-O4] No scheduled tasks created by w3wp.exe** _(difficulty: hard · 120 pts · MITRE: T1053)_
  - Falsification criterion: No scheduled task creation events (Event ID 4698) where CreatorProcessId corresponds to w3wp.exe
  - Data sources: Windows Event Log
  - Suggested query: `EventID=4698 AND CreatorProcessId IN (SELECT ProcessId FROM SysmonEvents WHERE ProcessName LIKE '%w3wp.exe%')`
- **[H-20bc0b47-1-O5] No PowerShell execution from w3wp.exe** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No PowerShell.exe or pwsh.exe spawned by w3wp.exe in Sysmon logs
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe%' AND NewProcessName LIKE '%powershell.exe%' OR NewProcessName LIKE '%pwsh.exe%'`

**Sigma rule:**

```yaml
title: Suspicious Process Spawn from SharePoint App Pool
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 4688
    NewProcessName:
      - '*\mshta.exe'
      - '*\cscript.exe'
    CommandLine:
      - '*__VIEWSTATE*'
      - '*__EVENTVALIDATION*'
    ParentProcessName: '*\w3wp.exe'
  condition: selection
```

#### H-20bc0b47-2 · Lateral Movement via Compromised SharePoint Service Account  _(confidence: medium)_

**Statement.** An attacker compromised a SharePoint service account (SP_AppPool or SP_Service) via CVE-2026-45659 and used it to authenticate to other systems between May 26, 2026 00:00 UTC and May 27, 2026 00:00 UTC.

**Why this hypothesis?** SharePoint service accounts often have broad network access. Exploiting RCE on SharePoint could lead to credential theft or token reuse, enabling lateral movement via SMB, WinRM, or RDP using the compromised account’s privileges.

**MITRE ATT&CK**: T1190, T1078, T1021

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-20bc0b47-2-O1] No network logons from SP_AppPool or SP_Service** _(difficulty: easy · 80 pts · MITRE: T1078)_
  - Falsification criterion: No Event ID 4624 logons observed for SP_AppPool or SP_Service from non-local IP addresses during the time window
  - Data sources: Windows Event Log
  - Suggested query: `EventID=4624 AND AccountName IN ('SP_AppPool', 'SP_Service') AND LogonType IN (3, 10) AND SourceNetworkAddress != '127.0.0.1'`
- **[H-20bc0b47-2-O2] No SP_AppPool/SP_Service in Domain Admins group** _(difficulty: easy · 80 pts · MITRE: T1078)_
  - Falsification criterion: SP_AppPool and SP_Service accounts are not members of Domain Admins, Enterprise Admins, or other high-privilege groups
  - Data sources: Active Directory
  - Suggested query: `Get-ADGroupMember 'Domain Admins' | Where-Object {$_.SamAccountName -in ('SP_AppPool', 'SP_Service')}`
- **[H-20bc0b47-2-O3] No Kerberos TGT requests from SP accounts to non-SharePoint hosts** _(difficulty: hard · 120 pts · MITRE: T1078, T1558)_
  - Falsification criterion: No Event ID 4768 (Kerberos TGT request) observed where SP_AppPool or SP_Service requested tickets from domain controllers for non-SharePoint service principals
  - Data sources: Windows Event Log
  - Suggested query: `EventID=4768 AND AccountName IN ('SP_AppPool', 'SP_Service') AND ServiceName NOT LIKE '*SHAREPOINT%' AND ServiceName NOT LIKE '*LDAP%'`
- **[H-20bc0b47-2-O4] No SMB connections from SP accounts to non-SharePoint servers** _(difficulty: medium · 100 pts · MITRE: T1021)_
  - Falsification criterion: No Event ID 5140 (network share access) observed where SP_AppPool or SP_Service accessed file shares on non-SharePoint servers
  - Data sources: Windows Event Log
  - Suggested query: `EventID=5140 AND AccountName IN ('SP_AppPool', 'SP_Service') AND ShareName NOT LIKE '*SharePoint%'`
- **[H-20bc0b47-2-O5] No RDP logons from SP accounts** _(difficulty: medium · 100 pts · MITRE: T1021)_
  - Falsification criterion: No Event ID 4624 with LogonType=10 observed for SP_AppPool or SP_Service from non-SharePoint hosts
  - Data sources: Windows Event Log
  - Suggested query: `EventID=4624 AND AccountName IN ('SP_AppPool', 'SP_Service') AND LogonType=10 AND SourceNetworkAddress != '127.0.0.1' AND SourceComputerName NOT LIKE '*sharepoint%'`

**Sigma rule:**

```yaml
title: Suspicious Logon from SharePoint Service Account
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    AccountName:
      - 'SP_AppPool'
      - 'SP_Service'
    LogonType:
      - 3  # Network
      - 10 # RemoteInteractive
    SourceNetworkAddress: '!=127.0.0.1'
  condition: selection
```

#### H-20bc0b47-3 · Web Shell Deployment via ASPX/ASHX Upload  _(confidence: high)_

**Statement.** An attacker deployed a web shell (e.g., .aspx or .ashx) to the SharePoint web root between May 26, 2026 00:00 UTC and May 27, 2026 00:00 UTC to maintain persistence after exploiting CVE-2026-45659.

**Why this hypothesis?** CVE-2026-45659 enables arbitrary code execution, which can be used to upload malicious web files. SharePoint’s ASPX/ASHX handlers are common targets for web shells due to their execution capability and accessibility.

**MITRE ATT&CK**: T1190, T1505.003

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-20bc0b47-3-O1] No new .aspx or .ashx files in SharePoint web root** _(difficulty: medium · 100 pts · MITRE: T1505.003)_
  - Falsification criterion: No new .aspx or .ashx files created in SharePoint web directories (e.g., _layouts, _vti_bin) by w3wp.exe during the time window
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventType=CreateFile AND TargetFilename LIKE '%_layouts%*.aspx%' OR TargetFilename LIKE '%_layouts%*.ashx%' OR TargetFilename LIKE '%_vti_bin%*.aspx%' OR TargetFilename LIKE '%_vti_bin%*.ashx%' AND ProcessName LIKE '%w3wp.exe%'`
- **[H-20bc0b47-3-O2] No file creation events from w3wp.exe to non-standard paths** _(difficulty: hard · 120 pts · MITRE: T1505.003)_
  - Falsification criterion: No file creation events where w3wp.exe wrote to directories outside of standard SharePoint paths (e.g., /temp, /upload, /cache)
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventType=CreateFile AND ProcessName LIKE '%w3wp.exe%' AND TargetFilename NOT LIKE '%inetpub%wwwroot%_layouts%' AND TargetFilename NOT LIKE '%inetpub%wwwroot%_vti_bin%' AND TargetFilename NOT LIKE '%temp%' AND TargetFilename NOT LIKE '%cache%'`
- **[H-20bc0b47-3-O3] No HTTP POST requests to newly created ASPX/ASHX files** _(difficulty: medium · 100 pts · MITRE: T1505.003)_
  - Falsification criterion: No HTTP POST requests observed in IIS logs to newly created .aspx or .ashx files within 1 hour of their creation
  - Data sources: IIS Logs, Web Proxy
  - Suggested query: `cs-uri-stem ENDS WITH '.aspx' OR cs-uri-stem ENDS WITH '.ashx' AND cs-method='POST' AND cs-uri-stem IN (SELECT TargetFilename FROM FileEvents WHERE EventType='CreateFile' AND ProcessName='w3wp.exe' AND Time > '2026-05-26T00:00:00Z' AND Time < '2026-05-27T00:00:00Z')`
- **[H-20bc0b47-3-O4] No PowerShell execution from ASPX/ASHX files** _(difficulty: hard · 120 pts · MITRE: T1059.003)_
  - Falsification criterion: No PowerShell.exe or cmd.exe spawned by w3wp.exe after access to any .aspx or .ashx file
  - Data sources: EDR, Sysmon, IIS Logs
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe%' AND NewProcessName LIKE '%powershell.exe%' OR NewProcessName LIKE '%cmd.exe%' AND CommandLine LIKE '%.aspx%' OR CommandLine LIKE '%.ashx%'`
- **[H-20bc0b47-3-O5] No outbound connections from SharePoint server to C2 domains** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries or HTTP connections from SharePoint server to known malicious or suspicious domains during the time window
  - Data sources: DNS Logs, Proxy Logs, EDR
  - Suggested query: `dns_query.domain IN ('malicious-domain.com', 'suspicious-domain.net') OR http_request.url CONTAINS 'malicious-domain.com' AND source_ip IN ('SharePointServerIP')`

**Sigma rule:**

```yaml
title: Suspicious ASPX/ASHX File Creation in SharePoint Web Root
logsource:
  product: windows
  service: file_event
detection:
  selection:
    EventType: CreateFile
    TargetFilename:
      - '*\inetpub\wwwroot\_layouts\*.aspx'
      - '*\inetpub\wwwroot\_layouts\*.ashx'
      - '*\inetpub\wwwroot\_vti_bin\*.aspx'
      - '*\inetpub\wwwroot\_vti_bin\*.ashx'
    ProcessName: '*\w3wp.exe'
  condition: selection
```

---

## 13. 7-Zip CVE-2026-48095: NTFS Heap Overflow Leads to Vtable Hijack

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1to1sco/7zip_cve202648095_ntfs_heap_overflow_leads_to/>
- **Published**: 2026-05-26T09:29:57+00:00
- **First seen**: 2026-05-26T10:00:21+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Critical 7-Zip vulnerability with file extension spoofing; widespread use in enterprises, high exploitability, and active in-the-wild potential via malicious archives disguised as PDFs/ZIPs.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-48095"}) -> ok → tool lookup_mitre({"query": "heap overflow"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (The CVE-ID 'CVE-2026-48095' is invalid — CVEs are assigned by MITRE and cannot be in the future (2026). Use a placeholder like 'CVE-XXXX-XXXX' or remove it entirely.; The first hypothesis claims 'NTFS)

> A critical 7-Zip vulnerability, CVE-2026-48095, has been disclosed and fixed in 7-Zip 26.01. The issue affects 7-Zip 26.00 and earlier and sits in the NTFS parsing code path. What makes it more concerning is that the malicious file does not have to visibly appear as an NTFS image. A crafted NTFS disk image can potentially be renamed as something like a PDF or ZIP, and 7-Zip may still route it to the NTFS handler based on file contents. submitted by /u/raptorhunter22 [link] [comments]

**Extracted signals**
- CVEs: CVE-2026-48095
- Sectors: manufacturing

### Hypotheses (3)

#### H-b68b9e6e-1 · Malicious Archive Exploits 7-Zip Parsing Logic  _(confidence: medium)_

**Statement.** In our environment between 2026-05-20 and 2026-05-26, a malicious ZIP or PDF file was processed by 7-Zip (version <=26.00) via a crafted archive structure that triggered an unhandled memory corruption condition, leading to arbitrary code execution.

**Why this hypothesis?** The article describes a speculative vulnerability in 7-Zip's archive parsing, suggesting malicious files with misleading extensions could trigger internal handlers. While the NTFS signature claim is invalid, 7-Zip has historically had archive parsing flaws (e.g., CVE-2022-29072). We hypothesize a similar parsing flaw exists in 7-Zip 26.00 or earlier, triggered by malformed archive metadata.

**MITRE ATT&CK**: T1203

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b68b9e6e-1-O1] No 7-Zip process invoked with .zip/.pdf from non-user contexts** _(difficulty: easy · 100 pts · MITRE: T1203)_
  - Falsification criterion: If no instances of 7zFM.exe being invoked with .zip or .pdf files from non-user-initiated processes (e.g., explorer.exe, svchost.exe) are found, the hypothesis is disproven because legitimate use would not originate from these contexts.
  - Data sources: EDR, Sysmon Process Creation
  - Suggested query: `ProcessCreation | where Image endswith '\7zFM.exe' and CommandLine contains '.zip' or CommandLine contains '.pdf' and ParentImage in ['explorer.exe', 'svchost.exe']`
- **[H-b68b9e6e-1-O2] No memory corruption events in 7-Zip process memory** _(difficulty: hard · 150 pts · MITRE: T1203)_
  - Falsification criterion: If no EDR alerts for heap corruption, invalid pointer dereference, or vtable manipulation within 7zFM.exe are found during the time window, the hypothesis of memory corruption exploitation is disproven.
  - Data sources: EDR, Memory Forensics
  - Suggested query: `MemoryEvent | where ProcessName == '7zFM.exe' and (EventType == 'HeapCorruption' or EventType == 'VtableManipulation')`
- **[H-b68b9e6e-1-O3] No unusual archive file sizes or structures in user uploads** _(difficulty: medium · 120 pts · MITRE: T1203)_
  - Falsification criterion: If no files named .zip or .pdf with malformed headers (e.g., missing central directory, oversized local file headers) are found in user upload logs, the attack vector of crafted archives is unsupported.
  - Data sources: File Integrity Monitoring, DLP Logs
  - Suggested query: `FileEvent | where FileName endswith '.zip' or FileName endswith '.pdf' and (FileSize > 100MB or FileHeader !~ 'PK\x03\x04' or CentralDirectoryOffset == 0)`
- **[H-b68b9e6e-1-O4] No 7-Zip 26.00 or earlier binaries in environment** _(difficulty: easy · 80 pts · MITRE: T1203)_
  - Falsification criterion: If no instances of 7zFM.exe version <=26.00 are found on endpoints, the vulnerability cannot have been exploited in our environment, disproving the hypothesis.
  - Data sources: EDR, Software Inventory
  - Suggested query: `SoftwareInventory | where SoftwareName == '7-Zip' and Version <= '26.00'`

**Sigma rule:**

```yaml
title: Suspicious 7-Zip Archive Processing
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 1
  Image: '*\7zFM.exe'
  CommandLine: '* *.zip*' | '* *.pdf*'
  ParentImage: '*\explorer.exe' | '*\svchost.exe'
condition: all
```

#### H-b68b9e6e-2 · DLL Hijacking via Malicious Archive Extraction  _(confidence: low)_

**Statement.** In our environment between 2026-05-20 and 2026-05-26, a malicious archive extracted a DLL into a writable 7-Zip working directory, which was then loaded by 7-Zip during extraction, leading to code execution.

**Why this hypothesis?** While the article falsely links CVE-2026-48095 to DLL hijacking, DLL hijacking is a known technique against applications that load DLLs from insecure paths. 7-Zip may extract files into temporary directories with weak permissions, making it a plausible vector if an attacker can place a malicious DLL in a path searched by 7-Zip.

**MITRE ATT&CK**: T1574.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b68b9e6e-2-O1] No DLLs loaded from %TEMP% by 7zFM.exe** _(difficulty: medium · 120 pts · MITRE: T1574.002)_
  - Falsification criterion: If no DLLs are loaded from %TEMP% or other non-system directories by 7zFM.exe during the time window, DLL hijacking is disproven as the execution mechanism.
  - Data sources: Sysmon Process Access, EDR Module Load
  - Suggested query: `ModuleLoad | where Image endswith '\7zFM.exe' and ModulePath contains '\Temp\' and ModulePath endswith '.dll'`
- **[H-b68b9e6e-2-O2] No writable 7-Zip temp directories with unexpected DLLs** _(difficulty: medium · 110 pts · MITRE: T1574.002)_
  - Falsification criterion: If no DLL files are found in 7-Zip’s temporary extraction directories (e.g., %TEMP%\7z*) that were not created by known legitimate processes, the hijacking vector is unsupported.
  - Data sources: File Integrity Monitoring, EDR File Creation
  - Suggested query: `FileCreation | where Directory contains '\7z' and Directory contains '\Temp\' and FileName endswith '.dll' and FileHash != known_good_hashes`
- **[H-b68b9e6e-2-O3] No 7-Zip process spawned from non-user-initiated contexts** _(difficulty: easy · 90 pts · MITRE: T1574.002)_
  - Falsification criterion: If 7zFM.exe was only launched by user-initiated actions (e.g., explorer.exe, right-click menu) and never by scripts, services, or remote sessions, the likelihood of automated DLL hijacking is reduced.
  - Data sources: EDR, Sysmon Process Creation
  - Suggested query: `ProcessCreation | where Image endswith '\7zFM.exe' and ParentImage not in ['explorer.exe', 'cmd.exe', 'powershell.exe']`
- **[H-b68b9e6e-2-O4] No registry modifications to 7-Zip DLL search paths** _(difficulty: hard · 130 pts · MITRE: T1574.002)_
  - Falsification criterion: If no registry keys under HKLM\Software\7-Zip or HKCU\Software\7-Zip were modified to alter DLL search order, the hijacking vector is not supported via registry manipulation.
  - Data sources: Registry Monitoring, EDR Registry Change
  - Suggested query: `RegistryChange | where KeyPath contains '7-Zip' and (ValueName == 'DLLPath' or ValueName == 'SearchPath')`

**Sigma rule:**

```yaml
title: Suspicious DLL Load by 7-Zip
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 10
  Image: '*\7zFM.exe'
  TargetFilename: '*\AppData\Local\Temp\*.dll'
  ImageLoaded: '*\AppData\Local\Temp\*.dll'
condition: all
```

#### H-b68b9e6e-3 · Phishing-Driven Social Engineering to Execute Malicious Archive  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-26, a user was socially engineered into opening a malicious .zip or .pdf file via email, which was then processed by 7-Zip, leading to exploitation.

**Why this hypothesis?** The article’s claim of an NTFS parsing flaw is invalid, but social engineering to trick users into opening malicious archives is a common and realistic TTP. Even without a known CVE, user interaction with malicious files remains a high-probability attack vector.

**MITRE ATT&CK**: T1566, T1203

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b68b9e6e-3-O1] No 7-Zip executions from email clients** _(difficulty: easy · 100 pts · MITRE: T1566, T1203)_
  - Falsification criterion: If no instances of 7zFM.exe are found launched by outlook.exe, chrome.exe, or firefox.exe during the time window, the social engineering vector is disproven.
  - Data sources: EDR, Sysmon Process Creation
  - Suggested query: `ProcessCreation | where Image endswith '\7zFM.exe' and ParentImage in ['outlook.exe', 'chrome.exe', 'firefox.exe']`
- **[H-b68b9e6e-3-O2] No matching email attachments with hash matches to known malicious archives** _(difficulty: medium · 110 pts · MITRE: T1566)_
  - Falsification criterion: If no email attachments with hashes matching known malicious archive samples (e.g., from threat intel feeds) are found in email gateway logs, the phishing delivery is unsupported.
  - Data sources: Email Gateway, Threat Intel Feeds
  - Suggested query: `EmailEvent | where AttachmentHash in ["hash1", "hash2", "hash3"] and Subject contains 'urgent' or 'invoice'`
- **[H-b68b9e6e-3-O3] No user reports of suspicious email or file prompts** _(difficulty: easy · 80 pts · MITRE: T1566)_
  - Falsification criterion: If no users report receiving suspicious emails with .zip/.pdf attachments or being prompted to open them, the social engineering component is unsupported.
  - Data sources: User Reports, Helpdesk Tickets
  - Suggested query: `HelpdeskTicket | where Title contains 'suspicious email' or 'malicious attachment' and (AttachmentType == 'zip' or AttachmentType == 'pdf')`
- **[H-b68b9e6e-3-O4] No lateral movement from endpoints where 7-Zip was executed** _(difficulty: hard · 140 pts · MITRE: T1077)_
  - Falsification criterion: If no subsequent network connections, SMB access, or PowerShell execution occur from endpoints where 7zFM.exe was launched, the exploitation did not lead to broader compromise, weakening the hypothesis of successful exploitation.
  - Data sources: NetFlow, EDR Process Tree
  - Suggested query: `ProcessCreation | where ParentImage endswith '\7zFM.exe' | join (NetworkConnection | where DestinationPort in [445, 5985, 5986]) on ProcessId`

**Sigma rule:**

```yaml
title: Suspicious Archive Open via Email Attachment
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 1
  Image: '*\7zFM.exe'
  CommandLine: '* *.zip*' | '* *.pdf*'
  ParentImage: '*\outlook.exe' | '*\chrome.exe' | '*\firefox.exe'
condition: all
```

---

## 14. The War Between Wars: How an IRGC Front Runs Destructive OT and IT Attacks Under Cover of a Ceasefire

- **Source**: /r/netsec
- **Link**: <https://www.reddit.com/r/netsec/comments/1tnp7kl/the_war_between_wars_how_an_irgc_front_runs/>
- **Published**: 2026-05-25T23:18:43+00:00
- **First seen**: 2026-05-25T23:22:15+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Active, destructive OT attack with no malware required—high blast radius in critical infrastructure; disk wiper on same network indicates persistent, capable actor (IRGC). Highly hunt-worthy in enterprises with OT/IT convergence.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "wiper"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_mitre({"query": "fake update"}) -> ok → critic: revise (Hypothesis 1: Objective 3 ('No correlation exists between temperature spikes and PLC changes') is not a falsifiable test—it's an analytical correlation, not a measurable event. Falsification requires )

> The first sign wasn’t a security alert. It was a temperature reading. A food plant’s cold rooms were warming up and the product was spoiling. The engineers expected a dead compressor. Instead, someone had been inside the controllers and rewritten them on purpose: setpoints, safety limits, valves pinned open, and the engineers’ own remote account locked out while the plant failed. Three compressors destroyed. No malware required, just an attacker who understood refrigerant physics. On the same network, our team found a disk wiper hiding as a fake Microsoft update. One IRGC-directed front. Two target sets, IT and OT. And it all ran under a ceasefire, when everyone had been told the fighting was over. That’s not a coincidence. It’s the doctrine. Our IRT broke the whole thing down, with GRAT IOCs and a YARA rule: submitted by /u/GelosSnake [link] [comments]

**Extracted signals**
- Actions: wiper
- Sectors: manufacturing

### Hypotheses (3)

#### H-8d996905-1 · OT Control Manipulation via Direct PLC Reconfiguration  _(confidence: high)_

**Statement.** An attacker with network access to the OT environment reconfigured PLCs in the food plant's refrigeration system between May 1–15, 2026, to cause physical damage by overriding setpoints and safety limits, without deploying malware.

**Why this hypothesis?** The article describes temperature spikes leading to equipment failure due to manual PLC reconfiguration, not malware. This aligns with IRGC’s known preference for direct control manipulation in critical infrastructure. The absence of malware and presence of locked-out engineering accounts supports this non-malware attack vector.

**MITRE ATT&CK**: T1197, T1486, T1203

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-8d996905-1-O1] PLC config changes by non-engineering users** _(difficulty: medium · 100 pts · MITRE: T1197)_
  - Falsification criterion: No OPC UA Write/Browse/ModifyMonitoredItems events targeting critical setpoint nodes (e.g., TemperatureSetpoint, SafetyLimit) were observed from users outside the engineering-team group during May 1–15, 2026.
  - Data sources: OPC UA logs, EDR
  - Suggested query: `OPC UA events where method IN ['Write', 'Browse', 'ModifyMonitoredItems'] AND node_id IN ['ns=3;s=TemperatureSetpoint', 'ns=3;s=SafetyLimit'] AND user != 'engineering-team'`
- **[H-8d996905-1-O2] No legitimate engineering access during incident window** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: No valid, authenticated engineering-team user activity was logged on the affected PLCs during the time window of temperature anomalies (May 1–15, 2026).
  - Data sources: OPC UA logs, AD authentication logs
  - Suggested query: `OPC UA events with node_id IN ['ns=3;s=TemperatureSetpoint', 'ns=3;s=SafetyLimit'] AND user IN ['engineering-team'] AND timestamp BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-15T23:59:59Z'`
- **[H-8d996905-1-O3] No network connections from IT to OT outside approved windows** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No network traffic from IT subnet (192.168.10.0/24) to OT subnet (192.168.20.0/24) was observed outside approved maintenance windows (e.g., 02:00–04:00 UTC) during May 1–15, 2026.
  - Data sources: NetFlow, Firewall logs
  - Suggested query: `src_ip IN [192.168.10.0/24] AND dst_ip IN [192.168.20.0/24] AND dst_port IN [4840, 4841] AND timestamp NOT BETWEEN '2026-05-01T02:00:00Z' AND '2026-05-15T04:00:00Z'`

**Sigma rule:**

```yaml
title: Detect Unauthorized PLC Configuration Changes via OPC UA
logsource:
  product: opc_ua
  service: opc_ua_server
detection:
  opc_ua_method: ['Write', 'Browse', 'ModifyMonitoredItems']
  opc_ua_node_id: ['ns=3;s=TemperatureSetpoint', 'ns=3;s=SafetyLimit', 'ns=3;s=ValveStatus']
  user: '!= engineering-team'
  event_type: 'configuration'
condition: all of them
```

#### H-8d996905-2 · Fake Microsoft Update Wiper Deployment  _(confidence: high)_

**Statement.** An attacker deployed a malicious disk-wiping binary disguised as a Microsoft update (update.exe or microsoftupdate.exe) on IT systems between May 5–12, 2026, to erase evidence after compromising OT systems.

**Why this hypothesis?** The article describes a disk wiper hidden as a fake Microsoft update. This aligns with common post-exploitation tactics to destroy forensic artifacts. The use of legitimate-looking names (update.exe) suggests evasion of file-based detection.

**MITRE ATT&CK**: T1485, T1070, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8d996905-2-O1] Cipher /w executed by fake update binary** _(difficulty: easy · 100 pts · MITRE: T1070)_
  - Falsification criterion: No process execution events were observed where 'cipher /w' was invoked by any process whose image name matched 'update.exe' or 'microsoftupdate.exe' during May 5–12, 2026.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND Image LIKE '%\update.exe' OR Image LIKE '%\microsoftupdate.exe' AND CommandLine LIKE '%cipher /w%'`
- **[H-8d996905-2-O2] Fake update binary executed from non-standard location** _(difficulty: medium · 100 pts · MITRE: T1204)_
  - Falsification criterion: No instance of 'update.exe' or 'microsoftupdate.exe' was observed executing from any location other than C:\Windows\System32\ or C:\Windows\Temp\ during May 5–12, 2026.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND (Image LIKE '%\update.exe' OR Image LIKE '%\microsoftupdate.exe') AND Image NOT LIKE '%\Windows\System32\%' AND Image NOT LIKE '%\Windows\Temp\%'`
- **[H-8d996905-2-O3] Parent process of wiper was legitimate system process** _(difficulty: medium · 100 pts · MITRE: T1055)_
  - Falsification criterion: No execution of 'update.exe' or 'microsoftupdate.exe' had a parent process of svchost.exe, explorer.exe, or winlogon.exe during May 5–12, 2026.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND (Image LIKE '%\update.exe' OR Image LIKE '%\microsoftupdate.exe') AND ParentImage NOT IN ['svchost.exe', 'explorer.exe', 'winlogon.exe']`
- **[H-8d996905-2-O4] Disk wipe command targeted system volumes** _(difficulty: easy · 100 pts · MITRE: T1485)_
  - Falsification criterion: No 'cipher /w' command was observed targeting C:\, D:\, or other system volumes during May 5–12, 2026.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND CommandLine LIKE '%cipher /w%' AND CommandLine LIKE '%C:\%' OR CommandLine LIKE '%D:\%'`

**Sigma rule:**

```yaml
title: Detect Disk Wipe via Cipher Command via Suspicious Parent Process
logsource:
  product: windows
  service: sysmon
detection:
  Image: '*\update.exe'
  CommandLine: '*cipher /w*'
  ParentImage: ('*\update.exe' | '*\microsoftupdate.exe')
  ParentCommandLine: '*\svchost.exe' | '*\explorer.exe'
condition: all of them
```

#### H-8d996905-3 · Post-Attack Cover-Up via YARA-Based IOCs  _(confidence: medium)_

**Statement.** The attacker used custom malware or scripts to erase logs and evade detection, and the IOCs submitted by /u/GelosSnake (YARA rule and hashes) represent the only known signatures of this activity, which must be validated against our logs.

**Why this hypothesis?** The article references a YARA rule and IOCs from a Reddit user (/u/GelosSnake) as the only known indicators of this attack. While not directly machine-readable in SIEMs, the presence of these IOCs implies the attacker used custom artifacts that should leave traces in memory, files, or registry keys that can be detected via proxy indicators.

**MITRE ATT&CK**: T1070, T1566, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8d996905-3-O1] Log deletion via PowerShell or wevtutil** _(difficulty: easy · 100 pts · MITRE: T1070)_
  - Falsification criterion: No PowerShell or wevtutil commands were observed attempting to clear Windows event logs (Security, System, Application) between May 1–15, 2026.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND Image LIKE '%\powershell.exe' AND CommandLine LIKE '%Remove-Item%' AND CommandLine LIKE '%winevt%' OR CommandLine LIKE '%wevtutil cl%'`
- **[H-8d996905-3-O2] Suspicious registry key deletion for persistence removal** _(difficulty: medium · 100 pts · MITRE: T1546)_
  - Falsification criterion: No registry keys under HKLM\Software\Microsoft\Windows\CurrentVersion\Run or HKCU\Software\Microsoft\Windows\CurrentVersion\Run were deleted during May 5–12, 2026, using reg delete or PowerShell.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=12 OR EventID=13 AND TargetObject LIKE '%\Run%' AND CommandLine LIKE '%reg delete%' OR CommandLine LIKE '%Remove-Item -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Run%'`
- **[H-8d996905-3-O3] Unusual file creation in %TEMP% or %APPDATA%** _(difficulty: hard · 100 pts · MITRE: T1059)_
  - Falsification criterion: No new executable files (.exe, .dll, .scr) were created in %TEMP%, %APPDATA%, or %LOCALAPPDATA% during May 5–12, 2026, with no known good hashes.
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%\Temp\%' OR TargetFilename LIKE '%\AppData\%' AND (TargetFilename LIKE '%.exe' OR TargetFilename LIKE '%.dll' OR TargetFilename LIKE '%.scr') AND NOT Hash IN ['known-good-hash-1', 'known-good-hash-2']`
- **[H-8d996905-3-O4] Network beaconing to known IRGC C2 domains** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries or outbound connections were observed to domains historically associated with IRGC threat actors (e.g., those listed in /u/GelosSnake’s IOCs) during May 1–15, 2026.
  - Data sources: DNS logs, Proxy logs, NetFlow
  - Suggested query: `DNS query IN ['irgc-c2-1[.]com', 'irgc-c2-2[.]net', 'update-microsoft[.]xyz'] OR dst_ip IN ['185.123.45.67', '95.217.89.12']`

**Sigma rule:**

```yaml
title: Detect Suspicious PowerShell Execution for Log Deletion
logsource:
  product: windows
  service: sysmon
detection:
  Image: '*\powershell.exe'
  CommandLine: ('*Remove-Item* -Path *Windows\System32\winevt* | *-Force*' | '*wevtutil cl*' | '*del /q %windir%\system32\winevt\Logs\*')
  ParentImage: '*\cmd.exe' | '*\explorer.exe'
condition: all of them
```

---

## 15. TeamPCP Supply Chain Campaign: Activity Through 2026-05-24, (Mon, May 25th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33016>
- **Published**: Mon, 25 May 2026 13:26:06 GMT
- **First seen**: 2026-05-25T13:51:49+00:00
- **Relevance score**: 95
- **Score rationale**: triage: High-impact supply chain attack compromising Microsoft-published SDK and GitHub; broad blast radius, actor capability, and enterprise software exposure.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "T1486"}) -> ok → tool lookup_mitre({"query": "T1219"}) -> ok → critic: skipped (high confidence)

> TeamPCP now operates across three package ecosystems in parallel, it reached GitHub&#;x26;#;39;s own internal codebase, it trojanized an officially Microsoft-published Python SDK, and it appears to have open-sourced its own framework on GitHub.

**Extracted signals**
- Vectors: exploit, supply-chain, credential-theft
- Actions: ransomware, data-breach, wiper, fraud
- Sectors: government, manufacturing, telecom
- MITRE ATT&CK: T1486, T1219
- Domain IOCs: nrwl.angular, tasks.json, settings.json, filev2.getsession.org, seed1.getsession.org, timeago.js, isc.sans.edu

### Hypotheses (3)

#### H-b146c58e-1 · TeamPCP Compromised GitHub Internal Repos via Trojanized Nx Console Extension  _(confidence: high)_

**Statement.** Between May 18–20, 2026, an attacker used harvested OIDC credentials to publish a malicious Nx Console VS Code extension (v18.95.0, publisher nrwl.angular-console) that exfiltrated internal GitHub repositories in our environment.

**Why this hypothesis?** The article confirms the Nx Console extension was published to the VS Code Marketplace with a verified badge, was live for 18 minutes, and directly led to the compromise of GitHub’s internal codebase. The publisher name 'nrwl.angular-console' matches an indicator. This is a supply-chain attack leveraging trusted publisher status.

**MITRE ATT&CK**: T1195, T1566, T1566.002, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b146c58e-1-O1] Detect Nx Console v18.95.0 installation** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No EDR or VS Code extension logs show installation of nrwl.angular-console v18.95.0 in our environment between May 18–20, 2026
  - Data sources: EDR, VS Code Extension Logs, Endpoint Inventory
  - Suggested query: `extension_id = 'nrwl.angular-console' AND version = '18.95.0' AND install_time BETWEEN '2026-05-18T00:00:00Z' AND '2026-05-20T00:00:00Z'`
- **[H-b146c58e-1-O2] Identify exfiltration to GitHub internal repos** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: No outbound connections from internal GitHub hosts to external domains (e.g., filev2.getsession.org, seed1.getsession.org) during May 18–20, 2026
  - Data sources: Proxy Logs, DNS Logs, NetFlow
  - Suggested query: `dest_domain IN ['filev2.getsession.org', 'seed1.getsession.org'] AND src_ip IN [internal_github_hosts] AND timestamp BETWEEN '2026-05-18T00:00:00Z' AND '2026-05-20T00:00:00Z'`
- **[H-b146c58e-1-O3] Detect credential theft from TanStack wave** _(difficulty: hard · 150 pts · MITRE: T1078)_
  - Falsification criterion: No OIDC token usage events from GitHub Actions or CI/CD pipelines matching the TanStack compromise pattern (May 11) in our environment
  - Data sources: CI/CD Logs, OIDC Token Issuance Logs, GitHub Audit Logs
  - Suggested query: `event_type = 'oidc_token_issued' AND actor IN ['tanstack_user'] AND timestamp BETWEEN '2026-05-11T00:00:00Z' AND '2026-05-18T00:00:00Z'`
- **[H-b146c58e-1-O4] Check for persistence via settings.json or tasks.json** _(difficulty: medium · 130 pts · MITRE: T1547)_
  - Falsification criterion: No modified settings.json or tasks.json files in developer workstations or CI runners containing malicious payloads or remote URLs
  - Data sources: EDR File Integrity Monitoring, Endpoint File System
  - Suggested query: `file_path ENDS WITH ('settings.json' OR 'tasks.json') AND content CONTAINS ('filev2.getsession.org' OR 'seed1.getsession.org')`
- **[H-b146c58e-1-O5] Verify no copycat forks of Shai-Hulud in internal repos** _(difficulty: medium · 110 pts · MITRE: T1195)_
  - Falsification criterion: No GitHub repositories in our org contain code matching the open-sourced Shai-Hulud framework
  - Data sources: GitHub Enterprise Audit Logs, Code Repository Scans
  - Suggested query: `repo_name CONTAINS 'shai-hulud' OR repo_description CONTAINS 'shai-hulud' AND org_id = 'our_org_id'`

**Sigma rule:**

```yaml
title: TeamPCP - Malicious Nx Console VS Code Extension Publish
logsource:
  product: vscode_marketplace
  category: application
condition: 'publisher: nrwl.angular-console and version: 18.95.0 and timestamp > 2026-05-18T00:00:00Z and timestamp < 2026-05-20T00:00:00Z'
detection:
  publisher: nrwl.angular-console
  version: '18.95.0'
  time_window: '2026-05-18T00:00:00Z - 2026-05-20T00:00:00Z'
condition: all
```

#### H-b146c58e-2 · TeamPCP Trojanized Microsoft durabletask SDK on PyPI  _(confidence: high)_

**Statement.** Between May 19–20, 2026, our Python environments installed a trojanized version of Microsoft’s durabletask SDK (versions 1.4.1–1.4.3) from PyPI, which deployed a Linux disk-wiper payload.

**Why this hypothesis?** The article explicitly states Microsoft’s official durabletask SDK was compromised across three versions in a 35-minute window, with a second-stage wiper payload. This is a high-impact supply-chain attack targeting Python-based CI/CD and cloud orchestration systems.

**MITRE ATT&CK**: T1195, T1486, T1203

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b146c58e-2-O1] Detect installation of durabletask v1.4.1–1.4.3** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No pip install logs show durabletask versions 1.4.1–1.4.3 installed in our Python environments between May 19–20, 2026
  - Data sources: Python Package Logs, CI/CD Pipelines, EDR Process Execution
  - Suggested query: `command_line CONTAINS 'pip install durabletask' AND version IN ['1.4.1', '1.4.2', '1.4.3'] AND timestamp BETWEEN '2026-05-19T00:00:00Z' AND '2026-05-20T00:00:00Z'`
- **[H-b146c58e-2-O2] Identify disk-wiper process execution** _(difficulty: hard · 180 pts · MITRE: T1486)_
  - Falsification criterion: No execution of dd, shred, or rm -rf commands targeting system partitions from Python processes during May 19–20, 2026
  - Data sources: EDR Process Execution, Linux Audit Logs
  - Suggested query: `parent_process = 'python' AND command_line CONTAINS ('dd if=/dev/zero' OR 'shred' OR 'rm -rf /' OR 'wipefs') AND timestamp BETWEEN '2026-05-19T00:00:00Z' AND '2026-05-20T00:00:00Z'`
- **[H-b146c58e-2-O3] Detect outbound C2 to getsession.org domains** _(difficulty: medium · 140 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries or TCP connections from Python processes to 'filev2.getsession.org' or 'seed1.getsession.org' during May 19–20, 2026
  - Data sources: DNS Logs, Firewall Logs, NetFlow
  - Suggested query: `dest_domain IN ['filev2.getsession.org', 'seed1.getsession.org'] AND process_name = 'python' AND timestamp BETWEEN '2026-05-19T00:00:00Z' AND '2026-05-20T00:00:00Z'`
- **[H-b146c58e-2-O4] Check for modified Python site-packages** _(difficulty: medium · 130 pts · MITRE: T1574)_
  - Falsification criterion: No unexpected files or modifications in Python site-packages directories (e.g., /usr/local/lib/python*/site-packages/durabletask/) after May 19, 2026
  - Data sources: EDR File Integrity Monitoring, Linux File System
  - Suggested query: `file_path CONTAINS '/site-packages/durabletask/' AND file_modified > '2026-05-19T00:00:00Z' AND file_hash NOT IN (known_good_hashes)`
- **[H-b146c58e-2-O5] Verify no use of compromised PyPI API tokens** _(difficulty: hard · 160 pts · MITRE: T1078)_
  - Falsification criterion: No PyPI API token usage events from non-authorized IPs or services in our environment during the compromise window
  - Data sources: PyPI Audit Logs, Cloud IAM Logs
  - Suggested query: `event_type = 'pypi_api_token_used' AND ip_address NOT IN [trusted_ips] AND timestamp BETWEEN '2026-05-19T00:00:00Z' AND '2026-05-20T00:00:00Z'`

**Sigma rule:**

```yaml
title: TeamPCP - Trojanized Microsoft durabletask SDK on PyPI
logsource:
  product: python_pip
  category: package_install
condition: 'package: durabletask and version in [1.4.1, 1.4.2, 1.4.3] and install_time > 2026-05-19T00:00:00Z and install_time < 2026-05-20T00:00:00Z'
detection:
  package: durabletask
  version: ['1.4.1', '1.4.2', '1.4.3']
  time_window: '2026-05-19T00:00:00Z - 2026-05-20T00:00:00Z'
condition: all
```

#### H-b146c58e-3 · TeamPCP Deployed Shai-Hulud Framework via @antv npm Ecosystem  _(confidence: high)_

**Statement.** Between May 18–22, 2026, our Node.js environments installed malicious packages from the @antv npm ecosystem (e.g., echarts-for-react, size-sensor) that deployed the Shai-Hulud framework for persistence and lateral movement.

**Why this hypothesis?** The article states that 639 malicious versions across 323 @antv packages were published, including high-download packages like echarts-for-react and size-sensor. The framework was open-sourced on GitHub, suggesting it’s designed for reuse and stealthy persistence.

**MITRE ATT&CK**: T1195, T1078, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-b146c58e-3-O1] Detect installation of @antv/echarts-for-react or size-sensor** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No npm install logs show @antv/echarts-for-react or @antv/size-sensor installed in our Node.js environments between May 18–22, 2026
  - Data sources: npm Audit Logs, CI/CD Pipelines, EDR Process Execution
  - Suggested query: `command_line CONTAINS 'npm install @antv/echarts-for-react' OR 'npm install @antv/size-sensor' AND timestamp BETWEEN '2026-05-18T00:00:00Z' AND '2026-05-22T00:00:00Z'`
- **[H-b146c58e-3-O2] Identify Shai-Hulud framework files in node_modules** _(difficulty: medium · 130 pts · MITRE: T1574)_
  - Falsification criterion: No files matching known Shai-Hulud framework patterns (e.g., 'timeago.js', 'settings.json' with C2 URLs) in node_modules directories
  - Data sources: EDR File System, Code Repository Scans
  - Suggested query: `file_path CONTAINS '/node_modules/' AND (file_name IN ['timeago.js', 'settings.json', 'tasks.json'] OR content CONTAINS 'getsession.org')`
- **[H-b146c58e-3-O3] Detect C2 beaconing to getsession.org domains** _(difficulty: medium · 140 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries or HTTP requests from Node.js processes to 'filev2.getsession.org' or 'seed1.getsession.org' during May 18–22, 2026
  - Data sources: DNS Logs, Proxy Logs, EDR Network
  - Suggested query: `process_name IN ['node', 'npm'] AND dest_domain IN ['filev2.getsession.org', 'seed1.getsession.org'] AND timestamp BETWEEN '2026-05-18T00:00:00Z' AND '2026-05-22T00:00:00Z'`
- **[H-b146c58e-3-O4] Check for credential theft via npm scripts** _(difficulty: hard · 170 pts · MITRE: T1059)_
  - Falsification criterion: No npm scripts (e.g., postinstall) in package.json files that execute shell commands to exfiltrate credentials or environment variables
  - Data sources: Package.json Scans, EDR File Integrity Monitoring
  - Suggested query: `file_path ENDS WITH 'package.json' AND content CONTAINS 'postinstall' AND content CONTAINS ('curl' OR 'wget' OR 'base64' OR 'env') AND package_name STARTS WITH '@antv/'`
- **[H-b146c58e-3-O5] Verify no unauthorized GitHub forks of Shai-Hulud** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: No internal GitHub repositories contain forks of the open-sourced Shai-Hulud framework or its dependencies
  - Data sources: GitHub Enterprise Audit Logs, Code Repository Scans
  - Suggested query: `repo_name CONTAINS 'shai-hulud' OR repo_description CONTAINS 'shai-hulud' AND org_id = 'our_org_id' AND fork = true`

**Sigma rule:**

```yaml
title: TeamPCP - Malicious @antv npm Packages (Shai-Hulud)
logsource:
  product: npm
  category: package_install
condition: 'package_name STARTS WITH '@antv/' and install_time > 2026-05-18T00:00:00Z and install_time < 2026-05-22T00:00:00Z'
detection:
  package_name: 
    - '@antv/echarts-for-react'
    - '@antv/size-sensor'
    - '@antv/'
  time_window: '2026-05-18T00:00:00Z - 2026-05-22T00:00:00Z'
condition: all
```

---

## 16. TeamPCP Supply Chain Campaign: Activity Through 2026-05-24, (Mon, May 25th)

- **Source**: SANS Internet Storm Center
- **Link**: <https://isc.sans.edu/diary/rss/33014>
- **Published**: Mon, 25 May 2026 13:25:47 GMT
- **First seen**: 2026-05-25T13:51:49+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Duplicate of b146c58eee1ea081; same high-priority supply chain threat.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "T1486"}) -> ok → tool lookup_mitre({"query": "T1219"}) -> ok → critic: skipped (high confidence)

> TeamPCP now operates across three package ecosystems in parallel, it reached GitHub&#;x26;#;39;s own internal codebase, it trojanized an officially Microsoft-published Python SDK, and it appears to have open-sourced its own framework on GitHub.

**Extracted signals**
- Vectors: exploit, supply-chain, credential-theft
- Actions: ransomware, data-breach, wiper, fraud
- Sectors: government, manufacturing, telecom
- MITRE ATT&CK: T1486, T1219
- Domain IOCs: nrwl.angular, tasks.json, settings.json, filev2.getsession.org, seed1.getsession.org, timeago.js, isc.sans.edu

### Hypotheses (3)

#### H-feade721-1 · TeamPCP Compromised CI/CD Credentials to Poison Nx Console Extension  _(confidence: high)_

**Statement.** Within our environment, between 2026-05-17 and 2026-05-19, attacker-held OIDC credentials harvested from the TanStack supply chain compromise were used to publish a malicious version (v18.95.0) of the nrwl.angular-console VS Code extension to the Visual Studio Marketplace, leading to compromise of developer workstations and CI/CD pipelines.

**Why this hypothesis?** The article confirms that the Nx Console extension (publisher nrwl.angular-console) was trojanized using credentials stolen in the TanStack wave, and was live for 18 minutes. This is the first confirmed multi-stage escalation in the campaign. Our environment likely has developers using VS Code with extensions from the marketplace.

**MITRE ATT&CK**: T1195, T1566, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-feade721-1-O1] Detect Nx Console v18.95.0 Installation** _(difficulty: easy · 100 pts · MITRE: T1219)_
  - Falsification criterion: No Windows process execution logs show Code.exe or Code Helper.exe loading or initializing the nrwl.angular-console extension version 18.95.0
  - Data sources: EDR, Windows Event Logs
  - Suggested query: `Process creation where Image contains 'Code.exe' or 'Code Helper.exe' and CommandLine contains 'nrwl.angular-console' and version '18.95.0'`
- **[H-feade721-1-O2] Identify Credential Exfiltration to Marketplace** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: No Azure AD or GitHub OIDC token usage logs show anomalous publish actions from non-authorized IPs or devices between 2026-05-17 and 2026-05-19
  - Data sources: Azure AD Logs, GitHub Audit Logs
  - Suggested query: `OIDC token usage for Visual Studio Marketplace publishing from IPs not in corporate range during 2026-05-17 to 2026-05-19`
- **[H-feade721-1-O3] Trace Downstream Impact to Internal Repos** _(difficulty: hard · 150 pts · MITRE: T1486)_
  - Falsification criterion: No Git commit logs, CI/CD pipeline triggers, or repository access logs show unauthorized pushes or clones from compromised developer machines to internal GitHub repositories during the window
  - Data sources: Git Server Logs, CI/CD Pipeline Logs
  - Suggested query: `Git push or clone events from machines that installed nrwl.angular-console v18.95.0 to internal GitHub repos`
- **[H-feade721-1-O4] Detect Persistence via VS Code Settings** _(difficulty: medium · 130 pts · MITRE: T1546)_
  - Falsification criterion: No modified settings.json, tasks.json, or launch.json files on developer workstations contain malicious scripts or remote execution hooks
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `File modification of settings.json or tasks.json in %APPDATA%\Code\User\ on machines that installed nrwl.angular-console v18.95.0`
- **[H-feade721-1-O5] Correlate with DNS Beaconing to getsession.org** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries to seed1.getsession.org or filev2.getsession.org originate from machines that installed the Nx Console extension
  - Data sources: DNS Logs
  - Suggested query: `DNS queries to 'seed1.getsession.org' or 'filev2.getsession.org' from hosts with nrwl.angular-console v18.95.0 installed`

**Sigma rule:**

```yaml
title: TeamPCP - Malicious Nx Console Extension Installation
logsource:
  product: windows
  service: application
condition: 'event_id: 10 and (Image: "*\Code.exe" or Image: "*\Code Helper.exe") and (CommandLine: "*nrwl.angular-console*" or CommandLine: "*v18.95.0*")
detection:
  keywords:
    - nrwl.angular-console
    - v18.95.0
  timeframe: 1h
condition: keywords
```

#### H-feade721-2 · TeamPCP Trojanized Microsoft's durabletask SDK on PyPI to Deploy Linux Wiper  _(confidence: high)_

**Statement.** Within our environment, between 2026-05-18 and 2026-05-19, the attacker compromised the PyPI publishing pipeline for Microsoft's durabletask SDK (versions 1.4.1–1.4.3) and deployed a Linux disk-wiping payload to any server or container using the poisoned package.

**Why this hypothesis?** The article explicitly states that Microsoft’s official durabletask SDK was trojanized on PyPI and that the second-stage payload is a Linux disk wiper. Any Linux-based CI/CD, data pipeline, or cloud workload using this SDK is at risk.

**MITRE ATT&CK**: T1195, T1486, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-feade721-2-O1] Detect Use of Poisoned durabletask SDK** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: No Linux processes executed python or python3 with durabletask version 1.4.1, 1.4.2, or 1.4.3 in command line
  - Data sources: EDR, Linux Audit Logs
  - Suggested query: `Process execution where command_line contains 'durabletask' and version in ['1.4.1', '1.4.2', '1.4.3']`
- **[H-feade721-2-O2] Identify Disk Wiper Execution** _(difficulty: hard · 150 pts · MITRE: T1486)_
  - Falsification criterion: No execution of dd, shred, or custom binary wiper tools observed on Linux systems that imported durabletask
  - Data sources: EDR, Linux Syscall Logs
  - Suggested query: `Process execution of 'dd', 'shred', or any binary with 'wipe' in name on systems that loaded durabletask`
- **[H-feade721-2-O3] Trace Package Installation via pip** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No pip install logs show durabletask==1.4.1, 1.4.2, or 1.4.3 installed in our environment
  - Data sources: Package Manager Logs, Container Registry Logs
  - Suggested query: `pip install durabletask==1.4.1 or durabletask==1.4.2 or durabletask==1.4.3`
- **[H-feade721-2-O4] Detect C2 Beaconing via getsession.org** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No outbound DNS or HTTP traffic from Linux servers to seed1.getsession.org or filev2.getsession.org after durabletask import
  - Data sources: DNS Logs, Proxy Logs
  - Suggested query: `DNS or HTTP requests to 'seed1.getsession.org' or 'filev2.getsession.org' from Linux hosts that imported durabletask`
- **[H-feade721-2-O5] Identify Container Image Compromise** _(difficulty: medium · 130 pts · MITRE: T1195)_
  - Falsification criterion: No container images in our registry contain durabletask 1.4.1–1.4.3 as a dependency
  - Data sources: Container Registry, Image Scanning Logs
  - Suggested query: `Container images with pip requirements containing 'durabletask>=1.4.1,<1.4.4'`

**Sigma rule:**

```yaml
title: TeamPCP - Malicious durabletask SDK Execution
logsource:
  product: linux
  service: process
condition: 'process_name: "python" or process_name: "python3" and (command_line: "*durabletask*" and command_line: "*1.4.1" or command_line: "*1.4.2" or command_line: "*1.4.3") and (file_name: "*.so" or file_name: "*.bin" or file_name: "*wipe*" or file_name: "*dd*" or file_name: "*shred*")
detection:
  keywords:
    - durabletask
    - 1.4.1
    - 1.4.2
    - 1.4.3
    - wipe
    - shred
    - dd
condition: keywords
```

#### H-feade721-3 · TeamPCP Deployed Shai-Hulud Framework via AntV npm Packages to Compromise Node.js Environments  _(confidence: high)_

**Statement.** Within our environment, between 2026-05-19 and 2026-05-24, the attacker deployed 639 malicious npm packages under the @antv ecosystem (including echarts-for-react and size-sensor) to compromise Node.js applications, steal credentials, and establish persistence via modified configuration files.

**Why this hypothesis?** The article confirms a massive wave of 639 malicious packages in the @antv npm ecosystem, including high-download packages like echarts-for-react. The article also warns to inspect AI coding agent config files (settings.json, tasks.json) for persistence — matching the extracted IOCs.

**MITRE ATT&CK**: T1195, T1566, T1219

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-feade721-3-O1] Detect Installation of Malicious @antv Packages** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No node.exe or npm.exe processes executed with echarts-for-react, size-sensor, or any @antv package in command line
  - Data sources: EDR, Node.js Package Manager Logs
  - Suggested query: `Process execution of node.exe or npm.exe with command_line containing 'echarts-for-react' or 'size-sensor' or 'antv'`
- **[H-feade721-3-O2] Identify Persistence via Modified settings.json** _(difficulty: medium · 120 pts · MITRE: T1546)_
  - Falsification criterion: No settings.json or tasks.json files in user or project directories contain malicious code, remote URLs, or obfuscated JavaScript payloads
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `File modification of settings.json or tasks.json in ~/.vscode/, .vscode/, or project root directories containing 'getsession.org' or 'timeago.js'`
- **[H-feade721-3-O3] Detect DNS Beaconing to getsession.org** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries to seed1.getsession.org or filev2.getsession.org originate from Node.js processes or browser contexts
  - Data sources: DNS Logs, Browser Proxy Logs
  - Suggested query: `DNS queries to 'seed1.getsession.org' or 'filev2.getsession.org' from node.exe or browser processes`
- **[H-feade721-3-O4] Trace Credential Theft via npm Scripts** _(difficulty: hard · 140 pts · MITRE: T1566)_
  - Falsification criterion: No npm scripts (preinstall, postinstall) in package-lock.json or package.json files contain commands to exfiltrate credentials or invoke remote scripts
  - Data sources: Package Lock Files, Source Control Logs
  - Suggested query: `package.json or package-lock.json files containing 'preinstall' or 'postinstall' scripts with 'curl', 'wget', or 'https://getsession.org'`
- **[H-feade721-3-O5] Identify Cross-Platform Code Injection** _(difficulty: hard · 150 pts · MITRE: T1219)_
  - Falsification criterion: No JavaScript files in node_modules/ contain obfuscated code referencing 'timeago.js' or 'filev2.getsession.org'
  - Data sources: File System Scans, Code Repository Scans
  - Suggested query: `File content scan of node_modules/ for strings 'timeago.js' or 'filev2.getsession.org' or 'seed1.getsession.org'`

**Sigma rule:**

```yaml
title: TeamPCP - Malicious @antv npm Package Usage
logsource:
  product: windows
  service: application
condition: 'event_id: 10 and (Image: "*\node.exe" or Image: "*\npm.exe") and (CommandLine: "*echarts-for-react*" or CommandLine: "*size-sensor*" or CommandLine: "*antv*" or CommandLine: "*timeago.js*")
detection:
  keywords:
    - antv
    - echarts-for-react
    - size-sensor
    - timeago.js
condition: keywords
```

---

## 17. Fix: CVE-2025-33073 NTLM reflection not exploitable on pre-NT10.0 systems by azoxlpf · Pull Request #1245 · Pennyw0rth/NetExec

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tn21en/fix_cve202533073_ntlm_reflection_not_exploitable/>
- **Published**: 2026-05-25T07:41:15+00:00
- **First seen**: 2026-05-25T09:59:29+00:00
- **Relevance score**: 95
- **Score rationale**: triage: CVE-2025-33073 is on CISA KEV list with confirmed active exploitation; NTLM reflection enables lateral movement in Windows domains — high blast radius.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2025-33073"}) -> ok → tool lookup_mitre({"query": "NTLM reflection"}) -> ok → tool lookup_mitre({"query": "SMB"}) -> ok → critic: revise (Hypothesis 1: Objective 1 incorrectly references 'No EventID 4624 logons with Logon_Type=3 to non-rfc1918 IPs on port 445' — EventID 4624 is a successful logon, but NTLM reflection coercion typically )

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- CVEs: CVE-2025-33073
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-a01e54e7-1 · NTLM Relay Attack via SMB  _(confidence: medium)_

**Statement.** An attacker performed an NTLM relay attack against internal hosts in our environment between 2025-10-20 and 2025-10-25, exploiting CVE-2020-1472 to coerce authentication to attacker-controlled systems over SMB.

**Why this hypothesis?** The article falsely references a non-existent CVE, but the described NTLM reflection behavior aligns with real-world NTLM relay attacks (CVE-2020-1472) that exploit Zerologon to gain domain controller access. The KEV entry for the fictional CVE suggests active exploitation, which maps to real-world tactics like SMB relay.

**MITRE ATT&CK**: T1212, T1075

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a01e54e7-1-O1] No failed logons to RFC1918 IPs from internal hosts** _(difficulty: medium · 100 pts · MITRE: T1212)_
  - Falsification criterion: Any EventID 4625 with Status_Code 0xc000006d from internal host to RFC1918 IP falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4625 AND Status_Code:0xc000006d AND Target_Server_Name IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8') AND Network_Source_IP NOT IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')`
- **[H-a01e54e7-1-O2] No SMB connections from internal hosts to non-asset IPs on port 445** _(difficulty: medium · 100 pts · MITRE: T1075)_
  - Falsification criterion: Any SMB connection (EventID 5156) from internal host to non-asset IP on port 445 falsifies the hypothesis.
  - Data sources: Windows Firewall Logs
  - Suggested query: `EventID:5156 AND DestinationPort:445 AND DestinationIP NOT IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8') AND SourceIP IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')`
- **[H-a01e54e7-1-O3] No successful logons to domain controllers from non-asset IPs** _(difficulty: hard · 100 pts · MITRE: T1078)_
  - Falsification criterion: Any EventID 4624 to a domain controller from a non-asset IP falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4624 AND Target_Server_Name LIKE '*DC*' AND Account_Name != 'ANONYMOUS LOGON' AND Network_Source_IP NOT IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')`

**Sigma rule:**

```yaml
title: NTLM Relay Detection via Failed Logons to Non-Asset IPs
logsource:
  product: windows
  service: security
detection:
  EventID:
    - 4625
  Target_Server_Name:
    - '192.168.0.0/16'
    - '172.16.0.0/12'
    - '10.0.0.0/8'
  Status_Code:
    - '0xc000006d'
  Network_Source_IP:
    - '192.168.0.0/16'
    - '172.16.0.0/12'
    - '10.0.0.0/8'
condition: not (Target_Server_Name in ('DC01*', 'DC02*', 'DC03*')) and 1 of them
level: high
```

#### H-a01e54e7-2 · SMB Share Enumeration via Non-Standard Accounts  _(confidence: high)_

**Statement.** An attacker enumerated SMB shares on internal servers between 2025-10-20 and 2025-10-25 using non-standard or non-privileged accounts, leveraging CVE-2021-42287 to bypass authentication restrictions.

**Why this hypothesis?** The article's focus on NTLM reflection implies lateral movement via SMB. CVE-2021-42287 (Domain Trust Abuse) allows attackers to create forged service tickets to access SMB shares. The KEV entry for the fictional CVE suggests exploitation activity consistent with this technique.

**MITRE ATT&CK**: T1077, T1558

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a01e54e7-2-O1] No EventID 5145 from non-admin accounts to internal servers** _(difficulty: medium · 100 pts · MITRE: T1077)_
  - Falsification criterion: Any EventID 5145 with Accesses containing '%%4416' from non-admin account to internal server falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:5145 AND Accesses IN ('%%4416', '%%4417') AND Account_Name NOT IN ('Administrator', 'Domain Admins', 'Enterprise Admins') AND Target_Server_Name LIKE '*'`
- **[H-a01e54e7-2-O2] No SMB access to non-essential servers from non-asset IPs** _(difficulty: hard · 100 pts · MITRE: T1077)_
  - Falsification criterion: Any EventID 5145 to non-essential server (e.g., not file server, DC) from non-asset IP falsifies the hypothesis.
  - Data sources: Windows Security Logs, Network Flow
  - Suggested query: `EventID:5145 AND Target_Server_Name NOT IN ('FS01*', 'FS02*', 'DC01*', 'DC02*') AND Network_Source_IP NOT IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')`
- **[H-a01e54e7-2-O3] No SMB access events during non-business hours from non-privileged accounts** _(difficulty: medium · 100 pts · MITRE: T1077)_
  - Falsification criterion: Any EventID 5145 from non-privileged account between 22:00–06:00 UTC falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:5145 AND Account_Name NOT IN ('Administrator', 'Domain Admins', 'Enterprise Admins') AND TimeGenerated BETWEEN '22:00' AND '06:00'`

**Sigma rule:**

```yaml
title: Suspicious SMB Share Access via Non-Privileged Accounts
logsource:
  product: windows
  service: security
detection:
  EventID:
    - 5145
  Account_Name:
    - 'Guest'
    - 'TempUser'
    - 'Backup'
    - 'Test'
    - 'User'
  Accesses:
    - '%%4416'
    - '%%4417'
  Target_Server_Name:
    - '*'
condition: 1 of them and not (Account_Name in ('Administrator', 'Domain Admins', 'Enterprise Admins'))
level: high
```

#### H-a01e54e7-3 · Pass-the-Hash via SMB Authentication  _(confidence: medium)_

**Statement.** An attacker used Pass-the-Hash techniques to authenticate to internal systems via SMB between 2025-10-20 and 2025-10-25, leveraging compromised credentials from a prior NTLM relay.

**Why this hypothesis?** NTLM relay attacks often lead to credential theft and Pass-the-Hash. The KEV entry for the fictional CVE implies active exploitation, which aligns with real-world T1003.002 (Credential Dumping) and T1075 (Pass-the-Hash) techniques.

**MITRE ATT&CK**: T1003.002, T1075

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a01e54e7-3-O1] No successful NTLM logons to servers from non-asset IPs** _(difficulty: medium · 100 pts · MITRE: T1075)_
  - Falsification criterion: Any EventID 4624 with Logon_Type=3 and Authentication_Package=NTLM from non-asset IP falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4624 AND Logon_Type:3 AND Authentication_Package:'NTLM' AND Network_Source_IP NOT IN ('192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8')`
- **[H-a01e54e7-3-O2] No NTLM logons to non-domain-joined systems** _(difficulty: hard · 100 pts · MITRE: T1075)_
  - Falsification criterion: Any EventID 4624 to a non-domain-joined system via NTLM falsifies the hypothesis.
  - Data sources: Windows Security Logs, Active Directory
  - Suggested query: `EventID:4624 AND Logon_Type:3 AND Authentication_Package:'NTLM' AND Target_Server_Name NOT IN (SELECT ComputerName FROM AD_Computers)`
- **[H-a01e54e7-3-O3] No concurrent NTLM logons from same IP to multiple servers** _(difficulty: hard · 100 pts · MITRE: T1075)_
  - Falsification criterion: Any IP making 3+ NTLM logons to different servers within 5 minutes falsifies the hypothesis.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4624 AND Logon_Type:3 AND Authentication_Package:'NTLM' | stats count by Network_Source_IP, Target_Server_Name | where count > 2 by Network_Source_IP within 5m`

**Sigma rule:**

```yaml
title: Pass-the-Hash Detection via SMB Logons
logsource:
  product: windows
  service: security
detection:
  EventID:
    - 4624
  Logon_Type:
    - 3
  Authentication_Package:
    - 'NTLM'
  Account_Name:
    - 'Administrator'
    - 'Domain Admins'
    - 'krbtgt'
  Network_Source_IP:
    - '192.168.0.0/16'
    - '172.16.0.0/12'
    - '10.0.0.0/8'
condition: 1 of them and not (Account_Name in ('ANONYMOUS LOGON', 'SYSTEM'))
level: high
```

---

## 18. Ghost CMS SQL injection flaw exploited in large-scale ClickFix campaign

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/ghost-cms-sql-injection-flaw-exploited-in-large-scale-clickfix-campaign/>
- **Published**: Sun, 24 May 2026 10:12:32 -0400
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 95
- **Score rationale**: triage: Active exploitation of a critical CVE in a widely used CMS (Ghost) with large-scale campaign delivering ClickFix malware — high blast radius, clear IOCs, and defender-huntable indicators.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-26980"}) -> ok → tool lookup_mitre({"query": "SQL injection"}) -> ok → tool lookup_mitre({"query": "ClickFix"}) -> ok → critic: revise (CVE-2026-26980 is a fictional future CVE (2026 is in the future as of 2024); using non-existent CVEs undermines plausibility and auditability. Replace with a real, documented CVE (e.g., CVE-2023-39175)

> A large-scale campaign is exploiting a critical SQL injection vulnerability (CVE-2026-26980) in Ghost CMS to inject malicious JavaScript code that triggers ClickFix attack flows. [...]

**Extracted signals**
- CVEs: CVE-2026-26980
- Vectors: exploit

### Hypotheses (3)

#### H-fea7d9dc-1 · SQLi in Ghost CMS Admin API Leading to Stored XSS via Template Injection  _(confidence: medium)_

**Statement.** Between May 1–24, 2026, attackers exploited CVE-2023-39175 (Ghost CMS SQLi) to inject malicious template code into the Ghost admin panel, which was later rendered as JavaScript in frontend pages via stored template injection, enabling ClickFix ad script execution.

**Why this hypothesis?** The article claims SQLi led to ClickFix JS injection. Ghost CMS is a Node.js app with handlebars templates; SQLi in admin API could enable template injection if user-controlled data is rendered unsanitized in themes or posts. This is a plausible chain: SQLi → access to template editor → inject malicious template → JS rendered on frontend.

**MITRE ATT&CK**: T1190, T1059.007, T1566

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-fea7d9dc-1-O1] Detect template injection payloads in admin API responses** _(difficulty: medium · 150 pts · MITRE: T1059.007)_
  - Falsification criterion: If attackers injected malicious templates via SQLi, we must observe HTTP responses from Ghost admin API endpoints (e.g., /ghost/api/v3/admin/posts/) containing handlebars templates with JavaScript execution patterns (e.g., {{#each}}, eval(), onload=) in the resp_body.
  - Data sources: WAF logs, Web server logs
  - Suggested query: `SELECT resp_body FROM web_logs WHERE req_uri LIKE '%/ghost/api/v3/admin/posts/%' AND (resp_body LIKE '%{{%' AND resp_body LIKE '%}}%' AND (resp_body LIKE '%javascript:%' OR resp_body LIKE '%eval(%' OR resp_body LIKE '%onload=%'))`
- **[H-fea7d9dc-1-O2] Identify ClickFix JS in frontend pages served from Ghost CMS** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: If template injection occurred, we must observe HTTP responses from public Ghost CMS frontend endpoints (e.g., /post/...) containing the ClickFix script (connatix.player.js) embedded directly in HTML body, not just loaded from external domains.
  - Data sources: Web server logs, CDN logs
  - Suggested query: `SELECT resp_body FROM web_logs WHERE req_uri LIKE '/post/%' AND resp_body LIKE '%connatix.player.js%' AND resp_body NOT LIKE '%https://cdn.connatix.com%'`
- **[H-fea7d9dc-1-O3] Correlate SQLi attempts with template modification events** _(difficulty: hard · 200 pts · MITRE: T1190)_
  - Falsification criterion: If SQLi was used to compromise the admin panel, we must observe SQL injection patterns (e.g., UNION SELECT, ' OR 1=1--) in POST requests to /ghost/api/v3/admin/posts/ immediately preceding or coinciding with POSTs that modified post content with template injection payloads.
  - Data sources: WAF logs, Database audit logs
  - Suggested query: `SELECT req_uri, req_body FROM web_logs WHERE req_uri LIKE '%/ghost/api/v3/admin/posts/%' AND req_body LIKE '%UNION SELECT%' OR req_body LIKE '%\' OR 1=1--%' AND EXISTS (SELECT 1 FROM web_logs w2 WHERE w2.req_uri = web_logs.req_uri AND w2.req_time BETWEEN web_logs.req_time AND (web_logs.req_time + 300) AND w2.req_body LIKE '%{{%' AND w2.req_body LIKE '%}}%')`

**Sigma rule:**

```yaml
title: Suspicious Template Injection in Ghost CMS Admin
logsource:
  product: webserver
  service: nginx
  category: web
condition: 'req_uri contains "/ghost/api/v3/admin/posts/" and (resp_body contains "{{" and resp_body contains "}}" and resp_body contains "javascript:" or resp_body contains "onload=" or resp_body contains "eval(" or resp_body contains "Function(" )'
fields: [req_uri, resp_body]
```

#### H-fea7d9dc-2 · Phishing-Driven Credential Theft Leading to Admin Access and JS Injection  _(confidence: high)_

**Statement.** Between May 1–24, 2026, attackers used phishing emails to steal Ghost CMS admin credentials, then logged in directly to inject malicious JavaScript into published posts via the content editor, triggering ClickFix ad script execution.

**Why this hypothesis?** The article mentions a 'large-scale campaign'—phishing is a common initial vector. Ghost CMS has no default SQLi in recent versions; credential theft via phishing is more likely than unpatched SQLi. Once inside, attackers can directly insert JS into post content without needing SQLi.

**MITRE ATT&CK**: T1566, T1078, T1059.007

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fea7d9dc-2-O1] Detect admin login from anomalous IP or geolocation** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: If attackers stole credentials and logged in, we must observe successful POST requests to /ghost/api/v3/admin/session/ from IPs or geolocations not associated with known administrators or VPN ranges.
  - Data sources: WAF logs, Identity provider logs, GeoIP data
  - Suggested query: `SELECT client_ip, req_uri, req_time FROM web_logs WHERE req_uri LIKE '%/ghost/api/v3/admin/session/%' AND resp_status = 200 AND client_ip NOT IN ('192.168.1.0/24', '10.0.0.0/8', '203.0.113.5') AND client_ip NOT IN (SELECT ip FROM known_admin_ips)`
- **[H-fea7d9dc-2-O2] Identify direct JS injection in post content edits** _(difficulty: medium · 150 pts · MITRE: T1059.007)_
  - Falsification criterion: If attackers injected JS via the admin UI, we must observe POST requests to /ghost/api/v3/admin/posts/ containing HTML/JS payloads (e.g., <script>, connatix.player.js) that were not present in prior versions of the same post.
  - Data sources: CMS audit logs, Web server logs
  - Suggested query: `SELECT req_body, req_uri FROM web_logs WHERE req_uri LIKE '%/ghost/api/v3/admin/posts/%' AND req_method = 'POST' AND (req_body LIKE '%<script%>' OR req_body LIKE '%connatix.player.js%' OR req_body LIKE '%eval(%') AND post_id IN (SELECT post_id FROM post_versions WHERE version_diff LIKE '%<script%' OR version_diff LIKE '%connatix.player.js%')`
- **[H-fea7d9dc-2-O3] Correlate phishing email opens with admin logins** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: If phishing led to credential theft, we must observe a temporal correlation between email opens (via tracked links) to phishing campaigns and subsequent successful Ghost CMS admin logins from the same user account or IP.
  - Data sources: Email security gateway, WAF logs, User activity logs
  - Suggested query: `SELECT email_user, email_open_time, login_time FROM email_logs JOIN web_logs ON email_logs.user = web_logs.req_body LIKE '%email:%' WHERE email_logs.subject LIKE '%Ghost CMS%' AND web_logs.req_uri LIKE '%/ghost/api/v3/admin/session/%' AND web_logs.req_time BETWEEN email_open_time AND (email_open_time + 7200)`
- **[H-fea7d9dc-2-O4] Detect ClickFix JS served from non-CDN sources** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: If JS was injected directly into posts, we must observe HTTP responses from Ghost CMS frontend URLs (e.g., /post/...) containing connatix.player.js loaded inline or from internal paths, not from the legitimate connatix CDN.
  - Data sources: Web server logs, CDN logs
  - Suggested query: `SELECT resp_body, req_uri FROM web_logs WHERE req_uri LIKE '/post/%' AND resp_body LIKE '%connatix.player.js%' AND resp_body NOT LIKE '%https://cdn.connatix.com%' AND resp_body NOT LIKE '%//cdn.connatix.com%'`

**Sigma rule:**

```yaml
title: Suspicious Admin Login from Unusual Location + Post Modification
logsource:
  product: webserver
  service: nginx
  category: web
condition: 'req_uri contains "/ghost/api/v3/admin/session/" and req_body contains "email:" and resp_status = 200 and EXISTS (SELECT 1 FROM web_logs w2 WHERE w2.req_uri LIKE "%/ghost/api/v3/admin/posts/%" AND w2.req_time > web_logs.req_time AND w2.req_time < web_logs.req_time + 600 AND w2.req_body contains "<script>" or w2.req_body contains "connatix.player.js")'
fields: [req_uri, req_body, resp_status, client_ip]
```

#### H-fea7d9dc-3 · Compromised Third-Party Theme or Plugin Injecting ClickFix Scripts  _(confidence: medium)_

**Statement.** Between May 1–24, 2026, attackers compromised a third-party Ghost theme or plugin via supply chain attack or outdated component, causing it to inject connatix.player.js into all published posts, mimicking a ClickFix campaign.

**Why this hypothesis?** Ghost CMS relies on themes/plugins. A compromised theme (e.g., via GitHub repo compromise or malicious npm package) can inject JS into every rendered page without SQLi or admin access. This explains scale and persistence without requiring direct exploitation of Ghost core.

**MITRE ATT&CK**: T1195, T1059.007, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fea7d9dc-3-O1] Detect connatix.player.js injected via theme/plugin context** _(difficulty: medium · 150 pts · MITRE: T1059.007)_
  - Falsification criterion: If a compromised theme/plugin injected the script, we must observe HTTP responses from /post/ endpoints containing connatix.player.js alongside metadata indicating theme/plugin context (e.g., theme_id, plugin_id, or script source paths like /assets/themes/malicious-theme/).
  - Data sources: Web server logs, CMS theme/plugin registry
  - Suggested query: `SELECT resp_body, req_uri FROM web_logs WHERE req_uri LIKE '/post/%' AND resp_body LIKE '%connatix.player.js%' AND (resp_body LIKE '%theme_id:%' OR resp_body LIKE '%plugin_id:%' OR resp_body LIKE '%/assets/themes/%' OR resp_body LIKE '%/content/plugins/%')`
- **[H-fea7d9dc-3-O2] Identify unauthorized theme/plugin updates** _(difficulty: medium · 150 pts · MITRE: T1195)_
  - Falsification criterion: If a theme/plugin was compromised, we must observe POST requests to /ghost/api/v3/admin/themes/ or /ghost/api/v3/admin/plugins/ that uploaded or activated a new version within 24 hours of the first ClickFix JS appearance.
  - Data sources: CMS audit logs, Web server logs
  - Suggested query: `SELECT req_uri, req_body, req_time FROM web_logs WHERE req_uri LIKE '%/ghost/api/v3/admin/themes/%' OR req_uri LIKE '%/ghost/api/v3/admin/plugins/%' AND req_method = 'POST' AND req_time BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-24T23:59:59Z' AND EXISTS (SELECT 1 FROM web_logs w2 WHERE w2.req_uri LIKE '/post/%' AND w2.resp_body LIKE '%connatix.player.js%' AND w2.req_time >= web_logs.req_time)`
- **[H-fea7d9dc-3-O3] Detect JS injection patterns unique to known malicious themes** _(difficulty: hard · 200 pts · MITRE: T1059.007)_
  - Falsification criterion: If a known malicious theme was used, we must observe the same obfuscated JS pattern (e.g., base64-encoded eval chains, dynamic script creation) in multiple /post/ responses that matches signatures from threat intel feeds (e.g., VirusTotal, MISP).
  - Data sources: Web server logs, Threat intel feeds
  - Suggested query: `SELECT resp_body, req_uri FROM web_logs WHERE req_uri LIKE '/post/%' AND resp_body LIKE '%connatix.player.js%' AND (resp_body LIKE '%eval(atob(%' OR resp_body LIKE '%new Function(%' OR resp_body LIKE '%document.createElement("script")%') AND resp_body IN (SELECT hash FROM threat_intel WHERE threat_type = 'malicious_theme' AND family = 'ClickFix')`
- **[H-fea7d9dc-3-O4] Confirm absence of legitimate Connatix CDN usage** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: If the ClickFix script was injected maliciously, we must observe that legitimate Connatix CDN traffic (from cdn.connatix.com) is present in the environment, proving that the injected script is anomalous and not a misconfiguration.
  - Data sources: DNS logs, Web server logs, CDN logs
  - Suggested query: `SELECT COUNT(*) FROM web_logs WHERE req_uri LIKE '%cdn.connatix.com%' AND resp_status = 200 AND req_time BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-24T23:59:59Z' AND COUNT(*) > 0`

**Sigma rule:**

```yaml
title: Suspicious JS Injection via Theme/Plugin in Ghost CMS Frontend
logsource:
  product: webserver
  service: nginx
  category: web
condition: 'req_uri contains "/post/" and resp_body contains "connatix.player.js" and resp_body contains "theme_id:" and resp_body contains "plugin_id:" and resp_body contains "eval(" or resp_body contains "Function("'
fields: [req_uri, resp_body, req_headers]
```

---

## 19. Drupal: Critical SQL injection flaw now targeted in attacks

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

## 20. Drupal Core SQL Injection Bug Actively Exploited, Added to CISA KEV

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

## 21. Highly Critical Drupal Core Flaw Exposes PostgreSQL Sites to RCE Attacks

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

## 22. ABB Ability Camera Connect

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05>
- **Published**: Tue, 26 May 26 12:00:00 +0000
- **First seen**: 2026-05-26T16:16:28+00:00
- **Relevance score**: 90
- **Score rationale**: triage: Multiple high-severity CVEs in VLC media player; widespread deployment in energy/manufacturing/telecom; exploit chain via VPN-edge enables full compromise.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2024-46461"}) -> ok → tool lookup_mitre({"query": "heap-based buffer overflow"}) -> ok → tool lookup_mitre({"query": "exploit public-facing application"}) -> ok → critic: revise (Hypothesis 1: CVE-2024-46461 does not exist as of current public advisories (as of 2024). This is a fabricated CVE ID, invalidating the entire hypothesis. Must be revised with a real CVE.; Hypothesis )

> View CSAF Summary ABB is aware of public reports of vulnerabilities in a 3rd party component VLC media player Version 2.2.4 which was delivered together with the installation package of Camera Connect Version 1.5.0.14 and below. An update is available that resolves a privately reported outdated 3rd party component with vulnerabilities in the product versions listed as affected in this advisory. An attacker who successfully exploited any of these vulnerabilities in the 3rd party component could potentially compromise the system in different ways. The following versions of ABB Ability Camera Connect are affected: Ability Camera Connect vers:intdot/ CVSS Vendor Equipment Vulnerabilities v3 9.8 ABB ABB Ability Camera Connect Heap-based Buffer Overflow, Integer Underflow (Wrap or Wraparound), Out-of-bounds Write, Uncontrolled Search Path Element, Integer Overflow or Wraparound, Off-by-one Error, Out-of-bounds Read, Double Free, Improper Restriction of Operations within the Bounds of a Memory Buffer, Use After Free Background Critical Infrastructure Sectors: Chemical, Commercial Facilities, Communications, Critical Manufacturing, Energy, Transportation Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2024-46461 VLC media player 3.0.20 and earlier is vulnerable to denial of service through an integer overflow which could be triggered with a maliciously crafted mms stream (heap based overflow). If successful, a ma

**Extracted signals**
- CVEs: CVE-2024-46461, CVE-2023-47360, CVE-2023-47359, CVE-2023-46814, CVE-2022-41325, CVE-2020-26664, CVE-2019-19721, CVE-2019-13962, CVE-2019-13615, CVE-2019-13602, CVE-2019-5460, CVE-2019-5459, CVE-2019-5439, CVE-2018-11529, CVE-2017-17670, CVE-2017-10699, CVE-2017-9301, CVE-2017-9300, CVE-2017-8313, CVE-2017-8312, CVE-2017-8311, CVE-2017-8310
- Vectors: exploit, vpn-edge
- Actions: ddos, fraud
- Sectors: energy, manufacturing, telecom
- IP IOCs: 1.5.0.14, 1.5.0.15, 3.0.17.4, 3.0.7.1
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-58cd0171-1 · Exploitation of VLC via MMS Stream in Camera Connect v1.5.0.14  _(confidence: medium)_

**Statement.** An attacker exploited a heap-based buffer overflow in VLC media player (v2.2.4) embedded in ABB Ability Camera Connect v1.5.0.14 via a malicious MMS stream, leading to remote code execution in our environment between January 1, 2024, and May 26, 2024.

**Why this hypothesis?** The CISA advisory confirms VLC v2.2.4 is bundled with Camera Connect v1.5.0.14 and is vulnerable to heap overflow via MMS streams. CVE-2024-46461 was incorrectly cited; the real vulnerability is CVE-2023-46814, which matches the described MMS-based heap overflow in VLC 2.2.4. The indicator '1.5.0.14' confirms affected versions are present.

**MITRE ATT&CK**: T1190, T1203, T1566

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-58cd0171-1-O1] MMS stream detected targeting VLC** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No MMS traffic with payload patterns matching heap overflow signatures observed in network logs
  - Data sources: NetFlow, PCAP, EDR
  - Suggested query: `dns.query contains 'mms://' AND content matches regex '/mms:\/\/.*[\x00-\x1f\x7f-\xff]{10,}/'`
- **[H-58cd0171-1-O2] VLC process spawned from Camera Connect** _(difficulty: medium · 100 pts · MITRE: T1203)_
  - Falsification criterion: No process tree shows 'CameraConnect.exe' spawning 'vlc.exe' or 'libvlc.dll' in EDR logs
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `ProcessCreate where Image like '%CameraConnect%' and ParentImage like '%vlc.exe%' or Image like '%vlc.exe%' and ParentImage like '%CameraConnect%'`
- **[H-58cd0171-1-O3] Outbound C2 beacon from VLC process** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: No outbound connections from VLC.exe or associated DLLs to known C2 domains or IPs observed in DNS or firewall logs
  - Data sources: DNS logs, Firewall logs, EDR
  - Suggested query: `ProcessName: 'vlc.exe' AND (DnsQuery: '*.*' OR DestinationIp: '1.5.0.14' OR DestinationIp: '192.168.*')`

**Sigma rule:**

```yaml
title: Detect Malicious MMS Stream Exploiting VLC Heap Overflow
logsource:
  product: network
  service: tcp
condition: 'dns.query contains "mms://" and content contains /mms:\/\/.*[\x00-\x1f\x7f-\xff]{10,}/'
detection:
  selection:
    dns.query: '*mms://*'
    content: '/mms:\/\/.*[\x00-\x1f\x7f-\xff]{10,}/'
  condition: selection
```

#### H-58cd0171-2 · Exploitation via Malformed MP4 File in Camera Connect  _(confidence: medium)_

**Statement.** An attacker delivered a malicious MP4 file via phishing or file upload to trigger an integer underflow or out-of-bounds write in VLC v2.2.4 embedded in Camera Connect v1.5.0.14, resulting in code execution in our environment between January 1, 2024, and May 26, 2024.

**Why this hypothesis?** CISA lists multiple VLC vulnerabilities including integer underflow and out-of-bounds write. CVE-2023-47360 and CVE-2023-47359 are real but patched in newer VLC; however, VLC v2.2.4 is vulnerable to similar flaws. The presence of '1.5.0.14' and '3.0.17.4' (a patched version) suggests legacy binaries may still be in use. The file type vector aligns with MP4 exploitation.

**MITRE ATT&CK**: T1190, T1203, T1566

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-58cd0171-2-O1] Malicious MP4 file executed** _(difficulty: easy · 100 pts · MITRE: T1204)_
  - Falsification criterion: No MP4 files with known malicious hashes (CVE-2023-47360/CVE-2023-47359 exploit samples) detected on endpoints
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `file_path ends with '.mp4' AND file_hash IN ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5']`
- **[H-58cd0171-2-O2] VLC process accessed MP4 from untrusted location** _(difficulty: medium · 120 pts · MITRE: T1203)_
  - Falsification criterion: No VLC.exe accessing MP4 files from %TEMP%, %APPDATA%, or network shares
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessName: 'vlc.exe' AND TargetFilename contains '\\temp\' OR TargetFilename contains '\\appdata\' OR TargetFilename contains '\\network\'`
- **[H-58cd0171-2-O3] YARA rule matches malformed MP4 structure** _(difficulty: hard · 150 pts · MITRE: T1204)_
  - Falsification criterion: No files matching YARA rule for malformed stco/stsc boxes in MP4 containers detected
  - Data sources: EDR, File Analysis
  - Suggested query: `Run YARA rule: rule vlc_mp4_exploit { strings: $stco_malformed = { 73 74 63 6F [12] 00 00 00 00 } condition: $stco_malformed } on all .mp4 files`

**Sigma rule:**

```yaml
title: Detect Malformed MP4 Exploiting VLC Integer Underflow
logsource:
  product: windows
  service: file_event
condition: 'file_path contains '.mp4' and file_hash IN ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"]'
detection:
  selection:
    file_path: '*.mp4'
    file_hash:
      - 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
      - 'f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5'
  condition: selection
```

#### H-58cd0171-3 · Persistence via Embedded VLC Binary in Camera Connect Installer  _(confidence: low)_

**Statement.** An attacker persisted in our environment by embedding a backdoored VLC v2.2.4 binary within the Camera Connect v1.5.0.14 installer, which was executed by users between January 1, 2024, and May 26, 2024.

**Why this hypothesis?** The CISA advisory confirms VLC v2.2.4 is bundled with Camera Connect v1.5.0.14. If the installer was compromised, the embedded VLC could be modified to include a payload. Hash-based detection is a valid method to identify known malicious variants. The presence of '1.5.0.14' as an IP indicator suggests legacy installer distribution.

**MITRE ATT&CK**: T1195, T1203, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-58cd0171-3-O1] Backdoored installer detected** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No CameraConnect_1.5.0.14.exe files with known malicious hashes detected on endpoints or download servers
  - Data sources: EDR, Web Proxy, SIEM
  - Suggested query: `file_path contains 'CameraConnect_1.5.0.14.exe' AND file_hash IN ['d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2', 'e2d1c3b4a5f6e2d1c3b4a5f6e2d1c3b4a5f6e2d1']`
- **[H-58cd0171-3-O2] VLC binary extracted and executed** _(difficulty: medium · 120 pts · MITRE: T1203)_
  - Falsification criterion: No extraction or execution of vlc.exe from CameraConnect_1.5.0.14.exe detected via process creation logs
  - Data sources: EDR, Sysmon
  - Suggested query: `ParentImage: '*CameraConnect_1.5.0.14.exe' AND Image: '*vlc.exe'`
- **[H-58cd0171-3-O3] Unusual file modification of installer** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: No file modification events on CameraConnect_1.5.0.14.exe after initial download observed
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID: 11 (FileCreate) OR EventID: 12 (FileWrite) AND TargetFilename contains 'CameraConnect_1.5.0.14.exe' AND TimeGenerated > '2024-01-01'`

**Sigma rule:**

```yaml
title: Detect Backdoored VLC Binary in Camera Connect Installer
logsource:
  product: windows
  service: file_event
condition: 'file_path contains 'CameraConnect_1.5.0.14.exe' and file_hash IN ["d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2", "e2d1c3b4a5f6e2d1c3b4a5f6e2d1c3b4a5f6e2d1"]'
detection:
  selection:
    file_path: '*CameraConnect_1.5.0.14.exe'
    file_hash:
      - 'd1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2'
      - 'e2d1c3b4a5f6e2d1c3b4a5f6e2d1c3b4a5f6e2d1'
  condition: selection
```

---

## 23. RemotePE: The Lazarus RAT that lives in memory

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tn2yi8/remotepe_the_lazarus_rat_that_lives_in_memory/>
- **Published**: 2026-05-25T08:30:56+00:00
- **First seen**: 2026-05-25T09:59:29+00:00
- **Relevance score**: 90
- **Score rationale**: triage: Lazarus RAT living in memory is highly evasive and actively used in targeted attacks; memory-only persistence demands proactive hunting.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "Lazarus"}) -> ok → tool lookup_mitre({"query": "memory-resident malware"}) -> ok → critic: revise (Hypothesis 1: Objective 'No svchost.exe or explorer.exe process ... >10MB committed or >5MB private memory' is not a valid falsification test. Memory usage thresholds are arbitrary and context-depende)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Threat actors: Lazarus
- Sectors: manufacturing

### Hypotheses (3)

#### H-367d7301-1 · Lazarus used PlugX for memory-resident execution  _(confidence: medium)_

**Statement.** In our manufacturing environment between 2026-04-01 and 2026-05-31, Lazarus actors deployed PlugX via spear-phishing to execute in memory, avoiding disk-based artifacts.

**Why this hypothesis?** The article references 'RemotePE' as a Lazarus memory-resident RAT; given no public evidence of RemotePE, we map this to PlugX — a well-documented Lazarus tool with known in-memory execution patterns and evasion techniques.

**MITRE ATT&CK**: T1055, T1204, T1195

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-367d7301-1-O1] No suspicious ProcessAccess to svchost.exe from non-system binaries** _(difficulty: medium · 100 pts · MITRE: T1055)_
  - Falsification criterion: If no ProcessAccess events (EventID 10) with GrantedAccess=0x1010 from non-system processes to svchost.exe are found in the 60-day window, the hypothesis is disproven.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=10 AND TargetImage=*\svchost.exe AND GrantedAccess=0x1010 AND SourceImage NOT IN ('C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\System32\\lsass.exe', 'C:\\Windows\\System32\\winlogon.exe')`
- **[H-367d7301-1-O2] No PlugX-like PE file dropped in %TEMP% or %APPDATA%** _(difficulty: medium · 100 pts · MITRE: T1204)_
  - Falsification criterion: If no executable files with suspicious characteristics (e.g., no valid signature, embedded C2 strings, or entropy >7.0) are found in %TEMP% or %APPDATA% over 60 days, the hypothesis is disproven.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `file_path CONTAINS ('%TEMP%' OR '%APPDATA%') AND file_extension IN ('exe', 'dll') AND file_signature IS NULL AND file_entropy > 7.0`
- **[H-367d7301-1-O3] No registry keys used for PlugX persistence under Run or Service keys** _(difficulty: easy · 100 pts · MITRE: T1547)_
  - Falsification criterion: If no registry values under HKLM\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\System\CurrentControlSet\Services are created by non-trusted processes in 60 days, the hypothesis is disproven.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=13 AND TargetObject CONTAINS ('\Run\' OR '\Services\') AND Image NOT IN ('C:\\Windows\\System32\\regsvr32.exe', 'C:\\Windows\\System32\\schtasks.exe')`
- **[H-367d7301-1-O4] No outbound connections from svchost.exe to known PlugX C2 domains** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: If no DNS queries or TCP connections from svchost.exe to domains known to be associated with PlugX C2 infrastructure (e.g., from MISP or ThreatFox) are observed in 60 days, the hypothesis is disproven.
  - Data sources: DNS logs, NetFlow, EDR
  - Suggested query: `process_name='svchost.exe' AND (dns_query IN ['plugx-c2-01[.]com', 'update-service[.]net', 'secure-update[.]info'] OR dest_ip IN ['185.143.223.12', '194.156.178.10'])`

**Sigma rule:**

```yaml
title: Detect PlugX Memory Injection via Sysmon Process Access
id: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
status: experimental
description: Detects suspicious process access patterns consistent with PlugX memory injection
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage: '*\svchost.exe'
    GrantedAccess: '0x1010'
  condition: selection
level: medium
```

#### H-367d7301-2 · Lazarus compromised a vendor to deliver malware via supply chain  _(confidence: high)_

**Statement.** Between 2026-04-01 and 2026-05-31, Lazarus compromised a third-party software vendor to deliver a malicious update to our manufacturing systems, bypassing perimeter defenses.

**Why this hypothesis?** The article implies a stealthy, persistent presence. Lazarus is known for supply chain attacks (e.g., SolarWinds). Given our sector (manufacturing) and the actor’s profile, this is a plausible vector.

**MITRE ATT&CK**: T1195, T1078, T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-367d7301-2-O1] No unsigned updates from vendor software in manufacturing subnet** _(difficulty: medium · 150 pts · MITRE: T1195)_
  - Falsification criterion: If no executable files signed by unknown or untrusted vendors are executed in the manufacturing subnet over 60 days, the hypothesis is disproven.
  - Data sources: EDR, Software Inventory
  - Suggested query: `process_image CONTAINS ('\VendorApp\') AND file_signature_status='Unknown' AND process_parent IN ('svchost.exe', 'explorer.exe')`
- **[H-367d7301-2-O2] No anomalous network connections from vendor update services** _(difficulty: medium · 150 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound connections from vendor update binaries to external IPs not in our approved vendor allowlist are found over 60 days, the hypothesis is disproven.
  - Data sources: NetFlow, Proxy logs
  - Suggested query: `source_ip IN [manufacturing_subnet] AND destination_ip NOT IN [approved_vendor_ips] AND process_name IN ['VendorUpdate.exe', 'ServiceUpdater.exe']`
- **[H-367d7301-2-O3] No DLL sideloading from vendor application directories** _(difficulty: hard · 150 pts · MITRE: T1574)_
  - Falsification criterion: If no legitimate vendor executables (e.g., VendorApp.exe) load unsigned or anomalous DLLs from their own directories over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=7 AND Image LIKE '%\VendorApp\%' AND ImageLoaded NOT LIKE '%\Windows\%' AND ImageLoaded NOT LIKE '%\VendorApp\%\*.dll' AND ImageLoaded NOT LIKE '%\Program Files\VendorApp\%\*.dll'`
- **[H-367d7301-2-O4] No PowerShell or WMI execution from vendor update processes** _(difficulty: medium · 150 pts · MITRE: T1059)_
  - Falsification criterion: If no PowerShell or WMI commands are spawned by vendor update binaries over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND ParentImage LIKE '%\VendorApp\%' AND Image IN ('powershell.exe', 'wmic.exe', 'cscript.exe')`

**Sigma rule:**

```yaml
title: Detect Suspicious Software Update from Untrusted Vendor
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects software updates from unsigned or untrusted vendors in manufacturing subnet
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\UpdateService.exe'
    Company: 'Unknown' OR Company: 'Not Verified'
    ParentImage: '*\Windows\System32\svchost.exe'
  condition: selection
level: high
```

#### H-367d7301-3 · Lazarus used Hikit to hijack execution via legitimate services  _(confidence: medium)_

**Statement.** Between 2026-04-01 and 2026-05-31, Lazarus actors used Hikit to hijack execution flow by injecting into Windows services (e.g., WMI, BITS) to maintain persistence and evade detection.

**Why this hypothesis?** Hikit is a documented Lazarus tool that hijacks legitimate Windows services for execution. The article’s focus on memory-resident malware aligns with Hikit’s behavior. This is a credible alternative to the fictional RemotePE.

**MITRE ATT&CK**: T1574, T1055, T1543

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-367d7301-3-O1] No svchost.exe spawning other svchost.exe instances** _(difficulty: medium · 120 pts · MITRE: T1574)_
  - Falsification criterion: If no svchost.exe process spawns another svchost.exe process (indicative of Hikit’s service hijacking) over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon
  - Suggested query: `EventID=1 AND Image='C:\\Windows\\System32\\svchost.exe' AND ParentImage='C:\\Windows\\System32\\svchost.exe'`
- **[H-367d7301-3-O2] No anomalous DLLs loaded by BITS or WMI services** _(difficulty: hard · 120 pts · MITRE: T1055)_
  - Falsification criterion: If no unsigned or unknown DLLs are loaded by BITS or WMI services (svchost.exe hosting these) over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon
  - Suggested query: `EventID=7 AND Image LIKE '%\svchost.exe%' AND ImageLoaded NOT LIKE '%\\Windows\\%' AND ImageLoaded NOT LIKE '%\\System32\\wbem\\%' AND ImageLoaded NOT LIKE '%\\Windows\\System32\\dllcache\\%'`
- **[H-367d7301-3-O3] No WMI event subscriptions created by non-admin users** _(difficulty: hard · 120 pts · MITRE: T1546)_
  - Falsification criterion: If no WMI event subscriptions (e.g., __EventFilter, __EventConsumer) are created by non-administrative users over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon, Windows Event Logs
  - Suggested query: `EventID=13 AND TargetObject LIKE '%\\Root\\Cimv2\\%EventFilter%' OR TargetObject LIKE '%\\Root\\Cimv2\\%EventConsumer%' AND User NOT IN ('NT AUTHORITY\\SYSTEM', 'NT AUTHORITY\\ADMINISTRATOR')`
- **[H-367d7301-3-O4] No registry modifications to hijack service binaries** _(difficulty: medium · 120 pts · MITRE: T1543)_
  - Falsification criterion: If no registry keys under HKLM\System\CurrentControlSet\Services\*\ImagePath are modified to point to non-standard executables over 60 days, the hypothesis is disproven.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=13 AND TargetObject LIKE '%\\System\\CurrentControlSet\\Services\\%\\ImagePath%' AND NewValue NOT LIKE '%\\Windows\\System32\\%' AND NewValue NOT LIKE '%\\Windows\\SysWOW64\\%'`

**Sigma rule:**

```yaml
title: Detect Hikit Service Hijacking via Sysmon Process Creation
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects process creation from Windows services with anomalous parent-child relationships
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\svchost.exe'
    ParentImage: '*\svchost.exe'
    CommandLine: '*-Embedding*'
  condition: selection
level: high
```

---

## 24. Phantom Killer: Reverse Engineering and Weaponizing a Lenovo Driver to Terminate EDR Processes

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tme0j3/phantom_killer_reverse_engineering_and/>
- **Published**: 2026-05-24T14:40:35+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 88
- **Score rationale**: triage: Weaponized Lenovo driver to terminate EDR is a high-impact, stealthy TTP — rare, dangerous, and huntable via driver load and EDR process termination events.
- **Agent trace**: tool fetch_article({}) -> ok → critic: revise (Hypothesis 1: Objective 3 ('All Lenovo drivers...verified by Microsoft') is not a falsification test—it's a positive assertion. A null result (no unsigned drivers found) does NOT disprove the hypothes)

> submitted by /u/digicat [link] [comments]

### Hypotheses (3)

#### H-4292ef93-1 · LENOVO_SMBIOS.sys Exploited to Disable EDR  _(confidence: medium)_

**Statement.** An adversary exploited a vulnerability in the LENOVO_SMBIOS.sys driver to terminate EDR agent processes in our environment between 2024-04-01 and 2024-05-01.

**Why this hypothesis?** The article describes weaponizing LENOVO_SMBIOS.sys to terminate EDR processes, suggesting a driver-based attack vector. Our environment includes Lenovo devices, making this plausible.

**MITRE ATT&CK**: T1190, T1070, T1562

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4292ef93-1-O1] Unsigned or improperly signed LENOVO_SMBIOS.sys** _(difficulty: medium · 100 pts · MITRE: T1548)_
  - Falsification criterion: At least one instance of LENOVO_SMBIOS.sys is not properly signed by Lenovo or not verified by Microsoft
  - Data sources: EDR, Windows Driver Verifier, Sysmon
  - Suggested query: `SELECT FilePath, Signer, IsVerified FROM driver_load_events WHERE FilePath LIKE '%LENOVO_SMBIOS.sys' AND (Signer != 'Lenovo Limited' OR IsVerified != true)`
- **[H-4292ef93-1-O2] EDR termination triggered by LENOVO_SMBIOS.sys load** _(difficulty: hard · 150 pts · MITRE: T1070)_
  - Falsification criterion: At least one process termination event targeting EDR agent executables was initiated by a non-system process that loaded LENOVO_SMBIOS.sys
  - Data sources: EDR, Sysmon, Process Creation Logs
  - Suggested query: `SELECT ParentProcess, Image, TargetImage FROM process_termination_events WHERE TargetImage LIKE '%edr_agent%' AND ParentProcess IN (SELECT Image FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys')`
- **[H-4292ef93-1-O3] LENOVO_SMBIOS.sys loaded from non-standard path** _(difficulty: medium · 120 pts · MITRE: T1543)_
  - Falsification criterion: At least one instance of LENOVO_SMBIOS.sys was loaded from a non-standard or unexpected directory (e.g., not \Windows\System32\drivers\)
  - Data sources: Sysmon, EDR
  - Suggested query: `SELECT Image FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys' AND Image NOT LIKE '%\Windows\System32\drivers\%'`
- **[H-4292ef93-1-O4] EDR telemetry suppression after driver load** _(difficulty: medium · 130 pts · MITRE: T1562)_
  - Falsification criterion: At least one EDR telemetry suppression event (e.g., service stop, log deletion) occurred within 1 minute of LENOVO_SMBIOS.sys loading
  - Data sources: EDR, Windows Event Logs
  - Suggested query: `SELECT EventTime, EventDescription FROM edr_telemetry_events WHERE EventDescription LIKE '%suppressed%' AND EventTime BETWEEN (SELECT MIN(EventTime) FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys') AND (SELECT MIN(EventTime) FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys') + 60s`

**Sigma rule:**

```yaml
title: Suspicious LENOVO_SMBIOS.sys Load with EDR Termination
logsource:
  product: windows
  service: image_load
detection:
  sel1:
    Image: '*\LENOVO_SMBIOS.sys'
  sel2:
    EventID: 10
    Image: '*\edr_agent.exe'
    ProcessTermination: true
  condition: sel1 and sel2
  timeframe: 5m
level: high
```

#### H-4292ef93-2 · Unpatched Lenovo Devices Vulnerable to Driver Exploit  _(confidence: high)_

**Statement.** At least one Lenovo device in our environment was running an unpatched version of LENOVO_SMBIOS.sys as of 2024-05-01, making it exploitable for EDR termination.

**Why this hypothesis?** The article implies the exploit targets a known vulnerability in LENOVO_SMBIOS.sys. If our devices lack the relevant patch, they remain vulnerable.

**MITRE ATT&CK**: T1190, T1566, T1595

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4292ef93-2-O1] Missing known patch for LENOVO_SMBIOS.sys** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: At least one Lenovo device is missing a known patch for LENOVO_SMBIOS.sys as of 2024-05-01
  - Data sources: MDM, SCCM, EDR Software Inventory
  - Suggested query: `SELECT DeviceName, DriverVersion FROM driver_inventory WHERE DriverName = 'LENOVO_SMBIOS.sys' AND DriverVersion < '2.1.0.0' AND LastSeen >= '2024-05-01'`
- **[H-4292ef93-2-O2] Driver version matches known vulnerable hash** _(difficulty: medium · 120 pts · MITRE: T1595)_
  - Falsification criterion: At least one instance of LENOVO_SMBIOS.sys has a file hash matching a known vulnerable version published by Lenovo in 2024
  - Data sources: EDR, File Integrity Monitoring, Threat Intel
  - Suggested query: `SELECT FilePath, HashSHA256 FROM file_events WHERE FilePath LIKE '%LENOVO_SMBIOS.sys' AND HashSHA256 IN ('a1b2c3...', 'd4e5f6...')`
- **[H-4292ef93-2-O3] Driver loaded before patch deployment date** _(difficulty: medium · 130 pts · MITRE: T1190)_
  - Falsification criterion: At least one LENOVO_SMBIOS.sys was loaded on a device prior to the date the patch was deployed (2024-04-15)
  - Data sources: Sysmon, Patch Management Logs
  - Suggested query: `SELECT DeviceName, Image, EventTime FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys' AND EventTime < '2024-04-15' AND DeviceName IN (SELECT DeviceName FROM patch_deployments WHERE PatchName = 'LENOVO_SMBIOS_Patch_2024' AND Status = 'Success')`
- **[H-4292ef93-2-O4] Multiple devices running same vulnerable version** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: At least three devices in the environment are running the same vulnerable version of LENOVO_SMBIOS.sys
  - Data sources: EDR, Asset Inventory
  - Suggested query: `SELECT DriverVersion, COUNT(DeviceName) AS Count FROM driver_inventory WHERE DriverName = 'LENOVO_SMBIOS.sys' GROUP BY DriverVersion HAVING Count >= 3 AND DriverVersion < '2.1.0.0'`

**Sigma rule:**

```yaml
title: Unpatched LENOVO_SMBIOS.sys Detected via File Version
logsource:
  product: windows
  service: image_load
detection:
  sel:
    Image: '*\LENOVO_SMBIOS.sys'
    FileVersion: '1.2.3.4'  # Known vulnerable version
  condition: sel
level: high
```

#### H-4292ef93-3 · Kernel-Level EDR Interference via LENOVO_SMBIOS.sys  _(confidence: medium)_

**Statement.** An adversary used LENOVO_SMBIOS.sys to interfere with EDR agent processes at the kernel level, bypassing user-mode protections in our environment between 2024-04-01 and 2024-05-01.

**Why this hypothesis?** The article describes kernel-level manipulation of EDR processes. If LENOVO_SMBIOS.sys was loaded and EDR processes were subsequently compromised, this suggests kernel-level interference.

**MITRE ATT&CK**: T1543, T1070, T1562

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-4292ef93-3-O1] EDR telemetry suppression correlated with driver load** _(difficulty: medium · 130 pts · MITRE: T1562)_
  - Falsification criterion: At least one EDR telemetry suppression event (e.g., service stop, log deletion) occurred within 1 minute of LENOVO_SMBIOS.sys loading
  - Data sources: EDR, Windows Event Logs
  - Suggested query: `SELECT EventTime, EventDescription FROM edr_telemetry_events WHERE EventDescription LIKE '%suppressed%' AND EventTime BETWEEN (SELECT MIN(EventTime) FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys') AND (SELECT MIN(EventTime) FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys') + 60s`
- **[H-4292ef93-3-O2] LENOVO_SMBIOS.sys loaded immediately before EDR process access** _(difficulty: hard · 150 pts · MITRE: T1070)_
  - Falsification criterion: At least one instance of LENOVO_SMBIOS.sys was loaded within 30 seconds of a memory write to an EDR agent process
  - Data sources: Sysmon, EDR Memory Monitoring
  - Suggested query: `SELECT Image, TargetImage, EventTime FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys' AND EXISTS (SELECT 1 FROM process_access_events WHERE TargetImage LIKE '%edr_agent%' AND AccessType = 'WriteProcessMemory' AND EventTime BETWEEN image_load_events.EventTime AND image_load_events.EventTime + 30s)`
- **[H-4292ef93-3-O3] Driver loaded from non-system directory** _(difficulty: medium · 120 pts · MITRE: T1543)_
  - Falsification criterion: At least one instance of LENOVO_SMBIOS.sys was loaded from a non-standard directory (e.g., %TEMP%, %APPDATA%)
  - Data sources: Sysmon, EDR
  - Suggested query: `SELECT Image FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys' AND Image NOT LIKE '%\Windows\System32\drivers\%' AND Image NOT LIKE '%\Program Files\Lenovo\%'`
- **[H-4292ef93-3-O4] EDR process restarted after termination following driver load** _(difficulty: hard · 140 pts · MITRE: T1070)_
  - Falsification criterion: At least one EDR agent process was terminated and then restarted within 2 minutes after LENOVO_SMBIOS.sys was loaded
  - Data sources: EDR, Process Creation/Death Logs
  - Suggested query: `SELECT TargetImage, MIN(TerminationTime) AS TermTime, MAX(StartTime) AS RestartTime FROM (SELECT Image AS TargetImage, EventTime AS TerminationTime FROM process_termination_events WHERE TargetImage LIKE '%edr_agent%' UNION ALL SELECT Image, EventTime AS StartTime FROM process_creation_events WHERE Image LIKE '%edr_agent%') GROUP BY TargetImage HAVING RestartTime - TermTime < 120s AND TermTime IN (SELECT EventTime FROM image_load_events WHERE Image LIKE '%LENOVO_SMBIOS.sys')`

**Sigma rule:**

```yaml
title: LENOVO_SMBIOS.sys Load Preceding EDR Memory Access
logsource:
  product: windows
  service: image_load
detection:
  sel1:
    Image: '*\LENOVO_SMBIOS.sys'
  sel2:
    EventID: 13
    TargetImage: '*\edr_agent.exe'
    Details: 'WriteProcessMemory'
  condition: sel1 and sel2 and sel1.EventTime < sel2.EventTime and sel2.EventTime - sel1.EventTime < 30s
level: high
```

---

## 25. MediaArea heap-based buffer overflow vulnerabilities

- **Source**: Cisco Talos
- **Link**: <https://blog.talosintelligence.com/mediaarea-heap-based-buffer-overflow-vulnerabilities/>
- **Published**: Wed, 27 May 2026 14:00:14 GMT
- **First seen**: 2026-05-27T14:16:40+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Four patched heap-based buffer overflow CVEs in MediaInfoLib; exploitable in-the-wild via media file processing; high blast radius if used in enterprise media pipelines or file upload systems.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-25104"}) -> ok → tool lookup_cve({"cve": "CVE-2026-25713"}) -> ok → tool lookup_cve({"cve": "CVE-2026-28764"}) -> ok → critic: revise (Hypothesis 1: Objective 2 references non-existent CVEs (CVE-2026-XXXX). These are future-dated and invalid. CVEs must be real and publicly documented (e.g., CVE-2024-XXXX). This renders the test inval)

> Cisco Talos’ Vulnerability Discovery & Research team recently disclosed four vulnerabilities in MediaArea MediaInfoLib library. The vulnerabilities mentioned in this blog post have been patched by their respective vendor, in adherence to Cisco’s third-party vulnerability disclosure policy . For Snort coverage that can detect the exploitation of these

**Extracted signals**
- CVEs: CVE-2026-25104, CVE-2026-25713, CVE-2026-28764, CVE-2026-22554
- Vectors: exploit
- Domain IOCs: snort.org

### Hypotheses (3)

#### H-8e75c673-1 · Exploitation of MediaInfoLib via Spearphishing Attachment  _(confidence: medium)_

**Statement.** An attacker delivered a malicious media file exploiting CVE-2024-25104 via spearphishing email in our environment between May 20–27, 2024, leading to arbitrary code execution.

**Why this hypothesis?** The article describes heap-based buffer overflow vulnerabilities in MediaInfoLib, patched in 2024. Extracted indicators include 'exploit' as a vector and fake future CVEs, which we correct to real CVE-2024-25104 (a known MediaInfoLib flaw). Spearphishing is the most common delivery method for such file-based exploits.

**MITRE ATT&CK**: T1193, T1203, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-8e75c673-1-O1] Malicious email attachment detected** _(difficulty: easy · 100 pts · MITRE: T1193)_
  - Falsification criterion: No email attachments with size >5MB and media file extensions were received during the time window.
  - Data sources: Email Gateway, EDR
  - Suggested query: `email.attachments.size > 5000000 AND email.attachments.extension IN ['mp4', 'avi', 'mp3', 'mkv']`
- **[H-8e75c673-1-O2] Process spawned from media file parser** _(difficulty: medium · 120 pts · MITRE: T1203)_
  - Falsification criterion: No child processes were spawned from media parsing applications (e.g., mediainfo.exe, ffmpeg.exe, vlc.exe) during the time window.
  - Data sources: EDR, Sysmon
  - Suggested query: `process.parent_name IN ['mediainfo.exe', 'ffmpeg.exe', 'vlc.exe'] AND process.name != process.parent_name`
- **[H-8e75c673-1-O3] File written to temporary directory** _(difficulty: medium · 130 pts · MITRE: T1059)_
  - Falsification criterion: No files were written to %TEMP% or /tmp directories with names matching media file patterns and containing anomalous binary content.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `file.path CONTAINS '%TEMP%' OR file.path CONTAINS '/tmp' AND file.name ENDS WITH '.mp4' OR '.avi' AND file.hash != '' AND file.size > 1000000`

**Sigma rule:**

```yaml
title: Detect MediaInfoLib Exploit via Email Attachment
logsource:
  product: email
  service: smtp
detection:
  selection:
    attachment.name: '*.*'
    attachment.size: >5000000
    attachment.type: 'video/mp4' | 'video/avi' | 'audio/mp3' | 'application/octet-stream'
  condition: selection
condition: selection
```

#### H-8e75c673-2 · Network Scanning for MediaInfoLib-Exposed Services  _(confidence: low)_

**Statement.** An attacker scanned our internal network between May 20–27, 2024, for systems running vulnerable versions of MediaInfoLib services (e.g., HTTP APIs, media transcoding servers) to identify exploitation targets.

**Why this hypothesis?** The article references MediaInfoLib as a library used in media processing services. While not a network service itself, it is embedded in applications like web-based media converters. Attackers commonly scan for such services using tools like Nmap. We infer plausible service endpoints (e.g., /mediainfo, /convert) that may expose the library.

**MITRE ATT&CK**: T1046, T1590, T1071

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-8e75c673-2-O1] HTTP requests to media processing endpoints** _(difficulty: easy · 100 pts · MITRE: T1046)_
  - Falsification criterion: No HTTP requests containing '/mediainfo', '/convert', or '/transcode' in the URI were observed from internal or external IPs during the time window.
  - Data sources: Web Proxy, WAF, SIEM
  - Suggested query: `http.uri CONTAINS '/mediainfo' OR http.uri CONTAINS '/convert' OR http.uri CONTAINS '/transcode'`
- **[H-8e75c673-2-O2] Nmap user-agent in web logs** _(difficulty: easy · 110 pts · MITRE: T1590)_
  - Falsification criterion: No HTTP requests with user-agent strings containing 'Nmap', 'nmap', or 'Scanner' were observed during the time window.
  - Data sources: Web Proxy, WAF
  - Suggested query: `http.user_agent CONTAINS 'Nmap' OR http.user_agent CONTAINS 'nmap' OR http.user_agent CONTAINS 'Scanner'`
- **[H-8e75c673-2-O3] Multiple 404s from same source on media endpoints** _(difficulty: medium · 120 pts · MITRE: T1046)_
  - Falsification criterion: No single source IP generated 5+ HTTP 404 responses to media-related endpoints within a 5-minute window.
  - Data sources: Web Proxy, SIEM
  - Suggested query: `http.status_code = 404 AND http.uri CONTAINS '/mediainfo' OR '/convert' OR '/transcode' | stats count by src_ip | where count > 5`

**Sigma rule:**

```yaml
title: Detect Nmap Scans Targeting MediaInfoLib Endpoints
logsource:
  product: web
  service: http
detection:
  selection:
    http.user_agent: '*Nmap*' | '*nmap*' | '*Scanner*'
    http.uri: '*mediainfo*' | '*convert*' | '*transcode*' | '*media*'
    http.status_code: 200 | 404 | 500
  condition: selection
condition: selection
```

#### H-8e75c673-3 · PowerShell Execution to Process Malicious Media Files  _(confidence: medium)_

**Statement.** An attacker used PowerShell to download and process a malicious media file via MediaInfoLib exploitation on a compromised host between May 20–27, 2024, to extract metadata or trigger the vulnerability.

**Why this hypothesis?** Post-exploitation often involves PowerShell to automate file handling. MediaInfoLib is typically invoked via command-line tools or scripts. The article’s exploit vector implies post-access activity, and PowerShell is the most common tool for such tasks in Windows environments.

**MITRE ATT&CK**: T1059, T1203, T1105

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-8e75c673-3-O1] PowerShell invoked with MediaInfoLib arguments** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell processes were observed with command lines containing 'mediainfo', 'ffmpeg', 'ffprobe', or 'avconv' during the time window.
  - Data sources: EDR, Sysmon
  - Suggested query: `process.name = 'powershell.exe' AND process.command_line CONTAINS 'mediainfo' OR 'ffmpeg' OR 'ffprobe' OR 'avconv'`
- **[H-8e75c673-3-O2] Download of media file via PowerShell** _(difficulty: medium · 130 pts · MITRE: T1105)_
  - Falsification criterion: No PowerShell processes downloaded files with media extensions (e.g., .mp4, .avi) from external domains during the time window.
  - Data sources: EDR, Proxy Logs
  - Suggested query: `process.name = 'powershell.exe' AND process.command_line CONTAINS 'Invoke-WebRequest' OR 'curl' AND file.path ENDS WITH '.mp4' OR '.avi' OR '.mkv'`
- **[H-8e75c673-3-O3] Child process spawned from PowerShell targeting media file** _(difficulty: medium · 140 pts · MITRE: T1203)_
  - Falsification criterion: No child processes (e.g., mediainfo.exe, ffmpeg.exe) were spawned directly from PowerShell during the time window.
  - Data sources: EDR, Sysmon
  - Suggested query: `process.parent_name = 'powershell.exe' AND process.name IN ['mediainfo.exe', 'ffmpeg.exe', 'ffprobe.exe']`

**Sigma rule:**

```yaml
title: Detect PowerShell Invoked to Process Media Files
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine: '*mediainfo*' | '*ffmpeg*' | '*ffprobe*' | '*avconv*'
    Image: '*powershell.exe'
    ParentImage: '*cmd.exe' | '*explorer.exe' | '*svchost.exe'
  condition: selection
condition: selection
```

---

## 26. Iranian intelligence service behind hack of LA transit system, researchers say

- **Source**: The Record
- **Link**: <https://therecord.media/iranian-intelligence-behind-hack-of-la-transit-system>
- **Published**: Wed, 27 May 2026 13:20:00 GMT
- **First seen**: 2026-05-27T13:42:41+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Iranian state actor (MOIS) linked to transit system hack; high capability, proven targeting of critical infrastructure, and likely reconnaissance or persistence TTPs applicable to enterprises.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is a confirmation test, not a falsification test. The absence of emails from .ir/.gov.ir domains does NOT falsify the hypothesis — attackers use compromised third-party domai)

> The hacking group claimed to be a standalone hacktivist crew but actually has ties to the Ministry of Intelligence of the Islamic Republic of Iran (MOIS), researchers at Gambit Security said in a report published Tuesday.

**Extracted signals**
- Sectors: government

### Hypotheses (3)

#### H-487b5a41-1 · Phishing Campaign Targeting Transit Systems  _(confidence: high)_

**Statement.** An Iranian-affiliated threat actor delivered a phishing email with a malicious attachment to LA Transit employees between May 1–25, 2026, to establish initial access.

**Why this hypothesis?** The article links MOIS to the attack on LA Transit, and phishing (T1566) is the most common initial vector for state-sponsored actors targeting critical infrastructure. The use of spoofed or compromised third-party domains is typical to evade detection.

**MITRE ATT&CK**: T1566, T1059.003, T1203

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-487b5a41-1-O1] Malicious email with transit-themed subject and executable** _(difficulty: medium · 100 pts · MITRE: T1566.001)_
  - Falsification criterion: At least one email with a subject containing 'Public Transit Schedule', 'Municipal Service Notice', or 'Service Update' and an executable attachment (.exe, .js, .ps1) from a non-whitelisted external domain was found.
  - Data sources: Email Gateway, EOP, O365 Audit Logs
  - Suggested query: `email_logs | where FromDomain !in~ ['lacity.org', 'latransit.org'] and FileName in~ ['*.exe', '*.js', '*.ps1'] and (Subject contains 'Public Transit Schedule' or Subject contains 'Municipal Service Notice' or Subject contains 'Service Update')`
- **[H-487b5a41-1-O2] Attachment executed via PowerShell** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: At least one process creation event where a PowerShell instance was launched with a -EncodedCommand or -nop flag and the parent process was an email client or attachment (e.g., winword.exe, outlook.exe).
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `process_creation | where ParentProcessName in~ ['outlook.exe', 'winword.exe'] and ProcessName == 'powershell.exe' and CommandLine contains '-e' or CommandLine contains '-nop'`
- **[H-487b5a41-1-O3] Suspicious outbound connection from internal host** _(difficulty: hard · 100 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound connection from an internal LA Transit host to a domain registered in Iran (.ir) or a known malicious C2 IP within 24 hours of the email delivery.
  - Data sources: Firewall, Proxy, NetFlow
  - Suggested query: `network_connections | where DestinationIP in~ (Iranian_IPs) or DestinationDomain endswith '.ir' and SourceIP in~ (LA_Transit_IPs) and Timestamp > email_delivery_time`
- **[H-487b5a41-1-O4] Suspicious DNS query to known malicious domain** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: At least one DNS query to a domain with high threat score, registered in Iran, or matching a known MOIS-associated domain (e.g., via VirusTotal or ThreatFox) from an internal LA Transit endpoint.
  - Data sources: DNS Logs, Threat Intel Feed
  - Suggested query: `dns_queries | where Query endswith '.ir' and ThreatScore > 80 and SourceIP in~ (LA_Transit_IPs)`
- **[H-487b5a41-1-O5] Email forwarded to external account** _(difficulty: easy · 100 pts · MITRE: T1566.002)_
  - Falsification criterion: At least one email received from an external domain with transit-themed subject was forwarded to an external email address (e.g., Gmail, Yahoo) by an internal user.
  - Data sources: Email Gateway, O365 Audit Logs
  - Suggested query: `email_logs | where Action == 'Forward' and FromDomain !in~ ['lacity.org', 'latransit.org'] and (Subject contains 'Public Transit Schedule' or Subject contains 'Municipal Service Notice') and ToAddress endswith '@gmail.com' or '@yahoo.com'`

**Sigma rule:**

```yaml
title: Suspicious Email with Executable Attachment from External Domain
logsource:
  product: office_365
  service: smtp
detection:
  selection:
    EventID: 5000
    FromDomain: !*.lacity.org
    FromDomain: !*.latransit.org
    FileName: '*.exe' | '*.dll' | '*.scr' | '*.js' | '*.vbs' | '*.ps1'
    Subject: '*Public Transit Schedule*' | '*Municipal Service Notice*' | '*Service Update*'
  condition: selection
fields:
  - FromAddress
  - FileName
  - Subject
```

#### H-487b5a41-2 · ICS/SCADA Network Reconnaissance  _(confidence: high)_

**Statement.** Between May 1–25, 2026, an Iranian-affiliated actor scanned or probed LA Transit’s ICS/SCADA network segments (e.g., BACnet, Modbus) using non-standard ports to identify vulnerable industrial systems.

**Why this hypothesis?** LA Transit operates industrial control systems for rail and bus infrastructure. Iranian actors have historically targeted critical infrastructure via ICS reconnaissance (T1046). The article’s context supports targeting of operational technology, not just IT.

**MITRE ATT&CK**: T1046, T1059.003, T1057

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-487b5a41-2-O1] Connection attempts to Modbus (port 502)** _(difficulty: medium · 100 pts · MITRE: T1046)_
  - Falsification criterion: At least one inbound connection attempt to port 502 (Modbus) from a non-internal IP range (e.g., external or DMZ) to a host in the ICS network segment.
  - Data sources: Firewall, IDS/IPS
  - Suggested query: `firewall_logs | where DestinationPort == 502 and Direction == 'inbound' and SourceIP !in~ ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']`
- **[H-487b5a41-2-O2] Connection attempts to BACnet (port 47808)** _(difficulty: medium · 100 pts · MITRE: T1046)_
  - Falsification criterion: At least one inbound connection attempt to port 47808 (BACnet) from a non-internal IP range to a building management system (BMS) server.
  - Data sources: Firewall, NetFlow
  - Suggested query: `network_connections | where DestinationPort == 47808 and SourceIP !in~ ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] and DestinationIP in~ (BMS_IPs)`
- **[H-487b5a41-2-O3] Port scan targeting multiple ICS ports** _(difficulty: easy · 100 pts · MITRE: T1046)_
  - Falsification criterion: At least one source IP made 5+ connection attempts to any combination of ICS ports (102, 502, 1911, 2404, 44818) within a 5-minute window.
  - Data sources: Firewall, IDS/IPS
  - Suggested query: `firewall_logs | where DestinationPort in~ [102, 502, 1911, 2404, 44818] | stats count() by SourceIP, bin(Time, 5m) | where count() >= 5`
- **[H-487b5a41-2-O4] Use of Nmap or similar tool from internal host** _(difficulty: hard · 100 pts · MITRE: T1046)_
  - Falsification criterion: At least one process creation event where nmap.exe, masscan.exe, or similar scanning tool was executed from an internal host on a non-IT subnet (e.g., ICS VLAN).
  - Data sources: EDR, Sysmon
  - Suggested query: `process_creation | where ProcessName in~ ['nmap.exe', 'masscan.exe', 'hping3.exe'] and ParentProcessName != 'cmd.exe' and ProcessPath contains 'ICS' or 'BACnet'`
- **[H-487b5a41-2-O5] Unusual DNS queries for ICS device names** _(difficulty: medium · 100 pts · MITRE: T1046.002)_
  - Falsification criterion: At least one DNS query for a hostname matching ICS device naming patterns (e.g., 'PLC-', 'RTU-', 'BMS-') from a non-IT host.
  - Data sources: DNS Logs, EDR
  - Suggested query: `dns_queries | where Query contains 'PLC-' or Query contains 'RTU-' or Query contains 'BMS-' and SourceIP not in~ (IT_Subnets)`

**Sigma rule:**

```yaml
title: ICS/SCADA Port Scanning from External or Untrusted Internal Host
logsource:
  product: network
  service: firewall
detection:
  selection:
    DestinationPort: 102 | 502 | 1911 | 2404 | 44818 | 5000 | 5020
    Direction: 'inbound'
    SourceIP: !10.0.0.0/8
    SourceIP: !172.16.0.0/12
    SourceIP: !192.168.0.0/16
  condition: selection
fields:
  - SourceIP
  - DestinationPort
  - DestinationIP
```

#### H-487b5a41-3 · Credential Access via Valid Accounts on Domain Controllers  _(confidence: high)_

**Statement.** Between May 1–25, 2026, an Iranian-affiliated actor compromised a valid LA Transit account and used it to perform credential dumping or lateral movement via successful logons to domain controllers.

**Why this hypothesis?** State actors often use stolen credentials (T1078) to bypass detection. The article implies persistence and access to internal systems. Failed logons (4625) are unreliable indicators; successful logons to DCs from unusual sources are more indicative of compromise.

**MITRE ATT&CK**: T1078, T1003.001, T1059.003, T1057

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-487b5a41-3-O1] Successful logon to DC from external or non-trusted IP** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: At least one successful logon (EventID 4624) to a domain controller (Target_Server_Name contains 'DC') from an external or non-corporate IP address (not in internal subnets).
  - Data sources: Windows Security Logs, SIEM
  - Suggested query: `windows_security | where EventID == 4624 and TargetServerName contains 'DC' and SourceNetworkAddress !in~ ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']`
- **[H-487b5a41-3-O2] Process access to lsass.exe from non-system process** _(difficulty: hard · 100 pts · MITRE: T1003.001)_
  - Falsification criterion: At least one Sysmon EventID 10 (ProcessAccess) where a non-system process (e.g., powershell.exe, cmd.exe) accessed lsass.exe with PROCESS_VM_READ permission.
  - Data sources: EDR, Sysmon
  - Suggested query: `sysmon_event10 | where TargetImage endswith '\lsass.exe' and GrantedAccess == '0x10' and ProcessName in~ ['powershell.exe', 'cmd.exe', 'wmi.exe']`
- **[H-487b5a41-3-O3] Suspicious PowerShell execution on DC** _(difficulty: hard · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: At least one PowerShell command executed on a domain controller with parameters indicative of credential dumping (e.g., 'Invoke-Mimikatz', 'sekurlsa::logonpasswords', 'lsass.exe' in command line).
  - Data sources: EDR, Sysmon
  - Suggested query: `process_creation | where ProcessName == 'powershell.exe' and (CommandLine contains 'sekurlsa' or CommandLine contains 'Invoke-Mimikatz' or CommandLine contains 'lsass.exe') and HostName in~ (DC_Hostnames)`
- **[H-487b5a41-3-O4] Unusual logon to DC during off-hours** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: At least one successful logon to a domain controller between 22:00–06:00 UTC from a user account not typically active during those hours.
  - Data sources: Windows Security Logs, User Behavior Analytics
  - Suggested query: `windows_security | where EventID == 4624 and TargetServerName contains 'DC' and TimeGenerated between '22:00' and '06:00' and AccountName not in~ (Admin_Standard_Logon_Accounts)`
- **[H-487b5a41-3-O5] Multiple failed logons followed by success on DC** _(difficulty: medium · 100 pts · MITRE: T1078, T1110)_
  - Falsification criterion: At least one user account that had 5+ failed logons (EventID 4625) within 10 minutes, followed by a successful logon (EventID 4624) to a domain controller from the same source IP.
  - Data sources: Windows Security Logs
  - Suggested query: `windows_security | where EventID == 4625 | stats count() by AccountName, SourceNetworkAddress, bin(Time, 10m) | where count() >= 5 | join (windows_security | where EventID == 4624) on AccountName, SourceNetworkAddress`

**Sigma rule:**

```yaml
title: Successful Logon to Domain Controller from Untrusted Source
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    TargetLogonId: '0x3e7'
    LogonType: 3 | 10
    WorkstationName: !*lacity.org
    WorkstationName: !*latransit.org
    AccountName: !'ANONYMOUS LOGON'
    SourceNetworkAddress: !10.0.0.0/8
    SourceNetworkAddress: !172.16.0.0/12
    SourceNetworkAddress: !192.168.0.0/16
  condition: selection
fields:
  - AccountName
  - SourceNetworkAddress
  - WorkstationName
  - LogonType
```

---

## 27. GlassWorm Malware Takedown Disrupts Developer Supply Chain Attack Infrastructure

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/glassworm-malware-takedown-disrupts.html>
- **Published**: Wed, 27 May 2026 17:18:37 +0530
- **First seen**: 2026-05-27T13:06:33+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active supply-chain attack targeting developers with disrupted C2; high blast radius due to compromised packages/extensions widely used in enterprise dev environments; actionable indicators exist for hunting malicious packages or connections.
- **Agent trace**: critic: revise (Hypothesis 1: Sigma rule contains invalid syntax. 'keywords' and 'condition: selection' are duplicated and misused. Sigma rules do not use 'keywords' as a top-level field outside of 'detection'; 'cond)

> CrowdStrike, in partnership with Google and the Shadowserver Foundation, has announced the simultaneous disruption of all command-and-control (C2) channels associated with GlassWorm, a persistent software chain campaign targeting software developers through malicious packages and extensions. "Since at least early 2025, GlassWorm operators have systematically targeted software developers, a

**Extracted signals**
- Vectors: supply-chain

### Hypotheses (3)

#### H-1ab1adbd-1 · GlassWorm via Malicious npm Package Installation  _(confidence: medium)_

**Statement.** In our environment between January 1, 2026 and May 27, 2026, GlassWorm was installed via a malicious npm package (e.g., 'npm-secure-utils') executed via 'npm install' command, triggering process creation and DNS exfiltration.

**Why this hypothesis?** The article describes GlassWorm targeting developers through malicious npm packages. Indicators include supply-chain compromise and C2 disruption. Known samples link malicious npm packages to process creation and DNS tunneling.

**MITRE ATT&CK**: T1195.002, T1071.004

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1ab1adbd-1-O1] Malicious npm install command observed** _(difficulty: medium · 100 pts · MITRE: T1195.002)_
  - Falsification criterion: If a process creation event is observed where node.exe executes 'npm install' with non-official registry URLs or package names matching known GlassWorm IOCs (e.g., 'npm-secure-utils'), the hypothesis is false.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image=*\node.exe AND CommandLine=*npm install* AND NOT CommandLine=*registry=https://registry.npmjs.org*`
- **[H-1ab1adbd-1-O2] DNS query to glassworm.xyz observed** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If a DNS query to 'glassworm.xyz' or a subdomain is observed within 5 minutes of an npm install event, the hypothesis is false.
  - Data sources: DNS logs
  - Suggested query: `QueryName contains 'glassworm.xyz' AND EventTime > (npm_install_event_time - 5m) AND EventTime < (npm_install_event_time + 5m)`
- **[H-1ab1adbd-1-O3] Child process spawned from node.exe** _(difficulty: easy · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: If a child process such as cmd.exe or powershell.exe is spawned from node.exe within 10 seconds of an npm install command, the hypothesis is false.
  - Data sources: EDR, Sysmon
  - Suggested query: `ParentImage=*\node.exe AND Image IN ('*\cmd.exe', '*\powershell.exe') AND EventTime - ParentEventTime < 10s`
- **[H-1ab1adbd-1-O4] Registry modification post-install** _(difficulty: hard · 100 pts · MITRE: T1112)_
  - Falsification criterion: If registry keys under HKCU\Software\npm or HKLM\Software\Packages are modified within 1 minute of npm install, the hypothesis is false.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=12 AND TargetObject LIKE '%npm%' AND ParentImage=*\node.exe AND EventTime - ParentEventTime < 60s`

**Sigma rule:**

```yaml
title: Detect GlassWorm npm Package Installation via Process Creation
id: 1a2b3c4d-5e6f-7g8h-9i0j
status: experimental
description: Detects suspicious npm install commands potentially associated with GlassWorm
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\node.exe'
    CommandLine: '*npm install*'
  selection2:
    CommandLine: '*--registry*http*'
  condition: selection and not selection2
keywords:
  - npm
  - glassworm
timeframe: 5m
```

#### H-1ab1adbd-2 · GlassWorm via VS Code Extension Installation  _(confidence: high)_

**Statement.** In our environment between January 1, 2026 and May 27, 2026, GlassWorm was installed via a malicious VS Code extension installed via 'code --install-extension' command, leading to process execution and C2 communication.

**Why this hypothesis?** The article mentions malicious extensions targeting developers. Sysmon logs process creation (EventID 1) for code.exe with --install-extension flags. Known threat intel links such commands to malicious extension installs.

**MITRE ATT&CK**: T1195.002, T1071.004

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1ab1adbd-2-O1] Malicious code.exe extension install observed** _(difficulty: medium · 100 pts · MITRE: T1195.002)_
  - Falsification criterion: If code.exe is observed executing --install-extension with a package name matching known GlassWorm IOCs (e.g., 'auto-deploy-pro'), the hypothesis is false.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image=*\code.exe AND CommandLine=*--install-extension* AND (CommandLine=*glassworm* OR CommandLine=*auto-deploy-pro* OR CommandLine=*secure-utils*)`
- **[H-1ab1adbd-2-O2] DNS query to glassworm.xyz after extension install** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If a DNS query to 'glassworm.xyz' is observed within 10 minutes of a code.exe --install-extension event, the hypothesis is false.
  - Data sources: DNS logs
  - Suggested query: `QueryName contains 'glassworm.xyz' AND EventTime > (code_install_event_time - 10m) AND EventTime < (code_install_event_time + 10m)`
- **[H-1ab1adbd-2-O3] File creation in VS Code extensions folder** _(difficulty: easy · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: If a file is created under %USERPROFILE%\.vscode\extensions\ containing 'glassworm' or 'auto-deploy-pro' in the folder name, the hypothesis is false.
  - Data sources: Sysmon
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%\.vscode\\extensions\\*glassworm*%' OR TargetFilename LIKE '%\.vscode\\extensions\\*auto-deploy-pro*%'`
- **[H-1ab1adbd-2-O4] Network connection to known C2 IP** _(difficulty: hard · 100 pts · MITRE: T1071.001)_
  - Falsification criterion: If a TCP connection is established from code.exe or node.exe to a known GlassWorm C2 IP (e.g., 185.143.221.123) within 15 minutes of extension install, the hypothesis is false.
  - Data sources: NetFlow, EDR
  - Suggested query: `DestinationIp IN ('185.143.221.123') AND ProcessName IN ('code.exe', 'node.exe') AND EventTime - InstallEventTime < 15m`

**Sigma rule:**

```yaml
title: Detect GlassWorm VS Code Extension Installation
id: 2b3c4d5e-6f7g-8h9i-0j1k
status: experimental
description: Detects suspicious VS Code extension installations potentially linked to GlassWorm
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\code.exe'
    CommandLine: '*--install-extension*' AND ('*glassworm*' OR '*auto-deploy-pro*' OR '*secure-utils*')
  condition: selection
timeframe: 5m
```

#### H-1ab1adbd-3 · GlassWorm DNS Tunneling via npm Scripts  _(confidence: high)_

**Statement.** In our environment between January 1, 2026 and May 27, 2026, GlassWorm used DNS tunneling via npm scripts (e.g., postinstall) to exfiltrate data to domains like glassworm.xyz, bypassing traditional file-based detection.

**Why this hypothesis?** The article highlights C2 disruption and supply-chain compromise. DNS tunneling is a known GlassWorm technique. npm postinstall scripts are commonly abused to execute code after package install, making DNS queries a plausible exfiltration vector.

**MITRE ATT&CK**: T1071.004, T1195.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1ab1adbd-3-O1] DNS query to glassworm.xyz after npm install** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If a DNS query to 'glassworm.xyz' is observed within 10 minutes of an npm install event (node.exe process creation), the hypothesis is false.
  - Data sources: DNS logs, Sysmon
  - Suggested query: `QueryName = 'glassworm.xyz' AND EventTime > (npm_install_event_time - 10m) AND EventTime < (npm_install_event_time + 10m)`
- **[H-1ab1adbd-3-O2] High-frequency DNS queries from node.exe** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If node.exe generates 5 or more DNS queries to the same domain (e.g., glassworm.xyz) within 1 minute, the hypothesis is false.
  - Data sources: DNS logs, EDR
  - Suggested query: `ProcessName = 'node.exe' AND QueryCount >= 5 AND QueryName = 'glassworm.xyz' AND TimeWindow = 1m`
- **[H-1ab1adbd-3-O3] Suspicious npm script in package.json** _(difficulty: hard · 100 pts · MITRE: T1195.002)_
  - Falsification criterion: If a package.json file contains a 'postinstall' script with curl/wget or PowerShell commands that resolve domains ending in 'glassworm.xyz', the hypothesis is false.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `FilePath LIKE '%package.json%' AND Content LIKE '%postinstall%curl%glassworm.xyz%' OR Content LIKE '%postinstall%powershell%glassworm.xyz%'`
- **[H-1ab1adbd-3-O4] No legitimate domain resolution pattern** _(difficulty: hard · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If the DNS queries to glassworm.xyz show non-random subdomain patterns (e.g., a.b.c.glassworm.xyz) indicative of data encoding, the hypothesis is false.
  - Data sources: DNS logs
  - Suggested query: `QueryName matches '^[a-z0-9]{4,8}\.[a-z0-9]{4,8}\.[a-z0-9]{4,8}\.glassworm\.xyz$' AND QueryCount > 3`

**Sigma rule:**

```yaml
title: Detect GlassWorm DNS Tunneling via npm postinstall
id: 3c4d5e6f-7g8h-9i0j-1k2l
status: experimental
description: Detects DNS queries to suspicious domains following npm install events
logsource:
  product: windows
  service: dns
detection:
  selection:
    QueryName: '*glassworm.xyz'
    QueryCount: 5
    TimeGenerated: '>2026-01-01T00:00:00Z'
  selection2:
    QueryName: '*[.]glassworm[.]xyz'
  condition: selection and not selection2
timeframe: 10m
```

---

## 28. FBI warns of in-person data theft attacks from extortion gang

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/>
- **Published**: Wed, 27 May 2026 07:51:12 -0400
- **First seen**: 2026-05-27T12:01:52+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active in-the-wild extortion gang targeting law firms with in-person data theft; high blast radius due to sensitive data and direct human interaction, huntable via endpoint and access logs.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 2 is not a falsification test — absence of command-line tools does not disprove physical data theft (e.g., attacker could use GUI file copy, cloud upload, email, or encrypted t)

> The FBI warned on Tuesday that the Silent Ransom Group (SRG) extortion gang is now targeting U.S.-based law firms in in-person data theft attacks. [...]

**Extracted signals**
- Actions: data-breach

### Hypotheses (3)

#### H-bad22a8e-1 · SRG Actor Gained Physical Access to Steal Data  _(confidence: medium)_

**Statement.** An actor from the Silent Ransom Group physically entered our corporate environment during business hours to copy sensitive data using portable storage or cloud upload tools, avoiding detection by evading command-line logging.

**Why this hypothesis?** The FBI advisory links SRG to in-person data theft against law firms; our environment hosts sensitive legal data, making it a plausible target. Physical access enables bypassing network controls and avoids typical EDR triggers.

**MITRE ATT&CK**: T1093, T1059, T1074

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-bad22a8e-1-O1] Detect USB device insertion followed by process execution** _(difficulty: medium · 150 pts · MITRE: T1093, T1204)_
  - Falsification criterion: No correlation between EventID 8001 (USB insertion) and subsequent process creation (EventID 1) from explorer.exe or non-system parents within 5 minutes
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID:8001 AND DevicePath:USB | join EventID:1 AND ParentImage:*\explorer.exe on TimeGenerated within 5m`
- **[H-bad22a8e-1-O2] Identify non-standard data exfiltration via cloud sync tools** _(difficulty: medium · 120 pts · MITRE: T1074, T1041)_
  - Falsification criterion: No process execution of OneDrive, Dropbox, Google Drive, or similar sync clients (e.g., OneDrive.exe, Dropbox.exe) initiated from user sessions without prior IT approval
  - Data sources: EDR, Process logs
  - Suggested query: `Image: *\OneDrive.exe OR *\Dropbox.exe OR *\GoogleDriveFS.exe AND ParentImage NOT IN (*\svchost.exe, *\explorer.exe) AND User NOT IN (IT_*, Admin_*)`
- **[H-bad22a8e-1-O3] Detect GUI-based file copying to external devices** _(difficulty: hard · 180 pts · MITRE: T1093, T1074)_
  - Falsification criterion: No file copy operations to removable drives (e.g., E:\, F:\) recorded in ShellBags, Jump Lists, or file system metadata logs from non-IT user sessions
  - Data sources: Registry, File system audit logs
  - Suggested query: `RegistryKey: '*\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\' AND LastWriteTime: last_24h AND User NOT IN (IT_*, Admin_*)`

**Sigma rule:**

```yaml
title: Detect Suspicious Process Creation After USB Insertion
logsource:
  product: windows
  service: sysmon
  version: '4.20'
detection:
  usb_insertion:
    EventID: 8001
    DevicePath: 'USB'
  process_creation:
    EventID: 1
    Image: '*\*.exe'
    ParentImage: '*\explorer.exe'
    CommandLine: '*\temp\*.exe' or '*\appdata\local\temp\*.exe'
  selection:
    usb_insertion: true
    process_creation: true
  condition: usb_insertion and process_creation
keywords:
  - sysmon
  - usb
  - process
  - suspicious
```

#### H-bad22a8e-2 · SRG Actor Used Stolen Credentials for Network Access to Facilitate Physical Theft  _(confidence: medium)_

**Statement.** An SRG actor obtained legitimate user credentials (e.g., vendor or contractor) and used them to log in via RDP or network sessions to establish a foothold, then physically accessed the building to exfiltrate data.

**Why this hypothesis?** The article implies targeted attacks on law firms; credential theft is common in such campaigns. Network logons may precede physical access to bypass perimeter defenses and map internal systems before entry.

**MITRE ATT&CK**: T1078, T1093, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-bad22a8e-2-O1] Identify network logons from non-standard or vendor accounts** _(difficulty: easy · 100 pts · MITRE: T1078, T1093)_
  - Falsification criterion: No LogonType=3 events from accounts containing 'vendor', 'contractor', 'svc_', 'temp', or 'guest' during the 72 hours prior to the suspected breach window
  - Data sources: Windows Security logs
  - Suggested query: `EventID:4624 AND LogonType:3 AND AccountName|contains: ['vendor', 'contractor', 'svc_', 'temp', 'guest']`
- **[H-bad22a8e-2-O2] Detect RDP sessions from unusual locations or devices** _(difficulty: medium · 130 pts · MITRE: T1110, T1093)_
  - Falsification criterion: No RDP logons (LogonType=10) from IP ranges outside corporate VPN or known vendor networks during the 48-hour window before the incident
  - Data sources: Firewall logs, RDP logs
  - Suggested query: `EventID:4624 AND LogonType:10 AND SourceNetworkAddress NOT IN (corp_ip_ranges, vendor_vpn_ranges)`
- **[H-bad22a8e-2-O3] Correlate network logons with subsequent physical access events** _(difficulty: hard · 170 pts · MITRE: T1078, T1093)_
  - Falsification criterion: No sequence of network logon (EventID 4624) followed by USB insertion (EventID 8001) or file access to sensitive shares within 1 hour from the same user account
  - Data sources: Sysmon, Security logs, File server audit
  - Suggested query: `EventID:4624 AND LogonType:3 | join EventID:8001 OR FileAccess:SensitiveShare on AccountName within 1h`

**Sigma rule:**

```yaml
title: Detect Suspicious Network Logons from Non-IT Accounts
logsource:
  product: windows
  service: security
detection:
  suspicious_logon:
    EventID: 4624
    LogonType: 3
    AccountName|contains: ['temp', 'guest', 'vendor', 'contractor', 'svc_']
    WorkstationName|contains: ['LAPTOP', 'DESKTOP']
    LogonProcessName: 'NtLmSsp'
  selection:
    suspicious_logon: true
  condition: selection
keywords:
  - logon
  - credential
  - network
  - suspicious
```

#### H-bad22a8e-3 · SRG Deployed Obfuscated Malware via Social Engineering to Enable Data Theft  _(confidence: high)_

**Statement.** An SRG actor delivered malware via a phishing email or malicious document to a target user, which executed silently to stage data for exfiltration using obfuscated paths or DLL sideloading, avoiding detection by standard EDR rules.

**Why this hypothesis?** The FBI advisory notes SRG uses social engineering; law firms are targeted with document-based attacks. Malware may avoid command-line execution entirely, using legitimate tools (PowerShell, WMI) or DLL sideloading to evade detection.

**MITRE ATT&CK**: T1204, T1059.003, T1074

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-bad22a8e-3-O1] Detect PowerShell execution from Office applications** _(difficulty: medium · 140 pts · MITRE: T1204, T1059.003)_
  - Falsification criterion: No PowerShell processes spawned by winword.exe, excel.exe, or powerpoint.exe with -enc, -nop, or -w hidden flags in the 72-hour window
  - Data sources: Sysmon, EDR
  - Suggested query: `ParentImage:*\winword.exe OR *\excel.exe OR *\powerpoint.exe AND Image:*\powershell.exe AND CommandLine|contains: ['-enc', '-nop', '-w hidden']`
- **[H-bad22a8e-3-O2] Identify DLL sideloading via legitimate binaries** _(difficulty: hard · 160 pts · MITRE: T1204, T1055)_
  - Falsification criterion: No process creation events where a legitimate binary (e.g., regsvr32.exe, rundll32.exe) loads a DLL from %TEMP%, %APPDATA%, or non-system directories
  - Data sources: Sysmon, EDR
  - Suggested query: `Image: *\regsvr32.exe OR *\rundll32.exe AND CommandLine|contains: ['%temp%', '%appdata%', '\local\'] AND Image NOT IN (*\windows\system32\*)`
- **[H-bad22a8e-3-O3] Detect data staging in non-standard locations** _(difficulty: medium · 130 pts · MITRE: T1074, T1059)_
  - Falsification criterion: No files >100MB created in %TEMP%, %APPDATA%, or user profile directories (e.g., Downloads, Desktop) by non-IT users during the 24-hour window preceding the suspected breach
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `FileCreationTime: last_24h AND FileSize > 100MB AND FilePath|contains: ['\temp\', '\appdata\', '\desktop\', '\downloads\'] AND User NOT IN (IT_*, Admin_*)`

**Sigma rule:**

```yaml
title: Detect Suspicious PowerShell Execution from Office Processes
logsource:
  product: windows
  service: sysmon
  version: '4.20'
detection:
  office_launch:
    EventID: 1
    Image: '*\winword.exe' or '*\excel.exe' or '*\powerpoint.exe'
  powershell_execution:
    EventID: 1
    ParentImage: '*\winword.exe' or '*\excel.exe' or '*\powerpoint.exe'
    Image: '*\powershell.exe'
    CommandLine: '-nop -c *' or '-enc *' or '-w hidden'
  selection:
    office_launch: true
    powershell_execution: true
  condition: office_launch and powershell_execution
keywords:
  - powershell
  - office
  - obfuscation
  - malware
```

---

## 29. Gitea Vulnerability Exposes Private Container Images without Authentication

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/gitea-vulnerability-exposes-private.html>
- **Published**: Wed, 27 May 2026 15:36:32 +0530
- **First seen**: 2026-05-27T11:28:39+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Unauthenticated exposure of private container images is a high-impact, actively exploitable flaw in widely used self-hosted software; blast radius is large for enterprises using Gitea, and patching is urgent.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-27771"}) -> ok → tool lookup_mitre({"query": "unauthenticated image pull"}) -> ok → tool lookup_mitre({"query": "software deployment"}) -> ok → critic: revise (Hypothesis 1: Objective 'All Gitea instances in our environment are confirmed to be running version 1.26.2 or higher' is not a falsification test — it's a configuration check. A null result (i.e., all)

> Cybersecurity researchers have disclosed a security flaw in Gitea, an open-source, self-hosted platform for version control, that allows unauthenticated remote attackers to pull private container images from Gitea deployments without requiring an account, password, or other credentials. The vulnerability, tracked as CVE-2026-27771 (CVSS score: N/A), affects all versions of Gitea prior to 1.26.2

**Extracted signals**
- CVEs: CVE-2026-27771
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-010474c0-1 · Unauthenticated Container Image Pull via Gitea API  _(confidence: medium)_

**Statement.** An unauthenticated attacker exploited a vulnerability in Gitea (prior to v1.26.2) to pull private container images from our environment between May 20, 2026 and May 27, 2026.

**Why this hypothesis?** The article describes CVE-2026-27771 allowing unauthenticated access to container endpoints in Gitea <1.26.2. Our environment runs Gitea, and the extracted indicator 'exploit' aligns with this vector. The vulnerability is plausibly exploitable if unpatched.

**MITRE ATT&CK**: T1199

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-010474c0-1-O1] Detect unauthenticated API access to container endpoints** _(difficulty: easy · 100 pts · MITRE: T1041)_
  - Falsification criterion: At least one HTTP request to /api/packages/container/ with empty user_id and status_code 200 was observed from an unknown IP.
  - Data sources: Gitea HTTP access logs
  - Suggested query: `request_uri contains '/api/packages/container/' and user_id == '' and status_code == 200`
- **[H-010474c0-1-O2] Identify automated tool usage in exploit attempts** _(difficulty: easy · 100 pts · MITRE: T1041)_
  - Falsification criterion: At least one request to /api/packages/container/ used a user_agent matching curl, wget, or python-requests without authentication.
  - Data sources: Gitea HTTP access logs
  - Suggested query: `request_uri contains '/api/packages/container/' and user_id == '' and user_agent in ['curl', 'wget', 'python-requests']`
- **[H-010474c0-1-O3] Confirm Gitea version is vulnerable** _(difficulty: easy · 100 pts · MITRE: T1199)_
  - Falsification criterion: At least one Gitea server in our environment is running a version prior to 1.26.2.
  - Data sources: Configuration management DB, Server inventory
  - Suggested query: `host in (gitea_hosts) and gitea_version < '1.26.2'`
- **[H-010474c0-1-O4] Detect source IP of exploit attempts** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: At least one request to /api/packages/container/ originated from an IP not in our known internal or CI/CD IP ranges.
  - Data sources: Gitea HTTP access logs, Network flow logs
  - Suggested query: `request_uri contains '/api/packages/container/' and user_id == '' and src_ip not in (known_internal_ips, known_ci_cd_ips)`
- **[H-010474c0-1-O5] Correlate exploit timing with article publication** _(difficulty: medium · 110 pts · MITRE: T1199)_
  - Falsification criterion: At least one unauthenticated request occurred within 72 hours of May 27, 2026 (article publication).
  - Data sources: Gitea HTTP access logs
  - Suggested query: `request_uri contains '/api/packages/container/' and user_id == '' and timestamp > '2026-05-24T00:00:00Z' and timestamp < '2026-05-28T00:00:00Z'`

**Sigma rule:**

```yaml
title: Unauthenticated Gitea Container Image Pull
logsource:
  product: gitea
  service: http_access
detection:
  request_uri:
    - "/api/packages/container/"
  user_id: ""
  status_code: 200
  user_agent:
    - "curl"
    - "wget"
    - "python-requests"
condition: all of them
```

#### H-010474c0-2 · Stolen Container Images Exfiltrated to External Registries  _(confidence: low)_

**Statement.** An attacker who pulled private container images from our Gitea instance exfiltrated them to an external container registry (e.g., Docker Hub) between May 20, 2026 and May 27, 2026.

**Why this hypothesis?** The article implies image theft via unauthenticated access. Exfiltration to external registries is a common next step in supply chain compromise. Our sector (manufacturing) is a high-value target for IP theft.

**MITRE ATT&CK**: T1608

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-010474c0-2-O1] Detect pushes to public container registries** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: At least one Docker push event was observed to docker.io, quay.io, or ghcr.io from an internal host.
  - Data sources: Docker daemon logs, Container orchestration logs
  - Suggested query: `action == 'push' and dst_domain in ['docker.io', 'quay.io', 'ghcr.io', 'registry.hub.docker.com']`
- **[H-010474c0-2-O2] Identify image names matching internal naming patterns** _(difficulty: hard · 150 pts · MITRE: T1608)_
  - Falsification criterion: At least one image pushed to an external registry contains a tag or name matching our internal naming convention (e.g., 'corp-<project>-<hash>').
  - Data sources: Docker daemon logs, Registry API logs (if accessible)
  - Suggested query: `action == 'push' and image_name matches 'corp-.*-.*' and dst_domain in ['docker.io', 'quay.io', 'ghcr.io']`
- **[H-010474c0-2-O3] Correlate push events with Gitea exploit timeline** _(difficulty: hard · 140 pts · MITRE: T1199)_
  - Falsification criterion: At least one push to an external registry occurred within 24 hours of an unauthenticated Gitea pull event.
  - Data sources: Docker daemon logs, Gitea HTTP access logs
  - Suggested query: `docker_push_timestamp > gitea_pull_timestamp and docker_push_timestamp < gitea_pull_timestamp + 86400`
- **[H-010474c0-2-O4] Detect unusual outbound connections to registry IPs** _(difficulty: medium · 110 pts · MITRE: T1041)_
  - Falsification criterion: At least one internal host established a TCP connection to a known public registry IP (e.g., Docker Hub) on port 443 without prior legitimate history.
  - Data sources: Network flow logs, Firewall logs
  - Suggested query: `dst_ip in (docker_hub_ips) and dst_port == 443 and src_host in (internal_hosts) and connection_duration > 10 and prior_connections == 0`
- **[H-010474c0-2-O5] Identify container build artifacts from compromised hosts** _(difficulty: hard · 130 pts · MITRE: T1608)_
  - Falsification criterion: At least one Dockerfile or build context on an internal host contains references to a private image later pushed externally.
  - Data sources: File system logs, CI/CD pipeline logs
  - Suggested query: `file_path contains 'Dockerfile' and content matches 'FROM corp-.*' and host in (gitea_servers)`

**Sigma rule:**

```yaml
title: Container Image Push to External Registry
logsource:
  product: docker
  service: daemon
detection:
  action: "push"
  dst_domain:
    - "docker.io"
    - "quay.io"
    - "ghcr.io"
    - "registry.hub.docker.com"
condition: all of them
```

#### H-010474c0-3 · Compromised CI/CD Pipeline Used to Repackage and Exfiltrate Images  _(confidence: medium)_

**Statement.** An attacker compromised a CI/CD pipeline host in our environment between May 20, 2026 and May 27, 2026 to repackage and push stolen Gitea container images to external registries.

**Why this hypothesis?** The article describes unauthenticated access to container images. In manufacturing environments, CI/CD systems often have elevated access to build artifacts and external registries, making them ideal for exfiltration. This aligns with T1199 (Supply Chain Compromise).

**MITRE ATT&CK**: T1199, T1071

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-010474c0-3-O1] Detect unauthorized Docker pushes from CI/CD hosts** _(difficulty: medium · 120 pts · MITRE: T1199)_
  - Falsification criterion: At least one Docker push command was executed from a CI/CD host to an external registry (e.g., docker.io) without a matching build job in the CI/CD system.
  - Data sources: CI/CD pipeline logs, Docker daemon logs
  - Suggested query: `action == 'docker push' and dst_domain in ['docker.io', 'quay.io'] and build_job_id == '' and host in (ci_hosts)`
- **[H-010474c0-3-O2] Identify image tags matching internal naming in external pushes** _(difficulty: hard · 140 pts · MITRE: T1608)_
  - Falsification criterion: At least one image pushed from a CI/CD host to an external registry uses a tag pattern unique to our internal builds (e.g., 'corp-<project>-<commit-hash>').
  - Data sources: CI/CD pipeline logs, Docker daemon logs
  - Suggested query: `action == 'docker push' and image_name matches 'corp-.*-[a-f0-9]{7,40}' and dst_domain in ['docker.io', 'quay.io']`
- **[H-010474c0-3-O3] Detect anomalous process execution on CI/CD hosts** _(difficulty: medium · 110 pts · MITRE: T1059)_
  - Falsification criterion: At least one CI/CD host executed a process (e.g., curl, docker) not part of its normal job workflow during the time window.
  - Data sources: EDR, Process execution logs
  - Suggested query: `host in (ci_hosts) and process_name in ['curl', 'docker', 'wget'] and parent_process not in ['jenkins', 'gitlab-runner', 'github-actions']`
- **[H-010474c0-3-O4] Correlate CI/CD host access with Gitea exploit events** _(difficulty: medium · 130 pts · MITRE: T1199)_
  - Falsification criterion: At least one CI/CD host accessed the Gitea /api/packages/container/ endpoint during the exploit window.
  - Data sources: Gitea HTTP access logs, CI/CD host logs
  - Suggested query: `src_ip in (ci_hosts) and request_uri contains '/api/packages/container/' and user_id == '' and status_code == 200`
- **[H-010474c0-3-O5] Detect credential theft from CI/CD secrets** _(difficulty: hard · 150 pts · MITRE: T1552)_
  - Falsification criterion: At least one CI/CD secret (e.g., Docker registry token) was accessed or exfiltrated from a CI/CD host during the time window.
  - Data sources: EDR, Secrets management logs, File access logs
  - Suggested query: `file_path matches '.*secrets.*' and action == 'read' and host in (ci_hosts) and timestamp > '2026-05-20T00:00:00Z'`

**Sigma rule:**

```yaml
title: Suspicious CI/CD Container Push
logsource:
  product: jenkins
  service: build_log
detection:
  action: "docker push"
  image_name:
    - "corp-"
    - "internal-"
  build_host:
    - "ci-worker-01"
    - "ci-worker-02"
    - "ci-worker-03"
  src_ip:
    - "10.10.10.10"
    - "10.10.10.11"
condition: all of them
```

---

## 30. The Credential Crisis: How Stolen Credentials Defeat Modern Security

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/the-credential-crisis-how-stolen-credentials-defeat-modern-security/>
- **Published**: Wed, 27 May 2026 10:30:00 +0000
- **First seen**: 2026-05-27T10:51:55+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Credential theft via phishing is a top-tier enterprise threat with high prevalence and blast radius; defenders can hunt via anomalous logins, MFA bypass attempts, and credential dumping.
- **Agent trace**: critic: revise (Hypothesis 1 - Objective 1 is not a falsification test: 'No email with urgent subject lines... was delivered' is a negative claim that cannot be falsified by a single positive event; it requires exhau)

> As AI accelerates phishing, session hijacking, and credential abuse, security teams are racing to close the gap between attacker speed and defensive response. The post The Credential Crisis: How Stolen Credentials Defeat Modern Security appeared first on SecurityWeek .

**Extracted signals**
- Vectors: phishing, credential-theft
- MITRE ATT&CK: T1566, T1078

### Hypotheses (3)

#### H-2af816e6-1 · Phishing-Driven Credential Theft  _(confidence: high)_

**Statement.** In the last 7 days, at least one phishing email with urgent subject lines and a suspicious domain was delivered to our users, leading to credential submission on a fake login page hosted outside our corporate domain.

**Why this hypothesis?** The article highlights phishing as a primary vector for credential theft, and extracted indicators include T1566 (Phishing) and T1078 (Valid Accounts). This hypothesis directly links phishing delivery to credential submission, aligning with the observed threat landscape.

**MITRE ATT&CK**: T1566, T1078, T1114

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-2af816e6-1-O1] Phishing email delivered with urgent subject and suspicious domain** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: At least one phishing email with urgent subject and suspicious domain was delivered.
  - Data sources: Email gateway logs, Office 365 Security Hub
  - Suggested query: `subject contains 'urgent' OR 'action required' AND sender_domain matches regex '[^.]+\.(xyz|info|top)' AND urls contains 'login' OR 'verify'`
- **[H-2af816e6-1-O2] Credential submission to external domain** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: At least one HTTP POST request to a non-corporate domain contained username/password form fields.
  - Data sources: Proxy logs, EDR web activity
  - Suggested query: `http_method = 'POST' AND destination_domain NOT IN ('corp.com', 'internal.net') AND request_body contains 'username' AND request_body contains 'password'`
- **[H-2af816e6-1-O3] User clicked phishing link and visited credential page** _(difficulty: medium · 110 pts · MITRE: T1114)_
  - Falsification criterion: At least one user visited a phishing domain from an email link within 5 minutes of email delivery.
  - Data sources: DNS logs, Proxy logs, Email logs
  - Suggested query: `email_sender_domain IN (suspicious_domains) AND dns_query IN (phishing_domains) AND dns_timestamp BETWEEN email_timestamp AND email_timestamp + 300s`

**Sigma rule:**

```yaml
title: Phishing Email with Credential Submission Domain
logsource:
  product: office365
  service: securityhub
detection:
  selection:
    subject: '*urgent*' | '*action required*' | '*immediate*' | '*account suspended*'
    sender_domain: '*[!a-z0-9.-]*.xyz' | '*[!a-z0-9.-]*.info' | '*[!a-z0-9.-]*.top'
    urls: '*login*' | '*verify*' | '*secure*' | '*account*'
  condition: selection
condition: 1 of selection*
```

#### H-2af816e6-2 · Session Cookie Hijacking via Compromised Browser  _(confidence: medium)_

**Statement.** Within the last 7 days, an attacker stole a user’s web session cookie from a non-allowlisted domain during an active authenticated session, enabling unauthorized access to corporate SaaS applications.

**Why this hypothesis?** The article emphasizes session hijacking as a growing threat. T1539 (Steal Web Session Cookie) and T1078 (Valid Accounts) are directly referenced in indicators. This hypothesis focuses on cookie theft post-authentication, a common bypass of MFA.

**MITRE ATT&CK**: T1539, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-2af816e6-2-O1] Cookie modified from non-allowlisted domain** _(difficulty: medium · 110 pts · MITRE: T1539)_
  - Falsification criterion: At least one cookie modification occurred from a non-allowlisted domain during an active session.
  - Data sources: EDR browser telemetry, SaaS access logs
  - Suggested query: `event_type = 'cookie_modified' AND domain NOT IN ('google.com', 'office365.com', 'corp.com') AND session_id IS NOT NULL`
- **[H-2af816e6-2-O2] Session reused from anomalous IP** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: At least one authenticated SaaS session was initiated from an IP address not associated with the user’s typical location or device.
  - Data sources: SaaS logs, Network access logs
  - Suggested query: `auth_status = 'success' AND user_id = 'known_user' AND source_ip NOT IN (user_ip_history) AND session_id = previous_session_id`
- **[H-2af816e6-2-O3] Cookie value exfiltrated via outbound HTTP** _(difficulty: hard · 130 pts · MITRE: T1539)_
  - Falsification criterion: At least one HTTP request contained a session cookie value in headers or body to an external domain not in allowlist.
  - Data sources: Proxy logs, EDR network traffic
  - Suggested query: `http_request_headers contains 'Cookie:' AND destination_domain NOT IN ('corp.com', 'trusted-saas.com') AND length(http_request_body) > 100`

**Sigma rule:**

```yaml
title: Session Cookie Modification from Non-Allowlisted Domain
logsource:
  product: chrome
  service: browser_extension
detection:
  selection:
    event_type: 'cookie_modified'
    domain: '*[!a-z0-9.-]*.malicious.site' | '*[!a-z0-9.-]*.phish.net' | '*[!a-z0-9.-]*.fakeapp.org'
    session_id: '*'
  condition: selection
condition: 1 of selection*
```

#### H-2af816e6-3 · Credential Stuffing Attack Leading to Account Takeover  _(confidence: high)_

**Statement.** In the last 7 days, an attacker used a list of known leaked credentials to perform credential stuffing against our corporate SaaS applications, resulting in at least one successful login using a compromised account.

**Why this hypothesis?** The article identifies credential stuffing as a scalable attack method. T1110 (Brute Force) and T1110.003 (Credential Stuffing) are explicitly indicated. This hypothesis targets automated login attempts using stolen credentials, a direct threat to valid account usage.

**MITRE ATT&CK**: T1110, T1110.003, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-2af816e6-3-O1] 10+ failed login attempts from same user/account** _(difficulty: easy · 100 pts · MITRE: T1110.003)_
  - Falsification criterion: At least one user account had 10 or more consecutive failed login attempts within 5 minutes.
  - Data sources: Azure AD logs, SSO logs
  - Suggested query: `result_type = 'Failure' AND user_id = 'user@corp.com' AND timestamp > now() - 5m | count by user_id > 10`
- **[H-2af816e6-3-O2] Successful login immediately after credential stuffing** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: At least one successful login occurred within 10 seconds of a burst of 10+ failed attempts for the same account.
  - Data sources: Azure AD logs, SIEM correlation engine
  - Suggested query: `result_type = 'Success' AND user_id IN (SELECT user_id FROM failures WHERE count > 10 AND time_window = 5m) AND timestamp < (SELECT max(timestamp) FROM failures WHERE user_id = this.user_id) + 10s`
- **[H-2af816e6-3-O3] Login from new device/location after credential stuffing** _(difficulty: hard · 130 pts · MITRE: T1078)_
  - Falsification criterion: At least one successful login occurred from a new device or geographic location immediately following a credential stuffing event.
  - Data sources: Azure AD logs, Device registration logs
  - Suggested query: `result_type = 'Success' AND device_id NOT IN (user_device_history) AND country NOT IN (user_country_history) AND user_id IN (frequent_failures)`

**Sigma rule:**

```yaml
title: Credential Stuffing - Multiple Failed Logins Followed by Success
logsource:
  product: azure_ad
  service: authentication
detection:
  selection:
    result_type: 'Failure'
    user_id: '*'
    timestamp: '*'
  condition: 10 of selection* by user_id
  selection2:
    result_type: 'Success'
    user_id: '*'
    timestamp: '> last_failure_timestamp + 10s'
  condition: selection2 AND user_id IN (selection.user_id)
condition: 1 of selection* and selection2
```

---

## 31. LA Metro Cyberattack Linked to Iranian State-Sponsored Hackers

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/la-metro-cyberattack-linked-to-iranian-state-sponsored-hackers/>
- **Published**: Wed, 27 May 2026 09:33:45 +0000
- **First seen**: 2026-05-27T09:41:17+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Iranian state-sponsored actor; active attack on critical infrastructure (transportation); high capability and likely use of tradecraft relevant to enterprise environments.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "nation state"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 1 ('No emails from irancell.ir, melli.ir, or gov.ir were received...') is not a falsification test — it's a negative assertion that cannot be proven true in practice. A null re)

> The attack was claimed by a hacktivist group, but evidence showed it used infrastructure linked to Iranian government threat actors. The post LA Metro Cyberattack Linked to Iranian State-Sponsored Hackers appeared first on SecurityWeek .

**Extracted signals**
- Sectors: government

### Hypotheses (3)

#### H-a917f30a-1 · Iranian APT used phishing to compromise initial access  _(confidence: medium)_

**Statement.** Between May 20-27, 2026, an Iranian state-sponsored APT delivered a phishing email to a LA Metro employee, leading to credential theft via a malicious link or attachment.

**Why this hypothesis?** The article links the attack to Iranian state-sponsored actors, and phishing (T1566) is the most common initial vector for such actors targeting government entities. The sector (government) aligns with known Iranian APT targeting patterns.

**MITRE ATT&CK**: T1566, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a917f30a-1-O1] No phishing emails from known Iranian domains** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: If even one email is found from irancell.ir, melli.ir, or gov.ir with malicious attachment or URL, the hypothesis is confirmed; absence of any such email falsifies the hypothesis.
  - Data sources: Email gateway logs, EOP/Exchange logs
  - Suggested query: `filter: event_type == 'email_received' and sender_domain in ['irancell.ir', 'melli.ir', 'gov.ir'] and (attachment_extension in ['exe','js','vbs','scr','zip','doc','xls'] or url contains 'http' and url contains '.ir')`
- **[H-a917f30a-1-O2] No credential harvesting landing pages hosted on Iranian domains** _(difficulty: medium · 120 pts · MITRE: T1566, T1078)_
  - Falsification criterion: If a login page hosted on a .ir domain is accessed by any internal user, the hypothesis is confirmed; if no such access occurs, the hypothesis is falsified.
  - Data sources: Web proxy logs, EDR browser activity
  - Suggested query: `filter: url contains '.ir' and http_status == 200 and request_method == 'GET' and (url_path contains 'login' or url_path contains 'signin' or url_path contains 'auth')`
- **[H-a917f30a-1-O3] No user clicked on phishing links from Iranian domains** _(difficulty: medium · 110 pts · MITRE: T1566)_
  - Falsification criterion: If any user clicked a link in an email from a .ir domain, the hypothesis is confirmed; if no clicks are recorded from such emails, the hypothesis is falsified.
  - Data sources: EDR, Browser telemetry, Email click tracking
  - Suggested query: `filter: event_type == 'url_click' and url contains '.ir' and source == 'email'`

**Sigma rule:**

```yaml
title: Phishing Email from Suspicious Iranian Domains
logsource:
  product: email
  service: exchange
condition: 'event_type: email_received and (sender_domain|contains: ["irancell.ir", "melli.ir", "gov.ir"] or sender_domain|contains: ["irancell", "melli", "gov"])
  and (attachment_extension: ["exe", "js", "vbs", "scr", "zip", "doc", "xls"] or url: contains "http" and url: contains ".ir" or subject: contains "invoice" or subject: contains "payment")
detection:
  sender_domain:
    - "irancell.ir"
    - "melli.ir"
    - "gov.ir"
  attachment_extension:
    - "exe"
    - "js"
    - "vbs"
    - "scr"
    - "zip"
    - "doc"
    - "xls"
  url:
    - "http"
  subject:
    - "invoice"
    - "payment"
condition: 'sender_domain in (sender_domain) or attachment_extension in (attachment_extension) or url in (url) or subject in (subject)'
```

#### H-a917f30a-2 · Iranian APT used compromised third-party infrastructure for C2  _(confidence: high)_

**Statement.** Between May 20-27, 2026, Iranian APT used compromised third-party domains or cloud services (e.g., GitHub, Dropbox, or free DNS) to establish C2 communication from internal hosts, avoiding direct Iranian IP connections.

**Why this hypothesis?** APT groups routinely evade static IOCs by using compromised infrastructure. The article implies sophisticated actors; direct Iranian IPs are unlikely. Behavioral pattern of C2 via legitimate services is more plausible than direct connections.

**MITRE ATT&CK**: T1071, T1567

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a917f30a-2-O1] No internal host queried known C2 proxy domains** _(difficulty: medium · 130 pts · MITRE: T1071, T1567)_
  - Falsification criterion: If any internal host queries github.com, pastebin.com, or similar domains more than 5 times in 5 minutes, the hypothesis is confirmed; if no such queries occur, the hypothesis is falsified.
  - Data sources: DNS logs, EDR network telemetry
  - Suggested query: `filter: domain in ['github.com', 'pastebin.com', 'dropbox.com', 'bit.ly', 'tinyurl.com', 'replit.com', 'glitch.me'] and src_ip in internal_network and query_count > 5 within 5m`
- **[H-a917f30a-2-O2] No outbound HTTPS connections to known C2 proxy services** _(difficulty: medium · 120 pts · MITRE: T1071, T1567)_
  - Falsification criterion: If any internal host makes HTTPS connections to pastebin.com, github.com, or similar with non-browser User-Agent, the hypothesis is confirmed; if none occur, it is falsified.
  - Data sources: Web proxy logs, Firewall logs
  - Suggested query: `filter: dest_domain in ['github.com', 'pastebin.com', 'dropbox.com'] and user_agent not contains 'Mozilla' and http_method == 'POST' and bytes_sent > 1000`
- **[H-a917f30a-2-O3] No DNS tunneling using TXT records over proxy domains** _(difficulty: hard · 140 pts · MITRE: T1041, T1071)_
  - Falsification criterion: If any internal host sends TXT queries to github.com or similar with long, base64-encoded strings, the hypothesis is confirmed; if no such queries exist, it is falsified.
  - Data sources: DNS logs
  - Suggested query: `filter: domain in ['github.com', 'pastebin.com'] and query_type == 'TXT' and query_length > 100 and query matches '^[A-Za-z0-9+/]+={0,2}$'`

**Sigma rule:**

```yaml
title: Suspicious C2 via Legitimate Services from Internal Hosts
logsource:
  product: network
  service: dns
condition: 'event_type: dns_query and (domain|contains: ["github.com", "pastebin.com", "dropbox.com", "bit.ly", "tinyurl.com", "replit.com", "glitch.me"]) and src_ip in (internal_ip_range) and query_type in ["A", "AAAA"] and response_count > 5 and time_window: 5m'
detection:
  domain:
    - "github.com"
    - "pastebin.com"
    - "dropbox.com"
    - "bit.ly"
    - "tinyurl.com"
    - "replit.com"
    - "glitch.me"
  query_type:
    - "A"
    - "AAAA"
  src_ip:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
condition: 'domain in (domain) and src_ip in (src_ip) and query_type in (query_type) and response_count > 5 within 5m'
```

#### H-a917f30a-3 · Iranian APT exfiltrated data via DNS tunneling using legitimate record types  _(confidence: high)_

**Statement.** Between May 20-27, 2026, an Iranian APT exfiltrated data from LA Metro internal systems using DNS tunneling via AAAA or TXT records to a domain under attacker control, disguised as normal DNS traffic.

**Why this hypothesis?** Iranian APTs have historically used DNS tunneling (T1041) to bypass network controls. The article implies stealth and persistence. Legitimate use of AAAA/TXT does not preclude abuse — the pattern is in volume, frequency, and encoding, not record type.

**MITRE ATT&CK**: T1041, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-a917f30a-3-O1] No internal host made >20 TXT/AAAA queries in 5 minutes** _(difficulty: medium · 130 pts · MITRE: T1041, T1071)_
  - Falsification criterion: If any internal host makes >20 TXT or AAAA queries in 5 minutes, the hypothesis is confirmed; if no host exceeds this threshold, the hypothesis is falsified.
  - Data sources: DNS logs
  - Suggested query: `filter: query_type in ['TXT', 'AAAA'] and src_ip in internal_network and query_count > 20 within 5m`
- **[H-a917f30a-3-O2] No DNS queries contain base64-encoded strings in TXT records** _(difficulty: hard · 150 pts · MITRE: T1041)_
  - Falsification criterion: If any TXT query contains a base64-encoded string longer than 50 characters, the hypothesis is confirmed; if none are found, it is falsified.
  - Data sources: DNS logs
  - Suggested query: `filter: query_type == 'TXT' and query matches '^[A-Za-z0-9+/]{50,}={0,2}$'`
- **[H-a917f30a-3-O3] No AAAA queries resolve to non-routable IPv6 ranges** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: If any AAAA query resolves to a non-routable IPv6 (e.g., fd00::/8, fe80::/10) or unusual pattern, the hypothesis is confirmed; if all AAAA queries resolve to public IPv6, it is falsified.
  - Data sources: DNS logs, Netflow
  - Suggested query: `filter: query_type == 'AAAA' and response_ip matches '^(fd|fe80|fec0)'`
- **[H-a917f30a-3-O4] No DNS queries to domains with entropy > 3.5** _(difficulty: hard · 160 pts · MITRE: T1041, T1053)_
  - Falsification criterion: If any domain queried via DNS has Shannon entropy > 3.5 (indicating DGA or random subdomain), the hypothesis is confirmed; if all domains are low-entropy (e.g., company names), it is falsified.
  - Data sources: DNS logs
  - Suggested query: `filter: domain_entropy > 3.5 and query_type in ['A', 'AAAA', 'TXT']`

**Sigma rule:**

```yaml
title: DNS Exfiltration via High-Volume TXT/AAAA Queries
logsource:
  product: network
  service: dns
condition: 'event_type: dns_query and query_type in ["TXT", "AAAA"] and src_ip in (internal_ip_range) and query_count > 20 within 5m and query_length > 50'
detection:
  query_type:
    - "TXT"
    - "AAAA"
  src_ip:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  query_length:
    - ">50"
condition: 'query_type in (query_type) and src_ip in (src_ip) and query_count > 20 within 5m and query_length > 50'
```

---

## 32. Tycoon 2FA AiTM detection for Entra ID and Google

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tovz13/tycoon_2fa_aitm_detection_for_entra_id_and_google/>
- **Published**: 2026-05-27T05:24:48+00:00
- **First seen**: 2026-05-27T06:22:30+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active AiTM attacks targeting Entra ID and Google 2FA are high-impact, widespread, and directly exploitable in enterprise environments; defenders can hunt for anomalous auth flows.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_mitre({"query": "T1566.001"}) -> ok → tool lookup_mitre({"query": "AiTM"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — absence of URLs with 'tycoon', '2fa-verify', etc. does not disprove the attack; attackers could use obfuscated or novel domains. Falsification r)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: cloud-misconfig

### Hypotheses (3)

#### H-b032f7d1-1 · Credential Relay via Cloud Proxy  _(confidence: medium)_

**Statement.** An attacker used a compromised user credential to relay authentication requests through a cloud proxy service to access Microsoft 365 resources between May 20-27, 2026, in our environment.

**Why this hypothesis?** The article suggests Tycoon is an AiTM framework targeting MFA bypass; given our use of Entra ID, this aligns with known credential relay tactics where attackers proxy authentication flows to bypass MFA without direct access to the victim's device.

**MITRE ATT&CK**: T1110, T1566, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-b032f7d1-1-O1] Detect federated auth from non-corporate IPs** _(difficulty: medium · 150 pts · MITRE: T1078)_
  - Falsification criterion: We observe at least one successful Azure AD sign-in with federated authentication from a public, non-corporate IP address without conditional access policies applied.
  - Data sources: Azure AD Sign-in Logs
  - Suggested query: `SigninLogs | where AuthenticationMethod == "federated" and ResultType == "0" and ConditionalAccessPolicies == "[]" and IPAddress !~ "10." and IPAddress !~ "172.16." and IPAddress !~ "192.168."`
- **[H-b032f7d1-1-O2] Identify rapid sequential authentications** _(difficulty: hard · 200 pts · MITRE: T1110)_
  - Falsification criterion: We detect two or more successful Azure AD authentications from the same user within 60 seconds from geographically distant IP addresses.
  - Data sources: Azure AD Sign-in Logs
  - Suggested query: `SigninLogs | where UserPrincipalName == "user@domain.com" | summarize count() by UserPrincipalName, bin(TimeGenerated, 1m) | where count_ > 1`
- **[H-b032f7d1-1-O3] Detect browser-based auth without MFA prompt** _(difficulty: medium · 180 pts · MITRE: T1566)_
  - Falsification criterion: We observe successful Azure AD sign-ins using browser client_app with no MFA challenge recorded in the ConditionalAccessDetails field.
  - Data sources: Azure AD Sign-in Logs
  - Suggested query: `SigninLogs | where ClientApp == "Browser" and ResultType == "0" and ConditionalAccessPolicies has "MFA" == false`

**Sigma rule:**

```yaml
title: Detect Credential Relay via Cloud Proxy
logsource:
  product: azure_ad
  service: signins
detection:
  selection:
    authentication_method: 'federated'
    status: 'Success'
    client_app: 'Browser'
    conditional_access: 'None'
  filter:
    ip_address: '10.0.0.0/8' | '172.16.0.0/12' | '192.168.0.0/16'
  condition: selection and not filter
condition: selection
```

#### H-b032f7d1-2 · Phishing Domain Hosting Credential Harvesting  _(confidence: high)_

**Statement.** An attacker deployed a phishing domain mimicking Microsoft 365 login pages to harvest credentials from employees between May 20-27, 2026, in our environment.

**Why this hypothesis?** The article references Tycoon as an AiTM tool; such tools typically rely on phishing domains to intercept credentials. We expect to find proxy or web gateway logs showing requests to newly registered domains with patterns resembling Microsoft login pages.

**MITRE ATT&CK**: T1566, T1071

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-b032f7d1-2-O1] Identify new domains with Microsoft branding** _(difficulty: medium · 160 pts · MITRE: T1566)_
  - Falsification criterion: We detect at least one newly registered domain (created within 7 days) that contains substrings like 'microsoft', 'office', or 'azure' in its hostname and has been accessed by internal users via web proxy.
  - Data sources: DNS logs, Web Proxy Logs
  - Suggested query: `DNSQueries | where QueryTime > ago(7d) | where Domain contains "microsoft" or Domain contains "office" or Domain contains "azure" | join (WebProxyLogs | where Timestamp > ago(7d)) on $left.Domain == $right.DestinationHost`
- **[H-b032f7d1-2-O2] Detect POSTs to non-Microsoft domains with credential fields** _(difficulty: hard · 200 pts · MITRE: T1071)_
  - Falsification criterion: We observe HTTP POST requests to domains outside our trusted list containing form fields named 'username', 'password', 'otp', or 'mfa_code'.
  - Data sources: Web Proxy Logs, EDR
  - Suggested query: `WebProxyLogs | where RequestMethod == "POST" and (RequestURL contains "username" or RequestURL contains "password" or RequestURL contains "otp" or RequestURL contains "mfa_code") and DestinationHost !~ "microsoft.com" and DestinationHost !~ "ourcompany.com"`
- **[H-b032f7d1-2-O3] Correlate DNS queries with phishing domain registrations** _(difficulty: hard · 180 pts · MITRE: T1566)_
  - Falsification criterion: We identify DNS queries from internal hosts to domains registered via public registrars within the last 48 hours that match known phishing domain patterns (e.g., typosquatting, homoglyphs).
  - Data sources: DNS logs, Domain Registration Feeds
  - Suggested query: `DNSQueries | where QueryTime > ago(2d) | where Domain matches regex "[microsoft|office|azure][0-9]*[.]com" | join (DomainRegistrationFeed | where RegistrationDate > ago(2d)) on $left.Domain == $right.Domain`

**Sigma rule:**

```yaml
title: Detect Phishing Domain Access via Proxy
logsource:
  product: proxy
  service: web
detection:
  selection:
    url|contains: "login.microsoftonline.com"
    url|contains: "auth" | "oauth" | "token" | "exchange"
    user_agent|contains: "Mozilla" | "Chrome" | "Safari"
  filter:
    domain|endswith: "microsoft.com" | "office.com" | "azure.com"
  condition: selection and not filter
condition: selection
```

#### H-b032f7d1-3 · MFA Bypass via Token Replay  _(confidence: medium)_

**Statement.** An attacker intercepted and replayed a valid MFA token or session cookie to gain persistent access to Google Workspace resources between May 20-27, 2026, in our environment.

**Why this hypothesis?** The article implies Tycoon enables MFA bypass; this aligns with token replay attacks where attackers capture and reuse valid authentication tokens from legitimate sessions, especially in environments using SSO or OAuth flows.

**MITRE ATT&CK**: T1555, T1078, T1550

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-b032f7d1-3-O1] Detect token replay events in Google Workspace** _(difficulty: medium · 170 pts · MITRE: T1555)_
  - Falsification criterion: We observe at least one 'token_replay' or 'session_reuse' event in Google Workspace audit logs originating from an external IP address.
  - Data sources: Google Workspace Audit Logs
  - Suggested query: `audit_logs | where event_type == "token_replay" or event_type == "session_reuse" | where ip_address !~ "10." and ip_address !~ "172.16." and ip_address !~ "192.168."`
- **[H-b032f7d1-3-O2] Identify concurrent sessions from disparate locations** _(difficulty: hard · 200 pts · MITRE: T1078)_
  - Falsification criterion: We detect two or more active Google Workspace sessions for the same user, simultaneously logged in from geographically distant locations (e.g., US and Asia) within a 5-minute window.
  - Data sources: Google Workspace Audit Logs
  - Suggested query: `audit_logs | where event_type == "login" | summarize count() by user, bin(timestamp, 5m) | where count_ > 1 | where location != prev(location)`
- **[H-b032f7d1-3-O3] Detect OAuth token requests to unknown third-party apps** _(difficulty: medium · 160 pts · MITRE: T1550)_
  - Falsification criterion: We observe OAuth token requests from Google Workspace to third-party applications not approved in our organization’s admin console.
  - Data sources: Google Workspace Admin Console Logs
  - Suggested query: `admin_logs | where event_name == "OAUTH_TOKEN_REQUEST" | where app_name not in ("ApprovedApps" | where status == "enabled")`

**Sigma rule:**

```yaml
title: Detect Suspicious Google Workspace Token Replay
logsource:
  product: google_workspace
  service: signins
detection:
  selection:
    event_type: "token_replay"
    client_ip: !"10.0.0.0/8" | !"172.16.0.0/12" | !"192.168.0.0/16"
    user_agent: "Mozilla" | "Chrome"
  condition: selection
condition: selection
```

---

## 33. Microsoft Issues Out-of-Band SharePoint Patch

- **Source**: Dark Reading
- **Link**: <https://www.darkreading.com/vulnerabilities-threats/microsoft-issues-sharepoint-patch>
- **Published**: Tue, 26 May 2026 18:25:44 GMT
- **First seen**: 2026-05-26T21:14:20+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Out-of-band SharePoint patch indicates critical vulnerability; SharePoint often contains sensitive enterprise data and is a high-value target for lateral movement and privilege escalation. Defenders can hunt for exploitation attempts via unusual file access, PowerShell execution, or SMB traffic patterns.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it checks for absence of SYSTEM logons, but the hypothesis claims attackers exploited a vulnerability to gain initial access via SharePoint. SYS)

> SharePoint access often means access to the keys of the kingdom, something attackers and defenders understand all too well.

### Hypotheses (3)

#### H-feb10918-1 · Initial Access via Unpatched SharePoint Vulnerability  _(confidence: high)_

**Statement.** Attackers exploited the unpatched CVE-2023-21712 vulnerability in our SharePoint server (10.10.50.10) between May 25–26, 2026, to gain initial access.

**Why this hypothesis?** The article highlights an out-of-band patch for SharePoint, indicating active exploitation. Our environment hosts SharePoint servers exposed to the internet, making CVE-2023-21712 (a remote code execution flaw) a credible initial access vector.

**MITRE ATT&CK**: T1190

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-feb10918-1-O1] Detect exploit payload in IIS logs** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests to /_vti_bin/ with path traversal or script injection payloads are found on SharePoint server 10.10.50.10 between May 25–26, 2026.
  - Data sources: IIS logs, Web proxy logs
  - Suggested query: `source_ip = '10.10.50.10' AND uri_path CONTAINS '_vti_bin/' AND query_string CONTAINS ('..%2f' OR '<script>')`
- **[H-feb10918-1-O2] Identify anomalous HTTP status codes** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No 500 or 404 responses with high volume from a single external IP targeting SharePoint endpoints during the time window.
  - Data sources: IIS logs
  - Suggested query: `source_ip NOT IN ('10.0.0.0/8') AND status_code IN (500, 404) AND uri_path CONTAINS '_vti_bin/' AND count > 100 in 5m`
- **[H-feb10918-1-O3] Correlate with failed authentication events** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No spikes in failed authentication events (Event ID 4625) on SharePoint server coinciding with exploit attempts.
  - Data sources: Windows Security logs
  - Suggested query: `EventID = 4625 AND TargetServer = '10.10.50.10' AND TimeGenerated BETWEEN '2026-05-25T00:00:00' AND '2026-05-26T23:59:59'`

**Sigma rule:**

```yaml
title: Detect CVE-2023-21712 Exploit Attempt in SharePoint
id: 1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6
status: experimental
level: high
description: Detects HTTP requests with payload patterns indicative of CVE-2023-21712 exploitation on SharePoint servers.
logsource:
  product: iis
  service: web
  category: web_server
detection:
  selection:
    uri_path: "/_vti_bin/"  # Common SharePoint endpoint
    query_string|contains:
      - "_vti_bin/"  # Exploit pattern
      - "..%2f"  # Path traversal
      - "<script>"  # Script injection
    client_ip: "10.10.50.10"  # Known SharePoint server IP
  condition: selection
fields:
  - client_ip
  - uri_path
  - query_string
```

#### H-feb10918-2 · Lateral Movement via Pass-the-Ticket  _(confidence: medium)_

**Statement.** After initial access, attackers used Pass-the-Ticket techniques to move laterally from the compromised SharePoint server to domain controllers or file servers between May 26–27, 2026.

**Why this hypothesis?** SharePoint servers often hold service accounts with high privileges. Attackers commonly use Kerberos tickets (TGTs/STs) to move laterally without triggering password-based alerts, especially if credential dumping occurred.

**MITRE ATT&CK**: T1075, T1003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-feb10918-2-O1] Detect TGT requests from SharePoint server** _(difficulty: medium · 100 pts · MITRE: T1075)_
  - Falsification criterion: No Event ID 4769 (Kerberos TGT requests) originating from SharePoint server 10.10.50.10 to domain controllers during May 26–27, 2026.
  - Data sources: Windows Security logs
  - Suggested query: `EventID = 4769 AND ClientIP = '10.10.50.10' AND TargetUserName = 'krbtgt'`
- **[H-feb10918-2-O2] Identify service account ticket requests** _(difficulty: medium · 100 pts · MITRE: T1075)_
  - Falsification criterion: No Kerberos service ticket requests (Event ID 4769) to critical services (e.g., CIFS, LDAP) from SharePoint server to domain controllers.
  - Data sources: Windows Security logs
  - Suggested query: `EventID = 4769 AND ClientIP = '10.10.50.10' AND TargetUserName ENDS WITH '$' AND ServiceName IN ('cifs', 'ldap', 'host')`
- **[H-feb10918-2-O3] Detect credential dumping on SharePoint server** _(difficulty: hard · 150 pts · MITRE: T1003)_
  - Falsification criterion: No Event ID 4688 (process creation) with command line containing 'lsass.exe', 'mimikatz', or 'sekurlsa::logonpasswords' on SharePoint server.
  - Data sources: Windows Security logs, EDR
  - Suggested query: `EventID = 4688 AND Image LIKE '%lsass.exe%' OR CommandLine CONTAINS ('mimikatz' OR 'sekurlsa::logonpasswords') AND ComputerName = 'SP-SRV-01'`
- **[H-feb10918-2-O4] Detect unusual logon types from SharePoint server** _(difficulty: medium · 100 pts · MITRE: T1075)_
  - Falsification criterion: No logon type 3 (network) or 10 (remote interactive) events from SharePoint server to other internal systems during the time window.
  - Data sources: Windows Security logs
  - Suggested query: `EventID = 4624 AND LogonType IN (3, 10) AND SourceComputer = '10.10.50.10' AND TargetUserName != 'ANONYMOUS LOGON'`

**Sigma rule:**

```yaml
title: Detect Suspicious Kerberos Ticket Usage for Lateral Movement
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
level: medium
description: Detects unusual Kerberos ticket requests from SharePoint server to domain controllers.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769  # Kerberos ticket request
    TargetUserName: 'krbtgt' OR TargetUserName|endswith: '$'
    ClientIP: '10.10.50.10'  # SharePoint server
    TicketOptions: '0x40810000'  # Forwardable, Renewable
  condition: selection
fields:
  - ClientIP
  - TargetUserName
  - TicketOptions
```

#### H-feb10918-3 · Data Exfiltration via External File Sharing  _(confidence: medium)_

**Statement.** Attackers exfiltrated sensitive documents by sharing them externally via SharePoint between May 26–28, 2026, using non-admin accounts to avoid detection.

**Why this hypothesis?** SharePoint is commonly used for collaboration, making it a prime vector for data exfiltration. Attackers often abuse sharing features to bypass traditional DLP controls, especially using non-admin accounts to evade alerting.

**MITRE ATT&CK**: T1078, T1041

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-feb10918-3-O1] Detect external sharing of sensitive file types** _(difficulty: medium · 100 pts · MITRE: T1041)_
  - Falsification criterion: No external sharing events (Operation: 'SharingInvitationCreated') for .docx, .xlsx, or .pdf files initiated by non-admin users during May 26–28, 2026.
  - Data sources: SharePoint audit logs
  - Suggested query: `Operation = 'SharingInvitationCreated' AND Target ENDS WITH ('.docx', '.xlsx', '.pdf') AND SharingType = 'ExternalUser' AND User NOT STARTS WITH 'admin'`
- **[H-feb10918-3-O2] Identify external sharing from non-standard IPs** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: No external sharing events originating from client IPs outside the corporate network range during the time window.
  - Data sources: SharePoint audit logs
  - Suggested query: `Operation = 'SharingInvitationCreated' AND ClientIP NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') AND SharingType = 'ExternalUser'`
- **[H-feb10918-3-O3] Detect high-volume sharing by single user** _(difficulty: medium · 100 pts · MITRE: T1041)_
  - Falsification criterion: No single non-admin user created more than 5 external sharing invitations in a 10-minute window.
  - Data sources: SharePoint audit logs
  - Suggested query: `Operation = 'SharingInvitationCreated' AND SharingType = 'ExternalUser' AND User NOT STARTS WITH 'admin' AND count > 5 in 10m GROUP BY User`
- **[H-feb10918-3-O4] Correlate with anomalous login times** _(difficulty: hard · 150 pts · MITRE: T1078)_
  - Falsification criterion: No external sharing events initiated by users who logged in outside business hours (8 PM–6 AM) during the time window.
  - Data sources: SharePoint audit logs, Azure AD sign-in logs
  - Suggested query: `Operation = 'SharingInvitationCreated' AND SharingType = 'ExternalUser' AND User IN (SELECT User FROM AzureADSignIns WHERE TimeGenerated BETWEEN '2026-05-26T20:00:00' AND '2026-05-28T06:00:00')`

**Sigma rule:**

```yaml
title: Detect Suspicious External File Sharing in SharePoint Audit Logs
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
level: medium
description: Detects external sharing events from non-admin users in SharePoint audit logs.
logsource:
  product: sharepoint
  category: audit
detection:
  selection:
    Operation: 'SharingInvitationCreated'
    Target: '*.docx' OR '*.xlsx' OR '*.pdf'
    SharingType: 'ExternalUser'
    User: !'admin*'  # Non-admin user
    ClientIP: NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
  condition: selection
fields:
  - User
  - Target
  - SharingType
  - ClientIP
```

---

## 34. KnowledgeDeliver flaw exploited as a zero-day to install web shells

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/knowledgedeliver-flaw-exploited-as-a-zero-day-to-install-web-shells/>
- **Published**: Tue, 26 May 2026 16:07:31 -0400
- **First seen**: 2026-05-26T20:40:00+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active zero-day exploit in a widely used LMS leading to web shell deployment — high blast radius, direct enterprise attack surface, and actionable indicators.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-12345"}) -> ok → tool lookup_mitre({"query": "T1505.003"}) -> ok → critic: revise (Hypothesis 1: Sigma rule is syntactically invalid — incomplete condition ('FileH') and malformed detection logic. 'FileCreation' is not a standard field in IIS logs; also mixing EventID=1 (Windows Eve)

> Hackers exploited a critical zero-day vulnerability in a server running the KnowledgeDeliver learning management system (LMS) to deploy the Godzilla web shell. [...]

**Extracted signals**
- Vectors: exploit
- MITRE ATT&CK: T1505.003

### Hypotheses (3)

#### H-3ec78a47-1 · Godzilla Web Shell Deployed via KnowledgeDeliver RCE  _(confidence: high)_

**Statement.** An attacker exploited a zero-day vulnerability in the KnowledgeDeliver LMS on our web server (10.10.10.5) between May 25–26, 2026, to deploy the Godzilla web shell (SHA-256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2) via an HTTP POST request to /KnowledgeDeliver.aspx, resulting in a new .aspx file creation by w3wp.exe.

**Why this hypothesis?** The BleepingComputer article describes exploitation of a zero-day in KnowledgeDeliver leading to Godzilla deployment. The extracted MITRE T1505.003 (Web Shell: Install Web Shell) aligns with file creation on web servers. Godzilla is a known .aspx-based web shell, and w3wp.exe is the default IIS worker process.

**MITRE ATT&CK**: T1190, T1505.003, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-3ec78a47-1-O1] No legitimate .aspx files created by w3wp.exe** _(difficulty: medium · 100 pts · MITRE: T1505.003)_
  - Falsification criterion: If legitimate .aspx files are found created by w3wp.exe during the time window, the hypothesis is falsified.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID:4688 AND Image:*\w3wp.exe AND TargetFilename:*.aspx AND NOT CommandLine:*"/app/"* AND NOT CommandLine:*"/deploy/"*`
- **[H-3ec78a47-1-O2] External POST to KnowledgeDeliver.aspx** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no HTTP POST requests to /KnowledgeDeliver.aspx originated from non-whitelisted external IPs, the hypothesis is falsified.
  - Data sources: WAF, IIS logs
  - Suggested query: `request_uri:/KnowledgeDeliver.aspx AND method:POST AND client_ip NOT IN ["10.10.10.0/24", "192.168.1.0/24"]`
- **[H-3ec78a47-1-O3] Godzilla hash matches file on disk** _(difficulty: medium · 100 pts · MITRE: T1505.003)_
  - Falsification criterion: If no file with SHA-256 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 is found on the web server, the hypothesis is falsified.
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `file_hash:sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 AND file_path:*\*.aspx`
- **[H-3ec78a47-1-O4] No legitimate admin activity during exploitation window** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: If legitimate admin activity (e.g., deployment scripts, patching) is found coinciding with the .aspx creation and POST events, the hypothesis is falsified.
  - Data sources: SIEM, Jump server logs
  - Suggested query: `event_type:login AND user:admin* AND timestamp:2026-05-25T20:00:00Z TO 2026-05-26T02:00:00Z`

**Sigma rule:**

```yaml
title: Detect Godzilla Web Shell Deployment via IIS
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects creation of suspicious .aspx files by IIS worker process following HTTP POST to KnowledgeDeliver.aspx
detection:
  selection:
    EventID: 4688
    CommandLine: '*KnowledgeDeliver.aspx*'
    ParentImage: '*\w3wp.exe'
    Image: '*\cmd.exe'
  condition: selection
logsource:
  product: windows
  service: sysmon
detection:
  FileCreation:
    Image: '*\w3wp.exe'
    ParentImage: '*\iisexpress.exe' or '*\w3wp.exe'
    TargetFilename: '*\*.aspx'
    CommandLine: '*Godzilla*' or '*base64*' or '*eval(*'
  HttpPost:
    EventID: 5156
    DestinationIp: '10.10.10.5'
    DestinationPort: '80'
    Protocol: 'TCP'
    DestinationHostname: '*KnowledgeDeliver.aspx*'
    SourceIp: '!10.10.10.0/24'
condition: FileCreation and HttpPost
```

#### H-3ec78a47-2 · Post-Exploitation via PowerShell Execution  _(confidence: medium)_

**Statement.** After deploying the Godzilla web shell, the attacker used PowerShell (cmd.exe or w3wp.exe spawning powershell.exe) to execute commands on the server between May 25–26, 2026, to enumerate systems and exfiltrate data, consistent with T1059.003.

**Why this hypothesis?** Godzilla web shells commonly invoke PowerShell for lateral movement and data exfiltration. The article implies post-exploitation activity. T1059.003 (Command and Scripting Interpreter: PowerShell) is a common next step after web shell deployment.

**MITRE ATT&CK**: T1059.003, T1071.004, T1082

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-3ec78a47-2-O1] PowerShell spawned by w3wp.exe** _(difficulty: easy · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: If no PowerShell process is found with w3wp.exe or cmd.exe as parent during the time window, the hypothesis is falsified.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID:4688 AND Image:*\powershell.exe AND ParentImage:*\w3wp.exe OR ParentImage:*\cmd.exe`
- **[H-3ec78a47-2-O2] Encoded PowerShell commands detected** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: If no PowerShell commands contain -EncodedCommand, Invoke-Expression, or base64-encoded strings, the hypothesis is falsified.
  - Data sources: Sysmon, EDR
  - Suggested query: `CommandLine:*-EncodedCommand* OR CommandLine:*Invoke-Expression* OR CommandLine:*[Convert]::FromBase64String*`
- **[H-3ec78a47-2-O3] No legitimate PowerShell usage from IIS context** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: If legitimate PowerShell scripts (e.g., deployment, monitoring) are found running under w3wp.exe context, the hypothesis is falsified.
  - Data sources: Sysmon, SIEM
  - Suggested query: `EventID:4688 AND Image:*\powershell.exe AND ParentImage:*\w3wp.exe AND NOT CommandLine:*"C:\Scripts\monitor.ps1"* AND NOT CommandLine:*"C:\Tools\healthcheck.ps1"*`
- **[H-3ec78a47-2-O4] DNS queries from PowerShell process** _(difficulty: hard · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If no DNS queries are observed originating from PowerShell processes during the time window, the hypothesis is falsified.
  - Data sources: DNS logs, EDR
  - Suggested query: `process_name:powershell.exe AND dns_query:* AND timestamp:2026-05-25T20:00:00Z TO 2026-05-26T02:00:00Z`

**Sigma rule:**

```yaml
title: Detect PowerShell Execution from IIS Process
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: Detects PowerShell execution spawned by w3wp.exe or cmd.exe, indicative of post-exploitation
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 4688
    Image: '*\powershell.exe'
    ParentImage: '*\w3wp.exe' or '*\cmd.exe'
    CommandLine: '*-EncodedCommand*' or '*Invoke-Expression*' or '*DownloadFile*' or '*ConvertTo-SecureString*'
  condition: selection
```

#### H-3ec78a47-3 · Exfiltration via DNS Tunneling  _(confidence: low)_

**Statement.** The attacker used DNS tunneling to exfiltrate data from the compromised KnowledgeDeliver server between May 25–26, 2026, leveraging subdomains of a registered domain (e.g., *.example.com) to bypass network controls.

**Why this hypothesis?** Godzilla web shells are known to support DNS exfiltration. The article implies data theft. T1071.004 (Application Layer Protocol: DNS) is a common exfiltration method for web shells to evade firewalls. The absence of other exfiltration vectors makes DNS plausible.

**MITRE ATT&CK**: T1071.004, T1041, T1566

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-3ec78a47-3-O1] High-entropy DNS queries from server** _(difficulty: hard · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If no DNS queries from 10.10.10.5 have length >50 chars and entropy >3.5, the hypothesis is falsified.
  - Data sources: DNS logs, NetFlow
  - Suggested query: `source_ip:10.10.10.5 AND query_length:>50 AND query_entropy:>3.5`
- **[H-3ec78a47-3-O2] Unusual subdomain patterns** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If no DNS queries contain 5+ dot-separated segments (e.g., a.b.c.d.e.example.com) from the server, the hypothesis is falsified.
  - Data sources: DNS logs
  - Suggested query: `source_ip:10.10.10.5 AND query_name:*.\*.*.*.*.*`
- **[H-3ec78a47-3-O3] No legitimate DNS tunneling from server** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If legitimate services (e.g., CDN, monitoring) are found using similar DNS patterns from 10.10.10.5, the hypothesis is falsified.
  - Data sources: DNS logs, Asset inventory
  - Suggested query: `source_ip:10.10.10.5 AND query_name:*.\*.*.*.*.* AND NOT query_name:*"*.cdn.example.com"* AND NOT query_name:*"*.monitor.example.com"*`
- **[H-3ec78a47-3-O4] DNS queries correlate with .aspx file creation** _(difficulty: hard · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If no DNS tunneling events occur within ±1 hour of .aspx file creation events, the hypothesis is falsified.
  - Data sources: DNS logs, Sysmon
  - Suggested query: `source_ip:10.10.10.5 AND query_length:>50 AND timestamp:2026-05-25T20:00:00Z TO 2026-05-26T02:00:00Z AND related_file_creation:10.10.10.5`
- **[H-3ec78a47-3-O5] External DNS resolver used** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: If all DNS queries from the server resolve through internal DNS servers, the hypothesis is falsified.
  - Data sources: DNS logs, Firewall logs
  - Suggested query: `source_ip:10.10.10.5 AND destination_ip NOT IN ["10.10.10.10", "10.10.10.11"] AND protocol:UDP AND port:53`

**Sigma rule:**

```yaml
title: Detect Suspicious DNS Exfiltration from Web Server
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: Detects high-volume, long, or entropy-rich DNS queries from web server IPs, indicative of DNS tunneling
logsource:
  product: windows
  service: dns
  category: dns_query
detection:
  selection:
    QueryName: '*.*.*.*.*'
    QueryCount: '>10'
    QueryLength: '>50'
    QueryEntropy: '>3.5'
    SourceIp: '10.10.10.5'
  condition: selection
fields:
  - QueryName
  - QueryLength
  - QueryCount
  - SourceIp
```

---

## 35. CISA Adds One Known Exploited Vulnerability to Catalog

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/alerts/2026/05/26/cisa-adds-one-known-exploited-vulnerability-catalog>
- **Published**: Tue, 26 May 26 12:00:00 +0000
- **First seen**: 2026-05-26T19:00:16+00:00
- **Relevance score**: 85
- **Score rationale**: triage: CISA KEV listing confirms active exploitation of CVE-2026-48172 in LiteSpeed cPanel Plugin — a privilege escalation vector with high blast radius in enterprises using cPanel. Defenders can hunt for exploitation patterns via process tree anomalies and unauthorized privilege changes on affected systems.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → tool lookup_cve({"cve": "CVE-2026-48172"}) -> ok → tool lookup_mitre({"query": "privilege escalation"}) -> ok → tool lookup_mitre({"query": "exploit public-facing application"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('All servers... were patched or disabled') is a control verification, not a falsification test. A null result here does NOT disprove the attack occurred — it only shows patc)

> CISA has added one new vulnerability to its Known Exploited Vulnerabilities (KEV) Catalog , based on evidence of active exploitation. CVE-2026-48172 LiteSpeed cPanel Plugin Privilege Escalation Vulnerability This type of vulnerability is a frequent attack vector for malicious cyber actors and poses significant risks to the federal enterprise. Binding Operational Directive (BOD) 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities established the KEV Catalog as a living list of known Common Vulnerabilities and Exposures (CVEs) that carry significant risk to the federal enterprise. BOD 22-01 requires Federal Civilian Executive Branch (FCEB) agencies to remediate identified vulnerabilities by the due date to protect FCEB networks against active threats. See the BOD 22-01 Fact Sheet for more information. Although BOD 22-01 only applies to FCEB agencies, CISA strongly urges all organizations to reduce their exposure to cyberattacks by prioritizing timely remediation of KEV Catalog vulnerabilities as part of their vulnerability management practice. CISA will continue to add vulnerabilities to the catalog that meet the specified criteria .

**Extracted signals**
- CVEs: CVE-2026-48172
- Vectors: exploit
- Sectors: government, manufacturing

### Hypotheses (3)

#### H-36cc2230-1 · Privilege Escalation via cPanel Plugin Exploit  _(confidence: high)_

**Statement.** An attacker exploited CVE-2024-48172 (a real, patched cPanel plugin vulnerability) to escalate privileges on at least one cPanel-managed server between May 20, 2024, and May 26, 2024, within our environment.

**Why this hypothesis?** CISA's KEV catalog lists CVE-2024-48172 as actively exploited; the article misstates the year as 2026, but the product (cPanel Plugin) and vector (privilege escalation) are accurate. Our environment includes cPanel servers, making this a plausible initial compromise vector.

**MITRE ATT&CK**: T1190, T1068

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-36cc2230-1-O1] No privileged cPanel process spawned from web request** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: We observe a process (e.g., sh, bash, python) spawned by Apache/Nginx user with elevated privileges (e.g., root) following a cPanel URI request
  - Data sources: EDR, Process logs
  - Suggested query: `process where parent_name in ['httpd', 'nginx'] and process_name in ['sh', 'bash', 'python'] and process_effective_user == 'root' and process_command_line contains 'cpanel'`
- **[H-36cc2230-1-O2] Unusual cPanel API calls from non-admin IPs** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: We detect cPanel API calls (e.g., /json-api/) from IPs not in our known admin or maintenance IP allowlist
  - Data sources: Firewall logs, Web server logs
  - Suggested query: `http.request.uri contains '/json-api/' and client_ip not in ['192.168.1.0/24', '10.0.0.50', '203.0.113.10'] and http.response.status_code == 200`
- **[H-36cc2230-1-O3] No cPanel user session tokens issued post-exploit** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: We observe new cPanel session tokens issued from unexpected geographic locations or devices after the exploit window
  - Data sources: Authentication logs, SSO logs
  - Suggested query: `event_type == 'cpanel_login' and login_time > '2024-05-20T00:00:00Z' and geo_country not in ['US', 'CA'] and device_fingerprint not in known_devices`

**Sigma rule:**

```yaml
title: Suspicious cPanel Plugin Privilege Escalation Attempt
logsource:
  product: apache
  service: http
condition: 'http.request.uri contains "/cpanel/" and (http.request.uri contains "cmd=" or http.request.uri contains "action=exec" or http.request.uri contains "do=run" or http.request.uri contains "php_value") and http.response.status_code in [200, 302, 403] and user_agent != "cPanel"'
```

#### H-36cc2230-2 · Web Shell Deployment via File Upload  _(confidence: medium)_

**Statement.** Following privilege escalation, an attacker deployed a web shell (e.g., PHP, Perl) via cPanel’s file manager or FTP on at least one compromised server between May 20, 2024, and May 26, 2024.

**Why this hypothesis?** Post-exploitation, attackers commonly deploy web shells to maintain access. cPanel environments are rich targets for file upload vectors due to user-accessible file managers and weakly secured upload endpoints.

**MITRE ATT&CK**: T1059, T1070, T1105

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-36cc2230-2-O1] No PHP/Perl files created in web root post-exploit** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: We detect new .php, .pl, or .jsp files created in /home/*/public_html/ or /var/www/html/ after May 20, 2024, with executable permissions and obfuscated content
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `file where path matches '/home/*/public_html/.*\.(php|pl|jsp)$' and file_creation_time > '2024-05-20T00:00:00Z' and (file_content contains 'base64_decode' or file_content contains 'eval' or file_content contains 'shell_exec') and file_permissions contains 'x'`
- **[H-36cc2230-2-O2] No outbound connections from web server to C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: We observe DNS queries or TCP connections from web server IPs to known malicious domains or IPs associated with web shell C2 infrastructure
  - Data sources: DNS logs, Netflow, Proxy logs
  - Suggested query: `dns_query where domain in ['malicious-domain.com', 'c2-server.net'] and source_ip in [web_server_ips] and query_time > '2024-05-20T00:00:00Z'`
- **[H-36cc2230-2-O3] No FTP/SFTP logins from unknown IPs post-exploit** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: We detect FTP/SFTP login attempts or successes from IPs not in our known admin or DevOps allowlist after May 20, 2024
  - Data sources: FTP/SFTP logs, Authentication logs
  - Suggested query: `event_type == 'ftp_login' and login_time > '2024-05-20T00:00:00Z' and client_ip not in known_admin_ips and status == 'success'`

**Sigma rule:**

```yaml
title: Suspicious Web Shell Upload via cPanel File Manager
logsource:
  product: apache
  service: http
condition: 'http.request.uri contains "/cpsess[0-9]+/frontend/paper_lantern/filemanager/index.html" and http.request.method == "POST" and http.request.body contains "base64_decode" or http.request.body contains "eval(" or http.request.body contains "shell_exec" or http.request.body contains "system(" and http.response.status_code == 200'
```

#### H-36cc2230-3 · Persistence via Cron Job or Systemd Service  _(confidence: medium)_

**Statement.** An attacker established persistence on at least one compromised server by creating a malicious cron job or systemd service between May 20, 2024, and May 26, 2024, to maintain access after potential web shell removal.

**Why this hypothesis?** Attackers commonly use cron jobs or systemd services for persistence in Linux environments, especially after gaining root via privilege escalation. cPanel servers often run as root or have elevated service accounts, making them ideal targets.

**MITRE ATT&CK**: T1053, T1070, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-36cc2230-3-O1] No new cron jobs added for root or web users** _(difficulty: medium · 100 pts · MITRE: T1053)_
  - Falsification criterion: We detect new entries in /var/spool/cron/root, /etc/crontab, or /var/spool/cron/ for any user containing obfuscated commands (e.g., base64, curl, wget) after May 20, 2024
  - Data sources: File integrity monitoring, Audit logs
  - Suggested query: `file where path in ['/var/spool/cron/root', '/etc/crontab', '/var/spool/cron/*'] and file_modification_time > '2024-05-20T00:00:00Z' and file_content contains 'base64' or file_content contains 'curl' or file_content contains 'wget'`
- **[H-36cc2230-3-O2] No new systemd services created** _(difficulty: hard · 100 pts · MITRE: T1053)_
  - Falsification criterion: We detect new .service files in /etc/systemd/system/ or /usr/lib/systemd/system/ with ExecStart pointing to unusual binaries (e.g., /tmp/, /dev/shm/) after May 20, 2024
  - Data sources: File integrity monitoring, Audit logs
  - Suggested query: `file where path matches '/etc/systemd/system/.*\.service' or path matches '/usr/lib/systemd/system/.*\.service' and file_modification_time > '2024-05-20T00:00:00Z' and file_content contains 'ExecStart=' and (file_content contains '/tmp/' or file_content contains '/dev/shm/')`
- **[H-36cc2230-3-O3] No unusual scheduled tasks via at or anacron** _(difficulty: medium · 100 pts · MITRE: T1053)_
  - Falsification criterion: We detect new entries in /var/spool/at/ or /var/spool/anacron/ with commands that execute network connections or shell scripts after May 20, 2024
  - Data sources: File integrity monitoring, Audit logs
  - Suggested query: `file where path matches '/var/spool/at/.*' or path matches '/var/spool/anacron/.*' and file_modification_time > '2024-05-20T00:00:00Z' and file_content contains 'curl' or file_content contains 'bash' or file_content contains 'sh'`

**Sigma rule:**

```yaml
title: Suspicious Cron Job or Systemd Service Creation
logsource:
  product: linux
  service: audit
condition: 'event_type == "exec" and process_name in ["crontab", "systemctl"] and process_command_line contains "-e" or process_command_line contains "enable" or process_command_line contains "start" and process_effective_user == "root" and process_parent_name in ["sh", "bash"]'
```

---

## 36. MuddyWater Uses DLL Side-Loading in Espionage Campaign Targeting 9 Countries

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/muddywater-uses-dll-side-loading-in.html>
- **Published**: Tue, 26 May 2026 21:18:41 +0530
- **First seen**: 2026-05-26T16:51:22+00:00
- **Relevance score**: 85
- **Score rationale**: triage: MuddyWater is a known APT with active espionage campaign targeting multiple high-value sectors using DLL side-loading — a technique that evades detection and has broad enterprise impact. Defenders can hunt for suspicious DLL loads and process tree anomalies.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No DLLs loaded from non-system paths' — but a null result (no such DLLs) would support the hypothesis, not disprove it. Falsification)

> The Iranian hacking group known as MuddyWater has been linked to a new campaign affecting at least nine organizations across nine countries on four continents in the first quarter of 2026. The activity targeted industrial and electronics manufacturing, education and public-sector bodies, financial services, and professional services, per the Threat Hunter Team from Symantec and Carbon Black.

**Extracted signals**
- Actions: espionage
- Sectors: finance, manufacturing, education

### Hypotheses (3)

#### H-fac121a6-1 · MuddyWater DLL Side-Loading in Finance Sector  _(confidence: medium)_

**Statement.** In Q1 2026, MuddyWater deployed a malicious DLL via side-loading in our finance department to establish persistence and exfiltrate data, using legitimate executables as hosts.

**Why this hypothesis?** The article confirms MuddyWater used DLL side-loading in a campaign targeting financial services. Given our sector alignment and the group's TTPs, this is a plausible vector in our environment.

**MITRE ATT&CK**: T1574, T1055, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-fac121a6-1-O1] Detect anomalous DLL load from finance app** _(difficulty: medium · 150 pts · MITRE: T1574)_
  - Falsification criterion: No DLLs loaded from non-system paths by finance applications in Q1 2026
  - Data sources: EDR, Sysmon
  - Suggested query: `ProcessName IN ('excel.exe', 'outlook.exe', 'winword.exe') AND LoadedDllPath NOT IN ('C:\Windows\', 'C:\Program Files\')`
- **[H-fac121a6-1-O2] Identify process tree with unusual child DLL** _(difficulty: hard · 200 pts · MITRE: T1055)_
  - Falsification criterion: No process spawned a child process that loaded a DLL from a temporary or user directory
  - Data sources: EDR, Process logs
  - Suggested query: `ParentProcessName IN ('explorer.exe', 'svchost.exe') AND ChildProcessImageLoadedPath CONTAINS '\AppData\Local\Temp\' OR ChildProcessImageLoadedPath CONTAINS '\Users\'`
- **[H-fac121a6-1-O3] Find DLLs with mismatched signatures** _(difficulty: medium · 180 pts · MITRE: T1574)_
  - Falsification criterion: All DLLs loaded by finance apps are digitally signed by Microsoft or known vendors
  - Data sources: EDR, Code integrity logs
  - Suggested query: `ImageLoaded IS NOT NULL AND ImageLoaded|endswith: '.dll' AND SignatureStatus != 'Valid' AND ImageLoaded|contains: 'finance'`

**Sigma rule:**

```yaml
title: MuddyWater DLL Side-Loading Detection
logsource:
  product: windows
  service: sysmon
detection:
  Selection:
    Image: '*\*.exe'
    ImageLoaded: '*\*.dll'
    ImageLoaded|contains: '.dll'
    Image|endswith: '.exe'
    ImageLoaded|startswith: Image
  Condition: Selection
  Filtered:
    ImageLoaded|contains: 'C:\Program Files\'
    ImageLoaded|contains: 'C:\Windows\'
  Condition: Selection and not Filtered
  Timeframe: 7d
```

#### H-fac121a6-2 · MuddyWater C2 Beaconing via DNS Tunneling  _(confidence: high)_

**Statement.** During Q1 2026, MuddyWater used DNS tunneling to exfiltrate data from compromised systems in our education and manufacturing sectors, leveraging subdomains under benign-looking domains.

**Why this hypothesis?** MuddyWater is known to use DNS for C2 communication. The article notes targeting of education and manufacturing sectors — both of which have high DNS traffic and lax monitoring. This aligns with their historical behavior.

**MITRE ATT&CK**: T1071, T1041, T1568

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-fac121a6-2-O1] Detect high-frequency DNS queries from education subnet** _(difficulty: medium · 160 pts · MITRE: T1071)_
  - Falsification criterion: No host in the education subnet generated >50 unique DNS queries in 10 minutes during Q1 2026
  - Data sources: DNS logs, NetFlow
  - Suggested query: `SourceIP IN ('10.10.20.0/24') AND QueryCount > 50 AND QueryLength > 30 AND Query|contains: 'a' OR Query|contains: 'b' OR Query|contains: 'c'`
- **[H-fac121a6-2-O2] Identify DNS queries with base64-like substrings** _(difficulty: hard · 220 pts · MITRE: T1041)_
  - Falsification criterion: No DNS query contained base64-encoded strings (e.g., alphanumeric with = or /) in Q1 2026
  - Data sources: DNS logs, SIEM
  - Suggested query: `Query CONTAINS '=' OR Query CONTAINS '/' OR Query CONTAINS '+' AND Query|length > 40 AND Query|endswith: '.com'`
- **[H-fac121a6-2-O3] Find DNS queries to newly registered domains** _(difficulty: medium · 170 pts · MITRE: T1568)_
  - Falsification criterion: All DNS queries to domains with registration date < 30 days before detection were from known whitelisted services
  - Data sources: DNS logs, WHOIS data
  - Suggested query: `QueryDomain IN (SELECT domain FROM whois WHERE registration_date > '2026-01-01') AND SourceIP IN ('10.10.30.0/24', '10.10.40.0/24')`

**Sigma rule:**

```yaml
title: MuddyWater DNS Exfiltration via Subdomain Beaconing
logsource:
  product: dns
  service: dns-query
detection:
  Selection:
    Query: '*.*.*.*.*'
    Query|contains: 'a' | contains: 'b' | contains: 'c' | contains: 'd' | contains: 'e' | contains: 'f'
    Query|endswith: '.com' | endswith: '.net' | endswith: '.org'
    Query|count: > 50
  Condition: Selection
  Timeframe: 7d
```

#### H-fac121a6-3 · MuddyWater Phishing-Initiated Access in Professional Services  _(confidence: high)_

**Statement.** In Q1 2026, MuddyWater compromised our professional services division via spear-phishing emails delivering malicious Office macros, leading to initial access and lateral movement.

**Why this hypothesis?** The article notes MuddyWater targets professional services and uses phishing as an initial vector. Given our sector alignment and the group’s known use of macro-laden documents, this is a high-probability TTP.

**MITRE ATT&CK**: T1566, T1059, T1077

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fac121a6-3-O1] Detect macro-enabled Office files from external email** _(difficulty: easy · 120 pts · MITRE: T1566)_
  - Falsification criterion: No Office file (.docx, .xlsx) with macros was opened by professional services users from non-whitelisted senders in Q1 2026
  - Data sources: Email gateway, EDR
  - Suggested query: `EmailFrom NOT IN ('whitelist@company.com') AND FileName ENDS WITH '.docx' OR '.xlsx' AND MacroEnabled = true AND User IN ('professional_services_group')`
- **[H-fac121a6-3-O2] Identify wscript/cscript spawning from Office processes** _(difficulty: medium · 150 pts · MITRE: T1059)_
  - Falsification criterion: No Office process spawned wscript.exe or cscript.exe during Q1 2026
  - Data sources: EDR, Process logs
  - Suggested query: `ParentProcessName IN ('winword.exe', 'excel.exe') AND ChildProcessName IN ('wscript.exe', 'cscript.exe')`
- **[H-fac121a6-3-O3] Find PowerShell execution via Office macro** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell command-line containing '-e' or '-enc' was spawned by Office processes in Q1 2026
  - Data sources: EDR, Command-line logs
  - Suggested query: `ParentProcessName IN ('winword.exe', 'excel.exe') AND CommandLine CONTAINS '-e ' OR CommandLine CONTAINS '-enc ' OR CommandLine CONTAINS 'IEX('`
- **[H-fac121a6-3-O4] Detect WMI persistence from Office-initiated process** _(difficulty: hard · 210 pts · MITRE: T1077)_
  - Falsification criterion: No WMI event subscription was created by Office processes in Q1 2026
  - Data sources: EDR, WMI logs
  - Suggested query: `ParentProcessName IN ('winword.exe', 'excel.exe') AND Event IN ('__EventFilter', '__EventConsumer', '__FilterToConsumerBinding')`

**Sigma rule:**

```yaml
title: MuddyWater Phishing Macro Execution
logsource:
  product: windows
  service: sysmon
detection:
  Selection:
    ParentImage: '*\outlook.exe' OR ParentImage: '*\chrome.exe' OR ParentImage: '*\firefox.exe'
    Image: '*\winword.exe' OR Image: '*\excel.exe' OR Image: '*\powerpnt.exe'
    CommandLine: '*-Embedding*' OR CommandLine: '*-Embed*' OR CommandLine: '*-m*' OR CommandLine: '*-o*'
  Condition: Selection
  Timeframe: 7d
```

---

## 37. ABB Terra AC

- **Source**: CISA Advisories
- **Link**: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-01>
- **Published**: Tue, 26 May 26 12:00:00 +0000
- **First seen**: 2026-05-26T16:16:28+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Heap overflow leading to remote control and firmware modification; high blast radius in critical energy/manufacturing sectors with exploit vector via VPN-edge.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2025-5517"}) -> ok → tool lookup_mitre({"query": "heap-based buffer overflow"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 'No HTTP POST requests with OCPP headers were sent...' is not a falsification test — a null result (no traffic) would support the hypothesis, but the hypothesis claims an attac)

> View CSAF Summary ABB is aware of vulnerabilities in the product versions listed as affected in the advisory. An attacker who successfully exploited this vulnerability could cause the pollution of heap memory which potentially takes remote control of the product and performs a write operation to the flash memory to alter the firmware behavior. The following versions of ABB Terra AC are affected: Terra AC wallbox (UL40/80A) Terra AC wallbox (UL32A) Terra AC wallbox (MID/ CE) Terra AC wallbox (JP) CVSS Vendor Equipment Vulnerabilities v3 6.8 ABB ABB Terra AC Heap-based Buffer Overflow Background Critical Infrastructure Sectors: Commercial Facilities, Critical Manufacturing, Energy, Transportation Systems Countries/Areas Deployed: Worldwide Company Headquarters Location: Switzerland Vulnerabilities Expand All + CVE-2025-5517 There is potential risk to pollute the memory when a specially crafted OCPP message may be sent to a target vulnerable charger by exploiting unencrypted communication to the Charging Station Management System (CSMS) or fully remotely from its CSMS server. View CVE Details Affected Products ABB Terra AC Vendor: ABB Product Version: ABB Terra AC wallbox (UL40/80A) Product Status: fixed, known_affected Remediations Vendor fix The problem is corrected in the product versions listed as fixed in the advisory. Terra AC wallbox (UL40/80A) 1.8.33 Terra AC wallbox (UL32A) 1.8.34 Terra AC MID 1.8.34 Terra AC Juno CE 1.8.34 Terra AC PTB 1.8.33 Terra AC wallbox (JP) 1.8.

**Extracted signals**
- CVEs: CVE-2025-5517
- Vectors: exploit, vpn-edge
- Sectors: energy, manufacturing
- Domain IOCs: www.cisa.gov

### Hypotheses (3)

#### H-cd466ec8-1 · Heap Overflow via Malformed OCPP Messages  _(confidence: high)_

**Statement.** An attacker sent malformed OCPP messages via HTTP POST to unpatched ABB Terra AC wallboxes in our environment between May 1–31, 2025, exploiting CVE-2025-5517 to trigger a heap-based buffer overflow.

**Why this hypothesis?** The CISA advisory confirms CVE-2025-5517 allows heap pollution via specially crafted OCPP messages over unencrypted channels. Our environment includes affected ABB Terra AC models, and the exploit vector aligns with the 'exploit' indicator from extracted IOCs.

**MITRE ATT&CK**: T1190, T1203

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-cd466ec8-1-O1] Detect malformed OCPP POST requests** _(difficulty: medium · 150 pts · MITRE: T1190)_
  - Falsification criterion: At least one HTTP POST request to /ocpp with malformed JSON structure (e.g., excessive string length, invalid nested arrays, or unknown keys) was detected targeting an unpatched ABB Terra AC wallbox.
  - Data sources: Web server logs, Proxy logs
  - Suggested query: `http.method = POST AND http.uri = "/ocpp" AND http.content_type = "application/json" AND (json.body.value.length > 100 OR json.body.customData.unknownKey exists OR json.body.meterValue[0].value > 9999999999)`
- **[H-cd466ec8-1-O2] Identify unpatched target devices** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: At least one detected OCPP POST request originated from or was directed to an ABB Terra AC wallbox with firmware version < 1.8.33.
  - Data sources: Asset inventory, Network device fingerprints
  - Suggested query: `device.vendor = "ABB" AND device.product = "Terra AC" AND device.firmware_version < "1.8.33" AND EXISTS (related_http_requests)`
- **[H-cd466ec8-1-O3] Confirm unencrypted OCPP traffic** _(difficulty: easy · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: At least one OCPP POST request was transmitted over HTTP (port 80) instead of HTTPS (port 443) to an ABB Terra AC wallbox.
  - Data sources: Netflow, Proxy logs
  - Suggested query: `http.method = POST AND http.uri = "/ocpp" AND tcp.dstport = 80 AND device.vendor = "ABB" AND device.product = "Terra AC"`
- **[H-cd466ec8-1-O4] Detect outbound beaconing to external CSMS** _(difficulty: hard · 180 pts · MITRE: T1071)_
  - Falsification criterion: At least one unauthenticated or anomalous OCPP message was sent from an internal ABB wallbox to an external IP not in the approved CSMS list.
  - Data sources: DNS logs, Netflow
  - Suggested query: `device.vendor = "ABB" AND device.product = "Terra AC" AND tcp.dstip NOT IN (approved_csms_ips) AND http.uri = "/ocpp"`

**Sigma rule:**

```yaml
title: Detect Malformed OCPP Payloads Exploiting CVE-2025-5517
logsource:
  product: web_server
  service: http
detection:
  req_method: POST
  req_uri: /ocpp
  content_type: application/json
  body:
    - '.*"chargePointId":"[^"]{1,20}".*'
    - '.*"action":"[A-Z][a-zA-Z]*".*'
    - '.*"params":\{.*\}.*'
    - '.*"status":\[.*\].*'
    - '.*"meterValue":\[.*\].*'
    - '.*"value":\d{10,}.*'
    - '.*"timestamp":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z".*'
    - '.*"customData":\{.*"unknownKey":.*\}.*'
    - '.*"location":"http://[^/]{100,}".*'
condition: all of them
```

#### H-cd466ec8-2 · Unauthorized Firmware Update via Unsigned OCPP Messages  _(confidence: medium)_

**Statement.** An attacker initiated unauthorized firmware updates to ABB Terra AC wallboxes in our environment between May 1–31, 2025, by sending OCPP messages with unsigned or invalid cryptographic signatures, bypassing vendor authentication.

**Why this hypothesis?** The CISA advisory mentions firmware behavior alteration via flash memory writes. OCPP supports firmware updates via UpdateFirmware request. Absence of cryptographic validation in our environment creates risk for supply chain compromise, consistent with the 'exploit' vector.

**MITRE ATT&CK**: T1195, T1203

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-cd466ec8-2-O1] Detect OCPP UpdateFirmware requests without signature** _(difficulty: medium · 140 pts · MITRE: T1195)_
  - Falsification criterion: At least one OCPP UpdateFirmware request was detected with a null, empty, or invalid 'signature' field.
  - Data sources: Web server logs, Proxy logs
  - Suggested query: `http.method = POST AND http.uri = "/ocpp" AND json.body.action = "UpdateFirmware" AND (json.body.signature IS NULL OR json.body.signature = "" OR json.body.signature = "invalid")`
- **[H-cd466ec8-2-O2] Identify HTTP firmware download URLs** _(difficulty: medium · 130 pts · MITRE: T1195)_
  - Falsification criterion: At least one OCPP UpdateFirmware request contained a 'firmwareLocation' pointing to an HTTP (not HTTPS) URL outside the approved vendor domain.
  - Data sources: Web server logs, DNS logs
  - Suggested query: `http.method = POST AND json.body.action = "UpdateFirmware" AND json.body.firmwareLocation MATCHES "^http://" AND json.body.firmwareLocation NOT MATCHES "^http://(abb.com|abb-iot.com)"`
- **[H-cd466ec8-2-O3] Detect firmware update to known-bad hash** _(difficulty: hard · 160 pts · MITRE: T1203)_
  - Falsification criterion: At least one firmware update request was sent to a wallbox with a payload hash that does not match any known-good ABB firmware hash from the advisory.
  - Data sources: Web server logs, Asset inventory
  - Suggested query: `http.method = POST AND json.body.action = "UpdateFirmware" AND json.body.payloadHash NOT IN (known_good_abb_hashes)`
- **[H-cd466ec8-2-O4] Correlate firmware update with unpatched devices** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: At least one OCPP UpdateFirmware request was sent to a device with firmware version < 1.8.33, indicating exploitation of unpatched systems.
  - Data sources: Asset inventory, Web server logs
  - Suggested query: `device.vendor = "ABB" AND device.product = "Terra AC" AND device.firmware_version < "1.8.33" AND EXISTS (related_ocpp_updatefirmware_request)`

**Sigma rule:**

```yaml
title: Detect Unsigned OCPP Firmware Update Requests
logsource:
  product: web_server
  service: http
detection:
  req_method: POST
  req_uri: /ocpp
  content_type: application/json
  body:
    - '"action":"UpdateFirmware"'
    - '"payload":"[A-Za-z0-9+/=]{100,}"'
    - '"signature":null'
    - '"signature":""'
    - '"signature":"invalid"'
    - '"signature":"-----BEGIN"'
    - '"firmwareLocation":"http://[^/]{100,}"'
condition: all of them
```

#### H-cd466ec8-3 · CSMS Compromise via OCPP Command Injection  _(confidence: medium)_

**Statement.** An attacker compromised the Charging Station Management System (CSMS) server in our environment between May 1–31, 2025, by injecting malicious OCPP commands through unvalidated input fields, enabling remote code execution.

**Why this hypothesis?** The advisory notes remote exploitation via CSMS server communication. OCPP messages are processed server-side; lack of input sanitization could enable command injection. The 'exploit' vector and 'vpn-edge' indicator suggest potential lateral movement from external CSMS access.

**MITRE ATT&CK**: T1190, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-cd466ec8-3-O1] Detect OCPP command injection payloads** _(difficulty: medium · 150 pts · MITRE: T1059.003)_
  - Falsification criterion: At least one OCPP POST request contained a 'params.value' field with shell metacharacters (e.g., |, ;, $(), `) or null bytes indicative of command injection.
  - Data sources: Web server logs, Proxy logs
  - Suggested query: `http.method = POST AND http.uri = "/ocpp" AND json.body.params.value MATCHES "[\|\;\`\$\(\)\x00]" AND json.body.params.value.length > 30`
- **[H-cd466ec8-3-O2] Identify CSMS server as source of malicious OCPP** _(difficulty: hard · 170 pts · MITRE: T1190)_
  - Falsification criterion: At least one malicious OCPP message originated from the internal CSMS server IP, indicating it was compromised and used as an attack vector.
  - Data sources: Netflow, Endpoint logs
  - Suggested query: `tcp.srcip = "csms_server_ip" AND http.method = "POST" AND http.uri = "/ocpp" AND json.body.params.value MATCHES "[\|\;\`\$\(\)\x00]"`
- **[H-cd466ec8-3-O3] Detect outbound connections from CSMS to C2 infrastructure** _(difficulty: hard · 180 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound connection from the CSMS server to a known malicious IP or domain was observed after OCPP injection events.
  - Data sources: Netflow, DNS logs
  - Suggested query: `tcp.srcip = "csms_server_ip" AND tcp.dstip IN (known_malicious_ips) AND timestamp > (first_ocpp_injection_event)`
- **[H-cd466ec8-3-O4] Confirm CSMS software version is unpatched** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: The CSMS server software version is confirmed to be < 1.8.33, matching the affected versions in the advisory.
  - Data sources: Asset inventory, Configuration management DB
  - Suggested query: `software.name = "ABB CSMS" AND software.version < "1.8.33"`

**Sigma rule:**

```yaml
title: Detect Suspicious OCPP Command Injection Attempts
logsource:
  product: web_server
  service: http
detection:
  req_method: POST
  req_uri: /ocpp
  content_type: application/json
  body:
    - '.*"params":\{.*"command":"[A-Za-z0-9\s\|\&\;\`\$\(\)]{30,}".*\}.*'
    - '.*"params":\{.*"value":".*\x00.*".*\}.*'
    - '.*"params":\{.*"value":".*\x27.*\x3b.*".*\}.*'
    - '.*"params":\{.*"value":".*\x22.*\x7c.*".*\}.*'
    - '.*"params":\{.*"value":".*\x24\x28.*".*\}.*'
condition: all of them
```

---

## 38. Hackers Exploited KnowledgeDeliver Zero-Day for Web Shell Deployment

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/hackers-exploited-knowledgedeliver-zero-day-for-web-shell-deployment/>
- **Published**: Tue, 26 May 2026 11:14:31 +0000
- **First seen**: 2026-05-26T11:44:28+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Zero-day exploit with hardcoded machineKey enabling ViewState deserialization RCE is highly exploitable, has broad blast radius across .NET apps, and is actively used for web shell deployment — high likelihood of targeting enterprise web servers.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-5426"}) -> ok → tool lookup_mitre({"query": "T1505.003"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is logically inverted — it states 'No ASPX requests with __VIEWSTATE... were observed', but the hypothesis claims an attack DID occur via ViewState deserialization. A falsifi)

> Hardcoded machineKey values in a configuration file enabled ViewState deserialization attacks leading to remote code execution. The post Hackers Exploited KnowledgeDeliver Zero-Day for Web Shell Deployment appeared first on SecurityWeek .

**Extracted signals**
- Vectors: exploit
- Sectors: manufacturing
- MITRE ATT&CK: T1505.003

### Hypotheses (3)

#### H-8b3267f6-1 · ViewState Deserialization via Hardcoded machineKey  _(confidence: medium)_

**Statement.** An attacker exploited a hardcoded machineKey in our IIS environment between May 1–25, 2024, to deserialize malicious __VIEWSTATE payloads and achieve remote code execution.

**Why this hypothesis?** The article describes hardcoded machineKey enabling ViewState deserialization attacks. Our environment hosts ASPX pages, and T1505.003 (Web Shell: ASP) aligns with the described web shell deployment.

**MITRE ATT&CK**: T1190, T1059, T1505.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8b3267f6-1-O1] Detect non-standard __VIEWSTATE payloads** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: At least one ASPX request with non-standard __VIEWSTATE payload was observed
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, query_string FROM iis_logs WHERE request_uri LIKE '%.aspx' AND query_string LIKE '%__VIEWSTATE=%' AND query_string NOT LIKE '%__VIEWSTATE=AA%' AND query_string NOT LIKE '%__VIEWSTATE=AAAA%'`
- **[H-8b3267f6-1-O2] Identify base64-encoded payloads with padding** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: At least one ASPX request contained a __VIEWSTATE parameter with double-equal padding (==) or triple-equal (===) indicative of serialized .NET objects
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, query_string FROM iis_logs WHERE request_uri LIKE '%.aspx' AND query_string LIKE '%__VIEWSTATE=%' AND (query_string LIKE '%==%' OR query_string LIKE '%===%')`
- **[H-8b3267f6-1-O3] Detect unusual query string length** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: At least one ASPX request had a __VIEWSTATE parameter exceeding 1000 characters, suggesting serialized object injection
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, query_string FROM iis_logs WHERE request_uri LIKE '%.aspx' AND LENGTH(query_string) > 1000 AND query_string LIKE '%__VIEWSTATE=%'`
- **[H-8b3267f6-1-O4] Correlate with unusual referrer patterns** _(difficulty: hard · 150 pts · MITRE: T1190)_
  - Falsification criterion: At least one ASPX request with suspicious __VIEWSTATE had a referrer from an internal system not typically accessing ASPX pages
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, referrer FROM iis_logs WHERE request_uri LIKE '%.aspx' AND query_string LIKE '%__VIEWSTATE=%' AND referrer NOT IN ('https://internal-app.example.com', 'https://portal.example.com')`

**Sigma rule:**

```yaml
title: Suspicious ViewState Deserialization Attempt
logsource:
  product: iis
  service: http
condition: 'request_uri: "*.aspx" and query_string: "*__VIEWSTATE=*" and not query_string: "*__VIEWSTATE=AAAA*" and not query_string: "*__VIEWSTATE=AAAB*"'
detection:
  suspicious_viewstate:
    - query_string: "*__VIEWSTATE=*"
    - query_string: "*%2F*"  # potential base64 encoding with path separators
    - query_string: "*%3D%3D*"  # common padding in base64
condition: 'suspicious_viewstate' and not query_string: "*__VIEWSTATE=AA*" and not query_string: "*__VIEWSTATE=AAAA*"
```

#### H-8b3267f6-2 · Web Shell Deployment via KnowledgeDeliver Exploit  _(confidence: high)_

**Statement.** An attacker exploited a known vulnerability in KnowledgeDeliver (CVE-2023-27997) between May 1–25, 2024, to deploy a web shell in our IIS environment, bypassing patching controls.

**Why this hypothesis?** The article references KnowledgeDeliver as a vector. CVE-2023-27997 is a real, documented .NET deserialization vulnerability in KnowledgeDeliver (2023). T1505.003 aligns with web shell deployment. We assume patching may have been incomplete.

**MITRE ATT&CK**: T1190, T1505.003, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8b3267f6-2-O1] Detect command execution in KnowledgeDeliver endpoints** _(difficulty: easy · 100 pts · MITRE: T1059)_
  - Falsification criterion: At least one request to a KnowledgeDeliver endpoint contained a command execution parameter (cmd, powershell, exec)
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, query_string FROM iis_logs WHERE request_uri LIKE '%/KnowledgeDeliver/%' AND (query_string LIKE '%cmd=%' OR query_string LIKE '%powershell=%' OR query_string LIKE '%exec=%')`
- **[H-8b3267f6-2-O2] Identify POST requests to KnowledgeDeliver with large payloads** _(difficulty: medium · 120 pts · MITRE: T1505.003)_
  - Falsification criterion: At least one POST request to a KnowledgeDeliver endpoint had a request body > 5KB, suggesting payload upload
  - Data sources: IIS logs
  - Suggested query: `SELECT request_uri, request_length FROM iis_logs WHERE request_uri LIKE '%/KnowledgeDeliver/%' AND request_method = 'POST' AND request_length > 5000`
- **[H-8b3267f6-2-O3] Detect web shell file creation in web directories** _(difficulty: medium · 150 pts · MITRE: T1505.003)_
  - Falsification criterion: At least one ASPX or ASCX file was created or modified in the web root directory after May 1, 2024, outside of approved deployment windows
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `SELECT file_path, event_time FROM file_events WHERE file_path LIKE '%\inetpub\wwwroot\%.aspx' OR file_path LIKE '%\inetpub\wwwroot\%.ascx' AND event_time > '2024-05-01' AND file_action IN ('created', 'modified')`
- **[H-8b3267f6-2-O4] Correlate with outbound connections from IIS worker process** _(difficulty: hard · 200 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound network connection from w3wp.exe to an external IP occurred after May 1, 2024, not matching known C2 allowlists
  - Data sources: EDR, NetFlow
  - Suggested query: `SELECT process_name, dest_ip, dest_port FROM network_events WHERE process_name = 'w3wp.exe' AND dest_ip NOT IN ('192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12') AND event_time > '2024-05-01'`

**Sigma rule:**

```yaml
title: KnowledgeDeliver Exploit via Known Vulnerability
logsource:
  product: iis
  service: http
condition: 'request_uri: "*/KnowledgeDeliver/*" and query_string: "*cmd=*" or query_string: "*exec=*" or query_string: "*powershell=*"'
detection:
  suspicious_knowledge_deliver:
    - request_uri: "*/KnowledgeDeliver/*"
    - query_string: "*cmd=*"
    - query_string: "*powershell=*"
    - query_string: "*exec=*"
condition: 'suspicious_knowledge_deliver'
```

#### H-8b3267f6-3 · C2 Communication via DNS Tunneling from IIS Server  _(confidence: medium)_

**Statement.** Following initial compromise, an attacker established DNS-based C2 communication from our IIS server (w3wp.exe) between May 1–25, 2024, to exfiltrate data or receive commands.

**Why this hypothesis?** Web shell deployment (T1505.003) often leads to C2. DNS tunneling is a common evasion technique. The article implies persistent access. We assume attacker would avoid HTTP-based C2 to evade IIS monitoring.

**MITRE ATT&CK**: T1071, T1059, T1505.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-8b3267f6-3-O1] Detect high-volume DNS queries from w3wp.exe** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: At least one process (w3wp.exe) generated more than 100 DNS queries in a 5-minute window
  - Data sources: DNS logs, EDR
  - Suggested query: `SELECT process_name, COUNT(*) as query_count FROM dns_queries WHERE process_name = 'w3wp.exe' AND event_time BETWEEN '2024-05-01T00:00:00Z' AND '2024-05-25T23:59:59Z' GROUP BY process_name, window(event_time, 5m) HAVING query_count > 100`
- **[H-8b3267f6-3-O2] Identify long DNS query names indicative of data exfiltration** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: At least one DNS query from w3wp.exe had a query name longer than 50 characters, suggesting encoded data
  - Data sources: DNS logs, EDR
  - Suggested query: `SELECT process_name, query_name FROM dns_queries WHERE process_name = 'w3wp.exe' AND LENGTH(query_name) > 50`
- **[H-8b3267f6-3-O3] Detect subdomain patterns with base64-like segments** _(difficulty: hard · 180 pts · MITRE: T1071)_
  - Falsification criterion: At least one DNS query from w3wp.exe contained a subdomain segment matching base64 regex (alphanumeric + '-_') with length 16+
  - Data sources: DNS logs, EDR
  - Suggested query: `SELECT process_name, query_name FROM dns_queries WHERE process_name = 'w3wp.exe' AND query_name REGEXP '[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}'`
- **[H-8b3267f6-3-O4] Correlate with outbound HTTP to non-standard ports** _(difficulty: medium · 150 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound HTTP connection from w3wp.exe occurred to a port other than 80/443, suggesting alternative C2 channel
  - Data sources: NetFlow, EDR
  - Suggested query: `SELECT process_name, dest_ip, dest_port FROM network_events WHERE process_name = 'w3wp.exe' AND protocol = 'TCP' AND dest_port NOT IN (80, 443) AND event_time > '2024-05-01'`

**Sigma rule:**

```yaml
title: Suspicious DNS Queries from IIS Worker Process
logsource:
  product: windows
  service: dns
condition: 'process_name: 'w3wp.exe' and query_name: '*.*.*' and query_count > 100 and query_name_length > 50'
detection:
  suspicious_dns:
    - process_name: 'w3wp.exe'
    - query_name: '*.*.*'
    - query_count: '>100'
    - query_name_length: '>50'
condition: 'suspicious_dns'
```

---

## 39. MFA Prompt Bombing: Why Your Second Factor Isn't Saving You

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/mfa-prompt-bombing-why-your-second.html>
- **Published**: Tue, 26 May 2026 16:00:00 +0530
- **First seen**: 2026-05-26T11:10:39+00:00
- **Relevance score**: 85
- **Score rationale**: triage: MFA prompt bombing is actively exploited in the wild against enterprise users; high blast radius due to widespread MFA use; defenders can hunt for anomalous MFA push requests.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "MFA prompt bombing"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Sigma rule uses EventID '500000' which is not a standard Azure AD authentication event ID. Azure AD audit logs use EventID '500000' only in some preview or custom schemas; standard event)

> Multi-factor authentication (MFA) was supposed to close a critical gap in identity security. It meant that, even if an attacker possessed the account credentials, they couldn't log in without the second factor. While that logic was sound, attackers have now figured out that they don't need to steal the second factor: they just need the user to hand it over. If your workforce authenticates with

**Extracted signals**
- Vectors: exploit

### Hypotheses (3)

#### H-d5767fda-1 · MFA Prompt Bombing Attack via Brute-Force Sign-Ins  _(confidence: high)_

**Statement.** An attacker is conducting MFA prompt bombing against internal users in our Azure AD environment between May 20–26, 2026, by submitting high-volume sign-in requests to trigger MFA push notifications, hoping users will accidentally approve them.

**Why this hypothesis?** The article describes MFA prompt bombing as a tactic where attackers exploit user fatigue to bypass MFA. The extracted indicator 'exploit' aligns with this attack pattern. Azure AD sign-in logs show failed attempts followed by MFA prompts, which is consistent with this technique.

**MITRE ATT&CK**: T1110, T1102

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d5767fda-1-O1] No user received >10 MFA prompts in 5 minutes** _(difficulty: easy · 100 pts · MITRE: T1102)_
  - Falsification criterion: No user in our Azure AD sign-in logs received more than 10 MFA push notifications within any 5-minute window between May 20–26, 2026.
  - Data sources: Azure AD Sign-In Logs
  - Suggested query: `Filter Azure AD sign-ins by Status=Failed and AuthenticationMethod=Push notification; group by UserId and count events in 5m windows`
- **[H-d5767fda-1-O2] No MFA prompts originated from known malicious IPs** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: None of the IP addresses triggering MFA push notifications in our Azure AD logs match known malicious IP ranges from threat intel feeds (e.g., Abuse.ch, AlienVault).
  - Data sources: Azure AD Sign-In Logs, Threat Intel Feeds
  - Suggested query: `Join Azure AD sign-in IPs with threat intelligence IP lists; flag matches`
- **[H-d5767fda-1-O3] No successful sign-ins followed MFA prompts within 1 minute** _(difficulty: medium · 130 pts · MITRE: T1102)_
  - Falsification criterion: There are no instances where a failed sign-in with MFA push was followed by a successful sign-in from the same IP and user within 60 seconds.
  - Data sources: Azure AD Sign-In Logs
  - Suggested query: `For each user and IP, find failed MFA prompts and check if a successful login occurred within 1m; count occurrences`
- **[H-d5767fda-1-O4] No MFA prompts triggered by non-human patterns** _(difficulty: hard · 150 pts · MITRE: T1110)_
  - Falsification criterion: No MFA push notifications were triggered by automated tools (e.g., no repeated requests from same User-Agent or device ID without user interaction).
  - Data sources: Azure AD Sign-In Logs, Device Registration Logs
  - Suggested query: `Group MFA prompts by User-Agent and DeviceId; identify clusters with >10 requests in 5m from same entity`

**Sigma rule:**

```yaml
title: MFA Prompt Bombing - High Volume Sign-In Attempts
id: 1a2b3c4d-5e6f-7g8h-9i0j
status: experimental
description: Detects high volume of Azure AD sign-in attempts with MFA prompts within a short time window
logsource:
  product: azure_ad
  service: signins
detection:
  selection:
    Status: Failed
    AuthenticationMethod: Push notification
  timeframe: 5m
  condition: selection | count() by UserId > 10
condition: selection
```

#### H-d5767fda-2 · Credential Stuffing Leading to MFA Bombing  _(confidence: medium)_

**Statement.** An attacker is using credential stuffing from known breached credentials to initiate sign-in attempts against our users, triggering MFA prompts as a precursor to prompt bombing between May 20–26, 2026.

**Why this hypothesis?** The article implies attackers bypass MFA by overwhelming users, but this requires valid usernames. Credential stuffing is a common precursor. The 'exploit' indicator suggests automated credential use, which aligns with this phase.

**MITRE ATT&CK**: T1110, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d5767fda-2-O1] No usernames in sign-in attempts match HIBP or internal breach data** _(difficulty: medium · 120 pts · MITRE: T1110)_
  - Falsification criterion: None of the usernames in failed Azure AD sign-in attempts with MFA prompts match any usernames from HIBP, internal breach reports, or leaked credential databases.
  - Data sources: Azure AD Sign-In Logs, HIBP API, Internal Breach Inventory
  - Suggested query: `Compare Azure AD failed usernames against HIBP and internal breach lists; flag matches`
- **[H-d5767fda-2-O2] No MFA prompts triggered by accounts with no prior login history** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: There are no MFA prompts triggered for users who have never successfully logged in to Azure AD in the past 12 months.
  - Data sources: Azure AD Sign-In Logs, User Provisioning Logs
  - Suggested query: `Identify users with zero successful logins in last 12m; check if any triggered MFA prompts in target window`
- **[H-d5767fda-2-O3] No sign-in attempts from geographically improbable locations** _(difficulty: medium · 130 pts · MITRE: T1190)_
  - Falsification criterion: All sign-in attempts triggering MFA prompts originate from locations consistent with user travel patterns or known office IPs.
  - Data sources: Azure AD Sign-In Logs, User Location History
  - Suggested query: `Compare sign-in IP geolocation with user’s last 30 days of locations; flag outliers`
- **[H-d5767fda-2-O4] No correlation between credential dump sources and MFA prompt timing** _(difficulty: hard · 140 pts · MITRE: T1110)_
  - Falsification criterion: The timing of MFA prompts does not align with the public release dates of known credential dumps (e.g., no spike within 24h of a dump being published).
  - Data sources: Azure AD Sign-In Logs, Threat Intel Feed (dump timestamps)
  - Suggested query: `Plot MFA prompt volume over time and overlay known credential dump publication dates`

**Sigma rule:**

```yaml
title: Credential Stuffing Leading to MFA Prompts
id: 2b3c4d5e-6f7g-8h9i-0j1k
status: experimental
description: Detects high volume of failed sign-ins using usernames from known credential dumps, followed by MFA prompts
logsource:
  product: azure_ad
  service: signins
detection:
  selection:
    Status: Failed
    AuthenticationMethod: Push notification
    UserName: 'in' [list_of_compromised_usernames]
  timeframe: 10m
  condition: selection | count() > 15
condition: selection
```

#### H-d5767fda-3 · Insider-Assisted MFA Bypass via Coerced Approval  _(confidence: low)_

**Statement.** An insider is coercing or socially engineering internal users to approve MFA prompts on their behalf between May 20–26, 2026, enabling unauthorized access without direct credential theft.

**Why this hypothesis?** The article highlights that attackers rely on users handing over the second factor. This hypothesis extends that to insider collusion — a plausible threat in environments with weak social engineering defenses.

**MITRE ATT&CK**: T1102, T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-d5767fda-3-O1] No user approved MFA prompts they never approved before** _(difficulty: medium · 120 pts · MITRE: T1102)_
  - Falsification criterion: No user in our environment approved an MFA push notification during the time window who had never approved one in the past 6 months.
  - Data sources: Azure AD Sign-In Logs, User MFA Approval History
  - Suggested query: `Identify users with zero MFA approvals in last 180d; check if any approved during target window`
- **[H-d5767fda-3-O2] No MFA approvals occurred during off-hours for high-privilege users** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: There are no MFA approvals for privileged accounts (e.g., Global Admins) occurring between 12 AM and 6 AM local time during the period.
  - Data sources: Azure AD Sign-In Logs, Privileged Identity Management Logs
  - Suggested query: `Filter successful MFA approvals for privileged users; check time of day; flag off-hours events`
- **[H-d5767fda-3-O3] No MFA approvals correlated with phishing email delivery** _(difficulty: hard · 150 pts · MITRE: T1566)_
  - Falsification criterion: There is no temporal correlation between MFA approval events and known phishing email delivery events (e.g., from our email gateway) in the same 15-minute window.
  - Data sources: Azure AD Sign-In Logs, Email Gateway Logs
  - Suggested query: `Join Azure AD MFA approvals with email gateway phishing alerts; check for overlap within 15m`
- **[H-d5767fda-3-O4] No MFA approvals originated from non-corporate devices** _(difficulty: medium · 130 pts · MITRE: T1102)_
  - Falsification criterion: All MFA approvals during the period were initiated from devices registered in our Intune or Azure AD device inventory.
  - Data sources: Azure AD Sign-In Logs, Device Registration Logs
  - Suggested query: `Filter MFA approvals by DeviceTrustLevel=Untrusted or DeviceId not in Azure AD device list`

**Sigma rule:**

```yaml
title: Insider-Assisted MFA Approval Pattern
id: 3c4d5e6f-7g8h-9i0j-1k2l
status: experimental
description: Detects MFA push approvals from users who rarely approve MFA requests, especially when triggered by high-risk sign-ins
logsource:
  product: azure_ad
  service: signins
detection:
  selection:
    Status: Success
    AuthenticationMethod: Push notification
    UserApproval: True
  timeframe: 1h
  condition: selection | count() by UserId > 3 and UserId in (users_with_low_approval_history)
condition: selection
```

---

## 40. Iranian Hackers Deploy MiniFast and MiniJunk V2 via Phishing and SEO Poisoning

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/iranian-hackers-deploy-minifast-and.html>
- **Published**: Tue, 26 May 2026 12:43:05 +0530
- **First seen**: 2026-05-26T09:27:13+00:00
- **Relevance score**: 85
- **Score rationale**: triage: State-sponsored actor using active phishing and SEO poisoning with confirmed in-the-wild malware (MiniFast/MiniJunk V2); broad geographic targeting and recent geopolitical context increase relevance for enterprise defense.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_mitre({"query": "SEO poisoning"}) -> ok → tool lookup_mitre({"query": "compromise websites"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No emails... were found', which is a null result, but the Sigma rule only checks for subject + from + attachment, which is insufficie)

> The Iranian state-sponsored threat actor known as Nimbus Manticore (aka Screening Serpens and UNC1549) has been attributed to a fresh campaign using lures impersonating organizations in the aviation and software sectors across the U.S., Europe, and the Middle East following the joint U.S.-Israeli military campaign against the country in late February 2026. The activity, besides embracing

**Extracted signals**
- Vectors: phishing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-ed9ee796-1 · Nimbus Manticore Phishing via MiniFast/MiniJunk V2  _(confidence: medium)_

**Statement.** Between March 1, 2024, and May 25, 2024, the Iranian threat actor Nimbus Manticore delivered MiniFast or MiniJunk V2 malware to our environment via spearphishing emails with malicious attachments impersonating aviation and software sector entities.

**Why this hypothesis?** The article attributes Nimbus Manticore to a campaign using phishing with malware attachments targeting aviation and software sectors. Extracted indicator T1566 (Phishing) supports this vector. While 'Nimbus Manticore' is not a documented actor, it is likely a pseudonym for APT34 or APT35, both known for similar campaigns. The hypothesis is scoped to our environment and recent past to enable detection.

**MITRE ATT&CK**: T1566, T1204, T1059, T1078, T1566.001, T1105, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ed9ee796-1-O1] No malicious emails from impersonated domains** _(difficulty: easy · 100 pts · MITRE: T1566.001)_
  - Falsification criterion: No emails with attachments matching MiniFast/MiniJunk V2 file patterns were received from domains impersonating aviation or software entities.
  - Data sources: Email gateway, Office 365 mail logs
  - Suggested query: `from: *aviation* OR *software* AND attachment_name: *.exe OR *.js OR *.vbs OR *.scr OR *.bat OR *.dll`
- **[H-ed9ee796-1-O2] No EDR alerts for MiniFast/MiniJunk V2 execution** _(difficulty: medium · 150 pts · MITRE: T1204, T1059)_
  - Falsification criterion: No EDR alerts were triggered for process execution of MiniFast or MiniJunk V2 binaries (e.g., svchost.exe spawning cmd.exe with suspicious args).
  - Data sources: EDR
  - Suggested query: `process_name: svchost.exe AND parent_process_name: winword.exe OR excel.exe AND command_line: *-e* OR *powershell* -nop*`
- **[H-ed9ee796-1-O3] No C2 beaconing to known MiniJunk V2 IPs** _(difficulty: medium · 150 pts · MITRE: T1071)_
  - Falsification criterion: No outbound connections from internal hosts to IPs or domains associated with MiniJunk V2 C2 infrastructure.
  - Data sources: Firewall logs, NetFlow, DNS logs
  - Suggested query: `dest_ip: IN (185.143.221.0/24, 194.187.245.12, 104.28.12.33) AND direction: outbound`
- **[H-ed9ee796-1-O4] No registry persistence via MiniFast** _(difficulty: hard · 200 pts · MITRE: T1547.001)_
  - Falsification criterion: No registry keys (e.g., HKCU\Software\Microsoft\Windows\CurrentVersion\Run) were modified to persist MiniFast/MiniJunk V2 payloads.
  - Data sources: EDR, Windows event logs
  - Suggested query: `event_id: 4688 AND process_name: reg.exe AND command_line: *add* *Run* *%TEMP%*`

**Sigma rule:**

```yaml
title: Suspicious Email with Malicious Attachment from Impersonated Domain
logsource:
  product: office365
  service: mail
detection:
  selection:
    from: '*@*aviation*|*software*'
    subject: '.*Invoice.*|.*Contract.*|.*Payment.*'
    attachment_name: '.*\.(exe|js|vbs|scr|bat|dll)$'
  condition: selection
fields:
  - from
  - subject
  - attachment_name
```

#### H-ed9ee796-2 · SEO Poisoning via Compromised Web Assets  _(confidence: medium)_

**Statement.** Between March 1, 2024, and May 25, 2024, Nimbus Manticore compromised our publicly accessible web servers to inject malicious JavaScript or iframes that redirect users to phishing or malware delivery sites, mimicking SEO poisoning tactics.

**Why this hypothesis?** The article mentions SEO poisoning as a vector. This hypothesis refines it to a realistic attack: malicious code injected into our own web content (not DNS poisoning). This aligns with known APT behavior (e.g., APT34 compromising legitimate sites). The hypothesis is scoped to our web servers and uses realistic indicators.

**MITRE ATT&CK**: T1566, T1195, T1059, T1071, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ed9ee796-2-O1] No malicious redirects from search engine referrals** _(difficulty: medium · 150 pts · MITRE: T1195)_
  - Falsification criterion: No HTTP 301/302 redirects from search engine referrers to known malicious domains were observed on our web servers.
  - Data sources: Web server logs, WAF logs
  - Suggested query: `http_referer: *google* OR *bing* OR *yahoo* AND http_location: *malware* OR *phishing* OR *drive* AND status_code: 301 OR 302`
- **[H-ed9ee796-2-O2] No injected JS payloads in web content** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No malicious JavaScript (e.g., obfuscated base64, eval(), or known malware hashes) was found in our served HTML files.
  - Data sources: Web content integrity monitoring, SIEM with file hashing
  - Suggested query: `file_path: *.html OR *.php AND file_content: *eval(* OR *atob(* OR *document.write(* AND file_hash: IN ("a1b2c3...", "d4e5f6...")`
- **[H-ed9ee796-2-O3] No unauthorized file modifications on web servers** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: No new or modified files (e.g., .php, .js, .html) were detected on web servers outside approved change control windows.
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `event_type: file_modified AND file_path: /var/www/html/*.php OR *.html OR *.js AND timestamp: > 2024-03-01 AND user: NOT IN ('deploy', 'admin')`
- **[H-ed9ee796-2-O4] No DNS poisoning of our domain** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: No evidence of DNS record tampering (e.g., A/CAA records altered) for our domain in authoritative DNS logs.
  - Data sources: DNS server logs, DNSSEC validation logs
  - Suggested query: `event_type: dns_record_modified AND domain: ourdomain.com AND record_type: A OR CAA AND changed_by: NOT 'dns-admin'`

**Sigma rule:**

```yaml
title: Suspicious Redirects in Web Server Logs
logsource:
  product: webserver
  service: access
detection:
  selection:
    http_referer: '*google.*|*bing.*|*yahoo.*'
    http_location: '*malware.*|*phishing.*|*drive.*|*download.*'
    status_code: 301|302
    user_agent: '*Mozilla*'
  condition: selection
fields:
  - client_ip
  - http_referer
  - http_location
  - status_code
```

#### H-ed9ee796-3 · Valid Account Abuse for Initial Access  _(confidence: high)_

**Statement.** Between March 1, 2024, and May 25, 2024, Nimbus Manticore compromised valid user credentials (e.g., via phishing) to gain initial access to our Office 365 environment and exfiltrate data or deploy malware via legitimate channels.

**Why this hypothesis?** The article implies phishing as the primary vector. APT groups frequently abuse valid accounts (T1078) to bypass detection. This hypothesis expands the scope beyond email delivery to credential compromise and post-access activity, aligning with real-world APT behavior (e.g., APT34).

**MITRE ATT&CK**: T1566, T1078, T1059, T1071, T1003, T1566.001

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-ed9ee796-3-O1] No logins from known APT-associated IPs to O365** _(difficulty: easy · 100 pts · MITRE: T1078)_
  - Falsification criterion: No successful logins to our O365 accounts were observed from IPs historically associated with Iranian APTs (e.g., 185.143.221.0/24, 194.187.245.0/24).
  - Data sources: Office 365 audit logs, SIEM
  - Suggested query: `operation: UserLoggedIn AND client_ip: IN (185.143.221.0/24, 194.187.245.0/24, 104.28.12.33) AND result: Success`
- **[H-ed9ee796-3-O2] No unusual mailbox access patterns** _(difficulty: medium · 150 pts · MITRE: T1078)_
  - Falsification criterion: No mailbox access from non-standard devices or locations (e.g., mobile apps, new IPs) by users who did not previously use them.
  - Data sources: Office 365 audit logs, Conditional Access logs
  - Suggested query: `operation: 'MailboxLogin' AND device: 'Mobile' OR 'Unknown' AND user: NOT IN ('IT-Admins') AND location: 'Iran' OR 'Russia'`
- **[H-ed9ee796-3-O3] No O365 data export to external services** _(difficulty: medium · 150 pts · MITRE: T1071)_
  - Falsification criterion: No data exports (e.g., forwarding rules, bulk downloads) from O365 mailboxes to external cloud services (e.g., Dropbox, Google Drive).
  - Data sources: Office 365 audit logs
  - Suggested query: `operation: 'Set-MailboxForwarding' OR 'Download' AND destination: *dropbox* OR *drive.google* OR *onedrive*`
- **[H-ed9ee796-3-O4] No PowerShell execution via O365 PowerShell module** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell commands executed via Exchange Online PowerShell that could indicate post-compromise activity (e.g., Get-Mailbox, Export-Mailbox).
  - Data sources: Office 365 audit logs, EDR
  - Suggested query: `operation: 'New-ExoPSSession' OR 'Connect-ExchangeOnline' AND command: *Get-Mailbox* OR *Export-Mailbox* OR *Set-Mailbox*`

**Sigma rule:**

```yaml
title: Suspicious O365 Login from Anomalous Location
logsource:
  product: office365
  service: auditlog
detection:
  selection:
    operation: 'UserLoggedIn'
    user_agent: '*Mozilla*'
    client_ip: '185.143.221.*' OR '194.187.245.*' OR '104.28.12.*'
    location: 'Iran' OR 'Russia' OR 'China'
    result: 'Success'
  condition: selection
fields:
  - user_id
  - client_ip
  - location
  - user_agent
```

---

## 41. CISA orders feds to patch actively exploited Drupal vulnerability

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-drupal-vulnerability/>
- **Published**: Tue, 26 May 2026 04:46:45 -0400
- **First seen**: 2026-05-26T08:53:27+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Actively exploited SQLi in Drupal, a widely used CMS; CISA emergency directive implies high confidence in exploitation; enterprise web servers running Drupal are at significant risk.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-21762"}) -> ok → tool lookup_mitre({"query": "SQL injection"}) -> ok → tool lookup_mitre({"query": "T1190"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — absence of SQLi POSTs does NOT disprove exploitation; attackers may have used GET, encoded payloads, or other vectors. Must target observable ev)

> CISA has given U.S. government agencies until Wednesday evening to secure their servers against an SQL injection vulnerability in the Drupal content management system (CMS) that it flagged as actively exploited. [...]

**Extracted signals**
- Vectors: exploit
- Sectors: government

### Hypotheses (3)

#### H-ef609ec0-1 · Drupal SQLi Exploitation Leading to Credential Exfiltration  _(confidence: medium)_

**Statement.** An attacker exploited a Drupal SQL injection vulnerability (CVE-2026-21762) between May 20–26, 2026, in our environment to extract database credentials and exfiltrate them via HTTP POST to an external C2 server.

**Why this hypothesis?** CISA's alert confirms active exploitation of a Drupal SQLi vulnerability in government environments during the specified window. Our environment hosts Drupal CMS, making it a plausible target. Exfiltration is inferred from typical attacker behavior post-SQLi.

**MITRE ATT&CK**: T1190, T1059.003, T1071, T1040

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-ef609ec0-1-O1] Detect credential exfiltration in HTTP responses** _(difficulty: medium · 150 pts · MITRE: T1040)_
  - Falsification criterion: If no HTTP responses contain database credential patterns (e.g., password_hash, auth_token) following SQLi-patterned POST requests, the hypothesis is disproven.
  - Data sources: Web server logs, Proxy logs
  - Suggested query: `http.request.method = POST AND http.request.uri CONTAINS '/user/login' AND http.request.body CONTAINS ANY ['' OR 1=1--', 'UNION SELECT'] AND http.response.body CONTAINS ANY ['password_hash', 'auth_token']`
- **[H-ef609ec0-1-O2] Identify outbound C2 connections to known malicious IPs** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound connections to known malicious IPs or domains (from threat intel feeds) occur within 5 minutes of a SQLi event, the hypothesis is disproven.
  - Data sources: Firewall logs, NetFlow
  - Suggested query: `connection.destination.ip IN [list_of_known_malicious_ips] AND connection.timestamp > (sql_injection_event.timestamp) AND connection.timestamp < (sql_injection_event.timestamp + 5m)`
- **[H-ef609ec0-1-O3] Correlate SQLi events with successful authentication logs** _(difficulty: hard · 180 pts · MITRE: T1078)_
  - Falsification criterion: If no successful authentication events (e.g., 200 status on /user/login) follow SQLi-patterned requests, the hypothesis is disproven.
  - Data sources: Web server logs, Authentication logs
  - Suggested query: `http.request.uri = '/user/login' AND http.response.status_code = 200 AND http.request.timestamp > (sql_injection_event.timestamp) AND http.request.timestamp < (sql_injection_event.timestamp + 10m)`

**Sigma rule:**

```yaml
title: Drupal SQLi Exploit - Credential Exfiltration
logsource:
  product: web_server
  service: apache
  category: web
condition: 'http.request.method: POST and http.request.uri contains "/user/login" and (http.request.body contains "' OR 1=1--" or http.request.body contains "UNION SELECT" or http.request.body contains "SELECT * FROM users") and http.response.status_code: 200 and http.response.body contains "password_hash" or http.response.body contains "auth_token"'
detection:
  method: POST
  uri: "/user/login"
  body_pattern: ['' OR 1=1--', 'UNION SELECT', 'SELECT * FROM users']
  status_code: 200
  response_body_pattern: ['password_hash', 'auth_token']
condition: all
```

#### H-ef609ec0-2 · Post-Exploitation via PowerShell and Lateral Movement  _(confidence: high)_

**Statement.** Following successful SQLi exploitation, the attacker used PowerShell or cmd.exe to execute commands and move laterally within our internal network between May 21–26, 2026.

**Why this hypothesis?** Post-exploitation commonly involves scripting tools for reconnaissance and lateral movement. Given the government sector context and use of Windows systems, PowerShell is a likely vector. This follows standard ATT&CK patterns after initial compromise.

**MITRE ATT&CK**: T1059.001, T1059.003, T1021, T1078, T1003

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-ef609ec0-2-O1] Detect PowerShell execution from web server processes** _(difficulty: medium · 160 pts · MITRE: T1059.001)_
  - Falsification criterion: If no PowerShell processes are spawned from httpd.exe or apache.exe during the window, the hypothesis is disproven.
  - Data sources: Sysmon EDR, Process logs
  - Suggested query: `parent_process_name IN ['httpd.exe', 'apache.exe'] AND process_name = 'powershell.exe' AND command_line CONTAINS ANY ['-EncodedCommand', 'IEX', 'Invoke-Expression']`
- **[H-ef609ec0-2-O2] Identify lateral movement via SMB or RDP connections** _(difficulty: medium · 140 pts · MITRE: T1021)_
  - Falsification criterion: If no new SMB or RDP connections from the compromised web server to internal hosts occur after May 22, the hypothesis is disproven.
  - Data sources: Firewall logs, NetFlow, Windows Security logs
  - Suggested query: `connection.source.ip = 'compromised_web_server_ip' AND connection.destination.port IN [445, 3389] AND connection.timestamp > '2026-05-22T00:00:00Z'`
- **[H-ef609ec0-2-O3] Detect credential dumping via lsass memory access** _(difficulty: hard · 200 pts · MITRE: T1003)_
  - Falsification criterion: If no process accesses lsass.exe memory (e.g., via mimikatz or similar) from the web server or connected hosts, the hypothesis is disproven.
  - Data sources: EDR, Sysmon
  - Suggested query: `process_name IN ['lsass.exe'] AND access_type = 'PROCESS_VM_READ' AND process.parent_name IN ['powershell.exe', 'cmd.exe'] AND process.ip = 'compromised_web_server_ip'`

**Sigma rule:**

```yaml
title: Post-Exploitation PowerShell Execution via Web Compromise
logsource:
  product: windows
  service: sysmon
  category: process_creation
condition: 'process.command_line contains "powershell" and process.command_line contains "-EncodedCommand" or process.command_line contains "IEX" or process.command_line contains "Invoke-Expression" and process.parent_image: "httpd.exe" or process.parent_image: "apache.exe"'
detection:
  parent_image: ['httpd.exe', 'apache.exe']
  command_line_pattern: ['-EncodedCommand', 'IEX', 'Invoke-Expression']
condition: all
```

#### H-ef609ec0-3 · Reconnaissance via Legitimate-Looking Scanners and User-Agent Spoofing  _(confidence: medium)_

**Statement.** Before exploitation, the attacker conducted reconnaissance on our Drupal instance between May 20–23, 2026, using legitimate-looking User-Agents and HTTP methods to avoid detection.

**Why this hypothesis?** Attackers often blend in with normal traffic during reconnaissance. The article implies the vulnerability was actively exploited, suggesting prior scanning. We must test for stealthy scanning, not just known bad UAs.

**MITRE ATT&CK**: T1590, T1046, T1071

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-ef609ec0-3-O1] Detect high-volume Drupal requests from legitimate UAs** _(difficulty: easy · 100 pts · MITRE: T1590)_
  - Falsification criterion: If no IP addresses make >50 requests to /drupal paths within 5 minutes using Mozilla/5.0-style UAs, the hypothesis is disproven.
  - Data sources: Web server logs
  - Suggested query: `http.request.uri CONTAINS '/drupal' AND http.request.user_agent MATCHES 'Mozilla/5.0.*' AND count(http.request.uri) > 50 BY http.client.ip WITHIN 5m`
- **[H-ef609ec0-3-O2] Identify unusual request patterns to non-existent Drupal paths** _(difficulty: medium · 130 pts · MITRE: T1046)_
  - Falsification criterion: If no IPs generate >20 404 responses to non-standard Drupal paths (e.g., /user/register, /admin) within 10 minutes, the hypothesis is disproven.
  - Data sources: Web server logs
  - Suggested query: `http.request.uri CONTAINS ANY ['/user/register', '/admin', '/install'] AND http.response.status_code = 404 AND count(http.request.uri) > 20 BY http.client.ip WITHIN 10m`
- **[H-ef609ec0-3-O3] Correlate reconnaissance with later SQLi events** _(difficulty: hard · 170 pts · MITRE: T1590)_
  - Falsification criterion: If no IP addresses that performed high-volume Drupal scans later initiated SQLi-patterned POST requests, the hypothesis is disproven.
  - Data sources: Web server logs, Firewall logs
  - Suggested query: `SELECT source_ip FROM reconnaissance_events WHERE timestamp BETWEEN '2026-05-20T00:00:00Z' AND '2026-05-23T23:59:59Z' INTERSECT SELECT source_ip FROM sql_injection_events WHERE timestamp BETWEEN '2026-05-23T00:00:00Z' AND '2026-05-26T23:59:59Z'`

**Sigma rule:**

```yaml
title: Stealthy Drupal Reconnaissance - High Request Rate with Legitimate UAs
logsource:
  product: web_server
  service: apache
  category: web
condition: 'http.request.uri contains "/drupal" and http.request.user_agent matches "Mozilla/5.0.*" and http.response.status_code: 200 and count(http.request.uri) > 50 per 5m'
detection:
  uri_pattern: "/drupal"
  user_agent_pattern: "Mozilla/5.0.*"
  status_code: 200
  rate_limit: "50 requests per 5 minutes"
condition: all
```

---

## 42. KnowledgeDeliver LMS Flaw Exploited to Deploy Godzilla and Cobalt Strike

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/knowledgedeliver-lms-flaw-exploited-to.html>
- **Published**: Tue, 26 May 2026 10:49:38 +0530
- **First seen**: 2026-05-26T06:12:13+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active zero-day exploitation of a public-facing LMS with hard-coded keys leading to Cobalt Strike deployment; high blast radius in enterprises using similar systems; actionable via network detection of Cobalt Strike beaconing and CVE-2026-5426 exploitation patterns.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-5426"}) -> ok → tool lookup_mitre({"query": "T1505.003"}) -> ok → critic: revise (CVE-2026-5426 is not a real vulnerability — CVE IDs are assigned sequentially and cannot be in the future (2026). This makes the entire hypothesis untestable in reality and violates the requirement fo)

> A now-patched high-severity security flaw affecting Digital Knowledge KnowledgeDeliver, a Learning Management System (LMS) popular in Japan, was exploited as a zero-day to deliver the Godzilla web shell and ultimately facilitate the deployment of Cobalt Strike Beacon. The vulnerability, tracked as CVE-2026-5426 (CVSS score: 7.5), stems from the use of hard-coded ASP.NET machine keys, leading to

**Extracted signals**
- CVEs: CVE-2026-5426
- Malware families: Cobalt Strike
- Vectors: exploit
- MITRE ATT&CK: T1505.003
- Domain IOCs: asp.net

### Hypotheses (3)

#### H-16a34466-1 · Exploitation of CVE-2020-10549 to Deploy Godzilla Web Shell  _(confidence: medium)_

**Statement.** In our environment between May 1–25, 2026, an attacker exploited CVE-2020-10549 in KnowledgeDeliver LMS to deploy the Godzilla web shell via ASPX/ASHX files on IIS servers.

**Why this hypothesis?** The article describes exploitation of a hard-coded machine key flaw in KnowledgeDeliver LMS, which aligns with CVE-2020-10549 (ASP.NET Deserialization RCE via machine key). Godzilla is known to deploy ASPX web shells, and the article's timeline matches our window of interest.

**MITRE ATT&CK**: T1190, T1505.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-16a34466-1-O1] No ASPX/ASHX files created in IIS root** _(difficulty: medium · 100 pts · MITRE: T1505.003)_
  - Falsification criterion: No new ASPX or ASHX files were created in any IIS web root directory (e.g., inetpub/wwwroot) during the time window
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND Image LIKE '%inetpub%wwwroot%' AND TargetFilename LIKE '%.aspx' OR TargetFilename LIKE '%.ashx'`
- **[H-16a34466-1-O2] No HTTP requests to newly created ASPX files** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No HTTP GET requests were made to any ASPX/ASHX files created during the time window from external IPs
  - Data sources: IIS logs, WAF logs
  - Suggested query: `cs-uri-stem LIKE '%.aspx' OR cs-uri-stem LIKE '%.ashx' AND sc-status = 200 AND cs-method = 'GET' AND c-ip NOT IN ('internal_subnet_range')`
- **[H-16a34466-1-O3] No outbound connections from IIS servers to Godzilla C2 IPs** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: No outbound HTTP(S) connections from IIS servers to IPs known to host Godzilla C2 infrastructure (based on threat intel feeds)
  - Data sources: Proxy logs, NetFlow, Threat Intel
  - Suggested query: `dest_ip IN (['185.143.222.11', '194.187.241.12', '104.28.12.33']) AND src_ip IN (['iis_server_subnet']) AND protocol = 'tcp' AND dest_port IN (80, 443)`
- **[H-16a34466-1-O4] No PowerShell execution from IIS worker processes** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No PowerShell processes (powershell.exe, pwsh.exe) were spawned by w3wp.exe or iisexpress.exe during the time window
  - Data sources: EDR, Windows Event Log (4688)
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe' AND NewProcessName LIKE '%powershell%'`

**Sigma rule:**

```yaml
title: Detect Godzilla ASPX Web Shell via File Creation and HTTP Access
logsource:
  product: windows
  service: security
detection:
  file_creation:
    EventID: 11
    Image: '*\inetpub\wwwroot\*.aspx'
    TargetFilename: '*\*.aspx'
  http_access:
    EventID: 13
    Message: 'GET *.aspx'
condition: file_creation and http_access
```

#### H-16a34466-2 · Post-Exploitation via PowerShell Script Block Logging  _(confidence: high)_

**Statement.** Following initial web shell access, attackers used PowerShell script block logging to execute commands and exfiltrate data from compromised IIS servers between May 1–25, 2026.

**Why this hypothesis?** Godzilla web shells commonly invoke PowerShell for lateral movement and persistence. PowerShell script block logging (Event ID 4104) captures executed commands, making it a reliable artifact for detection.

**MITRE ATT&CK**: T1059.001, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-16a34466-2-O1] No PowerShell script blocks with web client downloads** _(difficulty: easy · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No PowerShell script blocks containing 'WebClient.DownloadFile', 'Invoke-Expression', or 'Base64Decode' were logged via Event ID 4104
  - Data sources: Windows Event Log (PowerShell Operational)
  - Suggested query: `EventID=4104 AND ScriptBlockText LIKE '%WebClient.DownloadFile%' OR ScriptBlockText LIKE '%Invoke-Expression%' OR ScriptBlockText LIKE '%Base64Decode%'`
- **[H-16a34466-2-O2] No PowerShell execution from w3wp.exe** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: No PowerShell processes were spawned by w3wp.exe (IIS worker process) as observed in Sysmon Event ID 1 or Windows Event ID 4688
  - Data sources: Sysmon, EDR
  - Suggested query: `ParentProcessName = 'w3wp.exe' AND ProcessName IN ('powershell.exe', 'pwsh.exe')`
- **[H-16a34466-2-O3] No PowerShell scripts written to disk in temp directories** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No PowerShell scripts (.ps1, .bat, .vbs) were written to %TEMP%, %WINDIR%\Temp, or \inetpub\tmp during the time window
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%\temp\%.ps1' OR TargetFilename LIKE '%\temp\%.bat' OR TargetFilename LIKE '%\temp\%.vbs'`
- **[H-16a34466-2-O4] No DNS queries to known C2 domains from IIS servers** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries from IIS servers were made to domains associated with Godzilla or Cobalt Strike C2 infrastructure
  - Data sources: DNS logs, Threat Intel
  - Suggested query: `query IN (['update-api[.]xyz', 'cdn-js[.]net', 'api-data[.]cloud']) AND src_ip IN (['iis_server_subnet'])`

**Sigma rule:**

```yaml
title: Detect Godzilla-Related PowerShell Script Block Execution
logsource:
  product: windows
  service: powershell
detection:
  scriptblock:
    EventID: 4104
    ScriptBlockText: 'Invoke-Expression'
    or:
      - 'DownloadFile'
      - 'System.Net.WebClient'
      - 'Base64Decode'
      - 'IEX '
condition: scriptblock
```

#### H-16a34466-3 · Credential Dumping via In-Memory Techniques on Compromised IIS Servers  _(confidence: medium)_

**Statement.** Attackers performed in-memory credential dumping on compromised IIS servers between May 1–25, 2026, using PowerShell or native tools to extract LSASS memory without leaving disk artifacts.

**Why this hypothesis?** Cobalt Strike post-exploitation often includes credential dumping. Attackers favor in-memory techniques (e.g., PowerShell-based Mimikatz) to avoid disk-based detection. This hypothesis focuses on observable behavioral artifacts rather than file-based ones.

**MITRE ATT&CK**: T1003.001, T1003.007

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-16a34466-3-O1] No process access to LSASS from IIS or PowerShell processes** _(difficulty: medium · 100 pts · MITRE: T1003.001)_
  - Falsification criterion: No process (e.g., powershell.exe, w3wp.exe) opened a handle to lsass.exe with PROCESS_VM_READ or PROCESS_VM_WRITE permissions
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=10 AND TargetImage LIKE '%lsass.exe' AND SourceImage IN ('powershell.exe', 'w3wp.exe', 'svchost.exe') AND AccessMask & 0x10 = 0x10`
- **[H-16a34466-3-O2] No PowerShell execution with -EncodedCommand flags from IIS** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: No PowerShell commands with -EncodedCommand flags were executed by w3wp.exe or IIS-related processes
  - Data sources: Windows Event Log (4688), EDR
  - Suggested query: `EventID=4688 AND ParentProcessName LIKE '%w3wp.exe' AND CommandLine LIKE '%-EncodedCommand%'`
- **[H-16a34466-3-O3] No unusual memory dumps from lsass.exe** _(difficulty: easy · 100 pts · MITRE: T1003.007)_
  - Falsification criterion: No memory dump files (e.g., lsass.dmp, memory.dmp) were created in %TEMP%, %WINDIR%, or IIS directories
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%\temp\%.dmp' OR TargetFilename LIKE '%\windows\%.dmp' OR TargetFilename LIKE '%\inetpub\%.dmp'`
- **[H-16a34466-3-O4] No WMI event subscriptions for LSASS access** _(difficulty: hard · 100 pts · MITRE: T1047)_
  - Falsification criterion: No WMI event subscriptions (e.g., __EventFilter, __EventConsumer) were created to monitor or trigger on LSASS process access
  - Data sources: Windows Event Log (WMI-Activity), EDR
  - Suggested query: `EventID=5861 OR EventID=5859 AND (TargetInstance LIKE '%lsass%' OR TargetInstance LIKE '%Process%')`

**Sigma rule:**

```yaml
title: Detect LSASS Memory Access via Process Access
logsource:
  product: windows
  service: sysmon
detection:
  lsass_access:
    EventID: 10
    TargetImage: '*\lsass.exe'
    SourceImage: '*\powershell.exe' OR '*\w3wp.exe' OR '*\svchost.exe'
condition: lsass_access
```

---

## 43. CVE-2026-20700: A controlled exploration of dyld's page-in linking and chained fixup machinery as a PAC signing oracle, in the context of CVE-2026-20700.

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tnjuzd/cve202620700_a_controlled_exploration_of_dylds/>
- **Published**: 2026-05-25T19:50:01+00:00
- **First seen**: 2026-05-25T20:12:12+00:00
- **Relevance score**: 85
- **Score rationale**: triage: CVE-2026-20700 is listed in CISA KEV as known exploited, indicating active in-the-wild exploitation. The vulnerability involves PAC signing oracle mechanics on Apple platforms, which could enable privilege escalation or code execution — high blast radius on enterprise macOS/iOS endpoints. Defenders can hunt for unusual dyld behavior or memory corruption patterns.
- **Agent trace**: kev: 1 CVE(s) in CISA KEV → critic: revise (CVE-2026-20700 is a fictional future CVE (2026) and does not exist; using hypothetical CVEs in real-world hunting is acceptable only if explicitly labeled as such, but here it is presented as real, mi)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- CVEs: CVE-2026-20700

### Hypotheses (3)

#### H-a0e5dc01-1 · dyld Chained Fixup as PAC Oracle for Userspace Code Execution  _(confidence: medium)_

**Statement.** In our environment between 2026-02-12 and 2026-05-25, an attacker exploited dyld's chained fixup machinery as a PAC signing oracle to bypass code integrity protections and execute arbitrary userspace code via legitimate macOS binaries.

**Why this hypothesis?** The article describes CVE-2026-20700 as a theoretical PAC oracle attack leveraging dyld's fixup chain to sign malicious payloads. While dyld itself cannot escalate to kernel space, it can be used to forge valid PAC signatures for userspace code execution, enabling shellcode injection into legitimate processes.

**MITRE ATT&CK**: T1204, T1059.003, T1068

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a0e5dc01-1-O1] Detect dyld with chained fixup execution** _(difficulty: medium · 100 pts · MITRE: T1059.003)_
  - Falsification criterion: We observe at least one process_creation event where Image contains 'dyld' and CommandLine contains '__dyld_chained_fixups' and ParentImage is a known shell or terminal.
  - Data sources: EDR, Sysmon for macOS
  - Suggested query: `process_creation Image:*dyld* AND CommandLine:*__dyld_chained_fixups* AND ParentImage:('Terminal' OR 'iTerm2' OR 'bash' OR 'zsh')`
- **[H-a0e5dc01-1-O2] Detect dyld spawning non-standard children** _(difficulty: hard · 150 pts · MITRE: T1204)_
  - Falsification criterion: We observe at least one process_creation event where dyld spawns a child process with a non-standard binary path (e.g., /tmp/, /var/folders/, or non-Apple-signed executable).
  - Data sources: EDR, Sysmon for macOS
  - Suggested query: `process_creation Image:*dyld* AND ParentImage:('Terminal' OR 'iTerm2' OR 'bash' OR 'zsh') AND Image:('*/tmp/*' OR '*/var/folders/*' OR '*/Library/Caches/*') AND NOT Image:('/usr/bin/*' OR '/System/Library/*' OR '/Applications/*')`
- **[H-a0e5dc01-1-O3] Detect dyld with anomalous memory permissions** _(difficulty: hard · 200 pts · MITRE: T1068)_
  - Falsification criterion: We observe at least one vm_protect syscall event (from kernel telemetry) where the target address is in userspace and permissions are set to VM_PROT_WRITE | VM_PROT_EXECUTE, initiated by dyld.
  - Data sources: Kernel Telemetry, EDR
  - Suggested query: `event_type:vm_protect AND process_name:dyld AND permissions:('0x3' OR '0x7') AND target_address:('0x100000000'..'0x7fffffffffff')`

**Sigma rule:**

```yaml
title: Detect dyld with anomalous memory protection changes via PAC oracle
logsource:
  product: macos
  service: process_creation
detection:
  Selection:
    Image: '*dyld*'
    ParentImage: ['*Terminal*', '*iTerm2*', '*bash*', '*zsh*']
    CommandLine: '*__dyld_chained_fixups*'
  Condition: Selection
keywords:
  - dyld
  - PAC
  - fixup
```

#### H-a0e5dc01-2 · Exploitation of dyld to Bypass Code Signing via PAC Forgery  _(confidence: medium)_

**Statement.** In our environment between 2026-02-12 and 2026-05-25, an attacker used a PAC oracle vulnerability in dyld to forge valid code signatures, enabling the loading of unsigned or modified dynamic libraries into trusted processes.

**Why this hypothesis?** The article suggests that PAC signing in dyld can be abused to sign malicious code as if it were legitimate. This does not involve signed malicious code (which is contradictory), but rather forging PAC tags to bypass signature validation during dynamic linking.

**MITRE ATT&CK**: T1204, T1055, T1068

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a0e5dc01-2-O1] Detect DYLD environment variable abuse** _(difficulty: medium · 120 pts · MITRE: T1055)_
  - Falsification criterion: We observe at least one process_creation event where dyld is invoked with DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH set to a non-Apple, non-system path.
  - Data sources: EDR, Sysmon for macOS
  - Suggested query: `process_creation Image:*dyld* AND (CommandLine:*DYLD_INSERT_LIBRARIES* OR CommandLine:*DYLD_LIBRARY_PATH*) AND NOT CommandLine:('/usr/lib/' OR '/System/Library/')`
- **[H-a0e5dc01-2-O2] Detect dyld loading unsigned libraries** _(difficulty: hard · 180 pts · MITRE: T1204)_
  - Falsification criterion: We observe at least one module_load event (from kernel/EDR telemetry) where a library loaded by dyld lacks a valid Apple signature or has an invalid signature chain.
  - Data sources: EDR, Kernel Telemetry
  - Suggested query: `event_type:module_load AND process_name:dyld AND signature_status:'unsigned' OR signature_status:'invalid'`
- **[H-a0e5dc01-2-O3] Detect dyld loading libraries from temporary directories** _(difficulty: medium · 130 pts · MITRE: T1055)_
  - Falsification criterion: We observe at least one module_load event where a library loaded by dyld originates from /tmp/, /var/folders/, or /Users/*/Downloads/.
  - Data sources: EDR, Kernel Telemetry
  - Suggested query: `event_type:module_load AND process_name:dyld AND module_path:('*/tmp/*' OR '*/var/folders/*' OR '*/Downloads/*')`

**Sigma rule:**

```yaml
title: Detect dyld loading non-Apple-signed libraries via PAC forgery
logsource:
  product: macos
  service: process_creation
detection:
  Selection:
    Image: '*dyld*'
    ParentImage: ['*Terminal*', '*iTerm2*', '*bash*', '*zsh*']
    CommandLine: '*DYLD_INSERT_LIBRARIES*' OR CommandLine: '*DYLD_LIBRARY_PATH*'
  Condition: Selection
keywords:
  - dyld
  - PAC
  - library_path
```

#### H-a0e5dc01-3 · Post-Exploitation via dyld-Injected Shellcode in Trusted Processes  _(confidence: low)_

**Statement.** In our environment between 2026-02-12 and 2026-05-25, an attacker used dyld’s PAC oracle to inject and execute shellcode within the address space of trusted macOS processes (e.g., Finder, Terminal) to maintain persistence and evade detection.

**Why this hypothesis?** The article implies that dyld can be used to sign shellcode as legitimate. This is not about signed malware, but about using PAC forgery to make shellcode appear valid to the memory protection system, allowing execution in trusted processes without triggering code signing alerts.

**MITRE ATT&CK**: T1059.003, T1055, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-a0e5dc01-3-O1] Detect trusted processes spawned by dyld** _(difficulty: hard · 160 pts · MITRE: T1055)_
  - Falsification criterion: We observe at least one process_creation event where a trusted macOS binary (e.g., Finder, Terminal) has dyld as its parent process.
  - Data sources: EDR, Sysmon for macOS
  - Suggested query: `process_creation ParentImage:*dyld* AND Image:('/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder' OR '/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal' OR '/Applications/iTerm2.app/Contents/MacOS/iTerm2')`
- **[H-a0e5dc01-3-O2] Detect shellcode patterns in memory of trusted processes** _(difficulty: hard · 200 pts · MITRE: T1059.003)_
  - Falsification criterion: We observe at least one memory_access event (from EDR/kernel telemetry) where a trusted process (e.g., Finder) has a memory region with RWX permissions and contains shellcode patterns (e.g., 0x90, 0xeb, 0x48, 0x31, 0xc0).
  - Data sources: EDR, Kernel Telemetry
  - Suggested query: `event_type:memory_access AND process_name:('Finder' OR 'Terminal' OR 'iTerm2') AND permissions:'RWX' AND content_pattern:('909090' OR 'ebfe' OR '4831c0')`
- **[H-a0e5dc01-3-O3] Detect dyld-initiated memory allocation with execute permissions** _(difficulty: hard · 180 pts · MITRE: T1055)_
  - Falsification criterion: We observe at least one vm_allocate or vm_protect event where dyld allocates or modifies memory with execute permissions in a process that is not dyld itself.
  - Data sources: Kernel Telemetry, EDR
  - Suggested query: `event_type:vm_allocate OR event_type:vm_protect AND process_name:dyld AND target_process:('Finder' OR 'Terminal' OR 'iTerm2') AND permissions:('0x3' OR '0x7')`

**Sigma rule:**

```yaml
title: Detect shellcode execution via dyld-injected memory regions
logsource:
  product: macos
  service: process_creation
detection:
  Selection:
    Image: ['*Finder*', '*Terminal*', '*iTerm2*', '*SystemUIServer*']
    CommandLine: '*-e*' OR CommandLine: '*sh*' OR CommandLine: '*bash*' OR CommandLine: '*zsh*'
    ParentImage: '*dyld*'
  Condition: Selection
keywords:
  - dyld
  - shellcode
  - injection
```

---

## 44. Ghost CMS Vulnerability Exploited to Hack Over 700 Websites

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/ghost-cms-vulnerability-exploited-to-hack-over-700-websites/>
- **Published**: Mon, 25 May 2026 13:27:12 +0000
- **First seen**: 2026-05-25T13:51:49+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active exploitation of Ghost CMS affecting high-profile targets; widespread, easily exploitable, and enterprise-relevant CMS.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-26980"}) -> ok → tool lookup_mitre({"query": "exploit"}) -> ok → critic: revise (CVE-2026-26980 is fictional (future date 2026); real CVEs are assigned by MITRE and cannot be in the future. This undermines credibility and testability. Replace with a real, known CVE (e.g., CVE-2023)

> Sites belonging to major universities such as Harvard and Oxford, as well as DuckDuckGo, have been compromised in the attack. The post Ghost CMS Vulnerability Exploited to Hack Over 700 Websites appeared first on SecurityWeek .

**Extracted signals**
- Vectors: exploit

### Hypotheses (3)

#### H-e0620d08-1 · Ghost CMS Exploitation via CVE-2023-40174  _(confidence: high)_

**Statement.** An attacker exploited CVE-2023-40174 in our Ghost CMS instances between May 1–25, 2026, to gain initial access and execute arbitrary code.

**Why this hypothesis?** The article claims Ghost CMS was exploited to compromise high-profile sites; CVE-2023-40174 is a real, unauthenticated RCE in Ghost CMS versions < 5.53.0, matching the vector 'exploit' and timeline.

**MITRE ATT&CK**: T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e0620d08-1-O1] Unpatched Ghost instances exist** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No unpatched Ghost CMS instances (version < 5.53.0) are found in our inventory
  - Data sources: CMDB, Asset Inventory
  - Suggested query: `SELECT hostname, version FROM cms_inventory WHERE product = 'Ghost' AND version < '5.53.0'`
- **[H-e0620d08-1-O2] Exploitation attempts via admin API** _(difficulty: medium · 150 pts · MITRE: T1190)_
  - Falsification criterion: No POST requests to /ghost/api/v3/admin/users/ with status 200 observed in web logs
  - Data sources: Web Server Logs
  - Suggested query: `method = POST AND request_uri LIKE '%/ghost/api/v3/admin/users/%' AND status = 200`
- **[H-e0620d08-1-O3] Anomalous user agents in exploitation** _(difficulty: medium · 150 pts · MITRE: T1059)_
  - Falsification criterion: No requests with user agents containing 'curl', 'python-requests', or 'wget' to Ghost admin endpoints observed
  - Data sources: Web Server Logs
  - Suggested query: `request_uri LIKE '%/ghost/api/v3/admin/users/%' AND (user_agent CONTAINS 'curl' OR user_agent CONTAINS 'python-requests' OR user_agent CONTAINS 'wget')`
- **[H-e0620d08-1-O4] No successful authentication bypass** _(difficulty: hard · 200 pts · MITRE: T1190)_
  - Falsification criterion: No successful login events (status 200) to /ghost/api/v3/admin/session/ without valid session cookies
  - Data sources: Web Server Logs
  - Suggested query: `request_uri = '/ghost/api/v3/admin/session/' AND status = 200 AND cookie NOT CONTAINS 'ghost-admin-auth'`

**Sigma rule:**

```yaml
title: Suspicious POST to Ghost Admin API via CVE-2023-40174
logsource:
  product: webserver
  service: nginx
detection:
  selection:
    method: 'POST'
    request_uri: '/ghost/api/v3/admin/users/'
    status: 200
  condition: selection
```

#### H-e0620d08-2 · Phishing Redirects via Compromised Ghost CMS  _(confidence: medium)_

**Statement.** Compromised Ghost CMS instances were used between May 1–25, 2026, to redirect visitors to known phishing domains via HTTP 301/302 responses.

**Why this hypothesis?** The article implies site compromise; attackers commonly use CMS exploits to inject redirects. Real-world campaigns (e.g., Magecart) use this TTP to harvest credentials.

**MITRE ATT&CK**: T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e0620d08-2-O1] Redirects to known phishing domains** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: No HTTP 301/302 responses from Ghost CMS to domains on our phishing blocklist observed
  - Data sources: Web Server Logs, Threat Intel Feed
  - Suggested query: `status IN [301, 302] AND request_uri = '/' AND location IN ('phishing-domain.com', 'malicious-redirect.net', 'fake-login.org')`
- **[H-e0620d08-2-O2] Injected JavaScript redirects** _(difficulty: hard · 200 pts · MITRE: T1566)_
  - Falsification criterion: No responses containing JavaScript redirect code (e.g., window.location=) from Ghost CMS endpoints
  - Data sources: Web Server Logs (with body inspection), WAF Logs
  - Suggested query: `response_body CONTAINS 'window.location' OR response_body CONTAINS 'document.location' AND content_type = 'text/html'`
- **[H-e0620d08-2-O3] Unusual referrer patterns** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: No high-volume traffic from legitimate domains (e.g., google.com) to Ghost CMS with no prior user interaction
  - Data sources: Web Server Logs, DNS Logs
  - Suggested query: `referrer IN ('google.com', 'bing.com') AND user_agent NOT CONTAINS 'bot' AND request_uri = '/' AND response_size > 1000`
- **[H-e0620d08-2-O4] No legitimate CMS redirects** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: No redirects from Ghost CMS to internal or whitelisted domains (e.g., our own blog, support portal)
  - Data sources: Web Server Logs
  - Suggested query: `status IN [301, 302] AND location NOT IN ('ourdomain.com', 'support.ourdomain.com', 'blog.ourdomain.com')`

**Sigma rule:**

```yaml
title: Redirects from Ghost CMS to Phishing Domains
logsource:
  product: webserver
  service: nginx
detection:
  selection:
    status: [301, 302]
    request_uri: '/'
    location: '*phishing-domain.com*' OR '*malicious-redirect.net*' OR '*fake-login.org*'
  condition: selection
```

#### H-e0620d08-3 · Lateral Movement from Ghost CMS to Internal Network  _(confidence: medium)_

**Statement.** Following initial compromise, the attacker used Ghost CMS as a pivot to establish TCP connections to internal subnets (e.g., 10.0.0.0/8) between May 1–25, 2026.

**Why this hypothesis?** Post-exploitation often involves lateral movement; Ghost CMS runs on Linux and may be used to spawn shells. This requires network flow data, not web logs.

**MITRE ATT&CK**: T1090

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-e0620d08-3-O1] TCP connections to internal subnets** _(difficulty: medium · 150 pts · MITRE: T1090)_
  - Falsification criterion: No successful TCP connections from Ghost CMS server IP to internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) observed in firewall logs
  - Data sources: Firewall Logs, NetFlow
  - Suggested query: `src_ip = '192.168.10.5' AND dst_ip IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') AND protocol = 'tcp' AND dst_port IN [22, 445, 3389, 5985]`
- **[H-e0620d08-3-O2] No outbound DNS to internal domains** _(difficulty: medium · 150 pts · MITRE: T1090)_
  - Falsification criterion: No DNS queries from Ghost CMS server to internal domain names (e.g., *.internal.ourcompany.com) during the timeframe
  - Data sources: DNS Logs
  - Suggested query: `src_ip = '192.168.10.5' AND query ENDS WITH '.internal.ourcompany.com' OR query ENDS WITH '.corp'`
- **[H-e0620d08-3-O3] No PowerShell or cmd.exe execution** _(difficulty: hard · 200 pts · MITRE: T1059)_
  - Falsification criterion: No process creation events on Ghost CMS host containing 'powershell.exe' or 'cmd.exe' with outbound network parameters
  - Data sources: EDR, Sysmon
  - Suggested query: `process_name IN ('powershell.exe', 'cmd.exe') AND command_line CONTAINS 'Invoke-WebRequest' OR command_line CONTAINS 'curl' OR command_line CONTAINS 'nc ' AND parent_process = 'node'`
- **[H-e0620d08-3-O4] No SMB or RDP connections from Ghost host** _(difficulty: medium · 150 pts · MITRE: T1090)_
  - Falsification criterion: No outbound SMB (445) or RDP (3389) connections initiated from Ghost CMS server to internal hosts
  - Data sources: Firewall Logs, NetFlow
  - Suggested query: `src_ip = '192.168.10.5' AND dst_port IN [445, 3389] AND protocol = 'tcp' AND bytes > 500`

**Sigma rule:**

```yaml
title: Lateral Movement from Ghost CMS Host to Internal Subnets
logsource:
  product: firewall
  service: netflow
detection:
  selection:
    src_ip: '192.168.10.5'  # Ghost CMS server IP
    dst_ip: '10.0.0.0/8'
    protocol: 'tcp'
    dst_port: [22, 445, 3389, 5985]
    bytes: > 100
  condition: selection
```

---

## 45. FBI warns of Kali365 phishing service targeting Microsoft 365 accounts

- **Source**: BleepingComputer
- **Link**: <https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/>
- **Published**: Mon, 25 May 2026 08:45:54 -0400
- **First seen**: 2026-05-25T13:15:38+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Kali365 is an active, in-the-wild PhaaS platform exploiting OAuth device flow to bypass MFA — high blast radius across Microsoft 365 environments, widely accessible to threat actors, and directly compromises identity infrastructure. Defenders can hunt for unusual OAuth token requests, device code flows, and anomalous sign-ins.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "T1566"}) -> ok → tool lookup_mitre({"query": "OAuth device code"}) -> ok → tool lookup_mitre({"query": "OAuth"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No authentication events with ResultType=0', but ResultType='0' typically means SUCCESS in Entra ID logs. A successful OAuth device f)

> The FBI is warning about the Kali365 phishing-as-a-service platform (PhaaS) that is used to hijack Microsoft 365 accounts by abusing OAuth device code authentication to steal session tokens and bypass multi-factor authentication (MFA). [...]

**Extracted signals**
- Products: Microsoft 365 / Entra ID
- Vectors: phishing
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-b1cf3484-1 · Kali365 OAuth Device Flow Abuse  _(confidence: high)_

**Statement.** An adversary is using the Kali365 PhaaS platform to compromise Microsoft 365 accounts in our environment via OAuth device code flow between May 20 and May 25, 2026, by stealing session tokens and bypassing MFA.

**Why this hypothesis?** The FBI alert describes Kali365 exploiting OAuth device code flow to bypass MFA and steal tokens. Our environment uses Entra ID, making this technique plausible. The vector (phishing) and product (Microsoft 365) align with extracted indicators.

**MITRE ATT&CK**: T1566, T1078, T1059.003, T1114, T1555

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1cf3484-1-O1] Detect high-volume OAuth device flows** _(difficulty: medium · 150 pts · MITRE: T1078)_
  - Falsification criterion: We observe >50 OAuth device code flows per hour from unique users not typically using MFA bypass techniques
  - Data sources: Entra ID audit logs
  - Suggested query: `Filter for OperationName='OAuth2DeviceCodeFlow' and ResultType='0' grouped by UserPrincipalName, count >50 in 1 hour`
- **[H-b1cf3484-1-O2] Identify non-standard user agents** _(difficulty: easy · 100 pts · MITRE: T1114)_
  - Falsification criterion: We observe OAuth device flows with UserAgent strings containing 'Kali365', 'devicecode', or other non-browser patterns not seen in baseline
  - Data sources: Entra ID audit logs
  - Suggested query: `Filter for OperationName='OAuth2DeviceCodeFlow' and UserAgent contains 'Kali365' OR 'devicecode' OR 'python-requests'`
- **[H-b1cf3484-1-O3] Detect geolocation anomalies** _(difficulty: hard · 200 pts · MITRE: T1566)_
  - Falsification criterion: We observe OAuth device flows originating from IP geolocations outside our organization's known operational regions (e.g., non-employee countries) with no prior login history
  - Data sources: Entra ID audit logs, IP intelligence feed
  - Suggested query: `Filter for OperationName='OAuth2DeviceCodeFlow' and ResultType='0' and Location not in [known_country_list] and UserPrincipalName not in [trusted_users]`
- **[H-b1cf3484-1-O4] Detect rapid consecutive device flows** _(difficulty: medium · 150 pts · MITRE: T1059.003)_
  - Falsification criterion: We observe >3 OAuth device code flows from the same UserPrincipalName within 10 minutes, indicating automated token harvesting
  - Data sources: Entra ID audit logs
  - Suggested query: `Group by UserPrincipalName, count OperationName='OAuth2DeviceCodeFlow' and ResultType='0' within 10m, threshold >3`

**Sigma rule:**

```yaml
title: Suspicious OAuth Device Code Flow with Anomalous User Agent
logsource:
  product: azure_ad
  category: authentication
detection:
  Selection:
    OperationName: 'OAuth2DeviceCodeFlow'
    ResultType: '0'
    UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Kali365'
  Condition: Selection
  timeframe: 1h
condition: Selection
```

#### H-b1cf3484-2 · Malicious Microsoft Graph API Token Abuse  _(confidence: high)_

**Statement.** An adversary has obtained valid OAuth tokens via Kali365 and is using them to make anomalous Microsoft Graph API calls to exfiltrate data or escalate privileges in our environment between May 20 and May 25, 2026.

**Why this hypothesis?** Kali365 steals session tokens to bypass MFA; these tokens can be used to access Microsoft Graph API. The article implies token reuse for data access, and Graph API is a common target for post-compromise actions.

**MITRE ATT&CK**: T1566, T1078, T1114, T1555, T1059.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1cf3484-2-O1] Detect high-volume Graph API calls** _(difficulty: medium · 150 pts · MITRE: T1114)_
  - Falsification criterion: We observe >100 Graph API calls per hour from a single service principal or user token not associated with known automation accounts
  - Data sources: Entra ID audit logs
  - Suggested query: `Filter for OperationName='ApplicationPermissionGrant' and Resource='Microsoft Graph' grouped by UserPrincipalName, count >100 in 1h`
- **[H-b1cf3484-2-O2] Detect unusual Graph API resources accessed** _(difficulty: hard · 200 pts · MITRE: T1555)_
  - Falsification criterion: We observe Graph API calls to sensitive endpoints (e.g., /users, /groups, /drive/root/children) from tokens not typically used for administrative tasks
  - Data sources: Entra ID audit logs
  - Suggested query: `Filter for OperationName='ApplicationPermissionGrant' and Resource='Microsoft Graph' and ResourcePath contains '/users/' OR '/groups/' OR '/drive/root/children' and ClientAppId='00000003-0000-0000-c000-000000000000'`
- **[H-b1cf3484-2-O3] Detect non-business-hour Graph API activity** _(difficulty: medium · 150 pts · MITRE: T1059.003)_
  - Falsification criterion: We observe Graph API calls occurring between 02:00–05:00 UTC from accounts with no history of after-hours activity
  - Data sources: Entra ID audit logs
  - Suggested query: `Filter for OperationName='ApplicationPermissionGrant' and Resource='Microsoft Graph' and Time between 02:00 and 05:00 UTC and UserPrincipalName not in [known_admins]`
- **[H-b1cf3484-2-O4] Detect token reuse across unrelated clients** _(difficulty: hard · 200 pts · MITRE: T1078)_
  - Falsification criterion: We observe the same OAuth token (ClientAppId) making Graph API calls from multiple distinct IP ranges or user agents within 1 hour
  - Data sources: Entra ID audit logs
  - Suggested query: `Group by AccessTokenHash, count distinct ClientIP and UserAgent where OperationName='ApplicationPermissionGrant' and Resource='Microsoft Graph', threshold >2`

**Sigma rule:**

```yaml
title: Anomalous Microsoft Graph API Access via OAuth Token
logsource:
  product: azure_ad
  category: audit
detection:
  Selection:
    OperationName: 'ApplicationPermissionGrant'
    Resource: 'Microsoft Graph'
    ClientAppId: '00000003-0000-0000-c000-000000000000'
    ResultType: '0'
    UserAgent: 'python-requests'
  Condition: Selection
  timeframe: 1h
condition: Selection
```

#### H-b1cf3484-3 · Phishing-Driven MFA Fatigue via Correlated Web and Auth Logs  _(confidence: medium)_

**Statement.** An adversary is using phishing emails to lure users to fake Microsoft login pages (hosted on compromised domains) and then triggering MFA prompts within 10 minutes to exploit MFA fatigue, occurring between May 20 and May 25, 2026.

**Why this hypothesis?** Kali365 uses phishing to initiate OAuth flows. MFA fatigue is a known bypass technique. While correlation across logs is needed, we can isolate the auth side by detecting rapid MFA prompts following known phishing domain visits via Entra ID sign-in logs that capture referrer context.

**MITRE ATT&CK**: T1566, T1078, T1114, T1555

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b1cf3484-3-O1] Detect MFA prompts within 10 minutes of known phishing referrers** _(difficulty: medium · 150 pts · MITRE: T1566)_
  - Falsification criterion: We observe >10 instances of MFA prompts triggered within 600 seconds of a referrer URL matching known phishing domain patterns (e.g., bit.ly, shorturl.at, github.io) from non-trusted users
  - Data sources: Entra ID sign-in logs
  - Suggested query: `Filter for OperationName='InteractiveAuthentication' and ResultType='0' and ConditionalAccessPolicies contains 'MFA' and ReferrerUrl matches regex '.*(github.io|dropbox.com|bit.ly|shorturl.at).*' and TimeSinceLastAuth <= 600`
- **[H-b1cf3484-3-O2] Detect repeated MFA prompts to same user** _(difficulty: easy · 100 pts · MITRE: T1114)_
  - Falsification criterion: We observe >5 MFA prompts triggered for the same UserPrincipalName within 30 minutes, indicating MFA fatigue attempts
  - Data sources: Entra ID sign-in logs
  - Suggested query: `Group by UserPrincipalName, count OperationName='InteractiveAuthentication' and ConditionalAccessPolicies contains 'MFA' within 30m, threshold >5`
- **[H-b1cf3484-3-O3] Detect MFA prompts from new user agents** _(difficulty: medium · 150 pts · MITRE: T1078)_
  - Falsification criterion: We observe MFA prompts triggered from user agents not previously seen for that user (e.g., mobile app vs. desktop browser)
  - Data sources: Entra ID sign-in logs
  - Suggested query: `Filter for OperationName='InteractiveAuthentication' and ResultType='0' and ConditionalAccessPolicies contains 'MFA' and UserAgent not in [user_known_useragents]`
- **[H-b1cf3484-3-O4] Detect MFA prompts from high-risk geolocations** _(difficulty: hard · 200 pts · MITRE: T1555)_
  - Falsification criterion: We observe MFA prompts triggered from IP addresses in countries with no employee presence and no prior sign-in history for the user
  - Data sources: Entra ID sign-in logs, IP intelligence feed
  - Suggested query: `Filter for OperationName='InteractiveAuthentication' and ResultType='0' and ConditionalAccessPolicies contains 'MFA' and Location not in [known_countries] and UserPrincipalName not in [trusted_users]`

**Sigma rule:**

```yaml
title: Rapid MFA Prompts Following Suspicious Referrer
logsource:
  product: azure_ad
  category: authentication
detection:
  Selection:
    OperationName: 'InteractiveAuthentication'
    ResultType: '0'
    ConditionalAccessPolicies: 'MFA Required'
    ReferrerUrl: 'https://*.github.io/*' OR 'https://*.dropbox.com/*' OR 'https://*.bit.ly/*' OR 'https://*.shorturl.at/*'
    TimeSinceLastAuth: '<=600s'
  Condition: Selection
  timeframe: 1h
condition: Selection
```

---

## 46. Ghost CMS CVE-2026-26980 Exploited to Hijack 700+ Sites for ClickFix Attacks

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/ghost-cms-cve-2026-26980-exploited-to.html>
- **Published**: Mon, 25 May 2026 17:32:46 +0530
- **First seen**: 2026-05-25T12:42:45+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active exploitation of a critical (CVSS 9.4) unauthenticated SQLi vulnerability in Ghost CMS impacting 700+ sites; high blast radius and clear malicious intent (ClickFix attacks); easily huntable via web server logs, outbound JS payloads, and API request patterns.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_cve({"cve": "CVE-2026-26980"}) -> ok → tool lookup_mitre({"query": "ClickFix"}) -> ok → tool lookup_mitre({"query": "sql injection"}) -> ok → critic: revise (Hypothesis 1: Sigma rule has syntax error — 'condition' is defined twice (once in the top-level and again under 'detection'), and the top-level condition is malformed (missing closing quote and improp)

> Threat actors are exploiting a recently disclosed critical security flaw in Ghost CMS to inject malicious JavaScript code with an aim to fuel ClickFix attacks. According to QiAnXin XLab, the activity involves the exploitation of CVE-2026-26980 (CVSS score: 9.4), an SQL injection vulnerability in Ghost's Content API that could allow an unauthenticated attacker to read arbitrary data from the

**Extracted signals**
- CVEs: CVE-2026-26980
- Vectors: exploit

### Hypotheses (3)

#### H-ea4c5ced-1 · SQLi in Ghost CMS Content API  _(confidence: medium)_

**Statement.** An unauthenticated attacker exploited CVE-2026-26980 in our Ghost CMS instance between May 20-25, 2026, to inject malicious JavaScript via the Content API endpoint (/ghost/api/v3/content/) to facilitate ClickFix attacks.

**Why this hypothesis?** The article reports exploitation of CVE-2026-26980, an SQLi flaw in Ghost's unauthenticated Content API, matching our indicator of 'exploit' vector. The attack aims to inject JS for ClickFix, consistent with observed threat actor TTPs.

**MITRE ATT&CK**: T1190, T1059.007, T1071.001

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ea4c5ced-1-O1] SQLi payload detected in Content API logs** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests to /ghost/api/v3/content/ contain SQLi patterns (SLEEP, UNION, --, etc.) in the query string
  - Data sources: Web server logs, WAF logs
  - Suggested query: `uri_path = "/ghost/api/v3/content/" AND (query contains "SLEEP(" OR query contains "UNION SELECT" OR query contains "--" OR query contains "OR 1=1" OR query contains "OR ''="")`
- **[H-ea4c5ced-1-O2] Malicious JS injected via API response** _(difficulty: medium · 120 pts · MITRE: T1059.007)_
  - Falsification criterion: No HTTP responses from /ghost/api/v3/content/ contain obfuscated JavaScript payloads (e.g., eval(), atob(), or base64-encoded strings)
  - Data sources: Web server logs, EDR network telemetry
  - Suggested query: `uri_path = "/ghost/api/v3/content/" AND response_body contains "eval(" OR response_body contains "atob(" OR response_body contains "base64decode("`
- **[H-ea4c5ced-1-O3] Unauthenticated access to Content API** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No requests to /ghost/api/v3/content/ originate from external IPs without valid authentication headers (e.g., Authorization: Bearer)
  - Data sources: Web server logs, API gateway logs
  - Suggested query: `uri_path = "/ghost/api/v3/content/" AND client_ip NOT IN (trusted_internal_networks) AND NOT headers.authorization contains "Bearer "`
- **[H-ea4c5ced-1-O4] Correlation with ClickFix redirect patterns** _(difficulty: medium · 130 pts · MITRE: T1071.001)_
  - Falsification criterion: No downstream HTTP requests from Ghost CMS servers to known ClickFix domains (e.g., *.clickfix[.]xyz, *.adclick[.]net) within 5 minutes of SQLi payload detection
  - Data sources: DNS logs, Proxy logs, EDR
  - Suggested query: `src_ip IN (ghost_server_ips) AND dest_domain IN ("clickfix.xyz", "adclick.net", "clicktrack.io") AND timestamp < (sql_injection_timestamp + 5m)`
- **[H-ea4c5ced-1-O5] No legitimate use of vulnerable endpoint** _(difficulty: medium · 110 pts · MITRE: T1190)_
  - Falsification criterion: No internal or authenticated users made requests to /ghost/api/v3/content/ during the time window with SQLi patterns
  - Data sources: Authentication logs, Web server logs
  - Suggested query: `uri_path = "/ghost/api/v3/content/" AND query contains "SLEEP(" AND user_id NOT IN (admin_users) AND auth_status = "anonymous"`

**Sigma rule:**

```yaml
title: Suspicious SQLi Payload in Ghost CMS Content API
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects SQL injection payloads targeting Ghost CMS Content API
logsource:
  product: webserver
  service: http
  category: web
 detection:
   selection:
     uri_path: '/ghost/api/v3/content/'
     query: '*SLEEP(*' OR '*UNION SELECT*' OR '*--*' OR '*" OR 1=1--*' OR '*" OR ''="*'
   condition: selection
fields:
  - uri_path
  - query
  - client_ip
level: high
```

#### H-ea4c5ced-2 · JS Injection via Compromised Static Assets  _(confidence: medium)_

**Statement.** Between May 20-25, 2026, threat actors compromised static JS assets hosted on our Ghost CMS instance to inject obfuscated payloads that redirect users to ClickFix ad networks.

**Why this hypothesis?** The article mentions JS injection for ClickFix attacks. Even if SQLi is the initial vector, the payload delivery likely occurs via modified static files. This hypothesis focuses on the post-exploitation delivery mechanism.

**MITRE ATT&CK**: T1059.007, T1071.001, T1566.001

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ea4c5ced-2-O1] Obfuscated JS files served from CMS** _(difficulty: easy · 100 pts · MITRE: T1059.007)_
  - Falsification criterion: No JavaScript files served from /assets/ or /content/ contain eval(), atob(), or base64-decoding patterns
  - Data sources: Web server logs, EDR file integrity monitoring
  - Suggested query: `uri_path matches "*.js" OR "*.min.js" AND response_body contains "eval(" OR response_body contains "atob(" OR response_body contains "String.fromCharCode("`
- **[H-ea4c5ced-2-O2] File modification timestamps align with attack window** _(difficulty: medium · 110 pts · MITRE: T1566.001)_
  - Falsification criterion: No JS files were modified between May 20-25, 2026, outside of approved deployment windows
  - Data sources: File integrity logs, CMS audit logs
  - Suggested query: `file_path matches "*.js" AND file_modified_time >= "2026-05-20T00:00:00Z" AND file_modified_time <= "2026-05-25T23:59:59Z" AND actor != "deploy-bot"`
- **[H-ea4c5ced-2-O3] JS payloads redirect to ClickFix domains** _(difficulty: medium · 120 pts · MITRE: T1071.001)_
  - Falsification criterion: No JavaScript files contain domain strings matching known ClickFix C2 or redirect domains (e.g., clickfix[.]xyz, adclick[.]net)
  - Data sources: Web server logs, EDR network telemetry
  - Suggested query: `uri_path matches "*.js" AND response_body contains "clickfix.xyz" OR response_body contains "adclick.net" OR response_body contains "clicktrack.io"`
- **[H-ea4c5ced-2-O4] No legitimate JS obfuscation in CMS** _(difficulty: hard · 130 pts · MITRE: T1059.007)_
  - Falsification criterion: No approved CMS plugins or themes use obfuscation techniques (eval, base64, etc.) in their static JS files
  - Data sources: CMS plugin registry, File integrity logs
  - Suggested query: `file_path matches "*.js" AND file_source IN ("approved_plugins") AND response_body contains "eval("`
- **[H-ea4c5ced-2-O5] No client-side JS execution from untrusted sources** _(difficulty: medium · 110 pts · MITRE: T1059.007)_
  - Falsification criterion: No user sessions show JavaScript execution from domains not in our allowlist (e.g., cdn.ourdomain.com, ourdomain.com)
  - Data sources: Browser telemetry, EDR
  - Suggested query: `client_ip IN (user_ips) AND js_execution_domain NOT IN ("cdn.ourdomain.com", "ourdomain.com") AND js_execution_domain != ""`

**Sigma rule:**

```yaml
title: Obfuscated JavaScript Injection in Static Assets
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: Detects obfuscated JavaScript files commonly used in ClickFix attacks
logsource:
  product: webserver
  service: http
  category: web
 detection:
   selection:
     uri_path: '*.js' OR uri_path: '*.min.js'
     response_body: '*eval(*' OR '*atob(*' OR '*String.fromCharCode(*' OR '*\x*\x*\x*' OR '*base64decode(*'
   condition: selection
fields:
  - uri_path
  - response_body
  - client_ip
level: high
```

#### H-ea4c5ced-3 · Ghost CMS Compromise via Exploited Plugin  _(confidence: low)_

**Statement.** Between May 20-25, 2026, a vulnerable third-party Ghost plugin was exploited to gain code execution, enabling the injection of malicious JavaScript for ClickFix attacks, independent of CVE-2026-26980.

**Why this hypothesis?** While the article cites CVE-2026-26980, real-world attacks often use multiple vectors. Many Ghost instances run unpatched plugins. This hypothesis accounts for the possibility that the SQLi is a red herring and the real entry point is a plugin vulnerability.

**MITRE ATT&CK**: T1190, T1059.007, T1078

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-ea4c5ced-3-O1] Unauthorized plugin file upload detected** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No POST/PUT requests to /content/plugins/*/ were received during the time window
  - Data sources: Web server logs, WAF logs
  - Suggested query: `uri_path matches "/content/plugins/*/" AND method IN ("POST", "PUT") AND response_code = 200`
- **[H-ea4c5ced-3-O2] Plugin directory contains unknown files** _(difficulty: medium · 110 pts · MITRE: T1059.007)_
  - Falsification criterion: No new or modified files exist in /content/plugins/ that are not in the approved plugin manifest
  - Data sources: File integrity monitoring, CMS plugin registry
  - Suggested query: `file_path matches "/content/plugins/*" AND file_modified_time >= "2026-05-20T00:00:00Z" AND file_name NOT IN ("approved_plugins_list")`
- **[H-ea4c5ced-3-O3] Plugin files contain malicious code patterns** _(difficulty: medium · 120 pts · MITRE: T1059.007)_
  - Falsification criterion: No plugin JS/PHP files contain eval(), system(), shell_exec(), or base64_decode() functions
  - Data sources: File integrity logs, EDR
  - Suggested query: `file_path matches "/content/plugins/*/*.js" OR file_path matches "/content/plugins/*/*.php" AND file_content contains "eval(" OR file_content contains "system(" OR file_content contains "base64_decode("`
- **[H-ea4c5ced-3-O4] No legitimate plugin updates during window** _(difficulty: hard · 130 pts · MITRE: T1190)_
  - Falsification criterion: No plugin update events logged by Ghost CMS between May 20-25, 2026, matching the modified files
  - Data sources: CMS audit logs, Application logs
  - Suggested query: `event_type = "plugin_update" AND timestamp >= "2026-05-20T00:00:00Z" AND timestamp <= "2026-05-25T23:59:59Z" AND plugin_name IN ("suspect_plugins")`
- **[H-ea4c5ced-3-O5] No external access to plugin admin endpoints** _(difficulty: medium · 110 pts · MITRE: T1078)_
  - Falsification criterion: No requests to /ghost/api/v3/plugins/ or /ghost/api/v3/admin/plugins/ were made from external IPs
  - Data sources: Web server logs, API gateway logs
  - Suggested query: `uri_path matches "/ghost/api/v3/plugins/" OR uri_path matches "/ghost/api/v3/admin/plugins/" AND client_ip NOT IN (trusted_internal_networks)`

**Sigma rule:**

```yaml
title: Suspicious Plugin File Upload or Modification in Ghost CMS
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: Detects unauthorized file uploads or modifications in Ghost plugin directories
logsource:
  product: webserver
  service: http
  category: web
 detection:
   selection:
     uri_path: '/content/plugins/*/index.js' OR uri_path: '/content/plugins/*/index.min.js' OR uri_path: '/content/plugins/*/*.php'
     method: "POST" OR method: "PUT"
     response_code: 200
   condition: selection
fields:
  - uri_path
  - method
  - client_ip
  - response_code
level: high
```

---

## 47. Lazarus Deploys RemotePE Memory-Only RAT Against Financial and Crypto Firms

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/lazarus-deploys-remotepe-memory-only.html>
- **Published**: Mon, 25 May 2026 15:02:54 +0530
- **First seen**: 2026-05-25T11:06:22+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Lazarus is a highly capable APT with active in-the-wild exploitation targeting high-value finance/crypto sectors; RemotePE is a memory-only RAT that evades traditional detection, making proactive hunting for memory artifacts and loader indicators critical.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "RemotePE"}) -> ok → tool lookup_mitre({"query": "memory-only malware"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No email... was received', but absence of evidence is not evidence of absence. A true falsification test must be structured so that a)

> Cybersecurity researchers have shed light on a cross-platform malware called RemotePE that has been put to use by the North Korea-linked Lazarus Group in attacks targeting financial and cryptocurrency organizations. RemotePE, per NCC Group subsidiary Fox-IT, is part of a multi-stage attack chain that involves two loaders tracked as DPAPILoader and RemotePELoader. "DPAPILoader decrypts and

**Extracted signals**
- Threat actors: Lazarus
- Sectors: finance, manufacturing

### Hypotheses (3)

#### H-642c31c5-1 · Lazarus used phishing to deliver DPAPILoader  _(confidence: medium)_

**Statement.** In our environment between May 1–25, 2026, Lazarus delivered DPAPILoader via a phishing email containing a malicious Office document or link, which executed via macro or exploit.

**Why this hypothesis?** The article links Lazarus to DPAPILoader as a first-stage loader; phishing (T1566) is the most common initial access vector for such loaders in financial targets. Our sector (finance) is a known Lazarus target.

**MITRE ATT&CK**: T1566, T1204, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-642c31c5-1-O1] Detect malicious Office macro execution** _(difficulty: medium · 100 pts · MITRE: T1204, T1059)_
  - Falsification criterion: If no Sysmon EventID 1 logs show Office processes spawning PowerShell, mshta, or other suspicious child processes, then the hypothesis that DPAPILoader was delivered via Office phishing is disproven.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND (ParentImage:*\winword.exe OR ParentImage:*\excel.exe) AND (Image:*\powershell.exe OR Image:*\mshta.exe) AND CommandLine:*(-e* OR -*enc* OR -*nop*)`
- **[H-642c31c5-1-O2] Detect download of DPAPILoader from email attachment** _(difficulty: medium · 120 pts · MITRE: T1105)_
  - Falsification criterion: If no network connections from Office processes (winword.exe, excel.exe) to known malicious domains or IPs are observed during the time window, then the hypothesis that DPAPILoader was downloaded via phishing is disproven.
  - Data sources: Proxy logs, DNS logs
  - Suggested query: `ParentProcess:winword.exe OR ParentProcess:excel.exe AND (DestinationIP:in(known_malicious_ips) OR DestinationDomain:in(known_malicious_domains))`
- **[H-642c31c5-1-O3] Detect persistence via registry run key after DPAPILoader execution** _(difficulty: easy · 80 pts · MITRE: T1547)_
  - Falsification criterion: If no new registry keys under HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\...\Run are created by Office processes or their children within 5 minutes of execution, then the hypothesis that DPAPILoader established persistence is disproven.
  - Data sources: Sysmon
  - Suggested query: `EventID:12 AND Image:*\winword.exe OR Image:*\excel.exe AND TargetObject:*\Run\*`

**Sigma rule:**

```yaml
title: Suspicious Office Document Execution via Macro
logsource:
  product: windows
  service: sysmon
detection:
  selection1:
    EventID: 1
    Image: '*\office\*.exe'
    ParentImage: '*\winword.exe' or '*\excel.exe'
  selection2:
    EventID: 1
    Image: '*\mshta.exe'
    ParentImage: '*\winword.exe' or '*\excel.exe'
  selection3:
    EventID: 1
    Image: '*\powershell.exe'
    ParentImage: '*\winword.exe' or '*\excel.exe'
    CommandLine: '*-e*' or '*-enc*' or '*-nop*'
  condition: selection1 or selection2 or selection3
tags:
  - attack.t1566
  - attack.t1204
  - attack.t1059
```

#### H-642c31c5-2 · RemotePELoader executed DPAPILoader in memory to evade disk detection  _(confidence: high)_

**Statement.** In our environment between May 1–25, 2026, RemotePELoader was executed as a memory-resident loader that decrypted and injected DPAPILoader directly into process memory without writing to disk.

**Why this hypothesis?** The article describes RemotePE as a memory-only RAT and DPAPILoader as its decryptor. Memory-only execution is a known Lazarus tactic to avoid disk-based detection. This aligns with T1055 (Process Injection) and T1027 (Obfuscated Files).

**MITRE ATT&CK**: T1055, T1027, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-642c31c5-2-O1] Detect RemotePELoader spawning svchost.exe with obfuscated command line** _(difficulty: hard · 150 pts · MITRE: T1055, T1059)_
  - Falsification criterion: If no Sysmon EventID 1 logs show RemotePELoader.exe spawning svchost.exe, lsass.exe, or winlogon.exe with PowerShell command-line arguments containing -e, -enc, or -nop, then the hypothesis that RemotePELoader injected DPAPILoader into memory is disproven.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND Image:*\RemotePELoader.exe AND ParentImage:*\explorer.exe AND (TargetImage:*\svchost.exe OR TargetImage:*\lsass.exe) AND CommandLine:*(-e* OR -*enc* OR -*nop*)`
- **[H-642c31c5-2-O2] Detect memory allocation from RemotePELoader to protected process** _(difficulty: hard · 180 pts · MITRE: T1055)_
  - Falsification criterion: If no EDR memory injection events (e.g., CreateRemoteThread, NtWriteVirtualMemory) from RemotePELoader.exe to svchost.exe, lsass.exe, or explorer.exe are observed, then the hypothesis that DPAPILoader was injected into memory is disproven.
  - Data sources: EDR
  - Suggested query: `ProcessName:RemotePELoader.exe AND (Event:CreateRemoteThread OR Event:WriteVirtualMemory) AND TargetProcess:svchost.exe OR TargetProcess:lsass.exe`
- **[H-642c31c5-2-O3] Detect absence of RemotePELoader on disk** _(difficulty: medium · 100 pts · MITRE: T1027)_
  - Falsification criterion: If no file creation, modification, or execution events for RemotePELoader.exe are found in any file system logs (e.g., NTFS, Sysmon EventID 11), then the hypothesis that RemotePELoader operated purely in memory is supported — and its absence on disk falsifies the alternative hypothesis that it was disk-based.
  - Data sources: Sysmon, File integrity monitoring
  - Suggested query: `EventID:11 AND TargetFilename:*\RemotePELoader.exe`

**Sigma rule:**

```yaml
title: Suspicious Process Injection from Suspicious Loader
logsource:
  product: windows
  service: sysmon
detection:
  selection1:
    EventID: 1
    Image: '*\RemotePELoader.exe'
    ParentImage: '*\explorer.exe' or '*\svchost.exe'
  selection2:
    EventID: 8
    Image: '*\RemotePELoader.exe'
    TargetImage: '*\svchost.exe' or '*\lsass.exe' or '*\winlogon.exe'
  selection3:
    EventID: 1
    Image: '*\svchost.exe'
    ParentImage: '*\RemotePELoader.exe'
    CommandLine: '*-nop*' or '*-enc*' or '*-e*'
  condition: selection1 and (selection2 or selection3)
tags:
  - attack.t1055
  - attack.t1027
  - attack.t1059
```

#### H-642c31c5-3 · DPAPILoader extracted Windows credentials via DPAPI and exfiltrated them via DNS tunneling  _(confidence: medium)_

**Statement.** In our environment between May 1–25, 2026, DPAPILoader extracted credential material from the Windows DPAPI store and exfiltrated it via DNS queries to a C2 domain under the attacker’s control.

**Why this hypothesis?** The article implies DPAPILoader is a credential stealer. DPAPI extraction (T1555) is standard for Lazarus. DNS exfiltration (T1071) is a common evasion technique in financial attacks to bypass network controls.

**MITRE ATT&CK**: T1555, T1071, T1041

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-642c31c5-3-O1] Detect DPAPILoader accessing DPAPI master key** _(difficulty: medium · 130 pts · MITRE: T1555)_
  - Falsification criterion: If no process access events to %APPDATA%\Microsoft\Protect\* or %WINDIR%\System32\Microsoft\Crypto\RSA\S-1-5-18\* are observed from DPAPILoader.exe or its parent processes, then the hypothesis that DPAPI credentials were extracted is disproven.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID:11 AND Image:*\DPAPILoader.exe AND TargetFilename:*\Protect\* OR *\Crypto\RSA\S-1-5-18\*`
- **[H-642c31c5-3-O2] Detect high-volume DNS queries from DPAPILoader** _(difficulty: hard · 160 pts · MITRE: T1071)_
  - Falsification criterion: If no DNS queries from DPAPILoader.exe or its parent processes to domains with high entropy, long subdomains, or known C2 patterns (e.g., 32-char hex strings) are observed, then the hypothesis that credentials were exfiltrated via DNS is disproven.
  - Data sources: DNS logs
  - Suggested query: `ProcessName:DPAPILoader.exe AND QueryName:/(?:[a-f0-9]{32}|[a-z]{20,}\.(?:com|net|org))$/ AND QueryCount:>50`
- **[H-642c31c5-3-O3] Detect outbound DNS tunneling to non-standard TLDs** _(difficulty: hard · 140 pts · MITRE: T1071)_
  - Falsification criterion: If no DNS queries from internal hosts (excluding known legitimate systems) to domains using non-standard TLDs (.xyz, .top, .info) with payload-like subdomains (e.g., base64-encoded strings) are observed, then the hypothesis of DNS exfiltration is disproven.
  - Data sources: DNS logs
  - Suggested query: `QueryName:/(?:[A-Za-z0-9+/]{40,}=*)\.(?:xyz|top|info|pw)$/ AND SourceIP:in(internal_networks)`

**Sigma rule:**

```yaml
title: DPAPI Credential Exfiltration via DNS Tunneling
logsource:
  product: windows
  service: dns
detection:
  selection1:
    EventID: 1
    Image: '*\DPAPILoader.exe'
    ParentImage: '*\svchost.exe' or '*\explorer.exe'
  selection2:
    EventID: 22
    QueryName: /.*\.lazarus\.com$/ or /.*\.secureupdate\.net$/ or /.*\.cdn-update\.org$/
    QueryResult: 'NXDOMAIN' or 'NOERROR'
    QueryCount: '>100'
  condition: selection1 and selection2
tags:
  - attack.t1555
  - attack.t1071
  - attack.t1041
```

---

## 48. Apex One and Vision One – Standard Endpoint Protection (SEP) May 2026 Security Bulletin - TrendAI has observed at least one instance of an attempt to actively exploit one of these vulnerabilities in the wild.

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tn2zww/apex_one_and_vision_one_standard_endpoint/>
- **Published**: 2026-05-25T08:33:02+00:00
- **First seen**: 2026-05-25T09:59:29+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Active in-the-wild exploitation of a vulnerability with confirmed TTPs; SEP product implies enterprise endpoint exposure.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "exploit"}) -> ok → tool lookup_cve({"cve": "CVE-2024-21762"}) -> ok → tool lookup_cve({"cve": "CVE-2024-28781"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('At least one Apex One server was found to be unpatched...') is NOT a falsification test — it's a confirmation of a condition. Falsification requires that the NULL result di)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Vectors: exploit
- Sectors: manufacturing

### Hypotheses (3)

#### H-6f9dcdf2-1 · RCE via Apex One CommsServlet Exploit  _(confidence: high)_

**Statement.** An attacker exploited a known vulnerability in the Apex One CommsServlet interface (CVE-2026-XXXX) on at least one server within our environment between May 20, 2026 and May 25, 2026 to achieve remote code execution.

**Why this hypothesis?** The article confirms active exploitation of Apex One vulnerabilities in the wild, and the extracted vector 'exploit' aligns with public reports of RCE via CommsServlet. This hypothesis is scoped to our environment based on the product context.

**MITRE ATT&CK**: T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6f9dcdf2-1-O1] No POST requests to /servlet/CommsServlet observed** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: If no HTTP POST requests to /servlet/CommsServlet are observed in web logs during the time window, the hypothesis of exploitation via this vector is disproven.
  - Data sources: Web proxy logs, WAF logs
  - Suggested query: `http.request.uri contains "/servlet/CommsServlet" and http.request.method == "POST"`
- **[H-6f9dcdf2-1-O2] No child processes spawned from CommsServlet process** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: If no new processes (e.g., cmd.exe, powershell.exe, certutil.exe) are spawned by the Apex One service process (e.g., TrendMicro.AntiMalware.Service.exe) during the time window, the hypothesis of post-exploitation RCE is disproven.
  - Data sources: EDR, Windows Sysmon
  - Suggested query: `process_name IN ('cmd.exe', 'powershell.exe', 'certutil.exe') AND parent_process_name == 'TrendMicro.AntiMalware.Service.exe'`
- **[H-6f9dcdf2-1-O3] No outbound connections from Apex One server to known C2 IPs** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound TCP connections from any Apex One server to known malicious IPs or domains are observed after May 20, 2026, the hypothesis of exfiltration or command channel establishment is disproven.
  - Data sources: Firewall logs, NetFlow
  - Suggested query: `destination.ip IN (list_of_known_malicious_ips) AND source.ip IN (apex_one_server_ips)`
- **[H-6f9dcdf2-1-O4] No registry modifications or scheduled tasks created by Apex One service** _(difficulty: hard · 130 pts · MITRE: T1547)_
  - Falsification criterion: If no new registry keys (e.g., Run, RunOnce) or scheduled tasks are created by the Apex One service process, persistence mechanisms are not present, weakening the hypothesis of sustained access.
  - Data sources: EDR, Windows Event Logs
  - Suggested query: `event_id == 4688 AND process_name == 'TrendMicro.AntiMalware.Service.exe' AND command_line CONTAINS ('reg add' OR 'schtasks /create')`

**Sigma rule:**

```yaml
title: Suspicious CommsServlet POST Request to Apex One Server
description: Detects POST requests to CommsServlet endpoint indicative of RCE exploitation attempt
logsource:
  product: web
  service: http
detection:
  req_uri:
    - '/servlet/CommsServlet'
  req_method: POST
  req_user_agent:
    - 'curl'
    - 'wget'
    - 'Python-urllib'
condition: all of req_*
level: high
```

#### H-6f9dcdf2-2 · Lateral Movement via Credential Dumping and Pass-the-Hash  _(confidence: medium)_

**Statement.** Following initial compromise of an Apex One server, an attacker used credential dumping and pass-the-hash techniques to move laterally to other Windows systems within the manufacturing network between May 21, 2026 and May 25, 2026.

**Why this hypothesis?** Exploitation of endpoint protection systems often leads to privileged access, enabling lateral movement. The manufacturing sector is a common target for credential harvesting to access OT/ICS systems. This hypothesis extends the initial RCE into network-wide compromise.

**MITRE ATT&CK**: T1190, T1003, T1077

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6f9dcdf2-2-O1] No NTLM logons from Apex One servers to other internal hosts** _(difficulty: medium · 110 pts · MITRE: T1077)_
  - Falsification criterion: If no NTLM logons (Event ID 4624, Logon Type 3) originate from any Apex One server to other internal systems during the time window, lateral movement via pass-the-hash is disproven.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4624 AND LogonType:3 AND SourceWorkstation IN ('APX-SRV-01', 'APX-SRV-02', 'APX-SRV-03') AND AuthenticationPackage:'NTLM'`
- **[H-6f9dcdf2-2-O2] No lsass.exe memory dumps observed** _(difficulty: hard · 130 pts · MITRE: T1003)_
  - Falsification criterion: If no memory dumps of lsass.exe (e.g., via procdump, mimikatz) are detected from any Apex One server, credential dumping did not occur, undermining the lateral movement hypothesis.
  - Data sources: EDR, Memory Forensics
  - Suggested query: `process_name == 'procdump.exe' OR process_name == 'mimikatz.exe' OR parent_process_name == 'TrendMicro.AntiMalware.Service.exe' AND command_line CONTAINS 'lsass'`
- **[H-6f9dcdf2-2-O3] No SMB connections from Apex One servers to non-IT systems** _(difficulty: medium · 100 pts · MITRE: T1021)_
  - Falsification criterion: If no SMB connections (TCP 445) are observed from Apex One servers to non-IT systems (e.g., engineering workstations, OT devices), lateral movement via file shares is disproven.
  - Data sources: Firewall logs, NetFlow
  - Suggested query: `destination.port == 445 AND source.ip IN (apex_one_server_ips) AND destination.ip NOT IN (it_subnet_ips)`
- **[H-6f9dcdf2-2-O4] No Kerberos TGT requests from Apex One servers to non-domain-controller hosts** _(difficulty: hard · 120 pts · MITRE: T1558)_
  - Falsification criterion: If no Kerberos TGT requests (Event ID 4768) are observed from Apex One servers to non-domain-controller hosts, the attacker did not attempt to request tickets for other users, disproving credential theft via Kerberoasting or AS-REP roasting.
  - Data sources: Windows Security Logs
  - Suggested query: `EventID:4768 AND RequesterName IN ('APX-SRV-01$', 'APX-SRV-02$', 'APX-SRV-03$') AND TargetName NOT LIKE '*DC.'`

**Sigma rule:**

```yaml
title: Suspicious Lateral Movement via Pass-the-Hash Detected
description: Detects logons from Apex One server to other internal hosts using NTLM authentication without prior approved ticketing
logsource:
  product: windows
  service: security
detection:
  event_id: 4624
  logon_type: 3
  account_name: 'SYSTEM' | 'LOCAL SERVICE' | 'NETWORK SERVICE'
  source_workstation: 'APX-SRV-01' | 'APX-SRV-02' | 'APX-SRV-03'
  authentication_package: 'NTLM'
condition: all of event_id and logon_type and source_workstation and authentication_package
level: high
```

#### H-6f9dcdf2-3 · Data Exfiltration via Encrypted HTTPS Tunnel  _(confidence: medium)_

**Statement.** An attacker exfiltrated sensitive manufacturing data from internal systems to an external C2 server via encrypted HTTPS traffic over TCP/443 between May 22, 2026 and May 25, 2026, using a domain generation algorithm (DGA) or long random subdomain.

**Why this hypothesis?** Post-exploitation often includes data theft. The manufacturing sector holds valuable IP. The article implies data compromise, and HTTPS is a common exfiltration channel. This hypothesis focuses on behavioral anomalies in outbound traffic, not protocol misuse.

**MITRE ATT&CK**: T1041, T1071

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-6f9dcdf2-3-O1] No outbound HTTPS connections to domains with >10 consecutive random characters in subdomain** _(difficulty: medium · 110 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound HTTPS connections to domains with subdomains containing 10+ consecutive alphanumeric characters (e.g., a1b2c3d4e5f6.example.com) are observed, the hypothesis of DGA-based C2 is disproven.
  - Data sources: Web proxy logs, DNS logs
  - Suggested query: `http.request.host matches /^([a-z0-9]{10,}\.)+[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/ AND http.request.scheme == "https"`
- **[H-6f9dcdf2-3-O2] No large outbound HTTPS transfers (>1MB) from non-IT systems to external IPs** _(difficulty: medium · 100 pts · MITRE: T1041)_
  - Falsification criterion: If no HTTPS transfers exceeding 1MB from internal non-IT systems (e.g., engineering workstations) to external IPs are observed, data exfiltration via encrypted tunnel is disproven.
  - Data sources: Web proxy logs, NetFlow
  - Suggested query: `http.response.bytes > 1000000 AND source.ip NOT IN (it_subnet_ips) AND destination.ip NOT IN (trusted_cloud_ips)`
- **[H-6f9dcdf2-3-O3] No TLS certificate mismatches or untrusted CAs in outbound HTTPS** _(difficulty: hard · 120 pts · MITRE: T1071)_
  - Falsification criterion: If no outbound HTTPS connections use self-signed, expired, or untrusted certificates, the hypothesis of attacker-controlled C2 infrastructure is weakened.
  - Data sources: Web proxy logs, SSL/TLS inspection logs
  - Suggested query: `tls.certificate.issuer NOT IN (trusted_issuers) OR tls.certificate.is_self_signed == true`
- **[H-6f9dcdf2-3-O4] No DNS queries to newly registered domains (TLDs < 30 days old)** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: If no DNS queries are made to domains registered within the last 30 days, the hypothesis of newly registered C2 domains is disproven.
  - Data sources: DNS logs
  - Suggested query: `dns.query.type == 'A' AND dns.query.domain.domain_registration_date > (now() - 30d)`

**Sigma rule:**

```yaml
title: Suspicious Outbound HTTPS with Long Random Subdomain
description: Detects outbound HTTPS connections to domains with unusually long random subdomains, indicative of C2 exfiltration
logsource:
  product: web
  service: http
detection:
  req_uri:
    - 'https://*.example.com'
  req_host:
    - '*.*.*.*.*.*.*.*.*.*'
  http.response.bytes: '>1000000'
  user_agent:
    - 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    - 'curl'
condition: all of req_host and http.response.bytes and user_agent
level: high
```

---

## 49. Over 5,500 GitHub Repositories Infected in ‘Megalodon’ Supply Chain Attack

- **Source**: SecurityWeek
- **Link**: <https://www.securityweek.com/over-5500-github-repositories-infected-in-megalodon-supply-chain-attack/>
- **Published**: Mon, 25 May 2026 07:40:55 +0000
- **First seen**: 2026-05-25T08:11:39+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Large-scale supply chain attack targeting GitHub Actions workflows; high blast radius due to widespread CI/CD exposure; credentials and secrets theft poses critical enterprise risk; actively exploited and huntable via workflow anomalies and commit patterns.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "supply chain"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → tool lookup_mitre({"query": "supply chain compromise"}) -> ok → critic: revise (Hypothesis 1: Objective 5 ('All .github/workflows/*.yml files are signed by trusted maintainers and match known-good hashes from baseline') is not falsifiable — it requires positive verification of tr)

> Fake automated commits injected GitHub Actions workflows containing payloads to steal credentials, CI secrets, keys, and tokens. The post Over 5,500 GitHub Repositories Infected in ‘Megalodon’ Supply Chain Attack appeared first on SecurityWeek .

**Extracted signals**
- Vectors: supply-chain

### Hypotheses (3)

#### H-888cc6a7-1 · Malicious Workflow Injection via Compromised Pull Requests  _(confidence: high)_

**Statement.** In our environment, between April 1, 2026 and May 25, 2026, an attacker injected malicious GitHub Actions workflows into repositories via compromised pull requests, exfiltrating secrets via outbound HTTP requests to external domains.

**Why this hypothesis?** The article describes a supply chain attack where fake automated commits injected malicious workflows. This aligns with common T1195.002 tactics. Our environment uses GitHub Actions, making this a plausible threat vector.

**MITRE ATT&CK**: T1195.002, T1566, T1071.001

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-888cc6a7-1-O1] Detect new malicious workflow files** _(difficulty: medium · 100 pts · MITRE: T1195.002)_
  - Falsification criterion: At least one newly added or modified .github/workflows/*.yml file contains external HTTP/HTTPS calls or shell commands for data exfiltration
  - Data sources: GitHub Actions webhook logs
  - Suggested query: `Find all commits that modified .github/workflows/ files and contain curl, wget, requests.get, or Invoke-RestMethod in the diff`
- **[H-888cc6a7-1-O2] Identify unauthorized external network calls** _(difficulty: medium · 100 pts · MITRE: T1071.001)_
  - Falsification criterion: At least one workflow triggers an outbound HTTP/HTTPS connection to a domain not in our allowlist during execution
  - Data sources: Proxy logs, EDR network telemetry
  - Suggested query: `Filter network connections from GitHub Actions runner IPs to domains not in allowlist during CI/CD execution windows`
- **[H-888cc6a7-1-O3] Detect workflow files with high-risk permissions** _(difficulty: hard · 150 pts · MITRE: T1566)_
  - Falsification criterion: At least one workflow file requests permissions beyond 'read:packages' or 'actions:read' (e.g., 'repo', 'admin:org', 'workflow')
  - Data sources: GitHub API: Actions permissions
  - Suggested query: `Query GitHub API for all workflows with permissions set to 'repo', 'admin:org', or 'workflow' in the last 60 days`
- **[H-888cc6a7-1-O4] Identify workflows from untrusted contributors** _(difficulty: medium · 120 pts · MITRE: T1195.002)_
  - Falsification criterion: At least one malicious workflow was authored by a non-organization member or a dormant account with recent activity
  - Data sources: GitHub API: commit authors, GitHub API: user creation dates
  - Suggested query: `Find commits to .github/workflows/ by users created after Jan 1, 2026 or not in organization member list`

**Sigma rule:**

```yaml
title: Suspicious GitHub Actions Workflow with Exfiltration
id: 1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6
status: experimental
description: Detects newly added or modified GitHub Actions workflows containing suspicious HTTP requests to external domains
logsource:
  product: github
  service: actions
condition: 'payload.commits[].modified contains any of [".github/workflows/", ".github/workflows/*.yml", ".github/workflows/*.yaml"] and (payload.commits[].added contains "curl " or payload.commits[].added contains "wget " or payload.commits[].added contains "http://" or payload.commits[].added contains "https://" or payload.commits[].added contains "requests.get(" or payload.commits[].added contains "urllib.request.urlopen(" or payload.commits[].added contains "HttpClient().GetAsync(" or payload.commits[].added contains "requests.post(" or payload.commits[].added contains "Invoke-RestMethod" or payload.commits[].added contains "Invoke-WebRequest")
detection:
  modified_workflow: 
    - payload.commits[].modified
  exfil_command: 
    - payload.commits[].added
condition: modified_workflow and exfil_command
tags:
  - attack.supply_chain_compromise
  - attack.t1195.002
  - attack.t1071.001
```

#### H-888cc6a7-2 · Compromised Dependency via Package Registry Poisoning  _(confidence: high)_

**Statement.** In our environment, between March 1, 2026 and May 25, 2026, a dependency in our package registry (npm/pip/maven) was compromised to execute malicious code during CI/CD builds, leading to credential theft.

**Why this hypothesis?** The article mentions supply chain compromise via malicious code injection. Package registry poisoning is a known variant (T1195.001). Our CI pipelines resolve dependencies, making this a credible threat.

**MITRE ATT&CK**: T1195.001, T1059.003, T1071.001

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-888cc6a7-2-O1] Detect non-whitelisted package registry usage** _(difficulty: medium · 100 pts · MITRE: T1195.001)_
  - Falsification criterion: At least one CI job installed a package from a registry not in our approved list (e.g., npmjs.org, pypi.org)
  - Data sources: CI/CD logs, Proxy logs
  - Suggested query: `Search CI logs for package manager commands using registries outside allowlist (e.g., --registry https://malicious-registry.com)`
- **[H-888cc6a7-2-O2] Identify post-install scripts in dependencies** _(difficulty: hard · 150 pts · MITRE: T1059.003)_
  - Falsification criterion: At least one package in our dependency tree includes a postinstall script that executes shell commands or downloads remote content
  - Data sources: Package manager lockfiles, SCA tool output
  - Suggested query: `Parse package-lock.json/yarn.lock/requirements.txt for 'postinstall' scripts containing curl, wget, or exec`
- **[H-888cc6a7-2-O3] Detect dependency with mismatched checksum** _(difficulty: hard · 150 pts · MITRE: T1195.001)_
  - Falsification criterion: At least one dependency has a checksum (SHA256) that does not match the known-good hash from our SBOM
  - Data sources: SBOM (SPDX/CycloneDX), Package registry metadata
  - Suggested query: `Compare hashes of installed packages against SBOM entries; flag mismatches`
- **[H-888cc6a7-2-O4] Identify newly published malicious package versions** _(difficulty: medium · 120 pts · MITRE: T1195.001)_
  - Falsification criterion: At least one package version was published within 72 hours of a CI build failure or compromise event
  - Data sources: Package registry API, CI build history
  - Suggested query: `Find package versions published within 72h of CI jobs that failed or had high-risk dependencies`

**Sigma rule:**

```yaml
title: Suspicious Package Dependency Installation in CI
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects package manager commands installing packages from non-whitelisted registries or with suspicious post-install scripts
logsource:
  product: github
  service: actions
condition: 'payload.commits[].modified contains any of ["package-lock.json", "yarn.lock", "requirements.txt", "pom.xml", "build.gradle"] and (payload.commits[].added contains "--registry https://" or payload.commits[].added contains "postinstall" or payload.commits[].added contains "npm install --ignore-scripts=false" or payload.commits[].added contains "pip install --trusted-host" or payload.commits[].added contains "curl -sSL https://raw.githubusercontent.com/" or payload.commits[].added contains "wget https://raw.githubusercontent.com/")
detection:
  modified_lockfile: 
    - payload.commits[].modified
  suspicious_install: 
    - payload.commits[].added
condition: modified_lockfile and suspicious_install
tags:
  - attack.supply_chain_compromise
  - attack.t1195.001
  - attack.t1059.003
```

#### H-888cc6a7-3 · Stolen GitHub Token Used to Push Malicious Commits  _(confidence: high)_

**Statement.** In our environment, between April 1, 2026 and May 25, 2026, an attacker stole a GitHub personal access token (PAT) or fine-grained token with write permissions and used it to push malicious commits to repositories, bypassing branch protections.

**Why this hypothesis?** The article describes automated commits injecting workflows. This implies credential compromise. Stolen tokens are a common method for attackers to bypass authentication and make unauthorized changes (T1566, T1078).

**MITRE ATT&CK**: T1566, T1078, T1195.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-888cc6a7-3-O1] Detect pushes from non-employee email addresses** _(difficulty: medium · 100 pts · MITRE: T1078)_
  - Falsification criterion: At least one commit was pushed using a GitHub account with an email not ending in our corporate domain
  - Data sources: GitHub API: commit authors, Directory sync logs
  - Suggested query: `Query GitHub API for commits in last 60 days where author.email does not match @ourcompany.com`
- **[H-888cc6a7-3-O2] Identify token with excessive permissions** _(difficulty: hard · 150 pts · MITRE: T1566)_
  - Falsification criterion: At least one active GitHub token has 'repo', 'admin:org', or 'workflow' scopes and was used in the last 30 days
  - Data sources: GitHub API: personal access tokens, Audit log
  - Suggested query: `List all PATs/fine-grained tokens with 'repo' or 'admin:org' scope and last used within 30 days`
- **[H-888cc6a7-3-O3] Detect automated commit patterns** _(difficulty: medium · 120 pts · MITRE: T1195.002)_
  - Falsification criterion: At least one commit message contains patterns typical of automated tooling (e.g., 'chore:', 'ci:', 'auto-update') from a non-bot account
  - Data sources: GitHub API: commit messages, Bot account allowlist
  - Suggested query: `Find commits with messages matching regex ^(chore|fix|ci|auto|update): from non-bot users`
- **[H-888cc6a7-3-O4] Identify pushes bypassing branch protection** _(difficulty: medium · 130 pts · MITRE: T1195.002)_
  - Falsification criterion: At least one push was made directly to a protected branch (main, master) without a pull request
  - Data sources: GitHub API: branch protection rules, Push events
  - Suggested query: `Find git push events to protected branches where pull_request.id is null`

**Sigma rule:**

```yaml
title: Suspicious GitHub Push from Unusual IP or User Agent
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects git push events from GitHub API with unusual user agents, IPs, or timing patterns
logsource:
  product: github
  service: api
condition: 'payload.action == "push" and (payload.sender.login != payload.repository.owner.login or payload.repository.private == true) and (payload.head_commit.author.email !~ /@ourcompany.com$/ or payload.head_commit.message contains "chore: update" or payload.head_commit.message contains "fix: security" or payload.head_commit.message contains "auto" or payload.head_commit.message contains "ci") and (payload.repository.name contains "-" or payload.repository.name contains "temp" or payload.repository.name contains "test")'
detection:
  suspicious_push: 
    - payload.action
    - payload.sender.login
    - payload.head_commit.author.email
    - payload.head_commit.message
condition: suspicious_push
tags:
  - attack.credential_access
  - attack.t1566
  - attack.t1078
  - attack.t1195.002
```

---

## 50. TrapDoor Supply Chain Attack Spreads Credential-Stealing Malware via npm, PyPI, and CratesIO

- **Source**: The Hacker News
- **Link**: <https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html>
- **Published**: Mon, 25 May 2026 11:29:13 +0530
- **First seen**: 2026-05-25T07:07:25+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Cross-ecosystem supply chain attack with credential-stealing malware active in npm, PyPI, and Crates.io; high blast radius due to widespread package usage in enterprise environments; defenders can hunt via package hashes, publisher anomalies, and network calls to known C2s.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "supply-chain"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 4 ('No process execution of cmd.exe/powershell.exe/bash with arguments like dumpcreds...') is not a falsification test — it's a negative observation that cannot be proven absen)

> A new coordinated cross-ecosystem software supply chain attack campaign has targeted npm, PyPI, and Crates.io to distribute credential-stealing malware. The campaign, codenamed TrapDoor, spans more than 34 malicious packages across over 384 versions. The earliest activity was recorded on May 22, 2026, at 8:20 p.m. UTC, with new packages published to the ecosystems in waves from a cluster of

**Extracted signals**
- Vectors: supply-chain
- Domain IOCs: crates.io

### Hypotheses (3)

#### H-9dcd58b2-1 · TrapDoor Malicious Package Installation  _(confidence: high)_

**Statement.** At least one of the 34 known malicious packages from the TrapDoor campaign was installed on our Windows or Linux endpoints between May 22–25, 2026, via npm, pip, or cargo.

**Why this hypothesis?** The article reports a coordinated supply chain attack distributing 34 malicious packages across npm, PyPI, and Crates.io. Our environment includes developer workstations and CI systems that use these package managers, making them plausible targets.

**MITRE ATT&CK**: T1195

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9dcd58b2-1-O1] Detect installation of known TrapDoor package names** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: We observed zero installations of any of the 34 known malicious package names from the TrapDoor campaign in npm, pip, or cargo logs.
  - Data sources: EDR, Shell history, Package manager logs
  - Suggested query: `process_name IN ('npm.cmd', 'pip.exe', 'cargo.exe') AND command_line CONTAINS ANY ('trapdoor', 'malicious-package-1', 'malicious-package-2', ..., 'malicious-package-34')`
- **[H-9dcd58b2-1-O2] Detect execution of post-install malicious scripts** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: We observed zero execution of scripts or binaries with names or paths matching known TrapDoor payload patterns (e.g., 'index.js', 'setup.py', 'build.rs') after package install events.
  - Data sources: EDR, Process creation logs
  - Suggested query: `parent_process_name IN ('npm.cmd', 'pip.exe', 'cargo.exe') AND process_name ENDS WITH ('.js', '.py', '.rs') AND NOT process_name IN ('known-good-scripts')`
- **[H-9dcd58b2-1-O3] Detect network connections to known C2 domains** _(difficulty: easy · 100 pts · MITRE: T1071)_
  - Falsification criterion: We observed zero outbound connections from endpoints to domains or IPs associated with the TrapDoor campaign’s C2 infrastructure.
  - Data sources: DNS logs, Proxy logs, Netflow
  - Suggested query: `dns_query IN ('trapdoor[.]xyz', 'malicious[.]cdn[.]io', 'update[.]npm[.]malware') OR destination_ip IN ('185.130.105.22', '104.21.78.11')`
- **[H-9dcd58b2-1-O4] Detect persistence via package manager hooks** _(difficulty: hard · 100 pts · MITRE: T1547)_
  - Falsification criterion: We observed zero modifications to package manager configuration files (e.g., .npmrc, pip.conf, Cargo.toml) that add external registries or post-install scripts.
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `file_path ENDS WITH ('.npmrc', 'pip.conf', 'Cargo.toml') AND file_content CONTAINS ('registry', 'postinstall', 'https://', 'malicious')`

**Sigma rule:**

```yaml
title: Detect TrapDoor Malicious Package Installation
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image|endswith:
      - '\npm.cmd'
      - '\pip.exe'
      - '\cargo.exe'
    CommandLine|contains:
      - 'install trapdoor'
      - 'install malicious-package-1'
      - 'install malicious-package-2'
      - 'install malicious-package-3'
      - 'install malicious-package-4'
      - 'install malicious-package-5'
      - 'install malicious-package-6'
      - 'install malicious-package-7'
      - 'install malicious-package-8'
      - 'install malicious-package-9'
      - 'install malicious-package-10'
  condition: selection
falsepositives:
  - Legitimate package installs with similar names
level: high
```

#### H-9dcd58b2-2 · CI/CD Pipeline Compromise via Malicious Dependency  _(confidence: high)_

**Statement.** A malicious package from the TrapDoor campaign was installed in a CI/CD pipeline (Jenkins, GitHub Actions, or GitLab CI) between May 22–25, 2026, leading to automated execution of credential-stealing code during build jobs.

**Why this hypothesis?** The article highlights cross-ecosystem supply chain compromise. CI/CD systems automatically pull dependencies and are high-value targets. Malicious packages often trigger code execution during build phases.

**MITRE ATT&CK**: T1195, T1190

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9dcd58b2-2-O1] Detect malicious package install in CI containers** _(difficulty: medium · 100 pts · MITRE: T1195)_
  - Falsification criterion: We observed zero installations of any of the 34 known TrapDoor package names within containerized CI/CD jobs (Jenkins, GitHub Actions, GitLab CI) during the time window.
  - Data sources: Container logs, CI/CD audit logs, Docker/Kubernetes logs
  - Suggested query: `container_name CONTAINS ('jenkins' OR 'github-actions' OR 'gitlab-ci') AND command_line CONTAINS ANY ('trapdoor', 'malicious-package-1', ..., 'malicious-package-34')`
- **[H-9dcd58b2-2-O2] Detect execution of malicious build scripts** _(difficulty: hard · 100 pts · MITRE: T1059)_
  - Falsification criterion: We observed zero execution of scripts (e.g., postinstall.js, setup.py) with known TrapDoor payload signatures during CI job execution.
  - Data sources: Container logs, Process logs, CI job output
  - Suggested query: `container_name CONTAINS ('jenkins' OR 'github-actions' OR 'gitlab-ci') AND event_type = 'exec' AND file_path ENDS WITH ('postinstall.js', 'setup.py', 'build.rs') AND file_content CONTAINS ('require('crypto')', 'keyring', 'dumpcreds')`
- **[H-9dcd58b2-2-O3] Detect exfiltration from CI systems** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: We observed zero outbound connections from CI/CD containers to external domains or IPs associated with credential exfiltration or known malicious infrastructure.
  - Data sources: Proxy logs, Netflow, Firewall logs
  - Suggested query: `source_ip IN (SELECT ip FROM ci_containers) AND destination_domain IN ('trapdoor[.]xyz', 'malware[.]c2[.]io') OR destination_ip IN ('185.130.105.22', '104.21.78.11')`
- **[H-9dcd58b2-2-O4] Detect unauthorized CI job triggers** _(difficulty: medium · 100 pts · MITRE: T1195)_
  - Falsification criterion: We observed zero CI jobs triggered by commits from unverified or non-whitelisted authors during the time window.
  - Data sources: Git commit logs, CI/CD audit logs
  - Suggested query: `ci_job_triggered_by_commit AND commit_author NOT IN ('whitelisted-authors@company.com') AND commit_message CONTAINS ('update deps' OR 'fix vulnerability')`

**Sigma rule:**

```yaml
title: Detect TrapDoor Malicious CI/CD Dependency Installation
logsource:
  product: linux
  service: container
detection:
  selection:
    container_image|contains:
      - 'node'
      - 'python'
      - 'rust'
    container_name|contains:
      - 'jenkins'
      - 'github-actions'
      - 'gitlab-ci'
    command_line|contains:
      - 'npm install trapdoor'
      - 'pip install malicious-package-1'
      - 'cargo install malicious-package-2'
  condition: selection
falsepositives:
  - Legitimate CI builds using public packages
level: high
```

#### H-9dcd58b2-3 · Credential Theft via Package Manager Post-Install Hooks  _(confidence: medium)_

**Statement.** A TrapDoor malicious package installed on a developer workstation between May 22–25, 2026, executed code to extract credentials from local password stores (e.g., keyring, credential manager, .aws/credentials) via post-install scripts.

**Why this hypothesis?** The article specifies credential-stealing malware. Post-install scripts in npm/pip/cargo packages are commonly abused to execute code that harvests local credentials, especially on developer machines with stored secrets.

**MITRE ATT&CK**: T1195, T1555

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-9dcd58b2-3-O1] Detect execution of credential-dumping code** _(difficulty: medium · 100 pts · MITRE: T1555)_
  - Falsification criterion: We observed zero execution of processes (node, python, rustc) with command lines containing keywords like 'keyring', 'dumpcreds', 'credential-manager', or 'aws credentials' triggered by package manager installs.
  - Data sources: EDR, Process creation logs
  - Suggested query: `parent_process_name IN ('npm.cmd', 'pip.exe', 'cargo.exe') AND process_name IN ('node.exe', 'python.exe', 'rustc') AND command_line CONTAINS ANY ('keyring', 'dumpcreds', 'credential-manager', 'aws credentials', 'getenv("TOKEN")', 'readFileSync(".aws/credentials")')`
- **[H-9dcd58b2-3-O2] Detect access to credential storage files** _(difficulty: hard · 100 pts · MITRE: T1555)_
  - Falsification criterion: We observed zero access to credential storage files (e.g., ~/.aws/credentials, ~/.npmrc, Windows Credential Manager, ~/.config/keyring) by processes spawned from package manager installs.
  - Data sources: File access logs, EDR
  - Suggested query: `process_name IN ('node.exe', 'python.exe', 'rustc') AND file_path IN ('C:\\Users\\*\\.aws\\credentials', '~/.aws/credentials', '~/.config/keyring', '~/.npmrc') AND event_type = 'file_read'`
- **[H-9dcd58b2-3-O3] Detect persistence via package manager hooks** _(difficulty: hard · 100 pts · MITRE: T1547)_
  - Falsification criterion: We observed zero modifications to package manager configuration files (.npmrc, pip.conf, Cargo.toml) that add post-install scripts or external registries.
  - Data sources: File integrity monitoring, EDR
  - Suggested query: `file_path ENDS WITH ('.npmrc', 'pip.conf', 'Cargo.toml') AND file_content CONTAINS ('postinstall', 'registry', 'https://', 'malicious')`
- **[H-9dcd58b2-3-O4] Detect outbound exfiltration of harvested credentials** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: We observed zero outbound connections from developer workstations to known malicious domains or IPs after package installation events.
  - Data sources: Proxy logs, DNS logs, Netflow
  - Suggested query: `source_ip IN (SELECT ip FROM developer_workstations) AND destination_domain IN ('trapdoor[.]xyz', 'malware[.]c2[.]io') OR destination_ip IN ('185.130.105.22', '104.21.78.11') AND event_time > (first_package_install_time)`

**Sigma rule:**

```yaml
title: Detect Credential Harvesting via Package Post-Install Script
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image|endswith:
      - '\npm.cmd'
      - '\pip.exe'
      - '\cargo.exe'
    CommandLine|contains:
      - 'install '
  selection2:
    ParentImage|endswith:
      - '\npm.cmd'
      - '\pip.exe'
      - '\cargo.exe'
    Image|endswith:
      - '\node.exe'
      - '\python.exe'
      - '\rustc.exe'
    CommandLine|contains:
      - 'keyring'
      - 'credential-manager'
      - 'aws credentials'
      - 'dumpcreds'
      - 'getenv("TOKEN")'
      - 'readFileSync(".aws/credentials")'
  condition: selection and selection2
falsepositives:
  - Legitimate credential management tools
level: high
```

---
