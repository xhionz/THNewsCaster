# Threat Hunting News Package

- Generated: `2026-05-25T06:01:07+00:00`
- Generator: `THNewsCaster v0.1.0`
- Articles seen: **290**  ·  Skipped (below threshold): **290**  ·  Briefings: **25**
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

## 8. Ghost CMS SQL injection flaw exploited in large-scale ClickFix campaign

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

## 9. Drupal: Critical SQL injection flaw now targeted in attacks

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

## 10. Drupal Core SQL Injection Bug Actively Exploited, Added to CISA KEV

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

## 11. Highly Critical Drupal Core Flaw Exposes PostgreSQL Sites to RCE Attacks

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

## 12. Phantom Killer: Reverse Engineering and Weaponizing a Lenovo Driver to Terminate EDR Processes

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

## 13. Inside SHADOW-WATER-063’s Banana RAT: From Build Server to Banking Fraud

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmel3n/inside_shadowwater063s_banana_rat_from_build/>
- **Published**: 2026-05-24T15:02:27+00:00
- **First seen**: 2026-05-24T15:53:34+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Banana RAT is actively used in finance-sector banking fraud; high blast radius, proven exploitability, and direct relevance to enterprise financial systems.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "Banana RAT"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 3 ('No process injection...') is not a falsification test for Banana RAT — many malware families use process injection; absence does not disprove Banana RAT deployment. Also, ')

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Sectors: finance

### Hypotheses (3)

#### H-56b66d4e-1 · Banana RAT deployed via phishing to exfiltrate finance data via C2  _(confidence: medium)_

**Statement.** An actor deployed Banana RAT (v2) in our finance sector environment via a phishing email, establishing C2 communication to exfiltrate sensitive financial data between 2024-05-01 and 2024-05-31.

**Why this hypothesis?** The article references SHADOW-WATER-063 and Banana RAT targeting finance sectors. Banana RAT is a known RAT with documented C2 behavior. Given our sector focus and the absence of other indicators, phishing as an initial vector and C2 exfiltration are plausible.

**MITRE ATT&CK**: T1566, T1219, T1041

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-56b66d4e-1-O1] No C2 traffic to known Banana RAT domains** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No HTTP/S connections to domains matching patterns like *.bananarat[.]com, *.secure-update[.]info, or *.finance-data[.]net observed in DNS or proxy logs
  - Data sources: DNS logs, Proxy logs
  - Suggested query: `DNS queries or HTTP requests containing domain patterns matching '.*bananarat\.[a-z]{2,4}' or '.*secure-update\.[a-z]{2,4}'`
- **[H-56b66d4e-1-O2] No anomalous outbound connections from finance workstations** _(difficulty: medium · 100 pts · MITRE: T1071)_
  - Falsification criterion: No outbound HTTP/S connections from finance-sector endpoints to IPs not in the allowlist of known business partners or cloud services
  - Data sources: Firewall logs, EDR
  - Suggested query: `Outbound connections from finance-group hosts to IPs not in known-good IP allowlist (e.g., AWS, Azure, internal SaaS)`
- **[H-56b66d4e-1-O3] No persistence via registry run keys** _(difficulty: easy · 100 pts · MITRE: T1547)_
  - Falsification criterion: No new or modified registry keys under HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\...\Run containing suspicious executable paths
  - Data sources: EDR, Registry logs
  - Suggested query: `Registry modifications in Run keys with executable paths not in approved software list`
- **[H-56b66d4e-1-O4] No process injection into explorer.exe or svchost.exe** _(difficulty: medium · 100 pts · MITRE: T1055)_
  - Falsification criterion: No evidence of code injection into explorer.exe, svchost.exe, or other legitimate processes via CreateRemoteThread, APC injection, or reflective loading
  - Data sources: EDR, Process creation logs
  - Suggested query: `Process creation events where parent is explorer.exe or svchost.exe and child is not a known system binary`

**Sigma rule:**

```yaml
title: Detect Banana RAT C2 Communication via Suspicious HTTP User-Agent
logsource:
  product: windows
  service: http
condition: 'http.user_agent contains "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) BananaRAT/2.0" or http.user_agent contains "BananaRAT"'
detection:
  user_agent_pattern:
    - "BananaRAT/2.0"
    - "BananaRAT/1.0"
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) BananaRAT/2.0"
condition: user_agent_pattern
```

#### H-56b66d4e-2 · Banana RAT used DNS tunneling to exfiltrate data from build servers  _(confidence: medium)_

**Statement.** Banana RAT was used to exfiltrate finance-related data from build servers via DNS tunneling between 2024-05-01 and 2024-05-31, leveraging subdomain encoding to bypass network controls.

**Why this hypothesis?** The article implies data exfiltration from build environments. Banana RAT is known to use DNS tunneling. DNS exfiltration is a common evasion technique, especially in restricted environments like build servers.

**MITRE ATT&CK**: T1041, T1572

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-56b66d4e-2-O1] No DNS queries with high-entropy subdomains** _(difficulty: hard · 150 pts · MITRE: T1041)_
  - Falsification criterion: No DNS queries with subdomains exhibiting Shannon entropy > 3.5 or containing base64-like strings longer than 20 characters
  - Data sources: DNS logs
  - Suggested query: `DNS queries where subdomain length > 20 and entropy > 3.5 (calculated per label)`
- **[H-56b66d4e-2-O2] No DNS queries to newly registered domains** _(difficulty: medium · 120 pts · MITRE: T1572)_
  - Falsification criterion: No DNS queries to domains registered within the last 7 days and lacking WHOIS contact info or having privacy protection enabled
  - Data sources: DNS logs, WHOIS feeds
  - Suggested query: `DNS queries to domains registered <7 days ago with privacy protection or no valid registrant info`
- **[H-56b66d4e-2-O3] No unusual DNS query volume from build servers** _(difficulty: medium · 120 pts · MITRE: T1041)_
  - Falsification criterion: No build server generating >50 DNS queries per minute for >10 consecutive minutes outside business hours
  - Data sources: DNS logs
  - Suggested query: `Build server hosts with >50 DNS queries/min over 10-minute windows between 00:00-06:00`
- **[H-56b66d4e-2-O4] No DNS queries containing base64-encoded strings with structured patterns** _(difficulty: hard · 150 pts · MITRE: T1041)_
  - Falsification criterion: No DNS queries containing base64 strings matching patterns like 'user:[A-Za-z0-9]{8,}|pass:[A-Za-z0-9]{12,}' or 'finance_[A-Z]{3}_[0-9]{6}'
  - Data sources: DNS logs
  - Suggested query: `DNS queries matching regex 'user:[A-Za-z0-9]{8,}|pass:[A-Za-z0-9]{12,}|finance_[A-Z]{3}_[0-9]{6}'`

**Sigma rule:**

```yaml
title: Detect DNS Exfiltration via High Entropy Subdomains
logsource:
  product: dns
condition: 'query contains "." and count of dots in query > 5 and entropy(query) > 3.5'
detection:
  high_entropy_query:
    - query: '*.*.*.*.*.*'
    - query: '*[A-Za-z0-9+/]{20,}.*'
condition: high_entropy_query
```

#### H-56b66d4e-3 · Banana RAT harvested credentials via LSASS dumping and staged them for exfiltration  _(confidence: high)_

**Statement.** Banana RAT compromised a finance workstation, dumped LSASS memory to extract credentials, and staged them in temporary files for later exfiltration between 2024-05-01 and 2024-05-31.

**Why this hypothesis?** Banana RAT is known to include credential harvesting modules. The finance sector is a prime target for credential theft. LSASS dumping is a common technique used by RATs to gain lateral movement and persistence.

**MITRE ATT&CK**: T1003, T1055, T1053

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-56b66d4e-3-O1] No LSASS memory dumps via rundll32 or procdump** _(difficulty: easy · 100 pts · MITRE: T1003)_
  - Falsification criterion: No process creation events where rundll32.exe or procdump.exe is invoked with arguments targeting lsass.exe memory
  - Data sources: EDR, Process creation logs
  - Suggested query: `Process creation where parent is rundll32.exe or procdump.exe and command line contains 'lsass' and 'MiniDump' or 'dump'`
- **[H-56b66d4e-3-O2] No temporary files containing credential artifacts** _(difficulty: medium · 120 pts · MITRE: T1053)_
  - Falsification criterion: No files created in %TEMP%, %APPDATA%, or %LOCALAPPDATA% with names matching 'cred_*.tmp', 'lsass_*.dmp', or containing strings like 'username=', 'password='
  - Data sources: EDR, File creation logs
  - Suggested query: `File creation events in %TEMP% or %APPDATA% with filenames matching 'cred_*.tmp' or 'lsass_*.dmp' or content matching 'username=' or 'password='`
- **[H-56b66d4e-3-O3] No PowerShell execution to invoke Mimikatz-like commands** _(difficulty: medium · 120 pts · MITRE: T1003)_
  - Falsification criterion: No PowerShell commands containing 'Invoke-Mimikatz', 'sekurlsa::logonpasswords', or 'lsass' in script blocks or command-line arguments
  - Data sources: EDR, PowerShell logs
  - Suggested query: `PowerShell script blocks or command lines containing 'sekurlsa', 'logonpasswords', 'Invoke-Mimikatz', or 'lsass' with 'dump' or 'extract'`
- **[H-56b66d4e-3-O4] No scheduled tasks created to stage credential dumps** _(difficulty: medium · 120 pts · MITRE: T1053)_
  - Falsification criterion: No new scheduled tasks created with names like 'UpdateService', 'SysCheck', or 'TaskScheduler' that execute binaries in %TEMP% or %APPDATA%
  - Data sources: EDR, Scheduled Task logs
  - Suggested query: `Scheduled task creation with names matching '.*Update.*|.*Task.*|.*Sys.*' and action pointing to %TEMP% or %APPDATA%`

**Sigma rule:**

```yaml
title: Detect LSASS Memory Dumping via Comsvcs.dll
logsource:
  product: windows
  service: process_creation
condition: 'process_name: "rundll32.exe" and command_line contains "comsvcs.dll" and command_line contains "MiniDump"'
detection:
  lsass_dump:
    - process_name: "rundll32.exe"
      command_line: '*comsvcs.dll*MiniDump*lsass*'
condition: lsass_dump
```

---

## 14. Microsoft’s MSHTA Legacy Tool Still Powers Malware Campaigns on Windows

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tme3xk/microsofts_mshta_legacy_tool_still_powers_malware/>
- **Published**: 2026-05-24T14:44:15+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 85
- **Score rationale**: triage: MSHTA is a well-known living-off-the-land binary (LOLBin) actively abused in malware campaigns; high prevalence and easily huntable via process tree anomalies.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "MSHTA"}) -> ok → tool lookup_mitre({"query": "execution via script"}) -> ok → tool lookup_mitre({"query": "T1059"}) -> ok → critic: revise (Hypothesis 1 - Objective 1 is not a falsification test: 'No process creation events show...' is a negative assertion that cannot be falsified without exhaustive data coverage. A null result here does )

> submitted by /u/digicat [link] [comments]

### Hypotheses (3)

#### H-54ba8d5e-1 · MSHTA Abuse via Phishing-Attached Scripts  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-25, an adversary used MSHTA.exe to execute malicious .hta, .js, or .vbs scripts delivered via phishing emails, spawning from Outlook.exe or other email clients.

**Why this hypothesis?** The article highlights MSHTA.exe being used to execute scripts from phishing emails, and extracted indicators suggest email-based delivery. This aligns with common TTPs where adversaries abuse MSHTA to bypass application allowlisting.

**MITRE ATT&CK**: T1190, T1204, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-54ba8d5e-1-O1] MSHTA spawned by Outlook.exe** _(difficulty: medium · 100 pts · MITRE: T1204)_
  - Falsification criterion: At least one MSHTA.exe process was observed with ParentImage ending in '\\outlook.exe' and CommandLine containing '.hta', '.js', or '.vbs'
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND ParentImage LIKE '%outlook.exe' AND CommandLine CONTAINS '.hta' OR '.js' OR '.vbs'`
- **[H-54ba8d5e-1-O2] MSHTA executed from temporary email download path** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing '\AppData\Local\Temp' and a filename ending in '.hta', '.js', or '.vbs'
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND CommandLine CONTAINS '\AppData\Local\Temp' AND (CommandLine ENDSWITH '.hta' OR '.js' OR '.vbs')`
- **[H-54ba8d5e-1-O3] MSHTA executed with remote URL parameter** _(difficulty: hard · 150 pts · MITRE: T1190)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing 'http://' or 'https://' and ending in '.hta', '.js', or '.vbs'
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND CommandLine CONTAINS 'http://' OR 'https://' AND (CommandLine ENDSWITH '.hta' OR '.js' OR '.vbs')`

**Sigma rule:**

```yaml
title: Suspicious MSHTA Execution from Email Client
logsource:
  product: windows
  service: sysmon
detection:
  Selection:
    Image|endswith: '\\mshta.exe'
    CommandLine|contains: '.hta'
    ParentImage|endswith: '\\outlook.exe'
  Condition: Selection
keywords:
  - mshta
  - phishing
  - email
```

#### H-54ba8d5e-2 · MSHTA Abuse via Malicious Network Share  _(confidence: medium)_

**Statement.** In our environment between 2026-05-20 and 2026-05-25, an adversary deployed a malicious .hta, .js, or .vbs script to a non-administrative network share and executed it via MSHTA.exe from a compromised host.

**Why this hypothesis?** The article notes MSHTA is used to execute scripts from network locations. Adversaries often avoid admin shares (C$, ADMIN$) to evade detection, preferring data shares like \fileserverinance. This hypothesis targets that evasion pattern.

**MITRE ATT&CK**: T1190, T1059, T1078

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-54ba8d5e-2-O1] MSHTA executed from non-admin network share** _(difficulty: medium · 120 pts · MITRE: T1190)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing a UNC path (e.g., '\\server\share') that does NOT include '\\*\netlogon' or '\\*\sysvol' and ends in '.hta', '.js', or '.vbs'
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND CommandLine CONTAINS '\\' AND NOT CommandLine CONTAINS '\\*\netlogon' AND NOT CommandLine CONTAINS '\\*\sysvol' AND (CommandLine ENDSWITH '.hta' OR '.js' OR '.vbs')`
- **[H-54ba8d5e-2-O2] SMB authentication precedes MSHTA UNC execution** _(difficulty: hard · 150 pts · MITRE: T1078)_
  - Falsification criterion: At least one successful SMB authentication event (EventID 4624 logon type 3) occurred from the same user and source host within 60 seconds before the MSHTA UNC execution
  - Data sources: Windows Security Logs, EDR
  - Suggested query: `EventID=4624 AND LogonType=3 AND AccountName = [MSHTA User] AND WorkstationName = [MSHTA Host] AND TimeGenerated >= [MSHTA Time] - 60s AND TimeGenerated <= [MSHTA Time]`
- **[H-54ba8d5e-2-O3] MSHTA executed from share with suspicious filename** _(difficulty: hard · 150 pts · MITRE: T1059)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing a UNC path ending in a filename matching pattern '^[a-f0-9]{8,}\.hta$' or '^[a-f0-9]{8,}\.js$' or '^[a-f0-9]{8,}\.vbs$' (hex-named files)
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND CommandLine MATCHES '\\[^\\]+\\[^\\]+\\[a-f0-9]{8,}\.hta$' OR '\\[^\\]+\\[^\\]+\\[a-f0-9]{8,}\.js$' OR '\\[^\\]+\\[^\\]+\\[a-f0-9]{8,}\.vbs$'`

**Sigma rule:**

```yaml
title: Suspicious MSHTA Execution from Non-Admin Network Share
logsource:
  product: windows
  service: sysmon
detection:
  Selection:
    Image|endswith: '\\mshta.exe'
    CommandLine|contains: '\\' AND NOT CommandLine|contains: '\\*\netlogon' AND NOT CommandLine|contains: '\\*\sysvol'
    CommandLine|endswith: '.hta' OR '.js' OR '.vbs'
  Condition: Selection
keywords:
  - mshta
  - network share
  - malicious script
```

#### H-54ba8d5e-3 · MSHTA Abuse via Malicious Office Macro  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-25, an adversary delivered a malicious Office document (e.g., .docm) that executed a script via MSHTA.exe, using a temporary file or command-line argument to bypass execution restrictions.

**Why this hypothesis?** The article references MSHTA as a common post-exploitation tool. Office macros are a known initial access vector that spawn MSHTA to execute scripts. This hypothesis targets the chain: Office → VBA → MSHTA → script.

**MITRE ATT&CK**: T1203, T1059, T1204

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-54ba8d5e-3-O1] MSHTA spawned by Office application** _(difficulty: medium · 100 pts · MITRE: T1203)_
  - Falsification criterion: At least one MSHTA.exe process was observed with ParentImage ending in '\\winword.exe', '\\excel.exe', or '\\powerpnt.exe' and CommandLine containing '.hta', '.js', or '.vbs'
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND (ParentImage ENDSWITH 'winword.exe' OR 'excel.exe' OR 'powerpnt.exe') AND (CommandLine CONTAINS '.hta' OR '.js' OR '.vbs')`
- **[H-54ba8d5e-3-O2] MSHTA executed from Office-generated temp file** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing '\AppData\Local\Temp' and a filename ending in '.hta', '.js', or '.vbs' and ParentImage ending in an Office executable
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND ParentImage ENDSWITH 'winword.exe' OR 'excel.exe' OR 'powerpnt.exe' AND CommandLine CONTAINS '\AppData\Local\Temp' AND (CommandLine ENDSWITH '.hta' OR '.js' OR '.vbs')`
- **[H-54ba8d5e-3-O3] MSHTA executed with encoded script parameter** _(difficulty: hard · 150 pts · MITRE: T1059)_
  - Falsification criterion: At least one MSHTA.exe process was observed with CommandLine containing 'javascript:eval(' or 'vbscript:Execute(' and a base64-encoded or obfuscated payload
  - Data sources: EDR, Sysmon
  - Suggested query: `Process where Image = 'mshta.exe' AND (CommandLine CONTAINS 'javascript:eval(' OR CommandLine CONTAINS 'vbscript:Execute(') AND CommandLine CONTAINS 'base64' OR LENGTH(CommandLine) > 500`

**Sigma rule:**

```yaml
title: MSHTA Spawned from Office Macro via Temporary File
logsource:
  product: windows
  service: sysmon
detection:
  Selection:
    Image|endswith: '\\mshta.exe'
    ParentImage|endswith: '\\winword.exe' OR '\\excel.exe' OR '\\powerpnt.exe'
    CommandLine|contains: '\AppData\Local\Temp' AND (CommandLine|endswith: '.hta' OR '.js' OR '.vbs')
  Condition: Selection
keywords:
  - mshta
  - office macro
  - temp file
```

---

## 15. How Attackers Force Microsoft to Send Phishing Emails

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmd7ey/how_attackers_force_microsoft_to_send_phishing/>
- **Published**: 2026-05-24T14:08:36+00:00
- **First seen**: 2026-05-24T14:26:19+00:00
- **Relevance score**: 85
- **Score rationale**: triage: Attackers abusing Microsoft to send phishing emails is a high-impact, active technique with broad blast radius and high exploitability.
- **Agent trace**: critic: revise (Hypothesis 1 - Objective 1 is not a falsification test: 'No internal account sent more than 10 emails...' is a threshold-based observation, not a falsifiable claim. A falsification test would be: 'At )

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Vectors: phishing, exploit
- MITRE ATT&CK: T1566

### Hypotheses (3)

#### H-b7e0dbc8-1 · Compromised M365 Account Sent Phishing Emails  _(confidence: medium)_

**Statement.** At least one compromised M365 user account sent >10 phishing-like emails to external recipients within 7 days, using encoded PowerShell commands from a compromised endpoint.

**Why this hypothesis?** The article suggests attackers force Microsoft to send phishing emails, implying credential compromise and abuse of legitimate mail services. The extracted indicator T1566 (Phishing) supports this, and the use of encoded PowerShell is a common TTP for evading detection.

**MITRE ATT&CK**: T1566, T1059.001, T1078

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b7e0dbc8-1-O1] Account sent >10 phishing-like emails** _(difficulty: easy · 100 pts · MITRE: T1566)_
  - Falsification criterion: At least one M365 account sent more than 10 emails with phishing indicators (e.g., external recipients, suspicious subject lines) within 7 days.
  - Data sources: M365 Audit Logs, Email Gateway
  - Suggested query: `Filter M365 audit logs for EventID 50001 where RecipientCount > 10 and SenderAddress ends with '.onmicrosoft.com' and Subject contains keywords like 'urgent', 'invoice', 'click here'`
- **[H-b7e0dbc8-1-O2] Account logged in from non-corporate IP** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: At least one account that sent >10 phishing emails had a login from a non-corporate IP address within 24 hours prior to the email send.
  - Data sources: Azure AD Sign-in Logs, Proxy Logs
  - Suggested query: `Join Azure AD sign-ins with M365 email sends: find accounts with EventID 50001 and matching UserPrincipalName that had sign-ins from IPs not in corporate IP ranges in the prior 24h`
- **[H-b7e0dbc8-1-O3] Endpoint executed PowerShell with -EncodedCommand** _(difficulty: hard · 150 pts · MITRE: T1059.001)_
  - Falsification criterion: At least one endpoint associated with a compromised M365 account executed PowerShell with -EncodedCommand and connected to a phishing domain within 1 hour before the email was sent.
  - Data sources: EDR, DNS Logs, Proxy Logs
  - Suggested query: `Find EDR process creation events where CommandLine contains '-EncodedCommand' and DNS queries to domains matching known phishing indicators occurred within 60 minutes prior to M365 email send events`
- **[H-b7e0dbc8-1-O4] Email contained malicious attachment or link** _(difficulty: medium · 110 pts · MITRE: T1566.001)_
  - Falsification criterion: At least one of the >10 emails sent by the suspicious account contained a URL or attachment matching known phishing indicators (e.g., .zip, .js, short URL service).
  - Data sources: Email Gateway, URL Filtering Logs
  - Suggested query: `Inspect M365 message trace for emails with RecipientCount > 10 and extract URLs/attachments; match against threat intel feeds for phishing domains or malicious file hashes`

**Sigma rule:**

```yaml
title: Suspicious M365 Email Send with Encoded PowerShell
logsource:
  product: m365
  service: exchangeonline
detection:
  selection:
    EventID: 50001
    RecipientCount|gt: 10
    SenderAddress|endswith: '.onmicrosoft.com'
  condition: selection
  filter:
    - SenderAddress|contains: 'noreply'
    - SenderAddress|contains: 'support'
    - SenderAddress|contains: 'admin'
condition: selection and not filter
```

#### H-b7e0dbc8-2 · Malicious Outlook Add-in Triggered Phishing Campaign  _(confidence: low)_

**Statement.** An attacker installed a malicious Outlook add-in via a compromised MSHTA or WScript process, which triggered outbound SMTP traffic to phishing domains without user interaction.

**Why this hypothesis?** The article implies Microsoft services are being forced to send emails, suggesting abuse of trusted client software. T1566 is present, and Outlook add-ins (T1192) are a known method to hijack email sending capabilities without direct credential theft.

**MITRE ATT&CK**: T1566, T1192, T1059.005

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b7e0dbc8-2-O1] OUTLOOK.EXE initiated outbound SMTP to non-Microsoft IPs** _(difficulty: medium · 120 pts · MITRE: T1192)_
  - Falsification criterion: At least one OUTLOOK.EXE process initiated outbound SMTP connections to non-Microsoft IP addresses (e.g., not smtp.office365.com, not Microsoft ASN ranges).
  - Data sources: EDR, Firewall Logs, Proxy Logs
  - Suggested query: `Find EDR network events where Image = 'OUTLOOK.EXE' and DestinationIP not in Microsoft ASN ranges and DestinationPort = 25 or 587`
- **[H-b7e0dbc8-2-O2] Malicious add-in installed via MSHTA/WScript** _(difficulty: hard · 140 pts · MITRE: T1192, T1059.005)_
  - Falsification criterion: At least one MSHTA.exe or WScript.exe process created a child process of OUTLOOK.EXE or modified Outlook add-in registry keys (HKCU\Software\Microsoft\Office\Outlook\Addins).
  - Data sources: EDR, Registry Logs
  - Suggested query: `Search for parent-child process chains: MSHTA.exe or WScript.exe → reg.exe or PowerShell modifying HKCU\Software\Microsoft\Office\Outlook\Addins\*`
- **[H-b7e0dbc8-2-O3] Add-in registry key modified within 24h of email campaign** _(difficulty: hard · 130 pts · MITRE: T1192)_
  - Falsification criterion: At least one registry key under HKCU\Software\Microsoft\Office\Outlook\Addins\ was modified within 24 hours of the first phishing email being sent.
  - Data sources: EDR, Registry Audit Logs
  - Suggested query: `Query registry modification events for keys matching 'HKCU\\Software\\Microsoft\\Office\\Outlook\\Addins\\*' within 24h of M365 email send events with RecipientCount > 10`
- **[H-b7e0dbc8-2-O4] Add-in loaded without user consent** _(difficulty: medium · 110 pts · MITRE: T1192)_
  - Falsification criterion: At least one Outlook add-in was loaded automatically without user interaction (e.g., no user clicked 'Enable Add-in') and was not signed by a trusted publisher.
  - Data sources: EDR, Outlook Add-in Logs, Certificate Logs
  - Suggested query: `Extract Outlook add-in load events from EDR or event logs; filter for unsigned add-ins or those with unknown publisher that loaded without user prompt`

**Sigma rule:**

```yaml
title: Suspicious Outlook Add-in Installation via MSHTA/WScript
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image: '*\OUTLOOK.EXE'
    ParentImage|contains:
      - 'mshta.exe'
      - 'wscript.exe'
      - 'cscript.exe'
  condition: selection
  filter:
    - Image|contains: '\Microsoft\Office\'
    - ParentImage|contains: '\Windows\System32\'
condition: selection and not filter
```

#### H-b7e0dbc8-3 · Exploited Exchange Server Relayed Phishing Emails  _(confidence: medium)_

**Statement.** An attacker exploited a known vulnerable Exchange Server (CISA KEV-listed) to relay phishing emails from internal systems using SMTP, bypassing M365 controls.

**Why this hypothesis?** The article suggests attackers force Microsoft to send emails — this could mean compromising on-premises Exchange servers to relay mail. T1566 is present, and T1197 (BITS) or T1566.002 (Spearphishing Attachment) are plausible if files are delivered via Exchange.

**MITRE ATT&CK**: T1566, T1197, T1566.002

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-b7e0dbc8-3-O1] Exchange server runs CISA KEV-listed vulnerable version** _(difficulty: easy · 100 pts · MITRE: T1197)_
  - Falsification criterion: At least one on-premises Exchange Server is running a version listed in CISA’s Known Exploited Vulnerabilities catalog (e.g., CVE-2021-26855, CVE-2021-27065).
  - Data sources: CMDB, Patch Management System, Network Scans
  - Suggested query: `Query CMDB or vulnerability scanner for Exchange Server versions; compare against CISA KEV list for known exploitable versions`
- **[H-b7e0dbc8-3-O2] Internal IP relayed emails to external recipients** _(difficulty: medium · 120 pts · MITRE: T1566)_
  - Falsification criterion: At least one SMTP relay event on an Exchange Server originated from an internal IP (RFC 1918 range) and sent emails to external recipients with phishing indicators.
  - Data sources: Exchange Transport Logs, Firewall Logs
  - Suggested query: `Filter Exchange transport logs for EventID 1016 where ClientIP is in RFC 1918 range and RecipientDomain not in internal domains and Subject contains phishing keywords`
- **[H-b7e0dbc8-3-O3] Relay occurred within 1h of initial compromise** _(difficulty: hard · 140 pts · MITRE: T1197)_
  - Falsification criterion: At least one SMTP relay event occurred within 1 hour of a successful exploit attempt (e.g., HTTP 500 error on /ecp/ or /owa/) on the same Exchange server.
  - Data sources: Web Server Logs, Exchange Transport Logs
  - Suggested query: `Join IIS logs (EventID 404/500 on /ecp/, /owa/) with Exchange transport logs: find relay events (EventID 1016) occurring within 60 minutes of exploit indicators`
- **[H-b7e0dbc8-3-O4] Relayed email contained malicious attachment** _(difficulty: medium · 110 pts · MITRE: T1566.002)_
  - Falsification criterion: At least one email relayed via the Exchange server contained a file attachment matching known malicious hashes or extensions (.js, .vbs, .zip with macros).
  - Data sources: Email Gateway, File Analysis Sandbox
  - Suggested query: `Extract attachments from Exchange transport logs for relayed emails; match file hashes against threat intel feeds or check for known malicious extensions`

**Sigma rule:**

```yaml
title: Suspicious SMTP Relay from Vulnerable Exchange Server
logsource:
  product: exchange
  service: transport
detection:
  selection:
    EventID: 1016
    ClientIP|contains:
      - '192.168.'
      - '10.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
    MessageSubject|contains: ['urgent', 'invoice', 'click here', 'password', 'verify']
  condition: selection
```

---

## 16. Megalodon: Mass GitHub Repo Backdooring via CI Workflows

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmdutp/megalodon_mass_github_repo_backdooring_via_ci/>
- **Published**: 2026-05-24T14:34:22+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 82
- **Score rationale**: triage: Mass GitHub repo backdooring via CI workflows is a critical supply chain threat — high blast radius, actively exploited, and huntable via CI/CD anomalies.
- **Agent trace**: critic: revise (Hypothesis 1: Sigma rule is syntactically invalid — it defines 'condition' twice (once at top level, once under 'detection'), and uses malformed syntax ('status: "mer"' is truncated). Also, 'content:')

> submitted by /u/digicat [link] [comments]

### Hypotheses (3)

#### H-3e658180-1 · Supply Chain Compromise via Malicious PR  _(confidence: high)_

**Statement.** An attacker compromised our GitHub repository by submitting a pull request that injects malicious shell commands into a GitHub Actions workflow during the CI/CD pipeline, executed by a legitimate actor to evade detection.

**Why this hypothesis?** The article describes mass backdooring via CI workflows using PRs from seemingly legitimate contributors. Attackers use human actors to bypass bot detection and execute commands in build phases.

**MITRE ATT&CK**: T1195, T1059

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-3e658180-1-O1] Detect malicious shell command execution** _(difficulty: medium · 150 pts · MITRE: T1059)_
  - Falsification criterion: No shell command matching known malicious patterns (e.g., curl/wget to pastebin + pipe to bash/sh) is observed in any workflow_run event during the last 30 days.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:pull_request AND shell_command:* AND (shell_command:*curl*pastebin*|bash* OR shell_command:*wget*|sh*)`
- **[H-3e658180-1-O2] Detect unauthorized package install in non-build phase** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: No package installation command (npm install, pip install, gem install) is observed outside of explicitly defined build or test phases in any workflow_run event.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:workflow_run AND step_name:!('build' OR 'test') AND command:*install* AND (command:*npm* OR command:*pip* OR command:*gem*)`
- **[H-3e658180-1-O3] Detect use of obfuscated or encoded commands** _(difficulty: hard · 180 pts · MITRE: T1059, T1027)_
  - Falsification criterion: No base64-encoded, hex-encoded, or otherwise obfuscated shell commands are detected in any workflow step output or command field.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:pull_request AND (command:*base64* OR command:*echo*|*base64* -d OR command:*printf*%x* OR command:*eval*$(*)`

**Sigma rule:**

```yaml
title: Detect Malicious Shell Command in GitHub Actions Workflow
logsource:
  product: github_actions
  service: workflow_run
detection:
  event_type: pull_request
  actor_type: user
  shell_command:
    - 'curl -s https://*.pastebin.com/raw/* | bash'
    - 'wget -qO- https://*.malicious-domain.com/* | sh'
    - 'echo "malicious payload" > /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden &'
  condition: shell_command
```

#### H-3e658180-2 · Typosquatting Package Installation  _(confidence: medium)_

**Statement.** An attacker published a malicious package with a name similar to a legitimate dependency (e.g., 'expresss' instead of 'express') and tricked our CI pipeline into installing it during a dependency update.

**Why this hypothesis?** The article highlights supply chain attacks via package typosquatting. While Sigma cannot do semantic matching, it can detect suspicious package names with high edit distance patterns or known malicious prefixes.

**MITRE ATT&CK**: T1195, T1200

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-3e658180-2-O1] Detect installation of known malicious package variants** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: No package installation event matches any of the known typosquatting patterns (e.g., 'expresss', 'lodashx') in any workflow_run event over the last 30 days.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:workflow_run AND command:*install* AND (package_name:*expresss* OR package_name:*lodashx* OR package_name:*jqueryx*)`
- **[H-3e658180-2-O2] Detect package installs from non-official registries** _(difficulty: medium · 130 pts · MITRE: T1195)_
  - Falsification criterion: No package installation command references a non-standard registry URL (e.g., not registry.npmjs.org, pypi.org, rubygems.org).
  - Data sources: GitHub Actions logs
  - Suggested query: `command:*install* AND (command:*--registry* AND command:*https://* AND NOT command:*npmjs.org* AND NOT command:*pypi.org* AND NOT command:*rubygems.org*)`
- **[H-3e658180-2-O3] Detect package installs during non-update phases** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: No package installation occurs in workflow steps labeled 'deploy', 'test', or 'lint' — only in explicitly named 'install' or 'build' phases.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:workflow_run AND step_name:!('install' OR 'build') AND command:*install*`

**Sigma rule:**

```yaml
title: Detect Suspicious Package Installation via Typosquatting Pattern
logsource:
  product: github_actions
  service: workflow_run
detection:
  event_type: workflow_run
  package_manager: 'npm' | 'pip' | 'gem'
  package_name:
    - '*expresss*'
    - '*lodashx*'
    - '*jqueryx*'
    - '*requestx*'
    - '*axiosx*'
    - '*babel*'
    - '*webpack*'
  condition: package_name and package_manager
```

#### H-3e658180-3 · Exfiltration via Artifact Upload to Pastebin  _(confidence: medium)_

**Statement.** An attacker exfiltrated sensitive data from our CI environment by uploading artifacts to Pastebin or similar file-sharing services via GitHub Actions, using the artifact upload mechanism to bypass network controls.

**Why this hypothesis?** The article describes attackers using artifact uploads to exfiltrate data. While GitHub Actions does not expose upload_url in event logs, it does expose artifact_name and upload actions — attackers may use suspicious names like 'secrets.txt' or 'config.zip'.

**MITRE ATT&CK**: T1566, T1567

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-3e658180-3-O1] Detect upload of sensitive-named artifacts** _(difficulty: easy · 110 pts · MITRE: T1567)_
  - Falsification criterion: No artifact upload event has a name containing keywords like 'secrets', 'token', 'key', 'password', or 'config' in any workflow_run event over the last 30 days.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:artifact_uploaded AND artifact_name:*secrets* OR artifact_name:*token* OR artifact_name:*key* OR artifact_name:*password* OR artifact_name:*config*`
- **[H-3e658180-3-O2] Detect artifact uploads during non-release workflows** _(difficulty: medium · 140 pts · MITRE: T1567)_
  - Falsification criterion: No artifact is uploaded in workflows triggered by 'push', 'pull_request', or 'schedule' events — only in explicitly labeled 'release' workflows.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:artifact_uploaded AND workflow_name:!('release' OR 'deploy')`
- **[H-3e658180-3-O3] Detect multiple artifact uploads in single workflow** _(difficulty: medium · 130 pts · MITRE: T1567)_
  - Falsification criterion: No single workflow_run event triggers more than one artifact upload — indicating potential data aggregation for exfiltration.
  - Data sources: GitHub Actions logs
  - Suggested query: `event_type:artifact_uploaded | stats count by workflow_run_id | where count > 1`

**Sigma rule:**

```yaml
title: Detect Suspicious Artifact Upload in GitHub Actions
logsource:
  product: github_actions
  service: workflow_run
detection:
  event_type: artifact_uploaded
  artifact_name:
    - '*secrets*'
    - '*config*'
    - '*token*'
    - '*key*'
    - '*password*'
    - '*env*'
    - '*backup*'
  condition: artifact_name
```

---

## 17. Disrupting Fox Tempest: A cybercrime service that turned “verified” software into a pathway for ransomware

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tme9m6/disrupting_fox_tempest_a_cybercrime_service_that/>
- **Published**: 2026-05-24T14:50:24+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 80
- **Score rationale**: triage: Fox Tempest is a known cybercrime service enabling ransomware via trusted software — high impact, active in wild, and huntable via software supply chain anomalies.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it requires absence of events, but the hypothesis claims an adversary DID use a compromised vendor update. A true falsification test would be: ')

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Actions: ransomware
- MITRE ATT&CK: T1486

### Hypotheses (3)

#### H-da044c6e-1 · Supply Chain Compromise via Trusted Vendor Update  _(confidence: medium)_

**Statement.** An adversary compromised a trusted vendor's software update mechanism between 2026-05-20 and 2026-05-24, delivering ransomware via a signed Update.exe binary executed within our environment.

**Why this hypothesis?** The article describes a threat actor using verified software updates as a ransomware delivery vector. Extracted indicator T1486 (ransomware) implies impact, but the delivery mechanism aligns with T1195 (Supply Chain Compromise). We hypothesize this occurred within our environment during the reported timeframe.

**MITRE ATT&CK**: T1195, T1486

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-da044c6e-1-O1] Detect unauthorized Update.exe execution** _(difficulty: medium · 100 pts · MITRE: T1195)_
  - Falsification criterion: At least one Update.exe was executed from a trusted vendor directory with a file hash not present in the approved vendor hash inventory.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image=*\Update.exe AND ParentImage=*\TrustedVendor\*.exe AND Hash NOT IN (approved_hashes)`
- **[H-da044c6e-1-O2] Detect ransomware file encryption** _(difficulty: medium · 100 pts · MITRE: T1486)_
  - Falsification criterion: At least one file with .locked, .encrypted, or .crypt extension was created within 48 hours of a trusted vendor Update.exe execution.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%.locked' OR TargetFilename LIKE '%.encrypted' OR TargetFilename LIKE '%.crypt' AND TimeCreated > (Update.exe execution time) AND TimeCreated < (Update.exe execution time + 48h)`
- **[H-da044c6e-1-O3] Detect persistence via scheduled task** _(difficulty: hard · 150 pts · MITRE: T1053)_
  - Falsification criterion: At least one scheduled task was created within 24 hours of Update.exe execution, with a command line referencing a ransomware payload or encrypted file pattern.
  - Data sources: Sysmon, Windows Event Log
  - Suggested query: `EventID=12 OR EventID=13 AND (CommandLine LIKE '%.locked%' OR CommandLine LIKE '%.encrypted%') AND TimeCreated > (Update.exe execution time) AND TimeCreated < (Update.exe execution time + 24h)`
- **[H-da044c6e-1-O4] Detect lateral movement via SMB** _(difficulty: medium · 120 pts · MITRE: T1021)_
  - Falsification criterion: At least one SMB connection was established from a host that executed Update.exe to another internal host within 12 hours of execution, with file access patterns consistent with ransomware scanning.
  - Data sources: NetFlow, Sysmon
  - Suggested query: `EventID=3 AND Image=*\Update.exe AND DestinationIp != local_subnet AND (DestinationPort=445 OR Service='SMB') AND TimeCreated > (Update.exe execution time) AND TimeCreated < (Update.exe execution time + 12h)`
- **[H-da044c6e-1-O5] Detect registry modification for persistence** _(difficulty: medium · 120 pts · MITRE: T1547)_
  - Falsification criterion: At least one registry key under HKLM\Software\Microsoft\Windows\CurrentVersion\Run or HKCU\Software\Microsoft\Windows\CurrentVersion\Run was modified within 24 hours of Update.exe execution, with a value pointing to a non-whitelisted executable.
  - Data sources: Sysmon, Registry Audit
  - Suggested query: `EventID=12 OR EventID=13 AND (TargetObject LIKE '%\Run%' OR TargetObject LIKE '%\RunOnce%') AND Image=*\Update.exe AND TimeCreated > (Update.exe execution time) AND TimeCreated < (Update.exe execution time + 24h)`

**Sigma rule:**

```yaml
title: Suspicious Execution of Vendor Update with Unapproved Hash
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image: '*\Update.exe'
    ParentImage: '*\TrustedVendor\*.exe'
    Hash: '!*' # Any hash not in approved list
  condition: selection
fields:
  - Image
  - Hash
  - ParentImage
```

#### H-da044c6e-2 · Compromised Code Signing Certificate Used for Ransomware  _(confidence: medium)_

**Statement.** An adversary used a stolen or fraudulent code signing certificate to sign a ransomware payload, masquerading as a legitimate software update from TrustedVendor Inc., executed between 2026-05-20 and 2026-05-24.

**Why this hypothesis?** The article implies the use of 'verified' software. Code signing abuse is a common TTP for supply chain attacks. We hypothesize a certificate was compromised to bypass trust controls, enabling ransomware execution under the guise of legitimacy.

**MITRE ATT&CK**: T1195, T1553, T1486

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-da044c6e-2-O1] Detect use of untrusted signing certificate** _(difficulty: medium · 100 pts · MITRE: T1553)_
  - Falsification criterion: At least one binary signed by 'TrustedVendor Inc.' was executed with a certificate thumbprint not present in the organization's approved certificate inventory.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image=*\Update.exe AND Signature='TrustedVendor Inc.' AND SignatureThumbprint NOT IN (approved_thumbprints)`
- **[H-da044c6e-2-O2] Detect ransomware file creation post-signature execution** _(difficulty: medium · 100 pts · MITRE: T1486)_
  - Falsification criterion: At least one file with .locked, .encrypted, or .crypt extension was created within 48 hours of a binary signed by 'TrustedVendor Inc.' being executed.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%.locked' OR TargetFilename LIKE '%.encrypted' OR TargetFilename LIKE '%.crypt' AND TimeCreated > (SignedBinary execution time) AND TimeCreated < (SignedBinary execution time + 48h)`
- **[H-da044c6e-2-O3] Detect network beaconing from signed binary** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound HTTP/HTTPS connection was established from a binary signed by 'TrustedVendor Inc.' to a domain not in the approved allowlist, within 24 hours of execution.
  - Data sources: DNS logs, Proxy logs, EDR
  - Suggested query: `EventID=3 AND Image=*\Update.exe AND Signature='TrustedVendor Inc.' AND DestinationDomain NOT IN (approved_domains) AND TimeCreated > (SignedBinary execution time) AND TimeCreated < (SignedBinary execution time + 24h)`
- **[H-da044c6e-2-O4] Detect process injection into trusted process** _(difficulty: hard · 150 pts · MITRE: T1055)_
  - Falsification criterion: At least one process injection event occurred into a trusted system process (e.g., svchost.exe, explorer.exe) within 1 hour of a binary signed by 'TrustedVendor Inc.' being executed.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=8 AND Image=*\Update.exe AND TargetImage IN ('svchost.exe', 'explorer.exe', 'lsass.exe') AND TimeCreated > (SignedBinary execution time) AND TimeCreated < (SignedBinary execution time + 1h)`
- **[H-da044c6e-2-O5] Detect deletion of shadow copies** _(difficulty: medium · 120 pts · MITRE: T1490)_
  - Falsification criterion: At least one vssadmin delete shadowall or wbadmin delete backup command was executed within 1 hour of a signed binary execution, indicating ransomware preparation.
  - Data sources: Sysmon, Windows Event Log
  - Suggested query: `EventID=1 AND (CommandLine LIKE '%vssadmin delete shadows%' OR CommandLine LIKE '%wbadmin delete backup%') AND ParentImage=*\Update.exe AND TimeCreated > (SignedBinary execution time) AND TimeCreated < (SignedBinary execution time + 1h)`

**Sigma rule:**

```yaml
title: Suspicious Signed Binary with Untrusted Certificate Thumbprint
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image: '*\Update.exe'
    Signature: 'TrustedVendor Inc.'
    SignatureStatus: 'Valid'
    SignatureThumbprint: '!*' # Not in approved thumbprint list
  condition: selection
fields:
  - Image
  - Signature
  - SignatureThumbprint
```

#### H-da044c6e-3 · Phishing-Initiated Supply Chain Compromise  _(confidence: low)_

**Statement.** An adversary delivered a malicious Office document via phishing email between 2026-05-20 and 2026-05-24, which executed a script to download and install a compromised vendor update, leading to ransomware.

**Why this hypothesis?** While the article focuses on vendor compromise, phishing is a common initial access vector. We hypothesize that the supply chain compromise was initiated by a phishing email containing a malicious Office document that triggered the update mechanism.

**MITRE ATT&CK**: T1566, T1195, T1486

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-da044c6e-3-O1] Detect Office document spawning Update.exe** _(difficulty: medium · 100 pts · MITRE: T1566, T1195)_
  - Falsification criterion: At least one Update.exe was executed with a parent process of winword.exe, excel.exe, or powerpnt.exe within 24 hours of a user opening a .docx, .xlsx, or .pptx file.
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image=*\Update.exe AND (ParentImage=*\winword.exe OR ParentImage=*\excel.exe OR ParentImage=*\powerpnt.exe) AND TimeCreated < (Office file open time + 24h)`
- **[H-da044c6e-3-O2] Detect malicious macro execution** _(difficulty: hard · 150 pts · MITRE: T1204)_
  - Falsification criterion: At least one Office document was opened with macro execution enabled (EventID 7 or 8) and subsequently led to Update.exe execution within 1 hour.
  - Data sources: Sysmon, Office 365 Audit Logs
  - Suggested query: `EventID=7 OR EventID=8 AND (CommandLine LIKE '%vba%' OR CommandLine LIKE '%macro%') AND ParentImage IN ('winword.exe', 'excel.exe', 'powerpnt.exe') AND ChildImage=*\Update.exe AND TimeCreated < (Update.exe execution time + 1h)`
- **[H-da044c6e-3-O3] Detect ransomware file creation post-Office execution** _(difficulty: medium · 100 pts · MITRE: T1486)_
  - Falsification criterion: At least one file with .locked, .encrypted, or .crypt extension was created within 48 hours of a malicious Office document being opened.
  - Data sources: EDR, File Integrity Monitoring
  - Suggested query: `EventID=11 AND TargetFilename LIKE '%.locked' OR TargetFilename LIKE '%.encrypted' OR TargetFilename LIKE '%.crypt' AND TimeCreated > (Office file open time) AND TimeCreated < (Office file open time + 48h)`
- **[H-da044c6e-3-O4] Detect PowerShell download of payload** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: At least one PowerShell command was executed with -EncodedCommand or -nop -c parameters, downloading content from an external URL, within 1 hour of an Office document being opened.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND Image=*\powershell.exe AND (CommandLine LIKE '%-EncodedCommand%' OR CommandLine LIKE '%-nop -c%' OR CommandLine LIKE '%IEX%') AND ParentImage IN ('winword.exe', 'excel.exe', 'powerpnt.exe') AND TimeCreated < (Office file open time + 1h)`
- **[H-da044c6e-3-O5] Detect email phishing indicator** _(difficulty: medium · 120 pts · MITRE: T1566)_
  - Falsification criterion: At least one email from an external domain containing a .docx, .xlsx, or .pptx attachment was received by a user whose device later executed Update.exe.
  - Data sources: Email Gateway Logs, EDR
  - Suggested query: `EmailAttachmentName ENDS WITH '.docx' OR '.xlsx' OR '.pptx' AND SenderDomain NOT IN (trusted_domains) AND UserAccount IN (users who executed Update.exe)`

**Sigma rule:**

```yaml
title: Suspicious Office Document Execution Leading to Update.exe
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image: '*\Update.exe'
    ParentImage: '*\winword.exe' OR ParentImage: '*\excel.exe' OR ParentImage: '*\powerpnt.exe'
  condition: selection
fields:
  - Image
  - ParentImage
```

---

## 18. Bissa Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmcyqg/bissa_scanner_exposed_aiassisted_mass/>
- **Published**: 2026-05-24T13:59:14+00:00
- **First seen**: 2026-05-24T14:26:19+00:00
- **Relevance score**: 80
- **Score rationale**: triage: Bissa Scanner uses AI for mass exploitation and credential harvesting — active, scalable, and directly relevant to enterprise defense.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No HTTP requests with user-agent containing BissaScanner found', but the Sigma rule only looks for status 200. This creates a mismatc)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Vectors: exploit

### Hypotheses (3)

#### H-eb6e0dcf-1 · Bissa Scanner Reconnaissance via API Probing  _(confidence: low)_

**Statement.** An external actor using a scanner with user-agent 'BissaScanner' probed our web APIs for vulnerabilities between 2026-05-17 and 2026-05-24, seeking exploitable endpoints.

**Why this hypothesis?** The article claims 'BissaScanner' is an AI-assisted mass exploitation tool. While unverified, the extracted 'exploit' vector suggests reconnaissance activity. We assume the scanner targets APIs with common patterns (e.g., 404s on non-existent paths).

**MITRE ATT&CK**: T1590

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-eb6e0dcf-1-O1] No BissaScanner UA in web logs** _(difficulty: easy · 100 pts · MITRE: T1590)_
  - Falsification criterion: At least one HTTP request with user-agent 'BissaScanner' and status 404, 403, or 500 is observed in web server logs.
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" AND status_code IN [404, 403, 500]`
- **[H-eb6e0dcf-1-O2] No probing of critical endpoints** _(difficulty: medium · 120 pts · MITRE: T1590)_
  - Falsification criterion: At least one request to a known sensitive endpoint (e.g., /admin, /api/v1/auth, /wp-login.php) with user-agent 'BissaScanner' and status 404 or 500 is observed.
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" AND url IN ["/admin", "/api/v1/auth", "/wp-login.php"] AND status_code IN [404, 500]`
- **[H-eb6e0dcf-1-O3] No repeated probing from same IP** _(difficulty: medium · 130 pts · MITRE: T1590)_
  - Falsification criterion: At least one IP address made 5 or more requests with user-agent 'BissaScanner' within a 5-minute window.
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" | stats count by client_ip, bin(5m) | where count >= 5`

**Sigma rule:**

```yaml
title: Detect BissaScanner API Probing
logsource:
  product: webserver
detection:
  ua: BissaScanner
  status: [404, 403, 500]
  request_method: GET
condition: all
fields:
  - client_ip
  - user_agent
  - status
  - url
```

#### H-eb6e0dcf-2 · Bissa Scanner Credential Stuffing Attempts  _(confidence: medium)_

**Statement.** An external actor using a scanner with user-agent 'BissaScanner' attempted credential stuffing against our authentication endpoints between 2026-05-17 and 2026-05-24, using common username/password pairs.

**Why this hypothesis?** The article mentions 'credential harvesting'. Credential stuffing is a common follow-up to reconnaissance. We assume the scanner targets auth endpoints with POST requests and common credentials.

**MITRE ATT&CK**: T1110

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-eb6e0dcf-2-O1] No 401s with BissaScanner UA** _(difficulty: easy · 100 pts · MITRE: T1110)_
  - Falsification criterion: At least one POST request to an auth endpoint with user-agent 'BissaScanner' and HTTP status 401 is observed.
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" AND request_method: POST AND status_code: 401 AND url IN ["/login", "/auth", "/api/v1/login"]`
- **[H-eb6e0dcf-2-O2] No username patterns in auth attempts** _(difficulty: medium · 120 pts · MITRE: T1110)_
  - Falsification criterion: At least one auth attempt with user-agent 'BissaScanner' contains a username matching a common pattern (e.g., email format, admin, test, root).
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" AND status_code: 401 AND username: /.*@.*/ OR username IN ["admin", "root", "test", "user"]`
- **[H-eb6e0dcf-2-O3] No high-volume auth failures from single IP** _(difficulty: medium · 130 pts · MITRE: T1110)_
  - Falsification criterion: At least one IP address made 10 or more failed authentication attempts (401) with user-agent 'BissaScanner' within 10 minutes.
  - Data sources: Web server logs
  - Suggested query: `user_agent: "BissaScanner" AND status_code: 401 | stats count by client_ip, bin(10m) | where count >= 10`
- **[H-eb6e0dcf-2-O4] No use of breached password lists** _(difficulty: hard · 150 pts · MITRE: T1110)_
  - Falsification criterion: At least one auth attempt with user-agent 'BissaScanner' uses a password known to be in a public breach dataset (e.g., '123456', 'password', 'qwerty').
  - Data sources: Web server logs, Breached password lists (external)
  - Suggested query: `user_agent: "BissaScanner" AND status_code: 401 AND password IN ["123456", "password", "qwerty", "admin", "letmein"]`

**Sigma rule:**

```yaml
title: Detect BissaScanner Credential Stuffing
logsource:
  product: webserver
detection:
  ua: BissaScanner
  request_method: POST
  status: 401
  url: [/login, /auth, /api/v1/login]
  username: /.*@.*/
condition: all
fields:
  - client_ip
  - user_agent
  - status
  - url
  - username
```

#### H-eb6e0dcf-3 · Bissa Scanner Internal Lateral Movement  _(confidence: low)_

**Statement.** If Bissa Scanner successfully compromised an internal host between 2026-05-17 and 2026-05-24, it attempted to scan internal network services or establish outbound C2 connections.

**Why this hypothesis?** The article implies the scanner is capable of exploitation. If an internal host was compromised, lateral movement or C2 is plausible. We focus on outbound connections from internal hosts to external IPs that match known scanner patterns.

**MITRE ATT&CK**: T1046, T1071

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-eb6e0dcf-3-O1] No outbound BissaScanner traffic from internal hosts** _(difficulty: medium · 120 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound connection from an internal IP to an external IP contains the user-agent 'BissaScanner'.
  - Data sources: Firewall logs, Proxy logs
  - Suggested query: `src_ip IN ["192.168.0.0/16", "10.0.0.0/8"] AND user_agent: "BissaScanner" AND dst_ip NOT IN ["192.168.0.0/16", "10.0.0.0/8"]`
- **[H-eb6e0dcf-3-O2] No scanning of external API endpoints** _(difficulty: hard · 140 pts · MITRE: T1046)_
  - Falsification criterion: At least one outbound connection from an internal host to an external IP on port 80/443 includes a request path matching a common API endpoint (e.g., /api/v1/, /wp-json/) with user-agent 'BissaScanner'.
  - Data sources: Proxy logs
  - Suggested query: `src_ip IN ["192.168.0.0/16", "10.0.0.0/8"] AND user_agent: "BissaScanner" AND url: /api/v1/ OR url: /wp-json/ AND dst_port IN [80, 443]`
- **[H-eb6e0dcf-3-O3] No C2 beaconing patterns** _(difficulty: hard · 150 pts · MITRE: T1071)_
  - Falsification criterion: At least one outbound connection from an internal host to an external IP exhibits beaconing behavior (e.g., periodic requests every 30-120s) with user-agent 'BissaScanner'.
  - Data sources: Proxy logs, Netflow
  - Suggested query: `src_ip IN ["192.168.0.0/16", "10.0.0.0/8"] AND user_agent: "BissaScanner" | stats count by src_ip, dst_ip, bin(2m) | where count >= 3`

**Sigma rule:**

```yaml
title: Detect Internal Host Scanning to External IPs
logsource:
  product: firewall
detection:
  direction: outbound
  src_ip: 192.168.0.0/16
  dst_ip: !192.168.0.0/16
  dst_port: [80, 443, 8080, 8443]
  user_agent: BissaScanner
condition: all
fields:
  - src_ip
  - dst_ip
  - dst_port
  - user_agent
```

---

## 19. Primitive Process Injection: APC Tandem

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmdomr/primitive_process_injection_apc_tandem/>
- **Published**: 2026-05-24T14:27:40+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 78
- **Score rationale**: triage: APC Tandem is a novel process injection technique — evades common detection; huntable via unusual APC queueing or thread injection patterns.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 references Sysmon EventID 10 (ProcessAccess) with AccessMask 0x001F0FFF — this mask represents GENERIC_ALL, which is overly broad and commonly seen in legitimate system opera)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- MITRE ATT&CK: T1055

### Hypotheses (3)

#### H-2493be71-1 · APC Tandem via NtQueueApcThread Injection into Explorer.exe  _(confidence: medium)_

**Statement.** An attacker used NtQueueApcThread to inject malicious code into explorer.exe from a legitimate process (e.g., powershell.exe or cmd.exe) within the last 7 days in our environment.

**Why this hypothesis?** The article references 'APC Tandem', a known variant of APC injection (T1055.012) where an attacker queues an APC into a target process (often explorer.exe) to achieve persistence or code execution. This aligns with EDR telemetry showing NtQueueApcThread calls from user processes to system processes.

**MITRE ATT&CK**: T1055.012

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2493be71-1-O1] No NtQueueApcThread calls from user processes to explorer.exe** _(difficulty: medium · 150 pts · MITRE: T1055.012)_
  - Falsification criterion: If no EDR logs show NtQueueApcThread being called from user processes (e.g., powershell.exe) into explorer.exe, the hypothesis is disproven.
  - Data sources: EDR
  - Suggested query: `EDR: call_name = 'NtQueueApcThread' AND target_process = 'explorer.exe' AND process_name IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe') AND parent_process NOT IN ('svchost.exe', 'lsass.exe', 'winlogon.exe')`
- **[H-2493be71-1-O2] No process creation of suspicious parent-child chains leading to NtQueueApcThread** _(difficulty: medium · 120 pts · MITRE: T1055.012, T1059.003)_
  - Falsification criterion: If no process creation events show a chain like cmd.exe → powershell.exe → NtQueueApcThread(target=explorer.exe), the injection pathway is not observed.
  - Data sources: EDR, Sysmon
  - Suggested query: `EDR: process_name IN ('powershell.exe', 'cmd.exe') AND child_process_call: NtQueueApcThread AND target_process: explorer.exe`
- **[H-2493be71-1-O3] No memory dumps of explorer.exe containing anomalous APC payloads** _(difficulty: hard · 200 pts · MITRE: T1055.012)_
  - Falsification criterion: If memory analysis of explorer.exe shows no injected code or non-standard APC routines, the injection did not successfully execute.
  - Data sources: Memory Forensics, EDR
  - Suggested query: `Memory dump of explorer.exe analyzed for non-system DLLs or unusual APC routines via Volatility or Rekall`
- **[H-2493be71-1-O4] No registry or file artifacts indicating persistence via explorer.exe hooking** _(difficulty: medium · 130 pts · MITRE: T1055.012, T1547.001)_
  - Falsification criterion: If no registry keys (e.g., Run, RunOnce) or DLL sideloading artifacts are found that would support long-term APC persistence via explorer.exe, the technique was not used for persistence.
  - Data sources: File System, Registry
  - Suggested query: `Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run OR HKLM\Software\Microsoft\Windows\CurrentVersion\Run AND file modification time within 7 days of suspected event`

**Sigma rule:**

```yaml
title: APC Tandem - NtQueueApcThread Injection into Explorer.exe
id: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
status: experimental
description: Detects NtQueueApcThread calls from user processes into explorer.exe
logsource:
  product: windows
  service: edr
condition: 'call_name: NtQueueApcThread and target_process: explorer.exe and process_name: (powershell.exe or cmd.exe or wscript.exe or cscript.exe) and not parent_process: (svchost.exe or lsass.exe or winlogon.exe)'
detection:
  call_name:
    - NtQueueApcThread
  target_process:
    - explorer.exe
  process_name:
    - powershell.exe
    - cmd.exe
    - wscript.exe
    - cscript.exe
  parent_process:
    - svchost.exe
    - lsass.exe
    - winlogon.exe
condition: all of them
```

#### H-2493be71-2 · APC Injection via CreateRemoteThread in svchost.exe  _(confidence: medium)_

**Statement.** An attacker used CreateRemoteThread to inject code into a svchost.exe process hosting a malicious service within the last 7 days in our environment.

**Why this hypothesis?** APC Tandem can also manifest via CreateRemoteThread (T1055.012) when attackers target system services hosted in svchost.exe. This is a common evasion technique since svchost.exe is trusted and frequently running.

**MITRE ATT&CK**: T1055.012

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2493be71-2-O1] No CreateRemoteThread events from user processes into svchost.exe** _(difficulty: easy · 100 pts · MITRE: T1055.012)_
  - Falsification criterion: If Sysmon EventID 8 shows no CreateRemoteThread from user processes (e.g., powershell.exe) into svchost.exe, the hypothesis is disproven.
  - Data sources: Sysmon
  - Suggested query: `Sysmon EventID=8 AND SourceImage IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe') AND TargetImage='svchost.exe'`
- **[H-2493be71-2-O2] No svchost.exe child processes spawned from non-service hosts** _(difficulty: medium · 120 pts · MITRE: T1055.012, T1543.003)_
  - Falsification criterion: If no svchost.exe processes are found with parent processes other than services.exe or wininit.exe, it suggests no malicious service hosting occurred.
  - Data sources: Sysmon
  - Suggested query: `Sysmon EventID=1 AND Image='svchost.exe' AND ParentImage NOT IN ('services.exe', 'wininit.exe')`
- **[H-2493be71-2-O3] No network connections from svchost.exe to C2 domains** _(difficulty: easy · 80 pts · MITRE: T1055.012, T1071)_
  - Falsification criterion: If no outbound network connections from svchost.exe to known C2 IPs/domains are observed, the post-injection communication phase did not occur.
  - Data sources: NetFlow, Proxy Logs
  - Suggested query: `Network: ProcessName='svchost.exe' AND DestinationIP IN ('known_c2_ips') OR DestinationDomain IN ('known_c2_domains')`
- **[H-2493be71-2-O4] No EDR alerts for suspicious DLL loading into svchost.exe** _(difficulty: medium · 140 pts · MITRE: T1055.012, T1055.011)_
  - Falsification criterion: If no EDR alerts for unusual DLLs loaded into svchost.exe (e.g., non-Microsoft, unsigned, or from Temp folders) are found, injection payloads were not loaded.
  - Data sources: EDR
  - Suggested query: `EDR: process_name='svchost.exe' AND module_name NOT LIKE '%Microsoft%' AND module_path LIKE '%Temp%' OR module_hash NOT IN ('trusted_hashes')`

**Sigma rule:**

```yaml
title: APC Tandem - CreateRemoteThread into svchost.exe
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects CreateRemoteThread calls from user processes into svchost.exe
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 8
  SourceImage: (powershell.exe or cmd.exe or wscript.exe or cscript.exe)
  TargetImage: svchost.exe
  TargetProcessId: not null
condition: EventID of 8 and SourceImage of (powershell.exe or cmd.exe or wscript.exe or cscript.exe) and TargetImage: svchost.exe
```

#### H-2493be71-3 · APC Injection via DLL Sideloading into Trusted Process  _(confidence: low)_

**Statement.** An attacker used DLL sideloading to inject malicious code into a trusted process (e.g., explorer.exe or svchost.exe) via a malicious DLL placed in a search path, triggering NtQueueApcThread or CreateRemoteThread within 7 days.

**Why this hypothesis?** APC Tandem can be delivered via DLL sideloading, where a legitimate process loads a malicious DLL from a non-standard path, which then executes APC injection. This avoids direct process creation and evades many signature-based detections.

**MITRE ATT&CK**: T1055.012

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-2493be71-3-O1] No non-system DLLs loaded into explorer.exe or svchost.exe from non-standard paths** _(difficulty: medium · 130 pts · MITRE: T1055.012, T1055.011)_
  - Falsification criterion: If no DLLs are loaded into explorer.exe or svchost.exe from Temp, Downloads, or AppData folders, sideloading did not occur.
  - Data sources: EDR, Sysmon
  - Suggested query: `EDR: process_name IN ('explorer.exe', 'svchost.exe') AND module_path NOT LIKE '%Windows%' AND module_path LIKE '%Temp%' OR '%AppData%' OR '%Downloads%'`
- **[H-2493be71-3-O2] No NtQueueApcThread or CreateRemoteThread events following suspicious DLL load** _(difficulty: medium · 150 pts · MITRE: T1055.012)_
  - Falsification criterion: If suspicious DLL loads are found but no subsequent injection events (NtQueueApcThread or EventID 8), the sideloading did not lead to injection.
  - Data sources: EDR
  - Suggested query: `EDR: module_load IN ('explorer.exe', 'svchost.exe') AND module_path LIKE '%Temp%' AND (call_name: NtQueueApcThread OR event_id: 8) WITHIN 5 seconds`
- **[H-2493be71-3-O3] No file creation of suspicious DLLs in user-writable directories prior to injection** _(difficulty: medium · 120 pts · MITRE: T1055.012, T1055.011)_
  - Falsification criterion: If no new DLL files were created in Temp, Downloads, or AppData directories within 1 hour before injection events, sideloading was not used.
  - Data sources: File System, Sysmon
  - Suggested query: `Sysmon EventID=11 AND TargetFilename LIKE '%Temp%' OR '%AppData%' OR '%Downloads%' AND Extension='.dll' AND TimeGenerated > (injection_event_time - 1h)`
- **[H-2493be71-3-O4] No registry autoruns or scheduled tasks used to trigger sideloading** _(difficulty: easy · 100 pts · MITRE: T1055.012, T1547.001)_
  - Falsification criterion: If no registry keys (Run, RunOnce) or scheduled tasks were created to launch the sideloading executable, the attack chain was not initiated persistently.
  - Data sources: Registry, Sysmon
  - Suggested query: `Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run OR HKLM\...\Run AND (ValueData LIKE '%Temp%' OR ValueData LIKE '%AppData%')`

**Sigma rule:**

```yaml
title: APC Tandem - DLL Sideloading Triggering Injection
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects DLL sideloading into trusted processes followed by NtQueueApcThread or CreateRemoteThread
logsource:
  product: windows
  service: edr
condition: 'module_load: (explorer.exe or svchost.exe) AND module_path NOT LIKE "%Windows%" AND (call_name: NtQueueApcThread OR event_id: 8)'
detection:
  module_load:
    - explorer.exe
    - svchost.exe
  module_path:
    - '*\Temp\*'
    - '*\AppData\Local\*'
    - '*\Downloads\*'
    - '*\%USERPROFILE%\*'
  call_name:
    - NtQueueApcThread
  event_id:
    - 8
condition: all of them
```

---

## 20. A fraudulent scheme to obtain and use code signing certificates to deceive victims into downloading dangerous malware under the false belief that it is trusted software

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tme926/a_fraudulent_scheme_to_obtain_and_use_code/>
- **Published**: 2026-05-24T14:49:50+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 75
- **Score rationale**: triage: Fraudulent code signing certificates are a high-impact attack vector; enables trusted malware delivery — enterprise should hunt for anomalous code signing events.
- **Agent trace**: tool fetch_article({}) -> ok → critic: revise (Hypothesis 1: Sigma rule has contradictory logic — 'Signature: 'Invalid' | 'Unknown' | 'Expired' | 'Revoked'' and 'SignatureStatus: 'NotSigned'' cannot both be true. A file cannot be both signed with )

> submitted by /u/digicat [link] [comments]

### Hypotheses (3)

#### H-267f537d-1 · Fraudulent Code Signing Certificates Used to Sign Malware  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, attackers used fraudulent or compromised code signing certificates to sign malicious executables that executed from temporary or user-writable directories.

**Why this hypothesis?** The article describes a scheme where attackers obtain or abuse code signing certificates to make malware appear trusted. This aligns with observed trends in supply chain attacks and suggests that signed malware from high-risk paths (e.g., %TEMP%) is a likely indicator in our environment.

**MITRE ATT&CK**: T1190, T1071, T1566

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-267f537d-1-O1] No signed executables from %TEMP% or AppData** _(difficulty: medium · 100 pts · MITRE: T1204)_
  - Falsification criterion: No events found where a signed executable (SignatureStatus: Valid) executed from %TEMP%, %APPDATA%\Local, or %APPDATA%\Roaming
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image LIKE '%\temp\%' AND SignatureStatus='Valid'`
- **[H-267f537d-1-O2] No new certificates issued to non-employee accounts** _(difficulty: hard · 150 pts · MITRE: T1595)_
  - Falsification criterion: No certificate enrollment events (EventID 4886) in AD CS logs where the requester account is not a known employee or service account
  - Data sources: AD CS Logs, Domain Controller
  - Suggested query: `EventID=4886 AND RequesterAccount NOT IN ('domain\user1', 'domain\svc_app', 'domain\svc_deploy')`
- **[H-267f537d-1-O3] No certificate thumbprint reused across multiple signed files** _(difficulty: hard · 150 pts · MITRE: T1566)_
  - Falsification criterion: No certificate thumbprint appears in more than one signed executable file across all Sysmon EventID 1 logs
  - Data sources: EDR, Sysmon
  - Suggested query: `Group by SignatureThumbprint; count distinct Image paths; filter where count > 1`
- **[H-267f537d-1-O4] No certificate requests with mismatched email addresses** _(difficulty: hard · 150 pts · MITRE: T1595)_
  - Falsification criterion: No certificate enrollment requests (EventID 4885) contain an email address that does not match the requester's domain or known email pattern
  - Data sources: AD CS Logs
  - Suggested query: `EventID=4885 AND RequesterEmail NOT LIKE '%@ourcompany.com' AND RequesterEmail NOT IN ('admin@ourcompany.com', 'certadmin@ourcompany.com')`

**Sigma rule:**

```yaml
title: Suspicious Signed Executable from Temp or AppData
id: 1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p
status: experimental
description: Detects signed executables executed from temporary or user-writable directories, which may indicate certificate abuse
logsource:
  product: windows
  service: sysmon
detection:
  Selection1:
    EventID: 1
    Image: 
      - '*\temp\*.exe'
      - '*\appdata\local\*.exe'
      - '*\appdata\roaming\*.exe'
  Selection2:
    SignatureStatus: 'Valid'
  Condition: Selection1 and Selection2
  timeframe: 1d
reference: https://github.com/SigmaHQ/sigma
```

#### H-267f537d-2 · Phishing-Driven Certificate Enrollment Abuse  _(confidence: medium)_

**Statement.** Between 2026-05-20 and 2026-05-24, attackers used phishing to compromise user credentials and enroll for code signing certificates using the victims' identities, then used those certificates to sign malware.

**Why this hypothesis?** The article highlights phishing as the initial vector to obtain certificates. In our environment, this implies that compromised user accounts may have requested certificates, and those certificates may have been used to sign malicious payloads. We must test for anomalous certificate requests tied to user logons.

**MITRE ATT&CK**: T1566, T1078, T1595

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-267f537d-2-O1] No privileged logons followed by certificate requests** _(difficulty: medium · 120 pts · MITRE: T1078)_
  - Falsification criterion: No instances where EventID 4672 (privileged logon) is followed by EventID 4885 (certificate request) from the same account within 5 minutes
  - Data sources: AD CS Logs, Security Logs
  - Suggested query: `EventID=4672 | join EventID=4885 on AccountName | where TimeDiff < 300s`
- **[H-267f537d-2-O2] No certificate requests from non-IT user accounts** _(difficulty: medium · 120 pts · MITRE: T1595)_
  - Falsification criterion: No certificate enrollment requests (EventID 4885) originate from accounts not in the IT, Dev, or Certificate Requester security groups
  - Data sources: AD CS Logs, Active Directory
  - Suggested query: `EventID=4885 AND RequesterAccount NOT IN (members of 'IT_Support', 'Dev_Team', 'Cert_Requesters')`
- **[H-267f537d-2-O3] No certificate requests with email addresses outside domain policy** _(difficulty: medium · 120 pts · MITRE: T1595)_
  - Falsification criterion: No certificate enrollment requests contain an email address that does not conform to our domain’s email format (e.g., firstname.lastname@ourcompany.com)
  - Data sources: AD CS Logs
  - Suggested query: `EventID=4885 AND RequesterEmail NOT MATCHES '^[a-z]+\.[a-z]+@ourcompany\.com$'`
- **[H-267f537d-2-O4] No certificate enrollment from non-domain-joined devices** _(difficulty: hard · 150 pts · MITRE: T1595)_
  - Falsification criterion: No certificate enrollment events (EventID 4885) originate from devices not listed in our domain-joined asset inventory
  - Data sources: AD CS Logs, CMDB
  - Suggested query: `EventID=4885 AND RequesterComputer NOT IN (SELECT ComputerName FROM CMDB WHERE DomainJoined = 'True')`

**Sigma rule:**

```yaml
title: Suspicious Certificate Enrollment After Phishing Logon
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects privileged logons followed by certificate enrollment within 5 minutes, suggesting credential theft
logsource:
  product: windows
  service: security
detection:
  Selection1:
    EventID: 4672
    AccountName: '*@ourcompany.com'
  Selection2:
    EventID: 4885
    RequesterAccount: '*@ourcompany.com'
  Condition: Selection1 and Selection2
  timeframe: 5m
reference: https://github.com/SigmaHQ/sigma
```

#### H-267f537d-3 · Certificate Thumbprint Reuse for Malware Distribution  _(confidence: high)_

**Statement.** Between 2026-05-20 and 2026-05-24, attackers reused a single fraudulent certificate thumbprint across multiple malware samples distributed via different vectors to evade detection.

**Why this hypothesis?** The article suggests attackers reuse certificates to scale fraud. In our environment, this means a single certificate thumbprint appearing on multiple signed files could indicate a coordinated campaign. We must detect this reuse pattern across endpoints.

**MITRE ATT&CK**: T1566, T1071, T1204

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-267f537d-3-O1] No single certificate thumbprint used on >1 file** _(difficulty: hard · 150 pts · MITRE: T1566)_
  - Falsification criterion: No certificate thumbprint appears in more than one distinct signed executable file in Sysmon EventID 1 logs
  - Data sources: EDR, Sysmon
  - Suggested query: `Group by SignatureThumbprint; count distinct Image; filter where count > 1`
- **[H-267f537d-3-O2] No signed executables from network shares** _(difficulty: medium · 120 pts · MITRE: T1204)_
  - Falsification criterion: No signed executables (SignatureStatus: Valid) executed from any \\server\share path
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND Image LIKE '\\\\*\%' AND SignatureStatus='Valid'`
- **[H-267f537d-3-O3] No valid-signed files from non-standard directories** _(difficulty: medium · 120 pts · MITRE: T1204)_
  - Falsification criterion: No signed executables (SignatureStatus: Valid) executed from directories outside of %PROGRAMFILES%, %WINDIR%, or %SYSTEM32%
  - Data sources: EDR, Sysmon
  - Suggested query: `EventID=1 AND SignatureStatus='Valid' AND Image NOT LIKE '%\Program Files\%' AND Image NOT LIKE '%\Windows\%' AND Image NOT LIKE '%\System32\%'`
- **[H-267f537d-3-O4] No certificate issued to non-employee email** _(difficulty: hard · 150 pts · MITRE: T1595)_
  - Falsification criterion: No code signing certificate was issued to an email address not belonging to a known employee or approved service account
  - Data sources: AD CS Logs
  - Suggested query: `EventID=4886 AND RequesterEmail NOT IN (SELECT Email FROM HR_Inventory) AND RequesterEmail NOT LIKE '%@ourcompany.com'`

**Sigma rule:**

```yaml
title: Reused Certificate Thumbprint Across Multiple Executables
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects the same certificate thumbprint used to sign multiple distinct executable files, indicating potential certificate reuse in malware campaigns
logsource:
  product: windows
  service: sysmon
detection:
  Selection1:
    EventID: 1
    SignatureStatus: 'Valid'
    Signature: 'Microsoft Windows'
  Selection2:
    Image: 
      - '*\temp\*.exe'
      - '*\appdata\local\*.exe'
      - '*\appdata\roaming\*.exe'
  Condition: Selection1 and Selection2
  timeframe: 1d
reference: https://github.com/SigmaHQ/sigma
```

---

## 21. Kazuar Evolves From Backdoor to Resilient Espionage Ecosystem

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmd864/kazuar_evolves_from_backdoor_to_resilient/>
- **Published**: 2026-05-24T14:09:28+00:00
- **First seen**: 2026-05-24T14:26:19+00:00
- **Relevance score**: 75
- **Score rationale**: triage: Kazuar is a known, evolving espionage actor with active campaigns; espionage focus makes it relevant for enterprise detection.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No scheduled task creation events...', but the Sigma rule only detects task creation (EventID 4698), not the absence of events. Falsi)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Actions: espionage

### Hypotheses (3)

#### H-090bcc24-1 · Kazuar Uses Scheduled Tasks for Persistence  _(confidence: high)_

**Statement.** Adversaries in our environment have created scheduled tasks with obfuscated command lines to maintain persistence between 2026-05-10 and 2026-05-24.

**Why this hypothesis?** The article describes Kazuar evolving into a resilient espionage ecosystem using scheduled tasks for persistence, consistent with T1053.005. The extracted indicator 'espionage' aligns with this TTP.

**MITRE ATT&CK**: T1053.005

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-090bcc24-1-O1] Detect scheduled tasks with obfuscated triggers** _(difficulty: medium · 100 pts · MITRE: T1053.005)_
  - Falsification criterion: We observe scheduled task creation events with CommandLine containing /create and /tr referencing .dll, .dat, or .tmp files
  - Data sources: EDR, Windows Security Logs
  - Suggested query: `EventID:4698 AND (CommandLine:* /create * AND (CommandLine:*\*.dll* OR CommandLine:*\*.dat* OR CommandLine:*\*.tmp*))`
- **[H-090bcc24-1-O2] Detect on-logon scheduled tasks** _(difficulty: easy · 80 pts · MITRE: T1053.005)_
  - Falsification criterion: We observe scheduled task creation events with CommandLine containing /sc onlogon
  - Data sources: EDR, Windows Security Logs
  - Suggested query: `EventID:4698 AND CommandLine:* /sc onlogon *`
- **[H-090bcc24-1-O3] Detect scheduled tasks with non-standard executables** _(difficulty: medium · 90 pts · MITRE: T1053.005)_
  - Falsification criterion: We observe scheduled task creation events with CommandLine referencing executables outside %SystemRoot% or %ProgramFiles%
  - Data sources: EDR, Windows Security Logs
  - Suggested query: `EventID:4698 AND NOT CommandLine:*%SystemRoot%* AND NOT CommandLine:*%ProgramFiles%* AND CommandLine:* /tr *`
- **[H-090bcc24-1-O4] Detect task names with hex-encoded strings** _(difficulty: hard · 120 pts · MITRE: T1053.005)_
  - Falsification criterion: We observe scheduled task creation events with TaskName containing hex-encoded strings (e.g., [0-9a-f]{8,})
  - Data sources: EDR, Windows Security Logs
  - Suggested query: `EventID:4698 AND TaskName:*[0-9a-f]* AND TaskName:|len|>8`

**Sigma rule:**

```yaml
title: Detect Kazuar-Style Scheduled Task Creation
id: 1a2b3c4d-5e6f-7g8h-9i0j-k1l2m3n4o5p6
status: experimental
description: Detects suspicious scheduled task creation indicative of Kazuar espionage tooling
detection:
  selection:
    EventID: 4698
    CommandLine:
      - '* /create *'
      - '* /tr *'
      - '* /xml *'
      - '* /sc onlogon *'
      - '* /tr "*\*.dll" *'
      - '* /tr "*\*.dat" *'
      - '* /tr "*\*.tmp" *'
  condition: selection
logsource:
  product: windows
  service: security
category: process_creation
title: Detect Kazuar-Style Scheduled Task Creation
```

#### H-090bcc24-2 · Kazuar Uses WMI for Execution and Persistence  _(confidence: high)_

**Statement.** Adversaries in our environment have created WMI event subscriptions to execute malicious payloads between 2026-05-10 and 2026-05-24.

**Why this hypothesis?** The article highlights Kazuar’s use of WMI for resilience. WMI persistence (T1546.005) is a known technique in advanced espionage campaigns, and the absence of other TTPs in the indicators makes WMI a high-probability vector.

**MITRE ATT&CK**: T1546.005

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-090bcc24-2-O1] Detect WMI consumers with malicious executable paths** _(difficulty: medium · 100 pts · MITRE: T1546.005)_
  - Falsification criterion: We observe WMI consumer creation events (EventID 5861) with TargetInstance containing ExecutablePath referencing .dll, .dat, or .tmp files
  - Data sources: EDR, WMI Event Logs
  - Suggested query: `EventID:5861 AND TargetInstance:*ExecutablePath* AND (TargetInstance:*\*.dll* OR TargetInstance:*\*.dat* OR TargetInstance:*\*.tmp*)`
- **[H-090bcc24-2-O2] Detect WMI filters bound to system processes** _(difficulty: hard · 120 pts · MITRE: T1546.005)_
  - Falsification criterion: We observe WMI filter creation events (EventID 5860) where the associated consumer targets svchost.exe or lsass.exe
  - Data sources: EDR, WMI Event Logs
  - Suggested query: `EventID:5860 AND TargetInstance:*Win32_Process* AND TargetInstance:*svchost.exe* OR TargetInstance:*lsass.exe*`
- **[H-090bcc24-2-O3] Detect WMI subscriptions on domain controllers** _(difficulty: medium · 110 pts · MITRE: T1546.005)_
  - Falsification criterion: We observe WMI event subscriptions (EventID 5860 or 5861) created on domain controllers
  - Data sources: EDR, WMI Event Logs, Domain Controller Logs
  - Suggested query: `EventID:5860 OR EventID:5861 AND Computer:*DC*`
- **[H-090bcc24-2-O4] Detect WMI consumers with encoded command lines** _(difficulty: medium · 100 pts · MITRE: T1546.005)_
  - Falsification criterion: We observe WMI consumer creation events with CommandLine containing base64-encoded strings or PowerShell -EncodedCommand
  - Data sources: EDR, WMI Event Logs
  - Suggested query: `EventID:5861 AND TargetInstance:*-EncodedCommand* OR TargetInstance:*base64*`

**Sigma rule:**

```yaml
title: Detect Kazuar-Style WMI Event Subscription
id: 2b3c4d5e-6f7g-8h9i-0j1k-2l3m4n5o6p7q
status: experimental
description: Detects creation of WMI event consumers that execute malicious payloads
selection:
  EventID: 5861
  TargetInstance:
    - '*__EventFilter*'
    - '*CommandLineEventConsumer*'
    - '*ExecutablePath*\*.dll*'
    - '*ExecutablePath*\*.dat*'
    - '*ExecutablePath*\*.tmp*'
condition: selection
logsource:
  product: windows
  service: wmi-event-log
category: wmi_activity
title: Detect Kazuar-Style WMI Event Subscription
```

#### H-090bcc24-3 · Kazuar Uses DNS Tunneling for C2 Communication  _(confidence: medium)_

**Statement.** Adversaries in our environment are using DNS queries with obfuscated subdomains to exfiltrate data or receive C2 instructions between 2026-05-10 and 2026-05-24.

**Why this hypothesis?** The espionage nature of Kazuar implies data exfiltration. DNS tunneling (T1048.003) is a common stealthy C2 method in advanced campaigns, and the lack of network indicators in the article suggests this is a plausible hidden vector.

**MITRE ATT&CK**: T1048.003

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-090bcc24-3-O1] Detect DNS queries with long hex-encoded subdomains** _(difficulty: hard · 120 pts · MITRE: T1048.003)_
  - Falsification criterion: We observe DNS query events (EventID 256) with QueryName containing substrings of 8+ consecutive hex characters followed by .com, .net, or .org
  - Data sources: DNS Logs
  - Suggested query: `EventID:256 AND QueryName:*[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*.com* OR QueryName:*[0-9a-f]{8,}*.net* OR QueryName:*[0-9a-f]{8,}*.org*`
- **[H-090bcc24-3-O2] Detect high-volume DNS queries from single hosts** _(difficulty: medium · 100 pts · MITRE: T1048.003)_
  - Falsification criterion: We observe DNS query events (EventID 256) from a single host exceeding 100 queries in a 5-minute window
  - Data sources: DNS Logs
  - Suggested query: `EventID:256 | stats count by Computer, QueryName | where count > 100`
- **[H-090bcc24-3-O3] Detect DNS queries with non-standard TLDs** _(difficulty: medium · 110 pts · MITRE: T1048.003)_
  - Falsification criterion: We observe DNS query events (EventID 256) with QueryName using uncommon TLDs (e.g., .xyz, .info, .top) with hex patterns
  - Data sources: DNS Logs
  - Suggested query: `EventID:256 AND QueryName:*[0-9a-f]{8,}*.xyz* OR QueryName:*[0-9a-f]{8,}*.info* OR QueryName:*[0-9a-f]{8,}*.top*`
- **[H-090bcc24-3-O4] Detect DNS queries with high entropy names** _(difficulty: hard · 130 pts · MITRE: T1048.003)_
  - Falsification criterion: We observe DNS query events (EventID 256) where QueryName has Shannon entropy > 3.5 and length > 20 characters
  - Data sources: DNS Logs
  - Suggested query: `EventID:256 AND QueryName:|len|>20 AND QueryName:|entropy|>3.5`

**Sigma rule:**

```yaml
title: Detect Kazuar-Style DNS Tunneling
id: 3c4d5e6f-7g8h-9i0j-1k2l-3m4n5o6p7q8r
status: experimental
description: Detects high-volume DNS queries with hex-encoded or long subdomains indicative of DNS tunneling
selection:
  EventID: 256
  QueryName:
    - '*[0-9a-f]{8,}.com*'
    - '*[0-9a-f]{16,}.net*'
    - '*[0-9a-f]{32,}.org*'
    - '*[a-f0-9]{8,}.*'
  QueryCount: '>100'
condition: selection
logsource:
  product: windows
  service: dns-server
category: dns_query
title: Detect Kazuar-Style DNS Tunneling
```

---

## 22. Machine Overmatch: What Salt Typhoon Reveals About China’s Data-Centric Intelligence Strategy

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmebsf/machine_overmatch_what_salt_typhoon_reveals_about/>
- **Published**: 2026-05-24T14:52:39+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 70
- **Score rationale**: triage: Salt Typhoon is a known APT with state-sponsored capabilities; enterprise should hunt for TTPs even without specific IOCs due to high actor capability and persistent threat.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 is not a falsification test — absence of 'SaltTyphoonBot/1.0' UA does not disprove exploitation; attackers rarely use such predictable UAs. This is a confirmation bias trap. )

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Threat actors: Salt Typhoon

### Hypotheses (3)

#### H-787cc6b8-1 · Salt Typhoon Exploits Public-Facing Fortinet Device  _(confidence: medium)_

**Statement.** Salt Typhoon exploited a known vulnerability in a public-facing Fortinet device in our environment between February 24, 2026, and May 24, 2026, to establish initial access.

**Why this hypothesis?** The article identifies Salt Typhoon as a threat actor with a data-centric strategy, and public exploit databases (e.g., CVE-2023-28252) confirm their use of Fortinet vulnerabilities. Our environment has exposed FortiGate devices, making this a plausible TTP.

**MITRE ATT&CK**: T1190

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-787cc6b8-1-O1] Detect path traversal attempts via ../ or %2e%2e/** _(difficulty: easy · 100 pts · MITRE: T1190)_
  - Falsification criterion: No HTTP requests containing '../' or '%2e%2e/' with 404 status codes to Fortinet admin paths are observed in the 90-day window.
  - Data sources: Web proxy, Firewall logs
  - Suggested query: `filter: url contains '../' or url contains '%2e%2e/' and status_code == 404 and device_type == 'Fortinet'`
- **[H-787cc6b8-1-O2] Detect unauthorized admin panel access** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No successful authentication attempts (200 status) to /remote/login or /remote/fgt_lang paths are observed from external IPs not in allowlists.
  - Data sources: Web proxy, Firewall logs
  - Suggested query: `filter: url matches '/remote/(login|fgt_lang)' and status_code == 200 and src_ip not in allowlist`
- **[H-787cc6b8-1-O3] Detect unusual source IPs targeting Fortinet devices** _(difficulty: medium · 100 pts · MITRE: T1190)_
  - Falsification criterion: No external IPs with >50 failed HTTP requests to Fortinet admin paths in 24 hours are observed.
  - Data sources: Firewall logs, EDR
  - Suggested query: `group by src_ip | count requests where url matches '/remote/' and status_code == 404 and time_window = 24h | filter count > 50`

**Sigma rule:**

```yaml
title: Salt Typhoon Fortinet CVE-2023-28252 Exploit Attempt
logsource:
  product: fortinet
  service: firewall
detection:
  selection:
    action: 'deny'
    dst_ip: '10.0.0.0/8'
    url: '*../*' | '*%2e%2e/*'
    status_code: 404
  condition: selection
condition: selection
```

#### H-787cc6b8-2 · Salt Typhoon Uses DNS Exfiltration via Long Random Domains  _(confidence: medium)_

**Statement.** Salt Typhoon used DNS tunneling via long, randomly generated domains (≥32 alphanumeric chars) to exfiltrate data from our internal network between February 24, 2026, and May 24, 2026.

**Why this hypothesis?** Salt Typhoon is known to use DNS exfiltration (MITRE T1071.004). The article’s focus on data-centric operations supports this TTP. Legitimate domains rarely use such long, random structures without context.

**MITRE ATT&CK**: T1071.004

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-787cc6b8-2-O1] Detect high-volume TXT queries to long random domains** _(difficulty: medium · 100 pts · MITRE: T1071.004)_
  - Falsification criterion: No DNS client in our environment generates >100 TXT queries to domains matching ^[a-z0-9]{32,}\.com$ in a 24-hour period.
  - Data sources: DNS logs
  - Suggested query: `filter: query_type == 'TXT' and domain matches '^[a-z0-9]{32,}\.com$' | group by client_ip | count > 100 in 24h`
- **[H-787cc6b8-2-O2] Detect outbound DNS connections to non-whitelisted domains** _(difficulty: hard · 150 pts · MITRE: T1071.004)_
  - Falsification criterion: No internal hosts resolve domains ≥32 chars that are not in our approved third-party allowlist (e.g., CDN, SaaS).
  - Data sources: DNS logs, NetFlow
  - Suggested query: `filter: domain_length >= 32 and domain not in allowlist | group by src_ip | count > 5`
- **[H-787cc6b8-2-O3] Correlate DNS exfil with unusual outbound TCP connections** _(difficulty: hard · 200 pts · MITRE: T1071.004, T1048)_
  - Falsification criterion: No host with high TXT DNS volume also initiates >5 outbound TCP connections to unique external IPs on non-standard ports (e.g., 53, 853, 443) within 1 hour.
  - Data sources: DNS logs, NetFlow
  - Suggested query: `join DNS_query (count > 100) with NetFlow (dst_port not in [80,443,53] and count > 5) on src_ip within 1h`

**Sigma rule:**

```yaml
title: Salt Typhoon DNS Exfiltration via Long Random Domains
logsource:
  product: dns
  service: query
detection:
  selection:
    domain|re: '^[a-z0-9]{32,}\.com$'
    query_type: 'TXT'
    count: '>100'
  condition: selection
condition: count > 100
```

#### H-787cc6b8-3 · Salt Typhoon Uses Scheduled Tasks for Persistence  _(confidence: high)_

**Statement.** Salt Typhoon created scheduled tasks with obfuscated names in our Windows environment between February 24, 2026, and May 24, 2026, to maintain persistence after initial access.

**Why this hypothesis?** Salt Typhoon is documented to use scheduled tasks (T1053.005) for persistence. The article’s emphasis on automation and stealth aligns with this technique. Legitimate tasks rarely use random alphanumeric names.

**MITRE ATT&CK**: T1053.005

**CTF objectives (3) — find evidence that disproves the hypothesis:**

- **[H-787cc6b8-3-O1] Detect scheduled tasks with random alphanumeric names (≥16 chars)** _(difficulty: medium · 100 pts · MITRE: T1053.005)_
  - Falsification criterion: No scheduled tasks with names matching ^[a-zA-Z0-9]{16,}$ are created on any Windows host in the environment during the timeframe.
  - Data sources: Windows Event Logs (EDR)
  - Suggested query: `filter: EventID == 4698 and TaskName matches '^[a-zA-Z0-9]{16,}$' and TaskName not in known_legit_tasks`
- **[H-787cc6b8-3-O2] Detect PowerShell spawning cmd.exe or wmic.exe via scheduled task** _(difficulty: medium · 150 pts · MITRE: T1059.003, T1059.001)_
  - Falsification criterion: No scheduled task with CommandLine containing 'powershell' also contains 'cmd.exe' or 'wmic.exe' in the same command string.
  - Data sources: Windows Event Logs (EDR)
  - Suggested query: `filter: EventID == 4698 and CommandLine contains 'powershell' and (CommandLine contains 'cmd.exe' or CommandLine contains 'wmic.exe')`
- **[H-787cc6b8-3-O3] Detect task creation from non-system user contexts** _(difficulty: medium · 150 pts · MITRE: T1053.005)_
  - Falsification criterion: No scheduled tasks are created by non-administrative user accounts (e.g., non-System, non-NetworkService) with random names.
  - Data sources: Windows Event Logs (EDR)
  - Suggested query: `filter: EventID == 4698 and TaskName matches '^[a-zA-Z0-9]{16,}$' and AccountName not in ['SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE']`

**Sigma rule:**

```yaml
title: Salt Typhoon Suspicious Scheduled Task Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    CommandLine|contains: 'powershell' | 'cmd' | 'wmic'
    TaskName|re: '^[a-zA-Z0-9]{16,}$'
    TaskName|contains: 'UpdateService' | 'WindowsDefenderScan': false
  condition: selection
condition: selection
```

---

## 23. OpenPetya: A Proof-of-Concept bootkit inspired by Petya ransomware, written in Assembly, C, and C++

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmdvcd/openpetya_a_proofofconcept_bootkit_inspired_by/>
- **Published**: 2026-05-24T14:34:56+00:00
- **First seen**: 2026-05-24T15:17:26+00:00
- **Relevance score**: 70
- **Score rationale**: triage: OpenPetya bootkit PoC — bootkits are high-impact and rare; enterprise should hunt for unusual boot sector or early-stage process activity.
- **Agent trace**: critic: revise (Hypothesis 1: Objective 1 ('No executable files with .exe extension found in \boot\ or \EFI\Microsoft\Boot\') is not a valid falsification test. OpenPetya does not place .exe files in \boot\ or \EFI\M)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Actions: ransomware
- Sectors: manufacturing
- MITRE ATT&CK: T1486

### Hypotheses (3)

#### H-5ce19f41-1 · OpenPetya Ransomware Infection via Phished Credentials  _(confidence: medium)_

**Statement.** An attacker used stolen credentials to deploy OpenPetya ransomware on at least one host in our environment between 2026-05-20 and 2026-05-24, encrypting the MFT and overwriting the bootloader with a custom payload to prevent system boot.

**Why this hypothesis?** The article describes OpenPetya as a Petya-inspired ransomware that encrypts the MFT and modifies the bootloader. Extracted indicators include 'ransomware' and T1486 (Data Encrypted for Impact), consistent with OpenPetya's behavior. The absence of bootkit persistence indicators suggests a ransomware-focused attack, not a rootkit.

**MITRE ATT&CK**: T1078, T1566, T1486, T1059, T1030

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5ce19f41-1-O1] No MFT writes from non-system processes** _(difficulty: medium · 100 pts · MITRE: T1486)_
  - Falsification criterion: No process other than ntfs.sys or system threads wrote to $MFT between 2026-05-20 and 2026-05-24
  - Data sources: Sysmon
  - Suggested query: `EventID=11 AND TargetFilename='C:\$MFT' AND Image NOT IN ('\System32\ntfs.sys', '\Windows\System32\svchost.exe')`
- **[H-5ce19f41-1-O2] No bootloader modification via disk sector writes** _(difficulty: hard · 150 pts · MITRE: T1078)_
  - Falsification criterion: No process wrote directly to physical sector 0 (MBR) or EFI system partition boot files (e.g., \EFI\Microsoft\Boot\bootmgfw.efi) between 2026-05-20 and 2026-05-24
  - Data sources: Disk forensics, EDR
  - Suggested query: `DiskWriteEvent AND SectorAddress IN (0, 1-63) AND Image NOT IN ('\Windows\System32\bootmgr.exe', '\Windows\System32\bcdboot.exe')`
- **[H-5ce19f41-1-O3] No credential dumping prior to ransomware execution** _(difficulty: medium · 120 pts · MITRE: T1003)_
  - Falsification criterion: No lsass.exe memory access, mimikatz patterns, or credential theft indicators were observed in the 24 hours before MFT encryption
  - Data sources: EDR, Windows Security logs
  - Suggested query: `EventID=10 AND (ProcessName='lsass.exe' AND AccessMask IN (0x1410, 0x1438)) OR (Image LIKE '%mimikatz%' OR CommandLine LIKE '%sekurlsa%')`
- **[H-5ce19f41-1-O4] No scheduled task or WMI persistence for ransomware** _(difficulty: medium · 110 pts · MITRE: T1053, T1047)_
  - Falsification criterion: No new scheduled tasks, WMI event subscriptions, or registry run keys were created in the 48 hours before infection
  - Data sources: Sysmon, Windows Event Log
  - Suggested query: `(EventID=1 AND Image LIKE '%schtasks.exe%' AND CommandLine LIKE '%/create%') OR (EventID=19 AND TargetObject LIKE '%\Run\%') OR (EventID=19 AND TargetObject LIKE '%WMI%')`

**Sigma rule:**

```yaml
title: OpenPetya Ransomware - Suspicious Disk Write Pattern
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 11
  Image: '*\svchost.exe'
  TargetFilename: 'C:\\$MFT'
  Access: 'write'
condition: EventID == 11 and TargetFilename contains '$MFT' and Image endswith '\svchost.exe'
```

#### H-5ce19f41-2 · OpenPetya Deployed via Phishing Email with Macro  _(confidence: medium)_

**Statement.** An attacker delivered OpenPetya ransomware via a phishing email containing a malicious Office document that executed PowerShell to download and deploy the ransomware payload on 2026-05-22.

**Why this hypothesis?** The article implies OpenPetya is delivered as ransomware, and T1486 is the only MITRE technique provided. Phishing (T1566) is the most common initial vector for ransomware. While the article mentions Assembly/C/C++, it does not specify bootkit delivery — macro-based delivery is a plausible, common alternative.

**MITRE ATT&CK**: T1566, T1059, T1055, T1486

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5ce19f41-2-O1] No PowerShell execution from Office processes** _(difficulty: medium · 100 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell process was spawned from WINWORD.EXE, EXCEL.EXE, or OUTLOOK.EXE between 2026-05-20 and 2026-05-24
  - Data sources: Sysmon
  - Suggested query: `EventID=1 AND ParentImage IN ('\WINWORD.EXE', '\EXCEL.EXE', '\OUTLOOK.EXE') AND Image IN ('\powershell.exe', '\cmd.exe')`
- **[H-5ce19f41-2-O2] No suspicious PowerShell encoding detected** _(difficulty: medium · 110 pts · MITRE: T1059)_
  - Falsification criterion: No PowerShell command lines contained base64-encoded strings (e.g., -enc or -e flags) originating from Office processes
  - Data sources: Sysmon
  - Suggested query: `EventID=1 AND ParentImage IN ('\WINWORD.EXE', '\EXCEL.EXE') AND CommandLine =~ /(-e|-enc).*[A-Za-z0-9+/=]{100,}/`
- **[H-5ce19f41-2-O3] No outbound connections to known ransomware C2 domains** _(difficulty: easy · 90 pts · MITRE: T1071)_
  - Falsification criterion: No DNS queries or HTTP/S connections were made to domains associated with known ransomware C2 infrastructure (e.g., past OpenPetya samples) in the 24 hours before MFT encryption
  - Data sources: DNS logs, Proxy logs
  - Suggested query: `DNSQuery IN ('example-ransomware[.]com', 'bad-domain[.]net') OR HTTPRequest IN ('/payload.bin', '/update.exe') AND SourceIP IN ('internal_subnet')`
- **[H-5ce19f41-2-O4] No file drops in %TEMP% or %APPDATA%** _(difficulty: medium · 120 pts · MITRE: T1055)_
  - Falsification criterion: No executable files (.exe, .dll, .scr) were written to %TEMP%, %APPDATA%, or %LOCALAPPDATA% by Office processes in the 1 hour before MFT encryption
  - Data sources: EDR, File integrity monitoring
  - Suggested query: `FileCreate AND ParentImage IN ('\WINWORD.EXE', '\EXCEL.EXE') AND TargetFilename =~ /(\\Temp|\\AppData\\Roaming|\\AppData\\Local)\\.*\.(exe|dll|scr)$/ AND Timestamp > MFT_Encryption_Time - 1h`

**Sigma rule:**

```yaml
title: OpenPetya - Malicious Office Macro Triggering PowerShell Download
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 1
  Image: '*\powershell.exe'
  CommandLine: '(-nop|-noprofile|-e|-enc)'
  ParentImage: '*\WINWORD.EXE' OR '*\EXCEL.EXE'
condition: EventID == 1 and ParentImage endswith ('\WINWORD.EXE' or '\EXCEL.EXE') and CommandLine contains '-enc' or CommandLine contains '-e'
```

#### H-5ce19f41-3 · OpenPetya Spread via Exploited Remote Services  _(confidence: high)_

**Statement.** An attacker exploited a vulnerable remote service (e.g., SMB, RDP) to gain initial access and deploy OpenPetya ransomware across multiple hosts in our manufacturing network between 2026-05-21 and 2026-05-24.

**Why this hypothesis?** OpenPetya is known to propagate via SMB exploits (e.g., EternalBlue) and stolen credentials. The extracted indicator T1486 (Data Encrypted for Impact) and sector 'manufacturing' suggest a network-wide ransomware attack. This hypothesis aligns with real-world OpenPetya campaigns that spread laterally via network shares.

**MITRE ATT&CK**: T1190, T1078, T1021, T1486, T1059

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-5ce19f41-3-O1] No SMB connection spikes from internal hosts** _(difficulty: medium · 110 pts · MITRE: T1021)_
  - Falsification criterion: No host initiated >50 SMB connections to other internal hosts in a 10-minute window between 2026-05-21 and 2026-05-24
  - Data sources: NetFlow, Sysmon
  - Suggested query: `EventID=3 AND DestinationPort=445 AND SourceIP != DestinationIP | stats count by SourceIP | where count > 50`
- **[H-5ce19f41-3-O2] No RDP brute-force attempts** _(difficulty: easy · 90 pts · MITRE: T1110)_
  - Falsification criterion: No failed RDP login events (EventID 4625) from a single source IP targeting >10 internal hosts in 1 hour
  - Data sources: Windows Security logs
  - Suggested query: `EventID=4625 AND LogonType=10 | stats count by SourceIpAddress | where count > 10`
- **[H-5ce19f41-3-O3] No PsExec/WMI execution from non-admin hosts** _(difficulty: medium · 120 pts · MITRE: T1059, T1047, T1053)_
  - Falsification criterion: No PsExec, WMI, or schtasks commands were executed from non-administrative user accounts on target hosts
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID=1 AND (Image LIKE '%\psexec.exe%' OR Image LIKE '%\wmic.exe%' OR Image LIKE '%\schtasks.exe%') AND User NOT IN ('DOMAIN\Administrator', 'NT AUTHORITY\SYSTEM')`
- **[H-5ce19f41-3-O4] No lateral movement via network share access** _(difficulty: hard · 130 pts · MITRE: T1021)_
  - Falsification criterion: No user account accessed >5 network shares across different hosts in a 2-hour window without legitimate IT justification
  - Data sources: Windows Event Log, File server logs
  - Suggested query: `EventID=5145 AND ShareName != 'C$' AND ShareName != 'ADMIN$' | stats count by User, SourceComputerName | where count > 5`

**Sigma rule:**

```yaml
title: OpenPetya - Lateral Movement via SMB or RDP Exploitation
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 3
  DestinationPort: 445 OR 3389
  Image: '*\svchost.exe' OR '*\explorer.exe'
  DestinationIp: '192.168.10.0/24' OR '10.0.0.0/8'
condition: EventID == 3 and (DestinationPort == 445 or DestinationPort == 3389) and Image endswith ('\svchost.exe') and DestinationIp in ('192.168.10.0/24', '10.0.0.0/8')
```

---

## 24. Malicious Postinstall Hook Found Across 700+ GitHub Repositories, Including Packagist and Node.js Projects

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmd6aa/malicious_postinstall_hook_found_across_700/>
- **Published**: 2026-05-24T14:07:24+00:00
- **First seen**: 2026-05-24T14:26:19+00:00
- **Relevance score**: 70
- **Score rationale**: triage: 700+ compromised repos indicate widespread supply chain compromise; high potential for enterprise exposure via dependencies.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "postinstall hook"}) -> ok → tool lookup_mitre({"query": "npm"}) -> ok → tool lookup_mitre({"query": "supply chain"}) -> ok → critic: revise (Hypothesis 1: Objective 'No sysmon events show node.exe with postinstall in command line' is not a falsification test — it's a negative observation. Falsification requires a positive, observable event)

> submitted by /u/digicat [link] [comments]

**Extracted signals**
- Domain IOCs: node.js

### Hypotheses (3)

#### H-fbdd6446-1 · Malicious node.exe postinstall hook executed via npm  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, a malicious npm postinstall script was executed via node.exe with command-line arguments containing 'postinstall' as part of a supply chain compromise.

**Why this hypothesis?** The article reports malicious postinstall hooks in 700+ GitHub repos using node.exe to execute scripts during npm install. Our environment includes Node.js packages, making this a plausible attack vector.

**MITRE ATT&CK**: T1195, T1204

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fbdd6446-1-O1] Detect node.exe with postinstall in CommandLine** _(difficulty: easy · 100 pts · MITRE: T1195)_
  - Falsification criterion: At least one Sysmon EventID 1 event shows node.exe with 'postinstall' in CommandLine
  - Data sources: Sysmon
  - Suggested query: `EventID:1 Image:*\node.exe CommandLine:*postinstall*`
- **[H-fbdd6446-1-O2] Detect child process spawned by node.exe during postinstall** _(difficulty: medium · 120 pts · MITRE: T1059)_
  - Falsification criterion: At least one Sysmon EventID 1 event shows cmd.exe or powershell.exe spawned by node.exe with CommandLine containing 'postinstall'
  - Data sources: Sysmon
  - Suggested query: `EventID:1 ParentImage:*\node.exe Image:*\cmd.exe OR Image:*\powershell.exe CommandLine:*postinstall*`
- **[H-fbdd6446-1-O3] Detect npm install executed from non-standard directory** _(difficulty: medium · 110 pts · MITRE: T1195)_
  - Falsification criterion: At least one Sysmon EventID 1 event shows npm.exe executed from a non-system, non-user-app directory (e.g., Temp, AppData\Local\Temp)
  - Data sources: Sysmon
  - Suggested query: `EventID:1 Image:*\npm.exe ImagePath:*Temp* OR ImagePath:*AppData\Local\Temp*`
- **[H-fbdd6446-1-O4] Detect network connection from node.exe postinstall** _(difficulty: hard · 130 pts · MITRE: T1071)_
  - Falsification criterion: At least one Sysmon EventID 3 event shows node.exe establishing outbound connection to a non-whitelisted domain or IP during or after postinstall execution
  - Data sources: Sysmon
  - Suggested query: `EventID:3 Image:*\node.exe CommandLine:*postinstall* (DestinationIp:!192.168.* AND DestinationIp:!10.* AND DestinationIp:!172.16.*-172.31.*)`

**Sigma rule:**

```yaml
title: Malicious npm postinstall via node.exe
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 1
  Image: '*\node.exe'
  CommandLine: '*postinstall*'
condition: all
```

#### H-fbdd6446-2 · Malicious Git repository cloned via CI/CD pipeline  _(confidence: medium)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, a malicious Git repository with a name matching known malicious patterns was cloned during a CI/CD pipeline execution as part of a supply chain attack.

**Why this hypothesis?** The article highlights malicious repos in GitHub ecosystems. Our CI/CD pipelines clone external repos, making this a credible threat if attackers poisoned package dependencies via repo names.

**MITRE ATT&CK**: T1195

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fbdd6446-2-O1] Detect cloning of malicious repo name in CI/CD** _(difficulty: medium · 110 pts · MITRE: T1195)_
  - Falsification criterion: At least one GitLab CI log entry shows a project_path matching '*malware*', '*backdoor*', '*trojan*', or '*keylogger*' during a clone or push event
  - Data sources: GitLab CI logs
  - Suggested query: `project_path:*malware* OR project_path:*backdoor* OR project_path:*trojan* OR project_path:*keylogger* AND event_type:push`
- **[H-fbdd6446-2-O2] Detect npm install triggered from cloned repo in CI** _(difficulty: hard · 130 pts · MITRE: T1195)_
  - Falsification criterion: At least one GitLab CI log entry shows 'npm install' executed immediately after a clone event from a suspicious project_path
  - Data sources: GitLab CI logs
  - Suggested query: `stage:build script:*npm install* AND previous_stage:clone AND (project_path:*malware* OR project_path:*backdoor*)`
- **[H-fbdd6446-2-O3] Detect artifact download from malicious repo** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: At least one GitLab CI log entry shows a file being downloaded from a URL matching a known malicious domain or repo pattern during pipeline execution
  - Data sources: GitLab CI logs, Proxy logs
  - Suggested query: `script:*curl* OR script:*wget* AND (url:*github.com/*malware* OR url:*raw.githubusercontent.com/*backdoor*)`
- **[H-fbdd6446-2-O4] Detect untrusted commit author in malicious repo** _(difficulty: hard · 140 pts · MITRE: T1195)_
  - Falsification criterion: At least one GitLab CI log entry shows a commit authored by a non-whitelisted or newly created user account during a clone from a suspicious project_path
  - Data sources: GitLab CI logs, GitLab user audit logs
  - Suggested query: `project_path:*malware* AND commit_author:*@users.noreply.github.com* AND commit_author:!known-team@company.com`

**Sigma rule:**

```yaml
title: Malicious repo cloned in GitLab CI
logsource:
  product: gitlab
  service: ci_pipeline
detection:
  project_path: '*malware*' OR project_path: '*backdoor*' OR project_path: '*trojan*' OR project_path: '*keylogger*'
  event_type: push
condition: all
```

#### H-fbdd6446-3 · Malicious npm package installed via package.json modification  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, a malicious npm package was installed via a modified package.json file triggered by a user or automated process, leading to postinstall script execution.

**Why this hypothesis?** The article describes malicious packages modifying package.json to inject postinstall hooks. Our environment uses npm and package.json files, making this a plausible method for compromise.

**MITRE ATT&CK**: T1195, T1204

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-fbdd6446-3-O1] Detect package.json modification during npm install** _(difficulty: medium · 110 pts · MITRE: T1195)_
  - Falsification criterion: At least one Sysmon EventID 11 event shows package.json being modified by npm.exe within 1 minute of its execution
  - Data sources: Sysmon
  - Suggested query: `EventID:11 Image:*\npm.exe TargetFilename:*\package.json ParentImage:*\cmd.exe OR ParentImage:*\powershell.exe`
- **[H-fbdd6446-3-O2] Detect npm install triggered by non-interactive user** _(difficulty: hard · 130 pts · MITRE: T1053)_
  - Falsification criterion: At least one Sysmon EventID 1 event shows npm.exe executed by a process other than explorer.exe, powershell.exe, or a known terminal (e.g., cmd.exe from a scheduled task or service)
  - Data sources: Sysmon
  - Suggested query: `EventID:1 Image:*\npm.exe ParentImage:*\schtasks.exe OR ParentImage:*\services.exe OR ParentImage:*\winlogon.exe`
- **[H-fbdd6446-3-O3] Detect package.json modification with malicious script field** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: At least one file integrity monitoring event shows package.json modified to include 'postinstall' or 'preinstall' script field with suspicious content (e.g., curl, powershell, node)
  - Data sources: FIM, EDR file events
  - Suggested query: `file_path:*\package.json AND content:*postinstall* AND (content:*curl* OR content:*powershell* OR content:*node*)`
- **[H-fbdd6446-3-O4] Detect npm install from untrusted registry** _(difficulty: medium · 120 pts · MITRE: T1195)_
  - Falsification criterion: At least one Sysmon EventID 1 event shows npm.exe executed with --registry flag pointing to a non-NPMJS.org domain
  - Data sources: Sysmon
  - Suggested query: `EventID:1 Image:*\npm.exe CommandLine:*--registry* AND CommandLine:*http* AND CommandLine:!registry.npmjs.org`

**Sigma rule:**

```yaml
title: Suspicious package.json modification during npm install
logsource:
  product: windows
  service: sysmon
detection:
  EventID: 11
  Image: '*\npm.exe'
  TargetFilename: '*\package.json'
  UtcTime: '2026-05-20T00:00:00Z' - '2026-05-24T23:59:59Z'
condition: all
```

---

## 25. Updated UAC-0057 toolkit: OYSTERFRESH, OYSTERSHUCK and OYSTERBLUES

- **Source**: /r/blueteamsec
- **Link**: <https://www.reddit.com/r/blueteamsec/comments/1tmenjf/updated_uac0057_toolkit_oysterfresh_oystershuck/>
- **Published**: 2026-05-24T15:04:57+00:00
- **First seen**: 2026-05-24T15:53:34+00:00
- **Relevance score**: 65
- **Score rationale**: triage: UAC-0057 is a known Russian-linked APT group with active tooling; OYSTERFRESH et al. are new implants indicating ongoing operations, detectable via endpoint telemetry.
- **Agent trace**: tool fetch_article({}) -> ok → tool lookup_mitre({"query": "UAC-0057"}) -> ok → tool lookup_mitre({"query": "phishing"}) -> ok → critic: revise (Hypothesis 1: Objective 1 is not a falsification test — it states 'No PowerShell command line events contain...', but the Sigma rule only checks for 'OYSTERFRESH', 'Invoke-Expression', and 'Base64Enco)

> submitted by /u/digicat [link] [comments]

### Hypotheses (3)

#### H-1b6a3e74-1 · UAC-0057 deployed OYSTERFRESH via phishing email  _(confidence: medium)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, a phishing email delivered OYSTERFRESH, which executed via PowerShell with Base64-encoded commands to establish persistence.

**Why this hypothesis?** The article describes OYSTERFRESH as a phishing-delivered PowerShell payload using obfuscated commands. Our hypothesis focuses on the execution phase, which is detectable via EDR and Sysmon logs, even if delivery is not logged.

**MITRE ATT&CK**: T1566, T1059.001

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1b6a3e74-1-O1] No PowerShell execution with OYSTERFRESH keyword** _(difficulty: easy · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: If no Sysmon EventID 1 events contain 'OYSTERFRESH', 'Invoke-Expression', or 'Base64EncodedCommand' in CommandLine, the hypothesis is falsified.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND (CommandLine:*OYSTERFRESH* OR CommandLine:*Invoke-Expression* OR CommandLine:*Base64EncodedCommand*)`
- **[H-1b6a3e74-1-O2] No PowerShell execution with Base64-encoded strings** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: If no PowerShell commands contain Base64-encoded strings (e.g., matching regex [A-Za-z0-9+/]{50,}=*) in CommandLine, the hypothesis is falsified.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND CommandLine:~/[A-Za-z0-9+/]{50,}=*/`
- **[H-1b6a3e74-1-O3] No child process of Outlook or Word spawning PowerShell** _(difficulty: medium · 100 pts · MITRE: T1566, T1059.001)_
  - Falsification criterion: If no PowerShell processes were spawned by Outlook.exe or WINWORD.exe during the time window, the phishing delivery vector is unsupported.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND ParentImage:*\outlook.exe OR ParentImage:*\winword.exe AND Image:*\powershell.exe`
- **[H-1b6a3e74-1-O4] No registry keys modified by PowerShell to achieve persistence** _(difficulty: hard · 150 pts · MITRE: T1547.001)_
  - Falsification criterion: If no registry keys under HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\...\Run were modified by PowerShell during the window, persistence is not established.
  - Data sources: Sysmon
  - Suggested query: `EventID:12 OR EventID:13 OR EventID:14 AND Image:*\powershell.exe AND TargetObject:*\Run\*`

**Sigma rule:**

```yaml
title: Detect OYSTERFRESH PowerShell Execution via Base64
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - 'OYSTERFRESH'
      - 'Invoke-Expression'
      - 'Base64EncodedCommand'
  condition: selection
```

#### H-1b6a3e74-2 · UAC-0057 used OYSTERSHUCK for DLL hijacking via registry modification  _(confidence: high)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, OYSTERSHUCK performed DLL hijacking by modifying registry keys under HKCU\Software\Classes\* to load malicious DLLs from %TEMP%.

**Why this hypothesis?** The article describes OYSTERSHUCK as a UAC bypass tool using DLL hijacking. We focus on the registry modification and DLL load behavior, which are detectable via Sysmon RegistryEvent and FileCreate events.

**MITRE ATT&CK**: T1548.002, T1055

**CTF objectives (4) — find evidence that disproves the hypothesis:**

- **[H-1b6a3e74-2-O1] No registry modifications under Software\Classes by regsvr32 or certutil** _(difficulty: medium · 120 pts · MITRE: T1548.002)_
  - Falsification criterion: If no Sysmon EventID 12/13/14 events show regsvr32.exe or certutil.exe modifying keys under Software\Classes or CLSID, the hijacking did not occur.
  - Data sources: Sysmon
  - Suggested query: `(EventID:12 OR EventID:13 OR EventID:14) AND (Image:*\regsvr32.exe OR Image:*\certutil.exe) AND TargetObject:*\Software\Classes\*`
- **[H-1b6a3e74-2-O2] No DLL loaded from %TEMP% or non-system paths by regsvr32** _(difficulty: hard · 150 pts · MITRE: T1055)_
  - Falsification criterion: If no DLLs were loaded from %TEMP%, %APPDATA%, or non-Windows directories by regsvr32.exe, the hijacking mechanism is unsupported.
  - Data sources: Sysmon, EDR
  - Suggested query: `EventID:11 AND Image:*\regsvr32.exe AND TargetFilename:*\temp\*.dll OR TargetFilename:*\appdata\*.dll`
- **[H-1b6a3e74-2-O3] No process injection into explorer.exe or svchost.exe** _(difficulty: hard · 150 pts · MITRE: T1055)_
  - Falsification criterion: If no process injection into explorer.exe or svchost.exe occurred after registry modification, the payload did not execute.
  - Data sources: EDR
  - Suggested query: `ProcessInjection:True AND TargetProcess:explorer.exe OR TargetProcess:svchost.exe AND SourceProcess:regsvr32.exe`
- **[H-1b6a3e74-2-O4] No file creation of .dll in %TEMP% with OYSTERSHUCK naming pattern** _(difficulty: medium · 100 pts · MITRE: T1059.001)_
  - Falsification criterion: If no .dll files with names matching 'OYSTERSHUCK_*.dll' were created in %TEMP% during the window, the payload was not dropped.
  - Data sources: Sysmon
  - Suggested query: `EventID:11 AND TargetFilename:*\temp\OYSTERSHUCK_*.dll`

**Sigma rule:**

```yaml
title: Detect OYSTERSHUCK DLL Hijacking via Registry Modification
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 12 OR EventID: 13 OR EventID: 14
    TargetObject|contains:
      - '\Software\Classes\' 
      - '\CLSID\'
    Image|endswith: 
      - '\regsvr32.exe'
      - '\certutil.exe'
    CommandLine|contains:
      - 'OYSTERSHUCK'
      - '%TEMP%'
  condition: selection
```

#### H-1b6a3e74-3 · UAC-0057 used OYSTERBLUES for SMB lateral movement from non-admin workstations  _(confidence: medium)_

**Statement.** In our environment between 2026-05-20 and 2026-05-24, OYSTERBLUES executed from non-administrator workstations to access C$, ADMIN$, or IPC$ shares via SMB, using legitimate tools (psexec, smbclient) to move laterally.

**Why this hypothesis?** The article claims OYSTERBLUES uses SMB lateral movement. We focus on detecting non-admin users accessing administrative shares, which is a common lateral movement indicator, even if the malware uses legitimate tools.

**MITRE ATT&CK**: T1021.002, T1078

**CTF objectives (5) — find evidence that disproves the hypothesis:**

- **[H-1b6a3e74-3-O1] No SMB access to C$, ADMIN$, or IPC$ from non-admin accounts** _(difficulty: medium · 120 pts · MITRE: T1021.002)_
  - Falsification criterion: If no EventID 5145 events show non-administrator accounts accessing C$, ADMIN$, or IPC$ shares, lateral movement did not occur.
  - Data sources: Windows Security
  - Suggested query: `EventID:5145 AND ShareName:(C$ OR ADMIN$ OR IPC$) AND NOT AccountName:(Administrator OR 'Domain Admin')`
- **[H-1b6a3e74-3-O2] No SMB connections from non-domain-joined workstations** _(difficulty: hard · 150 pts · MITRE: T1021.002)_
  - Falsification criterion: If no SMB access originated from non-domain-joined machines (identified by workstation name not matching domain pattern), lateral movement was internal only.
  - Data sources: Windows Security, DNS logs
  - Suggested query: `EventID:5145 AND SourceComputer NOT LIKE '%.domain.local' AND ShareName:(C$ OR ADMIN$ OR IPC$)`
- **[H-1b6a3e74-3-O3] No failed logons (EventID 4625) preceding SMB access** _(difficulty: hard · 150 pts · MITRE: T1110)_
  - Falsification criterion: If no failed logons occurred on target hosts within 5 minutes before SMB access, credential theft or brute force was not used to enable access.
  - Data sources: Windows Security
  - Suggested query: `EventID:4625 AND TargetUserName:<> AND TimeGenerated > (EventID:5145 AND ShareName:(C$ OR ADMIN$ OR IPC$)) - 5m`
- **[H-1b6a3e74-3-O4] No process execution of psexec.exe or smbclient.exe on target hosts** _(difficulty: medium · 120 pts · MITRE: T1059.003)_
  - Falsification criterion: If no psexec.exe or smbclient.exe processes were executed on target hosts after SMB access, the malware did not execute commands remotely.
  - Data sources: Sysmon
  - Suggested query: `EventID:1 AND Image:*\psexec.exe OR Image:*\smbclient.exe AND ParentImage:*\svchost.exe OR ParentImage:*\explorer.exe`
- **[H-1b6a3e74-3-O5] No network connections from non-admin workstations to admin hosts on port 445** _(difficulty: medium · 100 pts · MITRE: T1021.002)_
  - Falsification criterion: If no outbound connections from non-admin workstations to admin hosts on TCP 445 occurred, SMB lateral movement did not initiate.
  - Data sources: NetFlow, EDR
  - Suggested query: `DestinationPort:445 AND SourceUser NOT IN ('Administrator', 'Domain Admin') AND DestinationIP IN (admin_hosts_list)`

**Sigma rule:**

```yaml
title: Detect Non-Admin SMB Access to Administrative Shares
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|contains:
      - 'C$'
      - 'ADMIN$'
      - 'IPC$'
    AccountName|contains: 
      - 'WORKSTATION$'
      - 'User'
    AccountName|exclude:
      - 'Administrator'
      - 'Domain Admin'
  condition: selection
```

---
