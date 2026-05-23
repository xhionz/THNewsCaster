"""Lightweight, embedded threat-intel knowledge base.

This is intentionally a curated dictionary rather than a live TI feed: it
lets the extractor recognise common malware families, threat groups, and
MITRE ATT&CK techniques mentioned in news articles without requiring any
network access at runtime. Update as new families emerge.
"""
from __future__ import annotations

# Map: canonical name -> list of case-insensitive aliases / regex-ready strings.
MALWARE_FAMILIES: dict[str, list[str]] = {
    "Cobalt Strike": ["cobalt strike", "cobaltstrike", "beacon"],
    "Emotet": ["emotet"],
    "IcedID": ["icedid", "bokbot"],
    "Qakbot": ["qakbot", "qbot"],
    "TrickBot": ["trickbot"],
    "BumbleBee": ["bumblebee"],
    "Lumma Stealer": ["lumma stealer", "lummac2", "lumma"],
    "RedLine Stealer": ["redline stealer", "redline"],
    "Raccoon Stealer": ["raccoon stealer"],
    "StealC": ["stealc"],
    "AsyncRAT": ["asyncrat"],
    "Remcos": ["remcos"],
    "NjRAT": ["njrat"],
    "AgentTesla": ["agent tesla", "agenttesla"],
    "FormBook": ["formbook"],
    "Gootloader": ["gootloader"],
    "PikaBot": ["pikabot"],
    "DarkGate": ["darkgate"],
    "SocGholish": ["socgholish", "fakeupdates"],
    "BlackCat / ALPHV": ["alphv", "blackcat"],
    "LockBit": ["lockbit"],
    "Akira": ["akira ransomware", "akira"],
    "Play": ["play ransomware"],
    "RansomHub": ["ransomhub"],
    "Royal": ["royal ransomware"],
    "Cl0p": ["cl0p", "clop"],
    "8Base": ["8base"],
    "Medusa": ["medusa ransomware"],
    "Rhysida": ["rhysida"],
    "BianLian": ["bianlian"],
    "Snake / Turla": ["snake malware", "turla"],
}

THREAT_ACTORS: dict[str, list[str]] = {
    "APT28 (Fancy Bear)": ["apt28", "fancy bear", "sofacy", "strontium"],
    "APT29 (Cozy Bear)": ["apt29", "cozy bear", "nobelium", "midnight blizzard"],
    "APT41": ["apt41", "barium", "winnti"],
    "Lazarus": ["lazarus", "hidden cobra"],
    "Kimsuky": ["kimsuky"],
    "Mustang Panda": ["mustang panda"],
    "Volt Typhoon": ["volt typhoon"],
    "Salt Typhoon": ["salt typhoon"],
    "Flax Typhoon": ["flax typhoon"],
    "Scattered Spider": ["scattered spider", "muddled libra", "octo tempest"],
    "FIN7": ["fin7", "carbon spider"],
    "FIN8": ["fin8"],
    "TA505": ["ta505"],
    "TA577": ["ta577"],
    "Charming Kitten": ["charming kitten", "apt35"],
    "Sandworm": ["sandworm"],
    "Black Basta": ["black basta"],
}

# Subset of MITRE ATT&CK Enterprise techniques most often referenced in news.
MITRE_TECHNIQUES: dict[str, list[str]] = {
    "T1566": ["phishing", "spear phishing", "spearphishing"],
    "T1190": ["exploit public-facing", "exploited a vulnerability in", "exploits a vulnerability in"],
    "T1133": ["external remote services", "vpn access"],
    "T1078": ["valid accounts", "stolen credentials", "compromised credentials"],
    "T1059": ["powershell", "command and scripting"],
    "T1059.001": ["powershell"],
    "T1059.003": ["cmd.exe", "windows command shell"],
    "T1053": ["scheduled task", "scheduled tasks", "cron"],
    "T1547": ["registry run key", "autostart", "startup folder"],
    "T1055": ["process injection"],
    "T1003": ["credential dumping", "lsass", "mimikatz", "ntds.dit"],
    "T1021.001": ["rdp", "remote desktop"],
    "T1021.002": ["smb", "admin shares"],
    "T1021.006": ["winrm", "powershell remoting"],
    "T1071": ["http command and control", "https beacon"],
    "T1071.004": ["dns tunneling"],
    "T1486": ["ransomware", "encrypts files", "data encrypted for impact"],
    "T1567": ["exfiltration over web", "mega.nz", "anonfiles"],
    "T1041": ["exfiltration over c2"],
    "T1567.002": ["cloud storage exfiltration"],
    "T1219": ["remote access software", "anydesk", "teamviewer", "screenconnect", "atera"],
    "T1620": ["reflective loading"],
    "T1218.011": ["rundll32"],
    "T1098": ["account manipulation"],
    "T1110": ["brute force", "password spraying"],
    "T1573": ["encrypted channel"],
    "T1497": ["sandbox evasion"],
    "T1505.003": ["webshell", "web shell"],
}

VECTOR_KEYWORDS: dict[str, list[str]] = {
    "phishing": ["phishing", "spear-phish", "lure", "malicious attachment", "malicious link"],
    "exploit": ["zero-day", "0-day", "exploit", "rce", "remote code execution", "deserialization", "unauthenticated"],
    "supply-chain": ["supply chain", "software supply chain", "update server"],
    "vpn-edge": ["vpn", "fortinet", "ivanti", "citrix", "palo alto", "sonicwall", "edge device", "firewall appliance"],
    "rdp": ["rdp", "remote desktop", "exposed rdp"],
    "smb": ["smb", "eternalblue", "lateral smb"],
    "ssh": ["ssh brute", "exposed ssh"],
    "cloud-misconfig": ["s3 bucket", "exposed bucket", "iam misconfiguration", "azure ad", "entra id"],
    "credential-theft": ["credential theft", "infostealer", "stealer logs", "stolen credentials"],
    "social-engineering": ["help desk", "vishing", "social engineering", "mfa fatigue", "mfa bombing"],
}

ACTION_KEYWORDS: dict[str, list[str]] = {
    "ransomware": ["ransomware", "ransom note", "data encrypted", "encrypted files"],
    "data-breach": ["data breach", "data theft", "data leak", "exfiltrated"],
    "espionage": ["espionage", "cyberespionage", "intelligence gathering"],
    "wiper": ["wiper", "destructive malware"],
    "cryptomining": ["cryptominer", "crypto mining", "xmrig"],
    "ddos": ["ddos", "denial of service"],
    "fraud": ["bec", "business email compromise", "wire fraud"],
}

SECTOR_KEYWORDS: dict[str, list[str]] = {
    "healthcare": ["hospital", "healthcare", "clinic", "medical"],
    "finance": ["bank", "financial", "fintech", "credit union"],
    "government": ["government", "federal", "agency", "municipal", "ministry"],
    "energy": ["energy", "utility", "power grid", "oil and gas"],
    "manufacturing": ["manufacturer", "manufacturing", "factory", "ot", "ics"],
    "education": ["university", "school", "education"],
    "retail": ["retailer", "retail", "ecommerce"],
    "telecom": ["telecom", "telecommunications", "isp"],
    "msp": ["managed service provider", "msp"],
}

# Human-readable names for the ATT&CK technique IDs we reference, so the
# MITRE lookup tool can resolve ids<->names fully offline.
TECHNIQUE_NAMES: dict[str, str] = {
    "T1566": "Phishing",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1055": "Process Injection",
    "T1003": "OS Credential Dumping",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1071": "Application Layer Protocol",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1095": "Non-Application Layer Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1219": "Remote Access Software",
    "T1620": "Reflective Code Loading",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1110.003": "Brute Force: Password Spraying",
    "T1573": "Encrypted Channel",
    "T1573.002": "Encrypted Channel: Asymmetric Cryptography",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1505.003": "Server Software Component: Web Shell",
    "T1204": "User Execution",
    "T1556": "Modify Authentication Process",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1560": "Archive Collected Data",
    "T1570": "Lateral Tool Transfer",
    "T1528": "Steal Application Access Token",
    "T1621": "Multi-Factor Authentication Request Generation",
}


# ATT&CK kill-chain stage order (subset we map) and technique -> primary stage.
KILLCHAIN_STAGES: list[str] = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

TECHNIQUE_TACTIC: dict[str, str] = {
    "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
    "T1078": "Initial Access", "T1078.004": "Initial Access",
    "T1059": "Execution", "T1059.001": "Execution", "T1059.003": "Execution",
    "T1059.005": "Execution", "T1053": "Execution", "T1053.005": "Execution",
    "T1204": "Execution",
    "T1547": "Persistence", "T1547.001": "Persistence", "T1098": "Persistence",
    "T1505.003": "Persistence",
    "T1055": "Defense Evasion", "T1620": "Defense Evasion", "T1218.011": "Defense Evasion",
    "T1497": "Defense Evasion",
    "T1003": "Credential Access", "T1110": "Credential Access", "T1110.003": "Credential Access",
    "T1556": "Credential Access", "T1558.003": "Credential Access", "T1528": "Credential Access",
    "T1621": "Credential Access",
    "T1021.001": "Lateral Movement", "T1021.002": "Lateral Movement",
    "T1021.006": "Lateral Movement", "T1570": "Lateral Movement",
    "T1560": "Collection",
    "T1071": "Command and Control", "T1071.004": "Command and Control",
    "T1095": "Command and Control", "T1219": "Command and Control",
    "T1573": "Command and Control", "T1573.002": "Command and Control",
    "T1567": "Exfiltration", "T1567.002": "Exfiltration", "T1041": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1486": "Impact",
}


PRODUCT_KEYWORDS: dict[str, list[str]] = {
    "Microsoft Exchange": ["exchange server", "outlook web access", "owa"],
    "Microsoft 365 / Entra ID": ["entra id", "azure ad", "microsoft 365", "office 365"],
    "Active Directory": ["active directory", "domain controller"],
    "Fortinet FortiOS": ["fortinet", "fortios", "fortigate"],
    "Ivanti Connect Secure": ["ivanti connect secure", "pulse secure", "ivanti"],
    "Citrix NetScaler": ["citrix", "netscaler", "citrix adc"],
    "Palo Alto GlobalProtect": ["globalprotect", "pan-os"],
    "Cisco ASA / FTD": ["cisco asa", "cisco ftd"],
    "VMware ESXi": ["esxi", "vmware esxi", "vcenter"],
    "MOVEit Transfer": ["moveit"],
    "ConnectWise ScreenConnect": ["screenconnect", "connectwise"],
    "Atlassian Confluence": ["confluence"],
    "GitLab": ["gitlab"],
    "Apache Struts": ["apache struts"],
    "Linux kernel": ["linux kernel"],
}
