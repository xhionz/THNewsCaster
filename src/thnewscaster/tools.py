"""Tools the agent can call to gather context.

Every tool is fail-safe: on error (network down, offline mode, not found)
it returns a dict with an ``error`` key instead of raising, so the agent
loop can continue and degrade gracefully. Network tools are disabled when
``offline=True``.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .feeds import _strip_html, fetch_url
from .intel import MITRE_TECHNIQUES, TECHNIQUE_NAMES

log = logging.getLogger(__name__)


def _is_public_http_url(url: str) -> bool:
    """Reject non-HTTP(S) URLs and any host resolving to a non-public address.

    The agent chooses what to fetch from prompt content that includes
    untrusted article text, so an injected URL could otherwise point at
    cloud metadata (169.254.169.254), localhost, or internal services
    (SSRF). We resolve the host and refuse private/loopback/link-local/
    reserved targets.
    """
    try:
        u = urlparse(url)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 80, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: dict[str, dict] | None = None  # cveID -> entry, loaded once per process
_kev_lock = threading.Lock()
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _load_kev(timeout: float) -> dict[str, dict]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    # Build a local dict and publish it atomically, so concurrent callers in
    # parallel briefing generation don't double-fetch or see a half-filled cache.
    with _kev_lock:
        if _kev_cache is not None:
            return _kev_cache
        loaded: dict[str, dict] = {}
        raw = fetch_url(_CISA_KEV_URL, timeout=timeout)
        if raw is not None:
            try:
                data = json.loads(raw.decode("utf-8"))
                for v in data.get("vulnerabilities", []):
                    cid = v.get("cveID", "").upper()
                    if cid:
                        loaded[cid] = v
                log.info("loaded %d CISA KEV entries", len(loaded))
            except (json.JSONDecodeError, AttributeError) as exc:
                log.warning("failed to parse CISA KEV: %s", exc)
        _kev_cache = loaded
        return _kev_cache


def kev_enrich(cves: list[str], *, offline: bool, timeout: float = 10.0) -> dict[str, dict]:
    """Pre-fetch CISA KEV status for already-extracted CVEs.

    Shared by triage and the hunt agent so they get authoritative
    in-the-wild/ransomware status without spending a tool round-trip. The KEV
    catalog is fetched once and cached, so enriching many articles is cheap.
    """
    if offline or not cves:
        return {}
    kev = _load_kev(timeout)
    out: dict[str, dict] = {}
    for c in cves:
        entry = kev.get(c.upper())
        if entry:
            out[c.upper()] = {
                "known_exploited": True,
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "date_added": entry.get("dateAdded"),
                "product": entry.get("product"),
            }
    return out


class ToolRegistry:
    """Holds the enabled tools and dispatches calls by name."""

    def __init__(self, *, offline: bool, enabled: set[str], timeout: float = 10.0,
                 article_url: str = ""):
        self.offline = offline
        self.enabled = enabled
        self.timeout = timeout
        # The only URL fetch_article is allowed to retrieve. Pinning it to the
        # article under analysis removes the SSRF surface entirely — the model
        # cannot redirect the fetch to an injected/internal URL.
        self.article_url = article_url

    # --- tool implementations ---------------------------------------------

    def fetch_article(self, max_chars: int = 6000) -> dict:
        if self.offline:
            return {"error": "offline: article fetch disabled"}
        url = self.article_url
        if not url:
            return {"error": "no article url available"}
        if not _is_public_http_url(url):
            return {"error": "refusing to fetch non-public or unsafe URL"}
        raw = fetch_url(url, timeout=self.timeout)
        if raw is None:
            return {"error": f"could not fetch {url}"}
        try:
            text = _strip_html(raw.decode("utf-8", errors="ignore"))
        except (UnicodeError, ValueError) as exc:
            return {"error": f"decode failed: {exc}"}
        return {"url": url, "text": text[:max_chars], "truncated": len(text) > max_chars}

    def lookup_cve(self, cve: str = "") -> dict:
        cve = (cve or "").upper().strip()
        if not _CVE_RE.match(cve):
            return {"error": f"'{cve}' is not a valid CVE id"}
        if self.offline:
            return {"cve": cve, "error": "offline: KEV lookup disabled"}
        kev = _load_kev(self.timeout)
        entry = kev.get(cve)
        if entry is None:
            return {"cve": cve, "known_exploited": False,
                    "note": "not present in CISA KEV catalog"}
        return {
            "cve": cve,
            "known_exploited": True,
            "vendor_project": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerability_name": entry.get("vulnerabilityName"),
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "required_action": entry.get("requiredAction"),
            "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
            "short_description": entry.get("shortDescription"),
        }

    def lookup_mitre(self, query: str = "") -> dict:
        """Resolve ATT&CK ids<->names. Fully offline (bundled catalog)."""
        q = (query or "").strip()
        if not q:
            return {"error": "no query provided"}
        # Exact technique id.
        up = q.upper()
        if up in TECHNIQUE_NAMES:
            return {"matches": [{"id": up, "name": TECHNIQUE_NAMES[up]}]}
        # Substring search over names + alias keywords.
        ql = q.lower()
        matches = [
            {"id": tid, "name": name}
            for tid, name in TECHNIQUE_NAMES.items()
            if ql in name.lower()
        ]
        for tid, aliases in MITRE_TECHNIQUES.items():
            if any(ql in a for a in aliases) and not any(m["id"] == tid for m in matches):
                matches.append({"id": tid, "name": TECHNIQUE_NAMES.get(tid, tid)})
        return {"matches": matches[:10]} if matches else {"matches": [], "note": "no match"}

    # --- dispatch ----------------------------------------------------------

    def call(self, name: str, args: dict) -> dict:
        if name not in self.enabled:
            return {"error": f"tool '{name}' is not enabled"}
        args = args or {}
        try:
            if name == "fetch_article":
                return self.fetch_article(**{k: v for k, v in args.items() if k in ("max_chars",)})
            if name == "lookup_cve":
                return self.lookup_cve(cve=args.get("cve", ""))
            if name == "lookup_mitre":
                return self.lookup_mitre(query=args.get("query", ""))
        except TypeError as exc:
            return {"error": f"bad arguments for {name}: {exc}"}
        return {"error": f"unknown tool '{name}'"}

    def schema(self) -> list[dict]:
        """Tool descriptions advertised to the model (name/args/desc)."""
        catalog = {
            "fetch_article": {
                "description": "Fetch and clean the full text of THIS article (more context "
                               "than the RSS summary). Takes no arguments.",
                "args": {},
            },
            "lookup_cve": {
                "description": "Look up a CVE in the CISA Known Exploited Vulnerabilities "
                               "catalog: in-the-wild status, vendor/product, ransomware use, due date.",
                "args": {"cve": "string e.g. CVE-2024-21762"},
            },
            "lookup_mitre": {
                "description": "Resolve a MITRE ATT&CK technique id or keyword to id+name(s).",
                "args": {"query": "string e.g. 'T1190' or 'phishing'"},
            },
        }
        return [{"name": n, **catalog[n]} for n in catalog if n in self.enabled]
