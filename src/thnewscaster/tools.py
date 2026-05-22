"""Tools the agent can call to gather context.

Every tool is fail-safe: on error (network down, offline mode, not found)
it returns a dict with an ``error`` key instead of raising, so the agent
loop can continue and degrade gracefully. Network tools are disabled when
``offline=True``.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from .feeds import _strip_html, fetch_url
from .intel import MITRE_TECHNIQUES, TECHNIQUE_NAMES

log = logging.getLogger(__name__)

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: dict[str, dict] | None = None  # cveID -> entry, loaded once per process
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _load_kev(timeout: float) -> dict[str, dict]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    _kev_cache = {}
    raw = fetch_url(_CISA_KEV_URL, timeout=timeout)
    if raw is None:
        return _kev_cache
    try:
        data = json.loads(raw.decode("utf-8"))
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID", "").upper()
            if cid:
                _kev_cache[cid] = v
        log.info("loaded %d CISA KEV entries", len(_kev_cache))
    except (json.JSONDecodeError, AttributeError) as exc:
        log.warning("failed to parse CISA KEV: %s", exc)
    return _kev_cache


class ToolRegistry:
    """Holds the enabled tools and dispatches calls by name."""

    def __init__(self, *, offline: bool, enabled: set[str], timeout: float = 10.0):
        self.offline = offline
        self.enabled = enabled
        self.timeout = timeout

    # --- tool implementations ---------------------------------------------

    def fetch_article(self, url: str = "", max_chars: int = 6000) -> dict:
        if self.offline:
            return {"error": "offline: article fetch disabled"}
        if not url:
            return {"error": "no url provided"}
        raw = fetch_url(url, timeout=self.timeout)
        if raw is None:
            return {"error": f"could not fetch {url}"}
        try:
            text = _strip_html(raw.decode("utf-8", errors="ignore"))
        except Exception as exc:  # noqa: BLE001
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
                return self.fetch_article(**{k: v for k, v in args.items() if k in ("url", "max_chars")})
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
                "description": "Fetch and clean the full text of the article from its URL "
                               "(more context than the RSS summary).",
                "args": {"url": "string (the article link)"},
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
