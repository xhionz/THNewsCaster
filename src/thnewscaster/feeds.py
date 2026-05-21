"""RSS / Atom feed fetcher and parser using only the standard library.

We deliberately avoid feedparser so the platform has zero runtime
dependencies. We parse both RSS 2.0 (``<rss><channel><item>``) and Atom 1.0
(``<feed><entry>``) and normalise into :class:`Article` instances.
"""
from __future__ import annotations

import hashlib
import html
import logging
import re
import socket
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from .models import Article

log = logging.getLogger(__name__)

# A realistic browser-ish UA: several feeds (Reddit, some Mastodon instances)
# reject the default Python-urllib agent with 403/406.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "THNewsCaster/0.1 Safari/537.36"
)
ACCEPT = "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5"
DEFAULT_TIMEOUT = 12.0

_ATOM_NS = {"a": "http://www.w3.org/2005/Atom"}
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    decoded = html.unescape(text)
    no_tags = _TAG_RE.sub(" ", decoded)
    return _WS_RE.sub(" ", no_tags).strip()


def _hash_id(*parts: str) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


def fetch_url(url: str, timeout: float = DEFAULT_TIMEOUT) -> bytes | None:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": ACCEPT,
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        log.warning("fetch failed for %s: %s", url, exc)
        return None
    except Exception as exc:  # noqa: BLE001 — network code, isolate failures
        log.warning("unexpected fetch failure for %s: %s", url, exc)
        return None


def parse_feed(source_name: str, data: bytes) -> list[Article]:
    """Parse an RSS or Atom feed payload into :class:`Article` objects."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        log.warning("parse failed for %s: %s", source_name, exc)
        return []

    tag = root.tag.lower()
    if tag.endswith("rss"):
        return _parse_rss(source_name, root)
    if tag.endswith("feed"):
        return _parse_atom(source_name, root)
    # RSS occasionally has channel at root or wrapped weirdly
    channel = root.find("channel")
    if channel is not None:
        return _parse_rss(source_name, root)
    log.warning("%s: unknown feed root element %s", source_name, root.tag)
    return []


def _parse_rss(source: str, root: ET.Element) -> list[Article]:
    items: list[Article] = []
    channel = root.find("channel") or root
    for item in channel.findall("item"):
        title = _strip_html((item.findtext("title") or "").strip())
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date") or "").strip()
        desc = _strip_html(item.findtext("description") or "")
        # content:encoded carries the long-form body when present
        ce = item.find("{http://purl.org/rss/1.0/modules/content/}encoded")
        body = _strip_html(ce.text if ce is not None else "")
        raw = " ".join(filter(None, [title, desc, body]))
        if not title and not link:
            continue
        items.append(
            Article(
                id=_hash_id(source, link or title),
                source=source,
                title=title,
                link=link,
                published=pub,
                summary=desc[:1500],
                raw_text=raw,
            )
        )
    return items


def _parse_atom(source: str, root: ET.Element) -> list[Article]:
    items: list[Article] = []
    for entry in root.findall("a:entry", _ATOM_NS):
        title = _strip_html((entry.findtext("a:title", default="", namespaces=_ATOM_NS) or "").strip())
        link_el = entry.find("a:link", _ATOM_NS)
        link = link_el.attrib.get("href", "") if link_el is not None else ""
        pub = (
            entry.findtext("a:published", default="", namespaces=_ATOM_NS)
            or entry.findtext("a:updated", default="", namespaces=_ATOM_NS)
            or ""
        ).strip()
        summary = _strip_html(entry.findtext("a:summary", default="", namespaces=_ATOM_NS) or "")
        content = _strip_html(entry.findtext("a:content", default="", namespaces=_ATOM_NS) or "")
        raw = " ".join(filter(None, [title, summary, content]))
        if not title and not link:
            continue
        items.append(
            Article(
                id=_hash_id(source, link or title),
                source=source,
                title=title,
                link=link,
                published=pub,
                summary=(summary or content)[:1500],
                raw_text=raw,
            )
        )
    return items


def load_local_feed(path: Path, source_name: str | None = None) -> list[Article]:
    data = path.read_bytes()
    return parse_feed(source_name or path.stem, data)


def collect(
    feeds: Iterable[tuple[str, str, str]],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    offline_fallback: Path | None = None,
) -> list[Article]:
    """Fetch and parse all feeds. Returns concatenated, de-duplicated articles."""
    seen: set[str] = set()
    out: list[Article] = []
    successes = 0
    for name, url, _kind in feeds:
        data = fetch_url(url, timeout=timeout)
        if data is None:
            continue
        successes += 1
        for art in parse_feed(name, data):
            if art.id in seen:
                continue
            seen.add(art.id)
            out.append(art)

    if successes == 0 and offline_fallback is not None and offline_fallback.exists():
        log.info("no live feeds reachable; loading offline sample from %s", offline_fallback)
        for art in load_local_feed(offline_fallback, source_name="OfflineSample"):
            if art.id in seen:
                continue
            seen.add(art.id)
            out.append(art)
    return out
