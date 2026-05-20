"""Default feed registry.

Each entry: (name, url, kind). `kind` is informational ("news", "vendor",
"social", "advisory") so downstream code can weight social signals
differently from vendor advisories.

URLs are public RSS/Atom endpoints. The fetcher will skip any source that is
not reachable from the current environment, so an offline run still completes.
"""
from __future__ import annotations

DEFAULT_FEEDS: list[tuple[str, str, str]] = [
    # Mainstream security news
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "news"),

    # Government / advisory
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "advisory"),
    ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "advisory"),

    # Vendor research blogs
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/", "vendor"),
    ("Google TAG / Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "vendor"),
    ("Talos Intelligence", "https://blog.talosintelligence.com/feeds/posts/default", "vendor"),
    ("CrowdStrike", "https://www.crowdstrike.com/blog/feed/", "vendor"),
    ("Unit42 (Palo Alto)", "https://unit42.paloaltonetworks.com/feed/", "vendor"),

    # Community / social via RSS bridges
    ("/r/netsec", "https://www.reddit.com/r/netsec/.rss", "social"),
    ("/r/blueteamsec", "https://www.reddit.com/r/blueteamsec/.rss", "social"),
    ("Infosec Exchange (Mastodon)", "https://infosec.exchange/public.rss", "social"),
]


SOURCE_WEIGHTS: dict[str, int] = {
    "advisory": 15,
    "vendor": 10,
    "news": 5,
    "social": 2,
}
