"""SQLite-backed persistence: dedup ledger + briefing archive.

Two responsibilities:

* **Dedup** — remember every article id we've already processed so the
  (expensive) hypothesis/LLM step only runs on genuinely new articles.
* **Rolling archive** — store full briefings as JSON so the published site
  can show a rolling window (e.g. last 14 days) even on days with little
  new news, and so we keep history.

Stdlib ``sqlite3`` only.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import HuntBriefing, briefing_from_dict
from dataclasses import asdict

log = logging.getLogger(__name__)


class BriefingStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS seen (
                article_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                title      TEXT,
                score      INTEGER
            );
            CREATE TABLE IF NOT EXISTS briefings (
                article_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                score      INTEGER,
                data       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_briefings_seen ON briefings(first_seen);
            """
        )
        self.conn.commit()

    # --- dedup -------------------------------------------------------------

    def known_ids(self) -> set[str]:
        rows = self.conn.execute("SELECT article_id FROM seen").fetchall()
        return {r["article_id"] for r in rows}

    def is_seen(self, article_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM seen WHERE article_id = ?", (article_id,)
        ).fetchone()
        return row is not None

    def mark_seen(self, article_id: str, title: str, score: int, when: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO seen(article_id, first_seen, title, score) VALUES (?,?,?,?)",
            (article_id, when, title, score),
        )

    # --- briefing archive --------------------------------------------------

    def save_briefing(self, briefing: HuntBriefing) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO briefings(article_id, first_seen, score, data) VALUES (?,?,?,?)",
            (
                briefing.article.id,
                briefing.first_seen,
                briefing.scoring.score,
                json.dumps(asdict(briefing), ensure_ascii=False),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def recent_briefings(self, within_days: int, limit: int | None = None) -> list[HuntBriefing]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=within_days)).isoformat()
        sql = "SELECT data FROM briefings WHERE first_seen >= ? ORDER BY score DESC, first_seen DESC"
        params: tuple = (cutoff,)
        if limit is not None:
            sql += " LIMIT ?"
            params = (cutoff, limit)
        rows = self.conn.execute(sql, params).fetchall()
        out: list[HuntBriefing] = []
        for r in rows:
            try:
                out.append(briefing_from_dict(json.loads(r["data"])))
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                log.warning("skipping corrupt stored briefing: %s", exc)
        return out

    def close(self) -> None:
        self.conn.close()
