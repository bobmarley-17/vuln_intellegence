"""SQLite-backed cache for articles and enriched CVE records.

Prevents re-querying intelligence sources for a CVE we already enriched
within the configured TTL, and gives the dashboard a single place to read
results from.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from modules.models import AffectedProduct, Article, EnrichedCVE

logger = logging.getLogger("vuln_intel.cache")

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    title TEXT,
    author TEXT,
    published_date TEXT,
    site_name TEXT,
    content TEXT,
    fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS article_cves (
    article_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (article_id, cve_id),
    FOREIGN KEY (article_id) REFERENCES articles(id)
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_enriched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    title TEXT,
    status TEXT NOT NULL,
    cves_found INTEGER,
    last_checked TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_article_cves_cve ON article_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_source_urls_status ON source_urls(status);
"""


class VulnCache:
    """Thin synchronous SQLite wrapper. One connection per call (safe for
    the moderate concurrency this tool uses); WAL mode allows concurrent
    readers (dashboard) while the pipeline writes."""

    def __init__(self, db_path: str, ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------
    def url_already_processed(self, url: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM articles WHERE url = ?", (url,)).fetchone()
            return row is not None

    def save_article(self, article: Article) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO articles (url, title, author, published_date, site_name, content, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    title=excluded.title,
                    author=excluded.author,
                    published_date=excluded.published_date,
                    site_name=excluded.site_name,
                    content=excluded.content,
                    fetched_at=excluded.fetched_at
                """,
                (
                    article.url,
                    article.title,
                    article.author,
                    article.published_date,
                    article.site_name,
                    article.content,
                    article.fetched_at,
                ),
            )
            article_id = cur.lastrowid
            if article_id == 0:  # ON CONFLICT UPDATE path: fetch existing id
                row = conn.execute("SELECT id FROM articles WHERE url = ?", (article.url,)).fetchone()
                article_id = row["id"]
            for cve_id in article.cves:
                conn.execute(
                    "INSERT OR IGNORE INTO article_cves (article_id, cve_id) VALUES (?, ?)",
                    (article_id, cve_id),
                )
            return article_id

    def get_articles(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM articles ORDER BY fetched_at DESC").fetchall()
            articles = []
            for row in rows:
                d = dict(row)
                cve_rows = conn.execute(
                    "SELECT cve_id FROM article_cves WHERE article_id = ?", (row["id"],)
                ).fetchall()
                d["cves"] = [r["cve_id"] for r in cve_rows]
                articles.append(d)
            return articles

    # ------------------------------------------------------------------
    # Source URLs
    # ------------------------------------------------------------------
    def add_source_url(self, url: str) -> int | None:
        """Adds a new source URL for processing. Returns the new row ID."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO source_urls (url, status, last_checked, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (url, "Pending", now, now),
                )
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            logger.warning("Source URL %s already exists in the database.", url)
            return None

    def get_all_sources(self) -> list[dict]:
        """Returns all tracked source URLs."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, url, title, status, cves_found, last_checked FROM source_urls ORDER BY created_at DESC"
            ).fetchall()
        # sqlite3.Row objects act like dicts, so this is fine for jsonify
        return [dict(r) for r in rows]

    def delete_source(self, source_id: int) -> None:
        """Deletes a source URL by its ID."""
        with self._connect() as conn:
            conn.execute("DELETE FROM source_urls WHERE id = ?", (source_id,))
            logger.info("Deleted source URL with ID %d", source_id)

    # ------------------------------------------------------------------
    # CVEs
    # ------------------------------------------------------------------
    def get_cached_cve(self, cve_id: str) -> EnrichedCVE | None:
        """Return a cached, still-fresh EnrichedCVE, or None if missing/stale."""
        with self._connect() as conn:
            row = conn.execute("SELECT data, last_enriched_at FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        last_enriched = datetime.fromisoformat(row["last_enriched_at"])
        if last_enriched.tzinfo is None:
            last_enriched = last_enriched.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - last_enriched > timedelta(hours=self.ttl_hours):
            logger.debug("Cache stale for %s (last enriched %s)", cve_id, row["last_enriched_at"])
            return None
        return self._deserialize(json.loads(row["data"]))

    def save_cve(self, cve: EnrichedCVE) -> None:
        cve.last_enriched_at = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(self._serialize(cve))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cves (cve_id, data, last_enriched_at) VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET data=excluded.data, last_enriched_at=excluded.last_enriched_at
                """,
                (cve.cve_id, payload, cve.last_enriched_at),
            )

    def get_all_cves(self) -> list[EnrichedCVE]:
        with self._connect() as conn:
            rows = conn.execute("SELECT data FROM cves").fetchall()
        return [self._deserialize(json.loads(r["data"])) for r in rows]

    @staticmethod
    def _serialize(cve: EnrichedCVE) -> dict:
        d = cve.__dict__.copy()
        d["affected_products"] = [ap.__dict__ for ap in cve.affected_products]
        return d

    @staticmethod
    def _deserialize(d: dict) -> EnrichedCVE:
        d = d.copy()
        d["affected_products"] = [AffectedProduct(**ap) for ap in d.get("affected_products", [])]
        return EnrichedCVE(**d)
