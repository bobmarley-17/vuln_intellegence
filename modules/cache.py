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

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    scan_time TEXT NOT NULL,
    duration_seconds REAL,
    status TEXT NOT NULL,
    articles_processed INTEGER NOT NULL DEFAULT 0,
    cves_found INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (source_id) REFERENCES source_urls(id)
);

CREATE INDEX IF NOT EXISTS idx_article_cves_cve ON article_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_source_urls_status ON source_urls(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_source ON scan_history(source_id);
"""

# Columns added after the original source_urls table shipped. Added via
# migration (ALTER TABLE) rather than the CREATE TABLE above so existing
# databases pick them up without losing data.
_SOURCE_MIGRATED_COLUMNS = {
    "name": "TEXT",
    "source_type": "TEXT NOT NULL DEFAULT 'security_blog'",
    "vendor": "TEXT",
    "polling_interval_minutes": "INTEGER",
    "enabled": "INTEGER NOT NULL DEFAULT 1",
    "last_error": "TEXT",
    "last_articles_processed": "INTEGER",
    "updated_at": "TEXT",
}

_SOURCE_LIST_COLUMNS = (
    "id, name, url, source_type, vendor, polling_interval_minutes, enabled, "
    "status, cves_found, last_articles_processed, last_checked, last_error, created_at, updated_at"
)

_UPDATABLE_SOURCE_FIELDS = {"name", "url", "source_type", "vendor", "polling_interval_minutes", "enabled"}

# Added after articles shipped without a source link -- feed/API scans
# produce article URLs that don't equal the source's own URL, so there was
# no way to trace an article back to the source that found it.
_ARTICLE_MIGRATED_COLUMNS = {"source_id": "INTEGER"}


class DuplicateSourceError(Exception):
    """Raised when a source URL already exists in the database."""


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
            self._migrate_columns(conn, "source_urls", _SOURCE_MIGRATED_COLUMNS)
            self._migrate_columns(conn, "articles", _ARTICLE_MIGRATED_COLUMNS)

    @staticmethod
    def _migrate_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for column, ddl in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    # ------------------------------------------------------------------
    # Articles
    # ------------------------------------------------------------------
    def url_already_processed(self, url: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM articles WHERE url = ?", (url,)).fetchone()
            return row is not None

    def save_article(self, article: Article) -> int:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO articles (url, title, author, published_date, site_name, content, fetched_at, source_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    title=excluded.title,
                    author=excluded.author,
                    published_date=excluded.published_date,
                    site_name=excluded.site_name,
                    content=excluded.content,
                    fetched_at=excluded.fetched_at,
                    source_id=excluded.source_id
                """,
                (
                    article.url,
                    article.title,
                    article.author,
                    article.published_date,
                    article.site_name,
                    article.content,
                    article.fetched_at,
                    article.source_id,
                ),
            )
            # SQLite's lastrowid is not reliable on the UPDATE side of an
            # UPSERT. Fetch the canonical row id every time.
            row = conn.execute("SELECT id FROM articles WHERE url = ?", (article.url,)).fetchone()
            article_id = row["id"]
            # Replace stale article-to-CVE associations on a later fetch.
            conn.execute("DELETE FROM article_cves WHERE article_id = ?", (article_id,))
            for cve_id in article.cves:
                conn.execute(
                    "INSERT OR IGNORE INTO article_cves (article_id, cve_id) VALUES (?, ?)",
                    (article_id, cve_id),
                )
            return article_id

    def get_articles(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*, s.name AS source_name
                FROM articles a
                LEFT JOIN source_urls s ON s.id = a.source_id
                ORDER BY a.fetched_at DESC
                """
            ).fetchall()
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
    # Sources
    # ------------------------------------------------------------------
    def add_source(
        self,
        url: str,
        name: str | None = None,
        source_type: str = "security_blog",
        vendor: str | None = None,
        polling_interval_minutes: int | None = None,
        enabled: bool = True,
    ) -> int:
        """Adds a new source. Returns the new row ID, or raises
        DuplicateSourceError if the URL is already tracked."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO source_urls
                        (url, name, source_type, vendor, polling_interval_minutes, enabled,
                         status, last_checked, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        url,
                        name,
                        source_type,
                        vendor,
                        polling_interval_minutes,
                        int(enabled),
                        "Pending",
                        now,
                        now,
                        now,
                    ),
                )
                return cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise DuplicateSourceError(f"Source URL already exists: {url}") from exc

    def get_all_sources(self) -> list[dict]:
        """Returns all tracked sources, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_SOURCE_LIST_COLUMNS} FROM source_urls ORDER BY created_at DESC"
            ).fetchall()
        return [self._source_row_to_dict(r) for r in rows]

    def get_enabled_sources(self) -> list[dict]:
        """Sources the scanning engine should actually process."""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_SOURCE_LIST_COLUMNS} FROM source_urls WHERE enabled = 1 ORDER BY id"
            ).fetchall()
        return [self._source_row_to_dict(r) for r in rows]

    def get_source(self, source_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {_SOURCE_LIST_COLUMNS} FROM source_urls WHERE id = ?", (source_id,)
            ).fetchone()
        return self._source_row_to_dict(row) if row is not None else None

    def update_source(self, source_id: int, **fields) -> bool:
        """Updates any of the user-editable source fields (only keys present
        in `fields` are touched, so callers should omit fields they don't
        want to change rather than passing None). Returns whether a row was
        actually updated (False if the id doesn't exist). Raises
        DuplicateSourceError if the new URL collides with another source."""
        updates = {k: v for k, v in fields.items() if k in _UPDATABLE_SOURCE_FIELDS}
        if not updates:
            return False
        if "enabled" in updates:
            updates["enabled"] = int(bool(updates["enabled"]))
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{column} = ?" for column in updates)
        params = [*updates.values(), source_id]
        try:
            with self._connect() as conn:
                cursor = conn.execute(f"UPDATE source_urls SET {set_clause} WHERE id = ?", params)
                return cursor.rowcount > 0
        except sqlite3.IntegrityError as exc:
            raise DuplicateSourceError(f"Source URL already exists: {updates.get('url')}") from exc

    def set_source_enabled(self, source_id: int, enabled: bool) -> bool:
        return self.update_source(source_id, enabled=enabled)

    def mark_source_scanning(self, source_id: int) -> None:
        """Flag a source as actively being scanned."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE source_urls SET status = ?, last_checked = ? WHERE id = ?",
                ("Processing", datetime.now(timezone.utc).isoformat(), source_id),
            )

    def delete_source(self, source_id: int) -> None:
        """Deletes a source by ID. Scan history rows are intentionally left
        in place (no cascade) so past scan results remain available."""
        with self._connect() as conn:
            conn.execute("DELETE FROM source_urls WHERE id = ?", (source_id,))
            logger.info("Deleted source with ID %d", source_id)

    @staticmethod
    def _source_row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------
    def record_scan(
        self,
        source_id: int,
        status: str,
        duration_seconds: float,
        articles_processed: int,
        cves_found: int,
        error_message: str | None = None,
    ) -> None:
        """Appends a scan_history row and updates the source's summary
        fields (status/cves_found/last_checked/last_error) to match."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_history
                    (source_id, scan_time, duration_seconds, status, articles_processed,
                     cves_found, error_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (source_id, now, duration_seconds, status, articles_processed, cves_found, error_message, now),
            )
            conn.execute(
                """
                UPDATE source_urls
                SET status = ?, cves_found = ?, last_articles_processed = ?, last_checked = ?,
                    last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, cves_found, articles_processed, now, error_message, now, source_id),
            )

    def get_scan_history(self, source_id: int, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_history WHERE source_id = ? ORDER BY scan_time DESC LIMIT ?",
                (source_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_scan_history(self, source_id: int | None = None, limit: int = 300) -> list[dict]:
        """Scan history across every source, newest first, for the
        dedicated Scan History page. Optionally scoped to one source."""
        query = """
            SELECT h.*, s.name AS source_name, s.url AS source_url, s.source_type AS source_type
            FROM scan_history h
            LEFT JOIN source_urls s ON s.id = h.source_id
        """
        params: list = []
        if source_id is not None:
            query += " WHERE h.source_id = ?"
            params.append(source_id)
        query += " ORDER BY h.scan_time DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

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

    def get_cve(self, cve_id: str) -> EnrichedCVE | None:
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return self._deserialize(json.loads(row["data"]))

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
