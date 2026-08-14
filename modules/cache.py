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

from werkzeug.security import check_password_hash, generate_password_hash

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

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS action1_endpoints (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    org_id TEXT,
    raw_json TEXT,
    synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action1_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version TEXT,
    FOREIGN KEY (endpoint_id) REFERENCES action1_endpoints(id)
);

CREATE TABLE IF NOT EXISTS action1_exposures (
    cve_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    product TEXT,
    installed_version TEXT,
    affected_range TEXT,
    fixed_version TEXT,
    version_status TEXT,
    detected_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, endpoint_id, product)
);

CREATE TABLE IF NOT EXISTS rt_tickets (
    cve_id TEXT NOT NULL,
    ticket_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, ticket_id)
);

CREATE TABLE IF NOT EXISTS rt_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending Approval',
    trigger_reason TEXT,
    ticket_origin TEXT,

    severity TEXT,
    cvss_score REAL,
    epss_score REAL,
    kev_listed INTEGER NOT NULL DEFAULT 0,
    vendor TEXT,
    product TEXT,
    affected_endpoint_count INTEGER,
    description TEXT,
    recommendation TEXT,
    source_articles TEXT,

    proposed_queue TEXT NOT NULL,
    proposed_priority TEXT,
    proposed_owner TEXT,
    proposed_subject TEXT NOT NULL,
    proposed_body TEXT NOT NULL,

    rt_ticket_id INTEGER,
    rejection_reason TEXT,
    failure_reason TEXT,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (status IN ('Draft','Pending Approval','Approved','Created','Rejected','Cancelled','Creation Failed'))
);

CREATE TABLE IF NOT EXISTS rt_draft_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    draft_id INTEGER NOT NULL,
    event TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (draft_id) REFERENCES rt_drafts(id)
);

CREATE TABLE IF NOT EXISTS nvd_discovery_evaluated (
    cve_id TEXT PRIMARY KEY,
    relevant INTEGER NOT NULL,
    reason TEXT,
    evaluated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_discovery_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_success_window_end TEXT
);

CREATE INDEX IF NOT EXISTS idx_article_cves_cve ON article_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_source_urls_status ON source_urls(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_source ON scan_history(source_id);
CREATE INDEX IF NOT EXISTS idx_action1_software_endpoint ON action1_software(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_action1_exposures_cve ON action1_exposures(cve_id);
CREATE INDEX IF NOT EXISTS idx_rt_tickets_cve ON rt_tickets(cve_id);
CREATE INDEX IF NOT EXISTS idx_rt_drafts_cve ON rt_drafts(cve_id);
CREATE INDEX IF NOT EXISTS idx_rt_drafts_status ON rt_drafts(status);
CREATE INDEX IF NOT EXISTS idx_rt_draft_audit_draft ON rt_draft_audit(draft_id);
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


class DuplicateUserError(Exception):
    """Raised when a username already exists in the database."""


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
    # Users (dashboard login)
    # ------------------------------------------------------------------
    def create_user(self, username: str, password: str) -> int:
        """Creates a login account. Returns the new user id, or raises
        DuplicateUserError if the username is already taken."""
        now = datetime.now(timezone.utc).isoformat()
        password_hash = generate_password_hash(password)
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (username, password_hash, is_active, created_at) VALUES (?, ?, 1, ?)",
                    (username, password_hash, now),
                )
                return cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise DuplicateUserError(f"User already exists: {username}") from exc

    def verify_user_password(self, username: str, password: str) -> dict | None:
        """Returns the user row if the username/password pair is valid and
        the account is active, else None. Never distinguishes 'no such
        user' from 'wrong password' in its return value -- that's the
        caller's job to keep constant-ish (avoid username enumeration)."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return None
        if not row["is_active"]:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        return dict(row)

    def get_user_by_id(self, user_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def get_user_by_username(self, username: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, username, is_active, created_at, last_login_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_last_login(self, user_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), user_id),
            )

    def set_user_active(self, username: str, active: bool) -> bool:
        """Returns whether a matching user was found and updated."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_active = ? WHERE username = ?",
                (int(active), username),
            )
            return cursor.rowcount > 0

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

    # ------------------------------------------------------------------
    # Action1 integration
    # ------------------------------------------------------------------
    def replace_action1_inventory(self, endpoints: list[dict], software: list[dict]) -> None:
        """Full-replace the cached Action1 inventory snapshot with the
        result of a fresh sync. The inventory is small enough (endpoints +
        installed software for one org) that a full replace is simpler and
        cheaper than diffing, and guarantees stale/removed endpoints and
        software don't linger."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("DELETE FROM action1_software")
            conn.execute("DELETE FROM action1_endpoints")
            for ep in endpoints:
                conn.execute(
                    """
                    INSERT INTO action1_endpoints (id, hostname, os, org_id, raw_json, synced_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ep["id"], ep.get("hostname"), ep.get("os"), ep.get("org_id"), ep.get("raw_json"), now),
                )
            for sw in software:
                conn.execute(
                    """
                    INSERT INTO action1_software (endpoint_id, vendor, product, version)
                    VALUES (?, ?, ?, ?)
                    """,
                    (sw["endpoint_id"], sw.get("vendor"), sw.get("product"), sw.get("version")),
                )

    def get_action1_software(self) -> list[dict]:
        """Every cached (endpoint, installed software) row, joined with the
        endpoint's hostname for display/matching."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.endpoint_id, s.vendor, s.product, s.version, e.hostname
                FROM action1_software s
                JOIN action1_endpoints e ON e.id = s.endpoint_id
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def replace_action1_exposures(self, cve_id: str, exposures: list[dict]) -> None:
        """Replace this CVE's exposure rows with a freshly computed set
        (called every time the CVE is re-enriched against the current
        inventory snapshot)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("DELETE FROM action1_exposures WHERE cve_id = ?", (cve_id,))
            for exp in exposures:
                conn.execute(
                    """
                    INSERT INTO action1_exposures
                        (cve_id, endpoint_id, hostname, vendor, product, installed_version,
                         affected_range, fixed_version, version_status, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        exp["endpoint_id"],
                        exp.get("hostname"),
                        exp.get("vendor"),
                        exp.get("product"),
                        exp.get("installed_version"),
                        exp.get("affected_range"),
                        exp.get("fixed_version"),
                        exp.get("version_status"),
                        now,
                    ),
                )

    def get_all_action1_exposures(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM action1_exposures ORDER BY cve_id").fetchall()
        return [dict(r) for r in rows]

    def get_action1_exposures_for_cve(self, cve_id: str) -> list[dict]:
        """Indexed lookup (idx_action1_exposures_cve) for callers that only
        care about one CVE -- avoids scanning the whole exposures table."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM action1_exposures WHERE cve_id = ?", (cve_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_action1_sync_status(self) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS endpoint_count, MAX(synced_at) AS last_synced_at FROM action1_endpoints"
            ).fetchone()
            software_count = conn.execute("SELECT COUNT(*) AS n FROM action1_software").fetchone()["n"]
        return {
            "endpoint_count": row["endpoint_count"],
            "software_count": software_count,
            "last_synced_at": row["last_synced_at"],
        }

    # ------------------------------------------------------------------
    # Request Tracker integration
    # ------------------------------------------------------------------
    def record_rt_ticket(self, cve_id: str, ticket_id: int, source: str) -> None:
        """Records that a ticket now exists for this CVE. Purely a local
        dedup/badge guard -- RT itself stays the source of truth for ticket
        content and status."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO rt_tickets (cve_id, ticket_id, source, created_at) VALUES (?, ?, ?, ?)",
                (cve_id, ticket_id, source, now),
            )

    def has_rt_ticket(self, cve_id: str) -> bool:
        """Whether a ticket has already been recorded for this CVE -- guards
        the pipeline against opening a duplicate ticket every time a still-
        Critical/KEV CVE's cache entry expires and gets re-enriched."""
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM rt_tickets WHERE cve_id = ? LIMIT 1", (cve_id,)).fetchone()
        return row is not None

    def get_rt_ticket_cve_ids(self) -> set[str]:
        """Every CVE ID that already has at least one recorded ticket, for
        bulk 'already ticketed' badges (e.g. Asset Exposure) without a
        per-row query."""
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT cve_id FROM rt_tickets").fetchall()
        return {r["cve_id"] for r in rows}

    # ------------------------------------------------------------------
    # RT ticket drafts (draft -> review -> approve workflow)
    # ------------------------------------------------------------------
    def create_rt_draft(
        self,
        cve_id: str,
        status: str,
        trigger_reason: str | None,
        ticket_origin: str | None,
        severity: str | None,
        cvss_score: float | None,
        epss_score: float | None,
        kev_listed: bool,
        vendor: str | None,
        product: str | None,
        affected_endpoint_count: int | None,
        description: str | None,
        recommendation: str | None,
        source_articles: list[str],
        proposed_queue: str,
        proposed_priority: str | None,
        proposed_owner: str | None,
        proposed_subject: str,
        proposed_body: str,
        rt_ticket_id: int | None = None,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO rt_drafts (
                    cve_id, status, trigger_reason, ticket_origin,
                    severity, cvss_score, epss_score, kev_listed, vendor, product,
                    affected_endpoint_count, description, recommendation, source_articles,
                    proposed_queue, proposed_priority, proposed_owner, proposed_subject, proposed_body,
                    rt_ticket_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id, status, trigger_reason, ticket_origin,
                    severity, cvss_score, epss_score, int(kev_listed), vendor, product,
                    affected_endpoint_count, description, recommendation, json.dumps(source_articles),
                    proposed_queue, proposed_priority, proposed_owner, proposed_subject, proposed_body,
                    rt_ticket_id, now, now,
                ),
            )
            return cursor.lastrowid

    _UPDATABLE_RT_DRAFT_FIELDS = {
        "status", "proposed_queue", "proposed_priority", "proposed_owner",
        "proposed_subject", "proposed_body", "rt_ticket_id", "rejection_reason",
        "failure_reason", "ticket_origin",
    }

    def update_rt_draft(self, draft_id: int, **fields) -> bool:
        """Partial update -- only keys present in `fields` are touched.
        Used both for analyst edits (proposed_*) and status transitions
        (status/rt_ticket_id/rejection_reason/failure_reason)."""
        updates = {k: v for k, v in fields.items() if k in self._UPDATABLE_RT_DRAFT_FIELDS}
        if not updates:
            return False
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{column} = ?" for column in updates)
        params = [*updates.values(), draft_id]
        with self._connect() as conn:
            cursor = conn.execute(f"UPDATE rt_drafts SET {set_clause} WHERE id = ?", params)
            return cursor.rowcount > 0

    @staticmethod
    def _rt_draft_row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["kev_listed"] = bool(d["kev_listed"])
        try:
            d["source_articles"] = json.loads(d["source_articles"]) if d["source_articles"] else []
        except json.JSONDecodeError:
            d["source_articles"] = []
        return d

    def get_rt_draft(self, draft_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM rt_drafts WHERE id = ?", (draft_id,)).fetchone()
        return self._rt_draft_row_to_dict(row) if row is not None else None

    def get_rt_draft_for_cve(self, cve_id: str) -> dict | None:
        """The most recent draft for this CVE, if any."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM rt_drafts WHERE cve_id = ? ORDER BY created_at DESC LIMIT 1", (cve_id,)
            ).fetchone()
        return self._rt_draft_row_to_dict(row) if row is not None else None

    def get_all_rt_drafts(self, status: str | None = None) -> list[dict]:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM rt_drafts WHERE status = ? ORDER BY created_at DESC", (status,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM rt_drafts ORDER BY created_at DESC").fetchall()
        return [self._rt_draft_row_to_dict(r) for r in rows]

    def get_rt_draft_status_map(self) -> dict[str, dict]:
        """cve_id -> {id, status, rt_ticket_id} for the most recent draft of
        each CVE, for bulk badges (Asset Exposure, drafts summary) without a
        per-row query."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT cve_id, id, status, rt_ticket_id FROM rt_drafts ORDER BY created_at DESC"
            ).fetchall()
        status_map: dict[str, dict] = {}
        for row in rows:
            status_map.setdefault(
                row["cve_id"], {"draft_id": row["id"], "status": row["status"], "rt_ticket_id": row["rt_ticket_id"]}
            )
        return status_map

    def get_rt_draft_summary(self) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN status = 'Pending Approval' THEN 1 ELSE 0 END), 0) AS pending,
                    COALESCE(SUM(CASE WHEN status = 'Pending Approval' AND severity = 'Critical' THEN 1 ELSE 0 END), 0) AS critical_pending,
                    COALESCE(SUM(CASE WHEN status = 'Pending Approval' AND kev_listed = 1 THEN 1 ELSE 0 END), 0) AS kev_pending,
                    COALESCE(SUM(CASE WHEN status = 'Created' THEN 1 ELSE 0 END), 0) AS created
                FROM rt_drafts
                """
            ).fetchone()
        return dict(row)

    def record_rt_draft_audit(self, draft_id: int, event: str, actor: str, detail: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO rt_draft_audit (draft_id, event, actor, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (draft_id, event, actor, detail, now),
            )

    def get_rt_draft_audit(self, draft_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rt_draft_audit WHERE draft_id = ? ORDER BY created_at ASC", (draft_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # NVD CVE discovery
    # ------------------------------------------------------------------
    def is_nvd_cve_evaluated(self, cve_id: str) -> bool:
        """Whether NVD discovery has already judged this CVE relevant or
        not -- once evaluated, a CVE is never re-processed by discovery
        again, so an irrelevant one isn't re-enriched on every overlapping
        discovery window."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM nvd_discovery_evaluated WHERE cve_id = ? LIMIT 1", (cve_id,)
            ).fetchone()
        return row is not None

    def record_nvd_cve_evaluated(self, cve_id: str, relevant: bool, reason: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO nvd_discovery_evaluated (cve_id, relevant, reason, evaluated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET relevant=excluded.relevant, reason=excluded.reason,
                    evaluated_at=excluded.evaluated_at
                """,
                (cve_id, int(relevant), reason, now),
            )

    def get_nvd_discovery_state(self) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_success_window_end FROM nvd_discovery_state WHERE id = 1"
            ).fetchone()
        return dict(row) if row is not None else None

    def set_nvd_discovery_state(self, window_end: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO nvd_discovery_state (id, last_success_window_end) VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET last_success_window_end=excluded.last_success_window_end
                """,
                (window_end,),
            )
