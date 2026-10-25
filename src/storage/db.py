"""SQLite database management with WAL mode, indexing, and parameterized queries."""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from ..config import AppConfig
from ..models import DnsRecords, EnrichedDetection, UrlscanResult

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite manager in WAL mode for persistent detection logging."""

    def __init__(self, db_path: Optional[Path | str] = None, config: Optional[AppConfig] = None):
        if db_path:
            self.db_path = Path(db_path)
        elif config:
            self.db_path = config.database_path
        else:
            self.db_path = AppConfig().database_path

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a contextual connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables and performance indexes."""
        with self.get_connection() as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        registered_domain TEXT,
                        suffix TEXT,
                        risk_score INTEGER NOT NULL,
                        matched_brands TEXT NOT NULL,
                        matched_keywords TEXT NOT NULL,
                        homoglyphs TEXT,
                        reasons TEXT,
                        dns_records TEXT,
                        urlscan_result TEXT,
                        first_seen TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'FLAGGED'
                    );
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detections_domain ON detections(domain);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detections_risk_score ON detections(risk_score);"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_detections_first_seen ON detections(first_seen);"
                )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alert_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        detection_id INTEGER NOT NULL,
                        channel TEXT NOT NULL,
                        status TEXT NOT NULL,
                        sent_at TEXT NOT NULL,
                        details TEXT,
                        FOREIGN KEY(detection_id) REFERENCES detections(id)
                    );
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_alert_logs_detection_id ON alert_logs(detection_id);"
                )

    def save_detection(self, d: EnrichedDetection) -> int:
        """
        Insert or update a detection record using parameterized SQL.

        Returns:
            The primary key ID of the inserted detection.
        """
        dns_json = json.dumps(d.dns_records.model_dump(mode="json")) if d.dns_records else None
        urlscan_json = json.dumps(d.urlscan.model_dump(mode="json")) if d.urlscan else None
        homoglyphs_json = json.dumps(d.homoglyphs)
        reasons_json = json.dumps(d.reasons)
        brands_json = json.dumps(d.matched_brands)
        keywords_json = json.dumps(d.matched_keywords)
        first_seen_str = d.first_seen.isoformat()

        sql = """
        INSERT INTO detections (
            domain, registered_domain, suffix, risk_score,
            matched_brands, matched_keywords, homoglyphs, reasons,
            dns_records, urlscan_result, first_seen, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            risk_score = excluded.risk_score,
            dns_records = COALESCE(excluded.dns_records, detections.dns_records),
            urlscan_result = COALESCE(excluded.urlscan_result, detections.urlscan_result),
            status = excluded.status;
        """

        with self.get_connection() as conn:
            with conn:
                cursor = conn.execute(
                    sql,
                    (
                        d.domain,
                        d.registered_domain,
                        d.suffix,
                        d.risk_score,
                        brands_json,
                        keywords_json,
                        homoglyphs_json,
                        reasons_json,
                        dns_json,
                        urlscan_json,
                        first_seen_str,
                        d.status,
                    ),
                )
                if cursor.lastrowid:
                    return cursor.lastrowid
                # In case of update on conflict, fetch existing id
                row = conn.execute(
                    "SELECT id FROM detections WHERE domain = ?", (d.domain,)
                ).fetchone()
                return row["id"] if row else 0

    def get_detection_by_domain(self, domain: str) -> Optional[EnrichedDetection]:
        """Retrieve a detection by exact domain name."""
        sql = "SELECT * FROM detections WHERE domain = ?"
        with self.get_connection() as conn:
            row = conn.execute(sql, (domain,)).fetchone()
            if not row:
                return None
            return self._row_to_model(row)

    def get_recent_detections(self, limit: int = 50, min_score: int = 0) -> List[EnrichedDetection]:
        """Fetch latest detections ordered by first_seen descending."""
        sql = """
        SELECT * FROM detections
        WHERE risk_score >= ?
        ORDER BY first_seen DESC
        LIMIT ?
        """
        with self.get_connection() as conn:
            rows = conn.execute(sql, (min_score, limit)).fetchall()
            return [self._row_to_model(r) for r in rows]

    def get_detections_by_timerange(
        self, start_time: datetime, end_time: datetime
    ) -> List[EnrichedDetection]:
        """Retrieve all detections within an ISO-formatted time range."""
        sql = """
        SELECT * FROM detections
        WHERE first_seen >= ? AND first_seen <= ?
        ORDER BY first_seen ASC
        """
        with self.get_connection() as conn:
            rows = conn.execute(sql, (start_time.isoformat(), end_time.isoformat())).fetchall()
            return [self._row_to_model(r) for r in rows]

    def log_alert(self, detection_id: int, channel: str, status: str, details: str = "") -> None:
        """Record an alert dispatch log entry."""
        sql = """
        INSERT INTO alert_logs (detection_id, channel, status, sent_at, details)
        VALUES (?, ?, ?, ?, ?)
        """
        now_str = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            with conn:
                conn.execute(sql, (detection_id, channel, status, now_str, details))

    def _row_to_model(self, row: sqlite3.Row) -> EnrichedDetection:
        """Convert a database row into an EnrichedDetection model."""
        dns_records = None
        if row["dns_records"]:
            try:
                dns_records = DnsRecords(**json.loads(row["dns_records"]))
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("Failed to deserialize dns_records for row %s: %s", row["id"], e)

        urlscan = None
        if row["urlscan_result"]:
            try:
                urlscan = UrlscanResult(**json.loads(row["urlscan_result"]))
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                logger.debug("Failed to deserialize urlscan_result for row %s: %s", row["id"], e)

        first_seen = datetime.fromisoformat(row["first_seen"])

        return EnrichedDetection(
            id=row["id"],
            domain=row["domain"],
            registered_domain=row["registered_domain"] or "",
            suffix=row["suffix"] or "",
            risk_score=row["risk_score"],
            matched_brands=json.loads(row["matched_brands"]),
            matched_keywords=json.loads(row["matched_keywords"]),
            homoglyphs=json.loads(row["homoglyphs"]) if row["homoglyphs"] else [],
            reasons=json.loads(row["reasons"]) if row["reasons"] else [],
            dns_records=dns_records,
            urlscan=urlscan,
            first_seen=first_seen,
            status=row["status"],
        )
