"""Tests for SQLite persistence and WAL mode."""

from datetime import datetime, timezone

import pytest

from src.models import DnsRecords, EnrichedDetection, UrlscanResult
from src.storage import DatabaseManager


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_detections.db"
    return DatabaseManager(db_path=db_file)


def test_db_wal_mode(temp_db):
    with temp_db.get_connection() as conn:
        cursor = conn.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert mode.lower() == "wal"


def test_save_and_retrieve_detection(temp_db):
    detection = EnrichedDetection(
        domain="sbi-update-kyc.top",
        registered_domain="sbi-update-kyc.top",
        suffix="top",
        risk_score=95,
        matched_brands=["SBI"],
        matched_keywords=["kyc", "update"],
        homoglyphs=[],
        reasons=["High risk keywords", "Target brand"],
        dns_records=DnsRecords(a=["192.0.2.1"], ns=["ns1.badhost.xyz"]),
        urlscan=UrlscanResult(submitted=True, scan_id="abc-123"),
        first_seen=datetime.now(timezone.utc),
        status="FLAGGED",
    )

    det_id = temp_db.save_detection(detection)
    assert det_id > 0

    fetched = temp_db.get_detection_by_domain("sbi-update-kyc.top")
    assert fetched is not None
    assert fetched.domain == "sbi-update-kyc.top"
    assert fetched.risk_score == 95
    assert fetched.matched_brands == ["SBI"]
    assert fetched.dns_records.a == ["192.0.2.1"]
    assert fetched.urlscan.scan_id == "abc-123"


def test_get_recent_detections(temp_db):
    d1 = EnrichedDetection(
        domain="fake-pnb.xyz",
        registered_domain="fake-pnb.xyz",
        suffix="xyz",
        risk_score=70,
        matched_brands=["PNB"],
        matched_keywords=["login"],
    )
    d2 = EnrichedDetection(
        domain="fake-hdfc.xyz",
        registered_domain="fake-hdfc.xyz",
        suffix="xyz",
        risk_score=85,
        matched_brands=["HDFC"],
        matched_keywords=["kyc"],
    )

    temp_db.save_detection(d1)
    temp_db.save_detection(d2)

    recent = temp_db.get_recent_detections(limit=10, min_score=60)
    assert len(recent) == 2

    high_only = temp_db.get_recent_detections(limit=10, min_score=80)
    assert len(high_only) == 1
    assert high_only[0].domain == "fake-hdfc.xyz"
