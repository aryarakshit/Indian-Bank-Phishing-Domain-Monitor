"""Tests for Threat Intelligence and Visual Analytics Dashboard."""

from datetime import datetime, timezone

import pytest
from aiohttp.test_utils import TestClient, TestServer

from src.dashboard.app import create_dashboard_app, generate_takedown_notice
from src.models import DnsRecords, EnrichedDetection
from src.storage import DatabaseManager


@pytest.mark.asyncio
async def test_dashboard_index(tmp_path):
    """Test dashboard index HTML response."""
    db = DatabaseManager(db_path=tmp_path / "test.db")
    app = create_dashboard_app(db_manager=db)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        resp = await client.get("/")
        assert resp.status == 200
        text = await resp.text()
        assert "Indian Bank Phishing Domain Monitor" in text
        assert "LIVE CT INTERCEPTOR" in text
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_dashboard_stats_and_detections(tmp_path):
    """Test /api/stats, /api/detections, and /api/takedown endpoints."""
    db = DatabaseManager(db_path=tmp_path / "test.db")

    det = EnrichedDetection(
        domain="sbi-test-phish.xyz",
        registered_domain="sbi-test-phish.xyz",
        suffix="xyz",
        is_whitelisted=False,
        matched_brands=["SBI"],
        matched_keywords=["kyc", "login"],
        risk_score=95,
        threshold_met=True,
        reasons=["Test reasons"],
        first_seen=datetime.now(timezone.utc),
        status="FLAGGED",
        dns_records=DnsRecords(a=["1.2.3.4"], ns=["ns1.host.com"]),
    )
    db.save_detection(det)

    app = create_dashboard_app(db_manager=db)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        # 1. Stats endpoint
        resp = await client.get("/api/stats")
        assert resp.status == 200
        stats = await resp.json()
        assert stats["total_detections"] == 1
        assert stats["critical_count"] == 1
        assert stats["brand_counts"]["SBI"] == 1
        assert stats["keyword_counts"]["kyc"] == 1

        # 2. Detections list endpoint
        resp_det = await client.get("/api/detections")
        assert resp_det.status == 200
        items = await resp_det.json()
        assert len(items) == 1
        assert items[0]["domain"] == "sbi-test-phish.xyz"
        assert items[0]["risk_score"] == 95

        # 3. Takedown packet generation endpoint
        resp_take = await client.get("/api/takedown/sbi-test-phish.xyz")
        assert resp_take.status == 200
        take_data = await resp_take.json()
        assert "CERT-In" in take_data["takedown_notice"]
        assert "sbi-test-phish.xyz" in take_data["takedown_notice"]

        # 4. Takedown not found
        resp_404 = await client.get("/api/takedown/nonexistent.com")
        assert resp_404.status == 404
    finally:
        await client.close()


def test_generate_takedown_notice_content():
    """Verify takedown notice formatting and incident reporting details."""
    notice = generate_takedown_notice(
        {
            "domain": "fake-hdfc-otp.top",
            "matched_brands": ["HDFC"],
            "risk_score": 100,
            "reasons": ["Urgent OTP threat keyword"],
            "dns_records": {"a": ["9.9.9.9"], "ns": ["ns.phish.com"]},
        }
    )
    assert "fake-hdfc-otp.top" in notice
    assert "HDFC" in notice
    assert "incident@cert-in.org.in" in notice
    assert "100 / 100" in notice
    assert "9.9.9.9" in notice
