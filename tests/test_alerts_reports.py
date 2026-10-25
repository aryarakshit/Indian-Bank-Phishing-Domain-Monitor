"""Tests for alert dispatching and daily reporting."""

from datetime import datetime, timezone

import pytest

from src.alerts import AlertDispatcher
from src.config import AppConfig
from src.models import DnsRecords, EnrichedDetection
from src.reports import DailyReportGenerator
from src.storage import DatabaseManager


@pytest.mark.asyncio
async def test_alert_dispatcher_simulation():
    config = AppConfig(enable_alerts=True, telegram_bot_token="", discord_webhook_url="")
    dispatcher = AlertDispatcher(config)

    detection = EnrichedDetection(
        domain="sbi-fake-portal.xyz",
        registered_domain="sbi-fake-portal.xyz",
        suffix="xyz",
        risk_score=90,
        matched_brands=["SBI"],
        matched_keywords=["portal", "login"],
        reasons=["Test reasons"],
        dns_records=DnsRecords(a=["1.2.3.4"]),
    )

    # Should not raise exception
    await dispatcher.dispatch(detection)


def test_daily_report_generator(tmp_path):
    db_file = tmp_path / "test_report.db"
    db = DatabaseManager(db_path=db_file)
    reports_dir = tmp_path / "reports"
    config = AppConfig(reports_dir=reports_dir)

    now = datetime.now(timezone.utc)
    d = EnrichedDetection(
        domain="fake-axis-kyc.top",
        registered_domain="fake-axis-kyc.top",
        suffix="top",
        risk_score=95,
        matched_brands=["AXIS"],
        matched_keywords=["kyc"],
        first_seen=now,
        dns_records=DnsRecords(a=["198.51.100.1"]),
    )
    db.save_detection(d)

    generator = DailyReportGenerator(db_manager=db, config=config)
    report_file = generator.generate_report(target_date=now)

    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "fake-axis-kyc.top" in content
    assert "AXIS" in content
    assert "95" in content
    assert "**Total High-Risk Detections:** 1" in content
