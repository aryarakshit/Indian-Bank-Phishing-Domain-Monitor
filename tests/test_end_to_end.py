"""End-to-end integration test for the entire monitor pipeline."""

import pytest

from src.config import AppConfig
from src.main import PhishingMonitor


@pytest.mark.asyncio
async def test_end_to_end_pipeline(tmp_path):
    db_file = tmp_path / "e2e_detections.db"
    reports_dir = tmp_path / "e2e_reports"

    config = AppConfig(
        database_path=db_file,
        reports_dir=reports_dir,
        risk_threshold=60,
        enable_dns_enrichment=False,  # Keep e2e fast and offline-resilient
        enable_urlscan=False,
        enable_alerts=False,
    )

    monitor = PhishingMonitor(config=config)

    # 1. Whitelisted domain
    res_whitelisted = await monitor.process_domain("onlinesbi.sbi")
    assert res_whitelisted is None

    # 2. Benign non-banking domain
    res_benign = await monitor.process_domain("news-technology-daily.org")
    assert res_benign is None

    # 3. Malicious phishing domain
    res_phishing = await monitor.process_domain("sbi-kyc-pan-verification.xyz")
    assert res_phishing is not None
    assert res_phishing.risk_score >= 60
    assert "SBI" in res_phishing.matched_brands
    assert "kyc" in res_phishing.matched_keywords

    # 4. Another phishing domain targeting HDFC
    res_hdfc = await monitor.process_domain("hdfc-netbanking-login-auth.top")
    assert res_hdfc is not None
    assert "HDFC" in res_hdfc.matched_brands

    # 5. Check Persistence in SQLite
    recent = monitor.db.get_recent_detections(limit=10, min_score=60)
    assert len(recent) == 2
    domains = {r.domain for r in recent}
    assert "sbi-kyc-pan-verification.xyz" in domains
    assert "hdfc-netbanking-login-auth.top" in domains

    # 6. Check Daily Report generation
    report_path = monitor.reports.generate_report(target_date=res_phishing.first_seen)
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "sbi-kyc-pan-verification.xyz" in report_text
    assert "hdfc-netbanking-login-auth.top" in report_text
    assert "**Total High-Risk Detections:** 2" in report_text
