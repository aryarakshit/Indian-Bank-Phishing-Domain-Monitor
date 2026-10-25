"""Tests for forensic enrichment (DNS and urlscan.io)."""

import pytest

from src.config import AppConfig
from src.enrichment import DnsResolver, EnrichmentPipeline, UrlscanClient
from src.models import TriageResult


@pytest.mark.asyncio
async def test_dns_resolver_nonexistent_domain():
    config = AppConfig(dns_timeout_seconds=2.0)
    resolver = DnsResolver(config)
    # Query a domain guaranteed to not exist
    records = await resolver.resolve("this-domain-definitely-does-not-exist-123456789.xyz")
    assert records.a == []
    assert records.ns == []
    assert records.error is None


@pytest.mark.asyncio
async def test_urlscan_client_disabled():
    config = AppConfig(enable_urlscan=False, urlscan_api_key="")
    client = UrlscanClient(config)
    result = await client.submit("example.com")
    assert result.submitted is False
    assert "disabled" in result.error.lower()


@pytest.mark.asyncio
async def test_enrichment_pipeline():
    config = AppConfig(enable_urlscan=False)
    pipeline = EnrichmentPipeline(config=config)

    triage = TriageResult(
        domain="sbi-fake-kyc.xyz",
        registered_domain="sbi-fake-kyc.xyz",
        suffix="xyz",
        is_whitelisted=False,
        matched_brands=["SBI"],
        matched_keywords=["kyc"],
        risk_score=85,
        threshold_met=True,
        reasons=["Test reasons"],
    )

    enriched = await pipeline.enrich(triage)
    assert enriched.domain == "sbi-fake-kyc.xyz"
    assert enriched.risk_score == 85
    assert enriched.matched_brands == ["SBI"]
    assert enriched.dns_records is not None
