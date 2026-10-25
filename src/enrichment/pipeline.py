"""Async pipeline coordinating forensic enrichment for suspect detections."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from ..config import AppConfig
from ..models import EnrichedDetection, TriageResult
from .dns_resolver import DnsResolver
from .urlscan_client import UrlscanClient

logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """Orchestrates parallel enrichment (DNS queries + sandbox scans)."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        dns_resolver: Optional[DnsResolver] = None,
        urlscan_client: Optional[UrlscanClient] = None,
    ):
        self.config = config or AppConfig()
        self.dns_resolver = dns_resolver or DnsResolver(self.config)
        self.urlscan_client = urlscan_client or UrlscanClient(self.config)

    async def enrich(self, triage: TriageResult) -> EnrichedDetection:
        """
        Enrich a triage result with passive DNS telemetry and sandbox submission.
        """
        domain = triage.domain

        # Run DNS and urlscan concurrently
        dns_task = self.dns_resolver.resolve(domain)
        urlscan_task = self.urlscan_client.submit(domain)

        dns_result, urlscan_result = await asyncio.gather(
            dns_task, urlscan_task, return_exceptions=True
        )

        dns_records = dns_result if not isinstance(dns_result, Exception) else None
        urlscan = urlscan_result if not isinstance(urlscan_result, Exception) else None

        homoglyph_dicts = [
            {
                "original_char": h.original_char,
                "target_char": h.target_char,
                "brand_imitated": h.brand_imitated,
                "variation_type": h.variation_type,
            }
            for h in triage.homoglyphs
        ]

        return EnrichedDetection(
            domain=triage.domain,
            registered_domain=triage.registered_domain,
            suffix=triage.suffix,
            risk_score=triage.risk_score,
            matched_brands=triage.matched_brands,
            matched_keywords=triage.matched_keywords,
            homoglyphs=homoglyph_dicts,
            reasons=triage.reasons,
            dns_records=dns_records,
            urlscan=urlscan,
            first_seen=datetime.now(timezone.utc),
            status="FLAGGED",
        )
