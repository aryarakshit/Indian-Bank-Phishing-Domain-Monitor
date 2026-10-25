"""Passive DNS resolution engine querying A, AAAA, NS, and MX records."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.resolver

from ..config import AppConfig
from ..models import DnsRecords

logger = logging.getLogger(__name__)


class DnsResolver:
    """Performs passive DNS lookups for suspect phishing domains."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.timeout = self.config.dns_timeout_seconds

    def _sync_query(self, domain: str) -> DnsRecords:
        """Synchronously query DNS records with custom timeout."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        records = DnsRecords(resolved_at=datetime.now(timezone.utc))

        # Query A records
        try:
            answers = resolver.resolve(domain, "A")
            records.a = [str(r.address) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("DNS A query error for %s: %s", domain, exc)

        # Query AAAA records
        try:
            answers = resolver.resolve(domain, "AAAA")
            records.aaaa = [str(r.address) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("DNS AAAA query error for %s: %s", domain, exc)

        # Query NS records
        try:
            answers = resolver.resolve(domain, "NS")
            records.ns = [str(r.target).rstrip(".") for r in answers]
            records.nameservers = list(records.ns)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("DNS NS query error for %s: %s", domain, exc)

        # Query MX records
        try:
            answers = resolver.resolve(domain, "MX")
            records.mx = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as exc:
            logger.debug("DNS MX query error for %s: %s", domain, exc)

        return records

    async def resolve(self, domain: str) -> DnsRecords:
        """
        Asynchronously resolve DNS records in a worker thread.
        """
        if not self.config.enable_dns_enrichment:
            return DnsRecords(error="DNS enrichment disabled by configuration.")

        try:
            return await asyncio.to_thread(self._sync_query, domain)
        except Exception as exc:
            logger.warning("Failed resolving DNS for %s: %s", domain, exc)
            return DnsRecords(error=str(exc))
