"""Data models representing domains, triage results, and forensic detections."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DomainCandidate(BaseModel):
    """Normalized domain candidate extracted from certificate log."""

    raw_domain: str
    cleaned_domain: str
    subdomain: str = ""
    registered_domain: str = ""  # e.g., onlinesbi-kyc.top
    suffix: str = ""  # e.g., top, co.in


class HomoglyphMatch(BaseModel):
    """Details of detected homoglyph or lookalike character substitution."""

    original_char: str
    target_char: str
    brand_imitated: str
    variation_type: str  # 'cyrillic', 'leetspeak', 'punycode', 'typo'


class TriageResult(BaseModel):
    """Result of running triage heuristics against a domain candidate."""

    domain: str
    registered_domain: str
    suffix: str
    is_whitelisted: bool = False
    matched_brands: List[str] = Field(default_factory=list)
    matched_keywords: List[str] = Field(default_factory=list)
    homoglyphs: List[HomoglyphMatch] = Field(default_factory=list)
    risk_score: int = 0
    threshold_met: bool = False
    reasons: List[str] = Field(default_factory=list)


class DnsRecords(BaseModel):
    """Resolved DNS telemetry."""

    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    resolved_at: Optional[datetime] = None
    error: Optional[str] = None


class UrlscanResult(BaseModel):
    """Results from headless urlscan.io sandbox submission."""

    submitted: bool = False
    scan_id: Optional[str] = None
    result_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    page_title: Optional[str] = None
    page_status: Optional[int] = None
    error: Optional[str] = None


class EnrichedDetection(BaseModel):
    """Full forensic detection entity for persistence and alerts."""

    id: Optional[int] = None
    domain: str
    registered_domain: str
    suffix: str
    risk_score: int
    matched_brands: List[str]
    matched_keywords: List[str]
    homoglyphs: List[Dict[str, Any]] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    dns_records: Optional[DnsRecords] = None
    urlscan: Optional[UrlscanResult] = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "FLAGGED"  # FLAGGED, ALERTED, ERROR
