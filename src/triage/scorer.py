"""Risk scoring engine computing transparent heuristic confidence scores (0-100)."""

from typing import List, Optional

import tldextract

from ..config import SUSPICIOUS_TLDS, AppConfig
from ..models import DomainCandidate, HomoglyphMatch, TriageResult
from .brands import BrandMatcher
from .homoglyphs import HomoglyphDetector
from .keywords import KeywordMatcher
from .whitelist import WhitelistChecker


class RiskScorer:
    """Calculates risk score (0-100) and filters against threshold."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        whitelist_checker: Optional[WhitelistChecker] = None,
        brand_matcher: Optional[BrandMatcher] = None,
        keyword_matcher: Optional[KeywordMatcher] = None,
        homoglyph_detector: Optional[HomoglyphDetector] = None,
    ):
        self.config = config or AppConfig()
        self.whitelist = whitelist_checker or WhitelistChecker()
        self.brands = brand_matcher or BrandMatcher()
        self.keywords = keyword_matcher or KeywordMatcher()
        self.homoglyphs = homoglyph_detector or HomoglyphDetector()
        self._tld_extractor = tldextract.TLDExtract()

    def extract_candidate(self, raw_domain: str) -> DomainCandidate:
        """Sanitize raw domain string and extract TLD components."""
        cleaned = raw_domain.lower().strip().lstrip("*.").rstrip(".")
        ext = self._tld_extractor(cleaned)
        # Use top_domain_under_public_suffix to avoid deprecation warning in tldextract >= 5
        registered_domain = (
            getattr(ext, "top_domain_under_public_suffix", "") or ext.registered_domain or cleaned
        )
        suffix = ext.suffix or ""
        subdomain = ext.subdomain or ""

        return DomainCandidate(
            raw_domain=raw_domain,
            cleaned_domain=cleaned,
            subdomain=subdomain,
            registered_domain=registered_domain,
            suffix=suffix,
        )

    def evaluate(self, candidate_or_domain: str | DomainCandidate) -> TriageResult:
        """
        Execute comprehensive heuristic analysis and calculate risk score.
        """
        if isinstance(candidate_or_domain, str):
            candidate = self.extract_candidate(candidate_or_domain)
        else:
            candidate = candidate_or_domain

        domain = candidate.cleaned_domain
        reg_domain = candidate.registered_domain
        suffix = candidate.suffix

        # Step 1: Whitelist Check
        if self.whitelist.is_whitelisted(domain, reg_domain):
            return TriageResult(
                domain=domain,
                registered_domain=reg_domain,
                suffix=suffix,
                is_whitelisted=True,
                risk_score=0,
                threshold_met=False,
                reasons=["Domain or parent domain is verified legitimate in official whitelist."],
            )

        score = 0
        reasons: List[str] = []
        all_homoglyphs: List[HomoglyphMatch] = []

        # Step 2: Homoglyph & Punycode analysis
        homoglyph_matches, normalized_domain = self.homoglyphs.detect_homoglyphs(domain)
        if homoglyph_matches:
            all_homoglyphs.extend(homoglyph_matches)
            score += 30
            reasons.append(
                f"Homoglyph/Cyrillic characters detected: {len(homoglyph_matches)} char(s)"
            )

        if "xn--" in domain:
            score += 20
            reasons.append("IDN Punycode domain (xn--)")

        leet_typo_matches = self.homoglyphs.detect_leetspeak_and_typos(domain)
        if leet_typo_matches:
            all_homoglyphs.extend(leet_typo_matches)
            for m in leet_typo_matches:
                score += 25
                reasons.append(
                    f"Detected {m.variation_type} variation targeting '{m.brand_imitated}'"
                )

        # Step 3: Brand Matching (on both original and homoglyph-normalized domain)
        matched_brands = self.brands.match_brands(domain, reg_domain)
        if not matched_brands and normalized_domain != domain:
            matched_brands = self.brands.match_brands(normalized_domain)
            if matched_brands:
                score += 35
                reasons.append(f"Homoglyph-obfuscated brand match: {', '.join(matched_brands)}")

        if matched_brands:
            brand_str = ", ".join(matched_brands)
            # Check if brand is in apex domain vs subdomain
            domain_body = reg_domain.split(".")[0] if reg_domain else domain
            if any(b.lower() in domain_body for b in matched_brands):
                score += 45
                reasons.append(f"Target financial brand in apex domain: {brand_str}")
            else:
                score += 35
                reasons.append(f"Target financial brand in subdomain: {brand_str}")

        # Step 4: High-Risk Keyword Scanning
        matched_kws, tier_map = self.keywords.find_keywords(domain)
        # Check normalized domain as well
        if normalized_domain != domain:
            norm_kws, norm_tiers = self.keywords.find_keywords(normalized_domain)
            for k, t in norm_tiers.items():
                if k not in tier_map:
                    matched_kws.append(k)
                    tier_map[k] = t

        for kw, tier in tier_map.items():
            if tier == 1:
                score += 18
                reasons.append(f"Tier-1 urgent threat keyword: '{kw}' (+18)")
            elif tier == 2:
                score += 12
                reasons.append(f"Tier-2 banking/security keyword: '{kw}' (+12)")
            else:
                score += 6
                reasons.append(f"Tier-3 account keyword: '{kw}' (+6)")

        # Synergy bonus: Brand + Keywords combination
        if matched_brands and matched_kws:
            score += 15
            reasons.append("Synergy bonus: Target Brand + High-Risk Keyword combination (+15)")

        # Step 5: TLD Reputation Check
        if suffix in SUSPICIOUS_TLDS:
            score += 15
            reasons.append(f"High-abuse phishing TLD: '.{suffix}' (+15)")

        # Step 6: Structural Anomalies
        # Excessive hyphens (>= 2)
        hyphen_count = domain.count("-")
        if hyphen_count >= 2:
            score += 10
            reasons.append(f"Structural anomaly: excessive hyphens ({hyphen_count}) (+10)")

        # Deep subdomain nesting
        subdomain_parts = [p for p in candidate.subdomain.split(".") if p]
        if len(subdomain_parts) >= 2:
            score += 10
            reasons.append("Structural anomaly: deep subdomain chaining (+10)")

        # Normalize score between 0 and 100
        final_score = min(100, max(0, score))
        threshold_met = final_score >= self.config.risk_threshold

        return TriageResult(
            domain=domain,
            registered_domain=reg_domain,
            suffix=suffix,
            is_whitelisted=False,
            matched_brands=matched_brands,
            matched_keywords=matched_kws,
            homoglyphs=all_homoglyphs,
            risk_score=final_score,
            threshold_met=threshold_met,
            reasons=reasons,
        )
