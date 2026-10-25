"""Tests for triage, heuristics, whitelist, and homoglyph detection."""

import pytest

from src.config import AppConfig
from src.triage import (
    HomoglyphDetector,
    RiskScorer,
)


@pytest.fixture
def scorer():
    config = AppConfig(risk_threshold=60)
    return RiskScorer(config=config)


def test_whitelist_official_domains(scorer):
    legitimate_domains = [
        "onlinesbi.sbi",
        "retail.onlinesbi.sbi",
        "sbi.co.in",
        "hdfcbank.com",
        "netbanking.hdfcbank.com",
        "icicibank.com",
        "paytm.com",
        "bhimupi.org.in",
        "rbi.org.in",
        "incometax.gov.in",
    ]
    for domain in legitimate_domains:
        result = scorer.evaluate(domain)
        assert result.is_whitelisted is True, f"Failed for {domain}"
        assert result.risk_score == 0
        assert result.threshold_met is False


def test_obvious_phishing_domains(scorer):
    phishing_cases = [
        ("sbi-kyc-update-pan.top", "SBI", ["kyc", "pan", "update"]),
        ("hdfc-netbanking-login.xyz", "HDFC", ["netbanking", "login"]),
        ("icici-apk-download.live", "ICICI", ["apk", "download"]),
        ("paytm-reward-refund-claim.club", "PAYTM", ["refund", "reward", "claim"]),
        ("yono-sbi-portal-security.shop", "SBI", ["portal", "security"]),
    ]
    for domain, expected_brand, expected_keywords in phishing_cases:
        result = scorer.evaluate(domain)
        assert result.is_whitelisted is False
        assert expected_brand in result.matched_brands, (
            f"Missing brand in {domain}: {result.matched_brands}"
        )
        for kw in expected_keywords:
            assert kw in result.matched_keywords, (
                f"Missing kw '{kw}' in {domain}: {result.matched_keywords}"
            )
        assert result.risk_score >= 60, f"Expected >= 60, got {result.risk_score} for {domain}"
        assert result.threshold_met is True


def test_homoglyphs_and_punycode(scorer):
    # Cyrillic 'і' (U+0456) in 'sbі-kyc.xyz'
    cyrillic_domain = "sb\u0456-kyc.xyz"
    result = scorer.evaluate(cyrillic_domain)
    assert len(result.homoglyphs) > 0
    assert result.risk_score >= 60
    assert result.threshold_met is True

    # Punycode representation of homoglyph domain
    puny_domain = "xn--sb-lza.xyz"
    detector = HomoglyphDetector()
    decoded, is_puny = detector.decode_punycode(puny_domain)
    assert is_puny is True


def test_leetspeak_detection():
    detector = HomoglyphDetector()
    matches = detector.detect_leetspeak_and_typos("p4ytm-login.com")
    assert any(m.brand_imitated == "PAYTM" for m in matches)


def test_benign_domains_not_flagged(scorer):
    benign_domains = [
        "python.org",
        "github.com",
        "google.com",
        "wikipedia.org",
        "news-daily-updates.com",
        "tech-gadgets-review.net",
    ]
    for domain in benign_domains:
        result = scorer.evaluate(domain)
        assert result.risk_score < 60, f"False positive for {domain}: {result.risk_score}"
        assert result.threshold_met is False


def test_ambiguous_aliases_inside_ordinary_words_are_not_brand_matches(scorer):
    for domain in [
        "axistools-login.com",
        "praxis-login.com",
        "login.upicorn.io",
        "stupidupi-memes.com",
    ]:
        result = scorer.evaluate(domain)
        assert result.matched_brands == [], f"{domain} matched {result.matched_brands}"
        assert result.threshold_met is False, f"False positive for {domain}: {result.risk_score}"


def test_ambiguous_aliases_still_match_as_their_own_token(scorer):
    for domain, brand in [("axis-kyc-update.top", "AXIS"), ("upi-refund-claim.xyz", "UPI_NPCI")]:
        result = scorer.evaluate(domain)
        assert brand in result.matched_brands, f"{domain} matched {result.matched_brands}"
        assert result.threshold_met is True


def test_ambiguous_alias_inside_a_word_matches_when_banking_context_is_present(scorer):
    result = scorer.evaluate("axiscard-kyc.top")

    assert "AXIS" in result.matched_brands
    assert result.threshold_met is True


def test_axis_communications_login_subdomain_is_not_flagged(scorer):
    result = scorer.evaluate("login.axis.com")

    assert result.is_whitelisted is True
    assert result.threshold_met is False
