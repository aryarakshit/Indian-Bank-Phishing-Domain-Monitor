"""Configuration settings, dictionaries, and brand profiles."""

import os
from pathlib import Path
from typing import Dict, List, Set

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load optional .env file
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


def _split_csv(raw: str) -> List[str]:
    """Split a comma-separated setting into trimmed, non-empty items."""
    return [item.strip() for item in raw.split(",") if item.strip()]


class AppConfig(BaseModel):
    """Application-wide runtime settings."""

    certstream_url: str = Field(default=os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io"))
    # Extra feeds tried in order when the primary one fails or goes silent, e.g. a
    # self-hosted certstream-server-go instance at ws://localhost:8080/
    certstream_fallback_urls: List[str] = Field(
        default_factory=lambda: _split_csv(os.getenv("CERTSTREAM_FALLBACK_URLS", ""))
    )
    # Public CT logs issue many certificates per second, so this long without a single
    # certificate means the feed has stalled even if the socket is still open.
    certstream_idle_timeout_seconds: float = Field(
        default=float(os.getenv("CERTSTREAM_IDLE_TIMEOUT_SECONDS", "60"))
    )
    risk_threshold: int = Field(default=int(os.getenv("RISK_THRESHOLD", "60")))
    database_path: Path = Field(
        default=Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "detections.db")))
    )
    reports_dir: Path = Field(default=Path(os.getenv("REPORTS_DIR", str(BASE_DIR / "reports"))))

    # Enrichment
    enable_dns_enrichment: bool = Field(
        default=os.getenv("ENABLE_DNS_ENRICHMENT", "true").lower() == "true"
    )
    dns_timeout_seconds: float = Field(default=float(os.getenv("DNS_TIMEOUT_SECONDS", "3.0")))
    urlscan_api_key: str = Field(default=os.getenv("URLSCAN_API_KEY", ""))
    enable_urlscan: bool = Field(default=os.getenv("ENABLE_URLSCAN", "false").lower() == "true")

    # Alerts
    telegram_bot_token: str = Field(default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = Field(default=os.getenv("TELEGRAM_CHAT_ID", ""))
    discord_webhook_url: str = Field(default=os.getenv("DISCORD_WEBHOOK_URL", ""))
    enable_alerts: bool = Field(default=os.getenv("ENABLE_ALERTS", "true").lower() == "true")


# --------------------------------------------------------------------------
# Whitelisted Legitimate Domains
# --------------------------------------------------------------------------
DEFAULT_WHITELIST: Set[str] = {
    # State Bank of India
    "sbi.co.in",
    "onlinesbi.sbi",
    "onlinesbi.com",
    "statebankofindia.com",
    "sbi.bank",
    "sbicard.com",
    "sbimf.com",
    "sbilife.co.in",
    "sbicaps.com",
    # HDFC Bank
    "hdfcbank.com",
    "hdfc.com",
    "hdfcbank.net",
    "hdfcfund.com",
    "hdfclife.com",
    "hdfcergo.com",
    # ICICI Bank
    "icicibank.com",
    "icicibank.co.in",
    "icicidirect.com",
    "icicilombard.com",
    "iciciprulife.com",
    "icicipruamc.com",
    # Axis Bank
    "axisbank.com",
    "axisbank.co.in",
    "axisdirect.in",
    "axismf.com",
    # Punjab National Bank
    "pnbindia.in",
    "pnb.bank",
    "netpnb.com",
    # Bank of Baroda
    "bankofbaroda.in",
    "bankofbaroda.com",
    "bobcards.in",
    "bobfinancial.com",
    # Canara Bank
    "canarabank.com",
    "canarabank.in",
    # Kotak Mahindra Bank
    "kotak.com",
    "kotakbank.com",
    "kotaksecurities.com",
    # Other Major Banks
    "indusind.com",
    "indusindbank.com",
    "yesbank.in",
    "yesbank.com",
    "unionbankofindia.co.in",
    "idbibank.in",
    "idbi.com",
    "centralbankofindia.co.in",
    "indianbank.in",
    "bankofindia.co.in",
    "federalbank.co.in",
    "rblbank.com",
    # FinTech & UPI
    "paytm.com",
    "paytmbank.com",
    "phonepe.com",
    "bhimupi.org.in",
    "npci.org.in",
    "upiqr.in",
    "razorpay.com",
    "cashfree.com",
    "cred.club",
    # Regulators & Essential Govt Portals
    "rbi.org.in",
    "irctc.co.in",
    "irctctourism.com",
    "incometax.gov.in",
    "epfindia.gov.in",
    "uidai.gov.in",
    "digilocker.gov.in",
    "cert-in.org.in",
    "cybercrime.gov.in",
    # Legitimate non-bank brands whose names collide with a bank alias
    "axis.com",  # Axis Communications (network cameras)
}


# --------------------------------------------------------------------------
# Target Brand Profiles & Patterns
# --------------------------------------------------------------------------
# Mapping of canonical brand identifier to aliases / brand tokens
TARGET_BRANDS: Dict[str, List[str]] = {
    "SBI": ["sbi", "onlinesbi", "statebank", "yono", "yonosbi"],
    "HDFC": ["hdfc", "hdfcbank", "mycards"],
    "ICICI": ["icici", "icicibank", "imobile", "ipru"],
    "AXIS": ["axis", "axisbank"],
    "PNB": ["pnb", "punjabnationalbank", "pnbone"],
    "BOB": ["bankofbaroda", "bobworld", "bobcard"],
    "CANARA": ["canarabank", "canara", "ai1"],
    "KOTAK": ["kotak", "kotak811", "kotakbank"],
    "PAYTM": ["paytm", "paytmbank", "paytmmall"],
    "PHONEPE": ["phonepe"],
    "UPI_NPCI": ["bhim", "npci", "upi"],
    "IRCTC": ["irctc", "irctcticket"],
    "INCOMETAX_UIDAI": ["aadhaar", "uidai", "incometax", "epfo"],
}

# Aliases that are also ordinary words or name fragments ("axis" in praxis, "upi" in
# upicorn). Inside a longer word they only count when the domain also carries banking
# context; as a stand-alone token (axis-kyc.top) they always count.
AMBIGUOUS_BRAND_ALIASES: Set[str] = {"axis", "upi", "bhim", "mycards", "imobile"}

BANKING_CONTEXT_TERMS: Set[str] = {
    "bank",
    "kyc",
    "card",
    "credit",
    "debit",
    "loan",
    "otp",
    "ifsc",
    "neft",
    "imps",
    "rtgs",
    "wallet",
    "refund",
    "cashback",
    "aadhaar",
}


# --------------------------------------------------------------------------
# High-Risk Keyword Taxonomy & Weighting
# --------------------------------------------------------------------------
# Tier 1 (Urgent/Financial Threat Action): High risk (+18 points)
TIER_1_KEYWORDS: Set[str] = {
    "kyc",
    "pan",
    "pancard",
    "apk",
    "refund",
    "reward",
    "cashback",
    "claim",
    "otp",
    "customercare",
    "customer-care",
    "helpline",
    "tollfree",
}

# Tier 2 (Banking & Security Verification): Medium-High risk (+12 points)
TIER_2_KEYWORDS: Set[str] = {
    "update",
    "verify",
    "verification",
    "netbanking",
    "banking",
    "online",
    "login",
    "signin",
    "auth",
    "portal",
    "secure",
    "security",
    "security-alert",
    "block",
    "unblock",
    "activate",
    "reactivate",
    "support",
    "service",
}

# Tier 3 (Account & Transaction Terms): Moderate risk (+6 points)
TIER_3_KEYWORDS: Set[str] = {
    "account",
    "credit",
    "debit",
    "card",
    "pin",
    "password",
    "statement",
    "transfer",
    "balance",
    "recharge",
    "fastag",
    "lottery",
    "gift",
    "download",
}


# --------------------------------------------------------------------------
# Suspicious Top-Level Domains (TLDs) frequently abused in phishing
# --------------------------------------------------------------------------
SUSPICIOUS_TLDS: Set[str] = {
    "top",
    "xyz",
    "club",
    "live",
    "shop",
    "online",
    "vip",
    "site",
    "work",
    "rest",
    "icu",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "buzz",
    "link",
    "cam",
    "fit",
    "cfd",
    "monster",
    "sbs",
    "lol",
}
