"""Domain sanitization and extraction from Certificate Transparency payloads."""

from typing import Any, Dict, List, Set


def clean_domain(raw_domain: str) -> str:
    """
    Clean and canonicalize raw domain string:
    - strip leading/trailing whitespace
    - lowercase
    - strip wildcard prefix (*.)
    - strip trailing dots (.)
    """
    if not raw_domain or not isinstance(raw_domain, str):
        return ""

    cleaned = raw_domain.strip().lower()
    while cleaned.startswith("*."):
        cleaned = cleaned[2:]
    cleaned = cleaned.rstrip(".")

    return cleaned


def extract_domains_from_cert(message: Dict[str, Any]) -> List[str]:
    """
    Extract all unique sanitized domain names from a CertStream JSON message.

    Supports:
    - data.leaf_cert.all_domains
    - data.leaf_cert.subject.CN
    """
    domains: Set[str] = set()

    data = message.get("data", {})
    if not isinstance(data, dict):
        return []

    leaf_cert = data.get("leaf_cert", {})
    if isinstance(leaf_cert, dict):
        # 1. Extract SANs (Subject Alternative Names) + Common Name list
        all_domains = leaf_cert.get("all_domains", [])
        if isinstance(all_domains, list):
            for d in all_domains:
                cleaned = clean_domain(d)
                if cleaned:
                    domains.add(cleaned)

        # 2. Extract Common Name (CN) directly if present
        subject = leaf_cert.get("subject", {})
        if isinstance(subject, dict):
            cn = subject.get("CN")
            if cn:
                cleaned_cn = clean_domain(cn)
                if cleaned_cn:
                    domains.add(cleaned_cn)

    return sorted(list(domains))
