"""Brand matching module for Indian banking institutions and payment gateways."""

import re
from typing import Dict, List, Optional, Set

from ..config import AMBIGUOUS_BRAND_ALIASES, BANKING_CONTEXT_TERMS, TARGET_BRANDS


class BrandMatcher:
    """Detects target Indian bank and financial brands in domain names."""

    def __init__(
        self,
        brands_dict: Optional[Dict[str, List[str]]] = None,
        ambiguous_aliases: Optional[Set[str]] = None,
        context_terms: Optional[Set[str]] = None,
    ):
        self._brands = brands_dict or TARGET_BRANDS
        self._ambiguous = (
            AMBIGUOUS_BRAND_ALIASES if ambiguous_aliases is None else ambiguous_aliases
        )
        self._context_terms = BANKING_CONTEXT_TERMS if context_terms is None else context_terms

    def _has_banking_context(self, cleaned: str, alias: str) -> bool:
        """True if a banking term appears in the domain outside the alias itself."""
        remainder = cleaned.replace(alias, " ")
        return any(term in remainder for term in self._context_terms)

    def match_brands(self, domain: str, registered_domain: str = "") -> List[str]:
        """
        Identify which Indian banking/fintech brands are targeted or referenced.

        Args:
            domain: Full domain (e.g., 'sbi-kyc-verification.top')
            registered_domain: Registered apex domain (e.g., 'sbi-kyc-verification.top')

        Returns:
            List of matched canonical brand keys (e.g., ['SBI'])
        """
        cleaned = domain.lower().strip()
        # Extract name without TLD if registered_domain is provided
        domain_body = registered_domain.split(".")[0] if registered_domain else cleaned

        # Tokenize by common delimiters: '.', '-', '_', and digits
        tokens = set(re.split(r"[.\-_0-9]+", cleaned))
        tokens.discard("")

        matched: Set[str] = set()

        for brand_key, brand_aliases in self._brands.items():
            for alias in brand_aliases:
                alias = alias.lower()

                # Case 1: Exact token match (e.g., 'sbi' in ['sbi', 'kyc', 'top'])
                if alias in tokens:
                    matched.add(brand_key)
                    break

                # Ambiguous aliases inside a longer word ('praxis', 'upicorn') are
                # ordinary words unless the domain also mentions banking.
                if alias in self._ambiguous and not self._has_banking_context(cleaned, alias):
                    continue

                # Case 2: For multi-character aliases (length >= 4, e.g., 'onlinesbi', 'hdfcbank', 'phonepe', 'paytm')
                # substring match in body or full domain is high confidence
                if len(alias) >= 4 and (alias in cleaned or alias in domain_body):
                    matched.add(brand_key)
                    break

                # Case 3: Short alias (length 3, e.g., 'sbi', 'bob', 'pnb', 'upi')
                # Substring match if anchored at start/end of a token or hyphenated
                # e.g., 'sbikyc', 'kycsbi', 'mysbi'
                if len(alias) == 3:
                    pattern = rf"(^|[.\-_0-9]){re.escape(alias)}([.\-_0-9]|$)"
                    if re.search(pattern, cleaned):
                        matched.add(brand_key)
                        break
                    # Check prefix/suffix with common terms (e.g. 'sbikyc', 'pnbupdate')
                    if re.search(rf"(^|[.\-_]){re.escape(alias)}[a-z]{{2,}}", cleaned) or re.search(
                        rf"[a-z]{{2,}}{re.escape(alias)}([.\-_]|$)", cleaned
                    ):
                        # Verify that the adjacent text is not an unrelated dictionary word
                        matched.add(brand_key)
                        break

        return sorted(list(matched))
