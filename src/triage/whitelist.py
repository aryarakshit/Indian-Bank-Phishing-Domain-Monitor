"""Whitelist checking module for legitimate banking and infrastructure domains."""

from typing import Iterable, Optional, Set

from ..config import DEFAULT_WHITELIST


class WhitelistChecker:
    """Evaluates whether a candidate domain belongs to legitimate banking infrastructure."""

    def __init__(self, custom_whitelist: Optional[Iterable[str]] = None):
        self._whitelist: Set[str] = {d.lower().strip() for d in DEFAULT_WHITELIST}
        if custom_whitelist:
            for d in custom_whitelist:
                self._whitelist.add(d.lower().strip())

    @property
    def entries(self) -> Set[str]:
        """Return the current set of whitelisted domains."""
        return set(self._whitelist)

    def is_whitelisted(self, domain: str, registered_domain: str = "") -> bool:
        """
        Check if a given domain or its parent registered domain is whitelisted.

        Args:
            domain: The full domain name (e.g. 'retail.onlinesbi.sbi')
            registered_domain: The apex/registered domain (e.g. 'onlinesbi.sbi')

        Returns:
            True if the domain is verified legitimate, False otherwise.
        """
        cleaned = domain.lower().strip().rstrip(".")
        if not cleaned:
            return False

        # Exact match
        if cleaned in self._whitelist:
            return True

        # Registered domain match
        if registered_domain:
            reg_clean = registered_domain.lower().strip().rstrip(".")
            if reg_clean in self._whitelist:
                return True

        # Check if candidate ends with any .<whitelisted-domain>
        for entry in self._whitelist:
            if cleaned == entry or cleaned.endswith("." + entry):
                return True

        return False
