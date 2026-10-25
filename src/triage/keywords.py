"""Keyword heuristic matching module."""

import re
from typing import Dict, List, Set, Tuple

from ..config import TIER_1_KEYWORDS, TIER_2_KEYWORDS, TIER_3_KEYWORDS


class KeywordMatcher:
    """Scans domains for phishing indicators and high-risk banking tokens."""

    def __init__(self):
        self.tier1 = TIER_1_KEYWORDS
        self.tier2 = TIER_2_KEYWORDS
        self.tier3 = TIER_3_KEYWORDS
        self.all_keywords = self.tier1 | self.tier2 | self.tier3

    def find_keywords(self, domain: str) -> Tuple[List[str], Dict[str, int]]:
        """
        Scan a domain for presence of high-risk banking keywords.

        Args:
            domain: Domain string (e.g. 'sbi-kyc-pan-update.xyz')

        Returns:
            Tuple of:
              - sorted list of matched unique keywords
              - dictionary breakdown mapping keyword to its tier level (1, 2, or 3)
        """
        cleaned = domain.lower().strip()
        # Tokenize by common delimiters
        tokens = set(re.split(r"[.\-_0-9]+", cleaned))
        tokens.discard("")

        matched: Set[str] = set()
        tier_map: Dict[str, int] = {}

        # 1. Direct token matches
        for kw in self.all_keywords:
            if kw in tokens:
                matched.add(kw)
            elif len(kw) >= 3 and kw in cleaned:
                # Substring match (e.g. 'sbikyc' contains 'kyc', 'updatepan' contains 'update')
                # Ensure substring boundary makes sense
                pattern = rf"(^|[.\-_0-9]|[a-z]){re.escape(kw)}([.\-_0-9]|[a-z]|$)"
                if re.search(pattern, cleaned):
                    matched.add(kw)

        # Classify matched keywords into tiers
        for kw in matched:
            if kw in self.tier1:
                tier_map[kw] = 1
            elif kw in self.tier2:
                tier_map[kw] = 2
            else:
                tier_map[kw] = 3

        return sorted(list(matched)), tier_map
