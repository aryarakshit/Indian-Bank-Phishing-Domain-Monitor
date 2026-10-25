"""Homoglyph, Punycode (IDN), and Typosquatting detection engine."""

from typing import Dict, List, Tuple

import idna

from ..config import TARGET_BRANDS
from ..models import HomoglyphMatch

# Homoglyph lookup mapping non-ASCII Unicode characters to ASCII equivalents
CONFUSABLE_MAPPING: Dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # Cyrillic а
    "\u0441": "c",  # Cyrillic с
    "\u0435": "e",  # Cyrillic е
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0455": "s",  # Cyrillic ѕ
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
    "\u0432": "b",  # Cyrillic в
    "\u043c": "m",  # Cyrillic м
    "\u0442": "t",  # Cyrillic т
    "\u04bb": "h",  # Cyrillic һ
    # Greek lowercase
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03bd": "v",  # Greek ν
    "\u03c1": "p",  # Greek ρ
    "\u03ba": "k",  # Greek κ
    "\u03b9": "i",  # Greek ι
}

# Common leetspeak substitutions
LEET_MAPPING: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class HomoglyphDetector:
    """Detects IDN Punycode attacks, homoglyph character substitutions, and typosquats."""

    def __init__(self):
        # Flatten brand aliases for distance checks
        self.brand_aliases: Dict[str, str] = {}
        for brand_key, aliases in TARGET_BRANDS.items():
            for alias in aliases:
                self.brand_aliases[alias.lower()] = brand_key

    def decode_punycode(self, domain: str) -> Tuple[str, bool]:
        """
        Decode Punycode domain to Unicode if internationalized domain name is present.

        Returns:
            Tuple of (decoded_domain, is_punycode_flag)
        """
        is_puny = "xn--" in domain.lower()
        if not is_puny:
            return domain, False

        try:
            decoded = idna.decode(domain)
            return decoded, True
        except Exception:
            return domain, True

    def detect_homoglyphs(self, domain: str) -> Tuple[List[HomoglyphMatch], str]:
        """
        Scan a domain for homoglyph characters and generate normalized ASCII equivalent.

        Returns:
            Tuple of (list_of_detected_matches, normalized_ascii_string)
        """
        decoded, is_puny = self.decode_punycode(domain)
        findings: List[HomoglyphMatch] = []
        normalized_chars: List[str] = []

        for char in decoded:
            if char in CONFUSABLE_MAPPING:
                ascii_replacement = CONFUSABLE_MAPPING[char]
                normalized_chars.append(ascii_replacement)
                findings.append(
                    HomoglyphMatch(
                        original_char=char,
                        target_char=ascii_replacement,
                        brand_imitated="UNKNOWN",
                        variation_type="punycode" if is_puny else "cyrillic",
                    )
                )
            else:
                normalized_chars.append(char)

        normalized_domain = "".join(normalized_chars)
        return findings, normalized_domain

    def detect_leetspeak_and_typos(self, domain: str) -> List[HomoglyphMatch]:
        """
        Check for leetspeak replacements and typosquatting against brand names.
        """
        findings: List[HomoglyphMatch] = []
        clean = domain.lower()
        parts = clean.replace("-", ".").split(".")

        for part in parts:
            if not part:
                continue

            # 1. Leetspeak substitution check
            has_leet = any(c in LEET_MAPPING for c in part)
            if has_leet:
                deleet_part = "".join(LEET_MAPPING.get(c, c) for c in part)
                for brand_alias, brand_key in self.brand_aliases.items():
                    if brand_alias in deleet_part and brand_alias not in part:
                        findings.append(
                            HomoglyphMatch(
                                original_char=part,
                                target_char=deleet_part,
                                brand_imitated=brand_key,
                                variation_type="leetspeak",
                            )
                        )
                        break

            # 2. Typosquatting / Edit Distance check
            # For parts with length >= 4, check edit distance of 1
            if len(part) >= 4:
                for brand_alias, brand_key in self.brand_aliases.items():
                    if len(brand_alias) >= 4 and abs(len(part) - len(brand_alias)) <= 1:
                        dist = levenshtein_distance(part, brand_alias)
                        if dist == 1:
                            findings.append(
                                HomoglyphMatch(
                                    original_char=part,
                                    target_char=brand_alias,
                                    brand_imitated=brand_key,
                                    variation_type="typo",
                                )
                            )
                            break

        return findings
