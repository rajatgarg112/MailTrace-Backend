import re
from typing import Optional, Tuple, List


class TyposquattingDetector:
    """
    Identifies common typosquatting patterns in domain names
    including character replacement, number substitution, and double characters.
    """

    SUBSTITUTION_MAP = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "8": "b",
        "rn": "m",
        "vv": "w",
    }

    def detect_typosquatting(self, domain: Optional[str]) -> Tuple[bool, List[str]]:
        if not domain:
            return False, []

        domain_clean = domain.strip().lower()
        findings: List[str] = []
        is_typo = False

        # Number-for-letter substitution check (e.g., paypa1, g00gle)
        for num, char in self.SUBSTITUTION_MAP.items():
            if num in domain_clean:
                # Check if it looks like leetspeak in a domain
                is_typo = True
                findings.append(f"Typosquatting indicator: Number/letter substitution '{num}' -> '{char}' detected in '{domain_clean}'")

        # Hyphen insertion trick check (e.g. pay-pal.com)
        domain_part = domain_clean.split(".")[0]
        if "-" in domain_part and not domain_part.startswith("xn--"):
            is_typo = True
            findings.append(f"Typosquatting indicator: Hyphen insertion detected in domain name '{domain_clean}'")

        return is_typo, findings
