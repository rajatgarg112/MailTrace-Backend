from typing import List, Tuple, Optional


class LookalikeDomainDetector:
    """
    Detects lookalike, homograph, and brand-spoofed domains using
    Levenshtein edit distance and brand keyword matching.
    """

    TARGET_BRANDS: List[str] = [
        "paypal.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "bankofamerica.com",
        "chase.com",
        "amazon.com",
        "wellsfargo.com",
        "netflix.com",
        "linkedin.com",
    ]

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Pure-Python implementation of Levenshtein edit distance."""
        if len(s1) < len(s2):
            return LookalikeDomainDetector.levenshtein_distance(s2, s1)

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

    def check_lookalike(self, domain: Optional[str]) -> Tuple[bool, Optional[str], Optional[int], List[str]]:
        if not domain:
            return False, None, None, []

        domain_clean = domain.strip().lower()
        findings: List[str] = []

        # Exclude exact match to legitimate brand domain
        if domain_clean in self.TARGET_BRANDS:
            return False, domain_clean, 0, []

        # Strip TLD for base string comparison
        domain_name_part = domain_clean.split(".")[0]

        # Create normalized domain string with leetspeak replaced for brand keyword checking
        normalized_domain = (
            domain_clean.replace("1", "l")
            .replace("0", "o")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
        )

        for brand in self.TARGET_BRANDS:
            brand_name_part = brand.split(".")[0]
            dist = self.levenshtein_distance(domain_name_part, brand_name_part)

            # Lookalike distance check (1 or 2 character edits away)
            if 1 <= dist <= 2 and len(domain_name_part) >= 4:
                msg = f"Lookalike domain detected: '{domain_clean}' is {dist} edit(s) away from target brand '{brand}'"
                findings.append(msg)
                return True, brand, dist, findings

            # Subdomain or combo spoofing check (e.g. paypal-verify-support.com or paypa1-verify.xyz)
            if (brand_name_part in domain_clean or brand_name_part in normalized_domain) and domain_clean != brand:
                msg = f"Brand spoofing detected: Domain '{domain_clean}' contains brand keyword '{brand_name_part}'"
                findings.append(msg)
                return True, brand, dist, findings

        return False, None, None, []
