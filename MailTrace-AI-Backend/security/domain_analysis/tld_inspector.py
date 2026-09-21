import re
from typing import Optional, Tuple, List


class TLDInspector:
    """
    Inspects TLD threat profiles and detects display name spoofing attacks.
    """

    HIGH_RISK_TLDS = [
        ".xyz",
        ".top",
        ".work",
        ".click",
        ".zip",
        ".mov",
        ".cc",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".fit",
        ".icu",
        ".rest",
        ".monster",
    ]

    BRAND_KEYWORDS = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "bank of america",
        "chase",
        "amazon",
        "wells fargo",
        "netflix",
        "support",
        "security team",
        "account verify",
        "billing department",
    ]

    def check_suspicious_tld(self, domain: Optional[str]) -> Tuple[bool, List[str]]:
        if not domain:
            return False, []

        domain_clean = domain.strip().lower()
        findings: List[str] = []

        for tld in self.HIGH_RISK_TLDS:
            if domain_clean.endswith(tld):
                findings.append(f"Suspicious TLD flagged: Domain '{domain_clean}' uses high-risk TLD '{tld}'")
                return True, findings

        return False, []

    def check_display_name_spoofing(self, display_name: Optional[str], sender_domain: Optional[str]) -> Tuple[bool, List[str]]:
        if not display_name or not sender_domain:
            return False, []

        display_clean = display_name.strip().lower()
        sender_clean = sender_domain.strip().lower()
        findings: List[str] = []

        for brand in self.BRAND_KEYWORDS:
            if brand in display_clean:
                # If display name mentions brand, check if sender domain contains brand
                brand_base = brand.split()[0]
                if brand_base not in sender_clean:
                    msg = f"Display name spoofing detected: Display name '{display_name}' claims '{brand}' identity, but email domain is '{sender_domain}'"
                    findings.append(msg)
                    return True, findings

        return False, []
