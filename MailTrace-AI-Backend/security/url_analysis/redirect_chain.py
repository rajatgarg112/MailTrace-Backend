from typing import List, Tuple
from urllib.parse import urlparse


class RedirectChainAnalyzer:
    """
    Detects URL shortener usage and flags potential redirect chain risks.
    """

    SHORTENER_DOMAINS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "mcaf.ee",
        "cutt.ly",
    ]

    def check_redirect_chains(self, urls: List[str]) -> Tuple[bool, List[str]]:
        if not urls:
            return False, []

        redirect_detected = False
        findings: List[str] = []

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = (parsed.netloc or "").split(":")[0].lower()

                if domain in self.SHORTENER_DOMAINS:
                    redirect_detected = True
                    msg = f"URL shortener detected: '{url}' uses known shortener domain '{domain}' hiding final target destination."
                    findings.append(msg)
            except Exception:
                continue

        return redirect_detected, findings
