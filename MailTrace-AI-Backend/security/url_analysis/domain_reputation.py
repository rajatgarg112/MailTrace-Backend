import re
from urllib.parse import urlparse
from typing import List, Tuple
from security.models import URLDetails, URLAnalysisResult


class URLDomainReputationAnalyzer:
    """
    Evaluates extracted URLs for suspicious structural features (IP URLs, credential harvesting paths, etc.).
    """

    IP_URL_REGEX = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE)
    SUSPICIOUS_PATH_KEYWORDS = ["login", "verify", "update", "account", "banking", "secure", "credential", "auth", "webmail"]

    def analyze(self, urls: List[str], has_anchor_mismatch: bool, anchor_mismatches: List[dict], redirect_chain_detected: bool, redirect_findings: List[str]) -> URLAnalysisResult:
        suspicious_count = 0
        details_list: List[URLDetails] = []
        overall_findings: List[str] = list(redirect_findings)

        if has_anchor_mismatch:
            for m in anchor_mismatches:
                overall_findings.append(
                    f"Anchor text mismatch detected: Visual display link '{m['display_url']}' leads to different target domain '{m['target_domain']}'"
                )

        for u in urls:
            is_susp = False
            reasons: List[str] = []
            domain = ""

            try:
                parsed = urlparse(u)
                domain = (parsed.netloc or "").split(":")[0].lower()
                path = (parsed.path or "").lower()

                # Check 1: Raw IP URL
                if self.IP_URL_REGEX.match(u):
                    is_susp = True
                    reasons.append("Raw IP address used as URL host.")

                # Check 2: Excessive subdomains
                subdomain_parts = domain.split(".")
                if len(subdomain_parts) >= 4 and not domain.endswith(".co.uk") and not domain.endswith(".com.au"):
                    is_susp = True
                    reasons.append(f"Excessive subdomains ({len(subdomain_parts)} levels) in URL host '{domain}'.")

                # Check 3: Credential harvesting path keywords
                for kw in self.SUSPICIOUS_PATH_KEYWORDS:
                    if kw in path and domain and not any(b in domain for b in ["google.com", "microsoft.com", "paypal.com", "apple.com"]):
                        is_susp = True
                        reasons.append(f"Suspicious path keyword '{kw}' found in unverified domain '{domain}'.")
                        break

            except Exception:
                pass

            if is_susp:
                suspicious_count += 1

            details_list.append(
                URLDetails(
                    url=u,
                    domain=domain,
                    is_suspicious=is_susp,
                    suspicious_reasons=reasons,
                )
            )

        return URLAnalysisResult(
            total_urls=len(urls),
            suspicious_urls_count=suspicious_count + (1 if has_anchor_mismatch else 0),
            extracted_urls=urls,
            redirect_chain_detected=redirect_chain_detected,
            anchor_text_mismatch_detected=has_anchor_mismatch,
            urls_details=details_list,
            findings=overall_findings,
        )
