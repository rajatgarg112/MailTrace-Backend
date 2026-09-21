import re
from typing import Dict, Any
from security.models import AuthStatus, AuthenticationResult


class DMARCEvaluator:
    """
    Evaluates Domain-based Message Authentication, Reporting, and Conformance (DMARC).
    Checks alignment between From domain and SPF/DKIM verification.
    """

    def evaluate(self, parsed_headers: Dict[str, Any], spf_status: AuthStatus, dkim_status: AuthStatus) -> AuthenticationResult:
        auth_results = parsed_headers.get("auth_results_raw", "")
        from_domain = parsed_headers.get("from_domain")
        return_path_domain = parsed_headers.get("return_path_domain")

        dmarc_status = AuthStatus.UNKNOWN
        dmarc_aligned = False
        details = []

        # Check explicit Authentication-Results header for dmarc status
        if auth_results:
            match = re.search(r"dmarc=(pass|fail|none|temperror|permerror)", auth_results, re.IGNORECASE)
            if match:
                res = match.group(1).lower()
                if res == "pass":
                    dmarc_status = AuthStatus.PASS
                    dmarc_aligned = True
                    details.append("DMARC passed via Authentication-Results header.")
                elif res in ["fail", "temperror", "permerror"]:
                    dmarc_status = AuthStatus.FAIL
                    dmarc_aligned = False
                    details.append(f"DMARC failed ({res}) via Authentication-Results header.")
                elif res == "none":
                    dmarc_status = AuthStatus.NONE
                    details.append("No DMARC policy declared in Authentication-Results.")

        # Evaluates alignment fallback if status is UNKNOWN or NONE
        if dmarc_status in [AuthStatus.UNKNOWN, AuthStatus.NONE]:
            spf_aligned = (spf_status == AuthStatus.PASS) and (from_domain is not None and return_path_domain == from_domain)
            dkim_aligned = (dkim_status == AuthStatus.PASS)

            if spf_aligned or dkim_aligned:
                dmarc_status = AuthStatus.PASS
                dmarc_aligned = True
                details.append("DMARC aligned: At least one authentication mechanism (SPF/DKIM) passed with domain alignment.")
            else:
                if spf_status == AuthStatus.FAIL or dkim_status == AuthStatus.FAIL:
                    dmarc_status = AuthStatus.FAIL
                    dmarc_aligned = False
                    details.append("DMARC failed: Neither SPF nor DKIM provided valid domain alignment.")

        return AuthenticationResult(
            spf=spf_status,
            dkim=dkim_status,
            dmarc=dmarc_status,
            header_from_domain=from_domain,
            envelope_from_domain=return_path_domain,
            dmarc_aligned=dmarc_aligned,
            details=details,
        )
