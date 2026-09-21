import re
from typing import Dict, Any, Tuple
from security.models import AuthStatus


class SPFEvaluator:
    """
    Evaluates Sender Policy Framework (SPF) validation status.
    Parses Authentication-Results and Received-SPF headers.
    """

    def evaluate(self, parsed_headers: Dict[str, Any]) -> Tuple[AuthStatus, str]:
        auth_results = parsed_headers.get("auth_results_raw", "")
        raw_headers = parsed_headers.get("raw_headers", {})

        received_spf = None
        for k, v in raw_headers.items():
            if k.lower() == "received-spf":
                received_spf = str(v)
                break

        # Check Received-SPF header first if present
        if received_spf:
            spf_lower = received_spf.lower()
            if "pass" in spf_lower:
                return AuthStatus.PASS, "SPF verification passed via Received-SPF header."
            elif "fail" in spf_lower and "softfail" not in spf_lower:
                return AuthStatus.FAIL, "SPF verification failed via Received-SPF header."
            elif "softfail" in spf_lower:
                return AuthStatus.FAIL, "SPF verification softfailed via Received-SPF header."
            elif "neutral" in spf_lower:
                return AuthStatus.NEUTRAL, "SPF verification result neutral via Received-SPF header."
            elif "none" in spf_lower:
                return AuthStatus.NONE, "No SPF record found via Received-SPF header."

        # Check Authentication-Results header
        if auth_results:
            match = re.search(r"spf=(pass|fail|softfail|neutral|none|permerror|temperror)", auth_results, re.IGNORECASE)
            if match:
                res = match.group(1).lower()
                if res == "pass":
                    return AuthStatus.PASS, "SPF verification passed via Authentication-Results."
                elif res in ["fail", "softfail"]:
                    return AuthStatus.FAIL, f"SPF verification {res}ed via Authentication-Results."
                elif res == "neutral":
                    return AuthStatus.NEUTRAL, "SPF result neutral via Authentication-Results."
                elif res == "none":
                    return AuthStatus.NONE, "No SPF record found via Authentication-Results."

        # If domain matches internal test cases or fallback
        from_domain = parsed_headers.get("from_domain")
        if not from_domain:
            return AuthStatus.UNKNOWN, "Cannot evaluate SPF: From domain is missing."

        return AuthStatus.UNKNOWN, "SPF status could not be verified from email headers."
