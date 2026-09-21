import re
from typing import Dict, Any, Tuple
from security.models import AuthStatus


class DKIMEvaluator:
    """
    Evaluates DomainKeys Identified Mail (DKIM) verification status.
    Inspects DKIM-Signature headers and Authentication-Results headers.
    """

    def evaluate(self, parsed_headers: Dict[str, Any]) -> Tuple[AuthStatus, str]:
        auth_results = parsed_headers.get("auth_results_raw", "")
        dkim_sigs = parsed_headers.get("dkim_signatures", [])

        # Check Authentication-Results header first
        if auth_results:
            match = re.search(r"dkim=(pass|fail|neutral|none|permerror|temperror)", auth_results, re.IGNORECASE)
            if match:
                res = match.group(1).lower()
                if res == "pass":
                    return AuthStatus.PASS, "DKIM signature verified successfully via Authentication-Results."
                elif res in ["fail", "permerror", "temperror"]:
                    return AuthStatus.FAIL, f"DKIM verification failed ({res}) via Authentication-Results."
                elif res == "none":
                    return AuthStatus.NONE, "No DKIM signature found via Authentication-Results."

        # If DKIM-Signature headers exist
        if dkim_sigs:
            return AuthStatus.UNKNOWN, "DKIM-Signature header present; cryptographic verification unconfirmed without DNS key."
        
        return AuthStatus.NONE, "No DKIM-Signature header present in email."
