import re
from typing import Dict, Any, List
from security.models import HeaderAnalysisResult


class HeaderAnomalyDetector:
    """
    Detects RFC anomalies, missing mandatory headers, and domain mismatches
    between From, Return-Path, Reply-To, and Message-ID.
    """

    MANDATORY_HEADERS = ["From", "Date", "Message-ID"]

    def detect_anomalies(self, parsed_headers: Dict[str, Any]) -> HeaderAnalysisResult:
        missing: List[str] = []
        anomalies: List[str] = []

        raw_headers = parsed_headers.get("raw_headers", {})
        header_keys_lower = [k.lower() for k in raw_headers.keys()]

        # Check mandatory headers
        for h in self.MANDATORY_HEADERS:
            if h.lower() not in header_keys_lower:
                missing.append(h)
                anomalies.append(f"Missing mandatory RFC 5322 header: '{h}'")

        from_addr = parsed_headers.get("from_addr")
        from_domain = parsed_headers.get("from_domain")
        return_path_domain = parsed_headers.get("return_path_domain")
        reply_to_domain = parsed_headers.get("reply_to_domain")
        message_id = parsed_headers.get("message_id")

        return_path_mismatch = False
        message_id_domain_mismatch = False

        # Return-Path Mismatch Check
        if from_domain and return_path_domain and from_domain != return_path_domain:
            return_path_mismatch = True
            anomalies.append(
                f"Return-Path domain mismatch: From domain '{from_domain}' differs from Return-Path domain '{return_path_domain}'"
            )

        # Reply-To Mismatch Check
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            anomalies.append(
                f"Reply-To domain mismatch: From domain '{from_domain}' differs from Reply-To domain '{reply_to_domain}'"
            )

        # Message-ID Domain Mismatch Check
        if message_id and "@" in message_id:
            # Extract domain from <id@domain.com>
            msg_id_domain_match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", message_id)
            if msg_id_domain_match:
                msg_id_domain = msg_id_domain_match.group(1).lower()
                if from_domain and msg_id_domain != from_domain and not from_domain.endswith("." + msg_id_domain) and not msg_id_domain.endswith("." + from_domain):
                    message_id_domain_mismatch = True
                    anomalies.append(
                        f"Message-ID domain mismatch: Message-ID domain '{msg_id_domain}' differs from From domain '{from_domain}'"
                    )

        return HeaderAnalysisResult(
            parsed_from=from_addr,
            parsed_sender=parsed_headers.get("sender_addr"),
            parsed_reply_to=parsed_headers.get("reply_to_addr"),
            parsed_return_path=parsed_headers.get("return_path_addr"),
            parsed_message_id=message_id,
            parsed_subject=parsed_headers.get("subject"),
            missing_mandatory_headers=missing,
            message_id_domain_mismatch=message_id_domain_mismatch,
            return_path_mismatch=return_path_mismatch,
            anomalies=anomalies,
        )
