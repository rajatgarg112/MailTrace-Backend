import re
import email
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple


class HeaderParser:
    """
    RFC 5322 Header Parser for MailTrace-AI Security Subsystem.
    Parses raw header strings or dictionaries into structured components.
    """

    @staticmethod
    def parse_email_address(raw_header_val: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Parses a header value like 'John Doe <john@example.com>' or 'john@example.com'.
        Returns (display_name, email_address).
        """
        if not raw_header_val:
            return None, None
        display_name, addr = parseaddr(str(raw_header_val))
        display_name = display_name.strip() if display_name else None
        addr = addr.strip().lower() if addr else None
        return display_name, addr

    @staticmethod
    def extract_domain(email_address: Optional[str]) -> Optional[str]:
        """Extracts the domain portion of an email address."""
        if not email_address or "@" not in email_address:
            return None
        return email_address.split("@")[-1].strip().lower()

    def parse(self, headers_input: Any) -> Dict[str, Any]:
        """
        Main entrypoint. Accepts a dict of headers, raw RFC 5322 text string, or email.message.Message object.
        Returns a standardized dictionary of header data.
        """
        headers_dict: Dict[str, Any] = {}

        if isinstance(headers_input, str):
            msg = email.message_from_string(headers_input)
            headers_dict = {k: v for k, v in msg.items()}
            # Capture multi-headers like Received
            headers_dict["_received_list"] = msg.get_all("Received", [])
            headers_dict["_dkim_signatures"] = msg.get_all("DKIM-Signature", [])
        elif isinstance(headers_input, dict):
            # Normalize keys to lowercase for dictionary access while retaining raw
            for k, v in headers_input.items():
                headers_dict[k] = v
            # Ensure received list handling
            if "Received" in headers_input and isinstance(headers_input["Received"], list):
                headers_dict["_received_list"] = headers_input["Received"]
            elif "Received" in headers_input and isinstance(headers_input["Received"], str):
                headers_dict["_received_list"] = [headers_input["Received"]]
            else:
                headers_dict["_received_list"] = []

            if "DKIM-Signature" in headers_input and isinstance(headers_input["DKIM-Signature"], list):
                headers_dict["_dkim_signatures"] = headers_input["DKIM-Signature"]
            elif "DKIM-Signature" in headers_input and isinstance(headers_input["DKIM-Signature"], str):
                headers_dict["_dkim_signatures"] = [headers_input["DKIM-Signature"]]
            else:
                headers_dict["_dkim_signatures"] = []
        else:
            headers_dict = {}

        # Case-insensitive helper lookup
        def get_header(name: str) -> Optional[str]:
            for k, v in headers_dict.items():
                if k.lower() == name.lower() and not k.startswith("_"):
                    return str(v)
            return None

        from_raw = get_header("From")
        sender_raw = get_header("Sender")
        reply_to_raw = get_header("Reply-To")
        return_path_raw = get_header("Return-Path")
        message_id_raw = get_header("Message-ID")
        subject_raw = get_header("Subject")
        auth_results_raw = get_header("Authentication-Results")

        from_display, from_addr = self.parse_email_address(from_raw)
        _, sender_addr = self.parse_email_address(sender_raw)
        _, reply_to_addr = self.parse_email_address(reply_to_raw)
        _, return_path_addr = self.parse_email_address(return_path_raw)

        return {
            "raw_headers": headers_dict,
            "from_raw": from_raw,
            "from_display": from_display,
            "from_addr": from_addr,
            "from_domain": self.extract_domain(from_addr),
            "sender_addr": sender_addr,
            "sender_domain": self.extract_domain(sender_addr),
            "reply_to_addr": reply_to_addr,
            "reply_to_domain": self.extract_domain(reply_to_addr),
            "return_path_addr": return_path_addr,
            "return_path_domain": self.extract_domain(return_path_addr),
            "message_id": message_id_raw,
            "subject": subject_raw,
            "auth_results_raw": auth_results_raw,
            "received_list": headers_dict.get("_received_list", []),
            "dkim_signatures": headers_dict.get("_dkim_signatures", []),
        }
