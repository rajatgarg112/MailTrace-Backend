import ipaddress
import re
from typing import Optional, List, Dict, Any


class IPResolver:
    """
    Extracts and validates originating and transit public IP addresses
    from parsed email headers and Received hops.
    Filters out private, loopback, and reserved addresses.
    """

    IP_REGEX = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    def extract_ips_from_string(self, text: str) -> List[str]:
        if not text:
            return []
        return self.IP_REGEX.findall(text)

    def is_public_ip(self, ip_str: str) -> bool:
        """
        Validates if the given string is a valid public, globally-routable IPv4 address.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            return False

    def resolve_originating_ip(self, headers: Dict[str, Any], hops: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
        """
        Finds the true public originating IP using standard forensic order:
        1. X-Originating-IP
        2. X-Sender-IP
        3. First public client_ip found from oldest Received hop
        """
        # 1. Check explicit client headers
        for candidate_header in ["x-originating-ip", "x-sender-ip", "x-client-ip"]:
            val = headers.get(candidate_header)
            if val:
                ips = self.extract_ips_from_string(str(val))
                for ip in ips:
                    if self.is_public_ip(ip):
                        return ip

        # 2. Check hops from chronological start (oldest hop)
        if hops:
            # Hops typically list newest first or oldest first. Inspect all client IPs:
            for hop in reversed(hops):
                client_ip = hop.get("client_ip")
                if client_ip and self.is_public_ip(client_ip):
                    return client_ip

        # 3. Fallback to parsing raw Received header text
        received = headers.get("received", [])
        if isinstance(received, str):
            received = [received]

        for entry in reversed(received):
            ips = self.extract_ips_from_string(entry)
            for ip in ips:
                if self.is_public_ip(ip):
                    return ip

        return None
