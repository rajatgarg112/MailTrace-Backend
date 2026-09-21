import re
from typing import List, Dict, Any, Tuple, Optional
from security.models import RelayHop


class HopCounter:
    """
    Parses RFC 5322 Received headers from top to bottom, extracts SMTP relay hops
    and identifies originating client IP address.
    """

    IP_REGEX = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
    FROM_REGEX = re.compile(r"from\s+([^\s]+(?:\s+\([^)]+\))?)", re.IGNORECASE)
    BY_REGEX = re.compile(r"by\s+([^\s]+)", re.IGNORECASE)

    def parse_hops(self, received_list: List[str]) -> Tuple[int, Optional[str], List[RelayHop]]:
        if not received_list:
            return 0, None, []

        hops: List[RelayHop] = []
        originating_ip: Optional[str] = None

        for idx, rec in enumerate(received_list, start=1):
            ip_match = self.IP_REGEX.search(rec)
            from_match = self.FROM_REGEX.search(rec)
            by_match = self.BY_REGEX.search(rec)

            ip_str = ip_match.group(1) if ip_match else None
            from_str = from_match.group(1) if from_match else None
            by_str = by_match.group(1) if by_match else None

            # The bottom-most Received header (highest hop number) is usually the originating hop
            if ip_str and not originating_ip:
                originating_ip = ip_str

            hops.append(
                RelayHop(
                    hop_number=idx,
                    from_host=from_str,
                    by_host=by_str,
                    client_ip=ip_str,
                    protocol="ESMTP",
                )
            )

        return len(hops), originating_ip, hops
