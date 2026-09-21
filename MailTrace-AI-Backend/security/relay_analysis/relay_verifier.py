from typing import List, Tuple, Optional
from security.models import RelayAnalysisResult, RelayHop


class RelayVerifier:
    """
    Verifies SMTP relay hop chains and detects anomalous routing paths.
    """

    MAX_EXPECTED_HOPS = 6

    def verify_relays(self, hop_count: int, originating_ip: Optional[str], hops: List[RelayHop]) -> RelayAnalysisResult:
        suspicious = False
        findings: List[str] = []

        if hop_count > self.MAX_EXPECTED_HOPS:
            suspicious = True
            findings.append(f"Excessive relay hops ({hop_count} hops detected, threshold is {self.MAX_EXPECTED_HOPS}).")

        if not originating_ip and hop_count > 0:
            suspicious = True
            findings.append("Missing originating client IP in Received header chain.")

        # Check for loopback or private IP as external originating IP
        if originating_ip:
            if originating_ip.startswith("127.") or originating_ip.startswith("10.") or originating_ip.startswith("192.168."):
                findings.append(f"Internal/Private originating IP detected: '{originating_ip}'.")

        return RelayAnalysisResult(
            hop_count=hop_count,
            originating_ip=originating_ip,
            suspicious_relay_detected=suspicious,
            hops=hops,
            findings=findings,
        )
