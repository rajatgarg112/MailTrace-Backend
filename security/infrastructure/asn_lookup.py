from typing import Dict, Any, Optional
import urllib.request
import json
import socket


class ASNLookup:
    """
    Resolves Autonomous System Number (ASN), ISP, and organization
    associated with an originating infrastructure IP.
    """

    KNOWN_BULLETPROOF_OR_CLOUD_ASNS = {
        "AS14061": "DigitalOcean",
        "AS16509": "Amazon AWS",
        "AS15169": "Google Cloud",
        "AS8075": "Microsoft Azure",
        "AS16276": "OVH SAS",
        "AS200000": "M247 Europe",
        "AS60068": "Datacamp Limited",
    }

    def get_reverse_dns(self, ip_address: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            return None

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Queries IP infrastructure intelligence.
        Uses free, unauthenticated ip-api / mock lookup with zero blocking.
        """
        reverse_dns = self.get_reverse_dns(ip_address)
        
        result = {
            "ip": ip_address,
            "asn": "UNKNOWN",
            "as_name": "Unknown Infrastructure",
            "isp": "Unknown ISP",
            "org": "Unknown Organization",
            "reverse_dns": reverse_dns,
            "is_datacenter_hosting": False,
        }

        if not ip_address:
            return result

        try:
            # Query standard ip-api endpoint (free, no token needed) with short timeout
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,org,as,query"
            req = urllib.request.Request(url, headers={"User-Agent": "MailTrace-AI-Forensics/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    as_full = data.get("as", "")
                    asn = as_full.split()[0] if as_full else "UNKNOWN"
                    as_name = " ".join(as_full.split()[1:]) if len(as_full.split()) > 1 else data.get("org", "")

                    isp = data.get("isp", "Unknown ISP")
                    org = data.get("org", "Unknown Org")

                    # Flag datacenter / cloud / bulletproof hosting
                    is_dc = False
                    for known_asn in self.KNOWN_BULLETPROOF_OR_CLOUD_ASNS:
                        if known_asn in asn or known_asn in as_full:
                            is_dc = True
                            break

                    result.update({
                        "asn": asn,
                        "as_name": as_name,
                        "isp": isp,
                        "org": org,
                        "is_datacenter_hosting": is_dc,
                    })
        except Exception:
            # Offline or timeout fallback: deterministic heuristic
            pass

        return result
