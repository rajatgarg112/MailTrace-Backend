import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional


class URLExtractor:
    """
    Extracts URLs from raw text and HTML body contents and identifies anchor text mismatches.
    """

    URL_REGEX = re.compile(
        r"https?://(?:[a-zA-Z0-9$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        re.IGNORECASE,
    )

    HREF_REGEX = re.compile(
        r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )

    def extract_urls(self, text_or_html: str) -> Tuple[List[str], bool, List[Dict[str, str]]]:
        if not text_or_html:
            return [], False, []

        found_urls: List[str] = []
        anchor_mismatches: List[Dict[str, str]] = []
        has_anchor_mismatch = False

        # Extract plain URLs
        plain_matches = self.URL_REGEX.findall(text_or_html)
        for u in plain_matches:
            clean_u = u.rstrip(".,;)\"']")
            if clean_u not in found_urls:
                found_urls.append(clean_u)

        # Extract HTML anchor links and check anchor text mismatch
        href_matches = self.HREF_REGEX.findall(text_or_html)
        for href_url, anchor_text in href_matches:
            clean_href = href_url.rstrip(".,;)\"']")
            if clean_href not in found_urls:
                found_urls.append(clean_href)

            # Check if anchor text looks like a URL pointing elsewhere
            anchor_clean = anchor_text.strip()
            if self.URL_REGEX.match(anchor_clean):
                target_domain = self.extract_domain(clean_href)
                display_domain = self.extract_domain(anchor_clean)

                if target_domain and display_domain and target_domain != display_domain:
                    has_anchor_mismatch = True
                    anchor_mismatches.append({
                        "href_url": clean_href,
                        "display_url": anchor_clean,
                        "target_domain": target_domain,
                        "display_domain": display_domain,
                    })

        return found_urls, has_anchor_mismatch, anchor_mismatches

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc or parsed.path
            # Strip port if present
            netloc = netloc.split(":")[0].lower()
            return netloc
        except Exception:
            return None
