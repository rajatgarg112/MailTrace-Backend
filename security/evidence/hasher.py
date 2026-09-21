import hashlib
from typing import Dict, Any, Union


class EvidenceHasher:
    """
    Computes cryptographic and forensic hashes for raw emails,
    headers, message bodies, and attachments to guarantee chain of custody.
    """

    @staticmethod
    def hash_bytes(data: bytes) -> Dict[str, str]:
        """
        Computes standard forensic hashes (SHA-256, MD5, SHA-1).
        """
        if not data:
            return {"sha256": "", "md5": "", "sha1": ""}

        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()

        return {
            "sha256": sha256,
            "md5": md5,
            "sha1": sha1,
        }

    @staticmethod
    def hash_string(text: str) -> Dict[str, str]:
        """
        Computes forensic hashes for string payloads.
        """
        return EvidenceHasher.hash_bytes(text.encode("utf-8", errors="replace"))

    @staticmethod
    def compute_fuzzy_hash(content: Union[str, bytes]) -> str:
        """
        Simulates Context Triggered Piecewise Hashing (SSDEEP/TLSH).
        Detects near-duplicate phishing emails or attachment variants.
        """
        if isinstance(content, str):
            data = content.encode("utf-8", errors="replace")
        else:
            data = content

        if len(data) == 0:
            return "0:0:0"

        # Block-based rolling signature representation
        chunk_size = max(16, len(data) // 10)
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        block_hashes = [hashlib.md5(c).hexdigest()[:4] for c in chunks[:12]]
        
        return f"{chunk_size}:{'-'.join(block_hashes)}"
