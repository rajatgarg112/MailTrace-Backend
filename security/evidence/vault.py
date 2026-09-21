from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from security.evidence.hasher import EvidenceHasher


class EvidenceVault:
    """
    Immutable Evidence Storage Handler.
    Packages tamper-proof evidence items with timestamps and cryptographic verification.
    """

    def __init__(self):
        self.hasher = EvidenceHasher()

    def package_evidence(
        self,
        email_id: str,
        raw_headers: Dict[str, Any],
        body_text_or_html: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()

        # Hash headers
        header_str = str(sorted(raw_headers.items()))
        header_hashes = self.hasher.hash_string(header_str)

        # Hash body
        body_content = body_text_or_html or ""
        body_hashes = self.hasher.hash_string(body_content)
        fuzzy_body_hash = self.hasher.compute_fuzzy_hash(body_content)

        # Hash attachments
        attachment_evidence = []
        if attachments:
            for att in attachments:
                name = att.get("filename", "unknown_attachment")
                content = att.get("content", b"")
                if isinstance(content, str):
                    content = content.encode("utf-8")
                hashes = self.hasher.hash_bytes(content)
                attachment_evidence.append({
                    "filename": name,
                    "size_bytes": len(content),
                    "hashes": hashes,
                    "fuzzy_hash": self.hasher.compute_fuzzy_hash(content),
                })

        # Master evidence integrity hash
        master_string = f"{email_id}:{timestamp}:{header_hashes['sha256']}:{body_hashes['sha256']}"
        master_integrity_hash = self.hasher.hash_string(master_string)["sha256"]

        return {
            "email_id": email_id,
            "captured_at": timestamp,
            "integrity_hash": master_integrity_hash,
            "headers_evidence": {
                "hash_sha256": header_hashes["sha256"],
                "hash_md5": header_hashes["md5"],
            },
            "body_evidence": {
                "hash_sha256": body_hashes["sha256"],
                "hash_md5": body_hashes["md5"],
                "fuzzy_hash": fuzzy_body_hash,
                "byte_size": len(body_content.encode("utf-8")),
            },
            "attachments_evidence": attachment_evidence,
            "chain_of_custody": {
                "custodian": "MailTrace-AI Pre-Delivery Gateway",
                "status": "SEALED",
                "tamper_evident": True,
            },
        }
