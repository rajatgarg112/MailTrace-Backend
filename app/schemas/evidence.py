from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class EvidenceRecord(BaseModel):
    """Evidence preservation record contract."""
    evidence_id: str = Field(description="Unique evidence record identifier")
    email_id: str = Field(description="Associated email identifier")
    evidence_type: str = Field(description="Evidence type: HEADER, ATTACHMENT, URL, QR, METADATA")
    sha256_hash: str = Field(description="64-character hex SHA-256 hash of preserved artifact")
    source_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata describing source/origin")
    extracted_facts: Dict[str, Any] = Field(default_factory=dict, description="Extracted security facts")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Preservation timestamp")

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("sha256_hash must be a valid 64-character hexadecimal string")
        return v
