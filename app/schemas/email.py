from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, EmailStr


class EmailAddress(BaseModel):
    """Email address representation with optional display name."""
    address: str = Field(description="Raw or parsed email address string")
    name: Optional[str] = Field(default=None, description="Optional associated display name")


class AttachmentMetadata(BaseModel):
    """Safe metadata description of an email attachment."""
    filename: str = Field(description="Original attachment filename")
    content_type: str = Field(description="Reported MIME content type")
    size_bytes: int = Field(ge=0, description="Size in bytes")
    md5_hash: Optional[str] = Field(default=None, description="MD5 cryptographic hash")
    sha256_hash: Optional[str] = Field(default=None, description="SHA-256 cryptographic hash")
    mime_type_detected: Optional[str] = Field(default=None, description="Magic byte detected MIME type")
    is_executable: bool = Field(default=False, description="Flag indicating if executable structure was detected")
    has_macro: bool = Field(default=False, description="Flag indicating if document macros were detected")
    is_archive: bool = Field(default=False, description="Flag indicating if file is an archive")


class URLEntry(BaseModel):
    """Parsed URL metadata within an email."""
    url: str = Field(description="Raw extracted URL")
    domain: Optional[str] = Field(default=None, description="Extracted hostname/domain")
    is_ip: bool = Field(default=False, description="Whether URL uses direct IP address")
    is_shortened: bool = Field(default=False, description="Whether URL uses a known URL shortener")
    suspicious_tld: bool = Field(default=False, description="Whether TLD is flagged as high-risk")


class ReceivedHop(BaseModel):
    """Trace entry from email Received headers."""
    by_host: Optional[str] = Field(default=None, description="Receiving mail server hostname")
    from_host: Optional[str] = Field(default=None, description="Sending mail server hostname")
    ip_address: Optional[str] = Field(default=None, description="Extracted hop IP address")
    timestamp: Optional[datetime] = Field(default=None, description="Timestamp recorded in Received header")
    delay_seconds: Optional[float] = Field(default=None, ge=0.0, description="Calculated hop delay in seconds")


class EmailNormalized(BaseModel):
    """Normalized email payload entering the MailTrace-AI analysis pipeline."""
    message_id: str = Field(description="Unique email message identifier")
    sender: EmailAddress = Field(description="Normalized sender address details")
    recipients: List[EmailAddress] = Field(default_factory=list, description="Primary recipient list")
    reply_to: Optional[List[EmailAddress]] = Field(default=None, description="Reply-To header addresses")
    subject: str = Field(default="", description="Email subject line")
    headers: Dict[str, str] = Field(default_factory=dict, description="Normalized header key-value map")
    body_text_preview: Optional[str] = Field(default=None, description="Safe transient text preview (sanitized)")
    attachments: List[AttachmentMetadata] = Field(default_factory=list, description="Attachment metadata list")
    urls: List[URLEntry] = Field(default_factory=list, description="Extracted URL list")
    received_hops: List[ReceivedHop] = Field(default_factory=list, description="Parsed Received header hop chain")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Ingestion timestamp")
    mailbox_id: Optional[str] = Field(default=None, description="Target mailbox identifier")
    user_id: Optional[str] = Field(default=None, description="Target user identifier")
