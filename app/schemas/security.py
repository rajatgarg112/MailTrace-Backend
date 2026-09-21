from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.common import SeverityLevel



class SenderIdentityFeatures(BaseModel):
    """1. Sender / Identity feature category."""
    sender_address: Optional[str] = None
    display_name: Optional[str] = None
    reply_to: Optional[str] = None
    from_domain: Optional[str] = None
    domain_age: Optional[int] = Field(default=None, ge=0)
    domain_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    sender_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    sender_first_seen: Optional[datetime] = None
    sender_frequency: Optional[float] = Field(default=None, ge=0.0)
    impersonation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    sender_seen_before: Optional[bool] = None
    sender_in_contacts: Optional[bool] = None


class EmailAuthenticationFeatures(BaseModel):
    """2. Email Authentication feature category."""
    spf: Optional[str] = Field(default=None, description="SPF result: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE")
    dkim: Optional[str] = Field(default=None, description="DKIM result: PASS, FAIL, NONE")
    dmarc: Optional[str] = Field(default=None, description="DMARC result: PASS, FAIL, NONE")
    spf_alignment: Optional[bool] = None
    dkim_alignment: Optional[bool] = None
    dmarc_alignment: Optional[bool] = None
    dmarc_policy: Optional[str] = Field(default=None, description="DMARC policy: reject, quarantine, none")
    authentication_consistency: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class DomainFeatures(BaseModel):
    """3. Domain feature category."""
    domain_age: Optional[int] = Field(default=None, ge=0)
    domain_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    domain_registration_date: Optional[datetime] = None
    domain_expiry_date: Optional[datetime] = None
    domain_whois_status: Optional[str] = None
    domain_tld: Optional[str] = None
    subdomain_depth: Optional[int] = Field(default=None, ge=0)
    lookalike_domain_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    typosquatting_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class URLFeatures(BaseModel):
    """4. URL / Link feature category."""
    url_count: Optional[int] = Field(default=0, ge=0)
    suspicious_url_count: Optional[int] = Field(default=0, ge=0)
    url_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    domain_mismatch: Optional[bool] = None
    url_shortener: Optional[bool] = None
    redirect_count: Optional[int] = Field(default=0, ge=0)
    final_destination_url: Optional[str] = None
    https_status: Optional[bool] = None
    punycode_detected: Optional[bool] = None
    ip_based_url: Optional[bool] = None
    suspicious_tld: Optional[bool] = None
    malicious_domain_match: Optional[bool] = None
    url_entropy: Optional[float] = Field(default=None, ge=0.0)


class ContentNLPFeatures(BaseModel):
    """5. Content / NLP feature category."""
    spam_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    phishing_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    urgency_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fear_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    credential_request_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    financial_request_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    social_engineering_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    impersonation_language_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    call_to_action_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    suspicious_keyword_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    sentiment_score: Optional[float] = Field(default=None, ge=-1.0, le=1.0)
    language: Optional[str] = None
    text_entropy: Optional[float] = Field(default=None, ge=0.0)


class HeaderFeatures(BaseModel):
    """6. Email Headers feature category."""
    originating_ip: Optional[str] = None
    sender_ip: Optional[str] = None
    ip_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    reverse_dns: Optional[str] = None
    helo_hostname: Optional[str] = None
    received_hops: Optional[int] = Field(default=0, ge=0)
    hop_count: Optional[int] = Field(default=0, ge=0)
    sending_server: Optional[str] = None
    asn: Optional[str] = None
    geolocation: Optional[str] = Field(default=None, description="Approximate infrastructure location context")
    tls_status: Optional[bool] = None
    mail_server_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class BehavioralFeatures(BaseModel):
    """7. Behavioral feature category."""
    sending_frequency: Optional[float] = Field(default=None, ge=0.0)
    volume_anomaly: Optional[bool] = None
    time_anomaly: Optional[bool] = None
    location_anomaly: Optional[bool] = None
    sender_behavior_change: Optional[bool] = None
    conversation_anomaly: Optional[bool] = None
    recipient_count: Optional[int] = Field(default=1, ge=1)
    bulk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    historical_similarity: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    conversation_exists: Optional[bool] = None


class AttachmentFeatures(BaseModel):
    """8. Attachment feature category."""
    attachment_count: Optional[int] = Field(default=0, ge=0)
    attachment_type: Optional[str] = None
    attachment_size: Optional[int] = Field(default=None, ge=0)
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    mime_type_mismatch: Optional[bool] = None
    double_extension: Optional[bool] = None
    executable_detected: Optional[bool] = None
    macro_detected: Optional[bool] = None
    archive_detected: Optional[bool] = None
    password_protected_archive: Optional[bool] = None
    malware_hash_match: Optional[bool] = None
    attachment_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    sandbox_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class QRCodeFeatures(BaseModel):
    """9. QR Code feature category."""
    qr_present: bool = Field(default=False)
    qr_count: Optional[int] = Field(default=0, ge=0)
    qr_decoded: Optional[bool] = None
    qr_destination_url: Optional[str] = None
    qr_domain: Optional[str] = None
    qr_domain_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    qr_domain_age: Optional[int] = Field(default=None, ge=0)
    qr_url_mismatch: Optional[bool] = None
    qr_redirect_count: Optional[int] = Field(default=0, ge=0)
    qr_phishing_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class BECImpersonationFeatures(BaseModel):
    """10. BEC / Impersonation feature category."""
    executive_impersonation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    brand_impersonation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    payment_request_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    invoice_request_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    bank_account_change_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    gift_card_request_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    urgency_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    conversation_hijacking_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    authority_impersonation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class ThreatIntelFeatures(BaseModel):
    """11. Reputation / Threat Intelligence feature category."""
    sender_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    domain_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    ip_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    url_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    attachment_reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    threat_intelligence_match: Optional[bool] = None
    blacklist_match: Optional[bool] = None
    malware_database_match: Optional[bool] = None
    phishing_database_match: Optional[bool] = None
    abuse_database_match: Optional[bool] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class UserOrgContextFeatures(BaseModel):
    """12. User / Organization Context feature category."""
    sender_seen_before: Optional[bool] = None
    domain_seen_before: Optional[bool] = None
    user_replied_before: Optional[bool] = None
    sender_in_contacts: Optional[bool] = None
    domain_in_contacts: Optional[bool] = None
    previous_email_count: Optional[int] = Field(default=0, ge=0)
    previous_email_similarity: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    trusted_sender: Optional[bool] = None
    internal_sender: Optional[bool] = None
    external_sender: Optional[bool] = None


class FinalScoresFeatures(BaseModel):
    """13. Final Decision-Layer Scores feature category."""
    spam_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    phishing_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    malware_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    bec_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    impersonation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    overall_risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    threat_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    threat_category: Optional[str] = None
    risk_level: Optional[str] = None


class CanonicalSecurityFeatures(BaseModel):
    """Aggregated container for all 13 canonical security feature categories."""
    sender_identity: Optional[SenderIdentityFeatures] = None
    email_authentication: Optional[EmailAuthenticationFeatures] = None
    domain: Optional[DomainFeatures] = None
    url: Optional[URLFeatures] = None
    content_nlp: Optional[ContentNLPFeatures] = None
    header: Optional[HeaderFeatures] = None
    behavioral: Optional[BehavioralFeatures] = None
    attachment: Optional[AttachmentFeatures] = None
    qr_code: Optional[QRCodeFeatures] = None
    bec_impersonation: Optional[BECImpersonationFeatures] = None
    threat_intel: Optional[ThreatIntelFeatures] = None
    user_org_context: Optional[UserOrgContextFeatures] = None
    final_scores: Optional[FinalScoresFeatures] = None


class SecurityFinding(BaseModel):
    """Structured security finding returned by security analyzers."""
    code: str = Field(description="Unique finding code, e.g. DMARC_FAIL, SUSPICIOUS_URL")
    severity: SeverityLevel = Field(description="Severity level")
    description: Optional[str] = Field(default=None, description="Human-readable detail")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured supporting evidence facts")
