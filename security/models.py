from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ThreatClassification(str, Enum):
    SAFE = "SAFE"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class DeliveryAction(str, Enum):
    INBOX = "INBOX"
    SPAM = "SPAM"
    WARN = "WARN"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


class AuthenticationResult(BaseModel):
    spf: AuthStatus = AuthStatus.UNKNOWN
    dkim: AuthStatus = AuthStatus.UNKNOWN
    dmarc: AuthStatus = AuthStatus.UNKNOWN
    header_from_domain: Optional[str] = None
    envelope_from_domain: Optional[str] = None
    dmarc_aligned: bool = False
    details: List[str] = Field(default_factory=list)


class DomainAnalysisResult(BaseModel):
    domain: Optional[str] = None
    is_lookalike: bool = False
    target_brand_domain: Optional[str] = None
    lookalike_distance: Optional[int] = None
    is_typosquatted: bool = False
    suspicious_tld: bool = False
    display_name_spoofed: bool = False
    claimed_display_name: Optional[str] = None
    actual_sender_email: Optional[str] = None
    domain_age_days: Optional[int] = None
    findings: List[str] = Field(default_factory=list)


class URLDetails(BaseModel):
    url: str
    expanded_url: Optional[str] = None
    domain: str
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class URLAnalysisResult(BaseModel):
    total_urls: int = 0
    suspicious_urls_count: int = 0
    extracted_urls: List[str] = Field(default_factory=list)
    redirect_chain_detected: bool = False
    anchor_text_mismatch_detected: bool = False
    urls_details: List[URLDetails] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)


class RelayHop(BaseModel):
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    client_ip: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None


class RelayAnalysisResult(BaseModel):
    hop_count: int = 0
    originating_ip: Optional[str] = None
    suspicious_relay_detected: bool = False
    hops: List[RelayHop] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)


class HeaderAnalysisResult(BaseModel):
    parsed_from: Optional[str] = None
    parsed_sender: Optional[str] = None
    parsed_reply_to: Optional[str] = None
    parsed_return_path: Optional[str] = None
    parsed_message_id: Optional[str] = None
    parsed_subject: Optional[str] = None
    missing_mandatory_headers: List[str] = Field(default_factory=list)
    message_id_domain_mismatch: bool = False
    return_path_mismatch: bool = False
    anomalies: List[str] = Field(default_factory=list)


class AttachmentDetails(BaseModel):
    filename: str
    extension: str
    is_dangerous: bool = False
    has_double_extension: bool = False
    reason: Optional[str] = None


class AttachmentAnalysisResult(BaseModel):
    total_attachments: int = 0
    dangerous_attachments_count: int = 0
    has_double_extension: bool = False
    attachments: List[AttachmentDetails] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    sequence: int
    timestamp: str
    stage: str
    status: str
    details: str


class NetworkContext(BaseModel):
    originating_ip: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    approximate_region: Optional[str] = None
    latitude: float = 0.0
    longitude: float = 0.0
    is_vpn_or_tor: bool = False
    map_marker: Dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = "Approximate network infrastructure location, not verified physical identity."


class ForensicResult(BaseModel):
    raw_sha256: str
    headers_sha256: str
    body_sha256: str
    timeline: List[TimelineEvent] = Field(default_factory=list)
    network_context: NetworkContext


class PolicyDecision(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    threat_classification: ThreatClassification
    delivery_action: DeliveryAction
    action_reason: str


class SecurityResult(BaseModel):
    email_id: str
    headers: HeaderAnalysisResult
    authentication: AuthenticationResult
    domain_analysis: DomainAnalysisResult
    url_analysis: URLAnalysisResult
    relay_analysis: RelayAnalysisResult
    attachments: AttachmentAnalysisResult
    forensics: ForensicResult
    policy_decision: PolicyDecision
    security_tags: List[str] = Field(default_factory=list)
    risk_score_contribution: int = Field(ge=0, le=100)
    infrastructure: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    timeline: List[Any] = Field(default_factory=list)
    forensic_case: Optional[Dict[str, Any]] = None
    sanitized_report: Optional[Dict[str, Any]] = None




