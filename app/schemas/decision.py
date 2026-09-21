from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.risk import RiskLevel


class ThreatClassification(str, Enum):
    """Documented security threat classification levels."""
    SAFE = "SAFE"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class DeliveryAction(str, Enum):
    """Documented backend delivery actions."""
    INBOX = "INBOX"
    SPAM = "SPAM"
    WARN = "WARN"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


class SpamCategory(str, Enum):
    """Documented spam classification sub-categories."""
    MARKETING = "MARKETING"
    EDUCATION = "EDUCATION"
    SOCIAL_NOTIFICATION = "SOCIAL_NOTIFICATION"
    BULK = "BULK"
    SCAM = "SCAM"
    FRAUD = "FRAUD"
    PHISHING = "PHISHING"
    SUSPICIOUS = "SUSPICIOUS"
    OTHER = "OTHER"


class SecurityGatewayCategory(str, Enum):
    """Documented security gateway / quarantine sub-categories."""
    MALICIOUS = "MALICIOUS"
    HIGH_RISK_PHISHING = "HIGH_RISK_PHISHING"
    MALWARE = "MALWARE"
    BEC_FRAUD = "BEC_FRAUD"
    OTHER_HIGH_RISK = "OTHER_HIGH_RISK"


class PolicyDecision(BaseModel):
    """Canonical delivery policy decision contract."""
    classification: ThreatClassification = Field(description="Threat classification verdict")
    action: DeliveryAction = Field(description="Selected delivery policy routing action")
    risk_level: RiskLevel = Field(description="Associated risk level")
    risk_score: float = Field(ge=0.0, le=100.0, description="Associated overall risk score")
    spam_category: Optional[SpamCategory] = Field(default=None, description="Detailed category if classified as SPAM")
    gateway_category: Optional[SecurityGatewayCategory] = Field(default=None, description="Detailed category if sent to QUARANTINE")
    reason: str = Field(description="Policy decision rationale")
    policy_version: str = Field(default="1.0.0", description="Policy version used")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Decision timestamp")
