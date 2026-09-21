from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.decision import SecurityGatewayCategory, ThreatClassification
from app.schemas.security import SecurityFinding


class SanitizedSecurityReport(BaseModel):
    """Sanitized report safe for presentation on high-risk/quarantined mail."""
    email_id: str
    sender_address: str
    subject: str
    classification: ThreatClassification
    risk_score: float
    reason: str
    security_tags: List[str] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    warning_notice: str = Field(default="Content blocked due to high-risk policy enforcement.")


class QuarantineItem(BaseModel):
    """Quarantine entity metadata contract."""
    quarantine_id: str = Field(description="Unique quarantine record identifier")
    email_id: str = Field(description="Quarantined email identifier")
    reason: str = Field(description="Quarantine policy rationale")
    gateway_category: SecurityGatewayCategory = Field(description="Security gateway category")
    risk_score: float = Field(ge=0.0, le=100.0, description="Risk score at quarantine time")
    classification: ThreatClassification = Field(description="Threat classification")
    sanitized_report: Optional[SanitizedSecurityReport] = Field(default=None, description="Safe security report for UI")
    original_content_blocked: bool = Field(default=True, description="Enforces original raw body is blocked")
    attachments_blocked: bool = Field(default=True, description="Enforces dangerous attachments are blocked")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Quarantine timestamp")
