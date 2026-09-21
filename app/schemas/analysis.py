from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from app.schemas.common import AnalyzerStatus
from app.schemas.decision import PolicyDecision
from app.schemas.risk import RiskResult
from app.schemas.security import CanonicalSecurityFeatures, SecurityFinding


class AnalyzerResultItem(BaseModel):
    """Execution output wrapper for a single analyzer module."""
    analyzer: str = Field(description="Analyzer name, e.g. url, header, attachment, qr, ml")
    status: AnalyzerStatus = Field(description="Analyzer status")
    features: Dict[str, Any] = Field(default_factory=dict, description="Extracted feature key-value pairs")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Security findings produced")
    execution_time_ms: Optional[float] = Field(default=None, ge=0.0, description="Latency in milliseconds")
    error_message: Optional[str] = Field(default=None, description="Error details if status is FAILED/UNAVAILABLE")


class AnalysisRun(BaseModel):
    """Comprehensive analysis run payload contract."""
    analysis_id: str = Field(description="Unique analysis run identifier")
    email_id: str = Field(description="Associated email identifier")
    status: AnalyzerStatus = Field(default=AnalyzerStatus.SUCCESS, description="Overall pipeline status")
    analyzer_results: Dict[str, AnalyzerResultItem] = Field(default_factory=dict, description="Map of analyzer name to result item")
    canonical_features: Optional[CanonicalSecurityFeatures] = Field(default=None, description="Merged 13-category canonical features")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Aggregated security findings")
    tags: List[str] = Field(default_factory=list, description="Generated security tags")
    risk_result: Optional[RiskResult] = Field(default=None, description="Calculated risk result")
    policy_decision: Optional[PolicyDecision] = Field(default=None, description="Final delivery policy decision")
    evidence_ids: List[str] = Field(default_factory=list, description="Associated preserved evidence record IDs")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Analysis start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Analysis completion timestamp")
    errors: List[str] = Field(default_factory=list, description="Pipeline warnings or non-fatal errors")


class EmailAnalysisRequest(BaseModel):
    """Structured or raw email payload submitted for gateway analysis."""
    raw_email: Optional[str] = Field(default=None, description="Raw RFC 5322 MIME email string payload")
    message_id: Optional[str] = Field(default=None, description="Optional Message-ID override")
    sender: Optional[Any] = Field(default=None, description="Sender string or dict")
    recipients: Optional[Any] = Field(default=None, description="Recipient string, dict, or list")
    subject: Optional[str] = Field(default=None, description="Subject line")
    body: Optional[str] = Field(default=None, description="Email body text or HTML")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Headers map")
    attachments: Optional[List[Dict[str, Any]]] = Field(default=None, description="Attachment metadata items")
    urls: Optional[List[Any]] = Field(default=None, description="Extracted URLs list")
    received_hops: Optional[List[Dict[str, Any]]] = Field(default=None, description="Received hops list")


class EmailAnalysisResponse(BaseModel):
    """API response contract for POST /api/v1/emails/analyze."""
    analysis_id: str = Field(description="Unique analysis run identifier")
    email_id: str = Field(description="Normalized message identifier")
    risk: RiskResult = Field(description="Calculated composite risk result")
    classification: str = Field(description="Threat classification verdict string")
    decision: PolicyDecision = Field(description="Final delivery policy decision")
    analyzer_results: Dict[str, AnalyzerResultItem] = Field(default_factory=dict, description="Detailed per-analyzer results")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Aggregated deduplicated security findings")
    tags: List[str] = Field(default_factory=list, description="Extracted security tags")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Response timestamp")

