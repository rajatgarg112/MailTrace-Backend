"""
Canonical schemas for ML/AI analyzers matching SECURITY_FEATURE_SCHEMA.md and ANALYSIS_PIPELINE.md.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator


class Finding(BaseModel):
    """Specific security finding emitted by an analyzer."""
    code: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    details: Optional[str] = None


class AnalyzerResult(BaseModel):
    """Standard analyzer output contract as defined in ANALYSIS_PIPELINE.md."""
    analyzer: str
    status: str = "SUCCESS"  # "SUCCESS", "UNAVAILABLE", "ERROR"
    features: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    error_message: Optional[str] = None


class MLPredictionResult(BaseModel):
    """Structured result model for ML classifier inference."""
    prediction: str = Field(..., description="Highest-probability predicted class label")
    confidence: float = Field(..., description="Maximum predicted class probability score [0.0, 1.0]")
    model_version: str = Field(default="1.0", description="Model version string")
    probabilities: Dict[str, float] = Field(default_factory=dict, description="Full class probability distribution")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence must be bounded to [0.0, 1.0], got {v}")
        return round(float(v), 4)

    @field_validator("prediction")
    @classmethod
    def validate_prediction(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("Prediction label must be a non-empty string.")
        return v.strip()


class MLEngineResult(BaseModel):
    """Unified container for all ML module signals emitted by analyze_email_ml()."""
    prediction: MLPredictionResult
    nlp: AnalyzerResult
    bec: AnalyzerResult
    behavioral: AnalyzerResult


class ContentNLPFeatures(BaseModel):
    """Canonical Category 5: Content / NLP Features."""
    spam_score: float = 0.0
    phishing_score: float = 0.0
    urgency_score: float = 0.0
    fear_score: float = 0.0
    credential_request_score: float = 0.0
    financial_request_score: float = 0.0
    social_engineering_score: float = 0.0
    impersonation_language_score: float = 0.0
    call_to_action_score: float = 0.0
    suspicious_keyword_score: float = 0.0
    sentiment_score: float = 0.0
    language: str = "en"
    text_entropy: float = 0.0


class BECFeatures(BaseModel):
    """Canonical Category 10: BEC / Impersonation Features."""
    executive_impersonation_score: float = 0.0
    brand_impersonation_score: float = 0.0
    payment_request_score: float = 0.0
    invoice_request_score: float = 0.0
    bank_account_change_score: float = 0.0
    gift_card_request_score: float = 0.0
    urgency_score: float = 0.0
    conversation_hijacking_score: float = 0.0
    authority_impersonation_score: float = 0.0


class BehavioralFeatures(BaseModel):
    """Canonical Category 7: Behavioral Features."""
    sending_frequency: float = 0.0
    volume_anomaly: float = 0.0
    time_anomaly: float = 0.0
    location_anomaly: float = 0.0
    sender_behavior_change: float = 0.0
    conversation_anomaly: float = 0.0
    recipient_count: int = 1
    bulk_score: float = 0.0
    historical_similarity: float = 1.0
    conversation_exists: bool = False
