from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Documented project risk level classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskResult(BaseModel):
    """Risk calculation output contract."""
    overall_risk_score: float = Field(ge=0.0, le=100.0, description="Composite risk score from 0 to 100")
    risk_level: RiskLevel = Field(description="Categorical risk level")
    threat_confidence: float = Field(ge=0.0, le=1.0, description="Overall threat confidence between 0.0 and 1.0")
    contributing_findings: List[str] = Field(default_factory=list, description="List of finding codes or tags that contributed to risk")
    explanation: Optional[str] = Field(default=None, description="Human-readable explainability summary")
