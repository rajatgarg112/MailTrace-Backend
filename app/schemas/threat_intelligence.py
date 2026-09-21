from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatIntelStatus(str, Enum):
    """Threat intelligence provider query status."""
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class IndicatorType(str, Enum):
    """Supported threat intelligence indicator types."""
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"
    EMAIL = "EMAIL"


class ThreatIntelResult(BaseModel):
    """Contract for external threat-intelligence adapter outputs."""
    provider: str = Field(description="Name of threat intel provider, e.g. VirusTotal, AbuseIPDB")
    indicator_type: IndicatorType = Field(description="Type of indicator queried")
    indicator_value: str = Field(description="Queried indicator value")
    status: ThreatIntelStatus = Field(default=ThreatIntelStatus.UNKNOWN, description="Query status")
    reputation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Reputation score normalized between 0.0 and 1.0")
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Provider confidence score")
    matches: List[str] = Field(default_factory=list, description="List of matched threat names or categories")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Query timestamp")
    error_detail: Optional[str] = Field(default=None, description="Error explanation if status is UNAVAILABLE or ERROR")
