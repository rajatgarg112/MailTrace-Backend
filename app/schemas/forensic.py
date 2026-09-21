from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ForensicTimelineEvent(BaseModel):
    """Forensic timeline event contract."""
    event_id: str = Field(description="Unique timeline event identifier")
    case_id: str = Field(description="Associated forensic case identifier")
    event_type: str = Field(description="Event type, e.g. INGESTION, ANALYSIS_COMPLETE, POLICIED, QUARANTINED")
    description: str = Field(description="Human-readable event summary")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Event timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Event supporting metadata")


class ForensicCase(BaseModel):
    """Forensic case investigation contract."""
    case_id: str = Field(description="Unique forensic case identifier")
    title: str = Field(description="Case title/heading")
    description: Optional[str] = Field(default=None, description="Detailed investigation notes")
    email_ids: List[str] = Field(default_factory=list, description="Associated email IDs")
    evidence_ids: List[str] = Field(default_factory=list, description="Associated evidence IDs")
    tags: List[str] = Field(default_factory=list, description="Investigation tags")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Case creation timestamp")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Case update timestamp")
