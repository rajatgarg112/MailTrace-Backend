from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from app.core.config import settings
from app.schemas.email import EmailNormalized


class AnalysisContext(BaseModel):
    """Immutable input context passed safely to email analyzers."""
    
    analysis_id: str = Field(description="Unique analysis run identifier")
    email: EmailNormalized = Field(description="Normalized email data contract")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context metadata")
    timeout_seconds: float = Field(
        default_factory=lambda: settings.ANALYZER_TIMEOUT_SECONDS,
        ge=0.1,
        description="Execution timeout budget in seconds"
    )

    model_config = {
        "frozen": True,
        "arbitrary_types_allowed": True
    }
