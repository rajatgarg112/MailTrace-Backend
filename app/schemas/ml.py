from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class MLModelStatus(str, Enum):
    """ML model inference execution status."""
    SUCCESS = "SUCCESS"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    INFERENCE_ERROR = "INFERENCE_ERROR"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


class MLPredictionResult(BaseModel):
    """Canonical contract for ML/NLP inference output returned by M3 ML branch."""
    model_name: str = Field(description="Name of the ML model/pipeline")
    model_version: str = Field(description="Version of the model artifact used")
    status: MLModelStatus = Field(default=MLModelStatus.SUCCESS, description="Status of ML inference")
    prediction: Optional[str] = Field(default=None, description="Primary prediction, e.g. PHISHING, SPAM, BEC, SAFE")
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Model confidence score between 0.0 and 1.0")
    scores: Dict[str, float] = Field(default_factory=dict, description="Detailed category/signal scores")
    features_used: List[str] = Field(default_factory=list, description="List of feature names extracted and evaluated")
    inference_time_ms: Optional[float] = Field(default=None, ge=0.0, description="Inference execution latency in milliseconds")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Inference timestamp")
    error_message: Optional[str] = Field(default=None, description="Error detail if status is not SUCCESS")
