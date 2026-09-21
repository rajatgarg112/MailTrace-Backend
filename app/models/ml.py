import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.analysis import AnalysisRun
    from app.models.email import Email


def generate_uuid() -> str:
    return str(uuid.uuid4())


class MLResult(Base):
    __tablename__ = "ml_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="SUCCESS", index=True, nullable=False)
    prediction: Mapped[Optional[str]] = mapped_column(String(50), index=True, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    scores: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    features_used: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    inference_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="ml_results")
    email: Mapped["Email"] = relationship("Email", back_populates="ml_results")

    def __repr__(self) -> str:
        return f"<MLResult(id='{self.id}', model='{self.model_name}', prediction='{self.prediction}', confidence={self.confidence})>"
