import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.analysis import AnalysisRun
    from app.models.email import DeliveryEvent, Email


def generate_uuid() -> str:
    return str(uuid.uuid4())


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    classification: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    spam_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    gateway_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, server_default=func.now(), nullable=False
    )

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="policy_decisions")
    email: Mapped["Email"] = relationship("Email", back_populates="policy_decisions")
    delivery_events: Mapped[List["DeliveryEvent"]] = relationship(
        "DeliveryEvent", back_populates="policy_decision"
    )

    def __repr__(self) -> str:
        return f"<PolicyDecision(id='{self.id}', email_id='{self.email_id}', action='{self.action}', classification='{self.classification}')>"
