import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.analysis import AnalysisRun, SecurityFinding
    from app.models.decision import PolicyDecision
    from app.models.forensic import Evidence, ForensicCase
    from app.models.ml import MLResult
    from app.models.user import Mailbox, User


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    message_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    mailbox_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("mailboxes.id", ondelete="SET NULL"), index=True, nullable=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    sender_address: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    sender_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recipients: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    reply_to: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    subject: Mapped[str] = mapped_column(String(998), default="", nullable=False)
    headers: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    body_text_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attachment_metadata: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    urls: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    received_hops: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="emails")
    mailbox: Mapped[Optional["Mailbox"]] = relationship("Mailbox", back_populates="emails")
    analysis_runs: Mapped[List["AnalysisRun"]] = relationship(
        "AnalysisRun", back_populates="email", cascade="all, delete-orphan"
    )
    delivery_events: Mapped[List["DeliveryEvent"]] = relationship(
        "DeliveryEvent", back_populates="email", cascade="all, delete-orphan"
    )
    policy_decisions: Mapped[List["PolicyDecision"]] = relationship(
        "PolicyDecision", back_populates="email", cascade="all, delete-orphan"
    )
    security_findings: Mapped[List["SecurityFinding"]] = relationship(
        "SecurityFinding", back_populates="email", cascade="all, delete-orphan"
    )
    ml_results: Mapped[List["MLResult"]] = relationship(
        "MLResult", back_populates="email", cascade="all, delete-orphan"
    )
    evidence: Mapped[List["Evidence"]] = relationship(
        "Evidence", back_populates="email", cascade="all, delete-orphan"
    )
    forensic_cases: Mapped[List["ForensicCase"]] = relationship(
        "ForensicCase", secondary="case_emails", back_populates="emails"
    )

    def __repr__(self) -> str:
        return f"<Email(id='{self.id}', message_id='{self.message_id}', sender='{self.sender_address}')>"


class DeliveryEvent(Base):
    __tablename__ = "delivery_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    policy_decision_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("policy_decisions.id", ondelete="SET NULL"), index=True, nullable=True
    )
    action: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="COMPLETED", index=True, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, server_default=func.now(), nullable=False
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="delivery_events")
    policy_decision: Mapped[Optional["PolicyDecision"]] = relationship("PolicyDecision", back_populates="delivery_events")

    def __repr__(self) -> str:
        return f"<DeliveryEvent(id='{self.id}', email_id='{self.email_id}', action='{self.action}', status='{self.status}')>"
