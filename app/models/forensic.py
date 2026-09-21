import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    JSON,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.analysis import AnalysisRun
    from app.models.email import Email
    from app.models.user import User


def generate_uuid() -> str:
    return str(uuid.uuid4())


case_emails = Table(
    "case_emails",
    Base.metadata,
    Column("case_id", String(36), ForeignKey("forensic_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("email_id", String(36), ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True),
    Column("added_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

case_evidence = Table(
    "case_evidence",
    Base.metadata,
    Column("case_id", String(36), ForeignKey("forensic_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", String(36), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
    Column("added_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    analysis_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), index=True, nullable=True
    )
    evidence_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    extracted_facts: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, server_default=func.now(), nullable=False
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="evidence")
    analysis_run: Mapped[Optional["AnalysisRun"]] = relationship("AnalysisRun", back_populates="evidence")
    forensic_cases: Mapped[List["ForensicCase"]] = relationship(
        "ForensicCase", secondary=case_evidence, back_populates="evidence"
    )

    def __repr__(self) -> str:
        return f"<Evidence(id='{self.id}', type='{self.evidence_type}', sha256='{self.sha256_hash[:10]}...')>"


class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", index=True, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    assigned_user: Mapped[Optional["User"]] = relationship("User", back_populates="assigned_cases")
    emails: Mapped[List["Email"]] = relationship("Email", secondary=case_emails, back_populates="forensic_cases")
    evidence: Mapped[List["Evidence"]] = relationship(
        "Evidence", secondary=case_evidence, back_populates="forensic_cases"
    )

    def __repr__(self) -> str:
        return f"<ForensicCase(id='{self.id}', title='{self.title}', status='{self.status}')>"
