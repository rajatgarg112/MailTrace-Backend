import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    DateTime,
    Float,
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
    from app.models.decision import PolicyDecision
    from app.models.email import Email
    from app.models.forensic import Evidence
    from app.models.ml import MLResult


def generate_uuid() -> str:
    return str(uuid.uuid4())


analysis_run_tags = Table(
    "analysis_run_tags",
    Base.metadata,
    Column("analysis_id", String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", String(36), ForeignKey("security_tags.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), default="SUCCESS", index=True, nullable=False)
    overall_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(50), index=True, nullable=True)
    threat_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    classification: Mapped[Optional[str]] = mapped_column(String(50), index=True, nullable=True)
    canonical_features: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    analyzer_results: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    errors: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, server_default=func.now(), nullable=False
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="analysis_runs")
    findings: Mapped[List["SecurityFinding"]] = relationship(
        "SecurityFinding", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    tags: Mapped[List["SecurityTag"]] = relationship(
        "SecurityTag", secondary=analysis_run_tags, back_populates="analysis_runs"
    )
    ml_results: Mapped[List["MLResult"]] = relationship(
        "MLResult", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    policy_decisions: Mapped[List["PolicyDecision"]] = relationship(
        "PolicyDecision", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    evidence: Mapped[List["Evidence"]] = relationship("Evidence", back_populates="analysis_run")

    def __repr__(self) -> str:
        return f"<AnalysisRun(id='{self.id}', email_id='{self.email_id}', status='{self.status}', classification='{self.classification}')>"


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="findings")
    email: Mapped["Email"] = relationship("Email", back_populates="security_findings")

    def __repr__(self) -> str:
        return f"<SecurityFinding(id='{self.id}', code='{self.code}', severity='{self.severity}')>"


class SecurityTag(Base):
    __tablename__ = "security_tags"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    analysis_runs: Mapped[List["AnalysisRun"]] = relationship(
        "AnalysisRun", secondary=analysis_run_tags, back_populates="tags"
    )

    def __repr__(self) -> str:
        return f"<SecurityTag(id='{self.id}', name='{self.name}', category='{self.category}')>"
