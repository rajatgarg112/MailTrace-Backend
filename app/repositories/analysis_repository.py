"""
Analysis repository for managing AnalysisRun persistence operations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import AnalysisRun


class AnalysisRepository:
    """
    Repository handling persistence for AnalysisRun entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        email_id: str,
        status: str = "SUCCESS",
        overall_risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        threat_confidence: Optional[float] = None,
        classification: Optional[str] = None,
        canonical_features: Optional[Dict[str, Any]] = None,
        analyzer_results: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        analysis_id: Optional[str] = None,
    ) -> AnalysisRun:
        """Creates and persists an AnalysisRun entity."""
        run = AnalysisRun(
            email_id=email_id,
            status=status,
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            threat_confidence=threat_confidence,
            classification=classification,
            canonical_features=canonical_features,
            analyzer_results=analyzer_results or {},
            errors=errors or [],
            completed_at=completed_at,
        )
        if started_at:
            run.started_at = started_at
        if analysis_id:
            run.id = analysis_id
        self.session.add(run)
        self.session.flush()
        return run

    def get_by_id(
        self,
        analysis_id: str,
        load_findings: bool = False,
        load_tags: bool = False,
    ) -> Optional[AnalysisRun]:
        """Retrieves an AnalysisRun by its ID, with optional eager loading."""
        stmt = select(AnalysisRun).where(AnalysisRun.id == analysis_id)
        if load_findings:
            stmt = stmt.options(selectinload(AnalysisRun.findings))
        if load_tags:
            stmt = stmt.options(selectinload(AnalysisRun.tags))
        return self.session.scalars(stmt).first()

    def get_history_for_email(
        self,
        email_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AnalysisRun]:
        """Retrieves analysis runs associated with an email ordered by creation date descending."""
        stmt = (
            select(AnalysisRun)
            .where(AnalysisRun.email_id == email_id)
            .order_by(AnalysisRun.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(stmt).all())

    def update_status_result(
        self,
        analysis_id: str,
        status: Optional[str] = None,
        overall_risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        threat_confidence: Optional[float] = None,
        classification: Optional[str] = None,
        canonical_features: Optional[Dict[str, Any]] = None,
        analyzer_results: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
        completed_at: Optional[datetime] = None,
    ) -> Optional[AnalysisRun]:
        """Updates status, verdict scores, and outputs for an active AnalysisRun."""
        run = self.get_by_id(analysis_id)
        if not run:
            return None

        if status is not None:
            run.status = status
        if overall_risk_score is not None:
            run.overall_risk_score = overall_risk_score
        if risk_level is not None:
            run.risk_level = risk_level
        if threat_confidence is not None:
            run.threat_confidence = threat_confidence
        if classification is not None:
            run.classification = classification
        if canonical_features is not None:
            run.canonical_features = canonical_features
        if analyzer_results is not None:
            run.analyzer_results = analyzer_results
        if errors is not None:
            run.errors = errors
        if completed_at is not None:
            run.completed_at = completed_at

        self.session.flush()
        return run
