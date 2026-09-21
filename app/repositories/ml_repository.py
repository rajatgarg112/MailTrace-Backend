"""
ML repository for managing MLResult persistence operations.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ml import MLResult


class MLRepository:
    """
    Repository handling persistence for MLResult entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        analysis_id: str,
        email_id: str,
        model_name: str,
        model_version: str,
        status: str = "SUCCESS",
        prediction: Optional[str] = None,
        confidence: Optional[float] = None,
        scores: Optional[Dict[str, Any]] = None,
        features_used: Optional[List[str]] = None,
        inference_time_ms: Optional[float] = None,
        error_message: Optional[str] = None,
        result_id: Optional[str] = None,
    ) -> MLResult:
        """Creates and persists an MLResult entity."""
        result = MLResult(
            analysis_id=analysis_id,
            email_id=email_id,
            model_name=model_name.strip(),
            model_version=model_version.strip(),
            status=status,
            prediction=prediction,
            confidence=confidence,
            scores=scores or {},
            features_used=features_used or [],
            inference_time_ms=inference_time_ms,
            error_message=error_message,
        )
        if result_id:
            result.id = result_id
        self.session.add(result)
        self.session.flush()
        return result

    def get_by_analysis(self, analysis_id: str) -> List[MLResult]:
        """Retrieves all ML results produced during a specific analysis run."""
        stmt = (
            select(MLResult)
            .where(MLResult.analysis_id == analysis_id)
            .order_by(MLResult.created_at.asc())
        )
        return list(self.session.scalars(stmt).all())

    def get_by_email(self, email_id: str) -> List[MLResult]:
        """Retrieves all ML results associated with an email across all runs."""
        stmt = (
            select(MLResult)
            .where(MLResult.email_id == email_id)
            .order_by(MLResult.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())
