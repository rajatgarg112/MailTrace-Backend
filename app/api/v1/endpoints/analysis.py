from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.db.database import get_db
from app.repositories.analysis_repository import AnalysisRepository

router = APIRouter()


@router.get(
    "/{analysis_id}",
    summary="Retrieve an AnalysisRun by ID",
    description="Retrieves a persisted analysis run including analyzer results, canonical features, risk score, classification, and tags.",
)
async def get_analysis_run_endpoint(
    analysis_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    analysis_repo = AnalysisRepository(db)
    run = analysis_repo.get_by_id(analysis_id, load_findings=True, load_tags=True)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Analysis run '{analysis_id}' not found")

    return {
        "id": run.id,
        "analysis_id": run.id,
        "email_id": run.email_id,
        "status": run.status,
        "overall_risk_score": run.overall_risk_score,
        "risk_level": run.risk_level,
        "threat_confidence": run.threat_confidence,
        "classification": run.classification,
        "canonical_features": run.canonical_features,
        "analyzer_results": run.analyzer_results,
        "errors": run.errors,
        "tags": [t.name for t in run.tags] if run.tags else [],
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }
