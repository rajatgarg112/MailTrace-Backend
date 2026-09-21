from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.db.database import get_db
from app.repositories.forensic_repository import ForensicRepository

router = APIRouter()


class CreateCaseRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = Field(default="OPEN")
    severity: Optional[str] = Field(default="HIGH")
    tags: Optional[List[str]] = Field(default_factory=list)
    assigned_to: Optional[str] = None
    email_id: Optional[str] = None
    evidence_id: Optional[str] = None


def _serialize_case(case, load_relations: bool = True) -> Dict[str, Any]:
    emails = []
    evidence = []
    if load_relations:
        if hasattr(case, "emails") and case.emails:
            emails = [{"id": e.id, "subject": e.subject, "sender": e.sender_address} for e in case.emails]
        if hasattr(case, "evidence") and case.evidence:
            evidence = [{"id": ev.id, "sha256": ev.sha256_hash, "type": ev.evidence_type} for ev in case.evidence]

    return {
        "id": case.id,
        "caseId": case.id,
        "case_id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "assignedTo": case.assigned_to,
        "assigned_to": case.assigned_to,
        "tags": case.tags or [],
        "emails": emails,
        "email_ids": [e["id"] for e in emails],
        "evidence": evidence,
        "evidence_ids": [ev["id"] for ev in evidence],
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }


@router.get(
    "",
    summary="List forensic cases",
    description="Retrieves persisted forensic investigation cases with optional status and severity filtering.",
)
async def list_cases_endpoint(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (e.g. OPEN, RESOLVED, CLOSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (e.g. CRITICAL, HIGH, MEDIUM, LOW)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    forensic_repo = ForensicRepository(db)
    cases = forensic_repo.list_cases(
        status=status_filter,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return [_serialize_case(c, load_relations=False) for c in cases]


@router.get(
    "/{case_id}",
    summary="Retrieve single forensic case",
    description="Retrieves a specific forensic case by ID including associated emails and evidence artifacts.",
)
async def get_case_endpoint(
    case_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    forensic_repo = ForensicRepository(db)
    case = forensic_repo.get_case_by_id(case_id, load_emails=True, load_evidence=True)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Forensic case '{case_id}' not found")
    return _serialize_case(case, load_relations=True)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create a forensic investigation case",
)
async def create_case_endpoint(
    payload: CreateCaseRequest,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    forensic_repo = ForensicRepository(db)
    case = forensic_repo.create_case(
        title=payload.title,
        description=payload.description,
        status=payload.status,
        severity=payload.severity,
        tags=payload.tags,
        assigned_to=payload.assigned_to,
    )

    if payload.email_id:
        forensic_repo.attach_email_to_case(case.id, payload.email_id)
    if payload.evidence_id:
        forensic_repo.attach_evidence_to_case(case.id, payload.evidence_id)

    db.commit()
    case_loaded = forensic_repo.get_case_by_id(case.id, load_emails=True, load_evidence=True)
    return _serialize_case(case_loaded, load_relations=True)
