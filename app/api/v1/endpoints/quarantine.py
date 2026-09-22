from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.db.database import get_db
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.decision_repository import DecisionRepository
from app.repositories.email_repository import EmailRepository
from app.repositories.forensic_repository import ForensicRepository
from app.repositories.security_repository import SecurityRepository
from app.api.v1.endpoints.emails import serialize_email

router = APIRouter()


def _build_sanitized_quarantine_item(email, db: Session) -> Dict[str, Any]:
    serialized = serialize_email(email, db)
    analysis_repo = AnalysisRepository(db)
    security_repo = SecurityRepository(db)
    decision_repo = DecisionRepository(db)

    run = analysis_repo.get_latest_for_email(email.id)
    findings = security_repo.get_findings_for_email(email.id)
    decision = decision_repo.get_latest_decision_for_email(email.id)

    serialized_findings = [
        {
            "id": f.id,
            "code": f.code,
            "severity": f.severity,
            "description": f.description,
            "details": f.details or {},
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]

    reason = decision.reason if decision else "Content isolated by pre-delivery security gateway policy."

    sanitized_report = {
        "email_id": email.id,
        "sender_address": email.sender_address,
        "subject": email.subject or "",
        "classification": serialized["classification"],
        "risk_score": serialized["risk_score"],
        "reason": reason,
        "security_tags": serialized["tags"],
        "findings": serialized_findings,
        "warning_notice": "Original raw body and active payloads blocked due to security policy enforcement.",
    }

    return {
        "id": email.id,
        "quarantine_id": f"quar-{email.id[:8]}",
        "email_id": email.id,
        "emailId": email.id,
        "subject": email.subject or "",
        "sender": email.sender_address,
        "senderName": email.sender_name or email.sender_address,
        "recipient": serialized["recipient"],
        "timestamp": serialized["timestamp"],
        "displayTime": serialized["displayTime"],
        "classification": serialized["classification"],
        "action": "QUARANTINE",
        "riskScore": serialized["riskScore"],
        "risk_score": serialized["risk_score"],
        "confidence": serialized["confidence"],
        "tags": serialized["tags"],
        "security_tags": serialized["tags"],
        "provenance": "VERIFIED_EVIDENCE",
        "gateway_category": decision.gateway_category if decision else "MALICIOUS",
        "reason": reason,
        "warningReason": reason,
        "forensicSummary": reason,
        "sanitized_report": sanitized_report,
        "original_content_blocked": True,
        "attachments_blocked": True,
        "unread": True,
    }


@router.get(
    "",
    summary="List quarantined emails",
    description="Retrieves persisted emails isolated in quarantine. Returns sanitized security summaries without exposing raw malicious payloads.",
)
async def list_quarantine_endpoint(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    email_repo = EmailRepository(db)
    emails = email_repo.query_filtered(
        action="QUARANTINE",
        limit=limit,
        offset=offset,
    )
    if not emails:
        emails = email_repo.query_filtered(
            classification="MALICIOUS",
            limit=limit,
            offset=offset,
        )

    return [_build_sanitized_quarantine_item(e, db) for e in emails]


@router.get(
    "/{email_id}",
    summary="Retrieve single quarantined email sanitized report",
    description="Returns a sanitized security report for a quarantined email. Returns 404 if not found or not quarantined.",
)
async def get_quarantine_item_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Quarantined email '{email_id}' not found")

    decision_repo = DecisionRepository(db)
    decision = decision_repo.get_latest_decision_for_email(email.id)
    serialized = serialize_email(email, db)

    if serialized["action"] != "QUARANTINE" and serialized["classification"] != "MALICIOUS":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' is not quarantined")

    return _build_sanitized_quarantine_item(email, db)


@router.post(
    "/{email_id}/release",
    summary="Release quarantined email to recipient inbox",
)
async def release_quarantined_email_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    decision_repo = DecisionRepository(db)
    decision = decision_repo.get_latest_decision_for_email(email.id)
    if decision:
        decision.action = "INBOX"
        decision.reason = "Approved and released to recipient by SOC Administrator."
        decision_repo.create_delivery_event(
            email_id=email.id,
            action="RELEASED",
            status="COMPLETED",
            policy_decision_id=decision.id,
            reason="SOC Administrator manual release",
        )

    forensic_repo = ForensicRepository(db)
    case = forensic_repo.get_case_for_email(email.id)
    if case:
        case.status = "RESOLVED"
        case.description = f"{case.description or ''}\n[SOC Admin Decision]: Approved & Delivered to Recipient."

    db.commit()

    return {
        "status": "RELEASED",
        "message": f"Email '{email.id}' successfully released to recipient inbox.",
        "email": serialize_email(email, db),
    }


@router.post(
    "/{email_id}/block",
    summary="Confirm threat and permanently block quarantined email",
)
async def block_quarantined_email_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    decision_repo = DecisionRepository(db)
    decision = decision_repo.get_latest_decision_for_email(email.id)
    if decision:
        decision.action = "REJECT"
        decision.reason = "Confirmed threat: Permanently blocked by SOC Administrator."
        decision_repo.create_delivery_event(
            email_id=email.id,
            action="BLOCKED",
            status="COMPLETED",
            policy_decision_id=decision.id,
            reason="SOC Administrator manual block confirmation",
        )

    forensic_repo = ForensicRepository(db)
    case = forensic_repo.get_case_for_email(email.id)
    if case:
        case.status = "RESOLVED"
        case.description = f"{case.description or ''}\n[SOC Admin Decision]: Confirmed Threat & Blocked."

    db.commit()

    return {
        "status": "BLOCKED",
        "message": f"Email '{email.id}' confirmed as threat and blocked.",
        "email": serialize_email(email, db),
    }
