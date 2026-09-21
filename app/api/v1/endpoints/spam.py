from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.db.database import get_db
from app.repositories.decision_repository import DecisionRepository
from app.repositories.email_repository import EmailRepository
from app.api.v1.endpoints.emails import serialize_email

router = APIRouter()


@router.get(
    "",
    summary="List spam emails",
    description="Retrieves persisted emails routed to spam or classified as spam.",
)
async def list_spam_emails_endpoint(
    category: Optional[str] = Query(None, description="Spam category filter (e.g. Marketing, Scam, Bulk)"),
    search: Optional[str] = Query(None, description="Search term in subject or sender"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    email_repo = EmailRepository(db)
    emails = email_repo.query_filtered(
        action="SPAM",
        category=category,
        search=search,
        limit=limit,
        offset=offset,
    )
    if not emails and not category and not search:
        # Fallback to classification=SPAM if no action=SPAM records
        emails = email_repo.query_filtered(
            classification="SPAM",
            limit=limit,
            offset=offset,
        )

    return [serialize_email(e, db) for e in emails]


@router.get(
    "/{email_id}",
    summary="Retrieve single spam email",
    description="Retrieves a specific spam email. Returns 404 if not found or not spam.",
)
async def get_spam_email_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Spam email '{email_id}' not found")

    decision_repo = DecisionRepository(db)
    decision = decision_repo.get_latest_decision_for_email(email.id)

    serialized = serialize_email(email, db)
    if serialized["action"] != "SPAM" and serialized["classification"] != "SPAM":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' is not classified as spam")

    return serialized
