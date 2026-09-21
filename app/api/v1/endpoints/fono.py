from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.db.database import get_db
from app.models.decision import PolicyDecision
from app.models.email import Email
from app.repositories.email_repository import EmailRepository
from app.api.v1.endpoints.emails import serialize_email

router = APIRouter()


@router.get(
    "/overview",
    summary="User mail overview dashboard metrics and recent deliveries",
)
async def get_fono_overview_endpoint(
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email_repo = EmailRepository(db)
    emails = email_repo.list(limit=50)

    total_received = len(emails)
    inbox_count = 0
    spam_count = 0
    warning_count = 0
    quarantine_count = 0

    decisions = list(db.scalars(select(PolicyDecision)).all())
    for d in decisions:
        act = (d.action or "").upper()
        if act == "INBOX":
            inbox_count += 1
        elif act == "SPAM":
            spam_count += 1
        elif act in ("WARN", "HOLD"):
            warning_count += 1
        elif act in ("QUARANTINE", "REJECT"):
            quarantine_count += 1

    threats_blocked = quarantine_count + warning_count

    recent_deliveries = [serialize_email(e, db) for e in emails[:5]]

    return {
        "stats": {
            "totalReceived": total_received,
            "inboxCount": inbox_count,
            "spamCount": spam_count,
            "warningCount": warning_count,
            "quarantineCount": quarantine_count,
            "threatsBlocked": threats_blocked,
        },
        "recentDeliveries": recent_deliveries,
    }
