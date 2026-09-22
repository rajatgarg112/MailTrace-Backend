"""
Email repository for managing Email persistence operations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email import Email


class EmailRepository:
    """
    Repository handling persistence for Email entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        message_id: str,
        sender_address: str,
        received_at: datetime,
        sender_name: Optional[str] = None,
        recipients: Optional[List[Dict[str, Any]]] = None,
        reply_to: Optional[List[Dict[str, Any]]] = None,
        subject: str = "",
        headers: Optional[Dict[str, Any]] = None,
        body_text_preview: Optional[str] = None,
        attachment_metadata: Optional[List[Dict[str, Any]]] = None,
        urls: Optional[List[Dict[str, Any]]] = None,
        received_hops: Optional[List[Dict[str, Any]]] = None,
        mailbox_id: Optional[str] = None,
        user_id: Optional[str] = None,
        email_id: Optional[str] = None,
    ) -> Email:
        """Creates and persists a normalized Email entity."""
        email = Email(
            message_id=message_id.strip(),
            sender_address=sender_address.strip().lower(),
            sender_name=sender_name,
            recipients=recipients or [],
            reply_to=reply_to,
            subject=subject,
            headers=headers or {},
            body_text_preview=body_text_preview,
            attachment_metadata=attachment_metadata or [],
            urls=urls or [],
            received_hops=received_hops or [],
            received_at=received_at,
            mailbox_id=mailbox_id,
            user_id=user_id,
        )
        if email_id:
            email.id = email_id
        self.session.add(email)
        self.session.flush()
        return email

    def get_by_id(self, email_id: str) -> Optional[Email]:
        """Retrieves an Email by primary key ID."""
        stmt = select(Email).where(Email.id == email_id)
        return self.session.scalars(stmt).first()

    def get_by_message_id(self, message_id: str) -> Optional[Email]:
        """Retrieves an Email by its unique RFC 5322 Message-ID."""
        stmt = select(Email).where(Email.message_id == message_id.strip())
        return self.session.scalars(stmt).first()

    def list(self, limit: int = 50, offset: int = 0) -> List[Email]:
        """Lists emails ordered by received timestamp descending."""
        stmt = select(Email).order_by(Email.received_at.desc()).limit(limit).offset(offset)
        return list(self.session.scalars(stmt).all())

    def query_by_sender(
        self,
        sender_address: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Email]:
        """Queries emails from a specific sender address using the sender index."""
        stmt = (
            select(Email)
            .where(Email.sender_address == sender_address.strip().lower())
            .order_by(Email.received_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(stmt).all())

    def query_by_mailbox(
        self,
        mailbox_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Email]:
        """Queries emails belonging to a specific mailbox using the mailbox_id index."""
        stmt = (
            select(Email)
            .where(Email.mailbox_id == mailbox_id)
            .order_by(Email.received_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(stmt).all())

    def query_by_received_at(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Email]:
        """Queries emails within a received timestamp range using the received_at index."""
        stmt = select(Email).where(Email.received_at >= start_date)
        if end_date is not None:
            stmt = stmt.where(Email.received_at <= end_date)
        stmt = stmt.order_by(Email.received_at.desc()).limit(limit).offset(offset)
        return list(self.session.scalars(stmt).all())

    def get_by_identifier(self, identifier: str) -> Optional[Email]:
        """Retrieves an Email by primary key ID or RFC 5322 Message-ID."""
        clean_id = identifier.strip()
        email = self.get_by_id(clean_id)
        if not email:
            email = self.get_by_message_id(clean_id)
        if not email and (clean_id.startswith("thr-") or clean_id.startswith("quar-")):
            short_id = clean_id.split("-", 1)[1]
            stmt = select(Email).where(Email.id.startswith(short_id))
            email = self.session.scalars(stmt).first()
        return email

    def query_filtered(
        self,
        action: Optional[str] = None,
        classification: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Email]:
        """Queries emails filtered by policy action, threat classification, category, or text search."""
        if action or classification or category:
            from app.models.decision import PolicyDecision
            stmt = select(Email).join(Email.policy_decisions)
            if action:
                stmt = stmt.where(PolicyDecision.action == action.strip().upper())
            if classification:
                stmt = stmt.where(PolicyDecision.classification == classification.strip().upper())
            if category:
                stmt = stmt.where(
                    (PolicyDecision.spam_category.ilike(category.strip())) |
                    (PolicyDecision.gateway_category.ilike(category.strip()))
                )
        else:
            stmt = select(Email)

        if search:
            term = f"%{search.strip()}%"
            stmt = stmt.where((Email.subject.ilike(term)) | (Email.sender_address.ilike(term)))

        stmt = stmt.order_by(Email.received_at.desc()).limit(limit).offset(offset)
        return list(self.session.scalars(stmt).unique().all())
