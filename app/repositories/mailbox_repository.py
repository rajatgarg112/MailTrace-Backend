"""
Mailbox repository for managing Mailbox persistence operations.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import Mailbox


class MailboxRepository:
    """
    Repository handling persistence for Mailbox entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        email_address: str,
        user_id: Optional[str] = None,
        mailbox_type: str = "INBOX",
        is_active: bool = True,
        mailbox_id: Optional[str] = None,
    ) -> Mailbox:
        """Creates and persists a new Mailbox."""
        mailbox = Mailbox(
            email_address=email_address.strip().lower(),
            user_id=user_id,
            mailbox_type=mailbox_type,
            is_active=is_active,
        )
        if mailbox_id:
            mailbox.id = mailbox_id
        self.session.add(mailbox)
        self.session.flush()
        return mailbox

    def get_by_id(self, mailbox_id: str) -> Optional[Mailbox]:
        """Retrieves a Mailbox by its unique ID."""
        stmt = select(Mailbox).where(Mailbox.id == mailbox_id)
        return self.session.scalars(stmt).first()

    def get_by_email_address(
        self,
        email_address: str,
        user_id: Optional[str] = None,
    ) -> Optional[Mailbox]:
        """Retrieves a Mailbox by its email address and optional user_id."""
        stmt = select(Mailbox).where(Mailbox.email_address == email_address.strip().lower())
        if user_id is not None:
            stmt = stmt.where(Mailbox.user_id == user_id)
        return self.session.scalars(stmt).first()

    def list_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Mailbox]:
        """Lists all mailboxes assigned to a specific User with pagination."""
        stmt = (
            select(Mailbox)
            .where(Mailbox.user_id == user_id)
            .order_by(Mailbox.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(stmt).all())
