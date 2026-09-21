import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

if TYPE_CHECKING:
    from app.models.email import Email
    from app.models.forensic import ForensicCase


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    mailboxes: Mapped[List["Mailbox"]] = relationship("Mailbox", back_populates="user", cascade="all, delete-orphan")
    emails: Mapped[List["Email"]] = relationship("Email", back_populates="user")
    assigned_cases: Mapped[List["ForensicCase"]] = relationship("ForensicCase", back_populates="assigned_user")

    def __repr__(self) -> str:
        return f"<User(id='{self.id}', email='{self.email}', role='{self.role}')>"


class Mailbox(Base):
    __tablename__ = "mailboxes"
    __table_args__ = (
        UniqueConstraint("user_id", "email_address", name="uq_mailbox_user_address"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True
    )
    email_address: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    mailbox_type: Mapped[str] = mapped_column(String(50), default="INBOX", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="mailboxes")
    emails: Mapped[List["Email"]] = relationship("Email", back_populates="mailbox")

    def __repr__(self) -> str:
        return f"<Mailbox(id='{self.id}', email_address='{self.email_address}', type='{self.mailbox_type}')>"
