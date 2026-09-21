"""
User repository for managing User persistence operations.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    """
    Repository handling persistence for User entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        email: str,
        full_name: Optional[str] = None,
        role: str = "analyst",
        is_active: bool = True,
        user_id: Optional[str] = None,
    ) -> User:
        """Creates and persists a new User."""
        user = User(
            email=email.strip().lower(),
            full_name=full_name,
            role=role,
            is_active=is_active,
        )
        if user_id:
            user.id = user_id
        self.session.add(user)
        self.session.flush()
        return user

    def get_by_id(self, user_id: str) -> Optional[User]:
        """Retrieves a User by their unique ID."""
        stmt = select(User).where(User.id == user_id)
        return self.session.scalars(stmt).first()

    def get_by_email(self, email: str) -> Optional[User]:
        """Retrieves a User by their email address."""
        stmt = select(User).where(User.email == email.strip().lower())
        return self.session.scalars(stmt).first()

    def update(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Optional[User]:
        """Updates attributes of an existing User."""
        user = self.get_by_id(user_id)
        if not user:
            return None

        if full_name is not None:
            user.full_name = full_name
        if role is not None:
            user.role = role
        if is_active is not None:
            user.is_active = is_active

        self.session.flush()
        return user

    def list(self, limit: int = 50, offset: int = 0) -> List[User]:
        """Lists users with pagination."""
        stmt = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        return list(self.session.scalars(stmt).all())
