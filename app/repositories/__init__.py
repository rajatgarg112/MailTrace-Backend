"""
MailTrace-AI Repository Layer.

Clean persistence layer providing query, storage, and retrieval abstractions
over authoritative SQLAlchemy 2.x ORM models.
"""

from app.repositories.user_repository import UserRepository
from app.repositories.mailbox_repository import MailboxRepository
from app.repositories.email_repository import EmailRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.security_repository import SecurityRepository
from app.repositories.ml_repository import MLRepository
from app.repositories.decision_repository import DecisionRepository
from app.repositories.forensic_repository import ForensicRepository

__all__ = [
    "UserRepository",
    "MailboxRepository",
    "EmailRepository",
    "AnalysisRepository",
    "SecurityRepository",
    "MLRepository",
    "DecisionRepository",
    "ForensicRepository",
]
