"""
MailTrace-AI ORM Models Integration Boundary.

Authoritative SQLAlchemy 2.x ORM models corresponding to the database specification
documented in database/README.md:
- users
- mailboxes
- emails
- delivery_events
- analysis_runs
- security_findings
- security_tags
- ml_results
- policy_decisions
- evidence
- forensic_cases
"""

from app.db.database import Base
from app.models.user import User, Mailbox
from app.models.email import Email, DeliveryEvent
from app.models.analysis import AnalysisRun, SecurityFinding, SecurityTag, analysis_run_tags
from app.models.ml import MLResult
from app.models.decision import PolicyDecision
from app.models.forensic import Evidence, ForensicCase, case_emails, case_evidence

__all__ = [
    "Base",
    "User",
    "Mailbox",
    "Email",
    "DeliveryEvent",
    "AnalysisRun",
    "SecurityFinding",
    "SecurityTag",
    "analysis_run_tags",
    "MLResult",
    "PolicyDecision",
    "Evidence",
    "ForensicCase",
    "case_emails",
    "case_evidence",
]
