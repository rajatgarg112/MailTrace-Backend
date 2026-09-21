"""
MailTrace-AI ORM Models Integration Boundary.

This module serves as the designated boundary for Member 5 (M5 Database Engineer)
to integrate authoritative SQLAlchemy ORM models corresponding to the database specification
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

M2 provides the infrastructure (Base, SessionLocal, get_db). M5 owns entity definitions,
relationships, constraints, and Alembic migrations.
"""

from app.db.database import Base

__all__ = ["Base"]
