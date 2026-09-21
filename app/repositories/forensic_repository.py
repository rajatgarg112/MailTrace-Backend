"""
Forensic repository for managing Evidence and ForensicCase persistence operations.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.email import Email
from app.models.forensic import Evidence, ForensicCase


class ForensicRepository:
    """
    Repository handling persistence for Evidence and ForensicCase entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    # --- Evidence Operations ---

    def create_evidence(
        self,
        email_id: str,
        evidence_type: str,
        sha256_hash: str,
        analysis_id: Optional[str] = None,
        source_metadata: Optional[Dict[str, Any]] = None,
        extracted_facts: Optional[Dict[str, Any]] = None,
        evidence_id: Optional[str] = None,
    ) -> Evidence:
        """Creates and persists an Evidence preservation record with SHA-256 hash."""
        evidence = Evidence(
            email_id=email_id,
            evidence_type=evidence_type.strip().upper(),
            sha256_hash=sha256_hash.strip().lower(),
            analysis_id=analysis_id,
            source_metadata=source_metadata or {},
            extracted_facts=extracted_facts or {},
        )
        if evidence_id:
            evidence.id = evidence_id
        self.session.add(evidence)
        self.session.flush()
        return evidence

    def get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieves an Evidence record by its ID."""
        stmt = select(Evidence).where(Evidence.id == evidence_id)
        return self.session.scalars(stmt).first()

    def get_evidence_by_sha256(self, sha256_hash: str) -> List[Evidence]:
        """Retrieves all Evidence records matching a specific SHA-256 hash."""
        stmt = select(Evidence).where(Evidence.sha256_hash == sha256_hash.strip().lower())
        return list(self.session.scalars(stmt).all())

    def get_evidence_for_email(self, email_id: str) -> List[Evidence]:
        """Retrieves all evidence preserved for an email."""
        stmt = (
            select(Evidence)
            .where(Evidence.email_id == email_id)
            .order_by(Evidence.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    def get_evidence_for_analysis(self, analysis_id: str) -> List[Evidence]:
        """Retrieves all evidence associated with an analysis run."""
        stmt = (
            select(Evidence)
            .where(Evidence.analysis_id == analysis_id)
            .order_by(Evidence.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    # --- Forensic Case Operations ---

    def create_case(
        self,
        title: str,
        description: Optional[str] = None,
        status: str = "OPEN",
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        assigned_to: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> ForensicCase:
        """Creates and persists a new ForensicCase."""
        case = ForensicCase(
            title=title.strip(),
            description=description,
            status=status.strip().upper(),
            severity=severity.strip().upper() if severity else None,
            tags=tags or [],
            assigned_to=assigned_to,
        )
        if case_id:
            case.id = case_id
        self.session.add(case)
        self.session.flush()
        return case

    def get_case_by_id(
        self,
        case_id: str,
        load_emails: bool = False,
        load_evidence: bool = False,
    ) -> Optional[ForensicCase]:
        """Retrieves a ForensicCase by ID with optional eager loading of relations."""
        stmt = select(ForensicCase).where(ForensicCase.id == case_id)
        if load_emails:
            stmt = stmt.options(selectinload(ForensicCase.emails))
        if load_evidence:
            stmt = stmt.options(selectinload(ForensicCase.evidence))
        return self.session.scalars(stmt).first()

    def attach_email_to_case(self, case_id: str, email_id: str) -> bool:
        """Attaches an Email to a ForensicCase via the case_emails association table."""
        case = self.get_case_by_id(case_id, load_emails=True)
        if not case:
            return False

        stmt = select(Email).where(Email.id == email_id)
        email = self.session.scalars(stmt).first()
        if not email:
            return False

        if email not in case.emails:
            case.emails.append(email)
            self.session.flush()
        return True

    def attach_evidence_to_case(self, case_id: str, evidence_id: str) -> bool:
        """Attaches an Evidence artifact to a ForensicCase via the case_evidence association table."""
        case = self.get_case_by_id(case_id, load_evidence=True)
        if not case:
            return False

        evidence = self.get_evidence_by_id(evidence_id)
        if not evidence:
            return False

        if evidence not in case.evidence:
            case.evidence.append(evidence)
            self.session.flush()
        return True

    def get_case_emails(self, case_id: str) -> List[Email]:
        """Retrieves all emails attached to a forensic investigation case."""
        case = self.get_case_by_id(case_id, load_emails=True)
        if not case:
            return []
        return list(case.emails)

    def get_case_evidence(self, case_id: str) -> List[Evidence]:
        """Retrieves all evidence artifacts attached to a forensic investigation case."""
        case = self.get_case_by_id(case_id, load_evidence=True)
        if not case:
            return []
        return list(case.evidence)
