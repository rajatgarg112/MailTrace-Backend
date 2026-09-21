"""
Security repository for managing SecurityFinding and SecurityTag persistence operations.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import AnalysisRun, SecurityFinding, SecurityTag


class SecurityRepository:
    """
    Repository handling persistence for SecurityFinding and SecurityTag entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    def create_finding(
        self,
        analysis_id: str,
        email_id: str,
        code: str,
        severity: str,
        description: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        finding_id: Optional[str] = None,
    ) -> SecurityFinding:
        """Creates and persists a SecurityFinding."""
        finding = SecurityFinding(
            analysis_id=analysis_id,
            email_id=email_id,
            code=code.strip().upper(),
            severity=severity.strip().upper(),
            description=description,
            details=details or {},
        )
        if finding_id:
            finding.id = finding_id
        self.session.add(finding)
        self.session.flush()
        return finding

    def get_findings_for_analysis(self, analysis_id: str) -> List[SecurityFinding]:
        """Retrieves all findings produced by a specific analysis run."""
        stmt = (
            select(SecurityFinding)
            .where(SecurityFinding.analysis_id == analysis_id)
            .order_by(SecurityFinding.created_at.asc())
        )
        return list(self.session.scalars(stmt).all())

    def get_findings_for_email(self, email_id: str) -> List[SecurityFinding]:
        """Retrieves all security findings associated with an email."""
        stmt = (
            select(SecurityFinding)
            .where(SecurityFinding.email_id == email_id)
            .order_by(SecurityFinding.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    def get_or_create_tag(
        self,
        name: str,
        category: Optional[str] = None,
        description: Optional[str] = None,
    ) -> SecurityTag:
        """Retrieves an existing SecurityTag by name or creates it if not found."""
        clean_name = name.strip()
        stmt = select(SecurityTag).where(SecurityTag.name == clean_name)
        existing = self.session.scalars(stmt).first()
        if existing:
            return existing

        tag = SecurityTag(
            name=clean_name,
            category=category,
            description=description,
        )
        self.session.add(tag)
        self.session.flush()
        return tag

    def get_tag_by_name(self, name: str) -> Optional[SecurityTag]:
        """Retrieves a SecurityTag by its unique name."""
        stmt = select(SecurityTag).where(SecurityTag.name == name.strip())
        return self.session.scalars(stmt).first()

    def attach_tags_to_analysis(
        self,
        analysis_id: str,
        tag_names: List[str],
    ) -> List[SecurityTag]:
        """Attaches normalized security tags to an AnalysisRun, creating missing tags if needed."""
        stmt = select(AnalysisRun).where(AnalysisRun.id == analysis_id).options(selectinload(AnalysisRun.tags))
        run = self.session.scalars(stmt).first()
        if not run:
            return []

        attached_tags: List[SecurityTag] = []
        existing_names = {t.name for t in run.tags}

        for raw_name in tag_names:
            name = raw_name.strip()
            if not name:
                continue
            tag = self.get_or_create_tag(name=name)
            if tag.name not in existing_names:
                run.tags.append(tag)
                existing_names.add(tag.name)
            attached_tags.append(tag)

        self.session.flush()
        return attached_tags

    def get_tags_for_email(self, email_id: str) -> List[SecurityTag]:
        """Retrieves all distinct security tags associated with an email."""
        stmt = (
            select(SecurityTag)
            .join(SecurityTag.analysis_runs)
            .where(AnalysisRun.email_id == email_id)
            .distinct()
        )
        return list(self.session.scalars(stmt).all())
