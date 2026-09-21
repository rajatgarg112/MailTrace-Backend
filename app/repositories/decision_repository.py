"""
Decision repository for managing PolicyDecision and DeliveryEvent persistence operations.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.decision import PolicyDecision
from app.models.email import DeliveryEvent


class DecisionRepository:
    """
    Repository handling persistence for PolicyDecision and DeliveryEvent entities.
    
    Transaction Responsibility:
    Methods perform database operations and call `session.flush()` to ensure
    entity state and database constraints are validated immediately within the
    current transaction. Transaction commit and rollback are controlled by the caller.
    """

    def __init__(self, session: Session):
        self.session = session

    # --- Policy Decision Operations ---

    def create_policy_decision(
        self,
        analysis_id: str,
        email_id: str,
        classification: str,
        action: str,
        risk_level: str,
        risk_score: float,
        reason: str,
        spam_category: Optional[str] = None,
        gateway_category: Optional[str] = None,
        policy_version: str = "1.0.0",
        decision_id: Optional[str] = None,
    ) -> PolicyDecision:
        """Creates and persists a canonical PolicyDecision."""
        decision = PolicyDecision(
            analysis_id=analysis_id,
            email_id=email_id,
            classification=classification.strip().upper(),
            action=action.strip().upper(),
            risk_level=risk_level.strip().upper(),
            risk_score=risk_score,
            reason=reason,
            spam_category=spam_category,
            gateway_category=gateway_category,
            policy_version=policy_version,
        )
        if decision_id:
            decision.id = decision_id
        self.session.add(decision)
        self.session.flush()
        return decision

    def get_decisions_for_email(self, email_id: str) -> List[PolicyDecision]:
        """Retrieves all policy decisions recorded for an email."""
        stmt = (
            select(PolicyDecision)
            .where(PolicyDecision.email_id == email_id)
            .order_by(PolicyDecision.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    def get_decision_for_analysis(self, analysis_id: str) -> Optional[PolicyDecision]:
        """Retrieves the policy decision produced by a specific analysis run."""
        stmt = select(PolicyDecision).where(PolicyDecision.analysis_id == analysis_id)
        return self.session.scalars(stmt).first()

    # --- Delivery Event Operations ---

    def create_delivery_event(
        self,
        email_id: str,
        action: str,
        status: str = "COMPLETED",
        policy_decision_id: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
    ) -> DeliveryEvent:
        """Creates and persists a DeliveryEvent audit record."""
        event = DeliveryEvent(
            email_id=email_id,
            action=action.strip().upper(),
            status=status.strip().upper(),
            policy_decision_id=policy_decision_id,
            reason=reason,
            details=details or {},
        )
        if event_id:
            event.id = event_id
        self.session.add(event)
        self.session.flush()
        return event

    def get_delivery_history_for_email(self, email_id: str) -> List[DeliveryEvent]:
        """Retrieves routing and delivery lifecycle history for an email."""
        stmt = (
            select(DeliveryEvent)
            .where(DeliveryEvent.email_id == email_id)
            .order_by(DeliveryEvent.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())

    def get_latest_decision_for_email(self, email_id: str) -> Optional[PolicyDecision]:
        """Retrieves the most recent policy decision for an email."""
        stmt = (
            select(PolicyDecision)
            .where(PolicyDecision.email_id == email_id)
            .order_by(PolicyDecision.created_at.desc())
        )
        return self.session.scalars(stmt).first()

    def get_latest_delivery_event_for_email(self, email_id: str) -> Optional[DeliveryEvent]:
        """Retrieves the most recent delivery event for an email."""
        stmt = (
            select(DeliveryEvent)
            .where(DeliveryEvent.email_id == email_id)
            .order_by(DeliveryEvent.created_at.desc())
        )
        return self.session.scalars(stmt).first()

    def list_by_action(self, action: str, limit: int = 50, offset: int = 0) -> List[PolicyDecision]:
        """Retrieves policy decisions matching an action (e.g. QUARANTINE, SPAM)."""
        stmt = (
            select(PolicyDecision)
            .where(PolicyDecision.action == action.strip().upper())
            .order_by(PolicyDecision.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(stmt).all())
