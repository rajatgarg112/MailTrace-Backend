import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models import (
    AnalysisRun,
    DeliveryEvent,
    Email,
    Evidence,
    ForensicCase,
    Mailbox,
    MLResult,
    PolicyDecision,
    SecurityFinding,
    SecurityTag,
    User,
    analysis_run_tags,
    case_emails,
    case_evidence,
)


@pytest.fixture
def db_session():
    """Provides an isolated in-memory SQLite session with all models created."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


def test_models_metadata_registration():
    """Verify all 11 entities and 3 association tables are registered in Base.metadata."""
    table_names = set(Base.metadata.tables.keys())
    expected_tables = {
        "users",
        "mailboxes",
        "emails",
        "delivery_events",
        "analysis_runs",
        "security_findings",
        "security_tags",
        "analysis_run_tags",
        "ml_results",
        "policy_decisions",
        "evidence",
        "forensic_cases",
        "case_emails",
        "case_evidence",
    }
    assert expected_tables.issubset(table_names)


def test_user_and_mailbox_lifecycle(db_session: Session):
    """Verify User and Mailbox persistence and relationship."""
    user = User(
        email="analyst@mailtrace.ai",
        full_name="Alice SecOps",
        role="admin",
    )
    db_session.add(user)
    db_session.flush()

    assert user.id is not None
    assert user.is_active is True

    mailbox = Mailbox(
        user_id=user.id,
        email_address="inbox@mailtrace.ai",
        mailbox_type="INBOX",
    )
    db_session.add(mailbox)
    db_session.commit()

    loaded_user = db_session.query(User).filter_by(email="analyst@mailtrace.ai").one()
    assert len(loaded_user.mailboxes) == 1
    assert loaded_user.mailboxes[0].email_address == "inbox@mailtrace.ai"
    assert loaded_user.mailboxes[0].user.email == "analyst@mailtrace.ai"


def test_user_unique_email_constraint(db_session: Session):
    """Verify unique constraint on User email."""
    user1 = User(email="duplicate@mailtrace.ai")
    db_session.add(user1)
    db_session.commit()

    user2 = User(email="duplicate@mailtrace.ai")
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_email_and_analysis_run_relationships(db_session: Session):
    """Verify Email, AnalysisRun, SecurityFinding, MLResult, and PolicyDecision relationships."""
    email = Email(
        message_id="<test-001@example.com>",
        sender_address="spammer@bad.org",
        sender_name="Bad Actor",
        recipients=[{"address": "target@domain.com", "name": "Target"}],
        subject="Claim your prize",
        headers={"Received": "by mx.example.com"},
        body_text_preview="Click here to claim",
        attachment_metadata=[{"filename": "prize.exe", "size_bytes": 5000}],
        urls=[{"url": "http://bad.org/claim", "domain": "bad.org"}],
        received_hops=[],
        received_at=datetime.now(timezone.utc),
    )
    db_session.add(email)
    db_session.flush()

    run = AnalysisRun(
        email_id=email.id,
        status="SUCCESS",
        overall_risk_score=90.0,
        risk_level="CRITICAL",
        threat_confidence=0.98,
        classification="MALICIOUS",
        canonical_features={"sender_identity": {"sender_address": "spammer@bad.org"}},
        analyzer_results={"url": {"status": "SUCCESS"}},
    )
    db_session.add(run)
    db_session.flush()

    finding = SecurityFinding(
        analysis_id=run.id,
        email_id=email.id,
        code="MALICIOUS_URL",
        severity="CRITICAL",
        description="Known phishing URL match",
        details={"url": "http://bad.org/claim"},
    )
    tag = SecurityTag(name="Phishing", category="CONTENT")
    run.tags.append(tag)
    db_session.add(finding)
    db_session.add(tag)

    ml = MLResult(
        analysis_id=run.id,
        email_id=email.id,
        model_name="nlp_phishing_detector",
        model_version="2.1.0",
        prediction="PHISHING",
        confidence=0.99,
        scores={"phishing": 0.99, "safe": 0.01},
    )
    db_session.add(ml)

    decision = PolicyDecision(
        analysis_id=run.id,
        email_id=email.id,
        classification="MALICIOUS",
        action="QUARANTINE",
        risk_level="CRITICAL",
        risk_score=90.0,
        gateway_category="MALICIOUS",
        reason="Blocked due to critical phishing verdict",
    )
    db_session.add(decision)
    db_session.flush()

    delivery_event = DeliveryEvent(
        email_id=email.id,
        policy_decision_id=decision.id,
        action="QUARANTINE",
        status="COMPLETED",
        reason="Moved to quarantine vault",
        details={"vault": "primary_quarantine"},
    )
    db_session.add(delivery_event)
    db_session.commit()

    loaded_email = db_session.query(Email).filter_by(message_id="<test-001@example.com>").one()
    assert len(loaded_email.analysis_runs) == 1
    assert loaded_email.analysis_runs[0].classification == "MALICIOUS"
    assert len(loaded_email.analysis_runs[0].findings) == 1
    assert loaded_email.analysis_runs[0].findings[0].code == "MALICIOUS_URL"
    assert len(loaded_email.analysis_runs[0].tags) == 1
    assert loaded_email.analysis_runs[0].tags[0].name == "Phishing"
    assert len(loaded_email.ml_results) == 1
    assert loaded_email.ml_results[0].prediction == "PHISHING"
    assert len(loaded_email.policy_decisions) == 1
    assert loaded_email.policy_decisions[0].action == "QUARANTINE"
    assert len(loaded_email.delivery_events) == 1
    assert loaded_email.delivery_events[0].status == "COMPLETED"


def test_evidence_and_forensic_case_relationships(db_session: Session):
    """Verify Evidence, ForensicCase, and many-to-many associations."""
    email = Email(
        message_id="<evidence-test@example.com>",
        sender_address="attacker@c2.net",
        subject="Invoice",
        received_at=datetime.now(timezone.utc),
    )
    db_session.add(email)
    db_session.flush()

    ev = Evidence(
        email_id=email.id,
        evidence_type="ATTACHMENT",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_metadata={"filename": "payload.exe"},
        extracted_facts={"is_executable": True},
    )
    db_session.add(ev)
    db_session.flush()

    case = ForensicCase(
        title="APT Phishing Campaign Q3",
        status="UNDER_INVESTIGATION",
        severity="CRITICAL",
        tags=["APT", "C2"],
    )
    case.emails.append(email)
    case.evidence.append(ev)
    db_session.add(case)
    db_session.commit()

    loaded_case = db_session.query(ForensicCase).filter_by(title="APT Phishing Campaign Q3").one()
    assert len(loaded_case.emails) == 1
    assert loaded_case.emails[0].message_id == "<evidence-test@example.com>"
    assert len(loaded_case.evidence) == 1
    assert loaded_case.evidence[0].sha256_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert loaded_case.evidence[0].forensic_cases[0].id == loaded_case.id
