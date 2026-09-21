"""
Unit tests for the Phase 11 Repository layer.
"""

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import Base
from app.repositories import (
    UserRepository,
    MailboxRepository,
    EmailRepository,
    AnalysisRepository,
    SecurityRepository,
    MLRepository,
    DecisionRepository,
    ForensicRepository,
)


@pytest.fixture
def session():
    """Provides an isolated SQLite in-memory session with all tables created."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    Base.metadata.drop_all(engine)


def test_user_repository_crud(session: Session):
    repo = UserRepository(session)

    # 1. Create
    user = repo.create(email="secops@mailtrace.ai", full_name="Sec Analyst", role="admin")
    assert user.id is not None
    assert user.email == "secops@mailtrace.ai"
    assert user.is_active is True

    # 2. Get by ID
    found = repo.get_by_id(user.id)
    assert found is not None
    assert found.email == "secops@mailtrace.ai"

    # 3. Get by Email
    found_email = repo.get_by_email("SECOPS@mailtrace.ai")
    assert found_email is not None
    assert found_email.id == user.id

    # 4. Update
    updated = repo.update(user.id, full_name="Updated Analyst", role="lead", is_active=False)
    assert updated is not None
    assert updated.full_name == "Updated Analyst"
    assert updated.role == "lead"
    assert updated.is_active is False

    # 5. List
    repo.create(email="user2@mailtrace.ai")
    users = repo.list(limit=10)
    assert len(users) == 2

    # 6. Integrity check
    with pytest.raises(IntegrityError):
        repo.create(email="secops@mailtrace.ai")
    session.rollback()


def test_mailbox_repository_crud(session: Session):
    user_repo = UserRepository(session)
    mailbox_repo = MailboxRepository(session)

    user = user_repo.create(email="owner@mailtrace.ai")

    # 1. Create
    mailbox = mailbox_repo.create(
        email_address="INBOX@mailtrace.ai",
        user_id=user.id,
        mailbox_type="INBOX",
    )
    assert mailbox.id is not None
    assert mailbox.email_address == "inbox@mailtrace.ai"

    # 2. Get by ID
    found = mailbox_repo.get_by_id(mailbox.id)
    assert found is not None
    assert found.id == mailbox.id

    # 3. Get by Email Address
    found_addr = mailbox_repo.get_by_email_address("inbox@mailtrace.ai", user_id=user.id)
    assert found_addr is not None
    assert found_addr.id == mailbox.id

    # 4. List by User
    mailbox_repo.create(email_address="archive@mailtrace.ai", user_id=user.id, mailbox_type="ARCHIVE")
    mailboxes = mailbox_repo.list_by_user(user.id)
    assert len(mailboxes) == 2


def test_email_repository_crud_and_queries(session: Session):
    repo = EmailRepository(session)
    now = datetime.now(timezone.utc)

    # 1. Create
    email1 = repo.create(
        message_id="<msg-001@bad.org>",
        sender_address="ATTACKER@bad.org",
        received_at=now,
        subject="Urgent Security Alert",
        recipients=[{"address": "victim@domain.com"}],
        body_text_preview="Please click this link immediately.",
        mailbox_id="mbx-1",
    )
    assert email1.id is not None
    assert email1.sender_address == "attacker@bad.org"

    email2 = repo.create(
        message_id="<msg-002@bad.org>",
        sender_address="attacker@bad.org",
        received_at=now - timedelta(hours=2),
        subject="Follow up",
        mailbox_id="mbx-1",
    )

    email3 = repo.create(
        message_id="<msg-003@other.org>",
        sender_address="other@other.org",
        received_at=now - timedelta(days=1),
        mailbox_id="mbx-2",
    )

    # 2. Get by ID
    assert repo.get_by_id(email1.id) is not None

    # 3. Get by message_id
    assert repo.get_by_message_id("<msg-001@bad.org>") is not None

    # 4. List
    assert len(repo.list()) == 3

    # 5. Query by sender
    sender_emails = repo.query_by_sender("attacker@bad.org")
    assert len(sender_emails) == 2

    # 6. Query by mailbox
    mailbox_emails = repo.query_by_mailbox("mbx-1")
    assert len(mailbox_emails) == 2

    # 7. Query by received_at
    recent_emails = repo.query_by_received_at(start_date=now - timedelta(hours=3))
    assert len(recent_emails) == 2


def test_analysis_repository_crud(session: Session):
    email_repo = EmailRepository(session)
    analysis_repo = AnalysisRepository(session)

    email = email_repo.create(
        message_id="<msg-analysis@test.com>",
        sender_address="test@test.com",
        received_at=datetime.now(timezone.utc),
    )

    # 1. Create analysis run
    run = analysis_repo.create(
        email_id=email.id,
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )
    assert run.id is not None
    assert run.status == "RUNNING"

    # 2. Update status and result
    completed = datetime.now(timezone.utc)
    updated_run = analysis_repo.update_status_result(
        analysis_id=run.id,
        status="SUCCESS",
        overall_risk_score=78.5,
        risk_level="HIGH",
        threat_confidence=0.91,
        classification="SUSPICIOUS",
        canonical_features={"url": {"count": 2}},
        analyzer_results={"url_analyzer": {"status": "SUCCESS"}},
        completed_at=completed,
    )
    assert updated_run is not None
    assert updated_run.status == "SUCCESS"
    assert updated_run.overall_risk_score == 78.5
    assert updated_run.classification == "SUSPICIOUS"

    # 3. Get by ID
    fetched = analysis_repo.get_by_id(run.id)
    assert fetched is not None
    assert fetched.status == "SUCCESS"

    # 4. Get history for email
    analysis_repo.create(email_id=email.id, status="SUCCESS")
    history = analysis_repo.get_history_for_email(email.id)
    assert len(history) == 2


def test_security_repository_crud(session: Session):
    email_repo = EmailRepository(session)
    analysis_repo = AnalysisRepository(session)
    security_repo = SecurityRepository(session)

    email = email_repo.create(
        message_id="<sec-test@test.com>",
        sender_address="sender@test.com",
        received_at=datetime.now(timezone.utc),
    )
    run = analysis_repo.create(email_id=email.id, status="SUCCESS")

    # 1. Create finding
    finding1 = security_repo.create_finding(
        analysis_id=run.id,
        email_id=email.id,
        code="dmarc_fail",
        severity="high",
        description="DMARC alignment failed",
        details={"dmarc_policy": "reject"},
    )
    assert finding1.id is not None
    assert finding1.code == "DMARC_FAIL"
    assert finding1.severity == "HIGH"

    finding2 = security_repo.create_finding(
        analysis_id=run.id,
        email_id=email.id,
        code="suspicious_url",
        severity="medium",
    )

    # 2. Get findings for analysis
    findings_analysis = security_repo.get_findings_for_analysis(run.id)
    assert len(findings_analysis) == 2

    # 3. Get findings for email
    findings_email = security_repo.get_findings_for_email(email.id)
    assert len(findings_email) == 2

    # 4. Create and attach tags
    tag = security_repo.get_or_create_tag(name="DMARC-Fail", category="AUTHENTICATION")
    assert tag.id is not None

    attached = security_repo.attach_tags_to_analysis(run.id, ["DMARC-Fail", "New-Domain"])
    assert len(attached) == 2

    fetched_run = analysis_repo.get_by_id(run.id, load_tags=True)
    assert len(fetched_run.tags) == 2


def test_ml_repository_crud(session: Session):
    email_repo = EmailRepository(session)
    analysis_repo = AnalysisRepository(session)
    ml_repo = MLRepository(session)

    email = email_repo.create(
        message_id="<ml-test@test.com>",
        sender_address="sender@test.com",
        received_at=datetime.now(timezone.utc),
    )
    run = analysis_repo.create(email_id=email.id, status="SUCCESS")

    # 1. Create MLResult
    ml1 = ml_repo.create(
        analysis_id=run.id,
        email_id=email.id,
        model_name="nlp_phishing_v1",
        model_version="1.0.0",
        prediction="PHISHING",
        confidence=0.94,
        scores={"phishing": 0.94, "safe": 0.06},
    )
    assert ml1.id is not None
    assert ml1.prediction == "PHISHING"

    # 2. Get by analysis
    by_analysis = ml_repo.get_by_analysis(run.id)
    assert len(by_analysis) == 1

    # 3. Get by email
    by_email = ml_repo.get_by_email(email.id)
    assert len(by_email) == 1


def test_decision_repository_crud(session: Session):
    email_repo = EmailRepository(session)
    analysis_repo = AnalysisRepository(session)
    decision_repo = DecisionRepository(session)

    email = email_repo.create(
        message_id="<dec-test@test.com>",
        sender_address="sender@test.com",
        received_at=datetime.now(timezone.utc),
    )
    run = analysis_repo.create(email_id=email.id, status="SUCCESS")

    # 1. Create policy decision
    decision = decision_repo.create_policy_decision(
        analysis_id=run.id,
        email_id=email.id,
        classification="malicious",
        action="quarantine",
        risk_level="high",
        risk_score=85.0,
        gateway_category="HIGH_RISK_PHISHING",
        reason="Credential harvesting detected",
    )
    assert decision.id is not None
    assert decision.classification == "MALICIOUS"
    assert decision.action == "QUARANTINE"

    # 2. Get decision for analysis
    dec_analysis = decision_repo.get_decision_for_analysis(run.id)
    assert dec_analysis is not None
    assert dec_analysis.id == decision.id

    # 3. Get decisions for email
    dec_email = decision_repo.get_decisions_for_email(email.id)
    assert len(dec_email) == 1

    # 4. Create delivery event
    event = decision_repo.create_delivery_event(
        email_id=email.id,
        action="quarantine",
        status="completed",
        policy_decision_id=decision.id,
        reason="Routing to quarantine store",
    )
    assert event.id is not None
    assert event.action == "QUARANTINE"

    # 5. Get delivery history for email
    history = decision_repo.get_delivery_history_for_email(email.id)
    assert len(history) == 1


def test_forensic_repository_crud(session: Session):
    email_repo = EmailRepository(session)
    forensic_repo = ForensicRepository(session)

    email = email_repo.create(
        message_id="<forensic-test@test.com>",
        sender_address="c2@attacker.com",
        received_at=datetime.now(timezone.utc),
    )

    # 1. Create Evidence
    ev1 = forensic_repo.create_evidence(
        email_id=email.id,
        evidence_type="attachment",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_metadata={"file": "dropper.exe"},
    )
    assert ev1.id is not None
    assert ev1.evidence_type == "ATTACHMENT"

    # 2. Get Evidence by ID and by Hash
    assert forensic_repo.get_evidence_by_id(ev1.id) is not None
    by_hash = forensic_repo.get_evidence_by_sha256("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert len(by_hash) == 1

    # 3. Create Case
    case = forensic_repo.create_case(
        title="Incident 2026-09",
        status="open",
        severity="high",
        tags=["Phishing", "APT"],
    )
    assert case.id is not None
    assert case.status == "OPEN"

    # 4. Attach email & evidence to case
    assert forensic_repo.attach_email_to_case(case.id, email.id) is True
    assert forensic_repo.attach_evidence_to_case(case.id, ev1.id) is True

    # 5. Retrieve case emails & evidence
    case_emails = forensic_repo.get_case_emails(case.id)
    assert len(case_emails) == 1
    assert case_emails[0].id == email.id

    case_evidence = forensic_repo.get_case_evidence(case.id)
    assert len(case_evidence) == 1
    assert case_evidence[0].id == ev1.id
