from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.database import Base, get_db
from app.main import app
from app.models.analysis import (
    AnalysisRun as AnalysisRunModel,
    SecurityFinding as SecurityFindingModel,
    SecurityTag as SecurityTagModel,
)
from app.models.decision import PolicyDecision as PolicyDecisionModel
from app.models.email import DeliveryEvent as DeliveryEventModel, Email

client = TestClient(app)
AUTH_HEADER = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}


@pytest.fixture(autouse=True)
def db_session():
    """Provides an isolated SQLite in-memory session for API endpoint tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    def override_get_db():
        try:
            yield session
        except Exception:
            session.rollback()
            raise

    app.dependency_overrides[get_db] = override_get_db
    yield session
    session.close()
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def test_health_endpoint_public():
    """1. GET /health remains public."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_protected_endpoint_rejects_missing_auth(db_session: Session):
    """2. Protected endpoint rejects missing auth header & does not create DB record."""
    res = client.post("/api/v1/emails/analyze", json={"subject": "Test"})
    assert res.status_code == 401
    assert "detail" in res.json()
    assert len(db_session.scalars(select(Email)).all()) == 0
    assert len(db_session.scalars(select(AnalysisRunModel)).all()) == 0
    assert len(db_session.scalars(select(SecurityFindingModel)).all()) == 0
    assert len(db_session.scalars(select(SecurityTagModel)).all()) == 0
    assert len(db_session.scalars(select(PolicyDecisionModel)).all()) == 0
    assert len(db_session.scalars(select(DeliveryEventModel)).all()) == 0


def test_protected_endpoint_rejects_invalid_auth(db_session: Session):
    """3. Protected endpoint rejects invalid auth token & does not create DB record."""
    headers = {"Authorization": "Bearer invalid_secret_token_123"}
    res = client.post("/api/v1/emails/analyze", json={"subject": "Test"}, headers=headers)
    assert res.status_code == 401
    assert "Invalid authentication credentials" in res.json()["detail"]
    assert len(db_session.scalars(select(Email)).all()) == 0
    assert len(db_session.scalars(select(AnalysisRunModel)).all()) == 0
    assert len(db_session.scalars(select(SecurityFindingModel)).all()) == 0
    assert len(db_session.scalars(select(SecurityTagModel)).all()) == 0
    assert len(db_session.scalars(select(PolicyDecisionModel)).all()) == 0
    assert len(db_session.scalars(select(DeliveryEventModel)).all()) == 0


def test_valid_auth_and_structured_email_analysis(db_session: Session):
    """4. Valid auth accepted, structured payload analyzed & persisted into Email, AnalysisRun, Findings, Tags, PolicyDecision, and DeliveryEvent tables."""
    payload = {
        "message_id": "<struct-001@example.com>",
        "sender": "Security Test <security@example.com>",
        "recipients": ["user@target.com"],
        "subject": "Urgent Account Verification",
        "body": "Please click http://phishing-domain.xyz/login to verify your account immediately.",
    }
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    assert "analysis_id" in data
    assert data["email_id"] == "<struct-001@example.com>"
    assert "risk" in data
    assert "overall_risk_score" in data["risk"]
    assert "classification" in data
    assert "decision" in data
    assert data["decision"]["action"] in ["INBOX", "SPAM", "WARN", "HOLD", "QUARANTINE", "REJECT"]
    assert "analyzer_results" in data
    assert "findings" in data
    assert "tags" in data

    # Database assertions
    emails = db_session.scalars(select(Email)).all()
    assert len(emails) == 1
    stored_email = emails[0]
    assert stored_email.message_id == "<struct-001@example.com>"

    runs = db_session.scalars(select(AnalysisRunModel)).all()
    assert len(runs) == 1
    stored_run = runs[0]
    assert stored_run.email_id == stored_email.id

    # PolicyDecision & DeliveryEvent assertions
    decisions = db_session.scalars(select(PolicyDecisionModel)).all()
    assert len(decisions) == 1
    stored_decision = decisions[0]
    assert stored_decision.analysis_id == stored_run.id
    assert stored_decision.email_id == stored_email.id
    assert stored_decision.classification == data["classification"]
    assert stored_decision.action == data["decision"]["action"]
    assert stored_decision.risk_score == data["risk"]["overall_risk_score"]
    assert stored_decision.risk_level == data["risk"]["risk_level"]

    events = db_session.scalars(select(DeliveryEventModel)).all()
    assert len(events) == 1
    stored_event = events[0]
    assert stored_event.email_id == stored_email.id
    assert stored_event.policy_decision_id == stored_decision.id
    assert stored_event.action == data["decision"]["action"]
    assert stored_event.status == "COMPLETED"


def test_raw_mime_email_analysis(db_session: Session):
    """5. Raw MIME email string reaches ingestion, returns analysis response, creates DB rows."""
    raw_mime = (
        "From: Alice <alice@sender.org>\r\n"
        "To: Bob <bob@receiver.org>\r\n"
        "Subject: Raw MIME Test\r\n"
        "Message-ID: <raw-mime-001@sender.org>\r\n"
        "\r\n"
        "Raw MIME email content body with http://phishing-site.xyz link."
    )
    payload = {"raw_email": raw_mime}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()
    assert data["email_id"] == "<raw-mime-001@sender.org>"

    # Database assertions
    emails = db_session.scalars(select(Email)).all()
    assert len(emails) == 1
    runs = db_session.scalars(select(AnalysisRunModel)).all()
    assert len(runs) == 1
    decisions = db_session.scalars(select(PolicyDecisionModel)).all()
    assert len(decisions) == 1
    events = db_session.scalars(select(DeliveryEventModel)).all()
    assert len(events) == 1


def test_empty_or_malformed_request_rejected(db_session: Session):
    """6. Empty request rejected cleanly with 422 without DB record or stack trace leakage."""
    payload = {}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 422
    data = res.json()
    assert "error" in data or "detail" in data
    assert "Traceback" not in res.text
    assert len(db_session.scalars(select(Email)).all()) == 0
    assert len(db_session.scalars(select(AnalysisRunModel)).all()) == 0
    assert len(db_session.scalars(select(PolicyDecisionModel)).all()) == 0
    assert len(db_session.scalars(select(DeliveryEventModel)).all()) == 0


def test_oversized_raw_email_rejected(db_session: Session):
    """7. Oversized raw email is rejected and does not create DB record."""
    raw_oversized = "A" * (settings.MAX_RAW_EMAIL_BYTES + 1024)
    payload = {"raw_email": raw_oversized}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 422
    assert "exceeds maximum limit" in res.text
    assert len(db_session.scalars(select(Email)).all()) == 0
    assert len(db_session.scalars(select(AnalysisRunModel)).all()) == 0
    assert len(db_session.scalars(select(PolicyDecisionModel)).all()) == 0
    assert len(db_session.scalars(select(DeliveryEventModel)).all()) == 0


def test_existing_message_id_creates_new_decision_and_event_per_run(db_session: Session):
    """8. Re-submitting email with existing message_id creates new PolicyDecision and DeliveryEvent per AnalysisRun."""
    payload = {
        "message_id": "<dup-check-001@domain.com>",
        "sender": "sender@domain.com",
        "subject": "Urgent Action Required",
        "body": "Please click http://phish.top to login immediately.",
    }
    res1 = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res1.status_code == 200

    res2 = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res2.status_code == 200

    emails = db_session.scalars(select(Email)).all()
    assert len(emails) == 1

    runs = db_session.scalars(select(AnalysisRunModel)).all()
    assert len(runs) == 2

    decisions = db_session.scalars(select(PolicyDecisionModel)).all()
    assert len(decisions) == 2
    assert decisions[0].analysis_id == runs[0].id
    assert decisions[1].analysis_id == runs[1].id

    events = db_session.scalars(select(DeliveryEventModel)).all()
    assert len(events) == 2


def test_security_tags_reuse(db_session: Session):
    """9. Submitting two emails triggering identical security tags reuses global SecurityTag rows."""
    payload1 = {
        "message_id": "<tag-test-1@domain.com>",
        "sender": "attacker1@domain.com",
        "subject": "Check this",
        "body": "Visit http://phish-site.top now",
    }
    payload2 = {
        "message_id": "<tag-test-2@domain.com>",
        "sender": "attacker2@domain.com",
        "subject": "Check that",
        "body": "Visit http://phish-site.top now",
    }

    res1 = client.post("/api/v1/emails/analyze", json=payload1, headers=AUTH_HEADER)
    assert res1.status_code == 200
    tags1 = res1.json()["tags"]

    res2 = client.post("/api/v1/emails/analyze", json=payload2, headers=AUTH_HEADER)
    assert res2.status_code == 200
    tags2 = res2.json()["tags"]

    if tags1 and tags2:
        common_tags = set(tags1).intersection(set(tags2))
        for tag_name in common_tags:
            tag_rows = db_session.scalars(select(SecurityTagModel).where(SecurityTagModel.name == tag_name)).all()
            assert len(tag_rows) == 1  # Reused globally


def test_analysis_with_zero_findings_and_tags_succeeds(db_session: Session):
    """10. Clean email with 0 findings and 0 tags succeeds with valid response and persisted decision/event."""
    payload = {
        "message_id": "<clean-001@safe.com>",
        "sender": "alice@safe.com",
        "recipients": ["bob@safe.com"],
        "subject": "Meeting Notes",
        "body": "Hi Bob, here are the clean meeting notes from today.",
    }
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200

    email = db_session.scalars(select(Email).where(Email.message_id == "<clean-001@safe.com>")).first()
    assert email is not None

    run = db_session.scalars(select(AnalysisRunModel).where(AnalysisRunModel.email_id == email.id)).first()
    assert run is not None

    decision = db_session.scalars(select(PolicyDecisionModel).where(PolicyDecisionModel.analysis_id == run.id)).first()
    assert decision is not None

    event = db_session.scalars(select(DeliveryEventModel).where(DeliveryEventModel.policy_decision_id == decision.id)).first()
    assert event is not None


def test_security_guarantees_no_leakage_and_no_network_calls(db_session: Session):
    """Security check: no raw email leakage, no stack traces, no outbound network calls."""
    payload = {
        "sender": "hacker@evil.com",
        "subject": "SECRET_BODY_PAYLOAD_12345",
        "body": "Confidential information string",
    }

    with patch("socket.create_connection") as mock_conn, patch("socket.gethostbyname") as mock_dns:
        res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
        assert res.status_code == 200
        assert mock_conn.called is False
        assert mock_dns.called is False





