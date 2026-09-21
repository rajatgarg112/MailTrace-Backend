from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.database import Base, get_db
from app.main import app

client = TestClient(app)
AUTH_HEADER = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}


@pytest.fixture(autouse=True)
def db_session():
    """Provides an isolated SQLite in-memory session for Read API tests."""
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


@pytest.fixture
def seed_pipeline_emails():
    """Seeds database with real pipeline-analyzed emails covering all categories."""
    emails = {
        "safe": {
            "message_id": "<safe-001@legitcorp.com>",
            "sender": "Alice Smith <alice@legitcorp.com>",
            "recipients": ["bob@company.org"],
            "subject": "Weekly Team Standup Notes",
            "body": "Hi Bob,\n\nHere are the notes from our team sync.\nEverything is on track.\n\nBest,\nAlice",
        },
        "phishing": {
            "message_id": "<phish-001@microsft-verify.com>",
            "sender": "Security Alert <security@microsft-verify.com>",
            "recipients": ["user@target.org"],
            "subject": "URGENT: Password Expired - Reset Immediately",
            "body": "Your password has expired. Click http://microsft-verify.com/login-portal to verify your credentials.",
        },
        "spam": {
            "message_id": "<spam-001@promotions-deals.net>",
            "sender": "Cloud Deals <promo@promotions-deals.net>",
            "recipients": ["user@target.org"],
            "subject": "Special Offer: 50% discount on cloud hosting today only",
            "body": "Exclusive offer! Buy now and save 50% on all cloud hosting plans.",
        },
        "bec": {
            "message_id": "<bec-001@exec-office-board.com>",
            "sender": "CEO Office <ceo@exec-office-board.com>",
            "recipients": ["finance@company.org"],
            "subject": "URGENT: Executive Wire Transfer Authorization Required",
            "body": "Please wire $50,000 immediately to account 987654321 for vendor settlement. Keep this confidential.",
        },
        "suspicious_url": {
            "message_id": "<url-001@external-notify.xyz>",
            "sender": "Billing Department <invoice@external-notify.xyz>",
            "recipients": ["user@target.org"],
            "subject": "Overdue Invoice Notice",
            "body": "Your invoice is past due. Please review payment details at http://pay-invoice-secure.top/check",
        },
        "malicious_attachment": {
            "message_id": "<malware-001@attacker-payload.biz>",
            "sender": "Payroll Support <payroll@attacker-payload.biz>",
            "recipients": ["user@target.org"],
            "subject": "Remittance Advice and Salary Statement",
            "body": "Attached is the encrypted salary advice document. Please execute.",
            "raw_email": (
                "From: Payroll Support <payroll@attacker-payload.biz>\r\n"
                "To: user@target.org\r\n"
                "Subject: Remittance Advice\r\n"
                "Message-ID: <malware-001@attacker-payload.biz>\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
                "--BOUNDARY\r\n"
                "Content-Type: text/plain\r\n\r\n"
                "Please review invoice.\r\n"
                "--BOUNDARY\r\n"
                "Content-Type: application/octet-stream; name=\"invoice.exe\"\r\n"
                "Content-Disposition: attachment; filename=\"invoice.exe\"\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n"
                "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
                "--BOUNDARY--\r\n"
            ),
        },
    }

    results = {}
    for key, payload in emails.items():
        res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
        assert res.status_code == 200, f"Failed to seed {key}: {res.text}"
        results[key] = res.json()

    return results


def test_auth_enforcement_on_read_endpoints():
    """Verify read endpoints require authentication and return 401 when token is missing or invalid."""
    endpoints = [
        "/api/v1/emails",
        "/api/v1/security/overview",
        "/api/v1/security/threats",
        "/api/v1/spam",
        "/api/v1/quarantine",
        "/api/v1/cases",
        "/api/v1/fono/overview",
    ]
    for ep in endpoints:
        # Missing header
        res_missing = client.get(ep)
        assert res_missing.status_code == 401, f"{ep} should reject missing auth"

        # Invalid token
        res_invalid = client.get(ep, headers={"Authorization": "Bearer invalid_secret"})
        assert res_invalid.status_code == 401, f"{ep} should reject invalid auth"


def test_get_emails_empty_and_populated(seed_pipeline_emails):
    """GET /api/v1/emails lists persisted emails and supports pagination and filtering."""
    # List all
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    assert res.status_code == 200
    emails = res.json()
    assert len(emails) == 6

    # Verify fields match contract
    email_sample = emails[0]
    assert "id" in email_sample
    assert "subject" in email_sample
    assert "sender" in email_sample
    assert "classification" in email_sample
    assert "action" in email_sample
    assert "riskScore" in email_sample
    assert "tags" in email_sample
    assert "provenance" in email_sample

    # Pagination: limit=2
    res_page = client.get("/api/v1/emails?limit=2&offset=0", headers=AUTH_HEADER)
    assert res_page.status_code == 200
    assert len(res_page.json()) == 2

    # Filter by action=INBOX
    res_inbox = client.get("/api/v1/emails?action=INBOX", headers=AUTH_HEADER)
    assert res_inbox.status_code == 200
    inbox_list = res_inbox.json()
    assert len(inbox_list) >= 1
    assert all(e["action"] == "INBOX" for e in inbox_list)

    # Filter by classification=PHISHING
    res_phish = client.get("/api/v1/emails?classification=PHISHING", headers=AUTH_HEADER)
    assert res_phish.status_code == 200
    for e in res_phish.json():
        assert e["classification"] in ("PHISHING", "MALICIOUS")

    # Search filter
    res_search = client.get("/api/v1/emails?search=Standup", headers=AUTH_HEADER)
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 1
    assert "Standup" in res_search.json()[0]["subject"]


def test_get_email_by_id_and_404(seed_pipeline_emails):
    """GET /api/v1/emails/{id} retrieves single normalized email or 404s."""
    # List emails to get a real ID
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    real_email = emails[0]
    email_id = real_email["id"]
    message_id = real_email["message_id"]

    # 1. Fetch by primary key ID
    res_by_id = client.get(f"/api/v1/emails/{email_id}", headers=AUTH_HEADER)
    assert res_by_id.status_code == 200
    assert res_by_id.json()["id"] == email_id

    # 2. Fetch by RFC 5322 Message-ID
    res_by_msg_id = client.get(f"/api/v1/emails/{message_id}", headers=AUTH_HEADER)
    assert res_by_msg_id.status_code == 200
    assert res_by_msg_id.json()["id"] == email_id

    # 3. Missing ID returns 404
    res_404 = client.get("/api/v1/emails/non-existent-uuid-99999", headers=AUTH_HEADER)
    assert res_404.status_code == 404
    assert "not found" in res_404.json()["detail"].lower()


def test_get_email_findings(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/findings retrieves persisted findings from database."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    phish_email = next(e for e in emails if "Password" in e["subject"] or e["riskScore"] > 50)

    res_findings = client.get(f"/api/v1/emails/{phish_email['id']}/findings", headers=AUTH_HEADER)
    assert res_findings.status_code == 200
    data = res_findings.json()
    assert "findings" in data
    assert "authResults" in data
    assert "urlFindings" in data

    # Missing email findings 404
    res_404 = client.get("/api/v1/emails/missing-email-id/findings", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_get_email_tags(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/tags retrieves persisted security tags."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    email_id = emails[0]["id"]

    res_tags = client.get(f"/api/v1/emails/{email_id}/tags", headers=AUTH_HEADER)
    assert res_tags.status_code == 200
    data = res_tags.json()
    assert "tags" in data
    assert isinstance(data["tags"], list)

    # Missing email tags 404
    res_404 = client.get("/api/v1/emails/missing-email-id/tags", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_get_email_risk(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/risk retrieves authoritative persisted risk verdict."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    email_id = emails[0]["id"]

    res_risk = client.get(f"/api/v1/emails/{email_id}/risk", headers=AUTH_HEADER)
    assert res_risk.status_code == 200
    data = res_risk.json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert "threat_confidence" in data
    assert "classification" in data

    # Missing email 404
    res_404 = client.get("/api/v1/emails/missing-id/risk", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_get_email_decision(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/decision retrieves authoritative policy decision."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    email_id = emails[0]["id"]

    res_dec = client.get(f"/api/v1/emails/{email_id}/decision", headers=AUTH_HEADER)
    assert res_dec.status_code == 200
    data = res_dec.json()
    assert "action" in data
    assert "classification" in data
    assert "risk_score" in data

    # Missing email 404
    res_404 = client.get("/api/v1/emails/missing-id/decision", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_get_email_ml_result(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/ml-result retrieves persisted ML prediction."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    email_id = emails[0]["id"]

    res_ml = client.get(f"/api/v1/emails/{email_id}/ml-result", headers=AUTH_HEADER)
    assert res_ml.status_code == 200
    data = res_ml.json()
    assert "prediction" in data
    assert "confidence" in data
    assert "model_version" in data
    assert data["provenance"] == "MODEL_PREDICTION"

    # Missing email 404
    res_404 = client.get("/api/v1/emails/missing-id/ml-result", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_get_email_evidence(seed_pipeline_emails):
    """GET /api/v1/emails/{id}/evidence retrieves cryptographic evidence records."""
    res = client.get("/api/v1/emails", headers=AUTH_HEADER)
    emails = res.json()
    email_id = emails[0]["id"]

    res_ev = client.get(f"/api/v1/emails/{email_id}/evidence", headers=AUTH_HEADER)
    assert res_ev.status_code == 200
    data = res_ev.json()
    assert "evidence" in data
    assert data["provenance"] == "VERIFIED_EVIDENCE"

    # Missing email 404
    res_404 = client.get("/api/v1/emails/missing-id/evidence", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_spam_endpoints(seed_pipeline_emails):
    """GET /api/v1/spam and /api/v1/spam/{id} retrieve spam-routed emails."""
    res_spam_list = client.get("/api/v1/spam", headers=AUTH_HEADER)
    assert res_spam_list.status_code == 200
    spam_items = res_spam_list.json()

    if spam_items:
        spam_id = spam_items[0]["id"]
        res_single = client.get(f"/api/v1/spam/{spam_id}", headers=AUTH_HEADER)
        assert res_single.status_code == 200
        assert res_single.json()["id"] == spam_id

    # 404 for missing spam
    res_404 = client.get("/api/v1/spam/non-existent-spam", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_quarantine_endpoints(seed_pipeline_emails):
    """GET /api/v1/quarantine and /api/v1/quarantine/{id} return sanitized reports."""
    res_quar_list = client.get("/api/v1/quarantine", headers=AUTH_HEADER)
    assert res_quar_list.status_code == 200
    quar_items = res_quar_list.json()
    assert len(quar_items) >= 1

    item = quar_items[0]
    assert item["action"] == "QUARANTINE"
    assert item["original_content_blocked"] is True
    assert item["attachments_blocked"] is True
    assert "sanitized_report" in item

    # Single quarantine item
    res_single = client.get(f"/api/v1/quarantine/{item['id']}", headers=AUTH_HEADER)
    assert res_single.status_code == 200
    single_data = res_single.json()
    assert single_data["id"] == item["id"]
    assert single_data["original_content_blocked"] is True

    # 404 for missing quarantine
    res_404 = client.get("/api/v1/quarantine/non-existent-id", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_security_overview(seed_pipeline_emails):
    """GET /api/v1/security/overview returns live database-backed SOC statistics."""
    res = client.get("/api/v1/security/overview", headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    assert "activeThreatsCount" in data
    assert "scannedCount" in data
    assert data["scannedCount"] == 6
    assert "quarantinedCount" in data
    assert "classificationsBreakdown" in data
    assert "riskDistribution" in data
    assert "engineStatuses" in data
    assert "recentQuarantineActivity" in data
    assert "recentEvents" in data


def test_security_threats(seed_pipeline_emails):
    """GET /api/v1/security/threats returns threat queue with risk scores and tags."""
    res = client.get("/api/v1/security/threats", headers=AUTH_HEADER)
    assert res.status_code == 200
    threats = res.json()
    assert len(threats) >= 1

    threat = threats[0]
    assert "threatId" in threat
    assert "emailId" in threat
    assert "riskScore" in threat
    assert "investigationStatus" in threat

    # Filter by status
    res_open = client.get("/api/v1/security/threats?status=OPEN", headers=AUTH_HEADER)
    assert res_open.status_code == 200
    for t in res_open.json():
        assert t["investigationStatus"] == "OPEN"


def test_security_investigation_and_details(seed_pipeline_emails):
    """GET /api/v1/security/investigations/{id}, timelines, infrastructure, evidence, cases."""
    # Get a threat email
    res_threats = client.get("/api/v1/security/threats", headers=AUTH_HEADER)
    threats = res_threats.json()
    target_id = threats[0]["emailId"]

    # 1. Investigation packet
    res_inv = client.get(f"/api/v1/security/investigations/{target_id}", headers=AUTH_HEADER)
    assert res_inv.status_code == 200
    inv = res_inv.json()
    assert inv["emailId"] == target_id
    assert "riskInfo" in inv
    assert "securityTags" in inv
    assert "authFindings" in inv
    assert "domainFindings" in inv
    assert "urlFindings" in inv
    assert "attachmentFindings" in inv
    assert "qrFindings" in inv
    assert "behavioralFindings" in inv
    assert "mlFindings" in inv
    assert "evidenceRecord" in inv
    assert "timelineEvents" in inv
    assert "infrastructureInfo" in inv
    assert "forensicCase" in inv

    # 2. Timeline
    res_time = client.get(f"/api/v1/security/timelines/{target_id}", headers=AUTH_HEADER)
    assert res_time.status_code == 200
    timeline = res_time.json()
    assert isinstance(timeline, list)
    assert len(timeline) >= 1

    # 3. Infrastructure
    res_infra = client.get(f"/api/v1/security/infrastructure/{target_id}", headers=AUTH_HEADER)
    assert res_infra.status_code == 200
    infra = res_infra.json()
    assert "originIp" in infra
    assert "networkHops" in infra
    assert "disclaimer" in infra

    # 4. Security Evidence
    res_ev = client.get(f"/api/v1/security/evidence/{target_id}", headers=AUTH_HEADER)
    assert res_ev.status_code == 200
    assert "sha256Hash" in res_ev.json()

    # 5. Security Case
    res_case = client.get(f"/api/v1/security/cases/{target_id}", headers=AUTH_HEADER)
    assert res_case.status_code == 200
    assert "caseId" in res_case.json()

    # 6. Missing investigation returns 404
    res_404 = client.get("/api/v1/security/investigations/missing-inv-id", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_cases_endpoints(seed_pipeline_emails):
    """GET /api/v1/cases, GET /api/v1/cases/{id}, POST /api/v1/cases."""
    # List cases
    res_cases = client.get("/api/v1/cases", headers=AUTH_HEADER)
    assert res_cases.status_code == 200
    cases = res_cases.json()
    assert len(cases) >= 1

    case_id = cases[0]["id"]
    res_single = client.get(f"/api/v1/cases/{case_id}", headers=AUTH_HEADER)
    assert res_single.status_code == 200
    assert res_single.json()["id"] == case_id

    # Create new case
    payload = {
        "title": "Manual Investigation of Suspicious BEC Campaign",
        "description": "SOC analyst initiated deep dive",
        "status": "OPEN",
        "severity": "CRITICAL",
        "tags": ["BEC", "EXECUTIVE_IMPERSONATION"],
    }
    res_create = client.post("/api/v1/cases", json=payload, headers=AUTH_HEADER)
    assert res_create.status_code == 201
    created_case = res_create.json()
    assert created_case["title"] == payload["title"]
    assert created_case["severity"] == "CRITICAL"

    # Missing case 404
    res_404 = client.get("/api/v1/cases/non-existent-case-id", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_fono_overview(seed_pipeline_emails):
    """GET /api/v1/fono/overview returns user metrics and recent deliveries."""
    res = client.get("/api/v1/fono/overview", headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    assert "stats" in data
    stats = data["stats"]
    assert stats["totalReceived"] == 6
    assert "inboxCount" in stats
    assert "quarantineCount" in stats
    assert "recentDeliveries" in data
    assert len(data["recentDeliveries"]) <= 5


def test_analysis_retrieval(seed_pipeline_emails):
    """GET /api/v1/analysis/{analysis_id} retrieves persisted AnalysisRun by ID."""
    phish_data = seed_pipeline_emails["phishing"]
    analysis_id = phish_data["analysis_id"]

    res = client.get(f"/api/v1/analysis/{analysis_id}", headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()
    assert data["analysis_id"] == analysis_id
    assert "status" in data
    assert "overall_risk_score" in data
    assert "classification" in data

    # Missing analysis run 404
    res_404 = client.get("/api/v1/analysis/non-existent-analysis-id", headers=AUTH_HEADER)
    assert res_404.status_code == 404


def test_api_prefix_alias(seed_pipeline_emails):
    """Verify both /api/v1/emails and /api/emails work identically."""
    res_v1 = client.get("/api/v1/emails", headers=AUTH_HEADER)
    res_alias = client.get("/api/emails", headers=AUTH_HEADER)

    assert res_v1.status_code == 200
    assert res_alias.status_code == 200
    assert len(res_v1.json()) == len(res_alias.json())
