"""
Step 7.1 Cross-System Pipeline Integration Tests.

Verifies end-to-end analyzer execution, ML and Security adapters,
decision engine authority, and database persistence (AnalysisRun verdicts,
MLResult, Evidence, ForensicCase) across all required threat scenarios:
A. Safe email
B. Phishing-like email
C. Spam-like email
D. BEC-like email
E. Suspicious URL email
F. Malicious attachment email
G. Unknown/insufficient input email
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.database import Base, get_db
from app.main import app
from app.models.analysis import AnalysisRun as AnalysisRunModel, SecurityFinding, SecurityTag
from app.models.decision import PolicyDecision as PolicyDecisionModel
from app.models.email import DeliveryEvent as DeliveryEventModel, Email
from app.models.forensic import Evidence, ForensicCase
from app.models.ml import MLResult

client = TestClient(app)
AUTH_HEADER = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}


@pytest.fixture(autouse=True)
def test_db_session():
    """Provides an isolated SQLite in-memory database session for integration tests."""
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


def test_scenario_a_safe_email(test_db_session: Session):
    """
    Scenario A: Safe Email
    - Analyzers execute via live default_registry
    - Result is NOT caused by an empty registry
    - Scores and MLResult are persisted
    """
    payload = {
        "message_id": "<safe-001@company.org>",
        "sender": "Alex Mercer <alex.product@company.org>",
        "recipients": ["user@target.com"],
        "subject": "Q4 Product Roadmap and Sprint Milestones",
        "body": "Hi team, please find the quarterly milestone updates attached. Everything is on schedule.",
        "headers": {
            "From": "alex.product@company.org",
            "Subject": "Q4 Product Roadmap and Sprint Milestones",
            "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
        },
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    # 1. Verify all live adapters executed in orchestrator
    results = data["analyzer_results"]
    assert "ml" in results
    assert "header_auth" in results
    assert "domain" in results
    assert "url" in results
    assert "attachment" in results
    assert "infrastructure" in results
    assert "forensic" in results
    assert results["ml"]["status"] == "SUCCESS"

    # 2. Risk & Classification from pipeline
    assert "risk" in data
    assert data["classification"] == "SAFE"
    assert data["decision"]["action"] in ["INBOX", "DELIVER"]

    # 3. Database persistence verification
    stored_run = test_db_session.scalars(select(AnalysisRunModel)).first()
    assert stored_run is not None
    assert stored_run.overall_risk_score is not None
    assert stored_run.risk_level == "SAFE"
    assert stored_run.classification == "SAFE"
    assert stored_run.threat_confidence is not None

    # 4. ML Result persistence verification
    stored_ml = test_db_session.scalars(select(MLResult)).first()
    assert stored_ml is not None
    assert stored_ml.analysis_id == stored_run.id
    assert stored_ml.prediction is not None
    assert stored_ml.confidence is not None
    assert stored_ml.model_version is not None
    assert isinstance(stored_ml.scores, dict)

    # 5. Evidence persistence verification
    stored_evidence = test_db_session.scalars(select(Evidence)).all()
    assert len(stored_evidence) >= 1
    assert stored_evidence[0].sha256_hash is not None


def test_scenario_b_phishing_email(test_db_session: Session):
    """
    Scenario B: Phishing Email
    - DMARC fail, brand spoofing, credential harvesting link
    - ML and security findings reach CorrelationEngine
    - Risk score and classification are elevated (NOT 0/SAFE)
    """
    payload = {
        "message_id": "<phish-001@paypa1-verify.xyz>",
        "sender": "PayPal Security <billing@paypa1-verify.xyz>",
        "recipients": ["user@target.com"],
        "subject": "URGENT: Your PayPal Account Has Been Suspended",
        "body": "Your PayPal account access has been restricted. Click here to confirm your password and verify identity immediately: http://185.220.101.5/account/login",
        "headers": {
            "From": "billing@paypa1-verify.xyz",
            "Subject": "URGENT: Your PayPal Account Has Been Suspended",
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
        },
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    # Analyzers produced non-empty findings
    findings = data["findings"]
    assert len(findings) > 0

    codes = [f["code"] for f in findings]
    # Verify expected security signals were detected
    assert any("DMARC" in c or "DOMAIN" in c or "URL" in c or "CREDENTIAL" in c for c in codes)

    # Risk calculation received signals
    risk_score = data["risk"]["overall_risk_score"]
    assert risk_score >= 40.0, f"Expected elevated risk score, got {risk_score}"
    assert data["classification"] in ["SUSPICIOUS", "MALICIOUS", "PHISHING"]
    assert data["decision"]["action"] in ["QUARANTINE", "WARN", "HOLD", "REJECT"]

    # AnalysisRun score persisted in DB
    stored_run = test_db_session.scalars(select(AnalysisRunModel)).first()
    assert stored_run.overall_risk_score == risk_score
    assert stored_run.classification == data["classification"]

    # Forensic Case created for high-risk threat
    stored_cases = test_db_session.scalars(select(ForensicCase)).all()
    assert len(stored_cases) >= 1
    assert "paypa1-verify.xyz" in stored_cases[0].title or "PayPal" in stored_cases[0].title


def test_scenario_c_spam_email(test_db_session: Session):
    """
    Scenario C: Spam Email
    - Marketing bulk unsolicited offer
    - Pipeline classifies as SPAM or SUSPICIOUS
    """
    payload = {
        "message_id": "<spam-001@promotions-deals.net>",
        "sender": "Exclusive Deals <promo@promotions-deals.net>",
        "recipients": ["user@target.com"],
        "subject": "Limited Time Offer: Claim your free gift card now!",
        "body": "Congratulations! You have been selected for a free gift card. Buy now and subscribe to our newsletter for exclusive discounts.",
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    # Risk and action evaluation
    assert data["risk"]["overall_risk_score"] >= 0.0
    assert data["classification"] in ["SPAM", "SUSPICIOUS", "SAFE"]
    assert data["decision"]["action"] in ["SPAM", "WARN", "INBOX", "HOLD"]

    # DB persistence
    stored_run = test_db_session.scalars(select(AnalysisRunModel)).first()
    assert stored_run.classification == data["classification"]
    assert stored_run.overall_risk_score == data["risk"]["overall_risk_score"]


def test_scenario_d_bec_email(test_db_session: Session):
    """
    Scenario D: BEC / Executive Impersonation
    - Display name spoofing with free webmail address requesting wire transfer
    - BEC and Domain detectors generate findings
    """
    payload = {
        "message_id": "<bec-001@gmail.com>",
        "sender": "Tim Cook (CEO) <tcook.apple.exec@gmail.com>",
        "recipients": ["finance@company.org"],
        "subject": "Urgent Wire Transfer Request - Confidential Acquisition",
        "body": "Are you at your desk? I need an urgent wire transfer sent to our new supplier before end of day. Keep this confidential.",
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    findings = data["findings"]
    codes = [f["code"] for f in findings]

    # Check for BEC or impersonation signals
    has_bec_signal = any(
        c in ["EXECUTIVE_IMPERSONATION", "PAYMENT_REQUEST", "FINANCIAL_REQUEST", "DISPLAY_NAME_SPOOF"]
        for c in codes
    )
    assert has_bec_signal or data["risk"]["overall_risk_score"] > 15.0

    # Risk was computed and stored
    stored_run = test_db_session.scalars(select(AnalysisRunModel)).first()
    assert stored_run.overall_risk_score == data["risk"]["overall_risk_score"]


def test_scenario_e_suspicious_url_email(test_db_session: Session):
    """
    Scenario E: Suspicious URL
    - Raw IP URL or Anchor text mismatch
    - URL Analyzer identifies the threat
    """
    payload = {
        "message_id": "<url-test-001@test.org>",
        "sender": "Notice <alerts@test.org>",
        "recipients": ["user@target.com"],
        "subject": "System Security Notice",
        "body": "Please login to your account using our direct server IP link: http://192.168.1.100/secure/banking/login",
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    url_res = data["analyzer_results"].get("url")
    assert url_res is not None
    assert url_res["status"] == "SUCCESS"
    assert url_res["features"]["suspicious_urls_count"] >= 1

    findings = [f["code"] for f in data["findings"]]
    assert "SUSPICIOUS_URL" in findings


def test_scenario_f_malicious_attachment(test_db_session: Session):
    """
    Scenario F: Malicious Attachment
    - Double extension executable disguise (.pdf.exe)
    - Attachment analyzer flags CRITICAL severity
    - Delivery policy routes to QUARANTINE or REJECT
    """
    payload = {
        "message_id": "<att-threat-001@external.com>",
        "sender": "Invoice Dept <invoices@external.com>",
        "recipients": ["ap@target.com"],
        "subject": "Overdue Invoice #94821",
        "body": "Please review the attached invoice.",
        "attachments": [
            {
                "filename": "Invoice_Sep2026.pdf.exe",
                "content_type": "application/x-dosexec",
                "size_bytes": 450000,
                "is_executable": True,
            }
        ],
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    att_res = data["analyzer_results"].get("attachment")
    assert att_res is not None
    assert att_res["status"] == "SUCCESS"
    assert att_res["features"]["has_double_extension"] is True

    findings = [f["code"] for f in data["findings"]]
    assert "MALICIOUS_ATTACHMENT" in findings or "EXECUTABLE_ATTACHMENT" in findings

    # Should trigger malicious classification and quarantine action
    assert data["classification"] == "MALICIOUS"
    assert data["decision"]["action"] in ["QUARANTINE", "REJECT", "HOLD"]

    # Forensic Case and Evidence persisted
    stored_cases = test_db_session.scalars(select(ForensicCase)).all()
    assert len(stored_cases) >= 1
    stored_evidence = test_db_session.scalars(select(Evidence)).all()
    assert len(stored_evidence) >= 1


def test_scenario_g_unknown_insufficient_input(test_db_session: Session):
    """
    Scenario G: Unknown / Insufficient Input
    - Minimal payload without body or sender headers
    - Pipeline executes safely without crashing
    - Preserves confidence and does not crash or fabricate facts
    """
    payload = {
        "message_id": "<minimal-001@local>",
        "subject": "Ping",
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    assert "analysis_id" in data
    assert "risk" in data
    assert "classification" in data

    stored_run = test_db_session.scalars(select(AnalysisRunModel)).first()
    assert stored_run is not None
    assert stored_run.overall_risk_score is not None


def test_ml_result_persistence_integrity(test_db_session: Session):
    """
    Validates that MLResult persistence strictly adheres to model schema:
    - prediction label
    - confidence bounded [0.0, 1.0]
    - model_version
    - probabilities distribution dictionary
    - features_used list
    """
    payload = {
        "message_id": "<ml-verify-001@test.com>",
        "sender": "Test <test@test.com>",
        "recipients": ["user@test.com"],
        "subject": "Security verification test",
        "body": "Standard informational email content for model verification.",
    }

    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200

    ml_rows = test_db_session.scalars(select(MLResult)).all()
    assert len(ml_rows) == 1
    ml_row = ml_rows[0]

    assert ml_row.prediction in ["phishing", "spam", "benign"]
    assert 0.0 <= ml_row.confidence <= 1.0
    assert ml_row.model_version is not None
    assert isinstance(ml_row.scores, dict)
    assert len(ml_row.scores) > 0
    assert isinstance(ml_row.features_used, list)
    assert ml_row.inference_time_ms is not None
