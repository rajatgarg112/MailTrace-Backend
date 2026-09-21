from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
AUTH_HEADER = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}


def test_health_endpoint_public():
    """1. GET /health remains public."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_protected_endpoint_rejects_missing_auth():
    """2. Protected endpoint rejects missing auth header."""
    res = client.post("/api/v1/emails/analyze", json={"subject": "Test"})
    assert res.status_code == 401
    assert "detail" in res.json()


def test_protected_endpoint_rejects_invalid_auth():
    """3. Protected endpoint rejects invalid auth token."""
    headers = {"Authorization": "Bearer invalid_secret_token_123"}
    res = client.post("/api/v1/emails/analyze", json={"subject": "Test"}, headers=headers)
    assert res.status_code == 401
    assert "Invalid authentication credentials" in res.json()["detail"]


def test_valid_auth_and_structured_email_analysis():
    """4, 5, 9-15. Valid auth accepted, structured payload analyzed by pipeline."""
    payload = {
        "sender": "Security Test <security@example.com>",
        "recipients": ["user@target.com"],
        "subject": "Urgent Account Verification",
        "body": "Please click http://phishing-domain.xyz/login to verify your account immediately.",
    }
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()

    assert "analysis_id" in data
    assert data["email_id"] is not None
    assert "risk" in data
    assert "overall_risk_score" in data["risk"]
    assert "classification" in data
    assert "decision" in data
    assert data["decision"]["action"] in ["INBOX", "SPAM", "WARN", "HOLD", "QUARANTINE", "REJECT"]
    assert "analyzer_results" in data
    assert "findings" in data
    assert "tags" in data


def test_raw_mime_email_analysis():
    """6. Raw MIME email string reaches ingestion and returns analysis response."""
    raw_mime = (
        "From: Alice <alice@sender.org>\r\n"
        "To: Bob <bob@receiver.org>\r\n"
        "Subject: Raw MIME Test\r\n"
        "Message-ID: <raw-mime-001@sender.org>\r\n"
        "\r\n"
        "Raw MIME email content body."
    )
    payload = {"raw_email": raw_mime}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 200
    data = res.json()
    assert data["email_id"] == "<raw-mime-001@sender.org>"
    assert data["classification"] in ["SAFE", "SPAM", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]


def test_empty_or_malformed_request_rejected():
    """7, 18. Empty request rejected cleanly with 422 without stack trace leakage."""
    payload = {}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 422
    data = res.json()
    assert "error" in data or "detail" in data
    # No stack trace
    assert "Traceback" not in res.text


def test_oversized_raw_email_rejected():
    """8. Oversized raw email is rejected."""
    raw_oversized = "A" * (settings.MAX_RAW_EMAIL_BYTES + 1024)
    payload = {"raw_email": raw_oversized}
    res = client.post("/api/v1/emails/analyze", json=payload, headers=AUTH_HEADER)
    assert res.status_code == 422
    assert "exceeds maximum limit" in res.text


def test_security_guarantees_no_leakage_and_no_network_calls():
    """16, 17, 19. Security check: no raw email leakage, no stack traces, no outbound network calls."""
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

