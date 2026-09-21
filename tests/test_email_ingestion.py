import socket
from unittest.mock import patch
import pytest

from app.core.config import settings
from app.core.errors import EmailIngestionError
from app.schemas.email import EmailNormalized
from app.services.analyzers.context import AnalysisContext
from app.services.email_ingestion import EmailIngestionService


@pytest.fixture
def service() -> EmailIngestionService:
    return EmailIngestionService()


def test_plain_text_email_parsing(service):
    """1. Simple plain-text email parses correctly."""
    raw_mime = (
        b"From: John Doe <john@example.com>\r\n"
        b"To: Jane Smith <jane@target.com>\r\n"
        b"Subject: Meeting Request\r\n"
        b"Message-ID: <msg-plain-001@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hello Jane, let us meet tomorrow at 10 AM.\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert isinstance(normalized, EmailNormalized)
    assert normalized.message_id == "<msg-plain-001@example.com>"
    assert normalized.sender.address == "john@example.com"
    assert normalized.sender.name == "John Doe"
    assert normalized.recipients[0].address == "jane@target.com"
    assert normalized.subject == "Meeting Request"
    assert "Hello Jane" in normalized.body_text_preview


def test_html_email_extraction_without_execution(service):
    """2. HTML email is extracted safely without execution."""
    raw_mime = (
        b"From: Promo <promo@store.com>\r\n"
        b"To: User <user@domain.com>\r\n"
        b"Subject: Special Offer\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body><script>alert('xss')</script><h1>Big Sale</h1><a href='https://example.com/buy'>Click</a></body></html>"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert normalized.sender.address == "promo@store.com"
    assert "Big Sale" in normalized.body_text_preview
    # Passive URL extracted from HTML
    assert len(normalized.urls) == 1
    assert normalized.urls[0].url == "https://example.com/buy"


def test_multipart_alternative_email(service):
    """3. Multipart alternative email is handled."""
    raw_mime = (
        b"From: Sender <sender@domain.com>\r\n"
        b"To: Recipient <recip@domain.com>\r\n"
        b"Subject: Multipart Test\r\n"
        b"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n"
        b"\r\n"
        b"--boundary123\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Plain text version\r\n"
        b"--boundary123\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>HTML version</p>\r\n"
        b"--boundary123--\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert "Plain text version" in normalized.body_text_preview


def test_sender_normalization(service):
    """4. Sender display-name/address are normalized."""
    addr1 = service._normalize_address_item("Alice Bob <alice@example.com>")
    assert addr1.address == "alice@example.com"
    assert addr1.name == "Alice Bob"

    addr2 = service._normalize_address_item("plain_user@test.org")
    assert addr2.address == "plain_user@test.org"
    assert addr2.name is None


def test_multiple_recipients(service):
    """5. Multiple recipients are handled."""
    raw_mime = (
        b"From: sender@domain.com\r\n"
        b"To: user1@domain.com, User 2 <user2@domain.com>\r\n"
        b"Cc: user3@domain.com\r\n"
        b"Subject: Group Email\r\n"
        b"\r\n"
        b"Hello everyone.\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    addresses = [r.address for r in normalized.recipients]
    assert "user1@domain.com" in addresses
    assert "user2@domain.com" in addresses
    assert "user3@domain.com" in addresses


def test_header_extraction(service):
    """6. Important headers are extracted."""
    raw_mime = (
        b"From: sender@domain.com\r\n"
        b"To: recip@domain.com\r\n"
        b"Subject: Header Check\r\n"
        b"X-Custom-Header: SecurityTest\r\n"
        b"Return-Path: <bounce@domain.com>\r\n"
        b"\r\n"
        b"Test body\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert normalized.headers.get("X-Custom-Header") == "SecurityTest"
    assert normalized.headers.get("Return-Path") == "<bounce@domain.com>"


def test_received_hops_extraction(service):
    """7. Received headers are extracted into ReceivedHop structures."""
    raw_mime = (
        b"From: sender@domain.com\r\n"
        b"To: recip@domain.com\r\n"
        b"Received: from mail.sending.com ([192.0.2.1]) by mx.target.com; Sun, 21 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: Hop Test\r\n"
        b"\r\n"
        b"Body text\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert len(normalized.received_hops) >= 1
    hop = normalized.received_hops[0]
    assert hop.from_host == "mail.sending.com"
    assert hop.ip_address == "192.0.2.1"


def test_attachment_metadata_extraction(service):
    """8. Attachment metadata is extracted without file execution."""
    raw_mime = (
        b"From: sender@domain.com\r\n"
        b"To: recip@domain.com\r\n"
        b"Subject: Attachment Test\r\n"
        b"Content-Type: multipart/mixed; boundary=\"boundary456\"\r\n"
        b"\r\n"
        b"--boundary456\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"See attached invoice.\r\n"
        b"--boundary456\r\n"
        b"Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.xlsm\"\r\n"
        b"\r\n"
        b"fake_file_content_bytes\r\n"
        b"--boundary456--\r\n"
    )

    normalized = service.parse_raw_email(raw_mime)
    assert len(normalized.attachments) == 1
    att = normalized.attachments[0]
    assert att.filename == "invoice.xlsm"
    assert att.has_macro is True
    assert att.sha256_hash is not None


def test_passive_url_extraction(service):
    """9. URLs are extracted passively."""
    dict_payload = {
        "sender": "sender@domain.com",
        "recipients": ["user@target.com"],
        "subject": "Link Test",
        "body": "Check these links: https://bit.ly/shortlink and http://192.168.1.1/admin and https://example.top/test",
    }

    normalized = service.parse_dict(dict_payload)
    extracted_urls = {u.url: u for u in normalized.urls}
    assert "https://bit.ly/shortlink" in extracted_urls
    assert extracted_urls["https://bit.ly/shortlink"].is_shortened is True

    assert "http://192.168.1.1/admin" in extracted_urls
    assert extracted_urls["http://192.168.1.1/admin"].is_ip is True

    assert "https://example.top/test" in extracted_urls
    assert extracted_urls["https://example.top/test"].suspicious_tld is True


def test_malformed_email_handling(service):
    """10. Malformed email does not crash unexpectedly."""
    malformed_bytes = b"From: ::: invalid email :::\r\nSubject: ===???===\r\n\r\nGarbage payload \x80\xff"
    normalized = service.parse_raw_email(malformed_bytes)
    assert isinstance(normalized, EmailNormalized)
    assert normalized.sender.address is not None


def test_empty_missing_optional_fields(service):
    """11. Empty/missing optional fields are handled correctly."""
    dict_payload = {"sender": "user@test.org"}
    normalized = service.parse_dict(dict_payload)
    assert normalized.sender.address == "user@test.org"
    assert normalized.subject == ""
    assert normalized.attachments == []
    assert normalized.urls == []


def test_oversized_input_rejection(service):
    """12. Oversized raw email input is rejected."""
    oversized_bytes = b"A" * (settings.MAX_RAW_EMAIL_BYTES + 1024)
    with pytest.raises(EmailIngestionError, match="exceeds maximum limit"):
        service.parse_raw_email(oversized_bytes)


def test_raw_content_not_logged_in_errors(service):
    """13. Raw email secret content is not leaked in exception messages."""
    dict_payload = "invalid_string_instead_of_dict"
    try:
        service.parse_dict(dict_payload)
    except EmailIngestionError as exc:
        assert "invalid_string" not in str(exc)
        assert exc.message == "Input data must be a dictionary"


def test_deterministic_output(service):
    """14. Same input produces deterministic normalized output."""
    raw_mime = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\nMessage-ID: <m1@b.com>\r\n\r\nBody"
    norm1 = service.parse_raw_email(raw_mime)
    norm2 = service.parse_raw_email(raw_mime)
    assert norm1.message_id == norm2.message_id
    assert norm1.sender.address == norm2.sender.address
    assert norm1.subject == norm2.subject


def test_analysis_context_compatibility(service):
    """15. Normalized email result can be passed into AnalysisContext."""
    raw_mime = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\nMessage-ID: <m1@b.com>\r\n\r\nBody"
    normalized = service.parse_raw_email(raw_mime)

    ctx = AnalysisContext(analysis_id="run-100", email=normalized)
    assert ctx.analysis_id == "run-100"
    assert ctx.email.message_id == "<m1@b.com>"


def test_security_guarantees_no_external_network_calls(service):
    """16. Explicitly verify no socket/HTTP/DNS network calls occur during ingestion."""
    raw_mime = (
        b"From: sender@domain.com\r\n"
        b"To: recip@domain.com\r\n"
        b"Received: from malicious.remote ([198.51.100.1]) by mx.target.com; Sun, 21 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: Security Test\r\n"
        b"\r\n"
        b"Visit http://suspicious-malicious-domain.xyz/phish"
    )

    with patch("socket.socket") as mock_socket, patch("socket.gethostbyname") as mock_dns:
        normalized = service.parse_raw_email(raw_mime)
        assert mock_socket.called is False
        assert mock_dns.called is False
        assert len(normalized.urls) == 1
