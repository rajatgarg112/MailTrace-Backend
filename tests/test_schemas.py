import pytest
from pydantic import ValidationError

from app.schemas import (
    AnalyzerStatus,
    CanonicalSecurityFeatures,
    DeliveryAction,
    EmailAddress,
    EmailNormalized,
    EvidenceRecord,
    MLModelStatus,
    MLPredictionResult,
    PolicyDecision,
    RiskLevel,
    RiskResult,
    SecurityFinding,
    SeverityLevel,
    ThreatClassification,
)


def test_valid_normalized_email():
    """1. Valid normalized email can be created."""
    email = EmailNormalized(
        message_id="<msg-123@example.com>",
        sender=EmailAddress(address="sender@example.com", name="John Doe"),
        recipients=[EmailAddress(address="victim@target.com")],
        subject="Urgent Security Update",
    )
    assert email.message_id == "<msg-123@example.com>"
    assert email.sender.address == "sender@example.com"
    assert email.recipients[0].address == "victim@target.com"


def test_invalid_required_fields_rejected():
    """2. Invalid required fields are rejected."""
    with pytest.raises(ValidationError):
        # Missing required message_id and sender
        EmailNormalized(subject="Test Email")


def test_risk_level_enum():
    """3. Risk enum accepts SAFE/LOW/MEDIUM/HIGH/CRITICAL."""
    expected_levels = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for level in expected_levels:
        result = RiskResult(
            overall_risk_score=50.0,
            risk_level=RiskLevel(level),
            threat_confidence=0.9,
        )
        assert result.risk_level.value == level


def test_classification_enum():
    """4. Classification enum accepts SAFE/SPAM/SUSPICIOUS/MALICIOUS/UNKNOWN."""
    expected_classifications = ["SAFE", "SPAM", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
    for cls_val in expected_classifications:
        decision = PolicyDecision(
            classification=ThreatClassification(cls_val),
            action=DeliveryAction.HOLD,
            risk_level=RiskLevel.MEDIUM,
            risk_score=50.0,
            reason="Test reasoning",
        )
        assert decision.classification.value == cls_val


def test_delivery_action_enum():
    """5. Delivery action values are validated."""
    valid_actions = ["INBOX", "SPAM", "WARN", "HOLD", "QUARANTINE", "REJECT"]
    for action in valid_actions:
        decision = PolicyDecision(
            classification=ThreatClassification.SAFE,
            action=DeliveryAction(action),
            risk_level=RiskLevel.SAFE,
            risk_score=0.0,
            reason="Valid action test",
        )
        assert decision.action.value == action

    with pytest.raises(ValidationError):
        PolicyDecision(
            classification=ThreatClassification.SAFE,
            action="INVALID_ACTION",  # type: ignore
            risk_level=RiskLevel.SAFE,
            risk_score=0.0,
            reason="Invalid action test",
        )



def test_ml_result_success():
    """6. ML result can represent a successful prediction."""
    ml_res = MLPredictionResult(
        model_name="bec_nlp_classifier",
        model_version="v1.2.0",
        status=MLModelStatus.SUCCESS,
        prediction="PHISHING",
        confidence=0.95,
        scores={"phishing": 0.95, "spam": 0.1},
    )
    assert ml_res.status == MLModelStatus.SUCCESS
    assert ml_res.prediction == "PHISHING"
    assert ml_res.confidence == 0.95


def test_ml_result_error_state():
    """7. ML result can represent unavailable/error state if specified."""
    ml_res = MLPredictionResult(
        model_name="bec_nlp_classifier",
        model_version="v1.2.0",
        status=MLModelStatus.MODEL_UNAVAILABLE,
        error_message="Model server connection timed out",
    )
    assert ml_res.status == MLModelStatus.MODEL_UNAVAILABLE
    assert ml_res.prediction is None
    assert ml_res.error_message == "Model server connection timed out"


def test_security_finding():
    """8. Security finding validates correctly."""
    finding = SecurityFinding(
        code="DMARC_FAIL",
        severity=SeverityLevel.HIGH,
        description="DMARC check failed for domain example.com",
        details={"domain": "example.com", "policy": "reject"},
    )
    assert finding.code == "DMARC_FAIL"
    assert finding.severity == SeverityLevel.HIGH


def test_evidence_record_sha256():
    """9. Evidence/hash schema validates correctly."""
    valid_hash = "a" * 64
    evidence = EvidenceRecord(
        evidence_id="ev-001",
        email_id="msg-123",
        evidence_type="HEADER",
        sha256_hash=valid_hash,
    )
    assert evidence.sha256_hash == valid_hash

    with pytest.raises(ValidationError):
        # Invalid hash (short length)
        EvidenceRecord(
            evidence_id="ev-002",
            email_id="msg-123",
            evidence_type="HEADER",
            sha256_hash="invalid_short_hash",
        )


def test_confidence_and_score_constraints():
    """10. Invalid confidence/score values are rejected where constraints exist."""
    with pytest.raises(ValidationError):
        # confidence > 1.0
        MLPredictionResult(
            model_name="test",
            model_version="1.0",
            confidence=1.5,
        )

    with pytest.raises(ValidationError):
        # risk score > 100.0
        RiskResult(
            overall_risk_score=150.0,
            risk_level=RiskLevel.CRITICAL,
            threat_confidence=0.9,
        )
