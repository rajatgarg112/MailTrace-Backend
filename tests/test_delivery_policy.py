from unittest.mock import patch
import pytest

from app.schemas.decision import (
    DeliveryAction,
    PolicyDecision,
    SecurityGatewayCategory,
    SpamCategory,
    ThreatClassification,
)
from app.schemas.risk import RiskLevel, RiskResult
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.correlation_engine import CorrelationOutput
from app.services.delivery_policy import DeliveryPolicyEngine


@pytest.fixture
def policy_engine() -> DeliveryPolicyEngine:
    return DeliveryPolicyEngine()


def test_safe_classification_to_inbox(policy_engine):
    """1. SAFE classification maps to INBOX delivery action."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=1.0)
    decision = policy_engine.evaluate_policy(ThreatClassification.SAFE, risk)
    assert isinstance(decision, PolicyDecision)
    assert decision.action == DeliveryAction.INBOX
    assert decision.classification == ThreatClassification.SAFE


def test_spam_classification_to_spam(policy_engine):
    """2. SPAM classification maps to SPAM delivery action with SpamCategory."""
    risk = RiskResult(overall_risk_score=25.0, risk_level=RiskLevel.LOW, threat_confidence=0.9)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="MARKETING_MAIL", severity=SeverityLevel.LOW, description="Promo mail")],
        security_tags=["Marketing"]
    )
    decision = policy_engine.evaluate_policy(ThreatClassification.SPAM, risk, corr)
    assert decision.action == DeliveryAction.SPAM
    assert decision.spam_category == SpamCategory.MARKETING


def test_suspicious_classification_to_warn_or_hold(policy_engine):
    """3. SUSPICIOUS classification maps to WARN (or HOLD if high risk)."""
    risk_med = RiskResult(overall_risk_score=45.0, risk_level=RiskLevel.MEDIUM, threat_confidence=0.85)
    decision_med = policy_engine.evaluate_policy(ThreatClassification.SUSPICIOUS, risk_med)
    assert decision_med.action == DeliveryAction.WARN

    risk_high = RiskResult(overall_risk_score=75.0, risk_level=RiskLevel.HIGH, threat_confidence=0.85)
    decision_high = policy_engine.evaluate_policy(ThreatClassification.SUSPICIOUS, risk_high)
    assert decision_high.action == DeliveryAction.HOLD


def test_malicious_classification_to_quarantine(policy_engine):
    """4. MALICIOUS classification maps to QUARANTINE delivery action."""
    risk = RiskResult(overall_risk_score=95.0, risk_level=RiskLevel.CRITICAL, threat_confidence=0.95)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="MALICIOUS_ATTACHMENT", severity=SeverityLevel.CRITICAL, description="Trojan binary")],
        security_tags=["Malicious-Attachment"]
    )
    decision = policy_engine.evaluate_policy(ThreatClassification.MALICIOUS, risk, corr)
    assert decision.action == DeliveryAction.QUARANTINE
    assert decision.gateway_category == SecurityGatewayCategory.MALWARE


def test_unknown_classification_to_hold(policy_engine):
    """5. UNKNOWN classification maps to conservative HOLD uncertainty action."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=0.30)
    decision = policy_engine.evaluate_policy(ThreatClassification.UNKNOWN, risk)
    assert decision.action == DeliveryAction.HOLD
    assert decision.action != DeliveryAction.INBOX
    assert decision.action != DeliveryAction.REJECT


def test_independent_risk_and_classification_combinations(policy_engine):
    """6, 7, 8, 9. Test explicit separation between RiskLevel, ThreatClassification, and DeliveryAction."""
    # Case A: RiskLevel = HIGH + Classification = SUSPICIOUS -> Action = HOLD
    risk_a = RiskResult(overall_risk_score=75.0, risk_level=RiskLevel.HIGH, threat_confidence=0.8)
    dec_a = policy_engine.evaluate_policy(ThreatClassification.SUSPICIOUS, risk_a)
    assert dec_a.risk_level == RiskLevel.HIGH
    assert dec_a.classification == ThreatClassification.SUSPICIOUS
    assert dec_a.action == DeliveryAction.HOLD

    # Case B: RiskLevel = MEDIUM + Classification = MALICIOUS -> Action = QUARANTINE
    risk_b = RiskResult(overall_risk_score=50.0, risk_level=RiskLevel.MEDIUM, threat_confidence=0.9)
    dec_b = policy_engine.evaluate_policy(ThreatClassification.MALICIOUS, risk_b)
    assert dec_b.risk_level == RiskLevel.MEDIUM
    assert dec_b.classification == ThreatClassification.MALICIOUS
    assert dec_b.action == DeliveryAction.QUARANTINE

    # Case C: RiskLevel = HIGH + Classification = SPAM -> Action = SPAM
    risk_c = RiskResult(overall_risk_score=70.0, risk_level=RiskLevel.HIGH, threat_confidence=0.85)
    dec_c = policy_engine.evaluate_policy(ThreatClassification.SPAM, risk_c)
    assert dec_c.risk_level == RiskLevel.HIGH
    assert dec_c.classification == ThreatClassification.SPAM
    assert dec_c.action == DeliveryAction.SPAM

    # Case D: RiskLevel = LOW + Classification = UNKNOWN -> Action = HOLD
    risk_d = RiskResult(overall_risk_score=10.0, risk_level=RiskLevel.LOW, threat_confidence=0.3)
    dec_d = policy_engine.evaluate_policy(ThreatClassification.UNKNOWN, risk_d)
    assert dec_d.risk_level == RiskLevel.LOW
    assert dec_d.classification == ThreatClassification.UNKNOWN
    assert dec_d.action == DeliveryAction.HOLD


def test_no_destructive_action_on_analyzer_failure(policy_engine):
    """10. Analyzer failure/uncertainty does not cause destructive REJECT/QUARANTINE solely due to missing analyzer."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=0.4)
    decision = policy_engine.evaluate_policy(ThreatClassification.UNKNOWN, risk)
    assert decision.action != DeliveryAction.REJECT
    assert decision.action != DeliveryAction.QUARANTINE


def test_deterministic_policy_decision(policy_engine):
    """11 & 12. Deterministic policy evaluation."""
    risk = RiskResult(overall_risk_score=85.0, risk_level=RiskLevel.HIGH, threat_confidence=0.9)
    d1 = policy_engine.evaluate_policy(ThreatClassification.MALICIOUS, risk)
    d2 = policy_engine.evaluate_policy(ThreatClassification.MALICIOUS, risk)
    assert d1.action == d2.action == DeliveryAction.QUARANTINE
    assert d1.reason == d2.reason


def test_no_network_or_db_calls_during_policy_evaluation(policy_engine):
    """14 & 15. Verify no network or database calls occur during policy evaluation."""
    risk = RiskResult(overall_risk_score=50.0, risk_level=RiskLevel.MEDIUM, threat_confidence=0.85)
    with patch("socket.socket") as mock_sock, patch("socket.gethostbyname") as mock_dns:
        decision = policy_engine.evaluate_policy(ThreatClassification.SUSPICIOUS, risk)
        assert mock_sock.called is False
        assert mock_dns.called is False
        assert isinstance(decision, PolicyDecision)
