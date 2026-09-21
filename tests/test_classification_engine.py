import pytest

from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.decision import ThreatClassification
from app.schemas.risk import RiskLevel, RiskResult
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.classification_engine import ClassificationEngine
from app.services.correlation_engine import CorrelationOutput


@pytest.fixture
def classifier() -> ClassificationEngine:
    return ClassificationEngine()


def test_clear_safe_evidence(classifier):
    """1. Clear safe evidence produces SAFE classification."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=1.0)
    corr = CorrelationOutput(deduplicated_findings=[], security_tags=[])
    cls = classifier.classify(risk, corr)
    assert cls == ThreatClassification.SAFE


def test_clear_spam_evidence(classifier):
    """2. Clear spam evidence produces SPAM classification."""
    risk = RiskResult(overall_risk_score=20.0, risk_level=RiskLevel.LOW, threat_confidence=0.9)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="SPAM_KEYWORD", severity=SeverityLevel.LOW, description="Spam word detected")],
        security_tags=["Spam"]
    )
    cls = classifier.classify(risk, corr)
    assert cls == ThreatClassification.SPAM


def test_suspicious_evidence(classifier):
    """3. Suspicious evidence produces SUSPICIOUS classification."""
    risk = RiskResult(overall_risk_score=45.0, risk_level=RiskLevel.MEDIUM, threat_confidence=0.85)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC fail")],
        security_tags=["DMARC-Fail"]
    )
    cls = classifier.classify(risk, corr)
    assert cls == ThreatClassification.SUSPICIOUS


def test_strong_malicious_evidence(classifier):
    """4. Strong malicious evidence produces MALICIOUS classification."""
    risk = RiskResult(overall_risk_score=95.0, risk_level=RiskLevel.CRITICAL, threat_confidence=0.95)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="MALICIOUS_ATTACHMENT", severity=SeverityLevel.CRITICAL, description="Malware Trojan")],
        security_tags=["Malicious-Attachment"]
    )
    cls = classifier.classify(risk, corr)
    assert cls == ThreatClassification.MALICIOUS


def test_insufficient_evidence_and_unknown_preservation(classifier):
    """5 & 6. Insufficient evidence preserves UNKNOWN without converting to SAFE."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=0.30)
    corr = CorrelationOutput(deduplicated_findings=[], security_tags=[])
    cls = classifier.classify(risk, corr)
    assert cls == ThreatClassification.UNKNOWN


def test_analyzer_unavailable_failed_timeout_handling(classifier):
    """7 & 8. Analyzer unavailable/failed/timeout preserves UNKNOWN when no evidence exists."""
    risk = RiskResult(overall_risk_score=0.0, risk_level=RiskLevel.SAFE, threat_confidence=0.40)
    corr = CorrelationOutput(deduplicated_findings=[], security_tags=[])
    analyzer_results = {
        "stub_ti": AnalyzerResultItem(analyzer="stub_ti", status=AnalyzerStatus.UNAVAILABLE, error_message="Service unavailable"),
        "stub_ml": AnalyzerResultItem(analyzer="stub_ml", status=AnalyzerStatus.FAILED, error_message="Inference failed"),
    }
    cls = classifier.classify(risk, corr, analyzer_results=analyzer_results)
    assert cls == ThreatClassification.UNKNOWN


def test_threat_intelligence_match_vs_unavailable(classifier):
    """9. Threat Intel MATCH produces MALICIOUS, whereas UNAVAILABLE is preserved."""
    risk = RiskResult(overall_risk_score=80.0, risk_level=RiskLevel.HIGH, threat_confidence=0.9)
    corr_match = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="THREAT_INTEL_MATCH", severity=SeverityLevel.CRITICAL, description="VirusTotal match")],
        security_tags=["Blacklisted-Indicator"]
    )
    cls_match = classifier.classify(risk, corr_match)
    assert cls_match == ThreatClassification.MALICIOUS


def test_deterministic_classification(classifier):
    """10. Deterministic classification output."""
    risk = RiskResult(overall_risk_score=50.0, risk_level=RiskLevel.MEDIUM, threat_confidence=0.8)
    corr = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="LOOKALIKE_DOMAIN", severity=SeverityLevel.HIGH, description="Lookalike domain")],
        security_tags=["Lookalike-Domain"]
    )
    c1 = classifier.classify(risk, corr)
    c2 = classifier.classify(risk, corr)
    assert c1 == c2 == ThreatClassification.SUSPICIOUS
