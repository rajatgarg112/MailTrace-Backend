import pytest

from app.schemas.analysis import AnalysisRun, AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.risk import RiskLevel, RiskResult
from app.schemas.security import CanonicalSecurityFeatures, SecurityFinding, SeverityLevel
from app.services.correlation_engine import CorrelationEngine, CorrelationOutput
from app.services.risk_engine import RiskEngine


@pytest.fixture
def correlation_engine() -> CorrelationEngine:
    return CorrelationEngine()


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


def test_correlation_engine_deduplication_and_tagging(correlation_engine):
    """1 & 2. Correlation engine deduplicates findings and maps finding codes to security tags."""
    f1 = SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC check failed")
    f2 = SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC check failed")  # Duplicate
    f3 = SecurityFinding(code="SUSPICIOUS_URL", severity=SeverityLevel.HIGH, description="Phishing URL detected")

    run = AnalysisRun(
        analysis_id="run-corr-1",
        email_id="msg-corr-1",
        status=AnalyzerStatus.SUCCESS,
        analyzer_results={
            "auth": AnalyzerResultItem(analyzer="auth", status=AnalyzerStatus.SUCCESS, findings=[f1, f2]),
            "url": AnalyzerResultItem(analyzer="url", status=AnalyzerStatus.SUCCESS, findings=[f3]),
        }
    )

    output = correlation_engine.correlate(run)
    assert isinstance(output, CorrelationOutput)
    # Deduplicated from 3 to 2 unique findings
    assert len(output.deduplicated_findings) == 2
    assert "DMARC-Fail" in output.security_tags
    assert "Suspicious-URL" in output.security_tags


def test_risk_engine_empty_findings(risk_engine):
    """5. Risk engine handles empty findings cleanly."""
    empty_output = CorrelationOutput(deduplicated_findings=[], security_tags=[])
    risk_res = risk_engine.calculate_risk(empty_output)
    assert isinstance(risk_res, RiskResult)
    assert risk_res.overall_risk_score == 0.0
    assert risk_res.risk_level == RiskLevel.SAFE
    assert risk_res.threat_confidence == 1.0
    assert risk_res.contributing_findings == []
    assert "No security threats" in risk_res.explanation


def test_risk_engine_score_and_level_mapping(risk_engine):
    """3. Risk engine calculates composite score and maps score ranges to RiskLevel."""
    # Low risk finding (score >= 15.0)
    output_low = CorrelationOutput(
        deduplicated_findings=[
            SecurityFinding(code="LOW_ANOMALY_1", severity=SeverityLevel.LOW, description="Minor anomaly 1"),
            SecurityFinding(code="LOW_ANOMALY_2", severity=SeverityLevel.LOW, description="Minor anomaly 2"),
            SecurityFinding(code="LOW_ANOMALY_3", severity=SeverityLevel.LOW, description="Minor anomaly 3"),
        ],
        security_tags=["Low-Anomaly-1", "Low-Anomaly-2", "Low-Anomaly-3"]
    )
    res_low = risk_engine.calculate_risk(output_low)
    assert res_low.risk_level == RiskLevel.LOW
    assert res_low.overall_risk_score == 15.0


    # Medium risk finding (score 65.0)
    output_medium = CorrelationOutput(
        deduplicated_findings=[
            SecurityFinding(code="MALICIOUS_ATTACHMENT", severity=SeverityLevel.CRITICAL, description="Malware binary"),
            SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC failed")
        ],
        security_tags=["Malicious-Attachment", "DMARC-Fail"]
    )
    res_medium = risk_engine.calculate_risk(output_medium)
    assert res_medium.risk_level == RiskLevel.MEDIUM
    assert res_medium.overall_risk_score == 65.0

    # High / Critical risk finding (score >= 70.0)
    output_high = CorrelationOutput(
        deduplicated_findings=[
            SecurityFinding(code="MALICIOUS_ATTACHMENT", severity=SeverityLevel.CRITICAL, description="Malware binary"),
            SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC failed"),
            SecurityFinding(code="CREDENTIAL_REQUEST", severity=SeverityLevel.HIGH, description="Cred request")
        ],
        security_tags=["Malicious-Attachment", "DMARC-Fail", "Credential-Request"]
    )
    res_high = risk_engine.calculate_risk(output_high)
    assert res_high.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert res_high.overall_risk_score >= 70.0



def test_risk_engine_multi_vector_compounding(risk_engine):
    """4. Multi-vector signal correlation compounding multiplier works."""
    # Single vector (auth fail only)
    out_single = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC fail")],
        security_tags=["DMARC-Fail"]
    )
    score_single = risk_engine.calculate_risk(out_single).overall_risk_score

    # Multi-vector (auth fail + domain risk + credential request)
    out_multi = CorrelationOutput(
        deduplicated_findings=[
            SecurityFinding(code="DMARC_FAIL", severity=SeverityLevel.HIGH, description="DMARC fail"),
            SecurityFinding(code="NEW_DOMAIN", severity=SeverityLevel.HIGH, description="New domain"),
            SecurityFinding(code="CREDENTIAL_REQUEST", severity=SeverityLevel.HIGH, description="Cred request")
        ],
        security_tags=["DMARC-Fail", "New-Domain", "Credential-Request"]
    )
    score_multi = risk_engine.calculate_risk(out_multi).overall_risk_score
    # Multi-vector compounding boosts score above sum of individual weights (75 * 1.35 = 100 capped)
    assert score_multi > (25.0 * 3)
    assert score_multi == 100.0


def test_risk_engine_confidence_with_unavailable_analyzers(risk_engine):
    """6. Risk Engine adjusts confidence score when analyzers fail/timeout."""
    out = CorrelationOutput(
        deduplicated_findings=[SecurityFinding(code="SUSPICIOUS_URL", severity=SeverityLevel.MEDIUM, description="Url check")],
        security_tags=["Suspicious-URL"]
    )
    statuses = ["SUCCESS", "SUCCESS", "UNAVAILABLE", "TIMEOUT"]
    res = risk_engine.calculate_risk(out, analyzer_statuses=statuses)
    assert res.threat_confidence < 0.85
    assert res.threat_confidence == 0.55
