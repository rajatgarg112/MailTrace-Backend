from typing import List, Optional, Set
from app.schemas.risk import RiskLevel, RiskResult
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.correlation_engine import CorrelationOutput

# Severity base score weights
SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 40.0,
    SeverityLevel.HIGH: 25.0,
    SeverityLevel.MEDIUM: 15.0,
    SeverityLevel.LOW: 5.0,
    SeverityLevel.INFO: 0.0,
}


class RiskEngine:
    """Calculates composite risk score, risk level, and explainability from correlated security signals."""

    def calculate_risk(
        self,
        correlation_output: CorrelationOutput,
        analyzer_statuses: Optional[List[str]] = None
    ) -> RiskResult:
        """Calculates canonical RiskResult from correlated findings and tags."""
        findings = correlation_output.deduplicated_findings
        tags = correlation_output.security_tags

        if not findings and not tags:
            return RiskResult(
                overall_risk_score=0.0,
                risk_level=RiskLevel.SAFE,
                threat_confidence=1.0,
                contributing_findings=[],
                explanation="No security threats or suspicious anomalies detected."
            )

        base_score = 0.0
        contributing_codes: List[str] = []

        for finding in findings:
            weight = SEVERITY_WEIGHTS.get(finding.severity, 5.0)
            base_score += weight
            if finding.code not in contributing_codes:
                contributing_codes.append(finding.code)

        # Multi-signal correlation compounding boost
        # Example: DMARC-Fail + New-Domain + Credential-Request indicates high-confidence phishing campaign
        has_auth_fail = any("DMARC" in c or "SPF" in c for c in contributing_codes)
        has_domain_risk = any("DOMAIN" in c for c in contributing_codes)
        has_content_risk = any("CREDENTIAL" in c or "IMPERSONATION" in c or "URL" in c for c in contributing_codes)

        if has_auth_fail and has_domain_risk and has_content_risk:
            base_score *= 1.35  # 35% compound risk multiplier for multi-vector threat
        elif has_auth_fail and has_content_risk:
            base_score *= 1.20

        # Cap overall risk score between 0.0 and 100.0
        overall_risk_score = round(min(100.0, max(0.0, base_score)), 2)

        # Map overall score to RiskLevel
        if overall_risk_score < 15.0:
            risk_level = RiskLevel.SAFE
        elif overall_risk_score < 40.0:
            risk_level = RiskLevel.LOW
        elif overall_risk_score < 70.0:
            risk_level = RiskLevel.MEDIUM
        elif overall_risk_score < 90.0:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # Calculate confidence score based on available signal coverage
        confidence = 0.85
        if analyzer_statuses:
            unavail_count = sum(1 for s in analyzer_statuses if s in ("UNAVAILABLE", "FAILED", "TIMEOUT"))
            if unavail_count > 0:
                confidence = max(0.40, round(0.85 - (unavail_count * 0.15), 2))

        # Formulate human-readable explanation
        if contributing_codes:
            explanation = (
                f"Risk evaluated as {risk_level.value} (Score: {overall_risk_score}/100) based on "
                f"{len(contributing_codes)} findings: {', '.join(contributing_codes)}."
            )
        else:
            explanation = f"Risk evaluated as {risk_level.value} (Score: {overall_risk_score}/100)."

        return RiskResult(
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            threat_confidence=confidence,
            contributing_findings=contributing_codes,
            explanation=explanation,
        )
