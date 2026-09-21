from typing import Dict, List, Optional

from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.decision import ThreatClassification
from app.schemas.risk import RiskLevel, RiskResult
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.correlation_engine import CorrelationOutput


class ClassificationEngine:
    """Evidence-based Threat Classification Engine."""

    def classify(
        self,
        risk_result: RiskResult,
        correlation_output: CorrelationOutput,
        analyzer_results: Optional[Dict[str, AnalyzerResultItem]] = None
    ) -> ThreatClassification:
        """Classifies an email into SAFE, SPAM, SUSPICIOUS, MALICIOUS, or UNKNOWN based on evidence."""
        findings = correlation_output.deduplicated_findings
        tags = correlation_output.security_tags
        codes = {f.code for f in findings}

        # 1. UNKNOWN Preservation: If analyzers failed/unavailable/timed-out or evidence is uncertain
        if analyzer_results:
            statuses = [item.status for item in analyzer_results.values()]
            all_unavailable_or_failed = all(s in (AnalyzerStatus.UNAVAILABLE, AnalyzerStatus.FAILED, AnalyzerStatus.TIMEOUT, AnalyzerStatus.SKIPPED) for s in statuses)
            if all_unavailable_or_failed and not findings:
                return ThreatClassification.UNKNOWN

        # If risk is LOW/SAFE but no reliable evidence exists or confidence is very low
        if risk_result.threat_confidence < 0.50 and not findings:
            return ThreatClassification.UNKNOWN

        # 2. MALICIOUS Evidence Check
        # Confirmed malicious indicators
        is_malicious = (
            "MALICIOUS_ATTACHMENT" in codes
            or "MALWARE_MATCH" in codes
            or "THREAT_INTEL_MATCH" in codes
            or ("CREDENTIAL_REQUEST" in codes and "SUSPICIOUS_URL" in codes)
            or any(f.severity == SeverityLevel.CRITICAL for f in findings)
        )
        if is_malicious:
            return ThreatClassification.MALICIOUS

        # 3. SPAM Evidence Check
        is_spam = (
            "SPAM_KEYWORD" in codes
            or "BULK_SENDER" in codes
            or "MARKETING_MAIL" in codes
            or "SPAM" in tags
        )
        if is_spam:
            return ThreatClassification.SPAM

        # 4. SUSPICIOUS Evidence Check
        is_suspicious = (
            "DMARC_FAIL" in codes
            or "SPF_FAIL" in codes
            or "NEW_DOMAIN" in codes
            or "LOOKALIKE_DOMAIN" in codes
            or "SUSPICIOUS_URL" in codes
            or "CREDENTIAL_REQUEST" in codes
            or "EXECUTIVE_IMPERSONATION" in codes
            or risk_result.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
            or len(findings) > 0
        )
        if is_suspicious:
            return ThreatClassification.SUSPICIOUS

        # 5. SAFE Classification: Explicit evidence evaluates clean with SAFE risk level
        if risk_result.risk_level == RiskLevel.SAFE and not findings:
            return ThreatClassification.SAFE

        return ThreatClassification.UNKNOWN
