from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.schemas.analysis import AnalysisRun, AnalyzerResultItem
from app.schemas.security import CanonicalSecurityFeatures, SecurityFinding, SeverityLevel


class CorrelationOutput(BaseModel):
    """Output payload from Signal Correlation Engine."""
    deduplicated_findings: List[SecurityFinding] = Field(default_factory=list)
    canonical_features: CanonicalSecurityFeatures = Field(default_factory=CanonicalSecurityFeatures)
    security_tags: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)


# Finding Code to Security Tag mapping rules
FINDING_TAG_MAP: Dict[str, str] = {
    "DMARC_FAIL": "DMARC-Fail",
    "SPF_FAIL": "SPF-Fail",
    "DKIM_FAIL": "DKIM-Fail",
    "NEW_DOMAIN": "New-Domain",
    "LOOKALIKE_DOMAIN": "Lookalike-Domain",
    "SUSPICIOUS_URL": "Suspicious-URL",
    "URL_SHORTENER": "URL-Shortener",
    "CREDENTIAL_REQUEST": "Credential-Request",
    "FINANCIAL_REQUEST": "Financial-Request",
    "EXECUTIVE_IMPERSONATION": "Executive-Impersonation",
    "MALICIOUS_ATTACHMENT": "Malicious-Attachment",
    "EXECUTABLE_ATTACHMENT": "Executable-Attachment",
    "MACRO_DETECTED": "Macro-Detected",
    "QR_CODE_DETECTED": "QR-Code-Present",
    "REPUTATION_BLACKLIST": "Blacklisted-Indicator",
}


class CorrelationEngine:
    """Correlates independent security findings, extracts canonical features, and deduplicates tags."""

    def correlate(self, analysis_run: AnalysisRun) -> CorrelationOutput:
        """Processes an AnalysisRun to produce deduplicated findings, tags, and feature structures."""
        seen_finding_keys: Set[str] = set()
        deduplicated_findings: List[SecurityFinding] = []
        tags: Set[str] = set()
        evidence_refs: Set[str] = set()

        # Iterate over analyzer results
        for analyzer_name, item in analysis_run.analyzer_results.items():
            for finding in item.findings:
                key = f"{finding.code}:{finding.severity}:{finding.description}"
                if key not in seen_finding_keys:
                    seen_finding_keys.add(key)
                    deduplicated_findings.append(finding)

                # Generate Security Tags
                if finding.code in FINDING_TAG_MAP:
                    tags.add(FINDING_TAG_MAP[finding.code])
                else:
                    # Default tag format
                    tags.add(finding.code.replace("_", "-").title())

                # Collect evidence references from finding details if available
                if finding.details and "evidence_id" in finding.details:
                    evidence_refs.add(str(finding.details["evidence_id"]))

        # Also collect findings directly attached to AnalysisRun
        for finding in analysis_run.findings:
            key = f"{finding.code}:{finding.severity}:{finding.description}"
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                deduplicated_findings.append(finding)
            if finding.code in FINDING_TAG_MAP:
                tags.add(FINDING_TAG_MAP[finding.code])

        canonical_features = analysis_run.canonical_features or CanonicalSecurityFeatures()

        return CorrelationOutput(
            deduplicated_findings=deduplicated_findings,
            canonical_features=canonical_features,
            security_tags=sorted(list(tags)),
            evidence_references=sorted(list(evidence_refs)),
        )
