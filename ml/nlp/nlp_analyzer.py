"""
Main Content / NLP Analyzer.
Exposes process_email_content() adhering to ANALYSIS_PIPELINE.md contract and SECURITY_FEATURE_SCHEMA.md.
"""

from typing import Dict, Any, Optional
from ml.schemas import AnalyzerResult, Finding, ContentNLPFeatures
from ml.nlp.feature_extractor import extract_nlp_base_features
from ml.nlp.intent_classifier import IntentClassifier
from ml.config import (
    THRESHOLD_PHISHING_HIGH, THRESHOLD_PHISHING_MEDIUM,
    THRESHOLD_SPAM_HIGH, THRESHOLD_URGENCY_HIGH
)


class ContentNLPAnalyzer:
    """Analyzer for Email Content & NLP signals."""

    def __init__(self, intent_classifier: Optional[IntentClassifier] = None):
        self.intent_classifier = intent_classifier or IntentClassifier()

    def analyze(self, subject: str = "", body: str = "") -> AnalyzerResult:
        """
        Analyze subject and body text, returning structured AnalyzerResult.
        """
        try:
            if not subject and not body:
                features = ContentNLPFeatures()
                return AnalyzerResult(
                    analyzer="ml_nlp",
                    status="SUCCESS",
                    features=features.model_dump(),
                    findings=[Finding(code="EMPTY_CONTENT", severity="INFO", details="Email subject and body are empty.")]
                )

            # 1. Base NLP Features
            base_features = extract_nlp_base_features(subject, body)

            # 2. Intent Classification
            intent_features = self.intent_classifier.classify_intent(
                subject=subject,
                body=body,
                cta_score=base_features["call_to_action_score"]
            )

            # 3. Combine Features
            combined = {**base_features, **intent_features}
            nlp_features = ContentNLPFeatures(**combined)

            # 4. Generate Security Findings
            findings = []

            if nlp_features.phishing_score >= THRESHOLD_PHISHING_HIGH:
                findings.append(Finding(
                    code="HIGH_PHISHING_INTENT",
                    severity="HIGH",
                    details=f"Content exhibits high phishing language characteristics (score: {nlp_features.phishing_score})."
                ))
            elif nlp_features.phishing_score >= THRESHOLD_PHISHING_MEDIUM:
                findings.append(Finding(
                    code="SUSPICIOUS_PHISHING_INTENT",
                    severity="MEDIUM",
                    details=f"Content exhibits moderate phishing language indicators (score: {nlp_features.phishing_score})."
                ))

            if nlp_features.credential_request_score >= 0.5:
                findings.append(Finding(
                    code="CREDENTIAL_HARVESTING_LANGUAGE",
                    severity="HIGH",
                    details="Email content explicitly requests login or credential updates."
                ))

            if nlp_features.financial_request_score >= 0.5:
                findings.append(Finding(
                    code="FINANCIAL_SOLICITATION_LANGUAGE",
                    severity="MEDIUM",
                    details="Email content requests payment, wire transfer, or financial information."
                ))

            if nlp_features.urgency_score >= THRESHOLD_URGENCY_HIGH:
                findings.append(Finding(
                    code="ARTIFICIAL_URGENCY_TACTIC",
                    severity="MEDIUM",
                    details="Email uses high-pressure urgency language to force immediate action."
                ))

            if nlp_features.spam_score >= THRESHOLD_SPAM_HIGH:
                findings.append(Finding(
                    code="HIGH_SPAM_SCORE",
                    severity="LOW",
                    details=f"Content exhibits spam features (score: {nlp_features.spam_score})."
                ))

            return AnalyzerResult(
                analyzer="ml_nlp",
                status="SUCCESS",
                features=nlp_features.model_dump(),
                findings=findings
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="ml_nlp",
                status="ERROR",
                features=ContentNLPFeatures().model_dump(),
                findings=[],
                error_message=str(e)
            )
