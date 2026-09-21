"""
ML Analyzer Adapter for MailTrace-AI Backend.

Implements BaseAnalyzer interface, bridging backend AnalysisContext to
ml.engine.analyze_email_ml() without duplicating any ML/NLP/BEC/Behavioral algorithms.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

from app.schemas.analysis import AnalyzerResultItem
from app.schemas.common import AnalyzerStatus
from app.schemas.security import SecurityFinding, SeverityLevel
from app.services.analyzers.base import BaseAnalyzer
from app.services.analyzers.context import AnalysisContext
from app.services.analyzers.result import create_analyzer_result, create_failed_result
from ml.engine import analyze_email_ml


def _map_severity(sev_str: Any) -> SeverityLevel:
    """Map string severity to canonical SeverityLevel Enum safely."""
    val = str(sev_str).strip().upper() if sev_str else "INFO"
    mapping = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
        "INFO": SeverityLevel.INFO,
    }
    return mapping.get(val, SeverityLevel.INFO)


class MLAnalyzer(BaseAnalyzer):
    """
    ML Analyzer bridging EmailNormalized context into the ML inference engine.
    
    Coordinates NLP content signals, BEC impersonation indicators, behavioral sender anomalies,
    and intent classification, returning a BaseAnalyzer-compliant AnalyzerResultItem.
    """

    def __init__(self, name_str: str = "ml", version_str: str = "1.0.0"):
        self._name = name_str
        self._version = version_str
        self._category = "ml"

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def category(self) -> str:
        return self._category

    async def analyze(self, context: AnalysisContext) -> AnalyzerResultItem:
        """Executes ML engine analysis safely using context email properties."""
        email = context.email

        sender_addr = email.sender.address if email.sender else ""
        sender_name = email.sender.name or "" if email.sender else ""
        reply_to_addr = email.reply_to[0].address if email.reply_to and len(email.reply_to) > 0 else ""
        recipient_count = len(email.recipients) if email.recipients else 1
        subject = email.subject or ""
        body = email.body_text_preview or ""

        # Extract non-fabricated metadata if explicitly supplied
        sender_history = context.metadata.get("sender_history")
        current_time_hour = context.metadata.get(
            "current_time_hour",
            email.timestamp.hour if isinstance(email.timestamp, datetime) else None
        )
        originating_country = context.metadata.get("originating_country")

        try:
            # Delegate to existing ML unified engine
            ml_engine_result = analyze_email_ml(
                subject=subject,
                body=body,
                display_name=sender_name,
                from_address=sender_addr,
                reply_to=reply_to_addr,
                sender_address=sender_addr,
                recipient_count=recipient_count,
                sender_history=sender_history,
                current_time_hour=current_time_hour,
                originating_country=originating_country,
            )
        except Exception as exc:
            return create_failed_result(
                analyzer_name=self.name,
                error_message=f"ML inference engine failure: {str(exc)}"
            )

        # Convert ML module findings into canonical SecurityFinding objects
        findings: List[SecurityFinding] = []

        all_ml_findings = (
            ml_engine_result.nlp.findings
            + ml_engine_result.bec.findings
            + ml_engine_result.behavioral.findings
        )

        for f in all_ml_findings:
            findings.append(
                SecurityFinding(
                    code=f.code,
                    severity=_map_severity(f.severity),
                    description=f.details or f"ML detected {f.code}",
                    details={"source": "ml", "finding_code": f.code, "details": f.details}
                )
            )

        # Add ML prediction verdict finding if high-confidence threat predicted
        pred = ml_engine_result.prediction
        if pred.prediction.lower() == "phishing" and pred.confidence >= 0.75:
            findings.append(
                SecurityFinding(
                    code="ML_PREDICTED_PHISHING",
                    severity=SeverityLevel.HIGH if pred.confidence >= 0.85 else SeverityLevel.MEDIUM,
                    description=f"ML intent model predicted PHISHING (confidence: {pred.confidence:.2f})",
                    details={
                        "prediction": pred.prediction,
                        "confidence": pred.confidence,
                        "model_version": pred.model_version,
                        "probabilities": pred.probabilities,
                    }
                )
            )
        elif pred.prediction.lower() == "spam" and pred.confidence >= 0.70:
            findings.append(
                SecurityFinding(
                    code="SPAM_KEYWORD",
                    severity=SeverityLevel.LOW,
                    description=f"ML intent model flagged SPAM content (confidence: {pred.confidence:.2f})",
                    details={
                        "prediction": pred.prediction,
                        "confidence": pred.confidence,
                        "model_version": pred.model_version,
                    }
                )
            )

        # Build feature map matching backend schema
        features: Dict[str, Any] = {
            "prediction": pred.prediction,
            "confidence": pred.confidence,
            "model_name": "intent_classifier_tfidf_nb",
            "model_version": pred.model_version,
            "probabilities": pred.probabilities,
            "nlp": ml_engine_result.nlp.features,
            "bec": ml_engine_result.bec.features,
            "behavioral": ml_engine_result.behavioral.features,
        }

        return create_analyzer_result(
            analyzer_name=self.name,
            status=AnalyzerStatus.SUCCESS,
            features=features,
            findings=findings,
        )
