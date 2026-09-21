"""
Unified ML Inference Entrypoint.
Provides analyze_email_ml() for coordinating ContentNLPAnalyzer, BECAnalyzer,
BehavioralAnalyzer, and MLPredictionResult.
"""

from typing import Dict, Any, Optional
from ml.schemas import MLEngineResult, MLPredictionResult, AnalyzerResult
from ml.nlp.nlp_analyzer import ContentNLPAnalyzer
from ml.bec.bec_analyzer import BECAnalyzer
from ml.behavioral.behavioral_analyzer import BehavioralAnalyzer
from ml.nlp.intent_classifier import IntentClassifier


def analyze_email_ml(
    subject: str = "",
    body: str = "",
    display_name: str = "",
    from_address: str = "",
    reply_to: str = "",
    sender_address: str = "",
    recipient_count: int = 1,
    sender_history: Optional[Dict[str, Any]] = None,
    current_time_hour: Optional[int] = None,
    originating_country: Optional[str] = None,
    nlp_analyzer: Optional[ContentNLPAnalyzer] = None,
    bec_analyzer: Optional[BECAnalyzer] = None,
    behavioral_analyzer: Optional[BehavioralAnalyzer] = None
) -> MLEngineResult:
    """
    Unified host-facing entrypoint for complete ML email feature analysis.

    Coordinates NLP content signals, BEC impersonation indicators, behavioral sender anomalies,
    and TF-IDF intent model inference, returning a structured MLEngineResult container.

    Does NOT calculate final overall risk score or issue gateway delivery/quarantine/reject decisions.
    """
    nlp_proc = nlp_analyzer or ContentNLPAnalyzer()
    bec_proc = bec_analyzer or BECAnalyzer()
    beh_proc = behavioral_analyzer or BehavioralAnalyzer()

    # 1. NLP Content Analysis
    nlp_result = nlp_proc.analyze(subject=subject, body=body)

    # 2. BEC Impersonation Analysis
    bec_result = bec_proc.analyze(
        display_name=display_name,
        from_address=from_address,
        subject=subject,
        body=body,
        reply_to=reply_to
    )

    # 3. Behavioral Anomaly Analysis
    # Default sender_address to from_address if omitted
    effective_sender = sender_address or from_address
    beh_result = beh_proc.analyze(
        sender_address=effective_sender,
        recipient_count=recipient_count,
        sender_history=sender_history,
        current_time_hour=current_time_hour,
        originating_country=originating_country
    )

    # 4. Direct Model Prediction
    full_text = f"{subject}\n{body}".strip()
    prediction_result = nlp_proc.intent_classifier.model.predict(full_text)

    return MLEngineResult(
        prediction=prediction_result,
        nlp=nlp_result,
        bec=bec_result,
        behavioral=beh_result
    )
