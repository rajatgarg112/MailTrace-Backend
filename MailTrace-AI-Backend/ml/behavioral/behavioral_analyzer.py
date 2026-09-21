"""
Behavioral ML Analyzer.
Exposes analyze() returning structured AnalyzerResult matching ANALYSIS_PIPELINE.md contract.
"""

from typing import Dict, Any, Optional
from ml.schemas import AnalyzerResult, Finding, BehavioralFeatures
from ml.behavioral.feature_extractor import extract_behavioral_features
from ml.config import THRESHOLD_BEHAVIORAL_ANOMALY


class BehavioralAnalyzer:
    """Analyzer for Sender Behavior, Anomaly Detection & Volume Metrics."""

    def analyze(
        self,
        sender_address: str = "",
        recipient_count: int = 1,
        sender_history: Optional[Dict[str, Any]] = None,
        current_time_hour: Optional[int] = None,
        originating_country: Optional[str] = None
    ) -> AnalyzerResult:
        """
        Analyze behavioral profile of sender and message distribution.
        """
        try:
            raw_features = extract_behavioral_features(
                sender_address=sender_address,
                recipient_count=recipient_count,
                sender_history=sender_history,
                current_time_hour=current_time_hour,
                originating_country=originating_country
            )

            behavioral_features = BehavioralFeatures(**raw_features)
            findings = []

            # Check Volume Anomaly
            if behavioral_features.volume_anomaly >= THRESHOLD_BEHAVIORAL_ANOMALY:
                findings.append(Finding(
                    code="VOLUME_ANOMALY_SPIKE",
                    severity="HIGH",
                    details=f"Unusual spike in sending volume detected from sender profile (score: {behavioral_features.volume_anomaly})."
                ))

            # Check Location Anomaly
            if behavioral_features.location_anomaly >= THRESHOLD_BEHAVIORAL_ANOMALY:
                findings.append(Finding(
                    code="UNUSUAL_ORIGINATING_LOCATION",
                    severity="MEDIUM",
                    details="Message originates from an unusual geolocation for this sender profile."
                ))

            # Check Time Anomaly
            if behavioral_features.time_anomaly >= THRESHOLD_BEHAVIORAL_ANOMALY:
                findings.append(Finding(
                    code="UNUSUAL_SENDING_TIME",
                    severity="LOW",
                    details="Message sent outside sender's typical active hours."
                ))

            # Check Bulk Email Score
            if behavioral_features.bulk_score >= 0.8:
                findings.append(Finding(
                    code="MASS_RECIPIENT_BULK_EMAIL",
                    severity="INFO",
                    details=f"Message addressed to a large recipient list (count: {behavioral_features.recipient_count})."
                ))

            return AnalyzerResult(
                analyzer="ml_behavioral",
                status="SUCCESS",
                features=behavioral_features.model_dump(),
                findings=findings
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="ml_behavioral",
                status="ERROR",
                features=BehavioralFeatures().model_dump(),
                findings=[],
                error_message=str(e)
            )
