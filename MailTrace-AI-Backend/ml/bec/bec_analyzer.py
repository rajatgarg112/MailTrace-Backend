"""
BEC / Impersonation Analyzer.
Exposes analyze() returning structured AnalyzerResult matching ANALYSIS_PIPELINE.md contract.
"""

from typing import Dict, Any, Optional
from ml.schemas import AnalyzerResult, Finding, BECFeatures
from ml.bec.feature_extractor import extract_bec_features
from ml.config import THRESHOLD_BEC_HIGH, THRESHOLD_BEC_MEDIUM


class BECAnalyzer:
    """Analyzer for BEC, Executive & Brand Impersonation signals."""

    def analyze(
        self,
        display_name: str = "",
        from_address: str = "",
        subject: str = "",
        body: str = "",
        reply_to: str = ""
    ) -> AnalyzerResult:
        """
        Analyze email metadata and text for BEC impersonation indicators.
        """
        try:
            raw_features = extract_bec_features(
                display_name=display_name,
                from_address=from_address,
                subject=subject,
                body=body,
                reply_to=reply_to
            )

            bec_features = BECFeatures(**raw_features)
            findings = []

            # Check Executive Impersonation
            if bec_features.executive_impersonation_score >= THRESHOLD_BEC_HIGH:
                findings.append(Finding(
                    code="EXECUTIVE_IMPERSONATION_ATTEMPT",
                    severity="CRITICAL",
                    details="Sender claims an executive role from a mismatched or free email domain."
                ))

            # Check Brand Impersonation
            if bec_features.brand_impersonation_score >= THRESHOLD_BEC_HIGH:
                findings.append(Finding(
                    code="BRAND_IMPERSONATION_ATTEMPT",
                    severity="HIGH",
                    details="Email content references a major brand but originates from an unrelated domain."
                ))

            # Check Bank Account / Direct Deposit Fraud
            if bec_features.bank_account_change_score >= 0.3:
                findings.append(Finding(
                    code="BANK_ACCOUNT_CHANGE_REQUEST",
                    severity="CRITICAL",
                    details="High-risk request detected attempting to modify banking or direct deposit details."
                ))

            # Check Gift Card Fraud
            if bec_features.gift_card_request_score >= 0.3:
                findings.append(Finding(
                    code="GIFT_CARD_SOLICITATION",
                    severity="HIGH",
                    details="Solicitation detected requesting gift card purchases or code transmission."
                ))

            # Check Conversation Hijacking
            if bec_features.conversation_hijacking_score >= 0.7:
                findings.append(Finding(
                    code="CONVERSATION_HIJACKING_PATTERN",
                    severity="HIGH",
                    details="Email mimics an ongoing thread (Re:/Fwd:) while requesting high-risk actions or using suspicious reply-to."
                ))

            return AnalyzerResult(
                analyzer="ml_bec",
                status="SUCCESS",
                features=bec_features.model_dump(),
                findings=findings
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="ml_bec",
                status="ERROR",
                features=BECFeatures().model_dump(),
                findings=[],
                error_message=str(e)
            )
