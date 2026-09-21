from datetime import datetime, timezone
from typing import Optional

from app.schemas.decision import (
    DeliveryAction,
    PolicyDecision,
    SecurityGatewayCategory,
    SpamCategory,
    ThreatClassification,
)
from app.schemas.risk import RiskLevel, RiskResult
from app.services.correlation_engine import CorrelationOutput


class DeliveryPolicyEngine:
    """Backend Delivery Policy Engine mapping threat classifications and risk results to routing actions."""

    def evaluate_policy(
        self,
        classification: ThreatClassification,
        risk_result: RiskResult,
        correlation_output: Optional[CorrelationOutput] = None
    ) -> PolicyDecision:
        """Evaluates project delivery policy to produce a canonical PolicyDecision."""
        codes = {f.code for f in correlation_output.deduplicated_findings} if correlation_output else set()

        action: DeliveryAction
        spam_cat: Optional[SpamCategory] = None
        gateway_cat: Optional[SecurityGatewayCategory] = None
        reason: str

        if classification == ThreatClassification.SAFE:
            action = DeliveryAction.INBOX
            reason = "Email evaluated clean and safe by security policy."

        elif classification == ThreatClassification.SPAM:
            action = DeliveryAction.SPAM
            if "MARKETING_MAIL" in codes:
                spam_cat = SpamCategory.MARKETING
            elif "BULK_SENDER" in codes:
                spam_cat = SpamCategory.BULK
            else:
                spam_cat = SpamCategory.OTHER
            reason = f"Routed to spam folder based on spam evidence (Category: {spam_cat.value})."

        elif classification == ThreatClassification.SUSPICIOUS:
            if risk_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                action = DeliveryAction.HOLD
                reason = "Suspicious high-risk indicators detected; holding message for security review."
            else:
                action = DeliveryAction.WARN
                reason = "Suspicious indicators detected; delivering with security warning banner."

        elif classification == ThreatClassification.MALICIOUS:
            action = DeliveryAction.QUARANTINE
            if "MALICIOUS_ATTACHMENT" in codes or "MALWARE_MATCH" in codes:
                gateway_cat = SecurityGatewayCategory.MALWARE
            elif "CREDENTIAL_REQUEST" in codes:
                gateway_cat = SecurityGatewayCategory.HIGH_RISK_PHISHING
            elif "EXECUTIVE_IMPERSONATION" in codes:
                gateway_cat = SecurityGatewayCategory.BEC_FRAUD
            else:
                gateway_cat = SecurityGatewayCategory.MALICIOUS
            reason = f"Malicious threat detected; message quarantined (Gateway Category: {gateway_cat.value})."

        elif classification == ThreatClassification.UNKNOWN:
            # Uncertainty Policy: Non-destructive HOLD policy
            action = DeliveryAction.HOLD
            reason = "Insufficient evidence or analyzer uncertainty; holding message for policy review."

        else:
            action = DeliveryAction.HOLD
            reason = "Unrecognized classification state; holding for policy review."

        return PolicyDecision(
            classification=classification,
            action=action,
            risk_level=risk_result.risk_level,
            risk_score=risk_result.overall_risk_score,
            spam_category=spam_cat,
            gateway_category=gateway_cat,
            reason=reason,
            policy_version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )
