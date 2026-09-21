import re
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class ForensicCaseBuilder:
    """
    Builds comprehensive Forensic Case Records and Sanitized Security Reports
    for suspicious/malicious emails.
    Enforces the 'Harmful Email Protection' rule: raw malicious payload is neutralized.
    """

    def sanitize_html(self, raw_html: str) -> str:
        """
        Strips dangerous scripts, iframes, and active content from raw email HTML.
        Neutralizes links so they cannot trigger drive-by downloads.
        """
        if not raw_html:
            return "<p><em>[No body content present in evidence artifact]</em></p>"

        # Strip script tags and content
        clean = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '[REMOVED_MALICIOUS_SCRIPT]', raw_html, flags=re.IGNORECASE)
        # Strip iframes
        clean = re.sub(r'<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>', '[REMOVED_IFRAME]', clean, flags=re.IGNORECASE)
        # Strip object/embed
        clean = re.sub(r'<(object|embed)\b[^<]*(?:(?!<\/(object|embed)>)<[^<]*)*<\/(object|embed)>', '[REMOVED_ACTIVE_CONTENT]', clean, flags=re.IGNORECASE)
        # Defang hrefs: replace http:// with hxxp://
        clean = re.sub(r'href=[\'"]https?://([^\'"]+)[\'"]', r'data-defanged="true" title="hxxp://\1" style="color:#ef4444;text-decoration:line-through;"', clean, flags=re.IGNORECASE)
        # Remove onerror/onload attributes
        clean = re.sub(r'\son\w+=[\'"][^\'"]*[\'"]', '', clean, flags=re.IGNORECASE)

        return clean

    def build_sanitized_report(
        self,
        email_id: str,
        sender: str,
        subject: str,
        raw_body: Optional[str],
        threat_tags: List[str],
        risk_score: int
    ) -> Dict[str, Any]:
        """
        Produces a safe security report for the frontend to render.
        Blocks active execution of suspicious code.
        """
        sanitized_content = self.sanitize_html(raw_body or "")
        return {
            "email_id": email_id,
            "sender": sender,
            "subject": subject,
            "threat_verdict": "MALICIOUS" if risk_score >= 80 else ("SUSPICIOUS" if risk_score >= 50 else "SAFE"),
            "risk_score": risk_score,
            "security_tags": threat_tags,
            "is_sanitized": True,
            "sanitized_body_html": sanitized_content,
            "raw_payload_blocked": risk_score >= 50,
            "safety_warning": "Active scripts, trackers, and external redirects were neutralized for safe forensic review.",
        }

    def build_case(
        self,
        email_id: str,
        sender: str,
        subject: str,
        risk_score: int,
        confidence: float,
        security_tags: List[str],
        evidence_summary: Dict[str, Any],
        geo_infrastructure: Dict[str, Any],
        timeline: List[Dict[str, Any]],
        case_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assembles a full digital forensic investigation case dossier.
        """
        if not case_id:
            case_id = f"case-{uuid.uuid4().hex[:6]}"

        severity = "CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 70 else ("MEDIUM" if risk_score >= 40 else "LOW"))
        status = "QUARANTINED" if risk_score >= 75 else ("HELD_FOR_REVIEW" if risk_score >= 50 else "CLEARED")

        return {
            "caseId": case_id,
            "case_id": case_id,
            "emailId": email_id,
            "email_id": email_id,
            "title": f"Forensic Threat Case: {subject or 'Untitled Email'}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "severity": severity,
            "riskScore": risk_score,
            "risk_score": risk_score,
            "confidence": confidence,
            "securityTags": security_tags,
            "security_tags": security_tags,
            "sender": sender,
            "evidence": evidence_summary,
            "infrastructure": geo_infrastructure,
            "timeline": timeline,
            "provenance": "VERIFIED_EVIDENCE",
        }
