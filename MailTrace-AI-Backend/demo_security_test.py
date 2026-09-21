"""
MailTrace-AI Security Subsystem (Member 4) — Interactive Demo Test Script
Run this script to test custom email payloads, attachments, and forensic outputs.
"""

import json
from security.runner import SecurityAnalyzer

def run_demo():
    print("=" * 75)
    print(" MailTrace-AI Security & Forensics Engine (Member 4) — CLI Test Runner")
    print("=" * 75)

    sample_headers = {
        "From": "PayPal Security Team <billing@paypa1-verify.xyz>",
        "Subject": "URGENT: Your Account Has Been Temporarily Suspended",
        "Date": "Mon, 21 Sep 2026 09:30:00 +0000",
        "Message-ID": "<202609210930.98765@cheap-vps-server.net>",
        "Return-Path": "<bounce@unrelated-spammer-domain.ru>",
        "Authentication-Results": "mx.google.com; spf=fail; dkim=fail; dmarc=fail",
        "Received": [
            "from mail.suspicious-relay.com ([185.220.101.5]) by mx.google.com; Mon, 21 Sep 2026 09:30:00 +0000",
            "from internal.spammer.local ([10.0.0.5]) by mail.suspicious-relay.com; Mon, 21 Sep 2026 09:29:58 +0000"
        ]
    }

    sample_html_body = """
    <html>
      <body>
        <h2>Account Security Notice</h2>
        <p>Dear PayPal User,</p>
        <p>We detected unauthorized login attempts on your account. Please confirm your identity immediately:</p>
        <p><a href="http://185.220.101.5/auth/login">http://paypal.com/verify-account</a></p>
        <p>Or use our short link: https://bit.ly/3x89qAZ</p>
      </body>
    </html>
    """

    sample_attachments = ["Account_Verification_Document.pdf.exe", "Instructions.txt"]

    print("\n--> Analyzing Sample Phishing & Attachment Payload...\n")

    analyzer = SecurityAnalyzer()
    result = analyzer.analyze(
        raw_headers_or_dict=sample_headers,
        body_text_or_html=sample_html_body,
        attachments_input=sample_attachments
    )

    result_dict = result.model_dump()

    print("=== SECURITY & POLICY DECISION ===")
    print(f"Email ID:                   {result.email_id}")
    print(f"Threat Classification:      {result.policy_decision.threat_classification.value}")
    print(f"Delivery Action Enforced:   {result.policy_decision.delivery_action.value}")
    print(f"Action Reason:              {result.policy_decision.action_reason}")
    print(f"Risk Score:                 {result.policy_decision.risk_score} / 100")
    print(f"Assigned Security Tags:     {result.security_tags}")
    print("-" * 75)
    print("SPF / DKIM / DMARC:         ", f"{result.authentication.spf.value} / {result.authentication.dkim.value} / {result.authentication.dmarc.value}")
    print("Lookalike Domain Flag:      ", result.domain_analysis.is_lookalike)
    print("Target Brand Domain:        ", result.domain_analysis.target_brand_domain)
    print("Dangerous Attachments:      ", result.attachments.dangerous_attachments_count)
    print("Double Extension Flag:      ", result.attachments.has_double_extension)
    print("Raw Payload SHA-256:        ", result.forensics.raw_sha256)
    print("Originating Network IP:     ", result.forensics.network_context.originating_ip)
    print("-" * 75)

    print("\nFull Structured JSON Payload:\n")
    print(json.dumps(result_dict, indent=2))
    print("=" * 75)

if __name__ == "__main__":
    run_demo()
