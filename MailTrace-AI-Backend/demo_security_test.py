"""
MailTrace-AI Security Subsystem (Member 4) — Interactive Demo Test Script
Run this script to analyze sample emails or test your own custom headers/body payloads.
"""

import json
from security.runner import SecurityAnalyzer

def run_demo():
    print("=" * 70)
    print(" MailTrace-AI Security Engine (Member 4) — Interactive Test Demo")
    print("=" * 70)

    # Sample 1: Phishing Email Impersonating PayPal
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

    print("\n--> Analyzing Sample Phishing Email Payload...\n")

    analyzer = SecurityAnalyzer()
    result = analyzer.analyze(sample_headers, sample_html_body)

    # Convert Pydantic result model to JSON dict
    result_dict = result.model_dump()

    print("=== ANALYSIS RESULTS ===")
    print(f"Email ID:                   {result.email_id}")
    print(f"Assigned Security Tags:     {result.security_tags}")
    print(f"Risk Score Contribution:    {result.risk_score_contribution} / 100")
    print("-" * 70)
    print("Header Anomalies:           ", result.headers.anomalies)
    print("SPF Status:                 ", result.authentication.spf.value)
    print("DKIM Status:                ", result.authentication.dkim.value)
    print("DMARC Status:               ", result.authentication.dmarc.value)
    print("Lookalike Domain Flag:      ", result.domain_analysis.is_lookalike)
    print("Target Brand:               ", result.domain_analysis.target_brand_domain)
    print("Display Name Spoof Flag:    ", result.domain_analysis.display_name_spoofed)
    print("Suspicious TLD Flag:        ", result.domain_analysis.suspicious_tld)
    print("Total URLs Extracted:       ", result.url_analysis.total_urls)
    print("Suspicious URLs Count:      ", result.url_analysis.suspicious_urls_count)
    print("Anchor Text Mismatch Flag:  ", result.url_analysis.anchor_text_mismatch_detected)
    print("Redirect Chain Flag:        ", result.url_analysis.redirect_chain_detected)
    print("Originating IP Extracted:   ", result.relay_analysis.originating_ip)
    print("-" * 70)
    
    print("\nFull Structured JSON Output:\n")
    print(json.dumps(result_dict, indent=2))
    print("=" * 70)

if __name__ == "__main__":
    run_demo()
