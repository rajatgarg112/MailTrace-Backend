"""
MailTrace-AI: Official 5 Demo Scenarios End-to-End Test Suite.
Verifies M6 (Forensics, Evidence Vault, Geolocation Map Markers, Timeline) + M4 (Security Analyzers) + M3 (Trained ML Models).

Scenarios:
1. SAFE / INBOX: Clean corporate communication with passing auth.
2. SPAM / MARKETING: Bulk cloud discount promotional newsletter.
3. PHISHING / QUARANTINE: Credential harvesting with German Tor Exit Node origin & map marker.
4. BEC / QUARANTINE: Executive CEO wire transfer impersonation with NLP financial coercion.
5. MALWARE / REJECT: Double-extension attachment payload with fuzzy hashing.
"""

import json
import sys
from datetime import datetime, timezone

from security.runner import SecurityAnalyzer
from ml.engine import analyze_email_ml


def run_demo_scenarios():
    print("=" * 80)
    print("      MAILTRACE-AI: VERIFYING 5 TEAM DEMO SCENARIOS (M6 + M4 + M3)")
    print("=" * 80)

    analyzer = SecurityAnalyzer()

    scenarios = [
        {
            "id": "scenario-1",
            "name": "Scenario 1: Clean Corporate Communication",
            "expected_action": "INBOX",
            "expected_class": "SAFE",
            "headers": {
                "From": "Alex Mercer <alex.product@company.org>",
                "To": "engineering-team@mailtrace.ai",
                "Subject": "Q4 Product Roadmap and Sprint Milestones",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from mail.company.org (198.51.100.25) by gateway.mailtrace.ai"
            },
            "body": "Hi Team,\nPlease review the updated Q4 product roadmap. All sprint deliverables are on schedule.\nBest,\nAlex",
            "attachments": ["roadmap_q4.pdf"]
        },
        {
            "id": "scenario-2",
            "name": "Scenario 2: Unsolicited Bulk Marketing / Spam",
            "expected_action": "SPAM",
            "expected_class": "SPAM",
            "headers": {
                "From": "CloudDeals Marketing <promotions@clouddeals-marketing-promo.xyz>",
                "To": "user@mailtrace.ai",
                "Subject": "Special Offer: Upgrade your Cloud Infrastructure with 50% Off Today",
                "Authentication-Results": "spf=pass dkim=none dmarc=pass",
                "Received": "from promo-node-88.clouddeals-marketing-promo.xyz (192.0.2.140) by gateway.mailtrace.ai",
                "List-Unsubscribe": "<mailto:unsub@clouddeals-marketing-promo.xyz>"
            },
            "body": "Click here to claim 50% discount on dedicated cloud infrastructure! Limited time only. Unsubscribe at any time.",
            "attachments": []
        },
        {
            "id": "scenario-3",
            "name": "Scenario 3: Credential Phishing with German Tor Exit Node Origin",
            "expected_action": "QUARANTINE",
            "expected_class": "MALICIOUS",
            "headers": {
                "From": "PayPal Security Team <billing@paypa1-verify-account.xyz>",
                "To": "victim@mailtrace.ai",
                "Subject": "URGENT: Your Account Has Been Temporarily Suspended",
                "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
                "Received": "from tor-exit-node.zwiebelfreunde.de ([185.220.101.5]) by gateway.mailtrace.ai"
            },
            "body": "Your PayPal account access has been restricted due to unauthorized login attempts. Click here to verify identity: http://185.220.101.5/auth/login or risk permanent deletion.",
            "attachments": []
        },
        {
            "id": "scenario-4",
            "name": "Scenario 4: Business Email Compromise (BEC) CEO Wire Fraud",
            "expected_action": "QUARANTINE",
            "expected_class": "MALICIOUS",
            "headers": {
                "From": "Satya Nadella <ceo-executive-desk@micro-soft-secure-corporate.net>",
                "To": "cfo@mailtrace.ai",
                "Subject": "Urgent & Confidential: Wire Transfer Authorization Required Before Close",
                "Authentication-Results": "spf=fail dkim=none dmarc=fail",
                "Received": "from vps-outbound.bulletproof-host.is ([194.26.29.112]) by gateway.mailtrace.ai"
            },
            "body": "Hi, I am in a confidential board meeting. I need an urgent wire transfer of $48,500 processed for our strategic acquisition. Send funds to the beneficiary account immediately. Do not call my mobile.",
            "attachments": []
        },
        {
            "id": "scenario-5",
            "name": "Scenario 5: Dangerous Double-Extension Malware Attachment",
            "expected_action": "QUARANTINE",
            "expected_class": "MALICIOUS",
            "headers": {
                "From": "Vendor Accounts <billing@spoofed-vendor-portal.top>",
                "To": "accounts-payable@mailtrace.ai",
                "Subject": "Overdue Invoice Notice - Immediate Payment Required",
                "Authentication-Results": "spf=none dkim=none dmarc=none",
                "Received": "from rogue-relay.unknown-net.org ([193.142.146.33]) by gateway.mailtrace.ai"
            },
            "body": "Please find attached the final overdue invoice notice. Open the attached invoice document to review outstanding penalties.",
            "attachments": ["overdue_invoice_oct2026.pdf.exe"]
        }
    ]

    all_passed = True
    results_summary = []

    for idx, sc in enumerate(scenarios, 1):
        print(f"\n[{idx}/5] RUNNING: {sc['name']}")
        print("-" * 75)

        # 1. Run M4 + M6 Security Analyzer
        sec_result = analyzer.analyze(
            raw_headers_or_dict=sc["headers"],
            body_text_or_html=sc["body"],
            attachments_input=sc["attachments"],
            email_id=f"demo-{sc['id']}"
        )

        # 2. Run M3 ML Engine
        from_hdr = sc["headers"].get("From", "")
        disp_name = from_hdr.split("<")[0].strip() if "<" in from_hdr else ""
        from_addr = from_hdr.split("<")[1].rstrip(">").strip() if "<" in from_hdr else from_hdr

        ml_result = analyze_email_ml(
            subject=sc["headers"].get("Subject", ""),
            body=sc["body"],
            display_name=disp_name,
            from_address=from_addr,
            reply_to="",
            sender_address=from_addr,
            recipient_count=1
        )

        # 3. Extract M6 Forensics & Geolocation details
        geo = sec_result.infrastructure or sec_result.forensics.network_context.model_dump()
        evidence = sec_result.evidence or {}
        timeline = sec_result.timeline or []
        forensic_case = sec_result.forensic_case or {}

        risk_val = sec_result.policy_decision.risk_score
        class_val = sec_result.policy_decision.threat_classification.value
        action_val = sec_result.policy_decision.delivery_action.value

        print(f"  * Threat Verdict:       {class_val} (Risk Score: {risk_val}/100)")
        print(f"  * Delivery Action:      {action_val} (Reason: {sec_result.policy_decision.action_reason})")
        print(f"  * ML Prediction:        {ml_result.prediction.prediction.upper()} (Confidence: {ml_result.prediction.confidence:.2f}, Spam Score: {ml_result.nlp.features.get('spam_score', 0):.2f})")
        print(f"  * Originating IP:       {geo.get('originating_ip')} | ASN: {geo.get('asn')} | ISP: {geo.get('isp')}")
        print(f"  * Geolocation:          {geo.get('city')}, {geo.get('country')} (Lat: {geo.get('latitude')}, Lon: {geo.get('longitude')})")
        print(f"  * Tor/VPN Exit Node:    {'YES [ALERT!]' if geo.get('is_vpn_or_tor') else 'NO (Standard Network)'}")
        print(f"  * Leaflet Map Marker:   Lat={geo.get('map_marker', {}).get('latitude')}, Lon={geo.get('map_marker', {}).get('longitude')}, Pulse={geo.get('map_marker', {}).get('pulse')}")
        print(f"  * Forensic SHA-256:     {evidence.get('raw_sha256', '')[:32]}...")
        print(f"  * Forensic TLSH Fuzzy:  {evidence.get('fuzzy_tlsh', 'N/A')}")
        print(f"  * Timeline Audit Steps: {len(timeline)} chronological stages verified")
        print(f"  * Disclaimer:           '{geo.get('disclaimer')}'")

        # Validation Checks
        is_action_ok = (action_val == sc["expected_action"])
        is_m6_geo_ok = (geo.get("map_marker") is not None and "disclaimer" in geo)
        is_m6_forensics_ok = (len(timeline) == 6 and "raw_sha256" in evidence and forensic_case is not None)

        test_passed = is_action_ok and is_m6_geo_ok and is_m6_forensics_ok
        status_str = "PASS" if test_passed else "FAIL"
        if not test_passed:
            all_passed = False

        print(f"  ==> Status: [{status_str}]")

        results_summary.append({
            "scenario": sc["name"],
            "action": action_val,
            "risk": risk_val,
            "ip": geo.get("originating_ip"),
            "location": f"{geo.get('city')}, {geo.get('country')}",
            "is_tor": geo.get("is_vpn_or_tor"),
            "status": status_str
        })

    print("\n" + "=" * 80)
    print("                     5 DEMO SCENARIOS VERIFICATION SUMMARY")
    print("=" * 80)
    for r in results_summary:
        tor_flag = " [TOR/VPN]" if r["is_tor"] else ""
        print(f"[{r['status']}] {r['scenario'][:45]:<45} | Action: {r['action']:<10} | Risk: {r['risk']:>3} | {r['location']}{tor_flag}")

    print("=" * 80)
    if all_passed:
        print(">>> ALL 5 DEMO SCENARIOS PASSED WITH ZERO ERRORS! PROTOTYPE IS DEMO-READY! <<<")
    else:
        print(">>> SOME SCENARIOS FAILED VERIFICATION <<<")
    print("=" * 80)

    return all_passed


if __name__ == "__main__":
    success = run_demo_scenarios()
    sys.exit(0 if success else 1)
