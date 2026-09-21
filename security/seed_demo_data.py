"""
Seeds the local database with the 5 official demo emails via the real FastAPI gateway pipeline.
Ensures that when the frontend dashboards are opened, real data is immediately visible.
"""

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

def seed_data():
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}

    demo_emails = [
        {
            "message_id": "eml-demo-safe-101",
            "subject": "Q4 Product Roadmap and Sprint Milestones",
            "from_address": "alex.product@company.org",
            "sender_name": "Alex Mercer (Product Lead)",
            "body": "Hi Team, Please review the updated Q4 product roadmap. All deliverables for the pre-delivery security gateway integration are on track. Best, Alex Mercer",
            "attachments": ["roadmap_q4.pdf"],
            "raw_headers": {
                "From": "Alex Mercer <alex.product@company.org>",
                "To": "engineering@mailtrace.ai",
                "Subject": "Q4 Product Roadmap and Sprint Milestones",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from mail.company.org ([198.51.100.25]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-demo-spam-201",
            "subject": "Special Offer: Upgrade your Cloud Infrastructure with 50% Off Today",
            "from_address": "promotions@clouddeals-marketing.xyz",
            "sender_name": "CloudDeals Marketing",
            "body": "Unsubscribe at any time. Get 50% off enterprise cloud nodes today only! Limited time offer.",
            "attachments": [],
            "raw_headers": {
                "From": "CloudDeals Marketing <promotions@clouddeals-marketing.xyz>",
                "To": "user@mailtrace.ai",
                "Subject": "Special Offer: Upgrade your Cloud Infrastructure with 50% Off Today",
                "Authentication-Results": "spf=pass dkim=none dmarc=pass",
                "Received": "from promo.clouddeals-marketing.xyz ([192.0.2.140]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-demo-phish-301",
            "subject": "URGENT: Your Account Has Been Temporarily Suspended",
            "from_address": "billing@paypa1-verify.xyz",
            "sender_name": "PayPal Security Team",
            "body": "Dear customer, your account has been temporarily restricted due to unauthorized login activity. Please verify your credentials immediately: http://185.220.101.5/auth/login or face permanent account termination.",
            "attachments": [],
            "raw_headers": {
                "From": "PayPal Security Team <billing@paypa1-verify.xyz>",
                "To": "victim@mailtrace.ai",
                "Subject": "URGENT: Your Account Has Been Temporarily Suspended",
                "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
                "Received": "from tor-exit-node.zwiebelfreunde.de ([185.220.101.5]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-demo-bec-401",
            "subject": "Confidential Request: Wire Transfer Authorization Required Before Close",
            "from_address": "ceo-desk@micro-soft-secure-corporate.net",
            "sender_name": "Satya Nadella",
            "body": "Hi, I am in a confidential board meeting right now. I need an urgent wire transfer of $48,500 processed for our strategic acquisition. Send funds immediately to the beneficiary. Do not call my mobile.",
            "attachments": [],
            "raw_headers": {
                "From": "Satya Nadella <ceo-desk@micro-soft-secure-corporate.net>",
                "To": "cfo@mailtrace.ai",
                "Subject": "Confidential Request: Wire Transfer Authorization Required Before Close",
                "Authentication-Results": "spf=fail dkim=none dmarc=fail",
                "Received": "from vps-outbound.bulletproof-host.is ([194.26.29.112]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-demo-malware-501",
            "subject": "Overdue Invoice Notice - Immediate Payment Required",
            "from_address": "billing@spoofed-vendor-portal.top",
            "sender_name": "Vendor Accounts",
            "body": "Please find attached the final overdue invoice notice. Open the attached invoice document to review outstanding penalties.",
            "attachments": ["overdue_invoice_oct2026.pdf.exe"],
            "raw_headers": {
                "From": "Vendor Accounts <billing@spoofed-vendor-portal.top>",
                "To": "accounts-payable@mailtrace.ai",
                "Subject": "Overdue Invoice Notice - Immediate Payment Required",
                "Authentication-Results": "spf=none dkim=none dmarc=none",
                "Received": "from rogue-relay.unknown-net.org ([193.142.146.33]) by gateway.mailtrace.ai"
            }
        }
    ]

    print("Submitting demo emails to gateway...")
    for item in demo_emails:
        payload = {
            "message_id": item["message_id"],
            "subject": item["subject"],
            "sender": {
                "address": item["from_address"],
                "name": item["sender_name"]
            },
            "recipients": [{"address": "user@mailtrace.ai", "name": "MailTrace User"}],
            "body_text_preview": item["body"],
            "headers": item["raw_headers"],
            "attachments": [{"filename": a, "size_bytes": 1024, "content_type": "application/octet-stream"} for a in item["attachments"]],
            "urls": [],
            "received_hops": [{"by": "gateway.mailtrace.ai", "from_host": item["raw_headers"].get("Received", ""), "ip": "185.220.101.5" if "185.220.101.5" in item["raw_headers"].get("Received", "") else "198.51.100.25"}]
        }
        res = client.post("/api/v1/emails/analyze", json=payload, headers=headers)
        if res.status_code == 200:
            data = res.json()
            print(f"  [+] {item['message_id']} -> Class: {data.get('classification')}, Decision: {data.get('decision', {}).get('action')}, Risk: {data.get('risk', {}).get('overall_risk_score')}")
        else:
            print(f"  [-] Failed {item['message_id']}: {res.status_code} - {res.text}")

    print("Demo database seeding complete!")

if __name__ == "__main__":
    seed_data()
