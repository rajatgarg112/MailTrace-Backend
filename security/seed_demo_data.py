"""
Seeds the local database with comprehensive demo emails via the real FastAPI gateway pipeline.
Populates:
- 5 Global Threats (Germany Tor, Iceland BEC, Netherlands Ransomware, Brazil Trojan, Russia Zero-Day)
- Outbound Sent emails from raghav@mailtrace.ai
- Inbound Cleared Inbox emails
- Spam emails
- Warning emails
"""

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

def seed_data():
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {settings.API_SECRET_KEY}"}

    demo_emails = [
        # --- GLOBAL THREAT 1: Germany Tor Exit Node Phishing ---
        {
            "message_id": "eml-threat-tor-001",
            "subject": "URGENT: PayPal Account Restricted - Verify Identity Immediately",
            "from_address": "security-team@paypa1-verify.de",
            "sender_name": "PayPal Global Security",
            "body": "Dear Customer, We detected unauthorized login attempts from an untrusted device. Your account has been temporarily restricted. Verify your login credentials within 24 hours at http://185.220.101.5/auth/verify to avoid suspension.",
            "attachments": [],
            "urls": [{"url": "http://185.220.101.5/auth/verify"}],
            "ip": "185.220.101.5",
            "raw_headers": {
                "From": "PayPal Global Security <security-team@paypa1-verify.de>",
                "To": "raghav@mailtrace.ai",
                "Subject": "URGENT: PayPal Account Restricted - Verify Identity Immediately",
                "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
                "Received": "from tor-exit-node.zwiebelfreunde.de ([185.220.101.5]) by gateway.mailtrace.ai"
            }
        },

        # --- GLOBAL THREAT 2: Iceland CEO Wire Fraud (BEC) ---
        {
            "message_id": "eml-threat-bec-002",
            "subject": "Confidential Request: Wire Transfer Authorization ($48,500)",
            "from_address": "ceo-office@microsoft-corporate-portal.is",
            "sender_name": "Satya Nadella (Executive Desk)",
            "body": "Hi Raghav, I am currently attending an off-site confidential acquisition committee meeting. We need an urgent wire transfer of $48,500 settled before end-of-day. Please process funds immediately. Do not call my cell phone as I cannot take calls during the session.",
            "attachments": [],
            "urls": [],
            "ip": "194.26.29.112",
            "raw_headers": {
                "From": "Satya Nadella <ceo-office@microsoft-corporate-portal.is>",
                "To": "cfo@mailtrace.ai",
                "Subject": "Confidential Request: Wire Transfer Authorization ($48,500)",
                "Authentication-Results": "spf=fail dkim=none dmarc=fail",
                "Received": "from vps-outbound.bulletproof-host.is ([194.26.29.112]) by gateway.mailtrace.ai"
            }
        },

        # --- GLOBAL THREAT 3: Netherlands Ransomware Campaign ---
        {
            "message_id": "eml-threat-ransomware-003",
            "subject": "FINAL NOTICE: Overdue Cloud Infrastructure Invoice #99218",
            "from_address": "billing-dept@spoofed-host-relay.nl",
            "sender_name": "Cloud Infrastructure Accounts",
            "body": "Your enterprise cloud cluster has overdue unpaid invoices totaling $12,450. Please find the attached itemized bill. Failure to resolve this by end-of-week will result in immediate data erasure.",
            "attachments": ["overdue_invoice_oct2026.pdf.exe"],
            "urls": [],
            "ip": "193.142.146.33",
            "raw_headers": {
                "From": "Cloud Infrastructure Accounts <billing-dept@spoofed-host-relay.nl>",
                "To": "accounts-payable@mailtrace.ai",
                "Subject": "FINAL NOTICE: Overdue Cloud Infrastructure Invoice #99218",
                "Authentication-Results": "spf=none dkim=none dmarc=none",
                "Received": "from rogue-relay.unknown-net.org ([193.142.146.33]) by gateway.mailtrace.ai"
            }
        },

        # --- GLOBAL THREAT 4: Brazil Trojan Botnet ---
        {
            "message_id": "eml-threat-trojan-004",
            "subject": "Aviso Urgente de Cobranca: Atualizacao Bancaria",
            "from_address": "atendimento@banco-central-notifica.br",
            "sender_name": "Banco Central Security",
            "body": "Prezado cliente, informamos que sua chave de seguranca foi temporariamente suspensa por motivos de prevencao. Acesse o portal http://177.12.160.2/bank/auth para reativar seu token de acesso.",
            "attachments": [],
            "urls": [{"url": "http://177.12.160.2/bank/auth"}],
            "ip": "177.12.160.2",
            "raw_headers": {
                "From": "Banco Central Security <atendimento@banco-central-notifica.br>",
                "To": "finance@mailtrace.ai",
                "Subject": "Aviso Urgente de Cobranca: Atualizacao Bancaria",
                "Authentication-Results": "spf=fail dkim=none dmarc=none",
                "Received": "from botnet-relay.brasil-telecom.net ([177.12.160.2]) by gateway.mailtrace.ai"
            }
        },

        # --- GLOBAL THREAT 5: Russia Fast-Flux DNS Zero-Day ---
        {
            "message_id": "eml-threat-fastflux-005",
            "subject": "CRITICAL CVE-2026-8819: Urgent Zero-Day Security Patch",
            "from_address": "root-security@kernel-updates-mirror.ru",
            "sender_name": "Linux Security Foundation",
            "body": "A critical remote code execution vulnerability (CVE-2026-8819) has been discovered in core web daemons. Download and execute the emergency mitigation shell script attached immediately.",
            "attachments": ["cve_patch_v6.11_emergency.sh"],
            "urls": [{"url": "http://185.156.74.88/cve/advisory"}],
            "ip": "185.156.74.88",
            "raw_headers": {
                "From": "Linux Security Foundation <root-security@kernel-updates-mirror.ru>",
                "To": "sysadmin@mailtrace.ai",
                "Subject": "CRITICAL CVE-2026-8819: Urgent Zero-Day Security Patch",
                "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
                "Received": "from bulletproof-fastflux.mow-proxy.ru ([185.156.74.88]) by gateway.mailtrace.ai"
            }
        },

        # --- OUTBOUND SENT EMAILS (From raghav@mailtrace.ai) ---
        {
            "message_id": "eml-sent-raghav-101",
            "subject": "MailTrace-AI System Architecture & Pre-Delivery Forensics Specification",
            "from_address": "raghav@mailtrace.ai",
            "sender_name": "Raghav Sharma",
            "body": "Hi Technical Evaluation Committee,\n\nPlease find our submission overview for SIH 2026 (PS 26106). MailTrace-AI implements 6 parallel analyzer engines, pre-delivery policy enforcement, SHA-256 evidence sealing, and live interactive infrastructure mapping.\n\nBest regards,\nRaghav Sharma\nLead Architect, MailTrace-AI",
            "attachments": ["MailTrace_Architecture_v1.0.pdf"],
            "urls": [],
            "ip": "127.0.0.1",
            "raw_headers": {
                "From": "Raghav Sharma <raghav@mailtrace.ai>",
                "To": "evaluators@hackathon-sih.gov.in",
                "Subject": "MailTrace-AI System Architecture & Pre-Delivery Forensics Specification",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from mailout.mailtrace.ai ([103.21.244.0]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-sent-raghav-102",
            "subject": "Sprint Milestone Review: M6 Forensics and Geolocation Completion",
            "from_address": "raghav@mailtrace.ai",
            "sender_name": "Raghav Sharma",
            "body": "Hi Team,\n\nAll M6 forensic milestones have been completed and verified against 118 unit and integration tests. Geolocation mapping with Tor exit node indicators is fully integrated.\n\nRegards,\nRaghav",
            "attachments": [],
            "urls": [],
            "ip": "127.0.0.1",
            "raw_headers": {
                "From": "Raghav Sharma <raghav@mailtrace.ai>",
                "To": "dev-team@mailtrace.ai",
                "Subject": "Sprint Milestone Review: M6 Forensics and Geolocation Completion",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from mailout.mailtrace.ai ([103.21.244.0]) by gateway.mailtrace.ai"
            }
        },

        # --- INBOX EMAILS (Safe Inbound) ---
        {
            "message_id": "eml-inbox-safe-201",
            "subject": "Smart India Hackathon 2026: Team Final Round Confirmation",
            "from_address": "coordination@sih.gov.in",
            "sender_name": "SIH Organizing Committee",
            "body": "Dear Raghav and Team,\n\nWe are pleased to confirm your shortlisted status for the Grand Finale under Problem Statement 26106. Please review the attached schedule and guidelines.\n\nBest regards,\nSIH Coordination Desk",
            "attachments": ["sih2026_grand_finale_schedule.pdf"],
            "urls": [],
            "ip": "164.100.158.23",
            "raw_headers": {
                "From": "SIH Organizing Committee <coordination@sih.gov.in>",
                "To": "raghav@mailtrace.ai",
                "Subject": "Smart India Hackathon 2026: Team Final Round Confirmation",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from nic-mail-gateway.nic.in ([164.100.158.23]) by gateway.mailtrace.ai"
            }
        },
        {
            "message_id": "eml-inbox-safe-202",
            "subject": "Quarterly Platform Reliability Report - All Systems Operational",
            "from_address": "engineering@cloudprovider-infra.com",
            "sender_name": "Infrastructure Reliability Team",
            "body": "Hello Raghav,\n\nYour production gateway instances have maintained 99.99% uptime over the past 90 days. Average ML classification latency remains steady at 28ms.\n\nWarm regards,\nEngineering Team",
            "attachments": [],
            "urls": [],
            "ip": "198.51.100.45",
            "raw_headers": {
                "From": "Infrastructure Reliability Team <engineering@cloudprovider-infra.com>",
                "To": "raghav@mailtrace.ai",
                "Subject": "Quarterly Platform Reliability Report - All Systems Operational",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
                "Received": "from mail.cloudprovider-infra.com ([198.51.100.45]) by gateway.mailtrace.ai"
            }
        },

        # --- SPAM EMAILS ---
        {
            "message_id": "eml-spam-promotions-301",
            "subject": "Exclusive 70% Discount: Upgrade Enterprise Server Nodes Today",
            "from_address": "sales@hostdeals-marketing-promo.biz",
            "sender_name": "HostDeals Marketing",
            "body": "Unsubscribe at any time. Get 70% off high-bandwidth dedicated servers today only! Limited quantities available.",
            "attachments": [],
            "urls": [],
            "ip": "192.0.2.88",
            "raw_headers": {
                "From": "HostDeals Marketing <sales@hostdeals-marketing-promo.biz>",
                "To": "raghav@mailtrace.ai",
                "Subject": "Exclusive 70% Discount: Upgrade Enterprise Server Nodes Today",
                "Authentication-Results": "spf=pass dkim=none dmarc=pass",
                "Received": "from promo-mktg.hostdeals.biz ([192.0.2.88]) by gateway.mailtrace.ai"
            }
        },

        # --- WARNINGS EMAILS ---
        {
            "message_id": "eml-warn-external-401",
            "subject": "Contractor Onboarding: Please verify direct deposit bank details",
            "from_address": "payroll-update@external-consultant-group.org",
            "sender_name": "Payroll Support",
            "body": "Hello, This is our first time contacting you from this domain. Please reply with updated bank account details for upcoming contractor payments.",
            "attachments": [],
            "urls": [],
            "ip": "203.0.113.55",
            "raw_headers": {
                "From": "Payroll Support <payroll-update@external-consultant-group.org>",
                "To": "raghav@mailtrace.ai",
                "Subject": "Contractor Onboarding: Please verify direct deposit bank details",
                "Authentication-Results": "spf=pass dkim=none dmarc=none",
                "Received": "from outbound.external-consultant-group.org ([203.0.113.55]) by gateway.mailtrace.ai"
            }
        },
    ]

    print("========================================================")
    print("      MailTrace-AI: Seeding Comprehensive Demo Dataset   ")
    print("========================================================")
    for item in demo_emails:
        payload = {
            "message_id": item["message_id"],
            "subject": item["subject"],
            "sender": {
                "address": item["from_address"],
                "name": item["sender_name"]
            },
            "recipients": [{"address": "raghav@mailtrace.ai" if item["from_address"] != "raghav@mailtrace.ai" else "client@external.com", "name": "MailTrace User"}],
            "body_text_preview": item["body"],
            "headers": item["raw_headers"],
            "attachments": [{"filename": a, "size_bytes": 1024, "content_type": "application/octet-stream"} for a in item["attachments"]],
            "urls": item["urls"],
            "received_hops": [{"by": "gateway.mailtrace.ai", "from_host": item["raw_headers"].get("Received", ""), "ip": item["ip"]}]
        }
        res = client.post("/api/v1/emails/analyze", json=payload, headers=headers)
        if res.status_code == 200:
            data = res.json()
            dec = data.get("decision", {})
            action = dec.get("action")
            risk = data.get("risk", {}).get("overall_risk_score")
            cls = data.get("classification")
            print(f"  [+] {item['message_id']} -> Class: {cls:<10} Action: {action:<10} Risk: {risk:<4} ({item['subject'][:40]}...)")
        else:
            print(f"  [-] Failed {item['message_id']}: {res.status_code} - {res.text}")

    print("\nDatabase seeding completed successfully!")

if __name__ == "__main__":
    seed_data()
