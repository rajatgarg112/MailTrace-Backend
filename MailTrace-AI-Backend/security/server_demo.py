"""
MailTrace-AI Security & Forensics Dashboard Server (Member 4)
Starts a FastAPI web server with a multi-tab Security Analyst Web UI at http://127.0.0.1:8000
"""

import uvicorn
from fastapi import FastAPI, Body
from fastapi.responses import HTMLResponse
from security.runner import SecurityAnalyzer

app = FastAPI(title="MailTrace-AI Security & Forensics Console (Member 4)")
analyzer = SecurityAnalyzer()

@app.post("/api/analyze")
def analyze_email(payload: dict = Body(...)):
    headers = payload.get("headers", {})
    body = payload.get("body", "")
    attachments = payload.get("attachments", [])
    
    sender = payload.get("sender")
    subject = payload.get("subject")
    
    if sender and "From" not in headers:
        headers["From"] = sender
    if subject and "Subject" not in headers:
        headers["Subject"] = subject
        
    result = analyzer.analyze(
        raw_headers_or_dict=headers,
        body_text_or_html=body,
        attachments_input=attachments
    )
    return result.model_dump()


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailTrace-AI — Security & Forensics Console (Member 4)</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0b0f19;
            --panel-bg: rgba(18, 26, 43, 0.75);
            --panel-border: rgba(255, 255, 255, 0.08);
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-green: #10b981;
            --accent-purple: #a855f7;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg-dark);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(59, 130, 246, 0.12) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(239, 68, 68, 0.1) 0%, transparent 40%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1440px;
            margin: 0 auto 24px;
            padding: 20px 28px;
            background: var(--panel-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
        }

        .logo-title {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .shield-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
        }

        .badge-member {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }

        .layout-grid {
            display: grid;
            grid-template-columns: 440px 1fr;
            gap: 24px;
            max-width: 1440px;
            margin: 0 auto;
        }

        .card {
            background: var(--panel-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
        }

        .card-title {
            font-size: 15px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .form-group { margin-bottom: 14px; }
        label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }

        input, textarea, select {
            width: 100%;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #fff;
            padding: 11px 14px;
            border-radius: 10px;
            font-family: inherit;
            font-size: 13.5px;
            transition: all 0.2s;
        }

        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 12px rgba(6, 182, 212, 0.3);
        }

        textarea { font-family: 'JetBrains Mono', monospace; font-size: 12px; resize: vertical; }

        .btn-analyze {
            width: 100%;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            color: #fff;
            border: none;
            padding: 14px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 15px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .btn-analyze:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.4);
        }

        /* Nav Tabs */
        .tab-bar {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            margin-bottom: 20px;
            padding-bottom: 10px;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 8px 16px;
            font-size: 13.5px;
            font-weight: 600;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.2s;
        }

        .tab-btn.active {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Risk Banner */
        .risk-banner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 24px;
            background: rgba(0,0,0,0.3);
            border-radius: 14px;
            border: 1px solid rgba(255,255,255,0.05);
        }

        .score-circle {
            width: 95px;
            height: 95px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 30px;
            border: 5px solid var(--accent-red);
            color: var(--accent-red);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }

        .tags-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 14px;
        }

        .tag-pill {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11.5px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }

        .auth-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 14px; }
        .auth-card { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); padding: 14px; border-radius: 12px; text-align: center; }
        .status-badge { display: inline-block; margin-top: 6px; padding: 4px 12px; border-radius: 6px; font-weight: 700; font-size: 12px; }
        .status-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .status-fail { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

        .finding-item {
            padding: 10px 14px;
            background: rgba(239, 68, 68, 0.08);
            border-left: 3px solid var(--accent-red);
            border-radius: 0 8px 8px 0;
            margin-bottom: 8px;
            font-size: 13px;
            color: #fecdd3;
        }

        /* Timeline Items */
        .timeline-step {
            display: flex;
            gap: 16px;
            padding-bottom: 16px;
            position: relative;
        }

        .timeline-step::before {
            content: '';
            position: absolute;
            left: 15px;
            top: 30px;
            bottom: 0;
            width: 2px;
            background: rgba(255,255,255,0.1);
        }

        .timeline-step:last-child::before { display: none; }

        .timeline-seq {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid var(--accent-blue);
            color: #60a5fa;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 13px;
            flex-shrink: 0;
            z-index: 1;
        }

        .hash-box {
            background: rgba(0,0,0,0.4);
            border: 1px solid rgba(255,255,255,0.08);
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11.5px;
            word-break: break-all;
            margin-bottom: 8px;
        }

        table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 10px; }
        th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.06); }
        th { color: var(--text-muted); font-weight: 600; }
        td { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    </style>
</head>
<body>

    <div class="header">
        <div class="logo-title">
            <div class="shield-icon">🛡️</div>
            <div>
                <h1 style="font-size: 22px; font-weight: 800;">MailTrace-AI Security & Forensics Console</h1>
                <p style="font-size: 13px; color: var(--text-muted);">Dynamic Threat Engine & Cryptographic Forensics (Member 4)</p>
            </div>
        </div>
        <div class="badge-member">Member 4 — Cyber Security Analyst</div>
    </div>

    <div class="layout-grid">
        <!-- Left Column: Payload Form & Presets -->
        <div>
            <div class="card">
                <div class="card-title">
                    <span>Email Inspection Payload</span>
                    <span>📥 Payload</span>
                </div>

                <div class="form-group">
                    <label>Preset Test Scenarios</label>
                    <select id="presetSelect" onchange="loadPreset()">
                        <option value="phish">1. Phishing Impersonating PayPal (Malicious / Quarantine)</option>
                        <option value="malware">2. Double Extension Attachment Malware (Malicious / Quarantine)</option>
                        <option value="safe">3. Legitimate Enterprise Email (Safe / Inbox)</option>
                        <option value="display_spoof">4. Executive Display Name Spoof (Suspicious / Warn)</option>
                        <option value="shortener">5. Shortened URL & Anchor Mismatch (Suspicious / Warn)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label>From Header / Sender</label>
                    <input type="text" id="senderInput" value="PayPal Security Team <billing@paypa1-verify.xyz>">
                </div>

                <div class="form-group">
                    <label>Subject</label>
                    <input type="text" id="subjectInput" value="URGENT: Your Account Has Been Suspended">
                </div>

                <div class="form-group">
                    <label>Email Body (HTML / Plaintext)</label>
                    <textarea id="bodyInput" rows="5">Dear User, verify your PayPal account now: <a href="http://185.220.101.5/login">http://paypal.com/verify</a> or click https://bit.ly/3x89qAZ</textarea>
                </div>

                <div class="form-group">
                    <label>Attachments (comma-separated filenames)</label>
                    <input type="text" id="attachmentsInput" value="Account_Security_Details.pdf.exe">
                </div>

                <div class="form-group">
                    <label>Authentication-Results Header</label>
                    <input type="text" id="authHeaderInput" value="mx.google.com; spf=fail; dkim=fail; dmarc=fail">
                </div>

                <div class="form-group">
                    <label>Received Headers (Hop Chain)</label>
                    <textarea id="receivedInput" rows="3">from mail.suspicious-relay.com ([185.220.101.5]) by mx.google.com
from internal.spammer.local ([10.0.0.5]) by mail.suspicious-relay.com</textarea>
                </div>

                <button class="btn-analyze" onclick="runAnalysis()">⚡ Run Security & Forensics Engine</button>
            </div>
        </div>

        <!-- Right Column: Multi-Tab Analyst Console -->
        <div>
            <div class="tab-bar">
                <button class="tab-btn active" onclick="switchTab('overviewTab', this)">Overview & Policy</button>
                <button class="tab-btn" onclick="switchTab('authTab', this)">Authentication</button>
                <button class="tab-btn" onclick="switchTab('domainTab', this)">Domain & Identity</button>
                <button class="tab-btn" onclick="switchTab('urlTab', this)">URLs & Links</button>
                <button class="tab-btn" onclick="switchTab('attachTab', this)">Attachments</button>
                <button class="tab-btn" onclick="switchTab('forensicsTab', this)">Forensics & Timeline</button>
            </div>

            <!-- Tab 1: Overview & Policy Decision -->
            <div id="overviewTab" class="tab-content active">
                <div class="card">
                    <div class="card-title">
                        <span>Threat Classification & Delivery Policy</span>
                        <span id="evalStatus">Ready</span>
                    </div>

                    <div class="risk-banner">
                        <div>
                            <h2 id="classificationText" style="font-size: 26px; font-weight: 800; color: var(--accent-red);">MALICIOUS</h2>
                            <p id="policyActionText" style="color: #60a5fa; font-weight: 700; font-size: 15px; margin-top: 4px;">Delivery Action: QUARANTINE</p>
                            <p id="policyReasonText" style="color: var(--text-muted); font-size: 12.5px; margin-top: 4px; max-width: 480px;"></p>
                        </div>
                        <div class="score-circle" id="scoreCircle">
                            <span id="scoreVal">100</span>
                            <span class="score-label" style="font-size: 9px; font-weight: 700;">RISK SCORE</span>
                        </div>
                    </div>

                    <h4 style="margin-top: 20px; font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Assigned Security Tags</h4>
                    <div class="tags-container" id="tagsContainer"></div>
                </div>
            </div>

            <!-- Tab 2: Authentication -->
            <div id="authTab" class="tab-content">
                <div class="card">
                    <div class="card-title">
                        <span>Email Authentication Protocols</span>
                        <span>🔑 Auth</span>
                    </div>
                    <div class="auth-grid">
                        <div class="auth-card">
                            <div style="font-size: 12px; color: var(--text-muted);">SPF Status</div>
                            <div class="status-badge status-fail" id="spfBadge">FAIL</div>
                        </div>
                        <div class="auth-card">
                            <div style="font-size: 12px; color: var(--text-muted);">DKIM Status</div>
                            <div class="status-badge status-fail" id="dkimBadge">FAIL</div>
                        </div>
                        <div class="auth-card">
                            <div style="font-size: 12px; color: var(--text-muted);">DMARC Policy</div>
                            <div class="status-badge status-fail" id="dmarcBadge">FAIL</div>
                        </div>
                    </div>
                    <div style="margin-top: 16px; font-size: 13px; color: var(--text-muted);" id="authDetailsBox"></div>
                </div>
            </div>

            <!-- Tab 3: Domain & Identity -->
            <div id="domainTab" class="tab-content">
                <div class="card">
                    <div class="card-title">
                        <span>Domain Security & Identity Spoofing</span>
                        <span>🌐 Identity</span>
                    </div>
                    <ul class="finding-list" id="domainFindingsList"></ul>
                </div>
            </div>

            <!-- Tab 4: URLs & Links -->
            <div id="urlTab" class="tab-content">
                <div class="card">
                    <div class="card-title">
                        <span>URL Extraction & Anchor Text Inspection</span>
                        <span>🔗 Links</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Extracted URL</th>
                                <th>Host Domain</th>
                                <th>Security Flag</th>
                            </tr>
                        </thead>
                        <tbody id="urlTableBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Tab 5: Attachments -->
            <div id="attachTab" class="tab-content">
                <div class="card">
                    <div class="card-title">
                        <span>Static Attachment Inspection</span>
                        <span>📎 Files</span>
                    </div>
                    <div id="attachmentFindingsContainer"></div>
                </div>
            </div>

            <!-- Tab 6: Forensics & Timeline -->
            <div id="forensicsTab" class="tab-content">
                <div class="card">
                    <div class="card-title">
                        <span>Cryptographic Evidence Hashes</span>
                        <span>🔒 SHA-256</span>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">Raw Payload SHA-256</div>
                        <div class="hash-box" id="rawHashBox"></div>
                        
                        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">Headers SHA-256</div>
                        <div class="hash-box" id="headersHashBox"></div>

                        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">Network Infrastructure Context</div>
                        <div class="hash-box" style="color: #60a5fa;" id="netContextBox"></div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">
                        <span>Step-by-Step Investigation Timeline</span>
                        <span>⏱️ Timeline</span>
                    </div>
                    <div id="timelineContainer"></div>
                </div>
            </div>

        </div>
    </div>

    <script>
        const PRESETS = {
            phish: {
                sender: "PayPal Security Team <billing@paypa1-verify.xyz>",
                subject: "URGENT: Your Account Has Been Suspended",
                body: 'Dear User, verify your PayPal account now: <a href="http://185.220.101.5/login">http://paypal.com/verify</a> or click https://bit.ly/3x89qAZ',
                attachments: "Account_Security_Details.pdf.exe",
                auth: "mx.google.com; spf=fail; dkim=fail; dmarc=fail",
                received: "from mail.suspicious-relay.com ([185.220.101.5]) by mx.google.com\nfrom internal.spammer.local ([10.0.0.5]) by mail.suspicious-relay.com"
            },
            malware: {
                sender: "Accounts Payable <invoices@finance-update.top>",
                subject: "OVERDUE INVOICE #89283 PAYMENT REQUIRED",
                body: "Please download the attached PDF invoice and process payment immediately.",
                attachments: "Invoice_2026_September.pdf.exe, Payment_Instructions.scr",
                auth: "mx.google.com; spf=fail; dkim=none; dmarc=fail",
                received: "from host.malware-drop.com ([198.51.100.22]) by mx.google.com"
            },
            safe: {
                sender: "HR Department <hr@company.com>",
                subject: "Updated Holiday Schedule for 2026",
                body: "Hello Team, please review the holiday schedule on our official internal portal: https://company.com/portal/holidays",
                attachments: "Company_Calendar.pdf",
                auth: "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
                received: "from mail.company.com ([192.0.2.1]) by mx.google.com"
            },
            display_spoof: {
                sender: "Bank of America Support <alert@random-scam-site.org>",
                subject: "Notice: Important security update required",
                body: "Please sign in to confirm your personal information.",
                attachments: "",
                auth: "mx.google.com; spf=neutral; dkim=none; dmarc=fail",
                received: "from host.scam.org ([198.51.100.4]) by mx.google.com"
            },
            shortener: {
                sender: "Notice <info@webmail-alert.click>",
                subject: "Verify Mailbox Storage Limit",
                body: 'Your mailbox is 99% full. Expand storage immediately: <a href="https://bit.ly/3x89qAZ">http://webmail.com/expand</a>',
                attachments: "",
                auth: "mx.google.com; spf=fail; dkim=none; dmarc=fail",
                received: "from relay.click.net ([203.0.113.8]) by mx.google.com"
            }
        };

        function switchTab(tabId, btn) {
            document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
            document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
            document.getElementById(tabId).classList.add("active");
            btn.classList.add("active");
        }

        function loadPreset() {
            const key = document.getElementById("presetSelect").value;
            const p = PRESETS[key];
            if (!p) return;
            document.getElementById("senderInput").value = p.sender;
            document.getElementById("subjectInput").value = p.subject;
            document.getElementById("bodyInput").value = p.body;
            document.getElementById("attachmentsInput").value = p.attachments;
            document.getElementById("authHeaderInput").value = p.auth;
            document.getElementById("receivedInput").value = p.received;
            runAnalysis();
        }

        async function runAnalysis() {
            const sender = document.getElementById("senderInput").value;
            const subject = document.getElementById("subjectInput").value;
            const body = document.getElementById("bodyInput").value;
            const attachStr = document.getElementById("attachmentsInput").value;
            const authHeader = document.getElementById("authHeaderInput").value;
            const receivedText = document.getElementById("receivedInput").value;

            const receivedList = receivedText.split("\n").filter(l => l.trim().length > 0);
            const attachmentsList = attachStr.split(",").map(a => a.trim()).filter(a => a.length > 0);

            const payload = {
                sender: sender,
                subject: subject,
                body: body,
                attachments: attachmentsList,
                headers: {
                    "From": sender,
                    "Subject": subject,
                    "Authentication-Results": authHeader,
                    "Received": receivedList
                }
            };

            document.getElementById("evalStatus").innerText = "Analyzing...";

            try {
                const resp = await fetch("/api/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const data = await resp.json();

                // 1. Overview & Risk Policy
                const score = data.policy_decision.risk_score;
                const classification = data.policy_decision.threat_classification;
                const action = data.policy_decision.delivery_action;

                document.getElementById("scoreVal").innerText = score;
                document.getElementById("classificationText").innerText = classification;
                document.getElementById("policyActionText").innerText = "Delivery Action: " + action;
                document.getElementById("policyReasonText").innerText = data.policy_decision.action_reason;
                document.getElementById("evalStatus").innerText = "Evaluated";

                const circle = document.getElementById("scoreCircle");
                const classText = document.getElementById("classificationText");

                if (score >= 76) {
                    circle.style.borderColor = "var(--accent-red)";
                    circle.style.color = "var(--accent-red)";
                    classText.style.color = "var(--accent-red)";
                } else if (score >= 56) {
                    circle.style.borderColor = "var(--accent-amber)";
                    circle.style.color = "var(--accent-amber)";
                    classText.style.color = "var(--accent-amber)";
                } else {
                    circle.style.borderColor = "var(--accent-green)";
                    circle.style.color = "var(--accent-green)";
                    classText.style.color = "var(--accent-green)";
                }

                // Security Tags
                const tagsContainer = document.getElementById("tagsContainer");
                tagsContainer.innerHTML = "";
                if (data.security_tags.length === 0) {
                    tagsContainer.innerHTML = '<span class="tag-pill" style="background: rgba(16,185,129,0.15); color: #34d399; border-color: rgba(16,185,129,0.3);">NO_THREATS_FLAGGED</span>';
                } else {
                    data.security_tags.forEach(t => {
                        tagsContainer.innerHTML += `<span class="tag-pill">${t}</span>`;
                    });
                }

                // 2. Auth Badges
                const setBadge = (elId, status) => {
                    const el = document.getElementById(elId);
                    el.innerText = status;
                    el.className = (status === "PASS") ? "status-badge status-pass" : "status-badge status-fail";
                };
                setBadge("spfBadge", data.authentication.spf);
                setBadge("dkimBadge", data.authentication.dkim);
                setBadge("dmarcBadge", data.authentication.dmarc);

                // 3. Domain Findings
                const findingsList = document.getElementById("domainFindingsList");
                findingsList.innerHTML = "";
                const df = data.domain_analysis.findings || [];
                const hf = data.headers.anomalies || [];
                const allF = [...df, ...hf];

                if (allF.length === 0) {
                    findingsList.innerHTML = '<li class="finding-item" style="border-color: var(--accent-green); background: rgba(16,185,129,0.08); color: #a7f3d0;">No domain anomalies or identity spoofing detected.</li>';
                } else {
                    allF.forEach(f => {
                        findingsList.innerHTML += `<li class="finding-item">${f}</li>`;
                    });
                }

                // 4. URLs Table
                const tbody = document.getElementById("urlTableBody");
                tbody.innerHTML = "";
                const urls = data.url_analysis.urls_details || [];
                if (urls.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="color: var(--text-muted);">No URLs extracted from body.</td></tr>';
                } else {
                    urls.forEach(u => {
                        const flag = u.is_suspicious 
                            ? `<span style="color: var(--accent-red);">${u.suspicious_reasons.join(", ") || "Suspicious"}</span>` 
                            : `<span style="color: var(--accent-green);">Clean</span>`;
                        tbody.innerHTML += `<tr><td>${u.url}</td><td>${u.domain}</td><td>${flag}</td></tr>`;
                    });
                }

                // 5. Attachments
                const attachContainer = document.getElementById("attachmentFindingsContainer");
                attachContainer.innerHTML = "";
                const atts = data.attachments.attachments || [];
                if (atts.length === 0) {
                    attachContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No attachments present in payload.</p>';
                } else {
                    atts.forEach(a => {
                        const style = a.is_dangerous 
                            ? 'border-color: var(--accent-red); background: rgba(239, 68, 68, 0.08); color: #fecdd3;' 
                            : 'border-color: var(--accent-green); background: rgba(16, 185, 129, 0.08); color: #a7f3d0;';
                        attachContainer.innerHTML += `
                            <div class="finding-item" style="${style}">
                                <strong>${a.filename}</strong> (${a.extension}) — ${a.is_dangerous ? (a.reason || 'Flagged Dangerous') : 'Safe Attachment'}
                            </div>`;
                    });
                }

                // 6. Forensics & Timeline
                document.getElementById("rawHashBox").innerText = data.forensics.raw_sha256;
                document.getElementById("headersHashBox").innerText = data.forensics.headers_sha256;
                
                const net = data.forensics.network_context;
                document.getElementById("netContextBox").innerText = `IP: ${net.originating_ip || 'N/A'} | ASN: ${net.asn} | Region: ${net.approximate_region}\nDisclaimer: ${net.disclaimer}`;

                const timelineContainer = document.getElementById("timelineContainer");
                timelineContainer.innerHTML = "";
                data.forensics.timeline.forEach(t => {
                    timelineContainer.innerHTML += `
                        <div class="timeline-step">
                            <div class="timeline-seq">${t.sequence}</div>
                            <div>
                                <div style="font-weight: 700; font-size: 13.5px; color: #f3f4f6;">${t.stage} — <span style="color: #60a5fa;">${t.status}</span></div>
                                <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">${t.details}</div>
                            </div>
                        </div>`;
                });

            } catch (err) {
                alert("Error connecting to Security Engine API: " + err);
            }
        }

        window.onload = runAnalysis;
    </script>
</body>
</html>"""


if __name__ == "__main__":
    print("=" * 70)
    print(" Starting MailTrace-AI Security & Forensics Dashboard Server (Member 4)...")
    print(" Web UI Available at: http://127.0.0.1:8000")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=8000)
