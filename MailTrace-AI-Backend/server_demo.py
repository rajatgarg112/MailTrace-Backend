"""
MailTrace-AI Security Dashboard Demo Server (Member 4)
Starts a FastAPI web server with an embedded rich Security Analyst Web UI at http://127.0.0.1:8000
"""

import uvicorn
from fastapi import FastAPI, Body
from fastapi.responses import HTMLResponse
from security.runner import SecurityAnalyzer

app = FastAPI(title="MailTrace-AI Security Dashboard Demo (Member 4)")
analyzer = SecurityAnalyzer()

@app.post("/api/analyze")
def analyze_email(payload: dict = Body(...)):
    headers = payload.get("headers", {})
    body = payload.get("body", "")
    
    # If custom sender/subject passed from UI form, synthesize headers
    sender = payload.get("sender")
    subject = payload.get("subject")
    
    if sender and "From" not in headers:
        headers["From"] = sender
    if subject and "Subject" not in headers:
        headers["Subject"] = subject
        
    result = analyzer.analyze(headers, body)
    return result.model_dump()


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailTrace-AI — Security Analyst Console (Member 4)</title>
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
            max-width: 1400px;
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
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 20px;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
        }

        .badge-member {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }

        .layout-grid {
            display: grid;
            grid-template-columns: 460px 1fr;
            gap: 24px;
            max-width: 1400px;
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
            font-size: 16px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .form-group {
            margin-bottom: 16px;
        }

        label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        input, textarea, select {
            width: 100%;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #fff;
            padding: 12px 14px;
            border-radius: 10px;
            font-family: inherit;
            font-size: 14px;
            transition: all 0.2s;
        }

        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 12px rgba(6, 182, 212, 0.3);
        }

        textarea {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            resize: vertical;
        }

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

        /* Risk Gauge & Stats */
        .risk-banner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 24px;
            background: rgba(0,0,0,0.3);
            border-radius: 14px;
            border: 1px solid rgba(255,255,255,0.05);
        }

        .score-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 32px;
            border: 6px solid var(--accent-red);
            color: var(--accent-red);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.3);
        }

        .score-label {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
        }

        .tags-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }

        .tag-pill {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }

        .auth-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
            margin-top: 16px;
        }

        .auth-card {
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.05);
            padding: 16px;
            border-radius: 12px;
            text-align: center;
        }

        .status-badge {
            display: inline-block;
            margin-top: 8px;
            padding: 4px 14px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 13px;
        }

        .status-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .status-fail { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }

        .finding-list {
            list-style: none;
        }

        .finding-item {
            padding: 10px 14px;
            background: rgba(239, 68, 68, 0.08);
            border-left: 3px solid var(--accent-red);
            border-radius: 0 8px 8px 0;
            margin-bottom: 8px;
            font-size: 13px;
            color: #fecdd3;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }

        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }

        th { color: var(--text-muted); font-weight: 600; }
        td { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    </style>
</head>
<body>

    <div class="header">
        <div class="logo-title">
            <div class="shield-icon">🛡️</div>
            <div>
                <h1 style="font-size: 22px; font-weight: 800;">MailTrace-AI Security Dashboard</h1>
                <p style="font-size: 13px; color: var(--text-muted);">Cyber Security Engine Live Inspection Console</p>
            </div>
        </div>
        <div class="badge-member">Member 4 — Cyber Security Analyst</div>
    </div>

    <div class="layout-grid">
        <!-- Left Column: Input Form & Presets -->
        <div>
            <div class="card">
                <div class="card-title">
                    <span>Email Inspection Payload</span>
                    <span>📥 Input</span>
                </div>

                <div class="form-group">
                    <label>Preset Test Cases</label>
                    <select id="presetSelect" onchange="loadPreset()">
                        <option value="phish">1. Phishing Impersonating PayPal (High Risk)</option>
                        <option value="safe">2. Legitimate Enterprise Email (Safe)</option>
                        <option value="display_spoof">3. Executive Display Name Spoofing</option>
                        <option value="shortener">4. Hidden URL Shortener & Mismatch</option>
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
                    <textarea id="bodyInput" rows="6">Dear User, verify your PayPal account now: <a href="http://185.220.101.5/login">http://paypal.com/verify</a> or click https://bit.ly/3x89qAZ</textarea>
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

                <button class="btn-analyze" onclick="runAnalysis()">⚡ Run Security Analysis</button>
            </div>
        </div>

        <!-- Right Column: Security Analysis Results -->
        <div>
            <!-- Risk Score Banner -->
            <div class="card">
                <div class="card-title">
                    <span>Security Analysis Summary</span>
                    <span id="evalStatus">Ready</span>
                </div>

                <div class="risk-banner">
                    <div>
                        <h2 id="classificationText" style="font-size: 28px; font-weight: 800; color: var(--accent-red);">MALICIOUS</h2>
                        <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Security Engine Assessment</p>
                    </div>
                    <div class="score-circle" id="scoreCircle">
                        <span id="scoreVal">100</span>
                        <span class="score-label">RISK CONTRIBUTION</span>
                    </div>
                </div>

                <h4 style="margin-top: 20px; font-size: 13px; color: var(--text-muted); text-transform: uppercase;">Generated Security Tags</h4>
                <div class="tags-container" id="tagsContainer">
                    <span class="tag-pill">HEADER_ANOMALY</span>
                    <span class="tag-pill">SPF_FAIL</span>
                    <span class="tag-pill">DMARC_FAIL</span>
                    <span class="tag-pill">LOOKALIKE_DOMAIN</span>
                    <span class="tag-pill">SUSPICIOUS_URL</span>
                </div>
            </div>

            <!-- Email Authentication (SPF, DKIM, DMARC) -->
            <div class="card">
                <div class="card-title">
                    <span>Email Authentication Checks</span>
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
            </div>

            <!-- Domain Security & Lookalike -->
            <div class="card">
                <div class="card-title">
                    <span>Domain & Identity Security</span>
                    <span>🌐 Domain</span>
                </div>
                <ul class="finding-list" id="domainFindingsList">
                    <li class="finding-item">Brand spoofing detected: Domain 'paypa1-verify.xyz' targets 'paypal.com'</li>
                    <li class="finding-item">Suspicious TLD flagged: '.xyz'</li>
                </ul>
            </div>

            <!-- Extracted URLs & Anchor Text -->
            <div class="card">
                <div class="card-title">
                    <span>URL & Link Inspection</span>
                    <span>🔗 Links</span>
                </div>
                <table id="urlTable">
                    <thead>
                        <tr>
                            <th>Extracted URL</th>
                            <th>Host / Domain</th>
                            <th>Flag</th>
                        </tr>
                    </thead>
                    <tbody id="urlTableBody">
                        <tr>
                            <td>http://185.220.101.5/login</td>
                            <td>185.220.101.5</td>
                            <td><span style="color: var(--accent-red);">Raw IP Host</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>

        </div>
    </div>

    <script>
        const PRESETS = {
            phish: {
                sender: "PayPal Security Team <billing@paypa1-verify.xyz>",
                subject: "URGENT: Your Account Has Been Suspended",
                body: 'Dear User, verify your PayPal account now: <a href="http://185.220.101.5/login">http://paypal.com/verify</a> or click https://bit.ly/3x89qAZ',
                auth: "mx.google.com; spf=fail; dkim=fail; dmarc=fail",
                received: "from mail.suspicious-relay.com ([185.220.101.5]) by mx.google.com\nfrom internal.spammer.local ([10.0.0.5]) by mail.suspicious-relay.com"
            },
            safe: {
                sender: "HR Department <hr@company.com>",
                subject: "Updated Holiday Schedule for 2026",
                body: "Hello Team, please review the holiday schedule on our official internal portal: https://company.com/portal/holidays",
                auth: "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
                received: "from mail.company.com ([192.0.2.1]) by mx.google.com"
            },
            display_spoof: {
                sender: "Bank of America Support <alert@random-scam-site.org>",
                subject: "Notice: Important update required",
                body: "Please sign in to confirm your information.",
                auth: "mx.google.com; spf=neutral; dkim=none; dmarc=fail",
                received: "from host.scam.org ([198.51.100.4]) by mx.google.com"
            },
            shortener: {
                sender: "Notice <info@webmail-alert.click>",
                subject: "Verify Mailbox Storage",
                body: 'Your mailbox is 99% full. Expand storage immediately: <a href="https://bit.ly/3x89qAZ">http://webmail.com/expand</a>',
                auth: "mx.google.com; spf=fail; dkim=none; dmarc=fail",
                received: "from relay.click.net ([203.0.113.8]) by mx.google.com"
            }
        };

        function loadPreset() {
            const presetKey = document.getElementById("presetSelect").value;
            const p = PRESETS[presetKey];
            if (!p) return;
            document.getElementById("senderInput").value = p.sender;
            document.getElementById("subjectInput").value = p.subject;
            document.getElementById("bodyInput").value = p.body;
            document.getElementById("authHeaderInput").value = p.auth;
            document.getElementById("receivedInput").value = p.received;
            runAnalysis();
        }

        async function runAnalysis() {
            const sender = document.getElementById("senderInput").value;
            const subject = document.getElementById("subjectInput").value;
            const body = document.getElementById("bodyInput").value;
            const authHeader = document.getElementById("authHeaderInput").value;
            const receivedText = document.getElementById("receivedInput").value;

            const receivedList = receivedText.split("\n").filter(line => line.trim().length > 0);

            const payload = {
                sender: sender,
                subject: subject,
                body: body,
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

                // Update Risk Score Banner
                const score = data.risk_score_contribution;
                document.getElementById("scoreVal").innerText = score;
                document.getElementById("evalStatus").innerText = "Evaluated";

                const circle = document.getElementById("scoreCircle");
                const classText = document.getElementById("classificationText");

                if (score >= 70) {
                    circle.style.borderColor = "var(--accent-red)";
                    circle.style.color = "var(--accent-red)";
                    classText.innerText = "HIGH RISK / MALICIOUS";
                    classText.style.color = "var(--accent-red)";
                } else if (score >= 30) {
                    circle.style.borderColor = "var(--accent-amber)";
                    circle.style.color = "var(--accent-amber)";
                    classText.innerText = "SUSPICIOUS";
                    classText.style.color = "var(--accent-amber)";
                } else {
                    circle.style.borderColor = "var(--accent-green)";
                    circle.style.color = "var(--accent-green)";
                    classText.innerText = "SAFE";
                    classText.style.color = "var(--accent-green)";
                }

                // Render Security Tags
                const tagsContainer = document.getElementById("tagsContainer");
                tagsContainer.innerHTML = "";
                if (data.security_tags.length === 0) {
                    tagsContainer.innerHTML = '<span class="tag-pill" style="background: rgba(16,185,129,0.15); color: #34d399; border-color: rgba(16,185,129,0.3);">NO_THREATS_FLAGGED</span>';
                } else {
                    data.security_tags.forEach(t => {
                        tagsContainer.innerHTML += `<span class="tag-pill">${t}</span>`;
                    });
                }

                // Render Auth Badges
                const setBadge = (elId, status) => {
                    const el = document.getElementById(elId);
                    el.innerText = status;
                    if (status === "PASS") {
                        el.className = "status-badge status-pass";
                    } else {
                        el.className = "status-badge status-fail";
                    }
                };
                setBadge("spfBadge", data.authentication.spf);
                setBadge("dkimBadge", data.authentication.dkim);
                setBadge("dmarcBadge", data.authentication.dmarc);

                // Render Domain Findings
                const findingsList = document.getElementById("domainFindingsList");
                findingsList.innerHTML = "";
                const df = data.domain_analysis.findings || [];
                const hf = data.headers.anomalies || [];
                const allF = [...df, ...hf];

                if (allF.length === 0) {
                    findingsList.innerHTML = '<li class="finding-item" style="border-color: var(--accent-green); background: rgba(16,185,129,0.08); color: #a7f3d0;">No domain anomalies or spoofing indicators detected.</li>';
                } else {
                    allF.forEach(f => {
                        findingsList.innerHTML += `<li class="finding-item">${f}</li>`;
                    });
                }

                // Render URL Table
                const tbody = document.getElementById("urlTableBody");
                tbody.innerHTML = "";
                const urls = data.url_analysis.urls_details || [];
                if (urls.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="color: var(--text-muted);">No URLs found in email body.</td></tr>';
                } else {
                    urls.forEach(u => {
                        const flag = u.is_suspicious 
                            ? `<span style="color: var(--accent-red);">${u.suspicious_reasons.join(", ") || "Suspicious"}</span>` 
                            : `<span style="color: var(--accent-green);">Clean</span>`;
                        tbody.innerHTML += `<tr><td>${u.url}</td><td>${u.domain}</td><td>${flag}</td></tr>`;
                    });
                }

            } catch (err) {
                alert("Error connecting to Security Engine API: " + err);
            }
        }

        // Run initial analysis on load
        window.onload = runAnalysis;
    </script>
</body>
</html>"""


if __name__ == "__main__":
    print("=" * 70)
    print(" Starting MailTrace-AI Security Dashboard Server (Member 4)...")
    print(" Web UI Available at: http://127.0.0.1:8000")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=8000)
