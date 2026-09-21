# MailTrace-AI — Two-Repository Project Specification

## Purpose

MailTrace-AI is an AI-powered **pre-delivery email threat detection, geolocation and forensic intelligence platform** for SIH 2026 Problem Statement 26106.

The project is intentionally split into **two GitHub repositories**:

1. `MailTrace-AI-Frontend`
2. `MailTrace-AI-Backend`

The old combined repository remains an archive/reference and is not the active development structure.

---

## Final Git Structure

```text
MAILTRACE-AI
│
├── MailTrace-AI-Frontend
│   └── main
│
└── MailTrace-AI-Backend
    ├── main
    ├── ml
    └── security
```

There is **no separate database repository**. The database is backend-owned.

| Repository | Branch | Responsibility |
|---|---|---|
| Frontend | `main` | React + Vite user/security dashboards and API integration |
| Backend | `main` | FastAPI API, database, gateway orchestration, correlation, risk/policy, delivery |
| Backend | `ml` | ML/NLP feature extraction, inference, training/evaluation utilities |
| Backend | `security` | Header/authentication, sender/domain, URL, attachment, QR, relay, TI and forensic analysis |

---

## Product Goal

MailTrace-AI is designed to inspect an incoming email **before normal user delivery**, combine independent security signals, calculate a risk decision, and apply a delivery policy.

```text
Incoming Email
      ↓
MailTrace Gateway
      ↓
Evidence Capture + Normalization
      ↓
Parallel Security Analysis
      ↓
Feature Extraction
      ↓
Security Tags
      ↓
Risk / Correlation Engine
      ↓
Classification + Confidence
      ↓
Delivery Policy
      ├── Inbox
      ├── Spam
      ├── Warning / Hold
      └── Quarantine
      ↓
Backend API
      ↓
Frontend
```

The current prototype may use its own MailTrace webmail/demo interface. Direct control of Gmail's internal delivery engine is **not** claimed. Gmail/Google Workspace integration is a future integration phase using official APIs/OAuth/Add-ons.

---

## High-Level Architecture

```text
                    ┌──────────────────────────────┐
                    │   MailTrace-AI Frontend      │
                    │                              │
                    │ React + Vite                 │
                    │ User Dashboard               │
                    │ Security Dashboard           │
                    └──────────────┬───────────────┘
                                   │ HTTPS / REST
                                   ▼
                    ┌──────────────────────────────┐
                    │   MailTrace-AI Backend       │
                    │                              │
                    │ FastAPI API Layer             │
                    │ Gateway / Orchestrator        │
                    │ Risk + Policy Engine          │
                    └──────────────┬───────────────┘
                                   │
                ┌──────────────────┼──────────────────┐
                ▼                  ▼                  ▼
       ┌────────────────┐ ┌────────────────┐ ┌─────────────────┐
       │ Security Branch│ │ ML Branch      │ │ Backend Services │
       │ `security`     │ │ `ml`           │ │ `main`           │
       │                │ │                │ │                 │
       │ Headers/Auth   │ │ NLP/BEC        │ │ Correlation     │
       │ Domain/URL     │ │ Features       │ │ Risk Engine     │
       │ Files/QR       │ │ Inference      │ │ Delivery Policy │
       │ TI/Forensics   │ │ Evaluation     │ │ API + DB        │
       └───────┬────────┘ └───────┬────────┘ └────────┬────────┘
               └──────────────────┬┴──────────────────┘
                                  ▼
                         ┌─────────────────┐
                         │ Backend Database│
                         │ SQLite/MySQL    │
                         └─────────────────┘
```

---

## Core Security Pipeline

```text
1. Email Ingestion
2. Evidence Preservation
3. Parsing / Normalization
4. Sender + Identity Analysis
5. Email Authentication Analysis
6. Domain Analysis
7. Header / IP / Relay Analysis
8. URL / Link Analysis
9. Attachment Analysis
10. Image / QR Analysis
11. Content / NLP Analysis
12. BEC / Impersonation Analysis
13. Behavioral + User Context Analysis
14. Threat Intelligence Correlation
15. Security Tag Generation
16. Risk Calculation
17. Threat Classification
18. Delivery Policy
19. Evidence / Event Persistence
20. Frontend Presentation
```

The analysis stages may run in parallel where safe and practical. The gateway/orchestrator is responsible for combining their structured outputs.

---

## Classification vs Delivery Action

These are separate concepts.

### Threat Classification

```text
SAFE
SPAM
SUSPICIOUS
MALICIOUS
UNKNOWN
```

### Delivery Action

```text
INBOX
SPAM
WARN
HOLD
QUARANTINE
REJECT
```

Example:

```text
Classification = PHISHING
Risk = 91
Action = QUARANTINE
```

Do not infer that every `SPAM` item is malicious.

---

## Spam and Security Gateway Partitions

### Spam

```text
Spam
├── Marketing
├── Education
├── Social / Notifications
├── Bulk
├── Scam
├── Fraud
├── Phishing
├── Suspicious
└── Other
```

### Security Gateway / Quarantine

```text
Security Gateway
├── Malicious
├── High-Risk Phishing
├── Malware
├── BEC / Fraud
└── Other High Risk
```

Safe/bulk mail is not automatically malicious. Routing is based on the final policy decision.

---

## Harmful Email Protection

For ordinary spam, the user may view the message according to policy.

For suspicious mail, the UI should show a clear warning and controlled access.

For malicious/high-risk quarantined mail:

- do not expose the original body by default
- do not expose or execute dangerous attachments
- do not automatically open suspicious links
- show a sanitized security report
- show security tags, findings, risk and evidence
- provide policy-controlled actions such as delete/report/release

---

## Unknown Handling

`UNKNOWN` must not silently become `SAFE`.

Recommended policy:

```text
UNKNOWN → HOLD / policy-defined review
```

The exact action can be configured, but unknown security state must remain visible.

---

## Privacy Principle

> **Analyze for security, not for curiosity.**

Raw email body, images and attachments may be processed transiently when required for security analysis, but should not be unnecessarily persisted, logged or displayed.

Prefer storing:

- normalized metadata
- security-derived features
- security tags
- risk/classification results
- hashes
- evidence references
- audit events

Avoid storing unrelated personal information merely because it appears in an email.

---

## Geolocation Rule

IP geolocation represents **approximate network/infrastructure context**.

It must not be presented as proof of:

- exact physical attacker location
- sender identity
- criminal attribution

Use wording such as:

> Approximate infrastructure location derived from available network/header evidence.

---

## External Intelligence

Threat-intelligence providers are **signals**, not the complete decision engine.

The system should correlate:

- sender reputation
- domain reputation
- IP reputation
- URL reputation
- attachment reputation
- phishing/malware/abuse matches
- historical and contextual signals

A `UNKNOWN` reputation is not equivalent to `SAFE`.

---

## ML Rule

The project may use ML/NLP models for phishing, spam, BEC, impersonation and related signals.

Do not publish fabricated accuracy, precision, recall, F1 or other evaluation metrics. Metrics should only be reported after a documented dataset, train/test split and reproducible evaluation.

---

## Database Ownership

The database belongs to the Backend repository.

```text
Frontend → Backend API → Database
```

The frontend must never connect directly to SQLite/MySQL.

---

## Core Data Entities

Initial entities include:

```text
users
mailboxes
emails
delivery_events
analysis_runs
security_findings
security_tags
ml_results
policy_decisions
evidence
forensic_cases
```

The schema may evolve through documented migrations.

---

## Development Principle

Keep the SIH prototype:

- practical
- modular
- explainable
- privacy-aware
- safe for untrusted content
- reproducible
- demo-ready

Avoid unnecessary microservices or over-engineering.
