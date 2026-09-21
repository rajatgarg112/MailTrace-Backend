# MailTrace-AI — Pre-Delivery Email Threat Detection Platform

## Overview

**MailTrace-AI** is an AI-powered pre-delivery email threat detection, geolocation, security analysis, and forensic intelligence platform built for **SIH 2026 Problem Statement 26106**.

MailTrace-AI analyzes incoming email messages **before normal user inbox delivery**. It combines multi-layer email security checks, natural language understanding, machine learning threat detection, network infrastructure forensics, and customizable policy controls to make authoritative security decisions.

---

## 1. System Architecture & Repository Structure

MailTrace-AI is structured into **2 separate GitHub repositories**:

```text
MAILTRACE-AI
│
├── MailTrace-AI-Frontend (Repository 1)
│   └── main
│
└── MailTrace-AI-Backend (Repository 2)
    ├── main
    ├── ml
    └── security
```

> [!IMPORTANT]
> There is **no separate database repository** and **no permanent database branch**. The database belongs to the backend (`MailTrace-AI-Backend/main`).

### Permanent Branch Map & Responsibilities

| Repository | Branch | Primary Responsibility | Primary Owners |
|---|---|---|---|
| `MailTrace-AI-Frontend` | `main` | User & Security Dashboards, Webmail interface, REST integration | Member 1 |
| `MailTrace-AI-Backend` | `main` | FastAPI REST API, Gateway Orchestration, Correlation, Risk Engine, Delivery Policy, Database | Member 2 & Member 5 |
| `MailTrace-AI-Backend` | `ml` | Content/NLP analysis, BEC/Impersonation detection, Behavioral ML inference, Model training | Member 3 |
| `MailTrace-AI-Backend` | `security` | Headers, Authentication (SPF/DKIM/DMARC), Domains, URLs, Relays, Attachments, QR, Forensics, Geo | Member 4 & Member 6 |

---

## 2. Six-Member Team Ownership Matrix

| Member | Primary Role | Repository | Permanent Branch | Directory Boundaries | Key Deliverables |
|---|---|---|---|---|---|
| **Member 1** | Frontend Developer | `MailTrace-AI-Frontend` | `main` | Root frontend codebase | User & Security Dashboards, Webmail interface, Risk & Quarantine UI |
| **Member 2** | Core Backend Engineer | `MailTrace-AI-Backend` | `main` | `app/` | FastAPI REST API, Gateway Orchestrator, Correlation & Risk Engine |
| **Member 3** | ML / AI Engineer | `MailTrace-AI-Backend` | `ml` | `ml/` | NLP feature extraction, BEC detectors, ML inference engine |
| **Member 4** | Cyber Security Analyst | `MailTrace-AI-Backend` | `security` | `security/header_analysis/`, `authentication/`, `domain_analysis/`, `url_analysis/`, `relay_analysis/` | SPF/DKIM/DMARC, lookalike domain detection, URL static inspection |
| **Member 5** | Database & Data Engineer | `MailTrace-AI-Backend` | `main` | `database/` | Database schemas, ORM models, migrations, seed datasets |
| **Member 6** | Forensics & Infrastructure | `MailTrace-AI-Backend` | `security` | `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/` | Forensic evidence preservation, audit timelines, approximate geo-infrastructure |

---

## 3. High-Level Integration Topology

```text
                    ┌──────────────────────────────┐
                    │   MailTrace-AI Frontend      │
                    │   (React + Vite Dashboard)   │
                    └──────────────┬───────────────┘
                                   │ HTTPS / REST API
                                   ▼
                    ┌──────────────────────────────┐
                    │   MailTrace-AI Backend       │
                    │   FastAPI API / Gateway      │
                    └──────────────┬───────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ Security Branch  │      │ ML Branch        │      │ Core Services    │
│ (`security`)     │      │ (`ml`)           │      │ (`main`)         │
│ Headers/Auth     │      │ NLP / BEC        │      │ Correlation      │
│ Domain / URL     │      │ Behavioral ML    │      │ Risk Engine      │
│ Forensics / Geo  │      │ Inference        │      │ Delivery Policy  │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │ Backend Database    │
                        │ (SQLite / PostgreSQL│
                        └─────────────────────┘
```

---

## 4. Fundamental Core Workflow

```text
Incoming Raw Email
      ↓
Gateway Ingestion & Normalization
      ↓
Evidence & Hash Preservation
      ↓
Parallel Analysis Execution
┌──────────────────────────┴──────────────────────────┐
│                                                     │
▼                                                     ▼
Security Analyzers (`security`)             ML Analyzers (`ml`)
(Auth, Headers, Domains, URLs)             (NLP, BEC, Phishing, Sentiment)
│                                                     │
└──────────────────────────┬──────────────────────────┘
      ↓
Canonical Feature Matrix Aggregation
      ↓
Security Tag Assignment
      ↓
Multi-Signal Correlation Engine
      ↓
Explainable Risk Score Calculation (0 - 100)
      ↓
Threat Classification (SAFE | SPAM | SUSPICIOUS | MALICIOUS | UNKNOWN)
      ↓
Delivery Policy Enforcement (INBOX | SPAM | WARN | HOLD | QUARANTINE | REJECT)
      ↓
Database & Forensic Event Persistence
      ↓
REST API Response → Frontend Presentation
```

---

## 5. Key Architecture Principles

1. **Pre-Delivery Analysis**: Email threat decision is determined before user delivery.
2. **Classification vs. Delivery Action**:
   - Threat Classifications: `SAFE`, `SPAM`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`
   - Delivery Actions: `INBOX`, `SPAM`, `WARN`, `HOLD`, `QUARANTINE`, `REJECT`
   - *Example*: `Classification = MALICIOUS`, `Risk Score = 94`, `Action = QUARANTINE`.
3. **`UNKNOWN ≠ SAFE`**: Missing information or external API failures result in `UNKNOWN` visibility, never a silent `SAFE` override.
4. **Approximate Geolocation**: IP geolocation represents network infrastructure context (ISP/ASN), not physical proof of criminal attribution.
5. **Frontend Non-Authority**: Frontend strictly displays security verdicts computed by Backend `main`; it never calculates risk scores or overrides actions.

---

## 6. Project Documentation Index

Detailed specifications are located inside `MailTrace-AI-Backend/`:

- [ARCHITECTURE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ARCHITECTURE.md) — System architecture, module topology, REST flow.
- [REPOSITORY_STRUCTURE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/REPOSITORY_STRUCTURE.md) — Directory trees & branch ownership map.
- [TEAM_OWNERSHIP.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/TEAM_OWNERSHIP.md) — Detailed 6-member responsibility split.
- [BRANCH_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/BRANCH_WORKFLOW.md) — Git workflow, branch strategy & PR process.
- [BACKEND_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/BACKEND_WORKFLOW.md) — Core backend development guide (Member 2 & 5).
- [ML_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ML_WORKFLOW.md) — Machine learning model pipeline guide (Member 3).
- [SECURITY_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/SECURITY_WORKFLOW.md) — Security analyzers & authentication checks (Member 4).
- [DATABASE_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DATABASE_WORKFLOW.md) — Database schema & migration guide (Member 5).
- [FORENSICS_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/FORENSICS_WORKFLOW.md) — Forensic evidence & geo-infrastructure guide (Member 6).
- [INTEGRATION.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/INTEGRATION.md) — Cross-branch integration standards & JSON payloads.
- [API_SPEC.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/API_SPEC.md) — REST API endpoints & payload definitions.
- [ANALYSIS_PIPELINE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ANALYSIS_PIPELINE.md) — 20-stage email analysis pipeline details.
- [SECURITY_FEATURE_SCHEMA.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/SECURITY_FEATURE_SCHEMA.md) — Canonical feature data contracts.
- [DELIVERY_POLICY.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DELIVERY_POLICY.md) — Risk calculation & policy enforcement rules.
- [EVIDENCE_AND_FORENSICS.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/EVIDENCE_AND_FORENSICS.md) — Forensic evidence structures & timeline logs.
- [DEVELOPMENT_GUIDELINES.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DEVELOPMENT_GUIDELINES.md) — Code style, testing, and pull request conventions.
