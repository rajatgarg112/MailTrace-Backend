# System Architecture Specification

## 1. Architectural Overview

MailTrace-AI follows a decoupled, modular architecture designed for SIH 2026 Problem Statement 26106. The platform is organized into two primary GitHub repositories:

1. **`MailTrace-AI-Frontend`**: React + Vite application handling user and security analyst interfaces.
2. **`MailTrace-AI-Backend`**: FastAPI application orchestrating analysis, database operations, security inspection, and machine learning inference.

```text
                    ┌──────────────────────────────┐
                    │   MailTrace-AI Frontend      │
                    │   (React + Vite)             │
                    └──────────────┬───────────────┘
                                   │ HTTPS REST API
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
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │ Backend Database    │
                        │ (SQLite/PostgreSQL) │
                        └─────────────────────┘
```

---

## 2. Core Architectural Layers

### A. Presentation Layer (`MailTrace-AI-Frontend`)
- **Technology**: React, Vite, CSS Modules / Vanilla CSS.
- **Responsibilities**: Renders User Webmail Dashboard, Security Analyst Console, Risk Badges, Quarantine Manager, and Forensic Timeline view.
- **Rule**: Purely presentation. Does not run risk logic or override backend policy actions.

### B. Gateway & API Layer (`MailTrace-AI-Backend` → `main`)
- **Technology**: Python 3.11+, FastAPI, Pydantic v2.
- **Responsibilities**: Exposes REST endpoints, validates untrusted input, orchestrates pipeline stages, invokes analyzer components, correlates signals, calculates risk, applies delivery policies, and persists records.

### C. Security Analysis Layer (`MailTrace-AI-Backend` → `security`)
- **Technology**: Python security utilities, DNS lookup engines, header parsers.
- **Responsibilities**: SPF/DKIM/DMARC evaluation, sender lookalike domain analysis, URL extraction and unshortening, relay hop calculation, forensic evidence capture, and approximate IP geolocation mapping.

### D. Machine Learning Layer (`MailTrace-AI-Backend` → `ml`)
- **Technology**: PyTorch / scikit-learn / HuggingFace Transformers, NLTK / spaCy.
- **Responsibilities**: Email body & subject cleaning, NLP vectorization, BEC / urgency detection, impersonation scoring, and behavioral ML inference.

### E. Database Layer (`MailTrace-AI-Backend` → `main`)
- **Technology**: SQLAlchemy ORM, Alembic migrations, SQLite (development) / PostgreSQL (production).
- **Responsibilities**: Relational storage for users, mailboxes, emails, analysis runs, security findings, ML predictions, policy decisions, evidence logs, and forensic cases.

---

## 3. Data Flow Sequence

```text
Frontend                    FastAPI Gateway               Security/ML Modules             Database
   │                               │                              │                          │
   │─── POST /api/emails ─────────>│                              │                          │
   │    (Ingest Raw Email)         │─── Extract Raw Evidence ────>│                          │
   │                               │    & Compute SHA-256         │                          │
   │                               │                              │                          │
   │                               │─── Run Security Checks ─────>│                          │
   │                               │    (Auth, Headers, Domains)  │                          │
   │                               │                              │                          │
   │                               │─── Run ML Checks ───────────>│                          │
   │                               │    (NLP, BEC, Sentiment)     │                          │
   │                               │                              │                          │
   │                               │<── Return Findings Matrix ───│                          │
   │                               │                              │                          │
   │                               │─── Correlate Signals ────────│                          │
   │                               │─── Calculate Risk (0-100) ───│                          │
   │                               │─── Apply Delivery Policy ────│                          │
   │                               │                              │                          │
   │                               │─── Persist Decision & Logs ────────────────────────────>│
   │                               │                                                         │
   │<── 201 Created (Result JSON) ─│                                                         │
```

---

## 4. Architectural Rules & Constraints

1. **Single Source of Truth**: The core backend (`main`) is the single authoritative decision engine.
2. **Stateless Gateway**: Analysis modules operate as pure functions or stateless services accepting canonical payloads and returning structured JSON outputs.
3. **Database Prohibitions**: Neither the Frontend nor external tools connect directly to the database. All interactions route through FastAPI endpoints.
4. **Provider Adapter Isolation**: External threat intelligence services (e.g., VirusTotal, AbuseIPDB) must be wrapped in timeout-bounded adapters so that external network failures do not block the pipeline.
