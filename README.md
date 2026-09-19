# MailTrace-AI — New Repository Structure

## Purpose
MailTrace-AI is an AI-powered email threat detection, geolocation and forensic intelligence platform for SIH 2026 Problem Statement 26106.

The project is split into **two GitHub repositories**:

1. `MailTrace-AI-Frontend`
2. `MailTrace-AI-Backend`

The old combined repository is kept untouched as an archive/reference.

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

### Repository responsibilities

| Repository | Branch | Responsibility |
|---|---|---|
| Frontend | `main` | Fono User Dashboard + Security Dashboard |
| Backend | `main` | FastAPI API, database integration, common services, authentication, analysis orchestration |
| Backend | `ml` | ML models, feature extraction, model inference/training utilities |
| Backend | `security` | Security/forensic analysis, header analysis, URL/domain checks, relay-chain analysis, evidence generation |

There is **no separate database repository** and **no database branch**.

---

## High-Level Architecture

```text
                    ┌─────────────────────────┐
                    │   MailTrace-AI Frontend │
                    │                         │
                    │  Fono User Dashboard    │
                    │  Security Dashboard     │
                    └────────────┬────────────┘
                                 │ HTTP/REST API
                                 ▼
                    ┌─────────────────────────┐
                    │ MailTrace-AI Backend    │
                    │                         │
                    │ FastAPI / API Layer     │
                    │ Core Services            │
                    │ Analysis Orchestrator   │
                    └───────┬─────────┬───────┘
                            │         │
                  ┌─────────┘         └──────────┐
                  ▼                              ▼
        ┌──────────────────┐           ┌──────────────────┐
        │ Security Module  │           │ ML Module        │
        │ `security`       │           │ `ml`             │
        └────────┬─────────┘           └────────┬─────────┘
                 │                              │
                 └──────────────┬───────────────┘
                                ▼
                     ┌────────────────────┐
                     │ Backend `main`     │
                     │ Correlation/Risk   │
                     │ Policy/Delivery    │
                     └─────────┬──────────┘
                               ▼
                     ┌────────────────────┐
                     │     Database       │
                     │ Backend-owned      │
                     └────────────────────┘
```

---

## Database Rule

The database belongs to the **Backend repository**.

Recommended location:

```text
MailTrace-AI-Backend/
├── app/
├── database/
│   ├── connection.py
│   ├── migrations/
│   ├── seed.py
│   └── README.md
├── tests/
├── requirements.txt
└── README.md
```

The frontend must never connect directly to the database.

```text
Frontend → Backend API → Database
```

The backend is responsible for database access, validation and persistence.

---

## Core Data Entities

The initial data model contains:

- `users`
- `mailboxes`
- `emails`
- `delivery_events`
- `analysis_runs`
- `security_findings`
- `security_tags`
- `ml_results`
- `policy_decisions`
- `evidence`
- `forensic_cases`

The exact schema can evolve as implementation progresses.

---

## Analysis Flow

```text
Incoming Email
      ↓
Evidence Capture
      ↓
Email Parsing & Normalization
      ↓
 ┌────┴─────────────┐
 ↓                  ↓
Security Analysis   ML Analysis
 ↓                  ↓
 └───────┬──────────┘
         ↓
Correlation
         ↓
Risk Calculation
         ↓
Threat Classification
         ↓
Delivery Policy
         ↓
Database Persistence
         ↓
Frontend Dashboard
```

Suggested classifications:

```text
SAFE
SPAM
SUSPICIOUS
MALICIOUS
UNKNOWN
```

Suggested delivery actions:

```text
DELIVER
SPAM
WARN
QUARANTINE
REJECT
HOLD
```

Classification and delivery action are separate concepts.

---

## Important GeoLocation Rule

GeoLocation should be represented as **approximate network/infrastructure context**.

It should not be presented as proof of:

- a person's exact physical location
- a sender's identity
- criminal attribution

Example wording:

> Approximate infrastructure location derived from available network/header evidence.

---

## Branch Workflow

### Backend `main`

Owns:

- FastAPI application
- API routes
- database connection
- database models
- shared schemas
- authentication
- analysis orchestration
- correlation
- risk calculation
- policy decisions
- common services

### Backend `ml`

Owns:

- feature extraction
- ML classifiers
- model inference
- training utilities
- model artifacts
- ML-specific tests

### Backend `security`

Owns:

- email header analysis
- SPF/DKIM/DMARC checks
- domain/lookalike analysis
- URL analysis
- relay-chain analysis
- suspicious infrastructure analysis
- forensic evidence generation
- security-specific tests

Stable work from `ml` and `security` should eventually be integrated into backend `main`.

---

## Frontend `main`

Contains both dashboards:

### Fono User Dashboard

Typical features:

- inbox
- threat status
- warnings
- quarantine
- safe email view
- email details
- basic security explanation

### Security Dashboard

Typical features:

- investigation queue
- threat overview
- risk level
- security findings
- ML results
- evidence
- timeline
- approximate infrastructure location
- forensic case details

The frontend displays backend results. It should not independently decide whether an email is malicious.

---

## Development Principle

Keep the project practical and demo-ready.

Prefer:

- simple architecture
- clear APIs
- modular code
- explainable results
- reproducible testing
- safe demo data
- clear separation of responsibilities

Avoid unnecessary microservices or over-engineering for the SIH prototype.
