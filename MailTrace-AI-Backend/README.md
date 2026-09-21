# MailTrace-AI Backend

## Overview

`MailTrace-AI-Backend` is the authoritative core backend repository for **MailTrace-AI**, containing the API layer, database integration, security feature extraction modules, machine learning inference engines, correlation engine, risk calculator, delivery policy enforcer, and forensic evidence generation.

---

## Repository Branch Structure

This repository uses **3 permanent branches**:

```text
MailTrace-AI-Backend
├── main      (Integrated Core Backend & Database)
├── ml        (Machine Learning & NLP Analysis)
└── security  (Security Analyzers & Forensics)
```

> [!NOTE]
> There is **no separate database branch**. Database modules belong directly in `main` under `database/`.

---

## Permanent Branch Summary

### 1. `main` Branch
- **Owners**: Member 2 (Core Backend) & Member 5 (Database & Data Engineering)
- **Directory**: `app/`, `database/`, `tests/`
- **Responsibilities**:
  - FastAPI web server and routing.
  - Gateway orchestration & pipeline execution.
  - Multi-signal correlation engine & risk score calculation.
  - Delivery policy evaluation.
  - Database schemas, ORM setup, migrations, CRUD queries.
  - Aggregation of structured outputs from `ml` and `security`.

### 2. `ml` Branch
- **Owner**: Member 3 (ML / AI)
- **Directory**: `ml/`
- **Responsibilities**:
  - Email content cleaning & NLP tokenization.
  - Business Email Compromise (BEC) & urgency detection.
  - Behavioral feature extraction.
  - Model training, evaluation, and artifact storage.
  - Standardized inference interface returning prediction, confidence, and model metadata.

### 3. `security` Branch
- **Owners**: Member 4 (Cyber Security) & Member 6 (Forensics & Infrastructure)
- **Directories**:
  - `security/header_analysis/`, `authentication/`, `domain_analysis/`, `url_analysis/`, `relay_analysis/` (Member 4)
  - `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/` (Member 6)
- **Responsibilities**:
  - Sender identity validation, SPF/DKIM/DMARC analysis.
  - Lookalike domain, typosquatting, and display name spoofing checks.
  - URL extraction, un-shortening, and static inspection.
  - Header & relay hop verification.
  - Forensic evidence preservation & step-by-step investigation timeline.
  - Approximate network/infrastructure geolocation (ASN, ISP, Region).

---

## Gateway Orchestrator Workflow

The core integration entrypoint resides on `main`:

```text
process_email(raw_email_payload)
       ↓
Parse & Normalize Payload
       ↓
Preserve Immutable Evidence & Hashes
       ↓
Run Security Analyzers (Member 4 + Member 6)
       ↓
Run ML Content & BEC Analyzers (Member 3)
       ↓
Aggregate Canonical Feature Matrix
       ↓
Assign Security Tags
       ↓
Correlate Signals & Detect Anomalies
       ↓
Calculate Risk Score (0-100) & Confidence
       ↓
Determine Threat Classification (SAFE | SPAM | SUSPICIOUS | MALICIOUS | UNKNOWN)
       ↓
Apply Delivery Policy Action (INBOX | SPAM | WARN | HOLD | QUARANTINE | REJECT)
       ↓
Persist Results & Events to Database (Member 5)
       ↓
Return REST Payload to Frontend (Member 1)
```

---

## Safe Untrusted Content Handling

All submitted emails, headers, links, and attachments are treated as **untrusted**:
- Attachments are never executed directly; static inspection is performed in isolated helpers.
- External threat intelligence requests use bounded timeouts and fail-open/fail-closed policy handling via provider adapters.
- URLs are sanitized before inspection.

---

## Documentation Index

- [ARCHITECTURE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ARCHITECTURE.md)
- [REPOSITORY_STRUCTURE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/REPOSITORY_STRUCTURE.md)
- [TEAM_OWNERSHIP.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/TEAM_OWNERSHIP.md)
- [BRANCH_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/BRANCH_WORKFLOW.md)
- [BACKEND_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/BACKEND_WORKFLOW.md)
- [ML_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ML_WORKFLOW.md)
- [SECURITY_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/SECURITY_WORKFLOW.md)
- [DATABASE_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DATABASE_WORKFLOW.md)
- [FORENSICS_WORKFLOW.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/FORENSICS_WORKFLOW.md)
- [INTEGRATION.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/INTEGRATION.md)
- [API_SPEC.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/API_SPEC.md)
- [ANALYSIS_PIPELINE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/ANALYSIS_PIPELINE.md)
- [SECURITY_FEATURE_SCHEMA.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/SECURITY_FEATURE_SCHEMA.md)
- [DELIVERY_POLICY.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DELIVERY_POLICY.md)
- [THREAT_INTELLIGENCE.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/THREAT_INTELLIGENCE.md)
- [PRIVACY_AND_SAFE_ANALYSIS.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/PRIVACY_AND_SAFE_ANALYSIS.md)
- [EVIDENCE_AND_FORENSICS.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/EVIDENCE_AND_FORENSICS.md)
- [TESTING.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/TESTING.md)
- [DEVELOPMENT_GUIDELINES.md](file:///d:/SIHproject/MailTrace-Backend/MailTrace-AI-Backend/DEVELOPMENT_GUIDELINES.md)
