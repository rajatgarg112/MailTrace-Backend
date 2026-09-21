# Team Ownership & Responsibility Specification

## 1. Master Ownership Matrix

The MailTrace-AI project is developed by a **6-member team** operating across **2 GitHub repositories** and **4 permanent branches**.

| Member | Primary Role | Repository | Permanent Branch | Primary Subdirectory | Integration Deliverable |
|---|---|---|---|---|---|
| **Member 1** | Frontend Developer | `MailTrace-AI-Frontend` | `main` | Root frontend repository | React User & Security Dashboards |
| **Member 2** | Core Backend Engineer | `MailTrace-AI-Backend` | `main` | `app/` | FastAPI API, Orchestrator, Risk Engine |
| **Member 3** | ML / AI Engineer | `MailTrace-AI-Backend` | `ml` | `ml/` | NLP, BEC & Phishing Inference Engine |
| **Member 4** | Cyber Security Analyst | `MailTrace-AI-Backend` | `security` | `security/header_analysis/`, `authentication/`, `domain_analysis/`, `url_analysis/`, `relay_analysis/` | SPF/DKIM/DMARC, Domain & URL Analyzers |
| **Member 5** | Database & Data Engineer | `MailTrace-AI-Backend` | `main` | `database/` | SQLAlchemy Schemas, Alembic Migrations, Seed Data |
| **Member 6** | Forensics & Infrastructure | `MailTrace-AI-Backend` | `security` | `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/` | Evidence Logger, Timeline Engine, Geo Mapping |

---

## 2. Detailed Member Responsibilities

### Member 1 — Frontend Developer
- **Repository**: `MailTrace-AI-Frontend` (`main`)
- **Key Responsibilities**:
  - Build and maintain the Fono User Webmail Interface and Security Analyst Dashboard.
  - Integrate with Backend REST APIs (`/api/emails`, `/api/quarantine`, etc.).
  - Render risk score gauges, threat warning banners, forensic timelines, and quarantine action buttons.
  - Implement responsive loading, error states, and token authentication.
- **Strict Boundary**: Frontend does **not** calculate risk scores or compute classification verdicts locally.

### Member 2 — Core Backend Engineer
- **Repository**: `MailTrace-AI-Backend` (`main`)
- **Key Responsibilities**:
  - Design and maintain FastAPI endpoints and Pydantic schemas.
  - Build the Gateway Orchestrator that coordinates parallel execution of `security` and `ml` components.
  - Develop the Correlation Engine, Risk Calculation Engine, and Delivery Policy Engine.
  - Expose clean JSON responses to the Frontend.

### Member 3 — ML / AI Engineer
- **Repository**: `MailTrace-AI-Backend` (`ml`)
- **Key Responsibilities**:
  - Design NLP text extraction, cleaning, and vectorization pipelines.
  - Train and evaluate classifiers for Phishing, Business Email Compromise (BEC), and Urgency/Scam detection.
  - Build a unified model inference wrapper returning standardized JSON predictions and confidence scores.

### Member 4 — Cyber Security Analyst
- **Repository**: `MailTrace-AI-Backend` (`security`)
- **Key Responsibilities**:
  - Implement SPF, DKIM, and DMARC verification modules.
  - Build sender lookalike domain, typosquatting, display name spoofing, and suspicious TLD analyzers.
  - Extract and inspect URLs for redirect chains, shorteners, and obfuscated domain names.
  - Parse `Received:` header hops to detect relay anomalies.

### Member 5 — Database & Data Engineer
- **Repository**: `MailTrace-AI-Backend` (`main`)
- **Key Responsibilities**:
  - Design normalized relational database schemas for users, emails, findings, ML predictions, policy decisions, and forensic records.
  - Maintain SQLAlchemy ORM models, session management, and Alembic database migrations.
  - Build realistic demo seed data generators for hackathon/presentation scenarios.
- **Strict Boundary**: Database code is co-located on `main` in `database/`. There is no separate database repository or branch.

### Member 6 — Forensics & Geo/Infrastructure Engineer
- **Repository**: `MailTrace-AI-Backend` (`security`)
- **Key Responsibilities**:
  - Implement SHA-256 raw email evidence preservation and cryptographic hashing.
  - Build step-by-step forensic investigation timeline tracking (`Ingestion -> Auth -> Domain -> ML -> Policy -> Decision`).
  - Extract relay IP context to provide approximate ASN, ISP, and geographic region mapping.
- **Strict Boundary**: Geolocation must be explicitly documented as **approximate network infrastructure context**, never as definitive physical attacker attribution.

---

## 3. Shared `security` Branch Management (Member 4 & Member 6)

Members 4 and 6 collaborate on `MailTrace-AI-Backend` (`security`). To prevent git merge conflicts, strict folder ownership boundaries are maintained:

```text
security/
│
├── header_analysis/       ← Owned exclusively by Member 4
├── authentication/        ← Owned exclusively by Member 4
├── domain_analysis/       ← Owned exclusively by Member 4
├── url_analysis/          ← Owned exclusively by Member 4
├── relay_analysis/        ← Owned exclusively by Member 4
│
├── forensic/              ← Owned exclusively by Member 6
├── evidence/              ← Owned exclusively by Member 6
├── timeline/              ← Owned exclusively by Member 6
└── infrastructure/        ← Owned exclusively by Member 6
```

Changes outside an owner's assigned directory must be coordinated prior to merging.
