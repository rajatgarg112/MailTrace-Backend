# Database Architecture & Data Engineering Specification

## 1. Workstream Overview

- **Primary Owner**: Member 5 (Database & Data Engineer)
- **Collaborator**: Member 2 (Core Backend Engineer)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `main`
- **Core Folder Location**: `database/`

> [!IMPORTANT]
> The database subsystem is co-located directly inside `MailTrace-AI-Backend` on `main`. There is **no standalone database repository** and **no database branch**.

---

## 2. Directory Structure inside `database/`

```text
database/
├── connection.py               # SQLAlchemy Engine & Session Factory
├── base.py                     # Declarative Base Class & Timestamp Mixins
├── models/                     # SQLAlchemy ORM Models
│   ├── user.py                 # Users & Auth Accounts
│   ├── mailbox.py              # Mailboxes & Ingestion Outlets
│   ├── email.py                # Ingested Email Metadata
│   ├── analysis_run.py         # Gateway Pipeline Execution Records
│   ├── finding.py              # Security & ML Findings
│   ├── tag.py                  # Assigned Security Tags
│   ├── policy_decision.py      # Final Policy Decisions & Actions
│   ├── evidence.py             # Cryptographic Evidence Hashes
│   └── forensic_case.py        # Investigation Timeline & Cases
│
├── migrations/                 # Alembic Database Migration Scripts
│   ├── env.py                  # Alembic Environment Config
│   └── versions/               # Migration Revisions
│
├── seed.py                     # Demo Dataset & Seed Generator
└── README.md                   # Database Setup & Schema Guide
```

---

## 3. Entity-Relationship Schema Overview

```text
  ┌───────────┐         ┌───────────┐         ┌───────────┐
  │   users   │ 1 ──── N│ mailboxes │ 1 ──── N│  emails   │
  └───────────┘         └───────────┘         └─────┬─────┘
                                                    │ 1
                                                    │
                                                    │ 1
                                             ┌──────┴──────┐
                                             │ analysis_   │
                                             │    runs     │
                                             └──────┬──────┘
                                                    │ 1
       ┌────────────────┬────────────────┬──────────┼────────────────┬────────────────┐
       │ N              │ N              │ N        │ 1              │ 1              │ 1
┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐ ┌─┴──────────┐  ┌──┴───────────┐ ┌──┴───────────┐
│  findings   │  │security_tags│  │ ml_results  │ │  policy_   │  │   evidence   │ │ forensic_   │
│             │  │             │  │             │ │ decisions  │  │   records    │ │   cases     │
└─────────────┘  └─────────────┘  └─────────────┘ └────────────┘  ──────────────┘ └─────────────┘
```

---

## 4. Key Relational Tables

### 1. `emails`
- `id` (String UUID, Primary Key)
- `mailbox_id` (Foreign Key -> `mailboxes.id`)
- `sender` (String)
- `subject` (String)
- `received_at` (DateTime)
- `raw_content_path` (String)

### 2. `analysis_runs`
- `id` (String UUID, Primary Key)
- `email_id` (Foreign Key -> `emails.id`)
- `status` (Enum: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`)
- `started_at` (DateTime)
- `completed_at` (DateTime)

### 3. `policy_decisions`
- `id` (String UUID, Primary Key)
- `analysis_run_id` (Foreign Key -> `analysis_runs.id`)
- `risk_score` (Integer, $0-100$)
- `threat_classification` (Enum: `SAFE`, `SPAM`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`)
- `delivery_action` (Enum: `INBOX`, `SPAM`, `WARN`, `HOLD`, `QUARANTINE`, `REJECT`)
- `enforced_at` (DateTime)

### 4. `evidence_records`
- `id` (String UUID, Primary Key)
- `email_id` (Foreign Key -> `emails.id`)
- `raw_sha256` (String)
- `headers_sha256` (String)
- `body_sha256` (String)
- `storage_uri` (String)

---

## 5. Engineering Constraints & Rules

1. **Strict Access Routing**: The database engine is accessible **only** to backend code running inside FastAPI or background tasks. The frontend connects exclusively via HTTP REST endpoints.
2. **Migrations Strategy**: Any schema modification must be introduced through a documented Alembic revision in `database/migrations/versions/`.
3. **Hackathon Seed Support**: `database/seed.py` must populate pre-configured safe, spam, suspicious, and quarantine email test cases for frontend demo scenarios.
