# Repository Structure & Branch Organization Specification

## 1. Multi-Repository Layout

MailTrace-AI is divided into **2 distinct repositories**:

```text
MAILTRACE-AI
│
├── MailTrace-AI-Frontend (Repo 1)
│   └── main
│
└── MailTrace-AI-Backend (Repo 2)
    ├── main
    ├── ml
    └── security
```

> [!WARNING]
> There is **no separate database repository** and **no permanent database branch**. Database code belongs inside `MailTrace-AI-Backend` on `main`.

---

## 2. `MailTrace-AI-Backend` Folder Map

```text
MailTrace-AI-Backend/
│
├── app/                          # Core Backend Application (main)
│   ├── api/                      # REST API Endpoints & Routers
│   ├── core/                     # Configuration, Security, Logging
│   ├── gateway/                  # Gateway Orchestrator & Pipeline Runner
│   ├── correlation/              # Signal Correlation & Tag Aggregator
│   ├── risk/                     # Risk Score Calculation Engine
│   ├── policy/                   # Delivery Policy Decision Engine
│   └── models/                   # Pydantic Schemas & Data Transfer Objects
│
├── database/                     # Database Subsystem (main)
│   ├── connection.py             # DB Session & Connection Manager
│   ├── base.py                   # SQLAlchemy Base Model Setup
│   ├── models/                   # SQLAlchemy ORM Model Definitions
│   ├── migrations/               # Alembic Migration Scripts
│   ├── seed.py                   # Demo & Prototype Seed Generator
│   └── README.md                 # Database System Specs
│
├── ml/                           # Machine Learning Subsystem (ml)
│   ├── classifiers/              # Phishing, BEC & Spam Classifiers
│   ├── features/                 # NLP & Behavioral Feature Extraction
│   ├── inference/                # Unified Model Inference Interface
│   ├── training/                 # Model Training Scripts & Pipelines
│   ├── artifacts/                # Trained Model Weights & Metadata
│   └── config/                   # ML Hyperparameters & Threshold Configs
│
├── security/                     # Cyber Security Subsystem (security)
│   ├── header_analysis/          # Header Parsing & Anomaly Checks (Member 4)
│   ├── authentication/           # SPF, DKIM, DMARC Evaluator (Member 4)
│   ├── domain_analysis/          # Lookalike, Typosquatting & TLD Checks (Member 4)
│   ├── url_analysis/             # URL Extraction & Static Inspection (Member 4)
│   ├── relay_analysis/           # Received Hop & Relay Verification (Member 4)
│   ├── forensic/                 # Evidence Preservation & Audit Logs (Member 6)
│   ├── evidence/                 # SHA-256 Hash & Payload Capture (Member 6)
│   ├── timeline/                 # Chronological Event Tracker (Member 6)
│   └── infrastructure/           # ASN, ISP & Approx Geo Mapping (Member 6)
│
├── tests/                        # Comprehensive Test Suites
│   ├── unit/                     # Unit Tests per Branch Module
│   ├── integration/              # Pipeline & API Integration Tests
│   └── fixtures/                 # Sample Raw Email Test Payloads
│
├── .env.example                  # Environment Variable Blueprint
├── requirements.txt              # Core Python Dependencies
└── README.md                     # Root Backend Documentation
```

---

## 3. Permanent Branch Responsibility Summary

### `main` Branch
- **Contents**: `app/`, `database/`, `tests/`
- **Purpose**: Production-ready integrated backend, API routing, database schema management, and orchestrator execution.

### `ml` Branch
- **Contents**: `ml/`
- **Purpose**: Development of machine learning models, feature extraction pipelines, inference adapters, and training code.

### `security` Branch
- **Contents**: `security/`
- **Purpose**: Development of static security analyzers, email authentication parsers, forensic evidence loggers, and network infrastructure tools.
