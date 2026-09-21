# Core Backend Workflow & Development Specification

## 1. Workstream Overview

- **Primary Owners**: Member 2 (Core Backend) & Member 5 (Database & Data Engineering)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `main`
- **Core Folder Location**: `app/` and `database/`

The Core Backend serves as the integration orchestrator for MailTrace-AI. It exposes REST API endpoints to the frontend, manages the end-to-end email analysis pipeline, collects signals from `ml` and `security` branches, executes the Risk Engine, applies Delivery Policies, and persists decisions to the database.

---

## 2. Component Architecture inside `app/`

```text
app/
├── main.py                     # FastAPI Application Initialization & Middleware
├── config.py                   # App Configuration & Environment Settings
├── api/                        # REST API Router Endpoints
│   ├── router.py               # Main API Router Registration
│   ├── health.py               # Health & System Status Endpoints
│   ├── emails.py               # Email Ingestion & Detail Retrieval
│   ├── analysis.py             # Pipeline Trigger & Status Endpoints
│   └── quarantine.py           # Quarantine Management & Release Endpoints
│
├── core/                       # Shared Utilities & Middleware
│   ├── logging.py              # Structured Logger Config
│   └── security.py             # API Key / JWT Authentication Handlers
│
├── gateway/                    # Gateway Pipeline Orchestration
│   ├── orchestrator.py         # Parallel Pipeline Runner
│   ├── normalizer.py           # Raw MIME / JSON Email Normalizer
│   └── evidence_preserver.py   # Immutable Evidence & Hashing Logic
│
├── correlation/                # Signal Aggregation & Tagging
│   ├── aggregator.py           # Feature Matrix Synthesizer
│   └── tagger.py               # Normalized Security Tag Assignment
│
├── risk/                       # Risk Engine
│   ├── calculator.py           # Multi-Signal Weighted Risk Calculator
│   └── classification.py       # Threat Classifier (SAFE, SPAM, SUSPICIOUS, etc.)
│
├── policy/                     # Delivery Policy Engine
│   └── enforcer.py             # Delivery Action Mapper (INBOX, QUARANTINE, etc.)
│
└── models/                     # Pydantic Request / Response Schemas
    ├── email_schema.py         # Email DTOs
    ├── analysis_schema.py      # Analysis Finding DTOs
    └── decision_schema.py      # Risk & Policy Action DTOs
```

---

## 3. Core Development Tasks (Member 2)

1. **REST API Construction**:
   - Maintain clean, OpenAPI-compliant FastAPI endpoints.
   - Implement strict input validation using Pydantic models.
2. **Gateway Pipeline Orchestration**:
   - Execute `security` static checks and `ml` inference wrappers asynchronously.
   - Handle timeout management (e.g., maximum 5.0 seconds total pipeline execution).
3. **Correlation & Risk Engine**:
   - Aggregate disparate security signals (e.g., SPF fail + lookalike domain + high urgency score).
   - Compute normalized Risk Score ($0 \le \text{Risk} \le 100$).
   - Assign final Threat Classification (`SAFE`, `SPAM`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`).
4. **Delivery Policy Engine**:
   - Determine enforceable action (`INBOX`, `SPAM`, `WARN`, `HOLD`, `QUARANTINE`, `REJECT`).
   - Enforce policy rules (e.g., `Risk Score ≥ 85` triggers `QUARANTINE`).

---

## 4. Example Core Execution Flow (`orchestrator.py`)

```python
async def process_email_pipeline(raw_email: RawEmailPayload) -> PipelineVerdict:
    # 1. Normalize and Preserve Evidence
    normalized_email = normalize_email(raw_email)
    evidence = preserve_evidence(raw_email)
    
    # 2. Parallel Analyzer Execution
    security_results, ml_results = await asyncio.gather(
        run_security_analyzers(normalized_email),
        run_ml_analyzers(normalized_email),
        return_exceptions=True
    )
    
    # 3. Aggregate Features & Assign Tags
    features = aggregate_features(security_results, ml_results)
    tags = assign_security_tags(features)
    
    # 4. Risk Engine & Classification
    risk_score, confidence = calculate_risk_score(features, tags)
    classification = classify_threat(risk_score, tags)
    
    # 5. Apply Delivery Policy
    delivery_action = determine_delivery_action(classification, risk_score)
    
    # 6. Database Persistence
    await persist_analysis_run(
        email=normalized_email,
        evidence=evidence,
        features=features,
        tags=tags,
        risk_score=risk_score,
        classification=classification,
        action=delivery_action
    )
    
    return PipelineVerdict(
        email_id=normalized_email.id,
        classification=classification,
        risk_score=risk_score,
        delivery_action=delivery_action
    )
```
