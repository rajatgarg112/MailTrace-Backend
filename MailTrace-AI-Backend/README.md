# MailTrace-AI Backend

## Repository

`MailTrace-AI-Backend`

## Permanent Branches

```text
main
ml
security
```

## Backend `main`

The `main` branch is the integration branch.

It owns:

- FastAPI application
- API routes
- authentication
- database integration
- shared models/schemas
- common services
- analysis orchestration
- result correlation
- risk calculation
- policy decisions
- delivery/quarantine workflow

## Database

The database is part of this repository.

Recommended structure:

```text
MailTrace-AI-Backend/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── routers/
│   ├── schemas/
│   ├── models/
│   ├── services/
│   └── utils/
│
├── database/
│   ├── connection.py
│   ├── migrations/
│   ├── seed.py
│   └── README.md
│
├── tests/
├── requirements.txt
├── .env.example
└── README.md
```

## Database Ownership

Only the backend communicates with the database.

```text
Frontend → API → Backend → Database
```

Do not place database credentials in the frontend.

## Core Tables

Initial tables:

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

## `ml` Branch

The `ml` branch contains ML-specific implementation.

Examples:

- feature extraction
- phishing/spam classification
- suspicious-language detection
- model loading
- inference
- training scripts
- model artifacts
- evaluation utilities

ML results should be returned to the backend integration layer in a structured format.

## `security` Branch

The `security` branch contains security and forensic analysis.

Examples:

- header analysis
- SPF/DKIM/DMARC checks
- sender/domain analysis
- lookalike-domain detection
- URL/redirect analysis
- relay-chain analysis
- infrastructure context
- evidence extraction
- forensic timeline generation

## Integration Rule

`ml` and `security` are specialized work branches.

After their work is stable:

```text
ml       ───────┐
                ├──→ main
security ───────┘
```

The `main` branch remains the final integrated backend.
