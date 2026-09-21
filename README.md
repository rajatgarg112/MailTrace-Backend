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

The `main` branch is the integrated backend and owns:

- Python + FastAPI application
- API routes
- authentication
- database integration
- shared models/schemas
- canonical security feature contracts
- gateway/orchestration
- correlation
- security-tag aggregation
- risk calculation
- classification
- delivery policy
- quarantine workflow
- evidence/event persistence
- common services

## `ml` Branch

Owns:

- NLP/content feature extraction
- phishing/spam signals
- BEC/impersonation signals
- behavioral feature extraction
- ML inference
- training/evaluation utilities
- model artifacts
- ML-specific tests

The `ml` branch must expose structured outputs that can be consumed by backend `main`.

## `security` Branch

Owns:

- sender/identity analysis
- email authentication: SPF/DKIM/DMARC
- domain and lookalike analysis
- URL/link analysis
- attachment static analysis
- image/QR analysis
- header/IP/relay analysis
- threat-intelligence adapters
- evidence extraction/preservation
- forensic timeline/evidence logic
- security-specific tests

## Gateway Orchestrator

The backend gateway is the integration point.

Conceptually:

```text
process_email(raw_email)
      ↓
parse + normalize
      ↓
preserve evidence
      ↓
run security analyzers
      ↓
run ML/content analyzers
      ↓
collect canonical features
      ↓
generate security tags
      ↓
correlate independent signals
      ↓
calculate risk/confidence
      ↓
classify threat
      ↓
apply delivery policy
      ↓
persist decision/events
      ↓
return frontend-safe response
```

The orchestrator must not duplicate analyzer logic. It should call modular analyzers and combine their structured outputs.

## Security Decision Layers

Keep these layers separate:

```text
Security Features
      ↓
Security Tags
      ↓
Risk Engine
      ↓
Threat Classification
      ↓
Delivery Action
```

Example:

```text
Features:
domain_age = 2 days
dmarc = fail
credential_request_score = 0.94

Tags:
New-Domain
DMARC-Fail
Credential-Request

Risk:
91

Classification:
PHISHING

Action:
QUARANTINE
```

## Database

The database is backend-owned.

```text
MailTrace-AI-Backend/
├── app/
├── database/
├── tests/
├── requirements.txt
└── .env.example
```

Only backend code communicates with the database.

## Safe Untrusted-Content Handling

Do not directly execute untrusted attachments or open suspicious URLs in a developer/user environment.

For deeper inspection:

```text
Attachment/URL
      ↓
Static inspection
      ↓
Reputation / parsing
      ↓
If required → isolated sandbox/browser
      ↓
Security result
```

The original artifact should not be exposed to the normal application runtime unnecessarily.

## External Integrations

External threat-intelligence services should be implemented behind adapters so that provider failure does not break the entire gateway.

Provider results are signals and should be represented with source/status/timestamp where applicable.

## GeoLocation

IP geolocation is approximate infrastructure context, not exact attacker attribution.

## Gmail / Google Workspace

Current prototype:

```text
MailTrace Gateway + MailTrace Webmail/Dashboard
```

Future integration:

```text
Gmail / Google Workspace
      ↓
Official APIs / OAuth / Add-on integration
      ↓
MailTrace
```

Do not claim direct control over Gmail's internal spam engine in the prototype.
