# Backend Database

The database is owned by the `MailTrace-AI-Backend` repository.

There is no separate database repository or permanent database branch.

## Architecture

```text
Frontend
   ↓
FastAPI Backend
   ↓
Database
```

## Initial Entities

### users
Application users.

### mailboxes
Mailbox/account metadata.

### emails
Normalized email metadata and safe content references. Raw content should only be persisted where required by an explicit evidence/retention policy.

### delivery_events
Gateway processing and delivery events.

### analysis_runs
Each security/ML analysis execution.

### security_findings
Structured security findings.

### security_tags
Normalized security/explainability tags.

### ml_results
ML predictions, scores and model metadata.

### policy_decisions
Final delivery action and policy context.

### evidence
Evidence references, hashes, extracted facts and preservation metadata.

### forensic_cases
Investigation/case information.

## Suggested Additional Fields

Security-related fields may include:

```text
classification
risk_score
threat_confidence
delivery_action
spam_category
quarantine_reason
```

Feature-level results should follow the canonical feature schema in:

```text
../SECURITY_FEATURE_SCHEMA.md
```

## Privacy

Avoid storing raw body/attachments unnecessarily.

Prefer:

```text
raw artifact
   ↓
transient analysis
   ↓
hash + extracted security facts
   ↓
persist required evidence only
```

## Integrity

For preserved evidence, store cryptographic hashes such as SHA-256 and relevant timestamps/metadata so that changes can be detected.

The database does not itself make an evidence report legally admissible; legal admissibility depends on applicable procedures and jurisdiction.
