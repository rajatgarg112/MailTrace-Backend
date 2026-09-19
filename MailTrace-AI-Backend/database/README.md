# Database

The database is owned by the MailTrace-AI Backend repository.

There is no separate database repository.

## Architecture

```text
Frontend
   ↓
FastAPI Backend
   ↓
Database
```

## Responsibilities

The database layer handles:

- connection management
- models
- migrations
- seed/demo data
- persistence
- querying

## Initial Entities

### users
Stores application users.

### mailboxes
Stores mailbox/account information.

### emails
Stores normalized email metadata and content references.

### delivery_events
Stores delivery and processing events.

### analysis_runs
Stores each analysis execution.

### security_findings
Stores findings produced by security analysis.

### security_tags
Stores normalized threat/security tags.

### ml_results
Stores ML predictions, scores and model metadata.

### policy_decisions
Stores the final delivery action.

### evidence
Stores forensic evidence references and extracted facts.

### forensic_cases
Stores investigation/case information.

## Important Rule

The database stores system results; the frontend only receives data through backend APIs.

Never:

```text
Frontend → Database
```

Always:

```text
Frontend → Backend API → Database
```
