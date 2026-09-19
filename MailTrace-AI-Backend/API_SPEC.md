# Backend API Specification

This is the initial API contract for frontend/backend integration.

## Health

```http
GET /health
```

Returns backend health status.

## Emails

```http
GET /api/emails
GET /api/emails/{email_id}
```

Returns email metadata and analysis state.

## Analysis

```http
POST /api/emails/{email_id}/analyze
GET /api/analysis/{analysis_id}
```

Starts and retrieves an analysis run.

## Security Findings

```http
GET /api/emails/{email_id}/findings
```

Returns security findings.

## ML Results

```http
GET /api/emails/{email_id}/ml-result
```

Returns ML prediction and supporting metadata.

## Evidence

```http
GET /api/emails/{email_id}/evidence
```

Returns safe forensic evidence references.

## Quarantine

```http
GET /api/quarantine
GET /api/quarantine/{email_id}
```

Returns quarantined email information.

## Cases

```http
GET /api/cases
GET /api/cases/{case_id}
POST /api/cases
```

Manages forensic investigation cases.

## API Rule

The backend is authoritative for:

- classification
- risk score
- security tags
- findings
- ML result
- delivery action
- evidence references

The frontend should not recreate these decisions.
