# Backend API Specification

This is the integration contract between `MailTrace-AI-Frontend` and `MailTrace-AI-Backend`.

## Health

```http
GET /health
```

Returns backend health status.

## Email Ingestion

```http
POST /api/emails
```

Accepts a demo/prototype email submission for gateway processing.

The request may contain:

- sender
- recipients
- subject
- headers
- body
- URLs
- attachments
- images/QR inputs

The backend must treat submitted content as untrusted.

## Email Retrieval

```http
GET /api/emails
GET /api/emails/{email_id}
```

Returns frontend-safe normalized metadata and current security/delivery state.

## Gateway Analysis

```http
POST /api/emails/{email_id}/analyze
GET /api/analysis/{analysis_id}
```

Starts/retrieves an analysis run.

## Findings

```http
GET /api/emails/{email_id}/findings
```

Returns structured security findings.

## Security Tags

```http
GET /api/emails/{email_id}/tags
```

Returns normalized security tags.

Example:

```json
{
  "tags": [
    "FIRST_TIME_SENDER",
    "NEW_DOMAIN",
    "DMARC_FAIL",
    "CREDENTIAL_REQUEST",
    "SUSPICIOUS_URL"
  ]
}
```

## Risk / Decision

```http
GET /api/emails/{email_id}/risk
GET /api/emails/{email_id}/decision
```

Example:

```json
{
  "classification": "PHISHING",
  "risk_score": 91,
  "threat_confidence": 0.94,
  "action": "QUARANTINE"
}
```

Risk score is a project decision signal, not a claim of probability unless the model has been calibrated and documented as such.

## Spam

```http
GET /api/spam
GET /api/spam/{email_id}
```

Spam responses may include a category:

```text
MARKETING
EDUCATION
SOCIAL_NOTIFICATION
BULK
SCAM
FRAUD
PHISHING
SUSPICIOUS
OTHER
```

## Quarantine

```http
GET /api/quarantine
GET /api/quarantine/{email_id}
```

For malicious/high-risk mail, return a sanitized security report rather than automatically exposing the original content.

## Evidence

```http
GET /api/emails/{email_id}/evidence
```

Returns safe evidence references, hashes, extracted facts and forensic metadata.

## Cases

```http
GET /api/cases
GET /api/cases/{case_id}
POST /api/cases
```

Manages forensic cases.

## ML Result

```http
GET /api/emails/{email_id}/ml-result
```

Returns model prediction metadata and supporting features that are safe to expose.

## API Authority Rule

The backend is authoritative for:

- security features
- security tags
- risk score
- confidence
- threat classification
- findings
- delivery action
- evidence references

The frontend must not recreate these decisions.

## Error / Unknown Rule

A missing or unavailable external signal must not automatically be converted to `SAFE`.

The backend should represent unavailable/unknown signals explicitly.
