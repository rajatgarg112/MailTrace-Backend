# Delivery Policy

## Purpose

The delivery policy converts the backend security decision into a user-facing routing action.

## Classification

```text
SAFE
SPAM
SUSPICIOUS
MALICIOUS
UNKNOWN
```

## Actions

```text
INBOX
SPAM
WARN
HOLD
QUARANTINE
REJECT
```

## Recommended Policy

```text
SAFE
  → INBOX

SPAM
  → SPAM category

SUSPICIOUS
  → WARN / HOLD

MALICIOUS
  → QUARANTINE

UNKNOWN
  → HOLD / policy-defined
```

## Spam Categories

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

## Security Gateway Categories

```text
MALICIOUS
HIGH_RISK_PHISHING
MALWARE
BEC_FRAUD
OTHER_HIGH_RISK
```

## Important Distinction

Classification and delivery action are independent.

Examples:

```text
Classification: PHISHING
Action: QUARANTINE
```

```text
Classification: SPAM
Category: MARKETING
Action: SPAM
```

```text
Classification: UNKNOWN
Action: HOLD
```

## Harmful Content Protection

For high-risk/malicious messages:

- original body is blocked by default
- attachments are blocked by default
- suspicious URLs are not automatically opened
- user receives a sanitized security report
- security findings and evidence remain available
- release is only possible through an explicit policy-controlled action

## User Actions

Possible policy-controlled actions:

```text
Delete
Report
Release (if allowed)
Review security report
```

Do not allow the frontend to bypass backend policy.
