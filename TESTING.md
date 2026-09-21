# Testing Strategy

## Unit Tests

Each analyzer should have tests for:

- valid input
- malformed input
- missing fields
- unknown provider result
- suspicious input
- safe input

## Integration Tests

At minimum, test the gateway with:

1. Safe email
2. Marketing/bulk email
3. Phishing email
4. BEC/payment-request email
5. Malicious attachment case
6. Suspicious URL case
7. QR-code phishing case
8. New/lookalike domain case
9. SPF/DKIM/DMARC failure case
10. Unknown/insufficient-signal case

## End-to-End Test

The first major integrated milestone is:

```text
Test Email
   ↓
Gateway
   ↓
Existing analyzers
   ↓
Canonical features
   ↓
Security tags
   ↓
Risk engine
   ↓
Classification
   ↓
Delivery policy
   ↓
Database
   ↓
Backend API
   ↓
Frontend
```

## Security Tests

Verify that:

- suspicious URLs are not auto-opened
- attachments are not executed in the normal backend
- malicious content is not exposed by default
- frontend cannot override backend decisions
- unknown signals are not silently converted to safe
- raw content is not unnecessarily written to logs

## ML Evaluation

Only publish ML metrics when:

- dataset is documented
- train/test split is defined
- evaluation is reproducible
- metrics are calculated from actual predictions

Do not invent demo accuracy numbers.
