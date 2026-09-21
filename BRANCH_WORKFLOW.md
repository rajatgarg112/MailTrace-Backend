# Backend Branch Workflow

## Permanent Branches

```text
main
ml
security
```

These are repository-level development branches, not a replacement for short-lived feature branches.

## `main`

Integration/source-of-truth branch.

Owns:

- API
- DB
- shared contracts
- gateway
- correlation
- risk engine
- delivery policy
- integrated backend

## `ml`

Owns:

- content/NLP
- BEC/impersonation
- behavioral features
- ML models
- inference/training/evaluation

## `security`

Owns:

- sender/domain
- SPF/DKIM/DMARC
- headers/IP/relay
- URL/domain
- attachments
- QR
- threat intelligence
- evidence/forensics

## Recommended Team Workflow

Use short-lived feature branches from the appropriate permanent branch when multiple people are working in parallel.

Example:

```text
security
   ↓
feature/url-attachment-qr
   ↓
merge → security
   ↓
integration merge → main
```

and:

```text
ml
 ↓
feature/content-bec-behavior
 ↓
merge → ml
 ↓
integration merge → main
```

Core gateway/risk/API work can use:

```text
main
 ↓
feature/gateway-orchestrator
 ↓
merge → main
```

## Dependency Order

Recommended implementation order:

```text
1. Canonical feature contract
2. Gateway/orchestrator
3. Security analyzers
4. ML/content/behavior analyzers
5. Security tags
6. Risk engine
7. Classification
8. Delivery policy
9. DB persistence
10. Frontend API integration
```

## Database Changes

If `ml` or `security` requires a DB change:

1. Document the field/entity.
2. Add migration/change.
3. Test it.
4. Merge the complete change into `main`.
5. Keep schema synchronized.

## Avoid

Do not create permanent branches such as:

```text
database
frontend-backend
api-final
ml-final-final
security-final-final
```

unless the team later documents a real need.
