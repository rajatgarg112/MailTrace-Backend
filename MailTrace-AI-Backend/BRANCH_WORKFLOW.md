# Backend Branch Workflow

## Branches

The backend repository has three permanent branches:

```text
main
ml
security
```

## main

Integration branch.

Contains the working backend and database integration.

## ml

ML development branch.

Contains:

- model code
- feature extraction
- inference
- training/evaluation utilities
- ML artifacts

## security

Security development branch.

Contains:

- email/header analysis
- authentication checks
- domain analysis
- URL analysis
- relay analysis
- forensic logic
- evidence generation

## Recommended Workflow

### ML developer

```text
main
 ↓
ml
 ↓
Develop/Test
 ↓
Merge into main
```

### Security developer

```text
main
 ↓
security
 ↓
Develop/Test
 ↓
Merge into main
```

### Core backend developer

```text
main
 ↓
API + DB + orchestration
 ↓
Test
```

## Shared Database Changes

If `ml` or `security` requires a database change:

1. Document the required table/field.
2. Add the migration/change on that branch.
3. Test it.
4. Merge the complete change into `main`.
5. Keep the database schema synchronized.

`main` is the source of truth for the integrated backend.

## Avoid

Do not create permanent branches such as:

```text
database
frontend-backend
api-final
ml-final-final
security-final
```

unless the team later has a specific documented reason.
