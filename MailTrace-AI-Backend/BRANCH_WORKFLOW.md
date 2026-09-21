# Branch Workflow & Git Strategy Specification

## 1. Permanent Shared Branches

The project relies on **4 permanent shared branches** across 2 repositories:

### Frontend Repository (`MailTrace-AI-Frontend`)
- `main`: Production-ready React frontend codebase.

### Backend Repository (`MailTrace-AI-Backend`)
- `main`: Integrated core backend application, FastAPI routers, database, and orchestrator.
- `ml`: Machine learning pipelines, model artifacts, and inference wrappers.
- `security`: Security analyzers, email authentication parsers, and forensic evidence engines.

---

## 2. Feature Branch Naming Conventions

All daily feature work must occur on **temporary feature branches** created off the appropriate permanent branch:

```text
feature/<component>-<short-description>
bugfix/<component>-<short-description>
refactor/<component>-<short-description>
```

### Examples by Workstream:
- **Member 1 (Frontend)**: `feature/frontend-quarantine-ui` (branched from `main`)
- **Member 2 (Backend)**: `feature/backend-risk-engine` (branched from `main`)
- **Member 3 (ML)**: `feature/ml-bec-classifier` (branched from `ml`)
- **Member 4 (Security)**: `feature/security-dmarc-parser` (branched from `security`)
- **Member 5 (Database)**: `feature/database-evidence-schema` (branched from `main`)
- **Member 6 (Forensics)**: `feature/forensic-timeline-logger` (branched from `security`)

---

## 3. Workstream Integration Strategy

```text
Feature Branches                 Permanent Branches             Integration Target
┌───────────────────────┐       ┌──────────────────┐
│ feature/bec-classifier│ ────> │ ml               │ ─────┐
└───────────────────────┘       └──────────────────┘      │
                                                          │   Pull Request & Code Review
┌───────────────────────┐       ┌──────────────────┐      ├────────────────────────────> ┌────────┐
│ feature/dmarc-parser  │ ────> │ security         │ ─────┤                              │ main   │
└───────────────────────┘       └──────────────────┘      │                              └────────┘
                                                          │
┌───────────────────────┐       ┌──────────────────┐      │
│ feature/db-migration  │ ───────────────────────────────>│
└───────────────────────┘                                 │
                                                          │
┌───────────────────────┐                                 │
│ feature/api-router    │ ────────────────────────────────┘
└───────────────────────┘
```

1. Developers work on `feature/*` branches and submit Pull Requests to their workstream's permanent branch (`ml` or `security`).
2. Once verified, features on `ml` and `security` are integrated into `main` via coordinated PRs.
3. Member 2 (Core Backend) conducts integration reviews before merging `ml` or `security` into `main`.

---

## 4. Strict Git Protection Rules

> [!CAUTION]
> **No Force Pushing**:
> Never execute `git push --force` or `git push -f` on any permanent shared branch (`main`, `ml`, `security`).

### Essential Developer Checklist

#### Before Starting Work:
```bash
git checkout <permanent-branch>
git pull origin <permanent-branch>
git checkout -b feature/<your-feature-name>
```

#### During Development:
```bash
git status
git diff
```

#### Before Pushing Feature Branch:
```bash
git add .
git commit -m "feat(security): add SPF authentication analyzer"
git push origin feature/<your-feature-name>
```

#### Open Pull Request:
- Submit Pull Request on GitHub to target branch (`security`, `ml`, or `main`).
- Request review from partner owner.
- Ensure automated test suite passes before merging.
