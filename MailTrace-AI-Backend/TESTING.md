# Testing Framework & Quality Assurance Specification

## 1. Testing Architecture

Testing is organized by workstream and permanent branch across `MailTrace-AI-Backend`:

```text
tests/
├── unit/                       # Isolated Module Unit Tests
│   ├── backend/                # Unit Tests for app/ (Member 2 & 5)
│   ├── ml/                     # Unit Tests for ml/ (Member 3)
│   ├── security/               # Unit Tests for security/ (Member 4)
│   └── forensics/              # Unit Tests for forensic/ (Member 6)
│
├── integration/                # Full Gateway & Database Integration Tests
│   ├── test_pipeline.py        # End-to-End Analysis Pipeline Test
│   └── test_api_routes.py      # FastAPI Endpoint Tests
│
└── fixtures/                   # Standardized Test Email Payloads
    ├── benign_email.eml        # Sample Safe Email
    ├── spf_fail_phish.eml      # Sample SPF/DMARC Failure Phish
    ├── lookalike_paypal.eml    # Sample Lookalike Domain Phish
    └── bec_urgency.eml         # Sample High-Urgency BEC Email
```

---

## 2. Test Execution Commands

```bash
# Run All Tests
pytest

# Run Unit Tests for Security Analyzers
pytest tests/unit/security/

# Run Unit Tests for ML Classifiers
pytest tests/unit/ml/

# Run End-to-End Pipeline Integration Tests
pytest tests/integration/test_pipeline.py
```

---

## 3. Test Coverage Requirements

1. **Feature Coverage**: Every new analyzer or ML classifier must include unit tests verifying `PASS`, `FAIL`, and edge-case behavior.
2. **Mocking External Services**: External network calls (DNS lookups, Threat Intel APIs) must be mocked using `unittest.mock` or `pytest-mock` in unit tests.
3. **No Direct Execution**: Test fixtures containing phishing URLs or malicious MIME samples must be stored safely in plaintext test fixtures (`.eml` or `.json`), never executed.
