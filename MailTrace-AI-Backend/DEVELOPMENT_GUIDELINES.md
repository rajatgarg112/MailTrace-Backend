# Development Guidelines & Engineering Conventions

## 1. Code Style & Standards

- **Python Version**: Python 3.11+.
- **Formatting**: PEP 8 compliance enforced via `black` and `isort`.
- **Type Annotations**: Mandatory type hinting for function parameters and return values (`typing` / Python 3.10+ native types).
- **Validation Framework**: Pydantic v2 models for API requests, responses, and cross-module feature data contracts.

---

## 2. Error Handling & Fail-Safe Principles

1. **Explicit Exceptions**: Avoid bare `except:` blocks. Catch specific exceptions (e.g., `requests.Timeout`, `dns.resolver.NXDOMAIN`).
2. **`UNKNOWN ≠ SAFE`**: If an external lookup or internal analyzer fails unexpectedly:
   - Log the failure clearly with stack trace details.
   - Return a feature status of `UNKNOWN`.
   - **Do not** default the email to `SAFE` or risk score to `0`.
3. **Bounded External Operations**: All network requests to external threat intelligence providers must set an explicit timeout (maximum 3.0 seconds) to prevent gateway blockages.

---

## 3. Untrusted Data Inspection Rules

- **Zero Untrusted Execution**: Email attachments must never be executed or dynamically evaluated directly within the main server process.
- **Sanitized Parsing**: Use strict parser wrappers for MIME headers, HTML body tags, and URLs to prevent injection or SSRF vulnerabilities.
- **Privacy Preservation**: Do not log raw user credentials or unencrypted authentication tokens in application log output.

---

## 4. Commit & Pull Request Guidelines

### Commit Message Format:
```text
<type>(<scope>): <short summary>

[optional body describing technical context]
```

#### Allowed Types:
- `feat`: A new feature or analyzer.
- `fix`: A bug fix.
- `refactor`: Code restructuring without functional changes.
- `test`: Adding or modifying unit/integration tests.
- `docs`: Documentation updates.

#### Examples:
- `feat(security): add lookalike domain distance algorithm`
- `fix(gateway): resolve deadlock on parallel analyzer execution`
- `test(ml): add test fixtures for BEC urgency detector`

---

## 5. Local Setup Instructions

```bash
# Clone the Backend Repository
git clone https://github.com/MailTrace-AI/MailTrace-AI-Backend.git
cd MailTrace-AI-Backend

# Create Virtual Environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Core & Development Dependencies
pip install -r requirements.txt

# Copy Configuration Blueprint
cp .env.example .env

# Run Tests
pytest
```
