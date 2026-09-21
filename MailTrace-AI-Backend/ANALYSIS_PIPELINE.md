# Complete 20-Stage Security & Analysis Pipeline Specification

## 1. Pipeline Architectural Principles

1. **Pre-Delivery Execution**: Analysis takes place before user inbox delivery.
2. **Parallel Analyzer Execution**: Independent static security checks (Member 4/6) and ML content checks (Member 3) execute concurrently.
3. **Authoritative Synthesis**: Core Backend `main` (Member 2) collects all signals, computes the Risk Score, determines Threat Classification, and enforces Delivery Policy.

---

## 2. 20-Stage Sequential Specification

```text
 1. Email Ingestion               (FastAPI Endpoint)
 2. Evidence Preservation         (SHA-256 Hashing & Storage)
 3. Parsing & Normalization       (MIME, Headers, Body, Links)
 4. Sender Identity Analysis      (Header From vs Envelope From)
 5. Email Authentication Check    (SPF, DKIM, DMARC Validation)
 6. Domain Security Inspection    (Lookalike, Typosquatting, TLD)
 7. Header & Relay Hop Analysis   (Received Chain & Anomaly Check)
 8. URL & Link Extraction         (Unshortening & Redirect Chains)
 9. Attachment Static Inspection  (MIME Type, Double Extensions)
10. Image & QR Code Inspection    (OCR & Encoded URL Extraction)
11. Content & NLP Analysis        (Text Vectorization & Cleaning)
12. BEC & Impersonation Check     (High-Executive Impersonation)
13. Behavioral Context Check      (First-Time Sender & Recipient History)
14. Threat Intel Correlation      (IP & Domain Reputation Adapters)
15. Security Tag Generation       (Canonical Tag Assignment)
16. Multi-Signal Risk Engine      (Weighted Score 0 - 100)
17. Threat Classification         (SAFE | SPAM | SUSPICIOUS | MALICIOUS | UNKNOWN)
18. Delivery Policy Enforcement   (INBOX | SPAM | WARN | HOLD | QUARANTINE | REJECT)
19. Database Event Persistence    (SQLAlchemy Persistence to DB)
20. REST Response & Presentation  (JSON Payload to React Frontend)
```

---

## 3. Stage Ownership & Responsibilities

| Stage Range | Stage Names | Responsible Branch & Subsystem | Primary Team Owner |
|---|---|---|---|
| **Stages 1 - 3** | Ingestion, Evidence Preservation, Normalization | `main` (`app/gateway/`) | Member 2 & Member 6 |
| **Stages 4 - 8** | Sender, Auth (SPF/DKIM/DMARC), Domains, Headers, URLs | `security` (`security/*/`) | Member 4 |
| **Stages 9 - 10** | Attachments, QR Static Inspection | `security` (`security/*/`) | Member 4 |
| **Stages 11 - 13** | NLP Content, BEC, Behavioral Signals | `ml` (`ml/*/`) | Member 3 |
| **Stage 14** | Threat Intelligence Adapter Correlation | `security` (`security/*/`) | Member 4 |
| **Stage 15** | Security Tag Assignment | `main` (`app/correlation/`) | Member 2 |
| **Stages 16 - 18** | Risk Engine, Threat Classification, Delivery Policy | `main` (`app/risk/`, `app/policy/`) | Member 2 |
| **Stage 19** | Database Record & Event Persistence | `main` (`database/`) | Member 5 |
| **Stage 20** | REST API Delivery to React Frontend | `main` (`app/api/`) | Member 2 → Member 1 |
