# Evidence Preservation & Forensic Auditing Specification

## 1. Subsystem Overview

- **Primary Owner**: Member 6 (Forensics & Infrastructure Engineer)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `security`
- **Core Folder Location**: `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/`

This document specifies the cryptographic preservation format for raw email evidence, investigation audit logs, and network infrastructure context.

---

## 2. Cryptographic Evidence Hashes

Upon ingestion, the evidence engine computes cryptographic SHA-256 fingerprints to guarantee immutability:

```json
{
  "evidence_id": "ev_001928374",
  "email_id": "eml_987654321",
  "hashes": {
    "raw_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "headers_sha256": "a7d9f2c81e3b567401d2e8934567891234567890abcdef1234567890abcdef12",
    "body_sha256": "f892bc910e1234567890abcdef1234567890abcdef1234567890abcdef123456"
  },
  "stored_at": "2026-09-21T09:30:00Z"
}
```

---

## 3. Forensic Case Structure

Security analysts viewing the Quarantine Dashboard can inspect full forensic case artifacts:

```json
{
  "case_id": "cas_44556677",
  "email_id": "eml_987654321",
  "summary": "Phishing attack impersonating PayPal via lookalike domain",
  "verdict": {
    "threat_classification": "MALICIOUS",
    "risk_score": 94,
    "action": "QUARANTINE"
  },
  "timeline_events_count": 5,
  "evidence_preserved": true,
  "infrastructure": {
    "originating_ip": "185.220.101.5",
    "asn": "AS43350",
    "isp": "NForce Entertainment B.V.",
    "approximate_region": "Frankfurt, Germany",
    "disclaimer": "Approximate network infrastructure location, not verified physical identity."
  }
}
```
