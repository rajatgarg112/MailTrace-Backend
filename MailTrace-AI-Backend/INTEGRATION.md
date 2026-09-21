# Integration Specification & Data Contracts

## 1. Cross-Branch Integration Architecture

`MailTrace-AI-Backend/main` serves as the central integration hub. Modules developed on `ml` and `security` communicate with `main` via strict Python data contracts (Pydantic models).

```text
 ┌──────────────────────┐        ┌──────────────────────┐
 │ security Branch      │        │ ml Branch            │
 │ (Member 4 & 6)       │        │ (Member 3)           │
 └──────────┬───────────┘        └──────────┬───────────┘
            │                               │
            │ SecurityResult                │ MLResult
            ▼                               ▼
 ┌──────────────────────────────────────────────────────┐
 │ main Branch (Member 2 & 5)                           │
 │ Gateway Orchestrator                                 │
 │  ├── Signal Aggregation                             │
 │  ├── Tag Generation                                 │
 │  ├── Risk Score Engine                              │
 │  └── Delivery Policy Decision                       │
 └──────────────────────────┬───────────────────────────┘
                            │ Final Pipeline Verdict
                            ▼
 ┌──────────────────────────────────────────────────────┐
 │ Database (Member 5) & REST API Output to Frontend    │
 └──────────────────────────────────────────────────────┘
```

---

## 2. Standardized Output Payloads

### A. Security Module Output Contract (`security` → `main`)

```json
{
  "email_id": "eml_987654321",
  "authentication": {
    "spf": "FAIL",
    "dkim": "PASS",
    "dmarc": "FAIL",
    "header_from": "billing@paypal-support-update.com",
    "envelope_from": "bounce@cheap-mail.ru"
  },
  "domain_analysis": {
    "is_lookalike": true,
    "target_domain": "paypal.com",
    "domain_age_days": 4,
    "suspicious_tld": true
  },
  "url_analysis": {
    "total_urls": 2,
    "suspicious_urls_count": 2,
    "redirect_chain_detected": true,
    "extracted_urls": [
      "https://bit.ly/3x89qAZ",
      "https://login-paypal-verify-user.com/auth"
    ]
  },
  "relay_analysis": {
    "hop_count": 3,
    "originating_ip": "185.220.101.5",
    "suspicious_relay_detected": true
  }
}
```

### B. Forensics Module Output Contract (`security` → `main`)

```json
{
  "email_id": "eml_987654321",
  "evidence_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timeline": [
    {"timestamp": "2026-09-21T09:30:00Z", "stage": "INGESTION", "status": "COMPLETED"},
    {"timestamp": "2026-09-21T09:30:01Z", "stage": "AUTH_CHECK", "status": "FAILED"},
    {"timestamp": "2026-09-21T09:30:02Z", "stage": "DOMAIN_LOOKALIKE", "status": "FLAGGED"}
  ],
  "infrastructure": {
    "originating_ip": "185.220.101.5",
    "asn": "AS43350",
    "isp": "NForce Entertainment B.V.",
    "approximate_region": "Frankfurt, Germany",
    "disclaimer": "Approximate network infrastructure location, not verified physical identity."
  }
}
```

### C. ML Module Output Contract (`ml` → `main`)

```json
{
  "email_id": "eml_987654321",
  "prediction": "PHISHING",
  "confidence": 0.94,
  "model_version": "phish-bert-v2.1",
  "nlp_features": {
    "urgency_score": 0.88,
    "financial_keyword_density": 0.12,
    "credential_harvesting_intent": 0.91,
    "sentiment": "HIGH_PRESSURE"
  }
}
```

---

## 3. Integrated Core Decision Model (`main`)

The Gateway Orchestration Engine on `main` receives the above structured outputs and synthesizes the definitive risk score and delivery policy action:

```json
{
  "email_id": "eml_987654321",
  "security_tags": [
    "DMARC_FAIL",
    "LOOKALIKE_DOMAIN",
    "NEW_DOMAIN",
    "SUSPICIOUS_URL",
    "HIGH_URGENCY",
    "CREDENTIAL_INTENT"
  ],
  "risk_score": 94,
  "threat_confidence": 0.94,
  "threat_classification": "MALICIOUS",
  "delivery_action": "QUARANTINE",
  "timestamp": "2026-09-21T09:30:03Z"
}
```
