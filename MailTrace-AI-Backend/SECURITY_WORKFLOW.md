# Cyber Security Workflow & Analyzer Specification

## 1. Workstream Overview

- **Primary Owner**: Member 4 (Cyber Security Analyst)
- **Collaborator**: Member 6 (Forensics & Infrastructure)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `security`
- **Core Folder Locations**:
  - Member 4: `security/header_analysis/`, `authentication/`, `domain_analysis/`, `url_analysis/`, `relay_analysis/`
  - Member 6: `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/`

Member 4 owns static security checks, email authentication protocols, domain similarity algorithms, link extraction, and header hop analysis.

---

## 2. Subsystem Ownership & Directory Layout

```text
security/
│
├── header_analysis/           # Member 4
│   ├── parser.py              # RFC 5322 Header Parser
│   └── anomaly_detector.py    # Missing/Malformed Header Inspector
│
├── authentication/            # Member 4
│   ├── spf_evaluator.py       # Sender Policy Framework Validator
│   ├── dkim_evaluator.py      # DomainKeys Identified Mail Verifier
│   └── dmarc_evaluator.py     # Domain-based Message Authentication Evaluator
│
├── domain_analysis/           # Member 4
│   ├── lookalike.py           # Levenshtein & Homograph Domain Checker
│   ├── typosquatting.py       # Typosquatting Pattern Detector
│   └── tld_inspector.py       # High-Risk / Suspicious TLD Evaluator
│
├── url_analysis/              # Member 4
│   ├── extractor.py           # HTML & Plaintext Link Extractor
│   ├── redirect_chain.py      # HTTP Redirect Hop Unshortener
│   └── domain_reputation.py   # Domain Threat Intelligence Adapter
│
├── relay_analysis/            # Member 4
│   ├── hop_counter.py         # Received Header Hop Extraction
│   └── relay_verifier.py      # Open Relay & Suspicious Hop Detector
│
├── forensic/                  # Member 6 (See FORENSICS_WORKFLOW.md)
├── evidence/                  # Member 6
├── timeline/                  # Member 6
└── infrastructure/            # Member 6
```

---

## 3. Analyzer Modules & Functional Specs

### A. Email Authentication (`authentication/`)
- **SPF Check**: Compares originating SMTP client IP against published DNS SPF records (`PASS`, `FAIL`, `NEUTRAL`, `SOFTFAIL`).
- **DKIM Check**: Verifies cryptographic signature in `DKIM-Signature` header against published public key (`PASS`, `FAIL`, `NONE`).
- **DMARC Check**: Evaluates alignment between Header From domain and SPF/DKIM validation (`PASS`, `FAIL`, `NONE`).

### B. Domain & Identity Security (`domain_analysis/`)
- **Display Name Spoofing**: Detects when `From:` display name claims an executive/brand identity (e.g., "PayPal Security") while the underlying email address uses an unrelated domain (`user@random-site.com`).
- **Lookalike & Homograph Domains**: Measures string edit distance (Levenshtein distance) and visual Unicode homograph substitution against protected brand targets.
- **Domain Age Check**: Identifies newly registered domains ($< 30$ days old).

### C. URL & Link Analysis (`url_analysis/`)
- **Extraction**: Parses all `href` attributes, plain text links, and canonical URLs.
- **Unshortening**: Expands short URLs (`bit.ly`, `tinyurl.com`, etc.) to reveal final target destinations.
- **Anchor Text Mismatch**: Flags instances where anchor text displays one URL (`https://bankofamerica.com`) but targets another (`https://malicious-login.ru`).

### D. Header & Relay Hop Analysis (`relay_analysis/`)
- Parses all `Received:` headers top-to-bottom to reconstruct the SMTP relay chain.
- Flags suspicious intermediary hops, missing timestamps, or unexpected geographic jumps.

---

## 4. Standardized Output Contract (`security` → `main`)

```json
{
  "email_id": "eml_987654321",
  "authentication": {
    "spf": "FAIL",
    "dkim": "PASS",
    "dmarc": "FAIL"
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
    "redirect_chain_detected": true
  },
  "relay_analysis": {
    "hop_count": 3,
    "originating_ip": "185.220.101.5",
    "suspicious_relay_detected": true
  }
}
```
