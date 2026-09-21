# Forensics & Geo-Infrastructure Specification

## 1. Workstream Overview

- **Primary Owner**: Member 6 (Forensics & Infrastructure Engineer)
- **Collaborator**: Member 4 (Cyber Security Analyst)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `security`
- **Core Folder Location**: `security/forensic/`, `evidence/`, `timeline/`, `infrastructure/`

Member 6 owns immutable evidence preservation, step-by-step investigation timeline generation, audit logging, and approximate network infrastructure geolocation mapping.

---

## 2. Component Architecture

```text
security/
│
├── forensic/                  # Main Forensics Subsystem Engine
│   ├── case_builder.py        # Assembles Forensic Case Artifacts
│   └── audit_logger.py        # Cryptographic Audit Log Generator
│
├── evidence/                  # Evidence Preservation
│   ├── hasher.py              # SHA-256 / SHA-512 Hash Extractor
│   └── vault.py               # Immutable Evidence Storage Handler
│
├── timeline/                  # Investigation Timeline Engine
│   └── event_tracker.py       # Step-by-Step Execution Logger
│
└── infrastructure/            # Network Infrastructure Context
    ├── ip_resolver.py         # Originating IP Extractor
    ├── asn_lookup.py          # Autonomous System Number Lookup
    └── geo_mapper.py          # Approximate Geolocation Resolver
```

---

## 3. Investigation Timeline Engine

Every ingested email generates an immutable chronological timeline tracking each stage of analysis:

```json
{
  "email_id": "eml_987654321",
  "timeline_events": [
    {
      "sequence": 1,
      "timestamp": "2026-09-21T09:30:00.102Z",
      "stage": "INGESTION",
      "status": "COMPLETED",
      "details": "Raw email payload received & SHA-256 hash verified."
    },
    {
      "sequence": 2,
      "timestamp": "2026-09-21T09:30:00.345Z",
      "stage": "AUTHENTICATION_CHECK",
      "status": "FAILED",
      "details": "SPF evaluation failed; DMARC policy validation failed."
    },
    {
      "sequence": 3,
      "timestamp": "2026-09-21T09:30:00.612Z",
      "stage": "DOMAIN_ANALYSIS",
      "status": "FLAGGED",
      "details": "Lookalike domain detected: 'paypal-support-update.com' targets 'paypal.com'."
    },
    {
      "sequence": 4,
      "timestamp": "2026-09-21T09:30:01.050Z",
      "stage": "ML_INFERENCE",
      "status": "COMPLETED",
      "details": "Phishing classification confidence 0.94; high urgency detected."
    },
    {
      "sequence": 5,
      "timestamp": "2026-09-21T09:30:01.210Z",
      "stage": "POLICY_ENFORCEMENT",
      "status": "ENFORCED",
      "details": "Risk score 94 triggered action QUARANTINE."
    }
  ]
}
```

---

## 4. Network Infrastructure & Approximate Geolocation

### Critical Boundary & Disclaimer Requirement

> [!WARNING]
> **Strict Geolocation Boundary**:
> Geolocation mapping is strictly documented as **approximate network infrastructure context** (ISP, Autonomous System Number, server hosting region).
> It must **never** be described as proof of physical attacker identity, exact residential coordinates, or legal criminal attribution.

```json
{
  "originating_ip": "185.220.101.5",
  "reverse_dns": "tor-exit-node.example.org",
  "network_context": {
    "asn": "AS43350",
    "asn_organization": "NForce Entertainment B.V.",
    "isp": "NForce Entertainment B.V.",
    "approximate_country": "DE",
    "approximate_region": "Frankfurt, Germany",
    "confidence": "LOW_PHYSICAL_ATTRIBUTION"
  },
  "disclaimer": "Geolocation represents approximate network server routing path context, not verified criminal identity."
}
```

---

## 5. Evidence Vault & Cryptographic Hashes

- Every email generates SHA-256 fingerprints of:
  1. Complete raw email source (`raw_sha256`)
  2. Headers section (`headers_sha256`)
  3. Body content (`body_sha256`)
- Evidence entries are signed and persisted to `evidence_records` table by Member 5.
