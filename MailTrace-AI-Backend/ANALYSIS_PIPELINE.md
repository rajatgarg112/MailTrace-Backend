# MailTrace-AI Analysis Pipeline

## Core Objective

MailTrace analyzes an incoming email **before normal user delivery**, correlates independent security signals and applies a backend-controlled delivery policy.

## Pipeline

```text
Incoming Email
      ↓
Gateway Ingestion
      ↓
Evidence Capture
      ↓
Parsing / Normalization
      ↓
┌─────────────────────────────────────────────┐
│ Parallel / Modular Security Analysis        │
│                                             │
│ Sender / Identity                           │
│ SPF / DKIM / DMARC                          │
│ Domain / Lookalike / Typosquatting          │
│ Headers / IP / Relay Chain                  │
│ URL / Redirect / Reputation                 │
│ Attachment Static Analysis                  │
│ Image / QR Detection                        │
│ NLP / Phishing / Spam                       │
│ BEC / Impersonation                         │
│ Behavioral / User Context                   │
│ Threat Intelligence                         │
└──────────────────────┬──────────────────────┘
                       ↓
              Canonical Features
                       ↓
               Security Tags
                       ↓
              Signal Correlation
                       ↓
              Risk Engine
                       ↓
       ┌───────────────┼────────────────┐
       ↓               ↓                ↓
 Classification     Score          Confidence
       └───────────────┼────────────────┘
                       ↓
                Delivery Policy
                       ↓
       ┌───────────────┼────────────────┐
       ↓               ↓                ↓
     Inbox            Spam         Warning/Hold
                                        │
                                        ↓
                                  Quarantine
                       ↓
               Events / Evidence
                       ↓
                 Frontend API
```

## Analyzer Output Contract

Each analyzer should return structured data, for example:

```json
{
  "analyzer": "url",
  "status": "SUCCESS",
  "features": {
    "url_count": 2,
    "suspicious_url_count": 1,
    "redirect_count": 2
  },
  "findings": [
    {
      "code": "SUSPICIOUS_URL",
      "severity": "HIGH"
    }
  ]
}
```

A failed external provider should produce an explicit unavailable/unknown state rather than a false safe result.

## Evidence

Evidence preservation should record appropriate:

- timestamps
- source metadata
- relevant headers
- hashes
- extracted facts
- analysis events

Avoid retaining raw human content unless required by the defined evidence/retention policy.

## URL Safety

```text
URL
 ↓
Parse
 ↓
Normalize
 ↓
Reputation / domain checks
 ↓
Redirect analysis
 ↓
Optional isolated browser/sandbox
 ↓
Findings
```

Never auto-open suspicious URLs in a user's normal browser.

## Attachment Safety

```text
Attachment
 ↓
Hash + metadata
 ↓
Magic bytes / MIME validation
 ↓
Static structure analysis
 ↓
Reputation
 ↓
Optional isolated sandbox
 ↓
Findings
```

Do not execute untrusted files in the normal application environment.

## QR Safety

```text
Image
 ↓
Detect QR
 ↓
Decode payload
 ↓
If URL → URL analysis
 ↓
Correlate with other email signals
```

QR payloads are untrusted input.

## Geo / Relay Analysis

Use email `Received`/trace information, IP/ASN, reverse DNS and related network evidence to derive approximate infrastructure context.

Do not claim that the first/earliest visible IP is automatically the attacker's physical location or identity.

## AI / ML

ML/NLP may provide:

- phishing score
- spam score
- urgency
- social engineering
- BEC/impersonation
- behavioral anomaly

These are signals to be correlated with non-ML evidence.

Do not allow a single model output to override all other security evidence without an explicit policy.
