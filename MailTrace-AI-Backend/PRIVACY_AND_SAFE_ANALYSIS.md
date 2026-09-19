# Privacy and Safe Analysis

## Principle

> **Analyze for security, not for curiosity.**

MailTrace should process only the information required to detect, classify and investigate email threats.

## Raw Email Content

Raw body, images and attachments may be processed transiently when required.

Default principles:

- minimize persistence
- avoid unnecessary logs
- avoid exposing raw content to dashboards
- use derived security features where possible
- use hashes/references for evidence
- apply explicit retention rules

## Security Tags

Tags must remain security-focused.

Good:

```text
New-Domain
DMARC-Fail
Suspicious-URL
Credential-Request
QR-Code
Phishing
```

Do not create unrelated tags from private content such as:

```text
Medical-Condition
Salary
Relationship
Personal-Preference
```

unless an explicit security requirement exists and policy permits it.

## Attachments

Do not execute untrusted files in the normal backend process.

Use:

```text
static analysis
→ reputation
→ isolated sandbox if required
```

## URLs

Do not automatically open suspicious URLs in the user's browser.

Use safe parsing, reputation, redirect inspection and an isolated browser/sandbox when deeper inspection is required.

## QR Codes

Decoded QR content is untrusted.

A QR URL follows the same URL analysis pipeline as a normal email URL.

## Evidence

Evidence records should include only what is necessary to support security/forensic analysis.

Use:

- SHA-256 hashes
- timestamps
- source metadata
- selected headers
- extracted security facts
- chain/event metadata

An evidence report should not be described as automatically “court-admissible” solely because ISO/IEC 27037 guidance was followed.

## GeoLocation

IP geolocation is approximate infrastructure context. It is not an exact physical-location or identity claim.

## Unknown Signals

Unknown reputation, unavailable APIs or missing context should be explicitly represented.

```text
UNKNOWN ≠ SAFE
```
