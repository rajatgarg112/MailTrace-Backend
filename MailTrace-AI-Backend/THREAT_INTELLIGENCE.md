# Threat Intelligence and External Signals

## Role

Threat intelligence strengthens MailTrace but does not replace the internal security pipeline.

## Signal Types

The platform may consume:

- sender reputation
- domain reputation
- IP reputation
- URL reputation
- attachment/hash reputation
- phishing databases
- malware databases
- abuse/blacklist feeds
- first-seen/last-seen context

## Provider Abstraction

Use adapters:

```text
ThreatIntelAdapter
├── Domain reputation provider
├── IP reputation provider
├── URL reputation provider
└── Hash reputation provider
```

Provider-specific logic should not be scattered through the gateway.

## Provider Failure

If a provider is unavailable:

```text
provider_status = UNAVAILABLE
```

Do not convert:

```text
UNAVAILABLE → SAFE
```

The remaining independent signals must still be evaluated.

## Reputation Is Not Verdict

A known-good reputation does not prove a message is safe.

A new/unknown domain does not prove it is malicious.

The risk engine should correlate reputation with:

- authentication
- domain age
- lookalike/typosquatting
- URL behavior
- content/NLP
- BEC indicators
- sender history
- behavioral anomalies
- user context
- attachment/QR findings

## Safe External Inspection

External URLs/files must be inspected only through safe mechanisms appropriate to their risk.

Never require the normal developer browser to open a suspicious URL merely to obtain a detection result.
