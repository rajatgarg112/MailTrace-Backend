# Threat Intelligence & Provider Adapter Specification

## 1. Subsystem Purpose

The Threat Intelligence subsystem (developed on `security` by Member 4) integrates external threat feeds (e.g., VirusTotal, AbuseIPDB, Quad9, Google Safe Browsing) to enrich IP, domain, and URL security evaluation.

---

## 2. Adapter Pattern Architecture

To prevent provider downtime or rate-limit exhaustion from impacting gateway processing, all threat intelligence services are implemented behind **Provider Adapters**:

```text
MailTrace Gateway Orchestrator (`main`)
                 │
                 ▼
Threat Intelligence Adapter Manager (`security`)
                 │
   ┌─────────────┼─────────────┐
   ▼             ▼             ▼
┌──────────────┐┌────────────┐┌──────────────┐
│ VirusTotal   ││ AbuseIPDB  ││ Local Cache  │
│ Adapter      ││ Adapter    ││ (Redis/Memory│
└──────────────┘└────────────┘└──────────────┘
```

---

## 3. Resilience Guidelines

1. **Strict Timeouts**: Every HTTP lookup to an external API must enforce a hard timeout of **1.5 to 2.5 seconds**.
2. **Local Caching**: Resolved IP and domain threat scores must be cached locally (TTL: 24 hours) to minimize API usage.
3. **Graceful Fallback**: If an external provider fails or times out:
   - Log the failure cleanly.
   - Return a result status of `PROVIDER_TIMEOUT` or `UNKNOWN`.
   - **Do not crash** the core pipeline execution.
