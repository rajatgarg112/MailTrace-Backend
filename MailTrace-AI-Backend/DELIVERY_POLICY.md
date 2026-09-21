# Delivery Policy & Risk Decision Matrix Specification

## 1. Threat Classification vs. Delivery Action

MailTrace-AI maintains a strict conceptual separation between **Threat Classification** (security diagnosis) and **Delivery Action** (enforcement decision).

```text
Security Feature Matrix
          ↓
Security Tags Assignment
          ↓
Weighted Risk Score Calculation (0 - 100)
          ↓
Threat Classification (SAFE | SPAM | SUSPICIOUS | MALICIOUS | UNKNOWN)
          ↓
Delivery Policy Engine Enforcement (INBOX | SPAM | WARN | HOLD | QUARANTINE | REJECT)
```

---

## 2. Threat Classifications

1. **`SAFE`**: Email authentication passes; no malicious links, domain anomalies, or BEC indicators found.
2. **`SPAM`**: Unsolicited marketing, educational, bulk, or notification emails lacking targeted malicious payloads.
3. **`SUSPICIOUS`**: Moderate-risk emails featuring low domain age, unverified senders, or elevated urgency scores.
4. **`MALICIOUS`**: Confirmed phishing attacks, credential harvesters, lookalike domain spoofs, or severe BEC attempts.
5. **`UNKNOWN`**: Analysis incomplete due to missing headers, external provider timeouts, or unparseable payloads.

> [!IMPORTANT]
> **`UNKNOWN ≠ SAFE`**: An email with incomplete data must never be silently classified as `SAFE`. It retains an `UNKNOWN` status to maintain visibility for analysts.

---

## 3. Delivery Actions

1. **`INBOX`**: Delivered directly to user's primary inbox.
2. **`SPAM`**: Routed to user's Spam/Junk folder.
3. **`WARN`**: Delivered to inbox with prominent warning header banner attached.
4. **`HOLD`**: Temporarily held for analyst review or asynchronous sandboxing.
5. **`QUARANTINE`**: Isolated in Quarantine Vault; blocked from user inbox.
6. **`REJECT`**: Hard bounce / SMTP rejection at gateway level.

---

## 4. Policy Mapping Matrix

| Risk Score Range | Threat Classification | Default Delivery Action | Security Tags Included |
|---|---|---|---|
| $0 \le \text{Risk} \le 20$ | `SAFE` | `INBOX` | (None or minor informational tags) |
| $21 \le \text{Risk} \le 55$ | `SPAM` | `SPAM` | `BULK_MARKETING`, `UNSUBSCRIBE_LINK` |
| $56 \le \text{Risk} \le 75$ | `SUSPICIOUS` | `WARN` or `HOLD` | `NEW_DOMAIN`, `SPF_FAIL`, `HIGH_URGENCY` |
| $76 \le \text{Risk} \le 100$ | `MALICIOUS` | `QUARANTINE` or `REJECT` | `DMARC_FAIL`, `LOOKALIKE_DOMAIN`, `CREDENTIAL_INTENT` |
| (Any score with missing data) | `UNKNOWN` | `HOLD` | `ANALYSIS_TIMEOUT`, `MISSING_HEADERS` |

---

## 5. Spam Category Taxonomy

When an email is classified as `SPAM`, it is sub-categorized for analyst reporting:

- `MARKETING`: Unsolicited commercial promotions.
- `EDUCATION`: Educational newsletters or webinar invitations.
- `SOCIAL_NOTIFICATION`: Social media updates or digest summaries.
- `BULK`: Automated bulk mailers.
- `SCAM`: Fraudulent financial proposals or advance-fee scams.
- `FRAUD`: Fake invoice or bogus payment notifications.
- `OTHER`: Unclassified promotional mailers.
