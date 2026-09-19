# Canonical Security Feature Schema

This document defines the canonical feature layer for MailTrace-AI.

The 13 categories are logical groups. Duplicate concepts must be canonicalized rather than stored as unrelated duplicate fields.

## 1. Sender / Identity

```text
sender_address
display_name
reply_to
from_domain
domain_age
domain_reputation
sender_reputation
sender_first_seen
sender_frequency
impersonation_score
sender_seen_before
sender_in_contacts
```

## 2. Email Authentication

```text
spf
dkim
dmarc
spf_alignment
dkim_alignment
dmarc_alignment
dmarc_policy
authentication_consistency
```

Authentication results are signals, not proof that an account is uncompromised or that a message is benign.

## 3. Domain

```text
domain_age
domain_reputation
domain_registration_date
domain_expiry_date
domain_whois_status
domain_tld
subdomain_depth
lookalike_domain_score
typosquatting_score
```

## 4. URL / Link

```text
url_count
suspicious_url_count
url_reputation
domain_mismatch
url_shortener
redirect_count
final_destination_url
https_status
punycode_detected
ip_based_url
suspicious_tld
malicious_domain_match
url_entropy
```

Suspicious URLs must not be opened directly in the user's/developer's normal browser.

## 5. Content / NLP

```text
spam_score
phishing_score
urgency_score
fear_score
credential_request_score
financial_request_score
social_engineering_score
impersonation_language_score
call_to_action_score
suspicious_keyword_score
sentiment_score
language
text_entropy
```

## 6. Email Headers

```text
originating_ip
sender_ip
ip_reputation
reverse_dns
helo_hostname
received_hops
hop_count
sending_server
asn
geolocation
tls_status
mail_server_reputation
```

Geolocation is approximate infrastructure context.

## 7. Behavioral

```text
sending_frequency
volume_anomaly
time_anomaly
location_anomaly
sender_behavior_change
conversation_anomaly
recipient_count
bulk_score
historical_similarity
conversation_exists
```

## 8. Attachment

```text
attachment_count
attachment_type
attachment_size
file_extension
mime_type
mime_type_mismatch
double_extension
executable_detected
macro_detected
archive_detected
password_protected_archive
malware_hash_match
attachment_reputation
sandbox_score
```

Recommended static checks include filename, MIME type, file signature/magic bytes, size, hashes and structure.

Untrusted files must not be executed in the normal backend runtime.

## 9. QR Code

```text
qr_present
qr_count
qr_decoded
qr_destination_url
qr_domain
qr_domain_reputation
qr_domain_age
qr_url_mismatch
qr_redirect_count
qr_phishing_score
```

QR workflow:

```text
Image
 ↓
QR detection
 ↓
Decode payload
 ↓
If URL → URL/domain security pipeline
 ↓
Risk correlation
```

Do not directly open a decoded URL.

## 10. BEC / Impersonation

```text
executive_impersonation_score
brand_impersonation_score
payment_request_score
invoice_request_score
bank_account_change_score
gift_card_request_score
urgency_score
conversation_hijacking_score
authority_impersonation_score
```

## 11. Reputation / Threat Intelligence

```text
sender_reputation
domain_reputation
ip_reputation
url_reputation
attachment_reputation
threat_intelligence_match
blacklist_match
malware_database_match
phishing_database_match
abuse_database_match
first_seen
last_seen
```

An unavailable or unknown reputation must remain `UNKNOWN`; it must not silently become `SAFE`.

## 12. User / Organization Context

```text
sender_seen_before
domain_seen_before
user_replied_before
sender_in_contacts
domain_in_contacts
previous_email_count
previous_email_similarity
trusted_sender
internal_sender
external_sender
```

## 13. Final Scores

```text
spam_score
phishing_score
malware_score
bec_score
impersonation_score
overall_risk_score
threat_confidence
threat_category
risk_level
```

Final scores are decision-layer outputs and should not be confused with raw features.

---

## Canonical Layering

```text
13 Feature Categories
        ↓
Security Tags
        ↓
Risk Engine
        ↓
Threat Classification
        ↓
Delivery Action
```

## Example

```json
{
  "features": {
    "domain_age": 3,
    "dmarc": "FAIL",
    "credential_request_score": 0.92,
    "suspicious_url_count": 2
  },
  "tags": [
    "NEW_DOMAIN",
    "DMARC_FAIL",
    "CREDENTIAL_REQUEST",
    "SUSPICIOUS_URL"
  ],
  "risk": {
    "overall_risk_score": 91,
    "threat_confidence": 0.94,
    "threat_category": "PHISHING",
    "risk_level": "HIGH"
  },
  "delivery_action": "QUARANTINE"
}
```
