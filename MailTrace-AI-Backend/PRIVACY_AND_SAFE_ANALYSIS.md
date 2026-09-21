# Privacy Preservation & Safe Untrusted Content Analysis Specification

## 1. Untrusted Content Isolation Principles

Emails processed by MailTrace-AI contain untrusted text, headers, links, and attachments. All analysis modules must enforce strict isolation boundaries:

1. **Zero Execution of Attachments**: Attachments are analyzed strictly via static inspection (MIME type verification, file hash lookup, header byte checks). No code execution occurs on the backend host.
2. **Safe URL Unshortening**: Link expansion engines must disallow downloading binary files or executing client-side JavaScript. HTTP `HEAD` requests are preferred over `GET` requests where supported.
3. **Data Sanitization**: Before storing email body contents or passing text to NLP models, HTML tags, script elements, and embedded tracking pixels must be stripped.

---

## 2. Privacy & PII Preservation

1. **Credentials & Token Scrubbing**: Password fields, OAuth tokens, and session cookies contained in email body text must be redacted prior to database persistence.
2. **Database Encryption**: Sensitive fields (e.g., raw email contents) should be encrypted at rest when stored in database columns.
3. **Internal Log Hygiene**: Debug log output must never contain raw user passwords, authentication headers, or unsanitized email body text.
