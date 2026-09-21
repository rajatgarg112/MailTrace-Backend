"""
Configuration & Threshold Constants for ML/AI Analyzers.
"""

from typing import Dict, List

# Thresholds for findings generation
THRESHOLD_PHISHING_HIGH = 0.75
THRESHOLD_PHISHING_MEDIUM = 0.50

THRESHOLD_SPAM_HIGH = 0.75
THRESHOLD_SPAM_MEDIUM = 0.50

THRESHOLD_URGENCY_HIGH = 0.70

THRESHOLD_BEC_HIGH = 0.70
THRESHOLD_BEC_MEDIUM = 0.40

THRESHOLD_BEHAVIORAL_ANOMALY = 0.65

# Executive titles for BEC matching
EXECUTIVE_TITLES: List[str] = [
    "ceo", "chief executive officer",
    "cfo", "chief financial officer",
    "coo", "chief operating officer",
    "cto", "chief technology officer",
    "cio", "chief information officer",
    "ciso", "chief information security officer",
    "cro", "chief risk officer",
    "president", "vice president", "vp",
    "director", "managing director", "general manager",
    "founder", "co-founder", "chairman", "head of finance"
]

# Impersonated brand targets
COMMON_TARGET_BRANDS: List[str] = [
    "microsoft", "office365", "outlook", "sharepoint", "google", "workspace",
    "apple", "paypal", "stripe", "docusign", "dropbox", "box", "salesforce",
    "adobe", "zoom", "quickbooks", "intuit", "workday", "slack",
    "wellsfargo", "chase", "bankofamerica", "amazon", "netflix", "dhl", "fedex", "ups"
]

# Keywords triggering specific intent categories
KEYWORDS_CREDENTIAL_REQUEST: List[str] = [
    "password", "passcode", "verify your account", "confirm credentials",
    "login to restore", "security update required", "reset your password",
    "sign in immediately", "update payment method", "account suspended",
    "login activity", "verify identity", "account verification",
    "update security information", "credential confirmation", "authenticate your account"
]

KEYWORDS_FINANCIAL_REQUEST: List[str] = [
    "wire transfer", "bank transfer", "invoice attached", "overdue payment",
    "outstanding balance", "remittance", "gift card", "apple gift card",
    "steam card", "direct deposit", "routing number", "account detail update",
    "wire transfer instructions", "payment processing", "past due invoice",
    "update billing details", "remittance advice", "ach payment", "purchase order"
]

KEYWORDS_URGENCY: List[str] = [
    "urgent", "immediately", "action required", "within 24 hours", "asap",
    "time sensitive", "account deletion pending", "unauthorized login",
    "final notice", "deadline", "important update", "immediate response required",
    "within 12 hours", "expires today", "urgent request", "time-sensitive notice", "act immediately"
]

KEYWORDS_FEAR: List[str] = [
    "suspended", "blocked", "terminated", "legal action", "lawsuit",
    "unauthorized access", "unauthorized transaction", "compromised",
    "account termination", "legal proceedings", "suspicious activity detected",
    "unauthorized transaction attempt", "security alert", "service suspension"
]
