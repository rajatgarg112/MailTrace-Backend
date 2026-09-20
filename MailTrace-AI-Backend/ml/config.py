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
    "president", "vice president", "vp",
    "director", "managing director",
    "founder", "co-founder", "chairman"
]

# Impersonated brand targets
COMMON_TARGET_BRANDS: List[str] = [
    "microsoft", "office365", "google", "workspace", "apple", "paypal",
    "stripe", "docusign", "dropbox", "wellsfargo", "chase", "bankofamerica",
    "amazon", "netflix", "dhl", "fedex", "ups"
]

# Keywords triggering specific intent categories
KEYWORDS_CREDENTIAL_REQUEST: List[str] = [
    "password", "passcode", "verify your account", "confirm credentials",
    "login to restore", "security update required", "reset your password",
    "sign in immediately", "update payment method", "account suspended"
]

KEYWORDS_FINANCIAL_REQUEST: List[str] = [
    "wire transfer", "bank transfer", "invoice attached", "overdue payment",
    "outstanding balance", "remittance", "gift card", "apple gift card",
    "steam card", "direct deposit", "routing number", "account detail update"
]

KEYWORDS_URGENCY: List[str] = [
    "urgent", "immediately", "action required", "within 24 hours", "asap",
    "time sensitive", "account deletion pending", "unauthorized login",
    "final notice", "deadline", "important update"
]

KEYWORDS_FEAR: List[str] = [
    "suspended", "blocked", "terminated", "legal action", "lawsuit",
    "unauthorized access", "unauthorized transaction", "compromised"
]
