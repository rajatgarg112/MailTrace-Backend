# Canonical Security Feature Schema Specification

## 1. Feature Matrix Purpose

The **Canonical Security Feature Schema** is the unified data model used to aggregate inputs from:
- `security` branch analyzers (Member 4 & Member 6)
- `ml` branch classifiers (Member 3)

The aggregated feature matrix is processed by the Risk Engine on `main` (Member 2) to calculate the Risk Score ($0-100$) and generate Security Tags.

---

## 2. Complete Pydantic Schema Blueprint (`app/models/feature_matrix.py`)

```python
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum

class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

class SecurityFeatureMatrix(BaseModel):
    email_id: str
    
    # Member 4: Authentication & Sender Features
    spf_status: AuthStatus = AuthStatus.UNKNOWN
    dkim_status: AuthStatus = AuthStatus.UNKNOWN
    dmarc_status: AuthStatus = AuthStatus.UNKNOWN
    display_name_spoofed: bool = False
    is_lookalike_domain: bool = False
    target_brand_domain: Optional[str] = None
    domain_age_days: Optional[int] = None
    suspicious_tld: bool = False
    
    # Member 4: Header & URL Features
    relay_hop_count: int = 0
    suspicious_relay_detected: bool = False
    total_urls_count: int = 0
    suspicious_urls_count: int = 0
    has_redirect_chain: bool = False
    anchor_text_mismatch: bool = False
    
    # Member 3: Machine Learning & NLP Features
    ml_phishing_prediction: str = "BENIGN"
    ml_phishing_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    ml_urgency_score: float = Field(default=0.0, ge=0.0, le=1.0)
    ml_financial_intent_score: float = Field(default=0.0, ge=0.0, le=1.0)
    ml_bec_impersonation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Member 6: Forensics & Infrastructure Features
    evidence_sha256: str
    originating_ip: str
    asn: Optional[str] = None
    approximate_region: Optional[str] = None
```

---

## 3. Normalized Security Tags Dictionary

When specific feature threshold conditions are met, the Correlation Engine assigns standardized security tags:

| Tag | Triggering Condition |
|---|---|
| `SPF_FAIL` | `spf_status == FAIL` |
| `DKIM_FAIL` | `dkim_status == FAIL` |
| `DMARC_FAIL` | `dmarc_status == FAIL` |
| `LOOKALIKE_DOMAIN` | `is_lookalike_domain == True` |
| `NEW_DOMAIN` | `domain_age_days < 30` |
| `SUSPICIOUS_URL` | `suspicious_urls_count > 0` |
| `REDIRECT_CHAIN` | `has_redirect_chain == True` |
| `HIGH_URGENCY` | `ml_urgency_score >= 0.80` |
| `CREDENTIAL_INTENT` | `ml_financial_intent_score >= 0.85` |
| `BEC_IMPERSONATION` | `ml_bec_impersonation_score >= 0.75` |
