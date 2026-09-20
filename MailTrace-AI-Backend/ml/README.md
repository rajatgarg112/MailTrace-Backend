# MailTrace-AI ML Engine (`ml` Branch)

## 1. Module Purpose

The **ML Engine** within `MailTrace-AI-Backend` provides specialized Machine Learning and Natural Language Processing security feature signals to the gateway analysis pipeline.

The ML engine extracts structured signals for:
- Phishing and spam intent scores
- Content entropy and language sentiment
- Business Email Compromise (BEC) & executive/brand impersonation indicators
- Behavioral volume, time, and geolocation anomalies

> **[IMPORTANT] Security Decision Boundaries**  
> The ML module provides feature signals and security findings. It **does NOT** make the final overall risk score, delivery action, quarantine, or message rejection decisions. Final risk scoring and delivery policy routing are strictly owned by the gateway orchestrator and risk engine in backend `main`.

---

## 2. Ownership Boundaries

### Owned Responsibilities
- Content & NLP feature extraction (`ml/nlp/`)
- Phishing and spam signal classification
- Business Email Compromise (BEC) and impersonation detection (`ml/bec/`)
- Behavioral anomaly feature extraction (`ml/behavioral/`)
- Text dataset preprocessing & normalization (`ml/datasets/`)
- ML model training & deterministic inference (`ml/models/`)
- Reproducible model evaluation tools (`ml/evaluation/`)
- ML-specific unit test suite (`ml/tests/`)

### Non-Owned Areas (Delegated to Backend `main` & `security` branches)
- Email Authentication (SPF, DKIM, DMARC)
- Email Header, IP, ASN, and Relay chain security
- URL parsing, redirect analysis, and link safety
- Domain age, lookalike, and typosquatting analysis
- Attachment static analysis and sandboxing
- Image processing and QR code payload decoding
- Threat intelligence feeds & reputation adapters
- Digital forensics and evidence persistence
- Database schemas and ORM ownership
- Final risk engine and Delivery policy routing

---

## 3. Directory Architecture

```text
MailTrace-AI-Backend/
└── ml/
    ├── __init__.py          # Package initialization
    ├── config.py            # ML thresholds, executive titles, brand targets, keyword lists
    ├── schemas.py           # Pydantic feature schemas & AnalyzerResult contract
    ├── nlp/
    │   ├── __init__.py
    │   ├── feature_extractor.py # Base NLP: text_entropy, language, sentiment, CTA, keywords
    │   ├── intent_classifier.py # Phishing, spam, urgency, fear, cred & fin request intent
    │   └── nlp_analyzer.py      # Main ContentNLPAnalyzer entrypoint
    ├── bec/
    │   ├── __init__.py
    │   ├── feature_extractor.py # Executive, brand, invoice, bank, gift card & convo hijacking features
    │   └── bec_analyzer.py      # Main BECAnalyzer entrypoint
    ├── behavioral/
    │   ├── __init__.py
    │   ├── feature_extractor.py # Volume, time, location, bulk & conversation anomaly features
    │   └── behavioral_analyzer.py # Main BehavioralAnalyzer entrypoint
    ├── models/
    │   ├── __init__.py
    │   ├── tfidf_classifier.py  # Multinomial Naive Bayes TF-IDF classifier
    │   └── rule_engine.py       # Shannon entropy, keyword density & heuristic rule functions
    ├── datasets/
    │   ├── __init__.py
    │   └── preprocessor.py      # HTML tag stripping, entity unescaping & reproducible train/test split
    ├── evaluation/
    │   ├── __init__.py
    │   └── evaluator.py         # Reproducible accuracy, precision, recall & F1 metric calculator
    └── tests/
        ├── __init__.py
        ├── test_nlp_analyzer.py
        ├── test_bec_analyzer.py
        ├── test_behavioral_analyzer.py
        ├── test_models.py
        └── test_evaluation.py
```

---

## 4. Canonical Feature Implementation

All features implemented in `ml/schemas.py` adhere strictly to the field names and data types defined in `SECURITY_FEATURE_SCHEMA.md`:

### Category 5: Content / NLP (`ContentNLPFeatures`)
| Field Name | Type | Value Range / Description |
| :--- | :--- | :--- |
| `spam_score` | `float` | `0.0` to `1.0` (Spam probability score) |
| `phishing_score` | `float` | `0.0` to `1.0` (Phishing language score) |
| `urgency_score` | `float` | `0.0` to `1.0` (High-pressure urgency language) |
| `fear_score` | `float` | `0.0` to `1.0` (Fear tactic / threat score) |
| `credential_request_score` | `float` | `0.0` to `1.0` (Password/login request score) |
| `financial_request_score` | `float` | `0.0` to `1.0` (Wire transfer/payment request score) |
| `social_engineering_score` | `float` | `0.0` to `1.0` (Combined social engineering score) |
| `impersonation_language_score`| `float` | `0.0` to `1.0` (Authority language score) |
| `call_to_action_score` | `float` | `0.0` to `1.0` (Intensity of action requests) |
| `suspicious_keyword_score` | `float` | `0.0` to `1.0` (Density of suspicious keywords) |
| `sentiment_score` | `float` | `-1.0` (Negative) to `1.0` (Positive) |
| `language` | `str` | ISO language code (`"en"`, `"non-en"`) |
| `text_entropy` | `float` | Shannon entropy of combined subject + body |

### Category 7: Behavioral (`BehavioralFeatures`)
| Field Name | Type | Value Range / Description |
| :--- | :--- | :--- |
| `sending_frequency` | `float` | Recent messages/day rate |
| `volume_anomaly` | `float` | `0.0` to `1.0` (Volume spike score vs baseline) |
| `time_anomaly` | `float` | `0.0` to `1.0` (Sending off-hours score) |
| `location_anomaly` | `float` | `0.0` to `1.0` (Unusual originating country score) |
| `sender_behavior_change` | `float` | `0.0` to `1.0` (Combined anomaly delta) |
| `conversation_anomaly` | `float` | `0.0` to `1.0` (Unsolicited bulk send to new targets) |
| `recipient_count` | `int` | Number of email recipients (`>= 1`) |
| `bulk_score` | `float` | `0.0` to `1.0` (Mass distribution score) |
| `historical_similarity` | `float` | `0.0` (New sender) to `1.0` (Known baseline) |
| `conversation_exists` | `bool` | `True` if prior email thread history exists |

### Category 10: BEC / Impersonation (`BECFeatures`)
| Field Name | Type | Value Range / Description |
| :--- | :--- | :--- |
| `executive_impersonation_score` | `float` | `0.0` to `1.0` (Executive title vs freemail sender) |
| `brand_impersonation_score` | `float` | `0.0` to `1.0` (Brand mention vs sender domain) |
| `payment_request_score` | `float` | `0.0` to `1.0` (Wire/ACH payment request score) |
| `invoice_request_score` | `float` | `0.0` to `1.0` (Overdue/attached invoice score) |
| `bank_account_change_score` | `float` | `0.0` to `1.0` (Direct deposit/account change score) |
| `gift_card_request_score` | `float` | `0.0` to `1.0` (Gift card purchase request score) |
| `urgency_score` | `float` | `0.0` to `1.0` (High-pressure timing score) |
| `conversation_hijacking_score` | `float` | `0.0` to `1.0` (Mismatched reply-to or hijacked thread) |
| `authority_impersonation_score` | `float` | `0.0` to `1.0` (Corporate authority pressure score) |

---

## 5. Analyzer Contract Interface

All analyzers output a standard `AnalyzerResult` object as defined in `ANALYSIS_PIPELINE.md`:

```json
{
  "analyzer": "ml_nlp",
  "status": "SUCCESS",
  "features": {
    "phishing_score": 0.85,
    "credential_request_score": 0.72,
    "urgency_score": 0.80
  },
  "findings": [
    {
      "code": "CREDENTIAL_HARVESTING_LANGUAGE",
      "severity": "HIGH",
      "details": "Email content explicitly requests login or credential updates."
    }
  ],
  "error_message": null
}
```

### Supported Statuses
- `"SUCCESS"`: Processing completed cleanly.
- `"UNAVAILABLE"`: Historical context or model required for processing is offline or disabled.
- `"ERROR"`: Unhandled exception caught; safe fallback features returned.

### Supported Severity Levels
- `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`

---

## 6. NLP Analyzer (`ContentNLPAnalyzer`)

The `ContentNLPAnalyzer` processes raw email subject lines and body text to generate Category 5 features:
1. **Structural Text Analysis:** Computes Shannon entropy (`text_entropy`) to measure obfuscation/randomness and performs basic language detection (`language`).
2. **Sentiment Lexicon:** Scores text sentiment between `-1.0` (threatening/hostile) and `1.0` (positive).
3. **Pattern Extractors:** Measures suspicious keyword density (`suspicious_keyword_score`) and Call-To-Action intensity (`call_to_action_score`).
4. **Intent Classification:** Combines Multinomial Naive Bayes model predictions with rule-engine scores to estimate `phishing_score`, `spam_score`, `urgency_score`, `fear_score`, `credential_request_score`, `financial_request_score`, `social_engineering_score`, and `impersonation_language_score`.

---

## 7. BEC / Impersonation Analyzer (`BECAnalyzer`)

The `BECAnalyzer` evaluates display names, sender email addresses, reply-to headers, and content text for Business Email Compromise:
- **Executive Impersonation:** Cross-references executive titles (CEO, CFO, Director, etc.) against generic/freemail sender domains (`@gmail.com`, `@yahoo.com`).
- **Brand Impersonation:** Detects corporate brand mentions (Microsoft, Google, DocuSign, PayPal, etc.) originating from non-brand domains.
- **Financial Fraud Targets:** Identifies specific high-risk solicitations: wire transfer requests, invoice payments, direct deposit/bank account change requests, and gift card purchase requests.
- **Conversation Hijacking:** Detects artificial `Re:` / `Fwd:` thread prefixes coupled with mismatched `reply-to` addresses.

---

## 8. Behavioral Analyzer (`BehavioralAnalyzer`)

The `BehavioralAnalyzer` compares incoming message distribution metadata against historical sender profile baselines (`sender_history`):
- **Volume Anomaly:** Identifies sudden sending volume spikes (>3x baseline rate).
- **Time Anomaly:** Flags messages dispatched outside the sender's established active hours.
- **Location Anomaly:** Flags messages sent from uncharacteristic originating countries.
- **Bulk Email Identification:** Computes mass recipient distribution scores (`bulk_score`).

> **[NOTE] Safe Baseline Handling**  
> If sender history is unavailable or first seen (`seen_before: False`), the analyzer **does not** falsely fabricate anomaly flags. Anomaly features default to `0.0` and `historical_similarity` is set to `0.0` to indicate a new sender profile.

---

## 9. ML Classifier Model (`SimpleTFIDFClassifier`)

`ml/models/tfidf_classifier.py` provides a lightweight, dependency-free text classification model:
- **Algorithm:** Multinomial Naive Bayes with Term Frequency-Inverse Document Frequency (TF-IDF) feature weighting.
- **N-Gram Tokenization:** Optional `ngram_range` parameter (`(1, 1)` default unigrams, `(1, 2)` unigrams + bigrams) for capturing multi-word context phrases while remaining 100% dependency-free.
- **Smoothing:** Applies Laplace smoothing and log-softmax conversion for probability distributions (`predict_proba`).
- **Training:** Exposes `train(documents, labels)` for online or batch training on text datasets.
- **Determinism:** Tokenization, vocabulary mapping, and inference are strictly deterministic.

---

## 10. Rule & Heuristic Engine (`ml/models/rule_engine.py`)

Deterministic helper functions used for feature extraction:
- `calculate_shannon_entropy(text)`: Measures text character entropy.
- `match_keyword_density(text, keywords)`: Exponentially scaled keyword density ratio.
- `detect_call_to_action(text)`: Regex pattern matching for high-pressure action verbs.
- `detect_social_engineering_tactics(text)`: Keyword pattern matching for urgency, fear, and authority tactics.

---

## 11. Dataset & Preprocessing (`ml/datasets/`)

- `clean_html_and_normalize(raw_text)`: Strips block-level HTML tags with space separation and inline tags without space, unescapes HTML entities (`html.unescape`), and normalizes whitespace while preserving security-critical punctuation, numbers, and currency tokens.
- `DatasetRecord`: Pydantic schema for validating record text non-emptiness and target label schema (`phishing`, `spam`, `benign`).
- `DatasetLoader`: Utilities to load and validate structured records from Python tuples, dictionaries, or JSON payloads (`from_tuples`, `from_dicts`, `from_json_string`).
- `prepare_dataset_split(samples, train_ratio, seed)`: 2-way reproducible dataset splitter (backward compatible).
- `split_dataset_3way(samples, train_ratio, val_ratio, test_ratio, seed, deduplicate)`: 3-way reproducible train/validation/test splitter with ratio validation and automatic deduplication across partitions to prevent data leakage.

> **[NOTE] Data Leakage Prevention & Dataset Status**
> To prevent data leakage, identical duplicate records across splits are filtered out via `deduplicate_samples()` prior to partitioning. Vocabulary and IDF statistics are derived strictly from training sets. No external static production dataset file (e.g. large CSV/JSON corpus) is committed in `ml/datasets/`; real external datasets can be ingested at runtime via `DatasetLoader`.

---

## 12. Model Evaluation (`ml/evaluation/evaluator.py`)

`evaluate_predictions(y_true, y_pred, positive_label)` calculates classification metrics directly from true and predicted label lists:
- **Metrics Calculated:** Accuracy, Precision, Recall, F1 Score, True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN).
- Contains no hard-coded or fabricated metrics; handles zero-division safely.

---

## 13. Security & Safe Content Analysis

The ML module adheres to privacy and security requirements:
- **No Unsafe Execution:** Suspicious URLs are treated as plain text and never opened; attachments are never executed.
- **No Credential Access:** Analyzers process only email strings and metadata; no API keys or environment secrets are exposed.
- **Privacy Minimization:** Raw email bodies are analyzed transiently and are not logged to console output.

---

## 14. Testing Suite

The unit test suite under `ml/tests/` verifies all analyzers, models, preprocessing utilities, dataset loading, data leakage safeguards, n-gram tokenization, and evaluation metrics:

```bash
python -m pytest ml/tests/
```

**Verified Test Summary:** 34 passed in 0.31s (14 baseline analyzer tests + 10 dataset pipeline tests + 10 feature engineering tests).

---

## 15. Usage Examples

```python
from ml.nlp.nlp_analyzer import ContentNLPAnalyzer
from ml.bec.bec_analyzer import BECAnalyzer
from ml.behavioral.behavioral_analyzer import BehavioralAnalyzer
from ml.datasets.dataset_loader import DatasetLoader
from ml.datasets.preprocessor import split_dataset_3way

# 1. Loading & Splitting a Dataset reproducibly
raw_samples = [
    ("Urgent: reset your password immediately", "phishing"),
    ("Weekly team status report attached", "benign"),
    ("Exclusive discount offer claim now", "spam")
]
records = DatasetLoader.from_tuples(raw_samples)
splits = split_dataset_3way(raw_samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42)
print(f"Train samples: {len(splits.train_text)}, Val: {len(splits.val_text)}, Test: {len(splits.test_text)}")

# 2. Content / NLP Analysis
nlp_analyzer = ContentNLPAnalyzer()
nlp_res = nlp_analyzer.analyze(
    subject="URGENT: Password Reset Required",
    body="Your account is suspended. Click here to verify your credentials immediately."
)
print("Phishing Score:", nlp_res.features["phishing_score"])
print("Findings:", [f.code for f in nlp_res.findings])

# 2. BEC / Impersonation Analysis
bec_analyzer = BECAnalyzer()
bec_res = bec_analyzer.analyze(
    display_name="CEO John Smith",
    from_address="john.smith.ceo123@gmail.com",
    subject="Urgent wire transfer",
    body="Please wire $50,000 to this vendor account ASAP."
)
print("Executive Impersonation Score:", bec_res.features["executive_impersonation_score"])

# 3. Behavioral Analysis
behavioral_analyzer = BehavioralAnalyzer()
behavioral_res = behavioral_analyzer.analyze(
    sender_address="alice@company.com",
    recipient_count=1,
    sender_history={"seen_before": True, "avg_daily_volume": 5.0, "recent_volume": 4.0}
)
print("Volume Anomaly:", behavioral_res.features["volume_anomaly"])
```

---

## 16. Current Limitations

1. **Production Corpus:** No large external static benchmark dataset is committed in `ml/datasets/`; models run on seed vectors.
2. **Heuristic Signals:** Rule-based functions rely on curated keyword patterns and regex heuristics.
3. **Behavioral Baseline Dependency:** Behavioral anomaly detection relies on historical profile metrics passed into the analyzer by the backend host process.
4. **Independent Signals:** ML outputs are security features and must be correlated with non-ML signals by the risk engine.
