# Machine Learning Workflow & AI Development Specification

## 1. Workstream Overview

- **Primary Owner**: Member 3 (ML / AI Engineer)
- **Repository**: `MailTrace-AI-Backend`
- **Permanent Branch**: `ml`
- **Core Folder Location**: `ml/`

The ML workstream is responsible for extracting natural language features, detecting Business Email Compromise (BEC) and impersonation tactics, identifying urgency/pressure sentiment, training classification models, and serving inference models to Core Backend `main`.

---

## 2. Directory Structure inside `ml/`

```text
ml/
├── classifiers/                # Core ML Classifier Implementations
│   ├── phishing_detector.py    # Phishing vs. Benign Text Classifier
│   ├── bec_detector.py         # Business Email Compromise / Impersonation Model
│   └── urgency_analyzer.py     # High-Pressure / Financial Intent Analyzer
│
├── features/                   # Feature Extraction & Data Preprocessing
│   ├── text_cleaner.py         # HTML Stripping & Normalization
│   ├── nlp_extractor.py        # TF-IDF / Embeddings Extraction
│   └── sentiment.py            # Urgency & Sentiment Scorer
│
├── inference/                  # Unified Inference Entrypoint
│   ├── runner.py               # Main Inference Runner (called by Backend main)
│   └── dto.py                  # ML Data Transfer Objects
│
├── training/                   # Model Training & Evaluation Scripts
│   ├── train_phishing.py       # Training Pipeline for Phishing Model
│   ├── train_bec.py            # Training Pipeline for BEC Model
│   └── evaluate.py             # Model Evaluation & Metrics Logger
│
├── artifacts/                  # Trained Model Weights & Metadata
│   ├── phishing_v1.pkl         # Serialized Classifier Weights
│   ├── bec_v1.pkl              # Serialized BEC Classifier Weights
│   └── metadata.json           # Model Version & Measured Metrics
│
└── config/                     # Configuration & Threshold Defaults
    └── ml_config.yaml          # Model Hyperparameters & Threshold Settings
```

---

## 3. Core Workflow Pipeline

```text
Raw Email Body & Subject
          ↓
HTML Stripping & Text Cleaning
          ↓
NLP Feature Extraction (Embeddings / Tokenization)
          ↓
Parallel Model Inference
┌───────────────────────────┴───────────────────────────┐
│                                                       │
▼                                                       ▼
Phishing Classifier                               BEC / Impersonation Detector
│                                                       │
└───────────────────────────┬───────────────────────────┘
          ↓
Feature Combination & Confidence Normalization
          ↓
Structured ML Output Payload → Backend main Gateway
```

---

## 4. Model Output Contract (`inference/runner.py`)

The ML subsystem must return structured Pydantic / JSON outputs adhering to the following schema:

```json
{
  "email_id": "eml_987654321",
  "prediction": "PHISHING",
  "confidence": 0.94,
  "model_version": "v1.2.0",
  "nlp_features": {
    "urgency_score": 0.89,
    "financial_intent_score": 0.92,
    "credential_harvesting_score": 0.95,
    "impersonation_score": 0.81
  },
  "detected_phrases": [
    "verify your account immediately",
    "wire transfer required within 24 hours"
  ]
}
```

---

## 5. Development & Metric Rigor Rules

1. **Empirical Metrics Only**: Never fabricate or hardcode accuracy, precision, recall, or F1 scores in documentation. Metrics logged must stem directly from `evaluate.py` execution against validated benchmarks.
2. **Lightweight & Fast Inference**: Models must execute inference within 500ms per email to prevent pipeline latency.
3. **Graceful Fallbacks**: If model weight loading fails or text input is unparseable, return neutral feature scores ($0.0$) and confidence $0.0$ with a status flag of `UNKNOWN`.
