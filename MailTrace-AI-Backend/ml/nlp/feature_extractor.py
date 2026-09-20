"""
Content / NLP Feature Extractor.
Extracts text_entropy, language, sentiment_score, suspicious_keyword_score, and call_to_action_score.
"""

import re
from typing import Dict, Any
from ml.config import KEYWORDS_CREDENTIAL_REQUEST, KEYWORDS_FINANCIAL_REQUEST, KEYWORDS_URGENCY, KEYWORDS_FEAR
from ml.models.rule_engine import calculate_shannon_entropy, match_keyword_density, detect_call_to_action


def extract_nlp_base_features(subject: str, body: str) -> Dict[str, Any]:
    """
    Extract base structural and NLP features from subject and body.
    """
    full_text = f"{subject}\n{body}".strip()

    # 1. Text Entropy
    text_entropy = calculate_shannon_entropy(full_text)

    # 2. Language Detection (simple heuristic detector default to 'en')
    language = detect_language(full_text)

    # 3. Suspicious Keyword Score
    all_keywords = KEYWORDS_CREDENTIAL_REQUEST + KEYWORDS_FINANCIAL_REQUEST + KEYWORDS_URGENCY + KEYWORDS_FEAR
    suspicious_keyword_score = match_keyword_density(full_text, all_keywords)

    # 4. Call to Action Score
    call_to_action_score = detect_call_to_action(full_text)

    # 5. Sentiment Score (-1.0 negative/threatening to 1.0 positive/friendly)
    sentiment_score = calculate_simple_sentiment(full_text)

    return {
        "text_entropy": text_entropy,
        "language": language,
        "suspicious_keyword_score": suspicious_keyword_score,
        "call_to_action_score": call_to_action_score,
        "sentiment_score": sentiment_score
    }


def detect_language(text: str) -> str:
    """Basic language detector (defaults to 'en')."""
    if not text:
        return "en"
    # Basic check for non-ASCII ratio
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii / max(1, len(text)) > 0.4:
        return "non-en"
    return "en"


def calculate_simple_sentiment(text: str) -> float:
    """Simple sentiment lexicon scoring between -1.0 and 1.0."""
    positive_words = ["thank", "kindly", "appreciate", "welcome", "good", "great", "please", "help"]
    negative_words = ["urgent", "fail", "error", "suspend", "threat", "cancel", "penalty", "block", "deny"]

    text_lower = text.lower()
    pos_count = sum(1 for w in positive_words if w in text_lower)
    neg_count = sum(1 for w in negative_words if w in text_lower)

    total = pos_count + neg_count
    if total == 0:
        return 0.0
    return round((pos_count - neg_count) / total, 4)
