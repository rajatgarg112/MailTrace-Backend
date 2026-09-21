"""
NLP Intent Classifier.
Computes intent scores: phishing_score, spam_score, urgency_score, fear_score,
credential_request_score, financial_request_score, social_engineering_score, impersonation_language_score.
"""

from typing import Dict, Any
from ml.config import KEYWORDS_CREDENTIAL_REQUEST, KEYWORDS_FINANCIAL_REQUEST
from ml.models.rule_engine import match_keyword_density, detect_social_engineering_tactics
from ml.models.tfidf_classifier import SimpleTFIDFClassifier


class IntentClassifier:
    """Classifies text into security intent categories."""

    def __init__(self, classifier_model: SimpleTFIDFClassifier = None):
        self.model = classifier_model or SimpleTFIDFClassifier()
        if not self.model.is_trained:
            self._bootstrap_default_model()

    def _bootstrap_default_model(self):
        """Train default model on representative synthetic sample vectors."""
        docs = [
            "Your account is suspended. Click here to verify credentials and password immediately.",
            "Wire transfer needed for invoice payment. Update bank account details ASAP.",
            "Weekly team meeting sync notes and project updates attached for review.",
            "Exclusive discount offer! Claim your free coupon now before deal expires.",
            "Urgent: Security alert regarding your Office365 password reset request.",
            "Hi, please find attached the monthly newsletter and community updates."
        ]
        labels = ["phishing", "phishing", "benign", "spam", "phishing", "benign"]
        self.model.train(docs, labels)

    def classify_intent(self, subject: str, body: str, cta_score: float) -> Dict[str, float]:
        full_text = f"{subject}\n{body}".strip()

        # Model inference probabilities
        probs = self.model.predict_proba(full_text)
        model_phishing = probs.get("phishing", 0.0)
        model_spam = probs.get("spam", 0.0)

        # Keyword & pattern scores
        cred_score = match_keyword_density(full_text, KEYWORDS_CREDENTIAL_REQUEST)
        fin_score = match_keyword_density(full_text, KEYWORDS_FINANCIAL_REQUEST)
        urgency_score, fear_score, authority_score = detect_social_engineering_tactics(full_text)

        # Social Engineering combined score
        social_eng_score = round(min(1.0, 0.4 * urgency_score + 0.3 * fear_score + 0.3 * cta_score), 4)

        # Impersonation language score
        impersonation_lang_score = round(min(1.0, 0.5 * authority_score + 0.5 * cred_score), 4)

        # Combined Phishing & Spam scores
        phishing_score = round(min(1.0, max(model_phishing, 0.5 * cred_score + 0.3 * cta_score + 0.2 * social_eng_score)), 4)
        spam_score = round(min(1.0, max(model_spam, 0.4 * cta_score + 0.3 * urgency_score)), 4)

        return {
            "spam_score": spam_score,
            "phishing_score": phishing_score,
            "urgency_score": urgency_score,
            "fear_score": fear_score,
            "credential_request_score": cred_score,
            "financial_request_score": fin_score,
            "social_engineering_score": social_eng_score,
            "impersonation_language_score": impersonation_lang_score
        }
