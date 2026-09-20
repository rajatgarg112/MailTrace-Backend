"""
Unit tests for STEP 3.1: Feature Engineering Enhancements.
Verifies continuous scaling, expanded vocabulary, n-gram tokenization, and bounds compliance.
"""

import unittest
from ml.models.tfidf_classifier import SimpleTFIDFClassifier
from ml.nlp.feature_extractor import extract_nlp_base_features
from ml.bec.feature_extractor import extract_bec_features
from ml.behavioral.feature_extractor import extract_behavioral_features
from ml.nlp.nlp_analyzer import ContentNLPAnalyzer
from ml.bec.bec_analyzer import BECAnalyzer


class TestFeatureEngineeringEnhancements(unittest.TestCase):

    def test_1_continuous_scaling_smoothness(self):
        # Recipient count continuous bulk score
        b1 = extract_behavioral_features(recipient_count=1)["bulk_score"]
        b5 = extract_behavioral_features(recipient_count=5)["bulk_score"]
        b20 = extract_behavioral_features(recipient_count=20)["bulk_score"]
        b100 = extract_behavioral_features(recipient_count=100)["bulk_score"]

        self.assertEqual(b1, 0.0)
        self.assertLess(b1, b5)
        self.assertLess(b5, b20)
        self.assertLess(b20, b100)

    def test_2_scaling_bounds_compliance(self):
        # Test extreme volume anomaly ratios
        history = {"seen_before": True, "avg_daily_volume": 1.0, "recent_volume": 1000.0}
        feats = extract_behavioral_features(sender_history=history)
        self.assertGreaterEqual(feats["volume_anomaly"], 0.0)
        self.assertLessEqual(feats["volume_anomaly"], 1.0)

    def test_3_neutral_input_produces_valid_output(self):
        feats = extract_nlp_base_features("", "")
        self.assertEqual(feats["text_entropy"], 0.0)
        self.assertEqual(feats["suspicious_keyword_score"], 0.0)
        self.assertEqual(feats["call_to_action_score"], 0.0)

    def test_4_expanded_nlp_vocabulary(self):
        # Expanded vocabulary phrase: "authenticate your account"
        f1 = extract_nlp_base_features("Notice", "Please authenticate your account to verify identity.")
        self.assertGreater(f1["suspicious_keyword_score"], 0.0)

    def test_5_expanded_bec_vocabulary(self):
        # Expanded brand: "salesforce", expanded title: "ciso"
        res = extract_bec_features(
            display_name="CISO Jane Doe",
            from_address="jane.ciso@gmail.com",
            subject="Urgent Salesforce login audit",
            body="Review wire transfer instructions attached."
        )
        self.assertGreaterEqual(res["executive_impersonation_score"], 0.70)
        self.assertGreaterEqual(res["brand_impersonation_score"], 0.70)

    def test_6_no_unrelated_feature_triggered(self):
        res = extract_bec_features(
            display_name="Alice Smith",
            from_address="alice@company.com",
            subject="Lunch tomorrow",
            body="Let's grab pizza at noon."
        )
        self.assertEqual(res["executive_impersonation_score"], 0.0)
        self.assertEqual(res["payment_request_score"], 0.0)
        self.assertEqual(res["gift_card_request_score"], 0.0)

    def test_7_ngram_unigram_baseline_preservation(self):
        clf1 = SimpleTFIDFClassifier(ngram_range=(1, 1))
        tokens = clf1._tokenize("verify your password reset")
        self.assertEqual(tokens, ["verify", "your", "password", "reset"])

    def test_8_ngram_bigram_feature_generation(self):
        clf2 = SimpleTFIDFClassifier(ngram_range=(1, 2))
        tokens = clf2._tokenize("verify your password")
        self.assertEqual(tokens, ["verify", "your", "password", "verify_your", "your_password"])

    def test_9_classifier_ngram_determinism(self):
        clf = SimpleTFIDFClassifier(ngram_range=(1, 2))
        docs = ["reset your password immediately", "weekly project status report"]
        labels = ["phishing", "benign"]
        clf.train(docs, labels)
        
        p1 = clf.predict_proba("reset your password immediately")
        p2 = clf.predict_proba("reset your password immediately")
        self.assertEqual(p1, p2)

    def test_10_classifier_handles_unknown_vocab_safely(self):
        clf = SimpleTFIDFClassifier(ngram_range=(1, 2))
        docs = ["phishing text", "benign text"]
        labels = ["phishing", "benign"]
        clf.train(docs, labels)

        probs = clf.predict_proba("unknown xyz123 non_existent_token")
        self.assertIn("phishing", probs)
        self.assertIn("benign", probs)


if __name__ == "__main__":
    unittest.main()
