"""
Unit tests for ML Inference Contract & Unified Engine Entrypoint (ml/engine.py).
"""

import unittest
from ml.schemas import MLPredictionResult, MLEngineResult, AnalyzerResult
from ml.models.tfidf_classifier import SimpleTFIDFClassifier
from ml.engine import analyze_email_ml


class TestInferenceEngine(unittest.TestCase):

    def test_ml_prediction_result_schema_validation(self):
        """Test MLPredictionResult fields, bounding, and validation."""
        result = MLPredictionResult(
            prediction="phishing",
            confidence=0.85432,
            model_version="1.0",
            probabilities={"phishing": 0.85432, "benign": 0.1, "spam": 0.04568}
        )

        self.assertEqual(result.prediction, "phishing")
        self.assertEqual(result.confidence, 0.8543)
        self.assertEqual(result.model_version, "1.0")
        self.assertIn("phishing", result.probabilities)

        # Invalid confidence bounds raise ValueError
        with self.assertRaises(ValueError):
            MLPredictionResult(prediction="phishing", confidence=1.5)

        with self.assertRaises(ValueError):
            MLPredictionResult(prediction="phishing", confidence=-0.1)

    def test_simple_tfidf_classifier_predict_helper(self):
        """Test SimpleTFIDFClassifier.predict() helper behavior."""
        docs = [
            "Verify your account password immediately",
            "Weekly team status meeting notes",
            "Claim your exclusive free gift card coupon"
        ]
        labels = ["phishing", "benign", "spam"]

        clf = SimpleTFIDFClassifier(ngram_range=(1, 1), model_version="1.0")
        clf.train(docs, labels)

        # Confirm predict() returns valid MLPredictionResult matching highest predict_proba()
        res = clf.predict("Verify password immediately")
        probs = clf.predict_proba("Verify password immediately")
        max_class = max(probs, key=probs.get)

        self.assertIsInstance(res, MLPredictionResult)
        self.assertEqual(res.prediction, max_class)
        self.assertEqual(res.confidence, round(probs[max_class], 4))
        self.assertEqual(res.model_version, "1.0")
        self.assertEqual(res.probabilities, probs)

        # Verify predict() does not retrain or mutate vocab size
        vocab_before = len(clf.vocab)
        clf.predict("Unseen random text tokens here")
        self.assertEqual(len(clf.vocab), vocab_before)

    def test_analyze_email_ml_unified_entrypoint(self):
        """Test analyze_email_ml() returns expected components without crashing or inventing history."""
        # 1. Normal/Phishing email test
        res = analyze_email_ml(
            subject="URGENT: Verify Office365 Account",
            body="Your credentials have expired. Click here to verify password immediately.",
            display_name="CEO John",
            from_address="john.ceo@freemail.com",
            sender_address="john.ceo@freemail.com",
            recipient_count=1,
            sender_history=None
        )

        self.assertIsInstance(res, MLEngineResult)
        self.assertIsInstance(res.prediction, MLPredictionResult)
        self.assertIsInstance(res.nlp, AnalyzerResult)
        self.assertIsInstance(res.bec, AnalyzerResult)
        self.assertIsInstance(res.behavioral, AnalyzerResult)

        self.assertEqual(res.nlp.analyzer, "ml_nlp")
        self.assertEqual(res.bec.analyzer, "ml_bec")
        self.assertEqual(res.behavioral.analyzer, "ml_behavioral")

        self.assertEqual(res.nlp.status, "SUCCESS")
        self.assertEqual(res.bec.status, "SUCCESS")
        self.assertEqual(res.behavioral.status, "SUCCESS")

        # Verify findings generated for high risk text
        nlp_finding_codes = [f.code for f in res.nlp.findings]
        self.assertIn("HIGH_PHISHING_INTENT", nlp_finding_codes)

        # 2. Verify no final risk engine / gateway delivery policy decisions exist in result schema
        res_dict = res.model_dump()
        self.assertNotIn("final_action", res_dict)
        self.assertNotIn("delivery_policy", res_dict)
        self.assertNotIn("overall_risk_score", res_dict)
        self.assertNotIn("quarantine", res_dict)

    def test_analyze_email_ml_empty_and_missing_inputs(self):
        """Test empty input handling and safe defaults for missing sender history."""
        res = analyze_email_ml(
            subject="",
            body="",
            from_address="",
            sender_history=None
        )

        self.assertEqual(res.nlp.status, "SUCCESS")
        self.assertEqual(res.bec.status, "SUCCESS")
        self.assertEqual(res.behavioral.status, "SUCCESS")

        # Verify EMPTY_CONTENT finding in nlp findings
        self.assertEqual(res.nlp.findings[0].code, "EMPTY_CONTENT")

        # Verify missing sender history defaults cleanly to 0 anomaly scores
        self.assertEqual(res.behavioral.features["volume_anomaly"], 0.0)
        self.assertEqual(res.behavioral.features["location_anomaly"], 0.0)
        self.assertEqual(res.behavioral.features["time_anomaly"], 0.0)


if __name__ == "__main__":
    unittest.main()
