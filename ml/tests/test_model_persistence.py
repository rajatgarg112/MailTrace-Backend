"""
Unit tests for STEP 4.1: Model Serialization & N-Gram Configuration Validation.
"""

import os
import tempfile
import unittest
from ml.models.tfidf_classifier import SimpleTFIDFClassifier, validate_ngram_range
from ml.nlp.intent_classifier import IntentClassifier


class TestModelPersistenceAndValidation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self.temp_dir.name, "test_model.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_save_load_roundtrip_and_prediction_equivalence(self):
        clf = SimpleTFIDFClassifier(ngram_range=(1, 2))
        docs = [
            "Your account is suspended. Click here to verify credentials and password immediately.",
            "Wire transfer needed for invoice payment. Update bank account details ASAP.",
            "Weekly team meeting sync notes and project updates attached for review."
        ]
        labels = ["phishing", "phishing", "benign"]
        clf.train(docs, labels)

        test_text = "Click here to verify credentials and password immediately"
        probs_before = clf.predict_proba(test_text)

        # Save model
        clf.save_model(self.model_path)
        self.assertTrue(os.path.exists(self.model_path))

        # Load model into new instance
        loaded_clf = SimpleTFIDFClassifier.load_model(self.model_path)
        self.assertTrue(loaded_clf.is_trained)
        self.assertEqual(loaded_clf.ngram_range, (1, 2))

        probs_after = loaded_clf.predict_proba(test_text)

        # Verify predictions match floating-point tolerance
        for key in probs_before:
            self.assertIn(key, probs_after)
            self.assertAlmostEqual(probs_before[key], probs_after[key], places=5)

    def test_2_vocabulary_and_idf_persistence(self):
        clf = SimpleTFIDFClassifier(ngram_range=(1, 1))
        clf.train(["Reset password now", "Team meeting sync"], ["phishing", "benign"])
        clf.save_model(self.model_path)

        loaded_clf = SimpleTFIDFClassifier.load_model(self.model_path)
        self.assertEqual(clf.vocab, loaded_clf.vocab)
        self.assertEqual(clf.idf, loaded_clf.idf)
        self.assertEqual(clf.class_priors, loaded_clf.class_priors)

    def test_3_untrained_model_save_rejection(self):
        clf = SimpleTFIDFClassifier()
        with self.assertRaises(ValueError):
            clf.save_model(self.model_path)

    def test_4_malformed_model_file_handling(self):
        # 1. Non-existent file
        with self.assertRaises(ValueError):
            SimpleTFIDFClassifier.load_model(os.path.join(self.temp_dir.name, "non_existent.json"))

        # 2. Malformed JSON (invalid format)
        bad_json_path = os.path.join(self.temp_dir.name, "bad.json")
        with open(bad_json_path, "w") as f:
            f.write("{invalid json syntax")

        with self.assertRaises(ValueError):
            SimpleTFIDFClassifier.load_model(bad_json_path)

        # 3. Incomplete keys
        incomplete_json_path = os.path.join(self.temp_dir.name, "incomplete.json")
        with open(incomplete_json_path, "w") as f:
            f.write('{"is_trained": true, "vocab": {}}')

        with self.assertRaises(ValueError):
            SimpleTFIDFClassifier.load_model(incomplete_json_path)

    def test_5_invalid_ngram_range_validation(self):
        invalid_ranges = [
            (2, 1),      # lower > upper
            (0, 0),      # bounds < 1
            (-1, 1),     # negative bound
            (1, 0),      # upper bound 0
            "1,2",       # non-tuple string
            [1],         # single element
            (1, 2, 3),   # 3 elements
            (1, "2")     # non-integer element
        ]

        for invalid in invalid_ranges:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    SimpleTFIDFClassifier(ngram_range=invalid)

    def test_6_valid_ngram_range_acceptance(self):
        valid_ranges = [(1, 1), (1, 2), (1, 3), (2, 2), [1, 2]]
        for valid in valid_ranges:
            with self.subTest(valid=valid):
                clf = SimpleTFIDFClassifier(ngram_range=valid)
                self.assertIsNotNone(clf)

    def test_7_intent_classifier_custom_loaded_model_integration(self):
        clf = SimpleTFIDFClassifier(ngram_range=(1, 2))
        clf.train(["Verify password reset", "Weekly status report"], ["phishing", "benign"])
        clf.save_model(self.model_path)

        loaded_clf = SimpleTFIDFClassifier.load_model(self.model_path)
        intent_clf = IntentClassifier(classifier_model=loaded_clf)

        res = intent_clf.classify_intent("Verify password reset", "Click here now", cta_score=0.8)
        self.assertIn("phishing_score", res)
        self.assertGreater(res["phishing_score"], 0.5)


if __name__ == "__main__":
    unittest.main()
