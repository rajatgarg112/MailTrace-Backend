"""
Unit tests for SimpleTFIDFClassifier, Rule Engine, and Preprocessing.
"""

import unittest
from ml.models.tfidf_classifier import SimpleTFIDFClassifier
from ml.models.rule_engine import calculate_shannon_entropy
from ml.datasets.preprocessor import clean_html_and_normalize, prepare_dataset_split


class TestMLModelsAndUtilities(unittest.TestCase):

    def test_tfidf_classifier_training_and_prediction(self):
        classifier = SimpleTFIDFClassifier()
        train_docs = [
            "Urgent: Reset password immediately account suspended",
            "Verify your credentials and login to continue",
            "Weekly newsletter update and team meeting agenda",
            "Quarterly financial report attached for review"
        ]
        train_labels = ["phishing", "phishing", "benign", "benign"]

        classifier.train(train_docs, train_labels)
        self.assertTrue(classifier.is_trained)

        probs = classifier.predict_proba("Reset password now immediately")
        self.assertGreater(probs["phishing"], probs["benign"])

    def test_shannon_entropy_calculation(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        entropy_low = calculate_shannon_entropy("aaaaaaaa")
        entropy_high = calculate_shannon_entropy("a8!kL9#mZ@2$")
        self.assertGreater(entropy_high, entropy_low)

    def test_html_cleaning_and_split(self):
        raw_html = "<p>Hello <b>World</b>! Check <a href='#'>link</a></p>"
        cleaned = clean_html_and_normalize(raw_html)
        self.assertEqual(cleaned, "Hello World! Check link")

        samples = [(f"doc {i}", "phishing" if i % 2 == 0 else "benign") for i in range(10)]
        tr_txt, tr_lbl, te_txt, te_lbl = prepare_dataset_split(samples, train_ratio=0.8, seed=42)
        self.assertEqual(len(tr_txt), 8)
        self.assertEqual(len(te_txt), 2)


if __name__ == "__main__":
    unittest.main()
