"""
Unit tests for Model Evaluator.
"""

import unittest
from ml.evaluation.evaluator import evaluate_predictions


class TestModelEvaluator(unittest.TestCase):

    def test_evaluator_metrics_calculation(self):
        y_true = ["phishing", "phishing", "benign", "benign", "phishing"]
        y_pred = ["phishing", "benign",   "benign", "benign", "phishing"]

        metrics = evaluate_predictions(y_true, y_pred, positive_label="phishing")

        self.assertEqual(metrics["sample_size"], 5.0)
        self.assertEqual(metrics["accuracy"], 0.8)
        self.assertEqual(metrics["tp"], 2.0)
        self.assertEqual(metrics["fn"], 1.0)
        self.assertEqual(metrics["fp"], 0.0)
        self.assertEqual(metrics["tn"], 2.0)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], round(2.0 / 3.0, 4))


if __name__ == "__main__":
    unittest.main()
