"""
Unit and integration pipeline tests for Model Evaluator, pipeline correctness,
and persistence metric consistency.

Note: Evaluation tests on synthetic test fixtures validate pipeline mechanics and determinism.
They do NOT establish or represent production model generalization performance.
"""

import os
import tempfile
import unittest
from ml.evaluation.evaluator import evaluate_predictions
from ml.datasets.dataset_loader import DatasetLoader
from ml.datasets.preprocessor import split_dataset_3way, deduplicate_samples
from ml.models.tfidf_classifier import SimpleTFIDFClassifier


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

    def test_end_to_end_evaluation_pipeline(self):
        """
        Task 1, 2, 3 & 6: Verify end-to-end evaluation pipeline correctness:
        Dataset -> 3-way split -> train -> test inference -> metrics calculation.
        Verifies data separation, structural metric validation, and determinism.
        """
        # Deterministic sample dataset with phishing, spam, and benign records
        raw_samples = [
            ("Urgent: verify your password now or account suspended", "phishing"),
            ("Immediate action required: click link to update credentials", "phishing"),
            ("Your bank password reset request is pending verification", "phishing"),
            ("Claim your exclusive free gift card coupon today", "spam"),
            ("Special discount deal on luxury watches claim now", "spam"),
            ("Buy cheap products fast limited time offer", "spam"),
            ("Weekly team meeting notes and agenda for review", "benign"),
            ("Please find attached the quarterly project documentation", "benign"),
            ("Community newsletter and updates for this month", "benign"),
            ("Hi, let us schedule a quick sync call tomorrow morning", "benign")
        ]

        records = DatasetLoader.from_tuples(raw_samples)
        self.assertEqual(len(records), 10)

        # 3-way reproducible split with seed=42
        split = split_dataset_3way(
            raw_samples,
            train_ratio=0.7,
            val_ratio=0.15,
            test_ratio=0.15,
            seed=42,
            deduplicate=True
        )

        # Verify data separation & deduplication
        self.assertGreater(len(split.train_text), 0)
        self.assertGreater(len(split.val_text), 0)
        self.assertGreater(len(split.test_text), 0)
        self.assertEqual(len(split.train_text) + len(split.val_text) + len(split.test_text), 10)

        # Train model strictly on training set partition
        classifier = SimpleTFIDFClassifier(ngram_range=(1, 2))
        classifier.train(split.train_text, split.train_labels)

        # Run inference strictly on held-out test partition
        y_true = split.test_labels
        y_pred = []
        for text in split.test_text:
            probs = classifier.predict_proba(text)
            best_label = max(probs, key=probs.get)
            y_pred.append(best_label)

        # Evaluate test set predictions
        metrics = evaluate_predictions(y_true, y_pred, positive_label="phishing")

        # Verify structural correctness of metrics
        self.assertEqual(metrics["sample_size"], float(len(split.test_text)))
        self.assertIn("accuracy", metrics)
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1_score", metrics)
        self.assertTrue(0.0 <= metrics["accuracy"] <= 1.0)
        self.assertTrue(0.0 <= metrics["precision"] <= 1.0)
        self.assertTrue(0.0 <= metrics["recall"] <= 1.0)
        self.assertTrue(0.0 <= metrics["f1_score"] <= 1.0)

        # Determinism check: re-running split and training with identical seed produces identical results
        split_repeat = split_dataset_3way(
            raw_samples,
            train_ratio=0.7,
            val_ratio=0.15,
            test_ratio=0.15,
            seed=42,
            deduplicate=True
        )
        self.assertEqual(split.train_text, split_repeat.train_text)
        self.assertEqual(split.test_text, split_repeat.test_text)

        classifier_repeat = SimpleTFIDFClassifier(ngram_range=(1, 2))
        classifier_repeat.train(split_repeat.train_text, split_repeat.train_labels)
        y_pred_repeat = [max(classifier_repeat.predict_proba(t), key=classifier_repeat.predict_proba(t).get) for t in split_repeat.test_text]
        self.assertEqual(y_pred, y_pred_repeat)

    def test_persistence_evaluation_consistency(self):
        """
        Task 4: Verify persistence evaluation consistency.
        Model predictions and evaluate_predictions() metrics before save and after load must be identical.
        """
        train_docs = [
            "Urgent password reset required for your security account",
            "Immediate wire transfer needed for overdue invoice",
            "Weekly team status updates and project documentation",
            "Claim your exclusive discount coupon for free items",
            "Security alert: verify your credentials immediately"
        ]
        train_labels = ["phishing", "phishing", "benign", "spam", "phishing"]

        # Train initial model (metrics A)
        model_a = SimpleTFIDFClassifier(ngram_range=(1, 2))
        model_a.train(train_docs, train_labels)

        eval_docs = [
            "Verify your password and credentials immediately",
            "Weekly team meeting sync notes attached",
            "Claim your exclusive free gift card coupon"
        ]
        eval_true = ["phishing", "benign", "spam"]

        # Predictions & evaluation A
        preds_a = []
        for text in eval_docs:
            probs = model_a.predict_proba(text)
            preds_a.append(max(probs, key=probs.get))
        metrics_a = evaluate_predictions(eval_true, preds_a, positive_label="phishing")

        # Save and reload model (metrics B)
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = os.path.join(tmp_dir, "eval_model.json")
            model_a.save_model(file_path)

            model_b = SimpleTFIDFClassifier.load_model(file_path)
            preds_b = []
            for text in eval_docs:
                probs = model_b.predict_proba(text)
                preds_b.append(max(probs, key=probs.get))
            metrics_b = evaluate_predictions(eval_true, preds_b, positive_label="phishing")

        # Verify prediction equivalence and metric equivalence
        self.assertEqual(preds_a, preds_b)
        self.assertEqual(metrics_a, metrics_b)


if __name__ == "__main__":
    unittest.main()
