"""
Unit and Integration Tests for STEP 7.4: Real Dataset Training & Evaluation Pipeline.
Tests CSV dataset ingestion, label normalization, deduplication, deterministic splitting,
data leakage detection, model training, evaluation metrics, and inference contract compatibility.
"""

import os
import tempfile
import unittest
from typing import List, Tuple

from ml.datasets.dataset_loader import DatasetLoader, DatasetRecord, ALLOWED_LABELS
from ml.datasets.preprocessor import (
    clean_html_and_normalize,
    deduplicate_samples,
    split_dataset_3way,
    audit_split_data_leakage
)
from ml.models.tfidf_classifier import SimpleTFIDFClassifier
from ml.evaluation.evaluator import evaluate_predictions, evaluate_multiclass
from ml.nlp.intent_classifier import IntentClassifier
from ml.nlp.nlp_analyzer import ContentNLPAnalyzer
from ml.engine import analyze_email_ml
from ml.schemas import MLPredictionResult, MLEngineResult


class TestRealDatasetPipeline(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.csv_path = os.path.join(self.temp_dir.name, "sample_dataset.csv")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_csv_loading_and_record_normalization(self):
        """Verify CSV loading normalizes rows into validated DatasetRecords."""
        csv_content = (
            "label,text,label_num\n"
            "ham,Subject: meeting sync tomorrow,0\n"
            "spam,Claim your free discount coupons now,1\n"
            "ham,Quarterly report documentation attached,0\n"
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        records, stats = DatasetLoader.load_csv_with_stats(self.csv_path)
        self.assertEqual(len(records), 3)
        self.assertEqual(stats["valid_records"], 3)
        self.assertEqual(stats["skipped_rows"], 0)
        self.assertEqual(records[0].label, "benign")
        self.assertEqual(records[1].label, "spam")
        self.assertEqual(records[2].label, "benign")
        self.assertIn("Subject: meeting sync", records[0].text)

    def test_2_required_column_validation(self):
        """Verify error is raised if required label column is missing."""
        invalid_csv = (
            "content,id\n"
            "Some text here,123\n"
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(invalid_csv)

        with self.assertRaises(ValueError):
            DatasetLoader.load_csv_with_stats(self.csv_path)

    def test_3_malformed_csv_row_handling(self):
        """Verify malformed, empty, or unparseable rows are safely skipped."""
        csv_content = (
            "label,text\n"
            "ham,Valid benign message\n"
            "ham,   \n"  # Empty whitespace text
            "unknown_label,Some text here\n"  # Unmapped label
            "spam,Valid spam message\n"
            ",Missing label text\n"  # Missing label
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        records, stats = DatasetLoader.load_csv_with_stats(self.csv_path)
        self.assertEqual(len(records), 2)
        self.assertEqual(stats["valid_records"], 2)
        self.assertEqual(stats["skipped_rows"], 3)
        self.assertEqual(stats["skip_reasons"]["empty_text"], 1)
        self.assertEqual(stats["skip_reasons"]["invalid_label"], 2)

    def test_4_ceas_style_subject_body_construction(self):
        """Verify subject and body combination for CEAS-style schemas."""
        csv_content = (
            "subject,body,label\n"
            "Urgent notification,Please review attached file immediately,1\n"
            ",Body only message without subject,0\n"
            "Subject only without body,,1\n"
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        records, stats = DatasetLoader.load_csv_with_stats(self.csv_path, dataset_type="ceas")
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].label, "spam")
        self.assertEqual(records[1].label, "benign")
        self.assertEqual(records[2].label, "spam")
        self.assertEqual(records[0].text, "Urgent notification Please review attached file immediately")
        self.assertEqual(records[1].text, "Body only message without subject")
        self.assertEqual(records[2].text, "Subject only without body")

    def test_5_label_normalization_mappings(self):
        """Verify both ham->benign, spam->spam, 0->benign, and 1->spam mappings."""
        csv_content = (
            "label,text\n"
            "ham,Message one\n"
            "spam,Message two\n"
            "0,Message three\n"
            "1,Message four\n"
        )
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        records = DatasetLoader.from_csv(self.csv_path)
        labels = [r.label for r in records]
        self.assertEqual(labels, ["benign", "spam", "benign", "spam"])
        for l in labels:
            self.assertIn(l, ALLOWED_LABELS)

    def test_6_deduplication_before_splitting(self):
        """Verify identical duplicate texts are deduplicated prior to splitting."""
        raw = [
            ("Click here for invoice", "spam"),
            ("Click here for invoice", "spam"),
            ("Click here for invoice", "spam"),
            ("Meeting at 2pm", "benign")
        ]
        unique, removed = deduplicate_samples(raw)
        self.assertEqual(removed, 2)
        self.assertEqual(len(unique), 2)

    def test_7_deterministic_stratified_split(self):
        """Verify 3-way split reproducibility with identical seed."""
        samples = [(f"Email message content #{i}", "benign" if i % 2 == 0 else "spam") for i in range(40)]
        split1 = split_dataset_3way(samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=99, stratify=True)
        split2 = split_dataset_3way(samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=99, stratify=True)

        self.assertEqual(split1.train_text, split2.train_text)
        self.assertEqual(split1.val_text, split2.val_text)
        self.assertEqual(split1.test_text, split2.test_text)

    def test_8_class_distribution_preservation(self):
        """Verify stratified split preserves relative class proportions."""
        # 30 benign, 10 spam (75% / 25%)
        samples = [("Benign text " + str(i), "benign") for i in range(30)] + \
                  [("Spam text " + str(i), "spam") for i in range(10)]

        split = split_dataset_3way(samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42, stratify=True)

        train_spam_ratio = split.train_labels.count("spam") / len(split.train_labels)
        self.assertAlmostEqual(train_spam_ratio, 0.25, delta=0.10)

    def test_9_data_leakage_audit(self):
        """Verify data leakage detection catches overlaps and verifies clean splits."""
        train_text = ["clean email 1", "clean email 2", "clean email 3"]
        val_text = ["clean email 4"]
        test_text = ["clean email 5"]

        clean_audit = audit_split_data_leakage(train_text, val_text, test_text)
        self.assertTrue(clean_audit["leakage_clean"])
        self.assertFalse(clean_audit["has_leakage"])

        # Intentionally introduce overlap
        leaky_val = ["clean email 2"]  # Exists in train
        leaky_audit = audit_split_data_leakage(train_text, leaky_val, test_text)
        self.assertFalse(leaky_audit["leakage_clean"])
        self.assertTrue(leaky_audit["has_leakage"])
        self.assertEqual(leaky_audit["overlap_train_val_count"], 1)

    def test_10_model_training_and_evaluation(self):
        """Verify model trains on dataset split and evaluates with valid metrics."""
        train_docs = [
            "Exclusive discount offer for luxury watch",
            "Urgent: claim your free gift card now",
            "Buy cheap pharmaceuticals fast online",
            "Weekly team status meeting agenda",
            "Project review documentation attached",
            "Monthly company townhall schedule"
        ]
        train_labels = ["spam", "spam", "spam", "benign", "benign", "benign"]

        clf = SimpleTFIDFClassifier(ngram_range=(1, 1), model_version="test-1.0")
        clf.train(train_docs, train_labels)

        val_docs = ["Claim your discount gift now", "Weekly team agenda sync"]
        val_true = ["spam", "benign"]
        val_preds = [clf.predict(t).prediction for t in val_docs]

        metrics = evaluate_predictions(val_true, val_preds, positive_label="spam")
        self.assertEqual(metrics["sample_size"], 2.0)
        self.assertIn("accuracy", metrics)
        self.assertIn("f1_score", metrics)
        self.assertTrue(0.0 <= metrics["accuracy"] <= 1.0)

        multi_metrics = evaluate_multiclass(val_true, val_preds)
        self.assertEqual(multi_metrics["sample_size"], 2.0)
        self.assertIn("macro_f1", multi_metrics)
        self.assertIn("per_class", multi_metrics)

    def test_11_model_persistence_with_metadata(self):
        """Verify model saves and reloads with training audit metadata."""
        clf = SimpleTFIDFClassifier(
            ngram_range=(1, 1),
            model_version="7.4-test",
            metadata={
                "dataset_name": "test_dataset",
                "training_sample_count": 100,
                "production_performance": "NOT ESTABLISHED"
            }
        )
        clf.train(["Account update", "Meeting sync"], ["spam", "benign"])

        model_file = os.path.join(self.temp_dir.name, "saved_clf.json")
        clf.save_model(model_file)

        loaded_clf = SimpleTFIDFClassifier.load_model(model_file)
        self.assertEqual(loaded_clf.metadata["dataset_name"], "test_dataset")
        self.assertEqual(loaded_clf.metadata["production_performance"], "NOT ESTABLISHED")
        self.assertEqual(loaded_clf.model_version, "7.4-test")

    def test_12_loaded_model_prediction_equivalence(self):
        """Verify identical predictions and probabilities before save and after load."""
        clf = SimpleTFIDFClassifier(ngram_range=(1, 1), model_version="1.0")
        clf.train(["Special discount claim coupon", "Project milestone report"], ["spam", "benign"])

        model_file = os.path.join(self.temp_dir.name, "equiv_clf.json")
        clf.save_model(model_file)

        loaded_clf = SimpleTFIDFClassifier.load_model(model_file)

        test_query = "Claim your special discount today"
        pred_before = clf.predict_proba(test_query)
        pred_after = loaded_clf.predict_proba(test_query)

        for label in pred_before:
            self.assertAlmostEqual(pred_before[label], pred_after[label], places=5)

    def test_13_inference_engine_compatibility_with_loaded_model(self):
        """Verify loaded model integrates smoothly with analyze_email_ml inference contract."""
        clf = SimpleTFIDFClassifier(ngram_range=(1, 1), model_version="7.4-prod")
        clf.train(["Urgent invoice payment required", "Team sync notes"], ["spam", "benign"])

        intent_clf = IntentClassifier(classifier_model=clf)
        nlp_proc = ContentNLPAnalyzer(intent_classifier=intent_clf)

        res = analyze_email_ml(
            subject="Invoice past due",
            body="Please remit payment for invoice 1024 immediately.",
            nlp_analyzer=nlp_proc
        )

        self.assertIsInstance(res, MLEngineResult)
        self.assertIsInstance(res.prediction, MLPredictionResult)
        self.assertIn("spam", res.prediction.probabilities)
        self.assertIn("benign", res.prediction.probabilities)
        self.assertEqual(res.prediction.model_version, "7.4-prod")
        self.assertTrue(0.0 <= res.prediction.confidence <= 1.0)

    def test_14_backward_compatibility_with_existing_loaders(self):
        """Verify existing from_tuples, from_dicts, from_json_string are 100% backward compatible."""
        # Tuples
        tuples_recs = DatasetLoader.from_tuples([("Text 1", "benign"), ("Text 2", "spam")])
        self.assertEqual(len(tuples_recs), 2)

        # Dicts
        dicts_recs = DatasetLoader.from_dicts([{"text": "Text 3", "label": "benign"}])
        self.assertEqual(len(dicts_recs), 1)

        # JSON String
        json_recs = DatasetLoader.from_json_string('[{"text": "Text 4", "label": "spam"}]')
        self.assertEqual(len(json_recs), 1)


if __name__ == "__main__":
    unittest.main()
