"""
Focused unit tests for STEP 2: Dataset Loading, Preprocessing & Data Leakage Prevention.
"""

import unittest
from ml.datasets.dataset_loader import DatasetRecord, DatasetLoader
from ml.datasets.preprocessor import (
    clean_html_and_normalize,
    prepare_dataset_split,
    split_dataset_3way,
    deduplicate_samples
)


class TestDatasetPipeline(unittest.TestCase):

    def test_1_html_removal(self):
        raw = "<h1>Security Alert</h1><p>Click <a href='http://bad.link'>here</a> to login.</p>"
        cleaned = clean_html_and_normalize(raw)
        self.assertNotIn("<h1>", cleaned)
        self.assertNotIn("<p>", cleaned)
        self.assertNotIn("</a>", cleaned)
        self.assertEqual(cleaned, "Security Alert Click here to login.")

    def test_2_html_entity_decoding(self):
        raw = "Password &amp; Security &lt;Update&gt; &#39;Immediate&#39;"
        cleaned = clean_html_and_normalize(raw)
        self.assertEqual(cleaned, "Password & Security <Update> 'Immediate'")

    def test_3_whitespace_normalization(self):
        raw = "   Urgent \n\n  Account   Suspended   \t  ASAP  "
        cleaned = clean_html_and_normalize(raw)
        self.assertEqual(cleaned, "Urgent Account Suspended ASAP")

    def test_4_empty_input_handling(self):
        self.assertEqual(clean_html_and_normalize(""), "")
        self.assertEqual(clean_html_and_normalize(None), "")
        tr, tr_l, te, te_l = prepare_dataset_split([])
        self.assertEqual(tr, [])
        self.assertEqual(te, [])

    def test_5_malformed_input_handling(self):
        malformed = "<div class='test' unclosed tag text > P@ssw0rd reset $$$"
        cleaned = clean_html_and_normalize(malformed)
        self.assertIn("P@ssw0rd reset $$$", cleaned)

        # Non-string record in loader
        records = DatasetLoader.from_tuples([("", "phishing"), ("Valid text", "invalid_label"), ("Good text", "phishing")])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].text, "Good text")

    def test_6_deterministic_preprocessing(self):
        raw = "<p>Verify your <b>account</b> details &amp; credentials!</p>"
        res1 = clean_html_and_normalize(raw)
        res2 = clean_html_and_normalize(raw)
        self.assertEqual(res1, res2)

    def test_7_deterministic_splitting(self):
        samples = [(f"Sample message {i}", "phishing" if i % 2 == 0 else "benign") for i in range(20)]
        split1 = split_dataset_3way(samples, seed=42)
        split2 = split_dataset_3way(samples, seed=42)
        self.assertEqual(split1.train_text, split2.train_text)
        self.assertEqual(split1.val_text, split2.val_text)
        self.assertEqual(split1.test_text, split2.test_text)

    def test_8_split_configuration_validation(self):
        samples = [("Test text", "phishing")]
        with self.assertRaises(ValueError):
            split_dataset_3way(samples, train_ratio=0.5, val_ratio=0.5, test_ratio=0.5)  # Sums to 1.5

        with self.assertRaises(ValueError):
            prepare_dataset_split(samples, train_ratio=1.5)  # Invalid train ratio

    def test_9_no_duplicate_records_across_splits(self):
        samples = [
            ("Duplicate text", "phishing"),
            ("Duplicate text", "phishing"),
            ("Unique text 1", "benign"),
            ("Unique text 2", "spam")
        ]
        unique, removed = deduplicate_samples(samples)
        self.assertEqual(removed, 1)
        self.assertEqual(len(unique), 3)

    def test_10_training_validation_test_separation(self):
        samples = [(f"Email subject and body text #{i}", "phishing" if i % 3 == 0 else ("spam" if i % 3 == 1 else "benign")) for i in range(30)]
        res = split_dataset_3way(samples, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=123)

        train_set = set(res.train_text)
        val_set = set(res.val_text)
        test_set = set(res.test_text)

        # Verify zero overlap between split partitions
        self.assertEqual(len(train_set.intersection(val_set)), 0)
        self.assertEqual(len(train_set.intersection(test_set)), 0)
        self.assertEqual(len(val_set.intersection(test_set)), 0)


if __name__ == "__main__":
    unittest.main()
