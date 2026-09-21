"""
Unit tests for ContentNLPAnalyzer matching TESTING.md guidelines.
"""

import unittest
from ml.nlp.nlp_analyzer import ContentNLPAnalyzer


class TestContentNLPAnalyzer(unittest.TestCase):

    def test_nlp_analyzer_safe_email(self):
        analyzer = ContentNLPAnalyzer()
        res = analyzer.analyze(
            subject="Weekly team meeting notes",
            body="Hi team, here are the action items from our project sync today. Best regards, Alice."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.analyzer, "ml_nlp")
        self.assertLess(res.features["phishing_score"], 0.50)
        self.assertEqual(res.features["credential_request_score"], 0.0)
        self.assertEqual(len([f for f in res.findings if f.severity in ["HIGH", "CRITICAL"]]), 0)

    def test_nlp_analyzer_suspicious_phishing_email(self):
        analyzer = ContentNLPAnalyzer()
        res = analyzer.analyze(
            subject="URGENT: Password Reset Required Immediately",
            body="Your account is suspended due to unauthorized access. Click here to login to restore and verify your password within 24 hours."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreaterEqual(res.features["phishing_score"], 0.50)
        self.assertGreater(res.features["credential_request_score"], 0.0)
        self.assertGreater(res.features["urgency_score"], 0.0)
        codes = [f.code for f in res.findings]
        self.assertTrue("CREDENTIAL_HARVESTING_LANGUAGE" in codes or "HIGH_PHISHING_INTENT" in codes)

    def test_nlp_analyzer_empty_and_missing_fields(self):
        analyzer = ContentNLPAnalyzer()
        res = analyzer.analyze(subject="", body="")
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.features["phishing_score"], 0.0)
        self.assertTrue(any(f.code == "EMPTY_CONTENT" for f in res.findings))

    def test_nlp_analyzer_malformed_input(self):
        analyzer = ContentNLPAnalyzer()
        res = analyzer.analyze(
            subject="P@ssw0rd Upd@t3",
            body="V3r1fy y0ur c1ed3nt1@ls n0w!!!"
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertIn("text_entropy", res.features)


if __name__ == "__main__":
    unittest.main()
