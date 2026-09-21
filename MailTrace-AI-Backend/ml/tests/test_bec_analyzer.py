"""
Unit tests for BECAnalyzer matching TESTING.md guidelines.
"""

import unittest
from ml.bec.bec_analyzer import BECAnalyzer


class TestBECAnalyzer(unittest.TestCase):

    def test_bec_analyzer_safe_email(self):
        analyzer = BECAnalyzer()
        res = analyzer.analyze(
            display_name="John Smith",
            from_address="john.smith@company.com",
            subject="Project status update",
            body="Attached is the quarterly progress report."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertLess(res.features["executive_impersonation_score"], 0.5)
        self.assertEqual(res.features["bank_account_change_score"], 0.0)
        self.assertEqual(len(res.findings), 0)

    def test_bec_analyzer_executive_impersonation(self):
        analyzer = BECAnalyzer()
        res = analyzer.analyze(
            display_name="CEO John Smith",
            from_address="john.smith.ceo12345@gmail.com",
            subject="Urgent wire transfer",
            body="I am in a meeting. Please wire transfer $50,000 to this vendor account immediately."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreaterEqual(res.features["executive_impersonation_score"], 0.70)
        self.assertTrue(any(f.code == "EXECUTIVE_IMPERSONATION_ATTEMPT" for f in res.findings))

    def test_bec_analyzer_gift_card_fraud(self):
        analyzer = BECAnalyzer()
        res = analyzer.analyze(
            display_name="VP Operations",
            from_address="vp.ops@yahoo.com",
            subject="Quick Request",
            body="Need you to buy 5 Apple gift cards for a client presentation right now. Send the codes to me."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(res.features["gift_card_request_score"], 0.0)
        self.assertTrue(any(f.code == "GIFT_CARD_SOLICITATION" for f in res.findings))

    def test_bec_analyzer_conversation_hijacking(self):
        analyzer = BECAnalyzer()
        res = analyzer.analyze(
            display_name="Accounting",
            from_address="billing@company.com",
            reply_to="attacker-billing@attacker-domain.xyz",
            subject="Re: Outstanding Invoice #4021",
            body="Please direct payment to our updated bank details attached below."
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreaterEqual(res.features["conversation_hijacking_score"], 0.70)
        self.assertTrue(any(f.code == "CONVERSATION_HIJACKING_PATTERN" for f in res.findings))


if __name__ == "__main__":
    unittest.main()
