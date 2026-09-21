"""
Unit tests for BehavioralAnalyzer.
"""

import unittest
from ml.behavioral.behavioral_analyzer import BehavioralAnalyzer


class TestBehavioralAnalyzer(unittest.TestCase):

    def test_behavioral_analyzer_normal_baseline(self):
        analyzer = BehavioralAnalyzer()
        history = {
            "seen_before": True,
            "avg_daily_volume": 5.0,
            "recent_volume": 4.0,
            "usual_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "usual_countries": ["US"],
            "conversation_exists": True
        }
        res = analyzer.analyze(
            sender_address="alice@company.com",
            recipient_count=1,
            sender_history=history,
            current_time_hour=10,
            originating_country="US"
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.features["volume_anomaly"], 0.0)
        self.assertEqual(res.features["location_anomaly"], 0.0)
        self.assertEqual(res.features["time_anomaly"], 0.0)
        self.assertTrue(res.features["conversation_exists"])

    def test_behavioral_analyzer_anomalies_detected(self):
        analyzer = BehavioralAnalyzer()
        history = {
            "seen_before": True,
            "avg_daily_volume": 2.0,
            "recent_volume": 50.0,
            "usual_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "usual_countries": ["US"],
            "conversation_exists": False
        }
        res = analyzer.analyze(
            sender_address="compromised@company.com",
            recipient_count=100,
            sender_history=history,
            current_time_hour=3,  # 3 AM (unusual)
            originating_country="RU"  # Unusual country
        )
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(res.features["volume_anomaly"], 0.5)
        self.assertGreater(res.features["location_anomaly"], 0.5)
        self.assertGreater(res.features["time_anomaly"], 0.5)
        self.assertGreater(res.features["bulk_score"], 0.8)
        codes = [f.code for f in res.findings]
        self.assertIn("VOLUME_ANOMALY_SPIKE", codes)
        self.assertIn("UNUSUAL_ORIGINATING_LOCATION", codes)


if __name__ == "__main__":
    unittest.main()
