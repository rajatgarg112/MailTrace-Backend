import unittest
from security.infrastructure import IPResolver, ASNLookup, GeoMapper
from security.evidence import EvidenceHasher, EvidenceVault
from security.timeline import InvestigationTimelineTracker
from security.forensic import ForensicCaseBuilder, AuditLogger
from security.runner import SecurityAnalyzer


class TestM6ForensicsAndGeo(unittest.TestCase):

    def setUp(self):
        self.analyzer = SecurityAnalyzer()
        self.ip_resolver = IPResolver()
        self.asn_lookup = ASNLookup()
        self.geo_mapper = GeoMapper()
        self.hasher = EvidenceHasher()
        self.vault = EvidenceVault()

    def test_ip_resolver_filters_private_ips(self):
        self.assertFalse(self.ip_resolver.is_public_ip("192.168.1.1"))
        self.assertFalse(self.ip_resolver.is_public_ip("10.0.0.5"))
        self.assertFalse(self.ip_resolver.is_public_ip("127.0.0.1"))
        self.assertTrue(self.ip_resolver.is_public_ip("185.220.101.5"))

    def test_evidence_hasher_and_fuzzy(self):
        hashes = self.hasher.hash_string("Hello Security Team")
        self.assertIn("sha256", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)
        
        fuzzy = self.hasher.compute_fuzzy_hash("Malicious Invoice payload with slight variation")
        self.assertTrue(len(fuzzy) > 5)

    def test_evidence_vault_packaging(self):
        package = self.vault.package_evidence(
            email_id="eml_test123",
            raw_headers={"From": "attacker@evil.com", "Subject": "Urgent Action"},
            body_text_or_html="<p>Click here</p>"
        )
        self.assertEqual(package["email_id"], "eml_test123")
        self.assertIn("integrity_hash", package)
        self.assertEqual(package["chain_of_custody"]["status"], "SEALED")

    def test_timeline_tracker(self):
        tracker = InvestigationTimelineTracker("eml_timeline_test")
        evt1 = tracker.record_event("INGESTION", "Received payload")
        evt2 = tracker.record_event("GEO_CHECK", "IP mapped to Germany")
        
        self.assertEqual(evt1["sequence"], 1)
        self.assertEqual(evt2["sequence"], 2)
        self.assertEqual(len(tracker.get_timeline()), 2)

    def test_geo_mapper_disclaimer_and_anomaly(self):
        geo = self.geo_mapper.resolve_geo("185.220.101.5", expected_country="IN")
        self.assertIn("Approximate infrastructure location", geo["disclaimer"])
        self.assertTrue(geo["is_vpn_or_tor"])

    def test_full_security_analyzer_pipeline_m6(self):
        headers = {
            "From": "Security <alert@phishing-target.xyz>",
            "Subject": "Action Required Immediately",
            "Received": ["from relay.host ([185.220.101.5]) by mail.server.com; Mon, 21 Sep 2026 10:00:00 +0000"]
        }
        result = self.analyzer.analyze(headers, "<p>Phishing body</p>", email_id="eml_full_test")
        
        # Verify M6 enhancements are populated
        self.assertIsNotNone(result.infrastructure)
        self.assertEqual(result.infrastructure["originating_ip"], "185.220.101.5")
        self.assertIsNotNone(result.evidence)
        self.assertTrue(len(result.timeline) >= 3)
        self.assertIsNotNone(result.forensic_case)
        self.assertIsNotNone(result.sanitized_report)
        self.assertTrue("VPN_OR_TOR_ORIGIN" in result.security_tags)


if __name__ == "__main__":
    unittest.main()
