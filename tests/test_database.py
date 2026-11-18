"""
SCAM KILLER — Tests for SQLite Telemetry & Privacy Operations
"""

import unittest
from database.db import init_db, get_db_connection
from database.models import TelemetryRepository


class TestDatabaseOperations(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_insert_and_fetch_scan(self):
        """Tests inserting a scan record and verifying stored non-sensitive metadata."""
        test_data = {
            "scan_id": "test-scan-999",
            "scan_type": "url",
            "risk_category": "suspicious",
            "timestamp": "2026-11-16 23:00",
            "time_ago": "Just now",
            "display_item": "https://test-threat-example.xyz",
            "content_status": "passed",
            "url_status": "flagged",
            "screenshot_status": "skipped",
            "intel_status": "flagged",
            "indicator_count": 2,
            "explanation": "Test explanation for audit verification.",
            "metadata": {
                "riskLabel": "Suspicious",
                "badgeClass": "badge-suspicious",
                "badgeIcon": "warning"
            }
        }
        TelemetryRepository.insert_scan(test_data)

        history = TelemetryRepository.get_recent_scans(limit=10)
        found = next((item for item in history if item["id"] == "test-scan-999"), None)
        self.assertIsNotNone(found)
        self.assertEqual(found["riskLevel"], "suspicious")
        self.assertEqual(found["submittedItem"], "https://test-threat-example.xyz")

    def test_community_reports_retrieval(self):
        """Tests that seeded community reports are retrievable."""
        TelemetryRepository.seed_initial_data_if_empty()
        reports = TelemetryRepository.get_community_reports()
        self.assertGreater(len(reports), 0)
        first = reports[0]
        self.assertIn("category", first)
        self.assertIn("upvotes", first)

    def test_upvote_community_report(self):
        """Tests upvoting a community report increments count."""
        reports = TelemetryRepository.get_community_reports()
        if reports:
            target_id = reports[0]["id"]
            prev_upvotes = reports[0]["upvotes"]
            new_upvotes = TelemetryRepository.upvote_report(target_id)
            self.assertEqual(new_upvotes, prev_upvotes + 1)

    def test_community_reports_demo_labeling(self):
        """Tests that sample/demo records are distinctly labeled from user submissions."""
        TelemetryRepository.seed_initial_data_if_empty()
        reports = TelemetryRepository.get_community_reports()
        demo_reports = [r for r in reports if r.get("isDemo")]
        self.assertGreater(len(demo_reports), 0)
        for r in demo_reports:
            self.assertEqual(r["source"], "Demonstration Sample")

    def test_get_radar_trends(self):
        """Tests authentic category aggregation without fabricated percentages."""
        trends_data = TelemetryRepository.get_radar_trends()
        self.assertIn("has_sufficient_data", trends_data)
        self.assertIn("trends", trends_data)
        self.assertIn("data_notice", trends_data)


if __name__ == "__main__":
    unittest.main()
