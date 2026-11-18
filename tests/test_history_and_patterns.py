"""
SCAM KILLER — Tests for Scan History, Persistent Report Management & Community Patterns
"""

import unittest
import json
from app import create_app
from database.db import init_db
from database.models import TelemetryRepository
from services.history_service import HistoryService
from services.scan_service import ScanService


class TestHistoryAndPatterns(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_insert_and_get_full_report(self):
        """Verifies that a scan record with full_report_json is inserted and retrieved intact."""
        scan_id = "test-perm-001"
        full_report = {
            "scan_id": scan_id,
            "scan_type": "url",
            "source_type": "url",
            "risk_level": "suspicious",
            "classification": "Suspicious",
            "confidence": 0.92,
            "explanation": "High-risk brand spoof with urgent credential solicitation.",
            "why_it_matters": "Credentials entered on this fake portal could lead to unauthorized account access.",
            "recommended_actions": [
                "Do not enter passwords or OTPs.",
                "Verify through official bank helpline."
            ],
            "detected_indicators": [
                {"title": "Typosquatting domain", "severity": "high", "explanation": "Domain mismatches claimed bank"}
            ],
            "submitted_item": "https://secure-hdfc-kyc.xyz",
            "timestamp": "2026-11-17 12:00"
        }

        TelemetryRepository.insert_scan({
            "scan_id": scan_id,
            "scan_type": "url",
            "risk_category": "suspicious",
            "timestamp": "2026-11-17 12:00",
            "display_item": "https://secure-hdfc-kyc.xyz",
            "explanation": full_report["explanation"],
            "full_report_json": full_report,
            "category": "Banking / KYC",
            "impersonated_entity": "HDFC Bank",
            "requested_action": "Disclose Credentials",
            "pattern_fingerprint": "pat_hdfc_kyc_01"
        })

        # Retrieve single report by ID
        res = self.client.get(f"/api/history/{scan_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        report = data.get("report")
        self.assertEqual(report["scan_id"], scan_id)
        self.assertEqual(report["risk_level"], "suspicious")
        self.assertEqual(len(report["recommended_actions"]), 2)
        self.assertEqual(report["submitted_item"], "https://secure-hdfc-kyc.xyz")

    def test_history_search_and_filtering(self):
        """Verifies searching and filtering by risk level and category."""
        # Insert test records across categories
        TelemetryRepository.insert_scan({
            "scan_id": "test-filter-delivery",
            "scan_type": "url",
            "risk_category": "suspicious",
            "timestamp": "2026-11-17 12:05",
            "display_item": "https://indiapost-parcel-redirection.xyz",
            "explanation": "Postal surcharge fee scam.",
            "category": "Delivery Phishing",
            "impersonated_entity": "India Post"
        })
        TelemetryRepository.insert_scan({
            "scan_id": "test-filter-safe",
            "scan_type": "text",
            "risk_category": "safe",
            "timestamp": "2026-11-17 12:10",
            "display_item": "Meeting rescheduled to 3 PM tomorrow.",
            "explanation": "Standard benign conversational note.",
            "category": "Benign Transactional",
            "impersonated_entity": "None"
        })

        # Filter by risk
        res_risk = self.client.get("/api/history?risk=suspicious")
        self.assertEqual(res_risk.status_code, 200)
        history_risk = res_risk.get_json()["history"]
        self.assertTrue(all(item["riskLevel"] == "suspicious" for item in history_risk))

        # Filter by category
        res_cat = self.client.get("/api/history?category=Delivery%20Phishing")
        self.assertEqual(res_cat.status_code, 200)
        history_cat = res_cat.get_json()["history"]
        self.assertTrue(any(item["scanId"] == "test-filter-delivery" for item in history_cat))
        self.assertFalse(any(item["scanId"] == "test-filter-safe" for item in history_cat))

        # Search query
        res_search = self.client.get("/api/history?q=indiapost")
        self.assertEqual(res_search.status_code, 200)
        history_search = res_search.get_json()["history"]
        self.assertTrue(any(item["scanId"] == "test-filter-delivery" for item in history_search))

    def test_single_scan_deletion(self):
        """Verifies deleting a single scan permanently removes it from SQLite."""
        scan_id = "test-delete-999"
        TelemetryRepository.insert_scan({
            "scan_id": scan_id,
            "scan_type": "text",
            "risk_category": "caution",
            "timestamp": "2026-11-17 12:15",
            "display_item": "Your electricity bill is pending payment.",
            "explanation": "Utility alert.",
            "category": "Utility Bill"
        })

        # Verify it exists
        res_get = self.client.get(f"/api/history/{scan_id}")
        self.assertEqual(res_get.status_code, 200)

        # Delete it
        res_del = self.client.delete(f"/api/history/{scan_id}")
        self.assertEqual(res_del.status_code, 200)
        del_data = res_del.get_json()
        self.assertTrue(del_data.get("success"))
        self.assertEqual(del_data.get("scan_id"), scan_id)

        # Verify it is gone
        res_get2 = self.client.get(f"/api/history/{scan_id}")
        self.assertEqual(res_get2.status_code, 404)

    def test_community_patterns_endpoint(self):
        """Verifies /api/community/patterns clustering and statistical threshold messages."""
        res = self.client.get("/api/community/patterns")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "active")
        self.assertIn("patterns", data)
        self.assertGreater(data["total_patterns"], 0)

        patterns = data["patterns"]
        for p in patterns:
            self.assertIn("pattern_id", p)
            self.assertIn("fingerprint", p)
            self.assertIn("category", p)
            self.assertIn("frequency", p)
            self.assertIn("threshold_notice", p)
            if p["frequency"] < 5:
                self.assertFalse(p["has_sufficient_data"])
                self.assertIn("Not enough reports yet", p["trend_badge"])
            else:
                self.assertTrue(p["has_sufficient_data"])

    def test_pattern_indicator_extraction(self):
        """Verifies deterministic pattern indicator extraction and zero-log fingerprinting."""
        sample_text = "Urgent: Your HDFC bank account KYC will be suspended in 24 hours. Click https://hdfc-kyc.xyz to update."
        indicators = ScanService.extract_pattern_indicators(sample_text, "suspicious", {})
        self.assertEqual(indicators["category"], "Banking / KYC")
        self.assertEqual(indicators["impersonated_entity"], "HDFC Bank")
        self.assertIn("Urgency", indicators["urgency_or_reward_pattern"])
        self.assertTrue(indicators["pattern_fingerprint"].startswith("pat_"))

    def test_pdf_generation_from_history(self):
        """Verifies that PDF reports can be generated directly from retrieved history data."""
        scan_id = "test-pdf-gen-01"
        report_data = {
            "scan_id": scan_id,
            "scan_type": "message",
            "risk_level": "suspicious",
            "classification": "Suspicious",
            "confidence": 0.88,
            "explanation": "Fake lottery winning alert.",
            "why_it_matters": "Solicits upfront fee before claiming prize.",
            "recommended_actions": ["Ignore and report to cybercrime."],
            "submitted_item": "You won a ₹25,000 lottery voucher!",
            "timestamp": "2026-11-17 12:30"
        }

        res = self.client.post("/api/report/pdf", json=report_data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Content-Type"), "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
