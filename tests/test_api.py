"""
SCAM KILLER — Tests for Flask REST API Endpoints
"""

import unittest
import io
import json
from app import create_app


class TestRestAPI(unittest.TestCase):

    def setUp(self):
        import os
        os.environ["GEMINI_TEST_MODE"] = "1"
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_health_endpoint(self):
        """Tests GET /api/health."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("capabilities", data)
        self.assertIn("local_ocr_engine", data["capabilities"])
        self.assertIn("ocr_engine_name", data["capabilities"])
        self.assertIn("ocr_languages", data["capabilities"])
        self.assertIn("privacy", data)

    def test_scan_text_phishing_url(self):
        """Tests POST /api/scan with phishing URL."""
        payload = {"input": "https://free-reward-claim.xyz", "type": "auto"}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["risk_level"], "suspicious")
        self.assertEqual(data["scan_type"], "url")
        self.assertIn("layers", data)
        self.assertEqual(data["layers"]["urlStructure"]["status"], "flagged")

    def test_scan_text_kyc_message(self):
        """Tests POST /api/scan with suspicious message containing URL."""
        payload = {
            "input": "Dear Customer, your account will be blocked within 24 hours. Update KYC at http://sbi-kyc-verify-portal.top/auth",
            "type": "auto"
        }
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["risk_level"], "suspicious")
        self.assertTrue(any(
            "account" in (ind["title"] if isinstance(ind, dict) else ind).lower()
            or "urgency" in (ind["title"] if isinstance(ind, dict) else ind).lower()
            or "coercion" in (ind["title"] if isinstance(ind, dict) else ind).lower()
            for ind in data["detected_indicators"]
        ))

    def test_scan_sensitive_otp_intercept(self):
        """Tests POST /api/scan intercepts private OTPs with safety alert."""
        payload = {"input": "My OTP verification code is 829104", "type": "auto"}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["scan_type"], "privacy_alert")
        self.assertIn("SAFETY INTERCEPT", data["explanation"])

    def test_scan_empty_input_rejected(self):
        """Tests POST /api/scan rejects empty payload."""
        payload = {"input": "   "}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_scan_screenshot_endpoint(self):
        """Tests POST /api/scan/screenshot with simulated image bytes."""
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60
        data = {
            "screenshot": (io.BytesIO(valid_png), "sample_capture.png")
        }
        response = self.client.post("/api/scan/screenshot", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertEqual(res["scan_type"], "screenshot")
        self.assertIn("layers", res)

    def test_scan_screenshot_invalid_file(self):
        """Tests POST /api/scan/screenshot rejects non-image bytes."""
        corrupted = b"Text file disguised as PNG"
        data = {
            "screenshot": (io.BytesIO(corrupted), "bad.png")
        }
        response = self.client.post("/api/scan/screenshot", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        res = response.get_json()
        self.assertEqual(res["layers"]["screenshot"]["status"], "failed")

    def test_history_endpoints(self):
        """Tests GET /api/history and DELETE /api/history."""
        # 1. Fetch
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("history", data)

        # 2. Delete
        del_response = self.client.delete("/api/history")
        self.assertEqual(del_response.status_code, 200)
        del_data = del_response.get_json()
        self.assertTrue(del_data["success"])

        # 3. Verify empty
        after_response = self.client.get("/api/history")
        after_data = after_response.get_json()
        self.assertEqual(after_data["count"], 0)

    def test_community_endpoints(self):
        """Tests GET /api/community and upvoting."""
        # Reseed initial data first if needed
        from database.models import TelemetryRepository
        TelemetryRepository.seed_initial_data_if_empty()

        response = self.client.get("/api/community")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertGreater(data["count"], 0)

        report_id = data["reports"][0]["id"]
        upvote_res = self.client.post(f"/api/community/{report_id}/upvote")
        self.assertEqual(upvote_res.status_code, 200)
        self.assertTrue(upvote_res.get_json()["success"])

    def test_scan_message_explainable_structure(self):
        """Tests that POST /api/scan returns rich explainable Layer 1 metadata."""
        payload = {
            "input": "URGENT: SBI Security Alert! Your account is suspended. Pay ₹500 fee immediately at http://sbi-unblock.xyz",
            "type": "message_with_url"
        }
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        content_layer = data["layers"]["content"]
        self.assertIn("detailed_indicators", content_layer)
        self.assertIn("categories_detected", content_layer)
        self.assertIn("confidence", content_layer)
        self.assertIn("mitigating_factors", content_layer)
        self.assertIn(content_layer["confidence"], ("high", "medium", "low"))
        for ind in content_layer["detailed_indicators"]:
            self.assertIn("name", ind)
            self.assertIn("why_detected", ind)
            self.assertIn("severity", ind)
            self.assertIn("contribution", ind)

        # Verify P1 Community Pattern Matching
        self.assertIn("community_match", data)
        self.assertIn("matched", data["community_match"])

        # Verify P2 Scam Journey Progression
        self.assertIn("scam_journey", data)
        self.assertIn("stages", data["scam_journey"])
        self.assertEqual(len(data["scam_journey"]["stages"]), 4)

        # Verify P5 Scoring Breakdown
        self.assertIn("scoring_breakdown", data)
        self.assertIn("content_score", data["scoring_breakdown"])
        self.assertIn("url_score", data["scoring_breakdown"])
        self.assertIn("total_score", data["scoring_breakdown"])

    def test_community_report_submission(self):
        """Tests POST /api/community/report submits a clean report."""
        payload = {
            "title": "FedEx Customs Fee SMS",
            "category": "Delivery Phishing",
            "reported_item": "SMS demanding $2.50 via fedex-parcel-clear.xyz",
            "description": "Scammer claims package cannot be delivered without immediate payment."
        }
        res = self.client.post("/api/community/report", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["report_id"].startswith("REP-"))

    def test_radar_trends_endpoint(self):
        """Tests GET /api/radar/trends returns authentic data without invented stats."""
        res = self.client.get("/api/radar/trends")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("status", data)
        self.assertIn("total_reports", data)
        self.assertIn("trends", data)
        self.assertIn("data_notice", data)
        self.assertIsInstance(data["has_sufficient_data"], bool)


    def test_extract_ocr_empty_upload(self):
        """Tests POST /api/extract/ocr without file returns structured 400 JSON error."""
        res = self.client.post("/api/extract/ocr", data={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("No screenshot file provided", data["error"])

    def test_extract_ocr_corrupt_file(self):
        """Tests POST /api/extract/ocr with corrupted non-image file returns structured 400 JSON error."""
        data = {"image": (io.BytesIO(b"NOT_A_REAL_IMAGE"), "bad.png")}
        res = self.client.post("/api/extract/ocr", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        resp_data = res.get_json()
        self.assertIn("error", resp_data)
        self.assertIn("Image validation failed", resp_data["error"])


if __name__ == "__main__":
    unittest.main()
