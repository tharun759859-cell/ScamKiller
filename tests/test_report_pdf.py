"""
SCAM KILLER — Tests for ReportLab PDF Generation Service
"""

import unittest
from services.report_service import ReportService


class TestReportService(unittest.TestCase):

    def test_reportlab_available(self):
        """Verifies ReportLab engine is available."""
        self.assertTrue(ReportService.is_available())

    def test_generate_pdf_structure(self):
        """Tests generating a valid PDF with header bytes."""
        sample_data = {
            "scan_id": "SK-TEST-001",
            "risk_level": "suspicious",
            "submitted_item": "URGENT: Click here to verify your account or it will be suspended",
            "explanation": "High urgency language combined with credential harvesting phishing patterns.",
            "detected_indicators": [
                {"title": "Account block threat"},
                {"title": "Urgency trigger language"}
            ],
            "why_it_matters": "Attackers induce panic to steal credentials.",
            "recommended_steps": [
                "Do not click links",
                "Contact bank directly"
            ]
        }
        pdf_bytes = ReportService.generate_pdf_report(sample_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 1000)
        # PDF files must start with %PDF
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_generate_safe_verdict_pdf(self):
        """Tests generating PDF for a safe classification."""
        sample_data = {
            "scan_id": "SK-TEST-002",
            "risk_level": "safe",
            "submitted_item": "Here is the agenda for our team meeting tomorrow morning.",
            "explanation": "No suspicious keywords, links, or urgency vectors detected.",
            "detected_indicators": [],
            "recommended_steps": ["Maintain standard digital security hygiene."]
        }
        pdf_bytes = ReportService.generate_pdf_report(sample_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_generate_screenshot_ocr_pdf(self):
        """Tests generating PDF with visual OCR extracted text, scoring breakdown, and attack journey."""
        sample_data = {
            "scan_id": "SK-OCR-003",
            "risk_level": "suspicious",
            "source_type": "screenshot",
            "category": "Banking / KYC",
            "impersonated_entity": "HDFC Bank",
            "extracted_text": "Dear Customer, Your HDFC NetBanking access is suspended due to expired PAN card. Complete re-KYC at https://hdfc-kyc-update.xyz immediately.",
            "explanation": "Visual OCR text reveals malicious PAN card phishing targeting HDFC Bank customers.",
            "detected_indicators": [
                {"title": "Fake Brand Authority", "severity": "high", "explanation": "Impersonates HDFC Bank."},
                {"title": "High-Risk Domain", "severity": "high", "explanation": "Directs to .xyz phishing site."},
                {"title": "Manufactured Urgency", "severity": "medium", "explanation": "Claims account is suspended."}
            ],
            "scam_journey": {
                "stages": [
                    {"stage": "SMS/WhatsApp Lure", "status": "active"},
                    {"stage": "Fake Portal", "status": "active"},
                    {"stage": "Credential Harvesting", "status": "active"},
                    {"stage": "Financial Theft", "status": "potential"}
                ]
            },
            "scoring_breakdown": {
                "total_score": 95,
                "content_score": 90,
                "url_score": 100
            },
            "why_it_matters": "Inputting NetBanking credentials will allow attackers to drain bank accounts.",
            "recommended_actions": [
                "Do not visit the .xyz link.",
                "Verify KYC status only inside official branch or verified NetBanking app."
            ],
            "verification_advice": "Check your KYC status only by calling the phone number on the back of your HDFC debit card."
        }
        pdf_bytes = ReportService.generate_pdf_report(sample_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 2500)

    def test_cached_styles_singleton(self):
        """Verifies that ReportService._get_styles() reuses the pre-cached style dictionary."""
        styles1 = ReportService._get_styles()
        styles2 = ReportService._get_styles()
        self.assertIs(styles1, styles2)
        self.assertIn("title", styles1)
        self.assertIn("bullet", styles1)
        self.assertIn("step_num", styles1)

    def test_high_volume_generation_speed(self):
        """Tests that generating 20 PDF reports consecutively is fast (averaging < 30ms)."""
        import time
        sample_data = {
            "scan_id": "SK-BENCH-001",
            "risk_level": "suspicious",
            "submitted_item": "Urgent KYC Verification Alert",
            "explanation": "High risk account compromise lure.",
            "detected_indicators": [{"title": "Phishing Link"}, {"title": "Fake Brand Authority"}],
            "why_it_matters": "Credentials may be harvested.",
            "recommended_steps": ["Do not click", "Verify with bank"]
        }
        start = time.perf_counter()
        for _ in range(20):
            pdf = ReportService.generate_pdf_report(sample_data)
            self.assertTrue(pdf.startswith(b"%PDF"))
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / 20) * 1000
        # Average must be well below 50ms
        self.assertLess(avg_ms, 50.0)

    def test_api_report_pdf_endpoint(self):
        """Verifies /api/report/pdf endpoint returns application/pdf with valid PDF bytes."""
        from app import create_app
        app = create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        sample_data = {
            "scan_id": "API-TEST-999",
            "risk_level": "suspicious",
            "submitted_item": "Your electricity will be disconnected tonight at 9:30 PM. Call +91-9876543210.",
            "explanation": "Utility bill disconnection scam attempting remote screen sharing.",
            "detected_indicators": [{"title": "Utility bill lure", "severity": "high", "explanation": "Evening power cut threat."}]
        }
        res = client.post("/api/report/pdf", json=sample_data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Content-Type"), "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF"))
        self.assertIn("API-TEST-999", res.headers.get("Content-Disposition", ""))

    def test_api_report_pdf_by_scan_id_from_sqlite(self):
        """Verifies /api/report/pdf endpoint looks up SQLite history when only scan_id is provided."""
        from app import create_app
        from database.models import TelemetryRepository
        app = create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        scan_id = "SQLITE-TEST-777"
        TelemetryRepository.insert_scan({
            "scan_id": scan_id,
            "scan_type": "url",
            "risk_category": "suspicious",
            "timestamp": "2026-11-19 12:00",
            "display_item": "https://fake-bank-auth.xyz",
            "explanation": "Harvests customer NetBanking credentials on fraudulent domain.",
            "full_report_json": {
                "scan_id": scan_id,
                "risk_level": "suspicious",
                "category": "Banking / KYC",
                "impersonated_entity": "State Bank of India",
                "submitted_item": "https://fake-bank-auth.xyz",
                "explanation": "Harvests customer NetBanking credentials on fraudulent domain.",
                "detected_indicators": [
                    {"title": "Unverified Domain", "severity": "high", "explanation": ".xyz TLD used for banking."}
                ],
                "recommended_actions": ["Do not submit credentials."]
            }
        })

        # Request PDF with ONLY scan_id
        res = client.post("/api/report/pdf", json={"scan_id": scan_id})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Content-Type"), "application/pdf")
        self.assertTrue(res.data.startswith(b"%PDF"))
        self.assertGreater(len(res.data), 2000)


if __name__ == "__main__":
    unittest.main()
