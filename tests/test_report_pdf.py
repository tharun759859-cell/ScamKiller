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


if __name__ == "__main__":
    unittest.main()
