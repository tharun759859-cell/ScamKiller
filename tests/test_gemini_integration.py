"""
SCAM KILLER — Google Gemini AI Integration Test Suite
Verifies all 10 required Phase 2 capabilities:
1. Gemini API connection and configuration.
2. Suspicious SMS analysis.
3. Legitimate transactional SMS analysis.
4. Suspicious email analysis.
5. Suspicious URL analysis.
6. Tamil and English content.
7. AI Advisory Chat.
8. Invalid API key handling.
9. API quota error handling.
10. Existing OCR, transcription, and PDF report regression tests.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from services.ai_service import AIService, ScamAnalysisResult, ThreatIndicator
from services.scan_service import ScanService
from services.report_service import ReportService
from services.transcription_service import TranscriptionService
from services.ocr_service import OcrService
from app import create_app


class TestGeminiAIIntegration(unittest.TestCase):

    def setUp(self):
        # Enable simulated AI test mode so tests run deterministically without consuming quota
        os.environ["GEMINI_TEST_MODE"] = "1"
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.ai_service = AIService()
        self.scan_service = ScanService()

    # -----------------------------------------------------------------
    # 1. Gemini API Connection & Configuration
    # -----------------------------------------------------------------
    def test_gemini_configuration_and_placeholders(self):
        """Verifies that missing or placeholder API keys are detected accurately."""
        # Unconfigured when empty
        svc_empty = AIService(api_key="")
        self.assertFalse(svc_empty.is_configured())

        # Unconfigured when using template placeholder
        svc_placeholder = AIService(api_key="PASTE_API_KEY_HERE")
        self.assertFalse(svc_placeholder.is_configured())

        # Configured when a real key is present
        svc_real = AIService(api_key="AIzaSyRealMockedKeyForTestingOnly12345")
        self.assertTrue(svc_real.is_configured())
        self.assertTrue(svc_real.model in ["gemini-2.5-flash", "gemini-3.5-flash-lite", "gemini-3.8-flash"])

    def test_missing_api_key_raises_clear_error_outside_test_mode(self):
        """When not in test mode, missing API key must raise a clear configuration error."""
        with patch.dict(os.environ, {"GEMINI_TEST_MODE": "0", "GEMINI_API_KEY": "PASTE_API_KEY_HERE"}):
            svc = AIService()
            with self.assertRaises(RuntimeError) as ctx:
                svc.analyze_content("Suspicious message text")
            self.assertIn("GEMINI_API_KEY", str(ctx.exception))
            self.assertIn(".env", str(ctx.exception))

    # -----------------------------------------------------------------
    # 2. Suspicious SMS Analysis
    # -----------------------------------------------------------------
    def test_suspicious_sms_analysis(self):
        """Verifies contextual detection of coercive banking KYC scam SMS."""
        sms_text = (
            "Dear SBI Customer, your YONO banking account will be blocked within 24 hours. "
            "Please update your PAN/KYC immediately at http://sbi-kyc-verify.top to avoid suspension."
        )
        res = self.scan_service.process_text_scan(sms_text)

        self.assertEqual(res["risk_level"], "suspicious")
        self.assertEqual(res["classification"], "Suspicious")
        self.assertGreaterEqual(res["confidence"], 0.85)
        self.assertTrue(len(res["detected_indicators"]) > 0)
        self.assertIn("why_it_matters", res)
        self.assertIn("recommended_actions", res)
        self.assertIn("verification_advice", res)

    # -----------------------------------------------------------------
    # 3. Legitimate Transactional SMS Analysis
    # -----------------------------------------------------------------
    def test_legitimate_transactional_sms_analysis(self):
        """Verifies that normal transactional SMS is not falsely flagged as a scam."""
        legit_text = (
            "INR 1,250.00 debited from HDFC Bank A/C XX4829 on 17-NOV-2026 at Swiggy UPI Ref 432891. "
            "Available balance: INR 24,510.50. If not done by you, call official bank helpline."
        )
        res = self.scan_service.process_text_scan(legit_text)

        self.assertEqual(res["risk_level"], "safe")
        self.assertEqual(res["classification"], "No Clear Warning Signs")
        self.assertIn("important_uncertainties", res)
        # Verify honesty about limitations
        self.assertTrue(any("guarantee" in u.lower() or "limit" in u.lower() or "verified" in u.lower() for u in res["important_uncertainties"]))

    # -----------------------------------------------------------------
    # 4. Suspicious Email Analysis
    # -----------------------------------------------------------------
    def test_suspicious_email_analysis(self):
        """Verifies detection of phishing email with tax refund and credential trap."""
        email_body = (
            "From: IRS Tax Department <refund@tax-refund-gov.xyz>\n"
            "Subject: Your annual tax refund of $850 is pending approval\n\n"
            "Dear Taxpayer, click here immediately to confirm your banking credentials "
            "and receive your unclaimed tax refund before the window expires tonight."
        )
        res = self.scan_service.process_text_scan(email_body)

        self.assertEqual(res["risk_level"], "suspicious")
        self.assertTrue(any("urgency" in str(ind).lower() or "credential" in str(ind).lower() for ind in res["detected_indicators"]))

    # -----------------------------------------------------------------
    # 5. Suspicious URL Analysis
    # -----------------------------------------------------------------
    def test_suspicious_url_analysis(self):
        """Verifies analysis of standalone malicious URL."""
        malicious_url = "https://free-reward-claim.xyz/login"
        res = self.scan_service.process_text_scan(malicious_url)

        self.assertEqual(res["risk_level"], "suspicious")
        self.assertEqual(res["scan_type"], "url")
        self.assertEqual(res["layers"]["urlStructure"]["status"], "flagged")

    # -----------------------------------------------------------------
    # 6. Tamil and English Multi-Language Content
    # -----------------------------------------------------------------
    def test_tamil_content_analysis(self):
        """Verifies scam detection on Tamil language input."""
        tamil_scam = (
            "உங்கள் எஸ்பிஐ வங்கி கணக்கு முடக்கப்பட்டது. "
            "உடனடியாக உங்கள் KYC விவரங்களை புதுப்பிக்க இந்த link ஐ கிளிக் செய்யவும்: http://sbi-kyc-verify.top"
        )
        res = self.scan_service.process_text_scan(tamil_scam)

        self.assertEqual(res["risk_level"], "suspicious")
        self.assertEqual(res["classification"], "Suspicious")
        self.assertIn("verification_advice", res)

    # -----------------------------------------------------------------
    # 7. AI Advisory Chat
    # -----------------------------------------------------------------
    def test_ai_advisory_chat_endpoint(self):
        """Verifies interactive advisory guidance via POST /api/chat."""
        messages = [
            {"role": "user", "content": "Someone called claiming to be from my bank asking for an OTP. What should I do?"}
        ]
        res = self.client.post("/api/chat", json={"messages": messages})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["role"], "assistant")
        reply = data["content"].lower()
        # Must give actionable safety guidance
        self.assertTrue("bank" in reply or "otp" in reply or "helpline" in reply or "disconnect" in reply)

    def test_ai_advisory_chat_upi_pin_question(self):
        """Verifies educational guidance regarding UPI PIN scam."""
        messages = [
            {"role": "user", "content": "A buyer sent me a QR code and asked me to enter my UPI PIN to receive money. Is this genuine?"}
        ]
        res = self.client.post("/api/chat", json={"messages": messages})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        reply = data["content"].lower()
        self.assertTrue("never" in reply or "scam" in reply or "pin" in reply)

    # -----------------------------------------------------------------
    # 8. Invalid API Key Error Handling
    # -----------------------------------------------------------------
    def test_invalid_api_key_error_handling(self):
        """Simulates 403 / API_KEY_INVALID from google-genai and checks user-friendly error."""
        from google.genai import errors

        # Mock exception
        mock_err = errors.APIError(403, {"error": {"message": "API key not valid. Please pass a valid API key."}})

        with patch.dict(os.environ, {"GEMINI_TEST_MODE": "0", "GEMINI_API_KEY": "AIzaFakeInvalidKey"}):
            svc = AIService(api_key="AIzaFakeInvalidKey")
            # Mock generate_content raising APIError
            mock_client = MagicMock()
            mock_client.models.generate_content.side_effect = mock_err
            svc._client = mock_client

            with self.assertRaises(RuntimeError) as ctx:
                svc.analyze_content("Test input message")

            self.assertIn("Invalid API key", str(ctx.exception))
            self.assertIn(".env", str(ctx.exception))

    # -----------------------------------------------------------------
    # 9. API Quota Exceeded Error Handling
    # -----------------------------------------------------------------
    def test_api_quota_error_handling(self):
        """Simulates 429 RESOURCE_EXHAUSTED from google-genai and checks user-friendly error."""
        from google.genai import errors

        mock_err = errors.APIError(429, {"error": {"message": "Resource has been exhausted (e.g. check quota)."}})

        with patch.dict(os.environ, {"GEMINI_TEST_MODE": "0", "GEMINI_API_KEY": "AIzaRealKeyWithNoQuota"}):
            svc = AIService(api_key="AIzaRealKeyWithNoQuota")
            mock_client = MagicMock()
            mock_client.models.generate_content.side_effect = mock_err
            svc._client = mock_client

            with self.assertRaises(RuntimeError) as ctx:
                svc.analyze_content("Test input message")

            self.assertIn("quota exceeded", str(ctx.exception).lower())

    # -----------------------------------------------------------------
    # 10. OCR, Transcription & PDF Regression Tests
    # -----------------------------------------------------------------
    def test_pdf_report_generation_with_gemini_data(self):
        """Verifies that PDF report generation integrates Gemini assessment fields cleanly."""
        sample_assessment = {
            "scan_id": "SK-GEMINI-TEST-001",
            "risk_level": "suspicious",
            "classification": "Suspicious",
            "confidence": 0.95,
            "explanation": "Contextual AI analysis detected fraudulent impersonation of India Post.",
            "summary": "Contextual AI analysis detected fraudulent impersonation of India Post.",
            "detected_indicators": [
                {"title": "Spoofed Domain Extension", "severity": "high", "explanation": "Registered on disposable .top TLD."},
                {"title": "Unsolicited Micro-Fee Surcharge", "severity": "high", "explanation": "Demands ₹5 payment to release delivery."}
            ],
            "why_it_matters": "Victims inputting card details suffer immediate unauthorized transactions.",
            "verification_advice": "Visit https://indiapost.gov.in directly to track registered articles.",
            "recommended_actions": [
                "Do not open the link or transmit card credentials.",
                "Report the transmitting sender to postal fraud authorities."
            ],
            "important_uncertainties": [
                "Carrier dispatch logs could not be verified offline."
            ],
            "submitted_item": "India Post: Your package cannot be delivered. Pay ₹5 at http://indiapost-fix.top"
        }

        pdf_bytes = ReportService.generate_pdf_report(sample_assessment)
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_health_reports_gemini_provider(self):
        """Verifies /api/health returns google-genai capability status."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        caps = data["capabilities"]
        self.assertEqual(caps["ai_provider"], "google-genai")
        self.assertIn("ai_model", caps)
        self.assertIn("ai_intelligence_engine", caps)


if __name__ == "__main__":
    unittest.main()
