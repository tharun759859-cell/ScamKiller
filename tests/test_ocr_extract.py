"""
SCAM KILLER — Tests for Dedicated OCR Extraction Service
"""

import unittest
from services.ocr_service import OcrService


class TestOcrService(unittest.TestCase):

    def setUp(self):
        self.service = OcrService()

    def test_engine_available(self):
        """Verifies OCR engine (Apple Vision or Tesseract) is detected."""
        self.assertTrue(self.service.is_ocr_available())

    def test_empty_image_rejected(self):
        """Empty image bytes must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.extract_text(b"", "empty.png")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_corrupt_file_rejected(self):
        """Non-image bytes must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.extract_text(b"NOT_AN_IMAGE_FILE_DATA", "test.png")
        self.assertIn("image validation failed", str(ctx.exception).lower())

    def test_real_screenshot_extraction_no_scam_verdict(self):
        """
        Tests OCR extraction on authentic screenshot.
        Verifies that OcrService returns extracted text without assigning a scam classification.
        """
        try:
            with open("scratch/sbi_kyc_screenshot.png", "rb") as f:
                img_bytes = f.read()
        except FileNotFoundError:
            self.skipTest("scratch/sbi_kyc_screenshot.png not found")

        res = self.service.extract_text(img_bytes, "sbi_kyc_screenshot.png")
        self.assertTrue(res["success"])
        self.assertIn("extracted_text", res)
        self.assertTrue(res["has_text"])
        self.assertGreater(res["word_count"], 0)
        # CRITICAL: OcrService must NOT classify or produce risk levels
        self.assertNotIn("risk_level", res)
        self.assertNotIn("threat_score", res)
        self.assertNotIn("status", res)


if __name__ == "__main__":
    unittest.main()
