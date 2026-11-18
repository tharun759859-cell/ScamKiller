"""
SCAM KILLER — Tests for Layer 3: Screenshot Text Analysis & OCR
"""

import unittest
from unittest.mock import patch, MagicMock
from analyzers.screenshot_analyzer import ScreenshotAnalyzer


class TestScreenshotAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ScreenshotAnalyzer()

    def test_valid_png_header(self):
        """Tests that a stream with authentic PNG magic bytes passes image validation."""
        valid_png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = self.analyzer.analyze(valid_png_bytes, filename="test_capture.png")
        # Should not fail image validation
        self.assertNotEqual(result["status"], "failed")
        self.assertIn(result["status"], ("unavailable", "completed", "passed"))

    def test_valid_jpeg_header(self):
        """Tests authentic JPEG magic bytes."""
        valid_jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        result = self.analyzer.analyze(valid_jpeg_bytes, filename="photo.jpg")
        self.assertNotEqual(result["status"], "failed")

    def test_invalid_image_file(self):
        """Tests that plain text or corrupted files are rejected by magic byte inspection."""
        corrupted_bytes = b"Hello, I am a plain text file pretending to be a PNG."
        result = self.analyzer.analyze(corrupted_bytes, filename="fake.png")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("Invalid image format" in ind for ind in result["indicators"]))

    def test_empty_image_stream(self):
        """Tests empty byte payload."""
        result = self.analyzer.analyze(b"", filename="empty.png")
        self.assertEqual(result["status"], "failed")

    def test_ocr_availability_reported_truthfully(self):
        """Tests that the system truthfully reports whether OCR engine is installed."""
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        result = self.analyzer.analyze(valid_png, filename="test.png")
        # Ensure ocr_engine_available key is present and boolean
        self.assertIn("ocr_engine_available", result)
        self.assertIsInstance(result["ocr_engine_available"], bool)

    def test_macos_vision_preservation(self):
        """Tests Apple Vision priority and language capabilities."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = True
        self.assertTrue(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "apple_vision")
        self.assertEqual(analyzer.get_available_languages(), ["eng", "tam", "multilingual"])

    def test_tesseract_unavailable_behavior(self):
        """Tests analyzer behavior when no OCR engine (Apple Vision nor Tesseract) is available."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = False
        analyzer.tesseract_binary = None

        self.assertFalse(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "none")
        self.assertEqual(analyzer.get_available_languages(), [])

        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        res = analyzer.analyze(valid_png, filename="test.png")
        self.assertEqual(res["status"], "unavailable")
        self.assertFalse(res["ocr_engine_available"])
        self.assertEqual(res["ocr_engine"], "none")
        self.assertIn("Local OCR extraction engine is not available", res["summary"])

    def test_tesseract_available_behavior(self):
        """Tests analyzer detection when Tesseract is available in Linux/Docker environment."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.available_languages = ["eng"]

        self.assertTrue(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "tesseract")
        self.assertEqual(analyzer.get_available_languages(), ["eng"])
        self.assertEqual(analyzer.get_tesseract_lang_string(), "eng")

    def test_tamil_and_english_ocr_language_selection(self):
        """Tests bilingual language string resolution for Tesseract."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"

        # Case 1: Both eng and tam installed (with osd filter)
        analyzer.available_languages = ["eng", "tam", "osd"]
        self.assertEqual(analyzer.get_available_languages(), ["eng", "tam"])
        self.assertEqual(analyzer.get_tesseract_lang_string(), "eng+tam")

        # Case 2: Only tam installed
        analyzer.available_languages = ["tam"]
        self.assertEqual(analyzer.get_available_languages(), ["tam"])
        self.assertEqual(analyzer.get_tesseract_lang_string(), "tam")

        # Case 3: Only eng installed
        analyzer.available_languages = ["eng"]
        self.assertEqual(analyzer.get_available_languages(), ["eng"])
        self.assertEqual(analyzer.get_tesseract_lang_string(), "eng")

    def test_tesseract_ocr_extraction_flow(self):
        """Tests complete text extraction flow under Tesseract engine."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.available_languages = ["eng", "tam"]

        mock_pytesseract = MagicMock()
        mock_pytesseract.image_to_string.return_value = "Urgent: Your SBI account is blocked. Update KYC now."
        analyzer.pytesseract = mock_pytesseract

        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        mock_img = MagicMock()
        mock_img.size = (800, 600)
        mock_img.mode = "L"
        with patch("PIL.Image.open") as mock_img_open:
            mock_img_open.return_value.__enter__.return_value = mock_img
            result = analyzer.analyze(valid_png, filename="sbi_alert.png")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["ocr_engine"], "tesseract")
        self.assertTrue(result["ocr_engine_available"])
        self.assertIn("SBI account is blocked", result["extracted_text"])
        self.assertIn("Tesseract OCR extracted", result["summary"])
        mock_pytesseract.image_to_string.assert_called_once()
        _, kwargs = mock_pytesseract.image_to_string.call_args
        self.assertEqual(kwargs.get("lang"), "eng+tam")

    def test_pillow_missing_makes_tesseract_unavailable(self):
        """Verifies that missing Pillow package prevents Tesseract from claiming availability."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.pillow_available = False

        self.assertFalse(analyzer.is_tesseract_ready())
        self.assertFalse(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "none")

    def test_pytesseract_missing_makes_tesseract_unavailable(self):
        """Verifies that missing pytesseract package prevents Tesseract from claiming availability."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = False
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.pillow_available = True

        self.assertFalse(analyzer.is_tesseract_ready())
        self.assertFalse(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "none")

    def test_tesseract_binary_missing_makes_tesseract_unavailable(self):
        """Verifies that missing tesseract system binary prevents Tesseract from claiming availability."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = None
        analyzer.pillow_available = True

        self.assertFalse(analyzer.is_tesseract_ready())
        self.assertFalse(analyzer.is_ocr_available())
        self.assertEqual(analyzer.get_engine_name(), "none")

    def test_valid_image_flag_propagation(self):
        """Verifies valid_image flag is True for valid image and False for corrupted file."""
        analyzer = ScreenshotAnalyzer()
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        res_valid = analyzer.analyze(valid_png, filename="test.png")
        self.assertTrue(res_valid.get("valid_image"))

        corrupt = b"NOT_A_VALID_IMAGE"
        res_corrupt = analyzer.analyze(corrupt, filename="test.png")
        self.assertFalse(res_corrupt.get("valid_image"))

    def test_large_image_rejection(self):
        """Tests that images exceeding 16 megapixels or 4096px dimension are rejected safely."""
        analyzer = ScreenshotAnalyzer()
        analyzer.pillow_available = True
        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

        mock_img = MagicMock()
        mock_img.size = (5000, 5000)

        with patch("PIL.Image.open") as mock_open:
            mock_open.return_value.__enter__.return_value = mock_img
            result = analyzer.analyze(valid_png, filename="giant.png")

        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["valid_image"])
        self.assertEqual(result.get("error_code"), "IMAGE_TOO_LARGE")
        self.assertIn("exceed safe limit", result["summary"])

    def test_ocr_timeout_handling(self):
        """Tests that Tesseract timeouts return a structured error response instead of crashing."""
        import subprocess
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.pillow_available = True

        mock_pytesseract = MagicMock()
        mock_pytesseract.image_to_string.side_effect = subprocess.TimeoutExpired(cmd="tesseract", timeout=25)
        analyzer.pytesseract = mock_pytesseract

        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        mock_img = MagicMock()
        mock_img.size = (800, 600)
        mock_img.mode = "RGB"
        mock_img.convert.return_value = mock_img

        with patch("PIL.Image.open") as mock_open:
            mock_open.return_value.__enter__.return_value = mock_img
            result = analyzer.analyze(valid_png, filename="timeout_test.png")

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result.get("error_code"), "OCR_TIMEOUT")
        self.assertIn("timed out", result["summary"])

    def test_tesseract_execution_failure_handled_gracefully(self):
        """Tests that an arbitrary Tesseract execution crash returns a structured response."""
        analyzer = ScreenshotAnalyzer()
        analyzer.apple_vision_available = False
        analyzer.pytesseract_available = True
        analyzer.tesseract_binary = "/usr/bin/tesseract"
        analyzer.pillow_available = True

        mock_pytesseract = MagicMock()
        mock_pytesseract.image_to_string.side_effect = RuntimeError("Fatal Leptonica error: corrupt pix")
        analyzer.pytesseract = mock_pytesseract

        valid_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        mock_img = MagicMock()
        mock_img.size = (800, 600)
        mock_img.mode = "L"

        with patch("PIL.Image.open") as mock_open:
            mock_open.return_value.__enter__.return_value = mock_img
            result = analyzer.analyze(valid_png, filename="corrupt_ocr.png")

        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["valid_image"])
        self.assertIn("Fatal Leptonica error", result["summary"])

    def test_find_tesseract_binary_fallback(self):
        """Tests that _find_tesseract_binary tests standard system paths when shutil.which is None."""
        analyzer = ScreenshotAnalyzer()
        with patch("shutil.which", return_value=None):
            with patch("os.path.exists", side_effect=lambda p: p == "/usr/bin/tesseract"):
                with patch("os.access", return_value=True):
                    found = analyzer._find_tesseract_binary()
                    self.assertEqual(found, "/usr/bin/tesseract")


if __name__ == "__main__":
    unittest.main()

