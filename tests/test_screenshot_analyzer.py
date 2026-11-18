"""
SCAM KILLER — Tests for Layer 3: Screenshot Text Analysis & OCR
"""

import unittest
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


if __name__ == "__main__":
    unittest.main()
