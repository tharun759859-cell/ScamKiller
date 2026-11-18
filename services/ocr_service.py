"""
SCAM KILLER — Dedicated OCR Text Extraction Service
Extracts text from screenshots using Apple Vision framework with Tesseract fallback.
Strictly returns extracted text and never performs automatic scam classification.
"""

from typing import Dict, Any
from analyzers.screenshot_analyzer import ScreenshotAnalyzer
from security.validator import InputValidator


class OcrService:
    """Provides pure image text extraction without threat classification."""

    def __init__(self):
        self._analyzer = ScreenshotAnalyzer()

    def is_ocr_available(self) -> bool:
        """Returns True if an OCR engine (Apple Vision or Tesseract) is available."""
        return self._analyzer.is_ocr_available()

    def get_engine_name(self) -> str:
        """Returns active OCR engine identifier."""
        return self._analyzer.get_engine_name()

    def extract_text(self, file_bytes: bytes, filename: str = "screenshot.png") -> Dict[str, Any]:
        """
        Validates image bytes and extracts readable text.
        Raises ValueError if file is empty or not an image.
        """
        if not file_bytes:
            raise ValueError("Uploaded image file is empty.")

        # Validate format via InputValidator magic byte inspection
        is_valid, err_msg, detected_fmt = InputValidator.validate_image_stream(file_bytes, filename)
        if not is_valid:
            raise ValueError(f"Image validation failed: {err_msg}")

        # Run analyzer strictly for text extraction
        res = self._analyzer.analyze(file_bytes, filename=filename)
        if res.get("status") == "failed":
            raise ValueError(res.get("summary", "Image processing failed."))
        if res.get("status") == "unavailable":
            raise RuntimeError(res.get("summary", "Local OCR engine is unavailable."))

        extracted_text = str(res.get("extracted_text", "")).strip()
        word_count = len(extracted_text.split()) if extracted_text else 0

        return {
            "success": True,
            "extracted_text": extracted_text,
            "word_count": word_count,
            "character_count": len(extracted_text),
            "ocr_engine": res.get("ocr_engine", self.get_engine_name()),
            "filename": filename,
            "has_text": word_count > 0,
            "message": "Text extracted successfully." if word_count > 0 else "Image was processed successfully, but no readable text was detected."
        }
