"""
SCAM KILLER — Layer 3: Screenshot Text Analysis
Extracts visible text from user-uploaded screenshots using local OCR
and coordinates downstream analysis with Layer 1 (Content) and Layer 2 (URL).
"""

import shutil
import tempfile
import os
import subprocess
from typing import Dict, Any, Optional
from .base import BaseAnalyzer
from security.validator import InputValidator


class ScreenshotAnalyzer(BaseAnalyzer):
    """
    Validates uploaded images and safely extracts visible text via local OCR
    (Apple Vision Framework on macOS, or Tesseract OCR on other platforms),
    gracefully reporting status when unavailable.
    """

    def __init__(self):
        # 1. Check native macOS Apple Vision availability via osascript and vision_ocr.js
        self.apple_vision_available = False
        self.vision_script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tools",
            "vision_ocr.js"
        )
        if os.path.exists("/usr/bin/osascript") and os.path.exists(self.vision_script_path):
            self.apple_vision_available = True

        # 2. Check system Tesseract binary & python package availability
        self.tesseract_binary = shutil.which("tesseract")
        self.pytesseract_available = False
        try:
            import pytesseract
            self.pytesseract = pytesseract
            self.pytesseract_available = bool(self.tesseract_binary)
        except ImportError:
            self.pytesseract = None
            self.pytesseract_available = False

    def is_ocr_available(self) -> bool:
        """Returns True if native Apple Vision or Tesseract OCR is available."""
        return self.apple_vision_available or (self.pytesseract_available and bool(self.tesseract_binary))

    def get_engine_name(self) -> str:
        """Returns the identifier of the active local OCR engine."""
        if self.apple_vision_available:
            return "apple_vision"
        elif self.pytesseract_available and bool(self.tesseract_binary):
            return "tesseract"
        return "none"

    def analyze(self, target: Any, **kwargs) -> Dict[str, Any]:
        """
        Analyzes an uploaded image bytes buffer.
        target: bytes (raw image file stream)
        kwargs: filename (optional str)
        """
        file_bytes = target
        filename = kwargs.get("filename", "screenshot.png")

        # 1. Validate image format & size via magic bytes
        is_valid, err_msg, detected_fmt = InputValidator.validate_image_stream(file_bytes, filename)
        if not is_valid:
            return {
                "status": "failed",
                "score": 0,
                "summary": f"Image validation failed: {err_msg}",
                "extracted_text": "",
                "indicators": [f"Invalid image format / header: {err_msg}"],
                "ocr_engine_available": self.is_ocr_available(),
                "ocr_engine": self.get_engine_name()
            }

        # 2. Check local OCR engine availability
        if not self.is_ocr_available():
            return {
                "status": "unavailable",
                "score": 0,
                "summary": (
                    f"Uploaded image ({detected_fmt.upper()}) validated successfully. "
                    "Local OCR extraction engine is not available in this environment. "
                    "Enable macOS Vision framework or install Tesseract OCR to extract visual text."
                ),
                "extracted_text": "",
                "indicators": ["Valid image file verified", "OCR engine not available on host"],
                "ocr_engine_available": False,
                "ocr_engine": "none",
                "detected_format": detected_fmt
            }

        # 3. Safe Temporary File Handling for OCR Execution
        extracted_text = ""
        temp_path = None
        engine_used = self.get_engine_name()

        try:
            with tempfile.NamedTemporaryFile(suffix=f".{detected_fmt}", delete=False) as tmp:
                tmp.write(file_bytes)
                temp_path = tmp.name

            if self.apple_vision_available:
                cmd = ["/usr/bin/osascript", "-l", "JavaScript", self.vision_script_path, temp_path]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if res.returncode == 0:
                    extracted_text = res.stdout
                else:
                    raise RuntimeError(f"Apple Vision OCR execution failed: {res.stderr}")
            elif self.pytesseract_available and self.tesseract_binary:
                from PIL import Image
                with Image.open(temp_path) as img:
                    extracted_text = self.pytesseract.image_to_string(img)

        except Exception as ocr_err:
            return {
                "status": "failed",
                "score": 0,
                "summary": f"OCR extraction encountered an error: {str(ocr_err)}",
                "extracted_text": "",
                "indicators": ["OCR extraction error occurred during image processing"],
                "ocr_engine_available": True,
                "ocr_engine": engine_used,
                "detected_format": detected_fmt
            }
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        cleaned_text = extracted_text.strip()
        if not cleaned_text:
            return {
                "status": "passed",
                "score": 0,
                "summary": "OCR completed: No readable text detected inside the uploaded screenshot.",
                "extracted_text": "",
                "indicators": ["Image contained zero discernible text characters"],
                "ocr_engine_available": True,
                "ocr_engine": engine_used,
                "detected_format": detected_fmt
            }

        word_count = len(cleaned_text.split())
        return {
            "status": "completed",
            "score": 10,
            "summary": f"Apple Vision OCR extracted {word_count} words from screenshot.",
            "extracted_text": cleaned_text,
            "indicators": [f"Extracted visible text from image ({word_count} words) via {engine_used}"],
            "ocr_engine_available": True,
            "ocr_engine": engine_used,
            "detected_format": detected_fmt
        }
