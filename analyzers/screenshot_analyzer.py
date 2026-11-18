"""
SCAM KILLER — Layer 3: Screenshot Text Analysis
Extracts visible text from user-uploaded screenshots using local OCR
(Apple Vision Framework on macOS, or Tesseract OCR on Linux/other platforms)
and coordinates downstream analysis with Layer 1 (Content) and Layer 2 (URL).
"""

import sys
import shutil
import tempfile
import os
import subprocess
import logging
from typing import Dict, Any, Optional
from .base import BaseAnalyzer
from security.validator import InputValidator

logger = logging.getLogger("scam_killer.ocr")


class ScreenshotAnalyzer(BaseAnalyzer):
    """
    Validates uploaded images and safely extracts visible text via local OCR
    (Apple Vision Framework on macOS, or Tesseract OCR on Linux/Docker),
    gracefully reporting status when unavailable.
    """

    def __init__(self):
        # 1. Native macOS Apple Vision detection (strictly on Darwin)
        self.apple_vision_available = False
        self.vision_script_path = None
        if sys.platform == "darwin" and os.path.exists("/usr/bin/osascript"):
            script_candidates = [
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "vision_ocr.js"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools", "vision_ocr.js"),
                os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "tools", "vision_ocr.js"),
                os.path.join(os.getcwd(), "tools", "vision_ocr.js")
            ]
            for candidate in script_candidates:
                if os.path.exists(candidate):
                    self.vision_script_path = os.path.abspath(candidate)
                    self.apple_vision_available = True
                    break

        # 2. System Tesseract executable detection (PATH search + standard Linux paths)
        self.tesseract_binary = self._find_tesseract_binary()

        # 3. Python package dependencies (pytesseract and Pillow)
        self.pytesseract_available = False
        self.pytesseract = None
        self.pillow_available = False
        self.available_languages = []

        # Check Pillow
        try:
            from PIL import Image
            self.pillow_available = True
        except ImportError as pil_err:
            self.pillow_available = False
            logger.warning("Pillow (PIL) is not installed: %s", pil_err)
        except Exception as pil_err:
            self.pillow_available = False
            logger.warning("Failed to initialize Pillow: %s", pil_err)

        # Check pytesseract
        try:
            import pytesseract
            self.pytesseract = pytesseract
            if self.tesseract_binary:
                self.pytesseract.pytesseract.tesseract_cmd = self.tesseract_binary
                self.pytesseract_available = True
                try:
                    self.available_languages = self.pytesseract.get_languages()
                except Exception as lang_err:
                    logger.warning("Could not probe Tesseract languages (%s). Defaulting to ['eng'].", lang_err)
                    self.available_languages = ["eng"]
            else:
                self.pytesseract_available = False
        except ImportError as pytess_err:
            self.pytesseract = None
            self.pytesseract_available = False
            logger.warning("pytesseract Python package is not installed: %s", pytess_err)
        except Exception as pytess_err:
            self.pytesseract = None
            self.pytesseract_available = False
            logger.warning("Failed to initialize pytesseract: %s", pytess_err)

        # Log active OCR engine state securely (no sensitive data)
        self._log_initialization_status()

    def _find_tesseract_binary(self) -> Optional[str]:
        """Locates the tesseract executable via PATH or standard Linux system locations."""
        bin_path = shutil.which("tesseract")
        if bin_path and os.path.exists(bin_path):
            return bin_path

        candidates = [
            "/usr/bin/tesseract",
            "/usr/local/bin/tesseract",
            "/bin/tesseract",
            "/opt/homebrew/bin/tesseract"
        ]
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _log_initialization_status(self):
        """Logs diagnostic status securely without leaking secrets or data."""
        if self.apple_vision_available:
            logger.info("OCR Engine initialized: Apple Vision Framework (macOS native).")
        elif self.is_tesseract_ready():
            logger.info(
                "OCR Engine initialized: Tesseract at '%s' (Languages: %s).",
                self.tesseract_binary,
                self.get_available_languages()
            )
        else:
            reasons = []
            if not self.apple_vision_available and sys.platform == "darwin":
                reasons.append("macOS Apple Vision script missing")
            if not self.tesseract_binary:
                reasons.append("Tesseract system executable not found")
            if not self.pytesseract_available:
                reasons.append("Python pytesseract package unavailable")
            if not self.pillow_available:
                reasons.append("Python Pillow package unavailable")
            logger.warning("Local OCR engine unavailable. Diagnostics: %s", ", ".join(reasons))

    def is_tesseract_ready(self) -> bool:
        """Returns True if Linux/system Tesseract executable and all Python libraries are ready."""
        return bool(
            self.tesseract_binary
            and self.pytesseract_available
            and self.pillow_available
        )

    def is_ocr_available(self) -> bool:
        """Returns True if native Apple Vision or Tesseract OCR is available."""
        return self.apple_vision_available or self.is_tesseract_ready()

    def get_engine_name(self) -> str:
        """Returns the identifier of the active local OCR engine."""
        if self.apple_vision_available:
            return "apple_vision"
        elif self.is_tesseract_ready():
            return "tesseract"
        return "none"

    def get_available_languages(self) -> list:
        """Returns list of active OCR languages."""
        if self.apple_vision_available:
            return ["eng", "tam", "multilingual"]
        if self.is_tesseract_ready() and self.available_languages:
            return [l for l in self.available_languages if l != "osd"]
        return []

    def get_tesseract_lang_string(self) -> str:
        """Determines optimal Tesseract language argument based on installed packs."""
        installed = self.available_languages or []
        has_tam = "tam" in installed
        has_eng = "eng" in installed
        if has_tam and has_eng:
            return "eng+tam"
        elif has_tam:
            return "tam"
        return "eng"

    MAX_IMAGE_DIMENSION = 4096
    MAX_IMAGE_PIXELS = 16_000_000  # 16 Megapixels
    MAX_OCR_TARGET_DIMENSION = 1400  # Optimal reading resolution for OCR
    OCR_TIMEOUT_SECONDS = 25

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
                "valid_image": False,
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
                "valid_image": True,
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

            # Pre-validate image dimensions using Pillow header read before full decoding
            if self.pillow_available:
                from PIL import Image, UnidentifiedImageError
                try:
                    with Image.open(temp_path) as pre_check:
                        if hasattr(pre_check, "size") and isinstance(pre_check.size, (tuple, list)) and len(pre_check.size) == 2:
                            w, h = pre_check.size
                            total_pixels = w * h
                            if w > self.MAX_IMAGE_DIMENSION or h > self.MAX_IMAGE_DIMENSION or total_pixels > self.MAX_IMAGE_PIXELS:
                                return {
                                    "status": "failed",
                                    "valid_image": False,
                                    "score": 0,
                                    "summary": f"Image dimensions ({w}x{h}, {total_pixels} pixels) exceed safe limit of 16 megapixels (4096px).",
                                    "extracted_text": "",
                                    "indicators": ["Image resolution exceeds safety limits (decompression bomb protection)"],
                                    "ocr_engine_available": self.is_ocr_available(),
                                    "ocr_engine": engine_used,
                                    "detected_format": detected_fmt,
                                    "error_code": "IMAGE_TOO_LARGE"
                                }
                except (UnidentifiedImageError, OSError):
                    # Truncated or mock image streams continue to engine
                    pass

            if self.apple_vision_available and self.vision_script_path:
                cmd = ["/usr/bin/osascript", "-l", "JavaScript", self.vision_script_path, temp_path]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if res.returncode == 0:
                    extracted_text = res.stdout
                else:
                    raise RuntimeError(f"Apple Vision OCR execution failed: {res.stderr}")
            elif self.is_tesseract_ready():
                from PIL import Image, ImageOps
                with Image.open(temp_path) as img:
                    # Optimize memory: downscale high-resolution images to optimal OCR resolution (max 1400px)
                    w, h = img.size
                    if max(w, h) > self.MAX_OCR_TARGET_DIMENSION:
                        scale = self.MAX_OCR_TARGET_DIMENSION / max(w, h)
                        new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
                        img = img.resize(new_size, Image.Resampling.BILINEAR)

                    # Optimize memory: convert to 8-bit grayscale to cut bitmap memory by 75%
                    if img.mode != "L":
                        img = img.convert("L")

                    # Contrast normalization to accelerate Otsu thresholding
                    try:
                        img = ImageOps.autocontrast(img)
                    except Exception:
                        pass

                    lang = self.get_tesseract_lang_string()
                    # Optimized Tesseract configuration:
                    # --oem 1: Neural LSTM engine only (faster than combined oem 3)
                    # --psm 6: Assume uniform block of text (skips expensive page layout/multi-column segmentation)
                    # -c preserve_interword_spaces=1: Retains URL and spacing fidelity
                    fast_config = r"--oem 1 --psm 6 -c preserve_interword_spaces=1"
                    try:
                        extracted_text = self.pytesseract.image_to_string(
                            img,
                            lang=lang,
                            config=fast_config,
                            timeout=self.OCR_TIMEOUT_SECONDS
                        )
                        # If fast PSM 6 yielded sparse text (< 10 chars), fallback to PSM 3
                        if not extracted_text or len(extracted_text.strip()) < 10:
                            extracted_text = self.pytesseract.image_to_string(
                                img,
                                lang=lang,
                                config=r"--oem 1 --psm 3",
                                timeout=self.OCR_TIMEOUT_SECONDS
                            )
                    except Exception as t_err:
                        if "timeout" in str(t_err).lower() or isinstance(t_err, subprocess.TimeoutExpired):
                            raise
                        logger.warning("Bilingual/optimized OCR extraction failed (%s), falling back to standard config.", t_err)
                        extracted_text = self.pytesseract.image_to_string(
                            img,
                            timeout=self.OCR_TIMEOUT_SECONDS
                        )

        except (subprocess.TimeoutExpired, Exception) as ocr_err:
            if "timeout" in str(ocr_err).lower() or isinstance(ocr_err, subprocess.TimeoutExpired):
                logger.warning("OCR extraction timed out after %ds", self.OCR_TIMEOUT_SECONDS)
                return {
                    "status": "failed",
                    "valid_image": True,
                    "score": 0,
                    "summary": f"OCR extraction timed out. The image could not be processed within {self.OCR_TIMEOUT_SECONDS} seconds.",
                    "extracted_text": "",
                    "indicators": ["OCR processing timed out"],
                    "ocr_engine_available": True,
                    "ocr_engine": engine_used,
                    "detected_format": detected_fmt,
                    "error_code": "OCR_TIMEOUT"
                }

            logger.error("OCR extraction encountered an error with engine '%s': %s", engine_used, str(ocr_err))
            return {
                "status": "failed",
                "valid_image": True,
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
            import gc
            gc.collect()

        cleaned_text = extracted_text.strip()
        if not cleaned_text:
            return {
                "status": "passed",
                "valid_image": True,
                "score": 0,
                "summary": "OCR completed: No readable text detected inside the uploaded screenshot.",
                "extracted_text": "",
                "indicators": ["Image contained zero discernible text characters"],
                "ocr_engine_available": True,
                "ocr_engine": engine_used,
                "detected_format": detected_fmt
            }

        word_count = len(cleaned_text.split())
        engine_label = "Apple Vision" if engine_used == "apple_vision" else "Tesseract OCR"
        return {
            "status": "completed",
            "valid_image": True,
            "score": 10,
            "summary": f"{engine_label} extracted {word_count} words from screenshot.",
            "extracted_text": cleaned_text,
            "indicators": [f"Extracted visible text from image ({word_count} words) via {engine_used}"],
            "ocr_engine_available": True,
            "ocr_engine": engine_used,
            "detected_format": detected_fmt
        }
