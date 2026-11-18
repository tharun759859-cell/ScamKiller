"""
SCAM KILLER — Input Validation & File Format Verifier
Validates text inputs and enforces true magic-byte verification on uploaded images.
"""

from typing import Tuple, Dict, Any, Optional
import io


class InputValidator:
    """Validates user inputs to ensure security and prevent malformed data."""

    MAX_TEXT_LENGTH = 10000  # 10 KB of text maximum
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB maximum image file size

    # Image magic byte signatures
    IMAGE_SIGNATURES = {
        "png": b"\x89PNG\r\n\x1a\n",
        "jpeg": b"\xff\xd8\xff",
        "webp_riff": b"RIFF",  # with WEBP at offset 8
        "gif": b"GIF8"
    }

    @classmethod
    def validate_text(cls, text: Any) -> Tuple[bool, Optional[str], str]:
        """
        Validates text input.
        Returns:
            (is_valid, error_message, sanitized_text)
        """
        if text is None:
            return False, "Input cannot be empty.", ""

        cleaned = str(text).replace("\x00", "").strip()
        if not cleaned:
            return False, "Please provide a non-empty message or URL.", ""

        if len(cleaned) > cls.MAX_TEXT_LENGTH:
            return False, f"Input exceeds maximum allowed size of {cls.MAX_TEXT_LENGTH} characters.", ""

        return True, None, cleaned

    @classmethod
    def validate_image_stream(cls, file_bytes: bytes, filename: str = "") -> Tuple[bool, Optional[str], str]:
        """
        Validates an image by inspecting header magic bytes.
        Returns:
            (is_valid, error_message, detected_format)
        """
        if not file_bytes:
            return False, "Uploaded file is empty.", ""

        if len(file_bytes) > cls.MAX_FILE_SIZE:
            return False, f"File size exceeds maximum permitted limit ({cls.MAX_FILE_SIZE // (1024*1024)}MB).", ""

        header = file_bytes[:16]

        if header.startswith(cls.IMAGE_SIGNATURES["png"]):
            return True, None, "png"

        if header.startswith(cls.IMAGE_SIGNATURES["jpeg"][:2]):
            return True, None, "jpeg"

        if header.startswith(b"RIFF") and len(file_bytes) >= 12 and file_bytes[8:12] == b"WEBP":
            return True, None, "webp"

        return False, "Invalid image format. Only authentic PNG, JPEG, and WebP images are accepted.", ""
