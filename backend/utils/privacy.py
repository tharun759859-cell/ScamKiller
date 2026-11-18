"""
SCAM KILLER — Privacy & Sensitive Data Safeguards
Detects accidental user submission of credentials, OTPs, or payment card numbers
BEFORE any analysis is executed or stored.
"""

import re
from typing import Dict, Any, Tuple


class PrivacyInterceptor:
    """
    Client & server-side safety guard to prevent accidental ingestion
    of sensitive authentication material or financial credentials.
    """

    # Payment card regex (13 to 19 digits with optional spaces/dashes)
    CARD_PATTERN = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b|\b(?:\d{4}[ -]?){2}\d{4}[ -]?\d{1,4}\b')

    # Standalone numeric code regex (4 to 8 digits)
    STANDALONE_CODE_PATTERN = re.compile(r'^\s*\d{4,8}\s*$')

    # Contextual keywords indicating an authentication secret
    SECRET_CONTEXT_KEYWORDS = re.compile(
        r'\b(otp|one[- ]time password|verification code|pin|cvv|cvc|secret key|password is|password:)\b',
        re.IGNORECASE
    )

    # Contextual code pattern
    CONTEXTUAL_CODE_PATTERN = re.compile(r'\b\d{4,8}\b')

    @classmethod
    def check_sensitive_submission(cls, text: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Inspects input text for private credentials.
        Returns:
            (is_sensitive, alert_dict)
        """
        raw = str(text or "").strip()
        if not raw:
            return False, {}

        # 1. Payment Card Detection
        if cls.CARD_PATTERN.search(raw):
            return True, {
                "blocked": True,
                "category": "payment_card",
                "message": (
                    "SAFETY INTERCEPT: Your input appears to contain a credit or debit card number. "
                    "For your security, analysis was halted immediately. Never paste financial credentials into any tool."
                ),
                "safe_next_steps": [
                    "Never transmit credit card details or CVVs via unencrypted web forms.",
                    "If you received a request for card numbers via SMS or email, it is likely a phishing scam.",
                    "Review your bank statement immediately if you recently submitted card details on an unverified site."
                ]
            }

        # 2. Standalone OTP or Numeric Code Detection
        if cls.STANDALONE_CODE_PATTERN.match(raw):
            return True, {
                "blocked": True,
                "category": "standalone_otp",
                "message": (
                    "SAFETY INTERCEPT: You entered a standalone numeric code (possible OTP or PIN). "
                    "One-Time Passwords authorize secure transactions and should never be shared with anyone or pasted into diagnostic tools."
                ),
                "safe_next_steps": [
                    "Keep your OTP confidential. No legitimate organization or bank will ever ask for your OTP.",
                    "Delete this code from your clipboard.",
                    "If an unknown caller asked you to read or verify this code, terminate the call immediately."
                ]
            }

        # 3. Contextual OTP / Credential Mention
        lower = raw.lower()
        if cls.SECRET_CONTEXT_KEYWORDS.search(lower) and cls.CONTEXTUAL_CODE_PATTERN.search(raw):
            return True, {
                "blocked": True,
                "category": "contextual_credential",
                "message": (
                    "SAFETY INTERCEPT: Your input appears to contain sensitive authentication credentials (such as an OTP or secret PIN). "
                    "Analysis was halted to prevent accidental logging of private data."
                ),
                "safe_next_steps": [
                    "Do not paste or share private authentication keys.",
                    "Legitimate customer support representatives will never ask you to disclose an OTP.",
                    "If you suspect an active account compromise, contact your service provider immediately."
                ]
            }

        return False, {}

    @classmethod
    def sanitize_metadata_snippet(cls, text: str, max_length: int = 60) -> str:
        """
        Safely truncates and cleans an item for telemetry display without logging private content.
        """
        clean = re.sub(r'[\r\n\t]+', ' ', str(text or "").strip())
        # Redact any remaining numbers that look like credentials
        clean = re.sub(r'\b\d{4,8}\b', '[REDACTED]', clean)
        if len(clean) > max_length:
            return clean[:max_length - 3] + "..."
        return clean
