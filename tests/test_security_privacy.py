"""
SCAM KILLER — Tests for Security & Privacy Safeguards
"""

import unittest
from security.privacy import PrivacyInterceptor
from security.validator import InputValidator


class TestSecurityPrivacy(unittest.TestCase):

    def test_payment_card_detection(self):
        """Tests that pasting a credit card number triggers an immediate safety intercept."""
        card_text = "Here is my Visa card: 4532-1294-8842-1092 and expiry is 12/28"
        is_sensitive, alert = PrivacyInterceptor.check_sensitive_submission(card_text)
        self.assertTrue(is_sensitive)
        self.assertTrue(alert["blocked"])
        self.assertEqual(alert["category"], "payment_card")
        self.assertIn("SAFETY INTERCEPT", alert["message"])

    def test_standalone_otp_detection(self):
        """Tests that entering a standalone 6-digit OTP halts analysis."""
        otp_text = "829104"
        is_sensitive, alert = PrivacyInterceptor.check_sensitive_submission(otp_text)
        self.assertTrue(is_sensitive)
        self.assertTrue(alert["blocked"])
        self.assertEqual(alert["category"], "standalone_otp")

    def test_contextual_otp_detection(self):
        """Tests phrases like 'my otp code is 492019'."""
        text = "The bank sent me an OTP: 492019 for login"
        is_sensitive, alert = PrivacyInterceptor.check_sensitive_submission(text)
        self.assertTrue(is_sensitive)
        self.assertEqual(alert["category"], "contextual_credential")

    def test_safe_text_not_intercepted(self):
        """Tests that benign sentences containing numbers like times or amounts are not blocked."""
        benign_text = "I will meet you at 12:30 pm on October 24"
        is_sensitive, _ = PrivacyInterceptor.check_sensitive_submission(benign_text)
        self.assertFalse(is_sensitive)

    def test_snippet_sanitization(self):
        """Tests that display snippets redact numeric secret patterns."""
        raw = "User requested verification with code 981204 on portal"
        snippet = PrivacyInterceptor.sanitize_metadata_snippet(raw)
        self.assertNotIn("981204", snippet)
        self.assertIn("[REDACTED]", snippet)

    def test_input_size_limit(self):
        """Tests that payloads exceeding 10KB are rejected."""
        large_text = "A" * 15000
        is_valid, err_msg, _ = InputValidator.validate_text(large_text)
        self.assertFalse(is_valid)
        self.assertIn("exceeds maximum allowed size", err_msg)

    def test_empty_input_rejected(self):
        """Tests that blank or whitespace-only inputs are rejected."""
        is_valid, err_msg, _ = InputValidator.validate_text("   ")
        self.assertFalse(is_valid)
        self.assertIn("non-empty", err_msg)


if __name__ == "__main__":
    unittest.main()
