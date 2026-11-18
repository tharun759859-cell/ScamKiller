"""
SCAM KILLER — Tests for Layer 1: Intelligent Message Detection Engine
Covers all 16 verification scenarios, detection categories A through G,
contextual correlation, defensive phrase mitigation, and privacy redaction.
"""

import unittest
from analyzers.content_analyzer import ContentAnalyzer


class TestContentAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ContentAnalyzer()

    # =========================================================================
    # Baseline Existing Tests (Preserved for Backward Compatibility)
    # =========================================================================
    def test_benign_message(self):
        """Tests that everyday normal messages pass without flags."""
        text = "Hi Alex, let me know if we are still having lunch at 12:30pm today."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(len(result["indicators"]), 0)
        self.assertFalse(result["critical_flag"])
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")

    def test_urgency_threat_message(self):
        """Tests detection of account block threats and artificial deadlines."""
        text = "URGENT: Your SBI account will be blocked within 24 hours. Immediate action required!"
        result = self.analyzer.analyze(text)
        self.assertIn(result["status"], ("flagged", "caution"))
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("urgency" in ind.lower() or "account block" in ind.lower() for ind in result["indicators"]))
        self.assertIn("urgency_pressure", result["categories_detected"])

    def test_financial_lottery_lure(self):
        """Tests detection of unexpected cash prizes and lottery promises."""
        text = "Congratulations! Your mobile number won 2nd prize of ₹25,00,000 in KBC Lucky Draw."
        result = self.analyzer.analyze(text)
        self.assertIn(result["status"], ("flagged", "caution"))
        self.assertTrue(any("lottery" in ind.lower() or "prize" in ind.lower() for ind in result["indicators"]))
        self.assertIn("reward_lottery", result["categories_detected"])

    def test_credential_apk_solicitation(self):
        """Tests critical flagging on APK download and KYC demands."""
        text = "Mandatory KYC update required. Install our official banking tool: HDFC_Support.apk now."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertTrue(any("apk" in ind.lower() or "kyc" in ind.lower() for ind in result["indicators"]))
        self.assertIn("credential_solicitation", result["categories_detected"])

    def test_fee_solicitation(self):
        """Tests detection of parcel redelivery fee demands."""
        text = "USPS: Parcel #9218 is on hold. Pay $1.95 redelivery fee to release package."
        result = self.analyzer.analyze(text)
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("fee" in ind.lower() or "payment" in ind.lower() for ind in result["indicators"]))
        self.assertIn("financial_manipulation", result["categories_detected"])

    def test_empty_content(self):
        """Tests graceful handling of empty or blank text."""
        result = self.analyzer.analyze("")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")
        self.assertEqual(len(result["indicators"]), 0)

    # =========================================================================
    # 16 Dedicated Scenarios Required by Specification
    # =========================================================================
    def test_scenario_01_normal_bank_notification(self):
        """Scenario 1: Normal bank notification (debit alert with official channel guidance)."""
        text = (
            "Your A/C ending 4921 is debited by INR 450.00 on 16-Nov-26 for UPI payment at Metro Supermarket. "
            "Avl Bal: INR 14,290. If not you, contact official customer care on back of your card."
        )
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")
        self.assertTrue(len(result["mitigating_factors"]) > 0)
        self.assertFalse(result["critical_flag"])

    def test_scenario_02_suspicious_bank_impersonation(self):
        """Scenario 2: Suspicious bank impersonation (HDFC brand spoof + blocked threat + phishing URL)."""
        text = (
            "Dear Customer, your HDFC netbanking access is blocked due to unverified PAN. "
            "Update immediately at http://hdfc-pan-portal.xyz/verify"
        )
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("impersonation", result["categories_detected"])
        self.assertIn("urgency_pressure", result["categories_detected"])
        self.assertIn("link_context", result["categories_detected"])
        self.assertTrue(any("HDFC" in ind for ind in result["indicators"]))

    def test_scenario_03_account_suspension_pressure(self):
        """Scenario 3: Account suspension / utility cutoff pressure."""
        text = (
            "FINAL NOTICE: Your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. "
            "Immediate action required to prevent disconnection."
        )
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("urgency_pressure", result["categories_detected"])
        self.assertTrue(any("disconnection" in ind.lower() for ind in result["indicators"]))

    def test_scenario_04_fake_lottery_message(self):
        """Scenario 4: Fake lottery / unearned windfall message."""
        text = "Congratulations! You won 1st prize of ₹25,00,000 in KBC Lucky Draw 2026. Claim your cash prize now."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("reward_lottery", result["categories_detected"])
        self.assertTrue(any("lottery" in ind.lower() for ind in result["indicators"]))

    def test_scenario_05_unexpected_payment_request(self):
        """Scenario 5: Unexpected payment request / customs clearance fee."""
        text = "Customs Notice: Your international parcel is held at airport. Pay $15.50 clearance fee to release package immediately."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("financial_manipulation", result["categories_detected"])
        self.assertTrue(any("fee" in ind.lower() for ind in result["indicators"]))

    def test_scenario_06_otp_request(self):
        """Scenario 6: Direct solicitation of one-time password (OTP)."""
        text = "Dear user, please share your 6-digit OTP verification code received on SMS to confirm your account login."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("credential_solicitation", result["categories_detected"])
        self.assertTrue(any("otp" in ind.lower() for ind in result["indicators"]))

    def test_scenario_07_password_request(self):
        """Scenario 7: Solicitation of netbanking password / PIN."""
        text = "Security update: submit your netbanking password and security code to confirm your profile identity."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("credential_solicitation", result["categories_detected"])
        self.assertTrue(any("password" in ind.lower() for ind in result["indicators"]))

    def test_scenario_08_normal_delivery_notification(self):
        """Scenario 8: Normal delivery notification (Amazon package fulfillment, no fee, no trap)."""
        text = "Your package #9281 from Amazon has been delivered to your front door. Thank you for shopping with us."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")
        self.assertFalse(result["critical_flag"])
        self.assertTrue(any("delivery" in m.lower() for m in result["mitigating_factors"]))

    def test_scenario_09_suspicious_delivery_fee_message(self):
        """Scenario 9: Suspicious delivery-fee demand with link."""
        text = "USPS: Package ID #8192-US cannot be delivered. Pay $1.95 redelivery fee to reschedule delivery: http://usps-redelivery.xyz"
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertIn("impersonation", result["categories_detected"])
        self.assertIn("financial_manipulation", result["categories_detected"])
        self.assertIn("link_context", result["categories_detected"])

    def test_scenario_10_legitimate_security_reminder(self):
        """Scenario 10: Legitimate bank security advisory (never share OTP, official app guidance)."""
        text = (
            "Security Tip: Your bank will never ask for your password, PIN, or OTP. "
            "Never share your secret credentials with anyone. Contact your branch directly through our official mobile app."
        )
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")
        self.assertFalse(result["critical_flag"])
        self.assertTrue(any("anti-phishing" in m.lower() for m in result["mitigating_factors"]))

    def test_scenario_11_ambiguous_message(self):
        """Scenario 11: Ambiguous promotional marketing message without phishing trap."""
        text = "Weekend Super Sale! Get up to 50% discount on all electronics today only at MegaStore. Offer valid till midnight."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "caution")
        self.assertEqual(result["risk_category"], "Caution")
        self.assertGreater(result["score"], 0)
        self.assertLess(result["score"], 35)
        self.assertFalse(result["critical_flag"])

    def test_scenario_12_multiple_suspicious_indicators(self):
        """Scenario 12: Multi-vector attack combining Brand + Urgency + Payment + OTP solicitation + Link."""
        text = (
            "URGENT: SBI Security Alert! Your account is suspended. "
            "Pay ₹500 reactivation fee and submit your OTP at http://sbi-unblock.xyz immediately."
        )
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["risk_category"], "Suspicious")
        self.assertTrue(result["critical_flag"])
        self.assertGreaterEqual(result["score"], 70)
        self.assertGreaterEqual(len(result["categories_detected"]), 4)

    def test_scenario_13_embedded_url_context(self):
        """Scenario 13: Message pressuring user to click embedded verification URL."""
        text = "Click here to verify your account details immediately: http://bank-secure-auth.top/login"
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "flagged")
        self.assertIn("link_context", result["categories_detected"])
        self.assertIn("urgency_pressure", result["categories_detected"])

    def test_scenario_14_empty_and_whitespace_input(self):
        """Scenario 14: Blank, whitespace, or None inputs."""
        for empty_val in ["", "    ", "\n\t  ", None]:
            result = self.analyzer.analyze(empty_val)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["score"], 0)
            self.assertEqual(result["risk_category"], "No Clear Warning Signs")
            self.assertEqual(len(result["indicators"]), 0)

    def test_scenario_15_long_and_special_character_input(self):
        """Scenario 15: Very long input (10KB) and inputs with Unicode emojis."""
        long_text = "Safe informational text. " * 400 + " 🔒 🛡️ ✨ ⚡"
        result = self.analyzer.analyze(long_text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_category"], "No Clear Warning Signs")

    def test_scenario_16_privacy_redaction_in_evidence(self):
        """Scenario 16: Ensure sensitive candidate OTPs and card numbers are redacted in evidence snippets."""
        text = "URGENT: verify your card 4532-8192-3819-2019 and code 892102 immediately."
        result = self.analyzer.analyze(text)
        for ev in result["evidence"]:
            self.assertNotIn("4532-8192-3819-2019", ev)
            self.assertNotIn("892102", ev)
        for ind in result["detailed_indicators"]:
            self.assertNotIn("4532-8192-3819-2019", ind["context_snippet"])
            self.assertNotIn("892102", ind["context_snippet"])

    # =========================================================================
    # Explainable Output & Schema Completeness
    # =========================================================================
    def test_explainable_indicator_structure(self):
        """Verifies that all detailed_indicators contain required explainability attributes."""
        text = "URGENT: Your SBI account will be blocked within 24 hours. Update KYC at http://sbi-portal.xyz"
        result = self.analyzer.analyze(text)
        self.assertGreater(len(result["detailed_indicators"]), 0)
        for item in result["detailed_indicators"]:
            self.assertIn("name", item)
            self.assertIn("category", item)
            self.assertIn("severity", item)
            self.assertIn("why_detected", item)
            self.assertIn("context_snippet", item)
            self.assertIn("contribution", item)
            self.assertIn(item["severity"], ("high", "medium", "low"))


if __name__ == "__main__":
    unittest.main()
