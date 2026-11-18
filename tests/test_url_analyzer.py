"""
SCAM KILLER — Tests for Layer 2: URL Structure Analysis
"""

import unittest
from analyzers.url_analyzer import UrlAnalyzer


class TestUrlAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = UrlAnalyzer()

    def test_whitelisted_domain(self):
        """Tests that authority domains reduce risk but are not certified 100% safe."""
        url = "https://developer.mozilla.org/en-US/docs/Web/Security"
        result = self.analyzer.analyze(url)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["critical_flag"])
        self.assertTrue(any("whitelist" in ind.lower() for ind in result["indicators"]))

    def test_high_risk_tld(self):
        """Tests detection of disposable/cheap top-level domains."""
        url = "https://free-reward-claim.xyz"
        result = self.analyzer.analyze(url)
        self.assertIn(result["status"], ("flagged", "caution"))
        self.assertTrue(any(".xyz" in ind for ind in result["indicators"]))

    def test_brand_typosquatting(self):
        """Tests critical flagging on brand impersonation."""
        url = "https://netflix-subscription-update.xyz/billing"
        result = self.analyzer.analyze(url)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertTrue(any("NETFLIX" in ind for ind in result["indicators"]))

    def test_raw_ip_address_hostname(self):
        """Tests critical detection of raw IP address URLs."""
        url = "http://192.168.1.100/secure-login"
        result = self.analyzer.analyze(url)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertTrue(any("IP address" in ind for ind in result["indicators"]))

    def test_url_shortener(self):
        """Tests detection of shortened redirect links."""
        url = "https://bit.ly/secret-offer"
        result = self.analyzer.analyze(url)
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("shortener" in ind.lower() for ind in result["indicators"]))

    def test_no_url_present(self):
        """Tests text without any links returns passed with no errors."""
        text = "Hello world, this is a plain message with no links."
        result = self.analyzer.analyze(text)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["domain"], "")

    def test_homoglyph_typosquatting(self):
        """Tests homoglyph substitutions like paypa1.com."""
        url = "https://paypa1-account-security.com/login"
        result = self.analyzer.analyze(url)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertTrue(any("PAYPAL" in ind for ind in result["indicators"]))

    def test_subdomain_deception(self):
        """Tests subdomain deceptive prefix like sbi.com.evil-portal.xyz."""
        url = "http://sbi.com.auth-server.xyz/verify"
        result = self.analyzer.analyze(url)
        self.assertEqual(result["status"], "flagged")
        self.assertTrue(result["critical_flag"])
        self.assertTrue(any("Subdomain deception" in ind for ind in result["indicators"]))



if __name__ == "__main__":
    unittest.main()
