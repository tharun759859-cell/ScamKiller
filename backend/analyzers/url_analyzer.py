"""
SCAM KILLER — Layer 2: URL Structure Analysis
Passive structural inspection of URLs and domain metadata.
STRICT PRIVACY GUARANTEE: Never visits, resolves, or downloads from submitted URLs.
"""

import re
import urllib.parse
from typing import Dict, Any, List
from .base import BaseAnalyzer


class UrlAnalyzer(BaseAnalyzer):
    """
    Passively evaluates URL strings for anomalies, typosquatting,
    and high-risk domain structures without ever generating network traffic.
    """

    HIGH_RISK_TLDS = {
        ".xyz", ".top", ".online", ".live", ".icu", ".click", ".link",
        ".club", ".info", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".monster"
    }

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"
    }

    # High-profile spoof targets
    TARGETED_BRANDS = [
        "sbi", "hdfc", "icici", "axis", "paypal", "netflix", "amazon",
        "apple", "google", "usps", "fedex", "indiapost", "chase", "wellsfargo"
    ]

    # Institutional whitelist (treated as baseline, but NEVER as proof of 100% safety)
    BENCHMARK_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "github.com", "amazon.com",
        "wikipedia.org", "mozilla.org", "w3.org", "stackoverflow.com", "stripe.com",
        "gov.in", "usa.gov", "nih.gov"
    }

    def analyze(self, target: Any, **kwargs) -> Dict[str, Any]:
        """
        Analyzes a URL or text containing a URL.
        target: str (URL string or text with embedded URL)
        """
        raw = str(target or "").strip()
        url = self._extract_primary_url(raw)

        if not url:
            return {
                "status": "passed",
                "score": 0,
                "summary": "No direct links or URL strings detected in submission.",
                "indicators": [],
                "domain": "",
                "critical_flag": False
            }

        score = 0
        indicators: List[str] = []
        critical_flag = False

        # Parse URL
        parsed = self._safe_parse_url(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return {
                "status": "caution",
                "score": 15,
                "summary": "Malformed or unparseable URL structure detected.",
                "indicators": ["Malformed URL syntax"],
                "domain": "",
                "critical_flag": False
            }

        # 1. Check IP-address hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 40
            critical_flag = True
            indicators.append("Direct raw IP address used as hostname instead of domain name")

        # 2. Check Benchmark Whitelist
        is_whitelisted = any(
            hostname == b or hostname.endswith("." + b)
            for b in self.BENCHMARK_DOMAINS
        )
        if is_whitelisted:
            # Documented: Not proof of 100% safety, but reduces structural heuristic score
            score -= 15
            indicators.append(f"Domain '{hostname}' belongs to a verified institutional authority whitelist (Heuristic baseline only, not legal guarantee of safety)")

        # 3. High-Risk TLD Check
        matched_tld = next((tld for tld in self.HIGH_RISK_TLDS if hostname.endswith(tld)), None)
        if matched_tld:
            # Rule: Do not treat suspicious TLD alone as proof of scam (+20 moderate weight)
            score += 20
            indicators.append(f"High-risk disposable domain extension ({matched_tld}) commonly seen in automated campaigns")

        # 4. URL Shortener Check
        if any(shortener in hostname for shortener in self.SHORTENER_DOMAINS):
            score += 20
            indicators.append("URL shortener used, concealing the destination address and query paths")

        # 5. Targeted Brand Impersonation, Typosquatting & Homoglyphs
        normalized_host = self._normalize_homoglyphs(hostname)
        host_parts = hostname.split(".")
        # Identify effective root domain (e.g., domain.tld)
        root_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else hostname

        for brand in self.TARGETED_BRANDS:
            is_legit_brand = hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")
            if is_legit_brand:
                continue

            # Subdomain deception check: brand in subdomain prefix while root domain is different
            if len(host_parts) >= 3:
                subdomain_prefix = ".".join(host_parts[:-2])
                if brand in subdomain_prefix:
                    score += 35
                    critical_flag = True
                    indicators.append(
                        f"Subdomain deception detected: '{brand.upper()}' used as a misleading prefix on untrusted root domain '{root_domain}'"
                    )
                    continue

            # Direct presence in hostname (e.g., sbi-kyc-update.com)
            if brand in hostname:
                score += 35
                critical_flag = True
                indicators.append(f"Potential brand impersonation / typosquatting imitating '{brand.upper()}'")
                continue

            # Homoglyph or edit distance typosquatting (e.g., paypa1, arnazon, netf1ix)
            for part in host_parts[:-1]:
                norm_part = self._normalize_homoglyphs(part)
                if brand in norm_part:
                    score += 35
                    critical_flag = True
                    indicators.append(
                        f"Typosquatting / homoglyph impersonation imitating '{brand.upper()}' detected in '{part}'"
                    )
                    break
                # Levenshtein distance 1 check for brands of length >= 4
                if len(brand) >= 4 and abs(len(part) - len(brand)) <= 1:
                    if self._levenshtein(part, brand) == 1:
                        score += 35
                        critical_flag = True
                        indicators.append(
                            f"Typosquatting edit-distance variant of '{brand.upper()}' detected in '{part}'"
                        )
                        break

        # 6. Excessive Hyphens or Subdomain Depth
        hyphen_count = hostname.count("-")
        if hyphen_count >= 2:
            score += 15
            indicators.append(f"Excessive hyphenation ({hyphen_count} hyphens) in domain name imitating legitimate corporate naming")

        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) >= 4 and not is_whitelisted:
            score += 15
            indicators.append(f"Deep subdomain chaining ({len(subdomain_parts)} parts) obscuring root registration")

        # 7. Obfuscated Encoding Check
        if "%" in url or "@" in url:
            score += 25
            indicators.append("Unusual character encoding or '@' symbol in URL, potentially masking target destination")

        # Clamp minimum score
        score = max(0, score)

        # Determine Layer Status
        if score >= 35 or critical_flag:
            status = "flagged"
            summary = f"Anomalous domain structure and high-risk indicators detected for '{hostname}'."
        elif score > 0:
            status = "caution"
            summary = f"Domain '{hostname}' features caution points such as masking or atypical naming conventions."
        else:
            status = "passed"
            summary = f"URL syntax for '{hostname}' conforms to standard domain conventions."

        return {
            "status": status,
            "score": score,
            "summary": summary,
            "indicators": indicators,
            "domain": hostname,
            "critical_flag": critical_flag
        }

    def _extract_primary_url(self, text: str) -> str:
        """Extracts the first valid URL candidate from input text."""
        url_match = re.search(
            r'(https?://[^\s<>"]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|online|edu|gov|io|co|in|info|live|icu|biz|me)[^\s<>"]*)',
            text,
            re.IGNORECASE
        )
        if url_match:
            return url_match.group(1).rstrip('.,;:)]}')
        return ""

    def _safe_parse_url(self, url: str) -> urllib.parse.ParseResult:
        """Parses URL safely, prepending scheme if missing."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            return urllib.parse.urlparse(url)
        except Exception:
            return urllib.parse.urlparse("")

    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Substitutes common visual homoglyphs with standard ASCII characters."""
        subs = {
            '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b',
            '@': 'a', 'vv': 'w', 'rn': 'm'
        }
        res = text.lower()
        for k, v in subs.items():
            res = res.replace(k, v)
        return res

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Computes Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return UrlAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev[j + 1] + 1
                deletions = curr[j] + 1
                substitutions = prev[j] + (c1 != c2)
                curr.append(min(insertions, deletions, substitutions))
            prev = curr
        return prev[-1]

