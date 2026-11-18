"""
SCAM KILLER — Composite Risk Classification Engine
Combines multi-layer signals, applies transparent scoring rules,
and derives final risk categorization (Suspicious / Caution / No Clear Warning Signs).
"""

from typing import Dict, Any, List


class RiskClassifier:
    """
    Evaluates multi-layer findings without relying on single weak indicators.
    Enforces honest, non-absolute risk labeling.
    """

    SUSPICIOUS_THRESHOLD = 50
    CAUTION_THRESHOLD = 20

    @classmethod
    def evaluate(
        cls,
        content_res: Dict[str, Any],
        url_res: Dict[str, Any],
        screenshot_res: Dict[str, Any],
        intel_res: Dict[str, Any],
        scan_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        Synthesizes layer results into a final risk assessment.
        """
        content_score = content_res.get("score", 0)
        url_score = url_res.get("score", 0)
        screenshot_score = screenshot_res.get("score", 0)
        intel_score = intel_res.get("score", 0)

        critical_flag = content_res.get("critical_flag", False) or url_res.get("critical_flag", False)
        has_verified_advisory = intel_res.get("has_verified_advisory", False)

        total_score = content_score + url_score + screenshot_score + intel_score

        # Combine all indicators
        all_indicators: List[str] = []
        all_indicators.extend(content_res.get("indicators", []))
        all_indicators.extend(url_res.get("indicators", []))
        all_indicators.extend(screenshot_res.get("indicators", []))
        all_indicators.extend(intel_res.get("indicators", []))
        all_indicators = list(dict.fromkeys(all_indicators))

        # Risk Classification Logic
        # Require strong composite score OR verified critical threat flags
        if total_score >= cls.SUSPICIOUS_THRESHOLD or (critical_flag and total_score >= 35) or has_verified_advisory:
            risk_level = "suspicious"
            risk_label = "Suspicious"
            badge_class = "badge-suspicious"
            badge_icon = "warning"
            explanation = (
                "Automated analysis detected multiple high-risk indicators consistent with active fraud operations. "
                f"{content_res.get('summary', '')} {url_res.get('summary', '')} "
                "Urgent coercion, brand spoofing, or verified advisory matches indicate severe social engineering hazard."
            )
            next_steps = [
                "DO NOT click, open, or transmit payment details on this link.",
                "DO NOT share passwords, OTPs, or install remote assistance tools (.apk / AnyDesk).",
                "Block the transmitting phone number, email address, or social profile.",
                "If credentials were provided earlier, notify your bank and freeze your card immediately."
            ]
        elif total_score >= cls.CAUTION_THRESHOLD or (total_score > 0 and len(all_indicators) > 0):
            risk_level = "caution"
            risk_label = "Caution"
            badge_class = "badge-caution"
            badge_icon = "error"
            explanation = (
                "Heuristic indicators show caution signals that require independent verification. "
                f"{content_res.get('summary', '')} {url_res.get('summary', '')} "
                "While not definitively confirmed as malicious, high promotional claims or unverified senders warrant extreme care."
            )
            next_steps = [
                "Exercise heightened vigilance. Verify the sender's identity through an independent official channel.",
                "Never pay advance processing fees or redelivery surcharges to claim unearned vouchers.",
                "Confirm requests directly using contact details printed on official bills or banking cards."
            ]
        else:
            risk_level = "safe"
            risk_label = "No Clear Warning Signs"
            badge_class = "badge-safe"
            badge_icon = "check_circle"
            explanation = (
                "Automated heuristic inspection detected no active phishing keywords, deceptive domain structures, "
                "or blacklisted CIRT signatures in this submission. "
                "Note: Absence of detected indicators is not a legal guarantee of safety. Always remain alert."
            )
            next_steps = [
                "Ensure your browser address bar displays the verified canonical domain name.",
                "Never submit authentication credentials after following unexpected third-party redirects.",
                "Maintain standard cybersecurity hygiene and double-check unexpected requests."
            ]

        if not all_indicators:
            all_indicators = [
                "No explicit high-risk keywords detected in content",
                "No anomalous domain structures identified"
            ]

        return {
            "risk_level": risk_level,
            "risk_label": risk_label,
            "badge_class": badge_class,
            "badge_icon": badge_icon,
            "total_score": total_score,
            "explanation": explanation.strip(),
            "detected_indicators": all_indicators,
            "recommended_steps": next_steps,
            "disclaimer": (
                "Results are automated heuristic risk indicators based on available threat intelligence, "
                "not definitive legal findings, guarantees, or warranties."
            )
        }
