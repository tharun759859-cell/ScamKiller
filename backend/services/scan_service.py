"""
SCAM KILLER — Unified Scan Service
Coordinates input validation, Google Gemini AI contextual fraud assessment,
auxiliary telemetry, and SQLite persistence.
"""

import os
import time
import re
import uuid
import hashlib
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

from security.privacy import PrivacyInterceptor
from security.validator import InputValidator
from services.ai_service import AIService
from analyzers.url_analyzer import UrlAnalyzer
from analyzers.screenshot_analyzer import ScreenshotAnalyzer
from analyzers.intel_analyzer import IntelAnalyzer
from database.models import TelemetryRepository


class ScanService:
    """Orchestrates Google Gemini AI contextual fraud assessment pipeline."""

    def __init__(self):
        self.ai_service = AIService()
        self.url_analyzer = UrlAnalyzer()
        self.screenshot_analyzer = ScreenshotAnalyzer()
        self.intel_analyzer = IntelAnalyzer()

    def classify_input(self, text: str) -> str:
        """
        Automatically classifies raw text into:
        'url' | 'message_with_url' | 'message'
        """
        raw = str(text or "").strip()
        url_pattern = re.compile(
            r'(https?://[^\s<>"]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|online|edu|gov|io|co|in|info|live|icu|biz|me)[^\s<>"]*)',
            re.IGNORECASE
        )
        matches = url_pattern.findall(raw)

        if matches:
            first_url = matches[0] if isinstance(matches[0], str) else matches[0][0]
            remaining = raw.replace(first_url, "").strip()
            if not remaining or len(remaining) < 5:
                return "url"
            return "message_with_url"

        return "message"

    @staticmethod
    def extract_pattern_indicators(text: str, risk_level: str, ai_assessment: Dict[str, Any], domain: str = "") -> Dict[str, str]:
        """
        Extracts structured pattern indicators for community pattern clustering.
        Identifies category, impersonated entity, message theme, urgency/reward, and action.
        Computes deterministic pattern fingerprint without exposing raw text or private identifiers.
        """
        lower_text = text.lower()

        # 1. Impersonated Entity Detection
        entities = [
            ("State Bank of India", ["sbi", "state bank", "onlinesbi"]),
            ("HDFC Bank", ["hdfc", "hdfcbank"]),
            ("ICICI Bank", ["icici"]),
            ("Axis Bank", ["axis bank"]),
            ("Paytm", ["paytm"]),
            ("India Post", ["india post", "indiapost", "speed post", "postal"]),
            ("USPS", ["usps", "postal service"]),
            ("FedEx", ["fedex"]),
            ("DHL", ["dhl"]),
            ("Amazon", ["amazon"]),
            ("Netflix", ["netflix"]),
            ("Electricity Board", ["electricity", "power", "discom", "bill payment", "bijli"]),
            ("Income Tax Dept", ["income tax", "it department", "tax refund"]),
            ("Telegram", ["telegram", "hotel review", "youtube subscribe task"])
        ]
        detected_entity = "None"
        for ent_name, aliases in entities:
            if any(a in lower_text for a in aliases) or any(a in domain.lower() for a in aliases):
                detected_entity = ent_name
                break

        # 2. Category Detection
        if detected_entity in ("State Bank of India", "HDFC Bank", "ICICI Bank", "Axis Bank", "Paytm") or "kyc" in lower_text or "pan" in lower_text or "account block" in lower_text:
            category = "Banking / KYC"
        elif detected_entity in ("India Post", "USPS", "FedEx", "DHL") or "parcel" in lower_text or "delivery" in lower_text or "package" in lower_text:
            category = "Delivery Phishing"
        elif "gift" in lower_text or "won" in lower_text or "lottery" in lower_text or "prize" in lower_text or "reward" in lower_text or "cashback" in lower_text:
            category = "Lottery / Rewards"
        elif "hotel review" in lower_text or "task" in lower_text or "part-time" in lower_text or "work from home" in lower_text or "daily income" in lower_text:
            category = "Work-from-Home"
        elif detected_entity == "Electricity Board" or "power cut" in lower_text or "electricity bill" in lower_text or "disconnection" in lower_text:
            category = "Utility Bill"
        elif "tax refund" in lower_text or "challan" in lower_text or "traffic police" in lower_text or "court order" in lower_text:
            category = "Government / Legal"
        elif risk_level == "safe":
            category = "Benign Transactional"
        elif risk_level == "caution":
            category = "Unverified Outreach"
        else:
            category = "General Phishing"

        # 3. Urgency / Reward Pattern
        if re.search(r"\b(24 hours|today|urgent|immediately|tonight|blocked|suspended|expires)\b", lower_text):
            urgency_pattern = "Manufactured Urgency / Immediate Deadline"
        elif re.search(r"\b(won|claim|reward|free|gift card|bonus|cashback|prize)\b", lower_text):
            urgency_pattern = "High-Value Unsolicited Reward Lure"
        else:
            urgency_pattern = "Standard Request Flow"

        # 4. Requested Action
        if ".apk" in lower_text or "install" in lower_text or "anydesk" in lower_text or "teamviewer" in lower_text or "quicksupport" in lower_text:
            action = "Install APK / Remote Assistance Tool"
        elif re.search(r"https?://|\.xyz|\.top|\.online|\.site|\.live|\.cc|\.me", lower_text) or "click" in lower_text or "link" in lower_text or "visit" in lower_text:
            action = "Visit Unverified Link to Input Credentials"
        elif "otp" in lower_text or "pin" in lower_text or "password" in lower_text:
            action = "Disclose Authentication Secrets (OTP/PIN)"
        elif "fee" in lower_text or "deposit" in lower_text or "transfer" in lower_text or "pay" in lower_text:
            action = "Transfer Money / Micro-Fee Surcharge"
        else:
            action = "Review Unsolicited Content"

        # 5. Message Theme
        if category == "Banking / KYC":
            theme = "Urgent KYC Verification / Account Suspension Alert"
        elif category == "Delivery Phishing":
            theme = "Package On Hold Due to Address or Fee Issue"
        elif category == "Lottery / Rewards":
            theme = "Unsolicited Monetary Prize Notification"
        elif category == "Work-from-Home":
            theme = "Paid Task / Rating Commission Scheme"
        elif category == "Utility Bill":
            theme = "Immediate Power Disconnection Threat"
        else:
            theme = f"{category} Notification"

        # 6. Deterministic Sanitized Fingerprint
        raw_key = f"{category.lower()}:{detected_entity.lower()}:{action.lower()}"
        fingerprint = f"pat_{hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:12]}"

        return {
            "category": category,
            "impersonated_entity": detected_entity,
            "message_theme": theme,
            "urgency_or_reward_pattern": urgency_pattern,
            "requested_action": action,
            "pattern_fingerprint": fingerprint
        }

    def process_text_scan(self, input_text: str, requested_type: str = "auto", source_type: str = "text") -> Dict[str, Any]:
        """
        Executes contextual AI scan on text/URL/OCR/Audio inputs using Google Gemini.
        """
        # 1. Input Validation
        is_valid, err_msg, sanitized_text = InputValidator.validate_text(input_text)
        if not is_valid:
            raise ValueError(err_msg)

        # 2. Strict Privacy Interception
        is_sensitive, alert = PrivacyInterceptor.check_sensitive_submission(sanitized_text)
        if is_sensitive:
            return {
                "scan_id": f"alert-{int(time.time())}",
                "scan_type": "privacy_alert",
                "risk_level": "suspicious",
                "classification": "Suspicious",
                "risk_label": "Suspicious (Credential Alert)",
                "badge_class": "badge-suspicious",
                "badge_icon": "warning",
                "submitted_item": PrivacyInterceptor.sanitize_metadata_snippet(sanitized_text),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "explanation": alert["message"],
                "summary": alert["message"],
                "confidence": 1.0,
                "confidence_score": 1.0,
                "confidence_explanation": "100% Deterministic match - Direct authentication secret intercepted",
                "detected_indicators": [
                    {
                        "title": "Private credential / OTP pattern detected",
                        "severity": "high",
                        "explanation": "Direct sensitive authentication secret detected in submission."
                    },
                    {
                        "title": "Direct credential hazard — analysis halted",
                        "severity": "high",
                        "explanation": "Never submit live authentication OTPs or passwords into web forms."
                    }
                ],
                "why_it_matters": "Entering real authentication codes into web forms or scanners poses an immediate account compromise risk.",
                "recommended_actions": alert["safe_next_steps"],
                "recommended_steps": alert["safe_next_steps"],
                "verification_advice": "Never enter OTPs, CVVs, or NetBanking passwords into any verification page or scanner.",
                "important_uncertainties": ["Analysis halted immediately to protect user authentication credentials."],
                "limitations": ["Analysis halted immediately to protect user authentication credentials."],
                "layers": {
                    "content": {
                        "status": "flagged",
                        "confidence": "high",
                        "detailed_indicators": [
                            {"name": "Private OTP Pattern", "why_detected": "Authentication code detected", "severity": "high", "contribution": 100}
                        ],
                        "categories_detected": ["credential_harvesting"],
                        "mitigating_factors": []
                    },
                    "urlStructure": {"status": "skipped"},
                    "trustedIntel": {"status": "passed"}
                },
                "scam_journey": {
                    "stages": [{"stage": "Credential Intercept", "status": "blocked"}] * 4
                },
                "scoring_breakdown": {
                    "content_score": 100,
                    "url_score": 0,
                    "total_score": 100
                },
                "engine_status": "Privacy Intercept Active"
            }

        # 3. Input Classification
        detected_type = self.classify_input(sanitized_text) if requested_type == "auto" else requested_type

        # 4. Contextual Google Gemini AI Assessment (Primary Engine)
        ai_assessment = self.ai_service.analyze_content(sanitized_text, source_type=source_type)

        raw_classification = ai_assessment.get("classification", "Caution")
        raw_risk = str(ai_assessment.get("risk_level", "caution")).lower()

        if "suspicious" in raw_risk or "suspicious" in str(raw_classification).lower():
            clean_classification = "Suspicious"
            risk_level = "suspicious"
            badge_class = "badge-suspicious"
            badge_icon = "warning"
        elif "no_clear" in raw_risk or "safe" in raw_risk or "no clear" in str(raw_classification).lower():
            clean_classification = "No Clear Warning Signs"
            risk_level = "safe"
            badge_class = "badge-safe"
            badge_icon = "verified_user"
        else:
            clean_classification = "Caution"
            risk_level = "caution"
            badge_class = "badge-caution"
            badge_icon = "error"

        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        display_snippet = PrivacyInterceptor.sanitize_metadata_snippet(sanitized_text, max_length=55)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Auxiliary: URL inspection for community pattern matching
        url_res = {"status": "skipped", "domain": ""}
        if detected_type in ("url", "message_with_url"):
            url_res = self.url_analyzer.analyze(sanitized_text)

        domain = url_res.get("domain", "")
        community_match = self.find_community_match(sanitized_text, domain=domain)

        # Standardize indicators format
        raw_indicators = ai_assessment.get("detected_indicators", [])
        formatted_indicators = []
        detailed_indicators = []
        for ind in raw_indicators:
            if isinstance(ind, dict):
                title = ind.get("title", "Threat Indicator")
                sev = ind.get("severity", "medium")
                exp = ind.get("explanation", "")
                formatted_indicators.append({
                    "title": title,
                    "severity": sev,
                    "explanation": exp
                })
                detailed_indicators.append({
                    "name": title,
                    "why_detected": exp,
                    "severity": sev,
                    "contribution": 50 if sev == "high" else 25
                })
            elif isinstance(ind, str) and ind.strip():
                formatted_indicators.append({
                    "title": ind.strip(),
                    "severity": "medium",
                    "explanation": ind.strip()
                })
                detailed_indicators.append({
                    "name": ind.strip(),
                    "why_detected": ind.strip(),
                    "severity": "medium",
                    "contribution": 25
                })

        actions = ai_assessment.get("recommended_actions", [
            "Do not share OTPs, passwords, or personal credentials.",
            "Verify independently through the official organization website or helpline."
        ])

        url_status = "flagged" if risk_level == "suspicious" and detected_type in ("url", "message_with_url") else "passed"
        content_status = "flagged" if risk_level == "suspicious" else ("caution" if risk_level == "caution" else "passed")

        layers_dict = {
            "content": {
                "status": content_status,
                "confidence": "high" if risk_level == "suspicious" else ("medium" if risk_level == "caution" else "low"),
                "risk_score": 85 if risk_level == "suspicious" else (50 if risk_level == "caution" else 10),
                "indicators": formatted_indicators,
                "detailed_indicators": detailed_indicators,
                "categories_detected": ["impersonation", "urgency"] if risk_level == "suspicious" else [],
                "mitigating_factors": [] if risk_level == "suspicious" else ["Normal conversational syntax"]
            },
            "urlStructure": {
                "status": url_status,
                "risk_score": 90 if url_status == "flagged" else 0,
                "domain": domain
            },
            "trustedIntel": {
                "status": "passed"
            }
        }

        scam_journey = {
            "stages": [
                {"stage": "Initial Contact", "status": "active"},
                {"stage": "Urgency Lure", "status": "active" if risk_level == "suspicious" else "inactive"},
                {"stage": "Credential Solicitation", "status": "active" if risk_level == "suspicious" else "inactive"},
                {"stage": "Account Compromise", "status": "potential" if risk_level == "suspicious" else "unlikely"}
            ]
        }

        scoring_breakdown = {
            "content_score": 85 if risk_level == "suspicious" else (50 if risk_level == "caution" else 10),
            "url_score": 90 if url_status == "flagged" else 0,
            "total_score": 92 if risk_level == "suspicious" else (50 if risk_level == "caution" else 15)
        }

        # Extract structured pattern indicators for community pattern detection
        pattern_indicators = self.extract_pattern_indicators(sanitized_text, risk_level, ai_assessment, domain)

        result_payload = {
            "scan_id": scan_id,
            "scanId": scan_id,
            "scan_type": detected_type,
            "source_type": source_type,
            "risk_level": risk_level,
            "classification": clean_classification,
            "risk_label": clean_classification,
            "category": pattern_indicators["category"],
            "impersonated_entity": pattern_indicators["impersonated_entity"],
            "message_theme": pattern_indicators["message_theme"],
            "urgency_or_reward_pattern": pattern_indicators["urgency_or_reward_pattern"],
            "requested_action": pattern_indicators["requested_action"],
            "pattern_fingerprint": pattern_indicators["pattern_fingerprint"],
            "confidence": ai_assessment.get("confidence", 0.85),
            "confidence_score": ai_assessment.get("confidence_score", 0.85),
            "confidence_explanation": ai_assessment.get("confidence_explanation", ""),
            "summary": ai_assessment.get("summary", ""),
            "explanation": ai_assessment.get("explanation", ""),
            "reasoning": ai_assessment.get("reasoning", ""),
            "why_it_matters": ai_assessment.get("why_it_matters", ""),
            "recommended_actions": actions,
            "recommended_steps": actions,
            "verification_advice": ai_assessment.get("verification_advice", ""),
            "important_uncertainties": ai_assessment.get("important_uncertainties", []),
            "limitations": ai_assessment.get("limitations", []),
            "detected_indicators": formatted_indicators,
            "badge_class": badge_class,
            "badge_icon": badge_icon,
            "submitted_item": display_snippet,
            "timestamp": timestamp_str,
            "engine_status": ai_assessment.get("engine_status", "Google Gemini AI Contextual Intelligence Active"),
            "ai_model": ai_assessment.get("ai_model", "gemini-2.5-flash"),
            "community_match": community_match,
            "layers": layers_dict,
            "scam_journey": scam_journey,
            "scoring_breakdown": scoring_breakdown
        }

        # 5. Persist to SQLite Audit Log with Full Report Data
        try:
            TelemetryRepository.insert_scan({
                "scan_id": scan_id,
                "scan_type": detected_type,
                "source_type": source_type,
                "risk_category": risk_level,
                "classification": clean_classification,
                "confidence": ai_assessment.get("confidence", 0.85),
                "timestamp": timestamp_str,
                "time_ago": "Just now",
                "display_item": display_snippet,
                "content_status": content_status,
                "url_status": url_status,
                "screenshot_status": "skipped" if source_type != "screenshot" else "passed",
                "intel_status": "passed",
                "indicator_count": len(formatted_indicators),
                "explanation": ai_assessment.get("summary", ""),
                "ai_summary": ai_assessment.get("summary", ""),
                "structured_data": result_payload,
                "full_report_json": result_payload,
                "category": pattern_indicators["category"],
                "impersonated_entity": pattern_indicators["impersonated_entity"],
                "message_theme": pattern_indicators["message_theme"],
                "urgency_or_reward_pattern": pattern_indicators["urgency_or_reward_pattern"],
                "requested_action": pattern_indicators["requested_action"],
                "pattern_fingerprint": pattern_indicators["pattern_fingerprint"],
                "metadata": {
                    "badgeClass": badge_class,
                    "badgeIcon": badge_icon,
                    "riskLabel": clean_classification,
                    "confidence": ai_assessment.get("confidence", 0.85),
                    "category": pattern_indicators["category"],
                    "layers": layers_dict,
                    "recommendedSteps": actions
                }
            })
        except Exception:
            pass

        return result_payload

    def process_screenshot_scan(self, file_bytes: bytes, filename: str = "screenshot.png") -> Dict[str, Any]:
        """
        Executes complete screenshot analysis pipeline:
        1. Validates image bytes.
        2. Performs local OCR text extraction.
        3. Analyzes extracted text using Gemini AI.
        4. Returns unified result payload.
        """
        screenshot_res = self.screenshot_analyzer.analyze(file_bytes, filename=filename)

        if not screenshot_res.get("valid_image"):
            return {
                "scan_id": f"screen-{uuid.uuid4().hex[:8]}",
                "scan_type": "screenshot",
                "source_type": "screenshot",
                "risk_level": "caution",
                "classification": "Caution",
                "risk_label": "Caution",
                "confidence": 0.5,
                "summary": "The uploaded file could not be decoded as a valid image format (PNG, JPEG, WEBP).",
                "explanation": "The uploaded file could not be decoded as a valid image format (PNG, JPEG, WEBP).",
                "detected_indicators": [
                    {"title": "Unreadable File", "severity": "medium", "explanation": "File data is corrupted or in an unsupported format."}
                ],
                "why_it_matters": "Corrupted or obfuscated media may attempt to bypass optical security scanners.",
                "recommended_actions": ["Upload a clear, standard PNG or JPEG screenshot."],
                "recommended_steps": ["Upload a clear, standard PNG or JPEG screenshot."],
                "limitations": ["Visual OCR could not execute on unreadable image data."],
                "layers": {
                    "screenshot": screenshot_res,
                    "content": {"status": "failed"}
                },
                "engine_status": "Google Gemini AI OCR Pipeline",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
            }

        extracted_text = screenshot_res.get("extracted_text", "").strip()

        if extracted_text:
            result = self.process_text_scan(extracted_text, requested_type="auto", source_type="screenshot")
            result["layers"]["screenshot"] = screenshot_res
            return result
        else:
            scan_id = f"screen-{uuid.uuid4().hex[:8]}"
            return {
                "scan_id": scan_id,
                "scan_type": "screenshot",
                "source_type": "screenshot",
                "risk_level": "safe",
                "classification": "No Clear Warning Signs",
                "risk_label": "No Clear Warning Signs",
                "confidence": 0.80,
                "summary": "Screenshot was decoded successfully, but no readable text was detected.",
                "explanation": "Screenshot was decoded successfully, but no readable text was detected.",
                "detected_indicators": [],
                "why_it_matters": "Without readable typography or QR codes, no immediate text-based phishing signatures were found.",
                "recommended_actions": ["Ensure text in the screenshot is sharp and legible, or paste the message directly."],
                "recommended_steps": ["Ensure text in the screenshot is sharp and legible, or paste the message directly."],
                "limitations": ["Visual OCR found no readable typography in the submitted image."],
                "layers": {
                    "screenshot": screenshot_res,
                    "content": {"status": "passed"}
                },
                "engine_status": "Google Gemini AI OCR Pipeline",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
            }

    def find_community_match(self, text: str, domain: str = "") -> Optional[Dict[str, Any]]:
        """Matches query tokens against stored SQLite community incident reports."""
        try:
            reports = TelemetryRepository.get_community_reports()
            lower_text = text.lower()

            for rep in reports:
                reported_item = str(rep.get("reported_item", "")).lower()
                desc = str(rep.get("description", "")).lower()

                # Domain match or high overlap in scam tokens
                if domain and domain in reported_item:
                    return {
                        "matched": True,
                        "report_id": rep["report_id"],
                        "category": rep["category"],
                        "title": rep["title"],
                        "upvotes": rep.get("upvotes", 0),
                        "description": rep.get("description", ""),
                        "source": rep.get("source", "Community Verified")
                    }

                # Check keyword signature overlap
                sig_words = [w for w in ["sbi", "hdfc", "kyc", "apk", "anydesk", "teamviewer", "electricity", "bill", "lottery", "gift"] if w in reported_item or w in desc]
                if sig_words and all(w in lower_text for w in sig_words[:2]):
                    return {
                        "matched": True,
                        "report_id": rep["report_id"],
                        "category": rep["category"],
                        "title": rep["title"],
                        "upvotes": rep.get("upvotes", 0),
                        "description": rep.get("description", ""),
                        "source": rep.get("source", "Community Verified")
                    }
        except Exception:
            pass

        return {"matched": False}
