"""
SCAM KILLER — Layer 1: Intelligent Message Detection Engine
Multi-category semantic inspection, contextual correlation, social engineering
synthesis, and explainable threat analysis.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from .base import BaseAnalyzer


class ContentAnalyzer(BaseAnalyzer):
    """
    Intelligent Message Content Analysis Engine.
    Inspects messages for deceptive patterns, urgency cues, brand impersonation,
    financial manipulation, credential solicitation, and social engineering.
    Distinguishes legitimate alerts and defensive reminders from fraudulent coercive traps.
    """

    # =========================================================================
    # CATEGORY A: Urgency & Psychological Pressure
    # =========================================================================
    URGENCY_RULES = [
        (
            r'\b(?:account|netbanking|access|card|service|profile|sim|connection|power|electricity)\s+(?:is|has been|was|will be|got)\s+(?:blocked|suspended|deactivated|closed|frozen|terminated|restricted|locked|on hold|disabled)\b|\b(?:blocked|suspended|deactivated|frozen|terminated|restricted|locked)\s+(?:your\s+)?(?:account|netbanking|access|card|service|profile|sim)\b|\b(?:unblock|reactivate|re-activate|restore|unlock)\s+(?:your\s+)?(?:account|card|access|netbanking|service)\b',
            "Account block / suspension threat",
            "high",
            "Message creates panic by threatening immediate loss of account access or service termination."
        ),
        (
            r'\b(disconnected (?:tonight|today)|power cut|electricity (?:will be |is )?cut|water supply (?:will be |is )?cut|electricity (?:power )?will be disconnected)\b',
            "Utility disconnection threat",
            "high",
            "Threatens imminent cutoff of essential utilities to induce panic."
        ),
        (
            r'\b(legal action (?:initiated|will be taken)|police (?:complaint|case|arrest)|court (?:notice|summons)|arrest warrant|penalty will be imposed)\b',
            "Legal intimidation & coercion",
            "high",
            "Uses coercive legal or law enforcement threats to pressure the recipient."
        ),
        (
            r'\b(within (?:24|12|48|2|6|1) hours?|today only|last warning|final notice|before midnight|before \d{1,2}(?::\d{2})?\s*(?:pm|am))\b',
            "Artificial deadline pressure",
            "medium",
            "Imposes a strict time constraint to prevent careful deliberation."
        ),
        (
            r'\b(immediately|urgent|urgently|right now|without delay|act now|hurry|action required)\b|\b(?:call|contact)\s+(?:our\s+)?(?:customer\s+care|support|executive|officer|manager|desk|team)\s+(?:immediately|urgently|to unblock|to verify)\b',
            "Urgency trigger language",
            "medium",
            "Uses high-pressure action verbs to rush the user into responding."
        )
    ]

    # =========================================================================
    # CATEGORY B: Entity & Brand Impersonation
    # =========================================================================
    ENTITY_PATTERNS = {
        "banking": (
            r'\b(sbi|state bank|hdfc|icici|axis bank|pnb|kotak|chase|wells fargo|bank of america|paypal|citi bank|barclays|reserve bank of india|rbi)\b',
            "Banking institution impersonation"
        ),
        "government": (
            r'\b(income tax|irs|hmrc|police department|cyber crime|customs office|enforcement directorate|aadhaar|uidai|pan department|dmv|social security)\b',
            "Government or regulatory agency claim"
        ),
        "delivery": (
            r'\b(usps|united states postal service|india post|fedex|dhl|ups|bluedart|delhivery|royal mail|speed post)\b',
            "Postal or delivery courier impersonation"
        ),
        "digital_platform": (
            r'\b(netflix|amazon|apple|microsoft|google|telegram|whatsapp|jio|airtel|vodafone)\b',
            "Digital platform or telecommunications provider claim"
        ),
        "support_persona": (
            r'\b(customer (?:care|support|service)|helpdesk officer|account manager|fraud (?:department|prevention team)|security alert officer)\b',
            "Customer support authority persona"
        )
    }

    # =========================================================================
    # CATEGORY C: Credential & Sensitive Information Solicitation
    # =========================================================================
    CREDENTIAL_RULES = [
        (
            r'\b(enter|share|send|provide|submit|give)\b.*?\b(otp|one[- ]time password|verification code)\b|\b(what is your otp|otp received|read me the code)\b',
            "OTP verification code solicitation",
            "high",
            "Directly solicits one-time authentication codes which can bypass multi-factor security."
        ),
        (
            r'\b(enter|share|send|provide|submit|confirm)\b.*?\b(password|pin|mpin|cvv|security code|atm pin)\b|\b(your password is required)\b',
            "Password or PIN solicitation",
            "high",
            "Requests confidential security credentials or personal identification numbers."
        ),
        (
            r'\b(?:update|complete|verify|unverified|mandatory|pending|link)\s*(?:your\s+)?(?:pan|aadhaar|kyc|identity)(?:\s*(?:update|verification|document|details|compliance))?\b|\b(?:pan[- ]kyc|kyc[- ]pan|e-kyc|ekyc|incomplete kyc)\b',
            "Unverified KYC / Identity verification lure",
            "high",
            "Claims mandatory identity compliance to harvest sensitive documentation and numbers."
        ),
        (
            r'\b(install|download)\b.*?\b[a-zA-Z0-9_\-]+\.apk\b|\bdownload.*?\bapk file\b',
            "Unsolicited Android APK installer",
            "high",
            "Attempts to distribute Android packages outside official application stores, posing severe malware risk."
        ),
        (
            r'\b(install|download|setup)\b.*?\b(anydesk|teamviewer|quicksupport|rustdesk|remote support|screen share)\b',
            "Remote access tool solicitation",
            "high",
            "Coerces installation of screen sharing or remote administration utilities."
        )
    ]

    # =========================================================================
    # CATEGORY D: Financial Manipulation
    # =========================================================================
    FINANCIAL_RULES = [
        (
            r'\b(redelivery fee|processing fee|customs surcharge|courier fee|tax payment|clearance fee|handling charge|(?:fee|charge|surcharge|penalty|challan)\s+(?:of\s+)?(?:[\$₹€£]|rs\.?|inr)?\s*\d+(?:\.\d{2})?)\b',
            "Advance fee or surcharge lure",
            "high",
            "Demands a seemingly small token fee to release an unverified parcel, package, or service."
        ),
        (
            r'\b(pay\s*(?:[\$₹€£]|rs\.?|inr)?\s*\d+(?:\.\d{2})?)\b|\b(transfer|deposit)\s*(?:[\$₹€£]|rs\.?|inr)?\s*\d+\b',
            "Direct payment demand in message",
            "medium",
            "Instructs immediate monetary transfer or payment directly in message text."
        ),
        (
            r'\b(tax refund of|pending refund|approved refund|refund of (?:[\$₹€£]|rs\.?|inr)?\s*\d+)\b',
            "Fake refund or rebate incentive",
            "medium",
            "Entices user with unexpected government, bank, or utility tax refunds."
        ),
        (
            r'\b(earn\s+(?:daily|per day|[\$₹€£]|rs\.?|inr)?\s*\d+|(?:part[- ]time job|work from home).*(?:daily|telegram|task|earn)|paid to like|watch videos.*earn)\b',
            "High-yield task or employment lure",
            "medium",
            "Promises unrealistically easy earnings via social tasks, Telegram groups, or advance deposits."
        )
    ]

    # =========================================================================
    # CATEGORY E: Reward & Lottery Manipulation
    # =========================================================================
    REWARD_RULES = [
        (
            r'\b(won|winner|lottery|lucky draw|kbc lucky draw|congratulations.*won)\b',
            "Unearned lottery or prize lure",
            "high",
            "Falsely claims user has won a raffle, lucky draw, or contest they never entered."
        ),
        (
            r'\b(gift card|voucher|cash prize|free reward|cashback bonus|reward claim)\b',
            "Cash prize or voucher lure",
            "medium",
            "Offers high-value vouchers or shopping incentives to elicit clicks or personal info."
        ),
        (
            r'(?:₹|\$|£|€)\s*(?:10,000|25,00,000|50,000|1,00,000|\d{5,9})',
            "High-value currency promise",
            "medium",
            "Mentions an excessively high cash payout as bait."
        ),
        (
            r'\b(airdrop|free (?:crypto|eth|btc|tokens)|connect wallet to claim)\b',
            "Cryptocurrency airdrop lure",
            "high",
            "Solicits cryptocurrency wallet connectivity under guise of free token distribution."
        )
    ]

    # =========================================================================
    # CATEGORY F: Suspicious Link Context
    # =========================================================================
    URL_CANDIDATE_REGEX = r'(?:https?://[^\s<>"]+|(?:\b[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|online|info|co|in|io|live|club|vip|site|app|buzz|ly|to|cc|tech|pro|me|gov|edu)(?:/[^\s<>"]*)?)'

    LINK_CONTEXT_RULES = [
        (
            r'\b(click|tap|visit|update|verify|login|resolve|unblock|reactivate)\b.*?(?:at|on|via)?\s*' + URL_CANDIDATE_REGEX + r'|' + URL_CANDIDATE_REGEX + r'.*?\b(to update|to verify|to unblock|to reactivate|to resolve|to login)\b',
            "Link framed as account verification requirement",
            "high",
            "Pressures the recipient into opening a link under the guise of security verification."
        ),
        (
            r'\b(claim|collect|redeem|receive|win)\b.*?(?:at|on|via)?\s*' + URL_CANDIDATE_REGEX + r'|' + URL_CANDIDATE_REGEX + r'.*?\b(to claim|to receive|to win)\b',
            "Link framed as prize or reward collection portal",
            "medium",
            "Routes user to an external URL to redeem an unverified prize."
        ),
        (
            r'\b(pay|transfer|fee|surcharge|deposit)\b.*?(?:at|on|via)?\s*' + URL_CANDIDATE_REGEX + r'|' + URL_CANDIDATE_REGEX + r'.*?\b(redelivery|customs|payment|fee)\b',
            "Link framed as mandatory payment or fee collection",
            "high",
            "Prompts payment on an external web address."
        )
    ]

    # =========================================================================
    # CATEGORY G: Social Engineering Patterns
    # =========================================================================
    SOCIAL_ENGINEERING_RULES = [
        (
            r'\b(keep (?:this )?(?:confidential|secret)|do not (?:tell|share with) (?:anyone|bank staff|family)|maintain secrecy)\b',
            "Secrecy and isolation pressure",
            "high",
            "Instructs the victim to conceal the interaction from family, police, or bank personnel."
        ),
        (
            r'\b(dear (?:valued )?customer|dear lucky winner|selected (?:mobile|user)|prestigious client)\b',
            "Generic false familiarity greeting",
            "low",
            "Uses generic formal flattery without personalizing to the recipient's real name."
        )
    ]

    # =========================================================================
    # MITIGATING & DEFENSIVE CONTEXT RULES (Anti-Phishing / Safety Reminders)
    # =========================================================================
    MITIGATION_PATTERNS = [
        (
            r'\b(?:never share (?:your )?(?:password|otp|pin|cvv|credentials)|(?:bank|we) (?:will )?never ask (?:for )?(?:your )?(?:otp|password|pin|cvv)|do not share (?:this )?(?:code|otp|pin) with anyone)\b',
            "Protective anti-phishing advisory ('never share your credentials')"
        ),
        (
            r'\b(?:official (?:mobile )?app|official website|nearest branch|verified portal|contact your bank directly|call the number on (?:the )?back of your card)\b',
            "Directs user to independent official channels (official app / bank branch)"
        ),
        (
            r'\b(?:debited (?:by|for)|credited (?:by|to)|avl bal|available balance|card ending (?:in|with)\s*\d{4})\b',
            "Standard transactional notification syntax (account debit/credit record)"
        ),
        (
            r'\b(?:has been delivered|out for delivery|delivered to your|package delivered|delivered on|order confirmed|shipped via)\b',
            "Standard delivery / order fulfillment notice"
        ),
        (
            r'\b(?:security tip|fraud awareness|cyber awareness|stay alert|advisory from)\b',
            "Educational security awareness notice"
        ),
        (
            r'\b(?:if not requested by you|if this was not you|report suspicious activity to)\b',
            "Standard security notification reporting clause"
        )
    ]

    @staticmethod
    def redact_sensitive(text: str) -> str:
        """
        Redacts any sensitive numeric strings (such as candidate card numbers or OTPs)
        from extracted snippets before returning in evidence.
        """
        if not text:
            return ""
        # Redact candidate 13-19 digit card numbers
        cleaned = re.sub(r'\b(?:\d[ -]?){13,19}\b', '[REDACTED CARD]', text)
        # Redact candidate 4-8 digit OTPs or account numbers
        cleaned = re.sub(r'\b\d{4,8}\b', '[REDACTED]', cleaned)
        return cleaned

    def analyze(self, target: Any, **kwargs) -> Dict[str, Any]:
        """
        Executes structured multi-category message analysis.
        target: str (message body)
        """
        text = str(target or "").strip()
        if not text:
            return {
                "status": "passed",
                "score": 0,
                "summary": "No text content available for semantic inspection.",
                "indicators": [],
                "evidence": [],
                "critical_flag": False,
                "risk_category": "No Clear Warning Signs",
                "confidence": "high",
                "categories_detected": [],
                "detailed_indicators": [],
                "mitigating_factors": [],
                "recommended_steps": [
                    "Enter or paste text into the workspace to evaluate threat signals."
                ]
            }

        # 1. Detect Mitigating & Defensive Context
        mitigating_factors: List[str] = []
        for pattern, label in self.MITIGATION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                mitigating_factors.append(label)

        # 2. Extract Category Indicators
        detected_categories: List[str] = []
        detailed_indicators: List[Dict[str, Any]] = []
        evidence_snippets: List[str] = []
        indicators: List[str] = []
        raw_score = 0
        critical_flag = False

        # --- Category A: Urgency ---
        urgency_found = False
        for pattern, name, severity, why in self.URGENCY_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                urgency_found = True
                if "urgency_pressure" not in detected_categories:
                    detected_categories.append("urgency_pressure")
                weight = 25 if severity == "high" else 15
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0))
                evidence_snippets.append(f'Urgency: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "urgency_pressure",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} to risk score"
                })

        # --- Category B: Entity / Impersonation ---
        impersonation_found = False
        detected_brands: List[str] = []
        for entity_type, (pattern, name) in self.ENTITY_PATTERNS.items():
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                impersonation_found = True
                brand_name = matches[0].group(0).upper()
                detected_brands.append(brand_name)
                # Brand alone has minimal score (+5) unless paired with actions
                weight = 5
                raw_score += weight
                ind_label = f"{name} ({brand_name})"
                indicators.append(ind_label)
                if "impersonation" not in detected_categories:
                    detected_categories.append("impersonation")
                evidence_snippets.append(f'Entity Claim: "{brand_name}"')
                detailed_indicators.append({
                    "name": ind_label,
                    "category": "impersonation",
                    "severity": "low",
                    "why_detected": f"Message references entity '{brand_name}'. Evaluated in conjunction with surrounding calls to action.",
                    "context_snippet": brand_name,
                    "contribution": "+5 (Entity observation)"
                })

        # --- Category C: Credential & Tool Solicitation ---
        credential_found = False
        for pattern, name, severity, why in self.CREDENTIAL_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                # Check if this match is in a DEFENSIVE context ("never share your OTP")
                match_span = matches[0].span()
                surrounding = text[max(0, match_span[0] - 30):min(len(text), match_span[1] + 30)].lower()
                is_defensive = any(def_phrase in surrounding for def_phrase in ["never share", "never ask", "do not share", "security tip", "beware of"])
                
                if is_defensive:
                    # Legitimate defensive advice, do not penalize
                    if "Protective anti-phishing advisory ('never share your credentials')" not in mitigating_factors:
                        mitigating_factors.append("Protective anti-phishing advisory ('never share your credentials')")
                    continue

                credential_found = True
                critical_flag = True
                if "credential_solicitation" not in detected_categories:
                    detected_categories.append("credential_solicitation")
                weight = 35
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0))
                evidence_snippets.append(f'Credential Trap: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "credential_solicitation",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} (Critical security violation)"
                })

        # --- Category D: Financial Manipulation ---
        financial_found = False
        for pattern, name, severity, why in self.FINANCIAL_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                financial_found = True
                if "financial_manipulation" not in detected_categories:
                    detected_categories.append("financial_manipulation")
                weight = 25 if severity == "high" else 15
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0))
                evidence_snippets.append(f'Fee/Financial Lure: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "financial_manipulation",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} to risk score"
                })

        # --- Category E: Reward & Lottery Manipulation ---
        reward_found = False
        for pattern, name, severity, why in self.REWARD_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                reward_found = True
                if "reward_lottery" not in detected_categories:
                    detected_categories.append("reward_lottery")
                weight = 25 if severity == "high" else 15
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0))
                evidence_snippets.append(f'Prize Lure: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "reward_lottery",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} to risk score"
                })

        # --- Category F: Suspicious Link Context ---
        link_context_found = False
        for pattern, name, severity, why in self.LINK_CONTEXT_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                link_context_found = True
                if "link_context" not in detected_categories:
                    detected_categories.append("link_context")
                weight = 25 if severity == "high" else 15
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0)[:60])
                evidence_snippets.append(f'Link Context: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "link_context",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} to risk score"
                })

        # --- Category G: Social Engineering Synthesis ---
        for pattern, name, severity, why in self.SOCIAL_ENGINEERING_RULES:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                if "social_engineering" not in detected_categories:
                    detected_categories.append("social_engineering")
                weight = 20 if severity == "high" else 5
                raw_score += weight
                indicators.append(name)
                match_text = self.redact_sensitive(matches[0].group(0))
                evidence_snippets.append(f'Social Engineering: "{match_text}"')
                detailed_indicators.append({
                    "name": name,
                    "category": "social_engineering",
                    "severity": severity,
                    "why_detected": why,
                    "context_snippet": match_text,
                    "contribution": f"+{weight} to risk score"
                })

        # Contextual Coupling: Authority Impersonation + Urgency + Call to Action
        if impersonation_found and (urgency_found or link_context_found or credential_found):
            social_engineering_label = "Authority Impersonation paired with Coercive Action"
            if social_engineering_label not in indicators:
                indicators.append(social_engineering_label)
                if "social_engineering" not in detected_categories:
                    detected_categories.append("social_engineering")
                raw_score += 15
                detailed_indicators.append({
                    "name": social_engineering_label,
                    "category": "social_engineering",
                    "severity": "high",
                    "why_detected": "Message combines an institutional identity claim with high urgency or a verification link, a hallmark of targeted spear-phishing.",
                    "context_snippet": f"Entity: {', '.join(detected_brands)} with urgent call to action",
                    "contribution": "+15 (Coercive compound pattern)"
                })

        # =========================================================================
        # 3. Contextual Adjustment & Mitigation Logic
        # =========================================================================
        has_phishing_link = link_context_found or ("http://" in text or "https://" in text)
        is_transactional_notification = any("transactional notification" in m.lower() for m in mitigating_factors)
        is_delivery_notification = any("delivery / order fulfillment" in m.lower() for m in mitigating_factors)
        has_defensive_warning = any("anti-phishing" in m.lower() or "official channels" in m.lower() for m in mitigating_factors)
        has_other_threats = urgency_found or credential_found or financial_found or reward_found or link_context_found

        # Case A: Legitimate Security Awareness or Defensive Reminder
        # (e.g. Bank reminds customer never to share OTP, no malicious links)
        if has_defensive_warning and not has_phishing_link and not credential_found and not financial_found:
            raw_score = 0
            critical_flag = False
            indicators = [ind for ind in indicators if "impersonation" in ind.lower() or "familiarity" in ind.lower()]
            status = "passed"
            risk_category = "No Clear Warning Signs"
            confidence = "high"
            summary = "Message identified as a legitimate security awareness notice or protective reminder advising vigilance."
            recommended_steps = [
                "Follow the safety advice provided: never share passwords or one-time codes with anyone.",
                "Maintain standard security awareness."
            ]

        # Case B: Standard Transactional or Delivery Fulfillment Notification
        # (e.g. "Your account was debited by ₹500 at Store" or "Your Amazon package #9281 has been delivered")
        elif (is_transactional_notification or is_delivery_notification) and not has_phishing_link and not credential_found and not reward_found and not financial_found:
            raw_score = 0
            critical_flag = False
            status = "passed"
            risk_category = "No Clear Warning Signs"
            confidence = "high"
            summary = "Message exhibits standard automated transaction or package delivery notification syntax without suspicious links or fees."
            recommended_steps = [
                "Verify order or delivery status via your official merchant account or carrier app.",
                "Maintain standard security hygiene."
            ]

        # Case B2: Normal Entity / Brand Mention without Threat Signals
        # (e.g. mentioning a brand like Netflix or Amazon in an everyday sentence without attacks)
        elif detected_categories == ["impersonation"] and not has_other_threats and not has_phishing_link:
            raw_score = 0
            critical_flag = False
            status = "passed"
            risk_category = "No Clear Warning Signs"
            confidence = "high"
            summary = "Message mentions a recognized brand or entity in a normal informational context without deceptive threat signals."
            recommended_steps = [
                "No suspicious requests or indicators identified in message content."
            ]

        # Case C: Active Scam / Social Engineering Attack
        elif raw_score >= 35 or critical_flag:
            status = "flagged"
            risk_category = "Suspicious"
            confidence = "high" if (critical_flag or raw_score >= 50) else "medium"
            summary = f"Detected multiple high-risk indicators across {len(detected_categories)} deception categories: coercive urgency, brand impersonation, or credential/payment solicitation."
            recommended_steps = [
                "DO NOT click, open, or submit credentials on any embedded links.",
                "DO NOT share One-Time Passwords (OTPs), PINs, or install remote assistance tools.",
                "Contact the claimed organization directly using contact info printed on official statements or bills."
            ]

        # Case D: Ambiguous or Low-Risk Promotional Language
        elif raw_score > 0:
            status = "caution"
            risk_category = "Caution"
            confidence = "medium"
            summary = "Promotional language, artificial deadline cues, or unverified claims detected without confirmed credential traps."
            recommended_steps = [
                "Exercise caution with unsolicited promotional offers or prize claims.",
                "Verify the authenticity of the sender before responding or providing personal information."
            ]

        # Case E: Clean / Benign Content
        else:
            status = "passed"
            risk_category = "No Clear Warning Signs"
            confidence = "high"
            summary = "Content passed semantic heuristics without detecting high-risk urgency language, lottery lures, or credential traps."
            recommended_steps = [
                "Standard cybersecurity hygiene: continue verifying sender identity before acting on unexpected requests."
            ]

        # Deduplicate indicators & evidence while preserving order
        indicators = list(dict.fromkeys(indicators))
        evidence_snippets = list(dict.fromkeys(evidence_snippets))

        return {
            "status": status,
            "score": min(100, raw_score),
            "summary": summary,
            "indicators": indicators,
            "evidence": evidence_snippets,
            "critical_flag": critical_flag,
            "risk_category": risk_category,
            "confidence": confidence,
            "categories_detected": detected_categories,
            "detailed_indicators": detailed_indicators,
            "mitigating_factors": mitigating_factors,
            "recommended_steps": recommended_steps
        }

