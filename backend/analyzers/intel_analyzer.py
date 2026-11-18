"""
SCAM KILLER — Layer 4: Trusted Intelligence Interface
Cross-references detected indicators with manually maintained, documented advisories
and structured threat repositories without initiating network queries.
"""

from typing import Dict, Any, List
from .base import BaseAnalyzer


class IntelAnalyzer(BaseAnalyzer):
    """
    Evaluates indicators against a documented intelligence catalog.
    Strictly separates verified institutional advisories from unverified community observations.
    """

    # Documented Verified Advisories (Authoritative CIRT / SOC sources)
    VERIFIED_ADVISORIES = [
        {
            "id": "ADV-2026-092",
            "source": "OpenPhish & Global Threat Feed",
            "verified_date": "2026-11-14",
            "threat_pattern": "free-reward-claim",
            "target": "Unsolicited Reward Voucher Harvesting",
            "description": "Disposable .xyz domain distributing malicious credential lures and survey traps.",
            "severity": "high"
        },
        {
            "id": "ADV-2026-081",
            "source": "National Cybercrime Coordination Advisory",
            "verified_date": "2026-11-10",
            "threat_pattern": "sbi-kyc",
            "target": "Banking KYC Phishing",
            "description": "Mass SMS campaigns spoofing State Bank of India claiming mandatory PAN update or imminent block.",
            "severity": "critical"
        },
        {
            "id": "ADV-2026-074",
            "source": "CERT Threat Telemetry",
            "verified_date": "2026-11-04",
            "threat_pattern": "indiapost",
            "target": "Postal Smishing & Token Fee Scams",
            "description": "Fraudulent postal parcel notification claiming unpaid surcharge ($1-$5) linking to disposable .xyz/.top domains.",
            "severity": "high"
        },
        {
            "id": "ADV-2026-062",
            "source": "OpenPhish Threat Feed Benchmark",
            "verified_date": "2026-10-28",
            "threat_pattern": "netflix",
            "target": "Streaming Subscription Credential Harvesting",
            "description": "Phishing sites imitating Netflix account renewal prompts.",
            "severity": "high"
        },
        {
            "id": "ADV-2026-055",
            "source": "Utility Fraud Warning Network",
            "verified_date": "2026-10-15",
            "threat_pattern": "electricity",
            "target": "Power Disconnection Social Engineering",
            "description": "SMS and WhatsApp messages threatening power cuts at 9:30 PM due to unpaid electricity bills, demanding calls to personal numbers.",
            "severity": "high"
        }
    ]

    # Documented Community Observation Signatures (Unverified peer reports)
    COMMUNITY_SIGNATURES = [
        {
            "id": "COMM-4091",
            "source": "Community Threat Reports (Peer-submitted, unverified)",
            "pattern": "apk",
            "category": "Malicious Android Package Distribution",
            "description": "Remote Access Trojans disguised as official banking apps (e.g., HDFC_Support.apk) targeting OTP interception."
        },
        {
            "id": "COMM-4075",
            "source": "Community Threat Reports (Peer-submitted, unverified)",
            "pattern": "telegram",
            "category": "Task & Hotel Review Investment Scam",
            "description": "Telegram task groups paying small sums initially before demanding large deposits."
        }
    ]

    def analyze(self, target: Any, **kwargs) -> Dict[str, Any]:
        """
        Cross-references target text, domain, and detected indicators.
        target: str (text or domain)
        kwargs: domain (optional str), indicators (optional list)
        """
        text = str(target or "").lower()
        domain = str(kwargs.get("domain", "")).lower()
        passed_indicators = [str(i).lower() for i in kwargs.get("indicators", [])]

        matched_advisories = []
        matched_community = []
        score = 0
        indicators = []

        # 1. Match Verified Advisories
        for adv in self.VERIFIED_ADVISORIES:
            pattern = adv["threat_pattern"]
            if pattern in text or pattern in domain or any(pattern in ind for ind in passed_indicators):
                matched_advisories.append({
                    "id": adv["id"],
                    "source": adv["source"],
                    "verified_date": adv["verified_date"],
                    "target": adv["target"],
                    "description": adv["description"],
                    "type": "Verified Advisory"
                })
                score += 30
                indicators.append(f"Matched Verified Advisory {adv['id']} ({adv['source']}, verified {adv['verified_date']})")

        # 2. Match Community Reports (explicitly treated as unverified observation, lower weight)
        for comm in self.COMMUNITY_SIGNATURES:
            pattern = comm["pattern"]
            if pattern in text or pattern in domain or any(pattern in ind for ind in passed_indicators):
                matched_community.append({
                    "id": comm["id"],
                    "source": comm["source"],
                    "category": comm["category"],
                    "description": comm["description"],
                    "type": "Community Observation (Unverified)"
                })
                # Community report adds caution (+15), not treated as confirmed proof
                score += 15
                indicators.append(f"Correlated with Community Observation {comm['id']} ({comm['category']} - Unverified peer observation)")

        # Determine Layer Status
        if matched_advisories:
            status = "flagged"
            summary = f"Correlated with {len(matched_advisories)} verified security advisories in threat database."
        elif matched_community:
            status = "caution"
            summary = f"Correlated with {len(matched_community)} unverified community threat patterns. Requires independent validation."
        else:
            status = "passed"
            summary = "No active records or verified CIRT advisories matched this specific payload signature."

        return {
            "status": status,
            "score": score,
            "summary": summary,
            "indicators": indicators,
            "verified_advisories": matched_advisories,
            "community_observations": matched_community,
            "has_verified_advisory": bool(matched_advisories)
        }
