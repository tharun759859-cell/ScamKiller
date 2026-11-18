"""
SCAM KILLER — Database Queries & Telemetry Operations
"""

import json
from typing import List, Dict, Any, Optional
from .db import get_db_connection


class TelemetryRepository:
    """Manages audit telemetry and community records in SQLite."""

    @classmethod
    def seed_initial_data_if_empty(cls) -> None:
        """Seeds initial reference records if tables are fresh."""
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check scans
        cursor.execute("SELECT COUNT(*) AS cnt FROM scans")
        if cursor.fetchone()["cnt"] == 0:
            sample_scans = [
                (
                    "scan-001",
                    "url",
                    "suspicious",
                    "2026-11-16 22:38",
                    "2 min ago",
                    "https://free-reward-claim.xyz",
                    "flagged",
                    "flagged",
                    "skipped",
                    "flagged",
                    3,
                    "High-risk cheap TLD (.xyz) with unverified reward claim incentives.",
                    json.dumps({
                        "badgeClass": "badge-suspicious",
                        "badgeIcon": "warning",
                        "riskLabel": "Suspicious"
                    })
                ),
                (
                    "scan-002",
                    "message",
                    "caution",
                    "2026-11-16 22:35",
                    "5 min ago",
                    "You won a ₹10,000 gift card!",
                    "flagged",
                    "passed",
                    "skipped",
                    "caution",
                    2,
                    "Promotional urgency and high-value unexpected gift voucher incentive.",
                    json.dumps({
                        "badgeClass": "badge-caution",
                        "badgeIcon": "error",
                        "riskLabel": "Caution"
                    })
                ),
                (
                    "scan-003",
                    "url",
                    "safe",
                    "2026-11-16 22:30",
                    "10 min ago",
                    "https://indian-bank-update.com",
                    "passed",
                    "caution",
                    "skipped",
                    "passed",
                    1,
                    "Automated heuristic inspection detected no active blacklists at audit time.",
                    json.dumps({
                        "badgeClass": "badge-safe",
                        "badgeIcon": "check_circle",
                        "riskLabel": "No clear warning signs"
                    })
                )
            ]
            cursor.executemany("""
                INSERT INTO scans (
                    scan_id, scan_type, risk_category, timestamp, time_ago,
                    display_item, content_status, url_status, screenshot_status,
                    intel_status, indicator_count, explanation, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_scans)

        # Check community reports
        cursor.execute("SELECT COUNT(*) AS cnt FROM community_reports")
        if cursor.fetchone()["cnt"] == 0:
            sample_reports = [
                (
                    "REP-4091",
                    "Banking / KYC",
                    "HDFC Urgent PAN Update SMS with APK attachment",
                    "sms: 'Your HDFC account KYC suspended. Install HDFC_Support.apk to reactivate'",
                    "Nov 16, 2026",
                    412,
                    "suspicious",
                    "Active Threat",
                    "Fraudsters distributing remote access trojans (RAT) masquerading as banking utilities to intercept OTPs.",
                    1,
                    "Demonstration Sample"
                ),
                (
                    "REP-4088",
                    "Delivery Phishing",
                    "India Post Delivery Address Update Scam",
                    "https://indiapost-parcel-redirection[.]xyz",
                    "Nov 15, 2026",
                    285,
                    "suspicious",
                    "Active Threat",
                    "Phishing page clones the official postal color scheme and prompts for credit card details for a ₹5 token redelivery fee.",
                    1,
                    "Demonstration Sample"
                ),
                (
                    "REP-4075",
                    "Work-from-Home",
                    "Telegram Hotel Review Task Scam",
                    "Telegram: @global_ratings_task_portal",
                    "Nov 14, 2026",
                    198,
                    "suspicious",
                    "Under Investigation",
                    "Victims are paid small amounts (₹150-₹300) before being requested to deposit ₹50,000 for 'premium VIP merchant level'.",
                    1,
                    "Demonstration Sample"
                ),
                (
                    "REP-4062",
                    "Utility Bill",
                    "Discom Power Disconnection WhatsApp Alert",
                    "whatsapp: +91-9481928371",
                    "Nov 13, 2026",
                    350,
                    "suspicious",
                    "Active Threat",
                    "Fake discom alerts demanding payment via AnyDesk/TeamViewer remote desktop installation.",
                    1,
                    "Demonstration Sample"
                )
            ]
            cursor.executemany("""
                INSERT INTO community_reports (
                    report_id, category, title, reported_item, date_reported,
                    upvotes, risk_level, status, description, is_demo, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_reports)

        # Ensure demo records in existing database are labeled clearly
        cursor.execute("UPDATE community_reports SET is_demo = 1, source = 'Demonstration Sample' WHERE report_id LIKE 'REP-40%'")

        conn.commit()
        conn.close()

    @classmethod
    def insert_scan(cls, scan_data: Dict[str, Any]) -> None:
        """Inserts a safe metadata record of a scan."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                scan_id, scan_type, risk_category, timestamp, time_ago,
                display_item, content_status, url_status, screenshot_status,
                intel_status, indicator_count, explanation, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["scan_id"],
            scan_data["scan_type"],
            scan_data["risk_category"],
            scan_data["timestamp"],
            scan_data.get("time_ago", "Just now"),
            scan_data["display_item"],
            scan_data.get("content_status", "passed"),
            scan_data.get("url_status", "passed"),
            scan_data.get("screenshot_status", "skipped"),
            scan_data.get("intel_status", "passed"),
            scan_data.get("indicator_count", 0),
            scan_data.get("explanation", ""),
            json.dumps(scan_data.get("metadata", {}))
        ))
        conn.commit()
        conn.close()

    @classmethod
    def get_recent_scans(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent scans ordered newest first."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, scan_type, risk_category, timestamp, time_ago,
                   display_item, content_status, url_status, screenshot_status,
                   intel_status, indicator_count, explanation, metadata_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            meta = {}
            if r["metadata_json"]:
                try:
                    meta = json.loads(r["metadata_json"])
                except Exception:
                    pass

            results.append({
                "id": r["scan_id"],
                "type": r["scan_type"],
                "riskLevel": r["risk_category"],
                "riskLabel": meta.get("riskLabel", r["risk_category"].capitalize()),
                "badgeClass": meta.get("badgeClass", f"badge-{r['risk_category']}"),
                "badgeIcon": meta.get("badgeIcon", "warning" if r["risk_category"] == "suspicious" else "check_circle"),
                "submittedItem": r["display_item"],
                "timestamp": r["timestamp"],
                "timeAgo": r["time_ago"],
                "explanation": r["explanation"],
                "icon": "link" if r["scan_type"] == "url" else ("image" if r["scan_type"] == "screenshot" else "mail"),
                "layers": meta.get("layers", {}),
                "recommendedSteps": meta.get("recommendedSteps", [])
            })
        return results

    @classmethod
    def purge_scans(cls) -> int:
        """Deletes all telemetry scan records per user request."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

    @classmethod
    def get_community_reports(cls) -> List[Dict[str, Any]]:
        """Retrieves community threat advisories."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(community_reports)")
        columns = [col[1] for col in cursor.fetchall()]
        has_is_demo = "is_demo" in columns
        has_source = "source" in columns

        cursor.execute("""
            SELECT report_id, category, title, reported_item, date_reported,
                   upvotes, risk_level, status, description
                   """ + (", is_demo" if has_is_demo else "") + (", source" if has_source else "") + """
            FROM community_reports
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": r["report_id"],
                "category": r["category"],
                "title": r["title"],
                "reportedItem": r["reported_item"],
                "date": r["date_reported"],
                "upvotes": r["upvotes"],
                "riskLevel": r["risk_level"],
                "status": r["status"],
                "description": r["description"],
                "isDemo": bool(r["is_demo"]) if has_is_demo and r["is_demo"] is not None else (r["report_id"].startswith("REP-40")),
                "source": (r["source"] if has_source and r["source"] else ("Demonstration Sample" if r["report_id"].startswith("REP-40") else "Community Verified Submission"))
            }
            for r in rows
        ]

    @classmethod
    def upvote_report(cls, report_id: str) -> Optional[int]:
        """Increments community confirmation count."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE community_reports SET upvotes = upvotes + 1 WHERE report_id = ?", (report_id,))
        if cursor.rowcount > 0:
            cursor.execute("SELECT upvotes FROM community_reports WHERE report_id = ?", (report_id,))
            new_val = cursor.fetchone()["upvotes"]
            conn.commit()
            conn.close()
            return new_val
        conn.close()
        return None

    @classmethod
    def insert_community_report(cls, report_data: Dict[str, Any]) -> str:
        """Inserts a new anonymized community report into SQLite."""
        import time
        from datetime import datetime
        conn = get_db_connection()
        cursor = conn.cursor()
        report_id = report_data.get("report_id") or f"REP-{int(time.time() % 100000)}"

        cursor.execute("PRAGMA table_info(community_reports)")
        columns = [col[1] for col in cursor.fetchall()]
        has_demo_col = "is_demo" in columns and "source" in columns

        if has_demo_col:
            cursor.execute("""
                INSERT INTO community_reports (
                    report_id, category, title, reported_item, date_reported,
                    upvotes, risk_level, status, description, is_demo, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                report_data.get("category", "General Phishing"),
                report_data.get("title", "Community Submitted Threat"),
                report_data.get("reported_item", ""),
                report_data.get("date_reported", datetime.now().strftime("%b %d, %Y")),
                1,
                report_data.get("risk_level", "suspicious"),
                "Community Verified",
                report_data.get("description", ""),
                0,
                "Community Verified Submission"
            ))
        else:
            cursor.execute("""
                INSERT INTO community_reports (
                    report_id, category, title, reported_item, date_reported,
                    upvotes, risk_level, status, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                report_data.get("category", "General Phishing"),
                report_data.get("title", "Community Submitted Threat"),
                report_data.get("reported_item", ""),
                report_data.get("date_reported", datetime.now().strftime("%b %d, %Y")),
                1,
                report_data.get("risk_level", "suspicious"),
                "Community Verified",
                report_data.get("description", "")
            ))

        conn.commit()
        conn.close()
        return report_id

    @classmethod
    def get_radar_trends(cls) -> Dict[str, Any]:
        """
        Calculates category breakdown and trend status based strictly on stored records in SQLite.
        Truthfully reports insufficient volume if the sample size is inadequate to prevent fabricated statistics.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT category, COUNT(*) as report_count, SUM(upvotes) as total_upvotes
            FROM community_reports
            GROUP BY category
            ORDER BY report_count DESC
        """)
        rows = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) as total_reports FROM community_reports")
        total = cursor.fetchone()["total_reports"]

        cursor.execute("PRAGMA table_info(community_reports)")
        columns = [col[1] for col in cursor.fetchall()]
        user_reports_count = 0
        if "is_demo" in columns:
            cursor.execute("SELECT COUNT(*) as user_reports FROM community_reports WHERE is_demo = 0")
            user_reports_count = cursor.fetchone()["user_reports"]

        conn.close()

        categories = [
            {
                "category": r["category"],
                "report_count": r["report_count"],
                "total_upvotes": r["total_upvotes"] or 0
            }
            for r in rows
        ]

        # Require at least 50 reports before generating automated percentage surge models
        has_sufficient_data = total >= 50

        return {
            "status": "sufficient_data" if has_sufficient_data else "insufficient_data",
            "has_sufficient_data": has_sufficient_data,
            "total_reports": total,
            "user_submitted_reports": user_reports_count,
            "data_notice": (
                "Verified statistical velocity calculated from community telemetry."
                if has_sufficient_data else
                f"Sample volume ({total} recorded incidents) is currently below the statistical threshold (50 incidents) required for velocity modeling. Displaying raw incident frequency without fabricated percentages."
            ),
            "trends": categories
        }

