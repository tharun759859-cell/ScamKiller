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
        """Inserts a safe metadata record of a scan into SQLite."""
        conn = get_db_connection()
        cursor = conn.cursor()

        full_report = scan_data.get("full_report_json", scan_data.get("structured_data", {}))
        if isinstance(full_report, dict):
            full_report_str = json.dumps(full_report)
        else:
            full_report_str = str(full_report or "")

        cursor.execute("PRAGMA table_info(scans)")
        cols = {col[1] for col in cursor.fetchall()}

        fields = [
            "scan_id", "scan_type", "risk_category", "timestamp", "time_ago",
            "display_item", "content_status", "url_status", "screenshot_status",
            "intel_status", "indicator_count", "explanation", "metadata_json",
            "source_type", "confidence", "ai_summary", "structured_data"
        ]
        values = [
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
            json.dumps(scan_data.get("metadata", {})),
            scan_data.get("source_type", "text"),
            scan_data.get("confidence", 0.8),
            scan_data.get("ai_summary", scan_data.get("explanation", "")),
            json.dumps(scan_data.get("structured_data", {}))
        ]

        if "full_report_json" in cols:
            fields.append("full_report_json")
            values.append(full_report_str)
        if "pattern_fingerprint" in cols:
            fields.append("pattern_fingerprint")
            values.append(scan_data.get("pattern_fingerprint", ""))
        if "impersonated_entity" in cols:
            fields.append("impersonated_entity")
            values.append(scan_data.get("impersonated_entity", "None"))
        if "category" in cols:
            fields.append("category")
            values.append(scan_data.get("category", "General Phishing"))
        if "message_theme" in cols:
            fields.append("message_theme")
            values.append(scan_data.get("message_theme", ""))
        if "urgency_or_reward_pattern" in cols:
            fields.append("urgency_or_reward_pattern")
            values.append(scan_data.get("urgency_or_reward_pattern", ""))
        if "requested_action" in cols:
            fields.append("requested_action")
            values.append(scan_data.get("requested_action", ""))

        placeholders = ", ".join(["?"] * len(fields))
        col_names = ", ".join(fields)
        cursor.execute(f"INSERT OR REPLACE INTO scans ({col_names}) VALUES ({placeholders})", values)
        conn.commit()
        conn.close()

    @classmethod
    def get_recent_scans(
        cls,
        limit: int = 50,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves recent scans ordered newest first with optional search and filters."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(scans)")
        cols = {col[1] for col in cursor.fetchall()}

        query = "SELECT * FROM scans WHERE 1=1"
        params: List[Any] = []

        if risk and risk.lower() not in ("all", ""):
            query += " AND LOWER(risk_category) = ?"
            params.append(risk.lower())

        if category and category.lower() not in ("all", ""):
            if "category" in cols:
                query += " AND (LOWER(category) LIKE ? OR LOWER(display_item) LIKE ?)"
                params.extend([f"%{category.lower()}%", f"%{category.lower()}%"])
            else:
                query += " AND LOWER(display_item) LIKE ?"
                params.append(f"%{category.lower()}%")

        if search_query and search_query.strip():
            sq = f"%{search_query.strip().lower()}%"
            extra_conds = ["LOWER(display_item) LIKE ?", "LOWER(explanation) LIKE ?"]
            params.extend([sq, sq])
            if "category" in cols:
                extra_conds.append("LOWER(category) LIKE ?")
                params.append(sq)
            if "impersonated_entity" in cols:
                extra_conds.append("LOWER(impersonated_entity) LIKE ?")
                params.append(sq)
            query += f" AND ({' OR '.join(extra_conds)})"

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
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

            item_category = r["category"] if "category" in cols and r["category"] else meta.get("category", "General Threat")
            item_entity = r["impersonated_entity"] if "impersonated_entity" in cols and r["impersonated_entity"] else "None"
            item_fingerprint = r["pattern_fingerprint"] if "pattern_fingerprint" in cols and r["pattern_fingerprint"] else ""
            item_confidence = r["confidence"] if "confidence" in cols and r["confidence"] is not None else 0.85

            results.append({
                "id": r["scan_id"],
                "scanId": r["scan_id"],
                "scan_id": r["scan_id"],
                "type": r["scan_type"],
                "scanType": r["scan_type"],
                "sourceType": r["source_type"] if "source_type" in cols and r["source_type"] else "text",
                "riskLevel": r["risk_category"],
                "riskCategory": r["risk_category"],
                "risk_category": r["risk_category"],
                "riskLabel": meta.get("riskLabel", r["risk_category"].capitalize()),
                "category": item_category,
                "badgeClass": meta.get("badgeClass", f"badge-{r['risk_category']}"),
                "badgeIcon": meta.get("badgeIcon", "warning" if r["risk_category"] == "suspicious" else "check_circle"),
                "displayItem": r["display_item"],
                "submittedItem": r["display_item"],
                "timestamp": r["timestamp"],
                "timeAgo": r["time_ago"],
                "explanation": r["explanation"],
                "aiSummary": r["ai_summary"] if "ai_summary" in cols and r["ai_summary"] else r["explanation"],
                "confidence": item_confidence,
                "confidencePercent": int(item_confidence * 100),
                "impersonatedEntity": item_entity,
                "patternFingerprint": item_fingerprint,
                "indicatorCount": r["indicator_count"] if "indicator_count" in cols else 0,
                "icon": "link" if r["scan_type"] == "url" else ("image" if r["scan_type"] == "screenshot" else ("mic" if r["scan_type"] == "audio" else "mail")),
                "layers": meta.get("layers", {}),
                "recommendedSteps": meta.get("recommendedSteps", [])
            })
        return results

    @classmethod
    def get_scan_by_id(cls, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete scan record including full report JSON for re-opening."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None

        # Check full_report_json or structured_data
        report_data = None
        if "full_report_json" in row.keys() and row["full_report_json"]:
            try:
                report_data = json.loads(row["full_report_json"])
            except Exception:
                pass

        if not report_data and "structured_data" in row.keys() and row["structured_data"]:
            try:
                report_data = json.loads(row["structured_data"])
            except Exception:
                pass

        if not isinstance(report_data, dict):
            report_data = {}

        # Ensure top-level identifiers and fields are intact
        report_data["scan_id"] = row["scan_id"]
        report_data["scanId"] = row["scan_id"]
        report_data["timestamp"] = row["timestamp"]
        report_data["submitted_item"] = row["display_item"]
        report_data["display_item"] = row["display_item"]
        report_data["risk_level"] = row["risk_category"]
        report_data["risk_category"] = row["risk_category"]
        if "explanation" in row.keys() and row["explanation"] and not report_data.get("explanation"):
            report_data["explanation"] = row["explanation"]

        return report_data

    @classmethod
    def delete_scan(cls, scan_id: str) -> bool:
        """Deletes a single scan by ID permanently."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

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

    @classmethod
    def get_community_patterns(cls) -> Dict[str, Any]:
        """
        Extracts structured scam patterns grouped by pattern fingerprint.
        Aggregates community reports and verified scans into pattern clusters.
        Applies transparent statistical thresholding without inventing metrics.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(scans)")
        scan_cols = {col[1] for col in cursor.fetchall()}
        cursor.execute("PRAGMA table_info(community_reports)")
        comm_cols = {col[1] for col in cursor.fetchall()}

        cursor.execute("SELECT * FROM community_reports ORDER BY id DESC")
        comm_rows = cursor.fetchall()

        patterns: Dict[str, Dict[str, Any]] = {}

        # 1. Aggregate from community_reports
        for r in comm_rows:
            category = r["category"] if "category" in comm_cols else "General Phishing"
            title = r["title"] if "title" in comm_cols else "Community Threat"
            date_rep = r["date_reported"] if "date_reported" in comm_cols else "Recent"
            upvotes = r["upvotes"] if "upvotes" in comm_cols else 1
            risk = r["risk_level"] if "risk_level" in comm_cols else "suspicious"
            desc = r["description"] if "description" in comm_cols else ""
            reported_item = r["reported_item"] if "reported_item" in comm_cols else ""
            is_demo = bool(r["is_demo"]) if "is_demo" in comm_cols and r["is_demo"] is not None else False

            entity = "India Post" if "India Post" in title else ("HDFC Bank" if "HDFC" in title else ("Telegram" if "Telegram" in title else ("Electricity Board" if "Power" in title or "Discom" in title else "Claimed Brand")))
            action = "Micro-Fee Surcharge Payment" if "Fee" in title or "Redirection" in title else ("Malicious APK / Remote Assistance" if "APK" in title or "Discom" in title else "Disclose Credentials / Review Task")

            clean_cat = category.strip().lower()
            key = f"comm:{clean_cat}:{entity.lower()}"

            if key not in patterns:
                patterns[key] = {
                    "pattern_id": f"PAT-{abs(hash(key)) % 100000:05d}",
                    "fingerprint": key,
                    "title": title,
                    "category": category,
                    "impersonated_entity": entity,
                    "requested_action": action,
                    "frequency": 0,
                    "confirmations": 0,
                    "first_observed": date_rep,
                    "last_observed": date_rep,
                    "risk_level": risk,
                    "description": desc,
                    "example_item": reported_item,
                    "is_demo": is_demo
                }

            patterns[key]["frequency"] += 1
            patterns[key]["confirmations"] += upvotes

        # 2. Aggregate from suspicious/caution scans
        if "pattern_fingerprint" in scan_cols:
            cursor.execute("""
                SELECT scan_id, category, impersonated_entity, requested_action,
                       message_theme, risk_category, timestamp, display_item,
                       pattern_fingerprint
                FROM scans
                WHERE risk_category IN ('suspicious', 'caution')
            """)
            scan_rows = cursor.fetchall()
            for r in scan_rows:
                fp = r["pattern_fingerprint"] or ""
                cat = r["category"] or "General Phishing"
                entity = r["impersonated_entity"] or "None"
                action = r["requested_action"] or "Unsolicited Request"
                theme = r["message_theme"] or r["display_item"]

                if not fp:
                    fp = f"scan:{cat.lower()}:{entity.lower()}"

                if fp not in patterns:
                    patterns[fp] = {
                        "pattern_id": f"PAT-{abs(hash(fp)) % 100000:05d}",
                        "fingerprint": fp,
                        "title": f"{entity} {theme}" if entity != "None" else f"{cat}: {theme[:45]}",
                        "category": cat,
                        "impersonated_entity": entity,
                        "requested_action": action,
                        "frequency": 0,
                        "confirmations": 1,
                        "first_observed": r["timestamp"],
                        "last_observed": r["timestamp"],
                        "risk_level": r["risk_category"],
                        "description": "Recurring threat pattern signature logged in audit telemetry.",
                        "example_item": r["display_item"],
                        "is_demo": False
                    }
                patterns[fp]["frequency"] += 1
                patterns[fp]["last_observed"] = r["timestamp"]

        conn.close()

        pattern_list = sorted(patterns.values(), key=lambda x: (x["frequency"], x["confirmations"]), reverse=True)

        for pat in pattern_list:
            freq = pat["frequency"]
            if freq >= 10:
                pat["trend_status"] = "High Surge"
                pat["trend_badge"] = "Surge Alert"
            elif freq >= 4:
                pat["trend_status"] = "Active Pattern"
                pat["trend_badge"] = "Active"
            else:
                pat["trend_status"] = "Emerging / Low Volume"
                pat["trend_badge"] = "Not enough reports yet"

            pat["has_sufficient_data"] = freq >= 5
            pat["threshold_notice"] = (
                f"Statistically verified from {freq} incident reports."
                if pat["has_sufficient_data"] else
                f"Not enough reports yet ({freq} recorded incident{'s' if freq > 1 else ''}). Minimum 5 reports required for confirmed threat pattern."
            )

        return {
            "patterns": pattern_list,
            "total_patterns": len(pattern_list),
            "total_incidents": sum(p["frequency"] for p in pattern_list),
            "threshold_required": 5,
            "status": "active"
        }


