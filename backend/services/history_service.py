"""
SCAM KILLER — History & Telemetry Service
Handles scan audit log retrieval and user-controlled data deletion.
"""

from typing import List, Dict, Any, Optional
from database.models import TelemetryRepository


class HistoryService:
    """Provides history management and community feed access."""

    @classmethod
    def get_scan_history(
        cls,
        limit: int = 50,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Returns recent scan telemetry records with optional category/risk filtering and search."""
        return TelemetryRepository.get_recent_scans(
            limit=limit,
            category=category,
            risk=risk,
            search_query=search_query
        )

    @classmethod
    def get_scan_by_id(cls, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves single complete scan report by ID."""
        return TelemetryRepository.get_scan_by_id(scan_id)

    @classmethod
    def purge_history(cls) -> Dict[str, Any]:
        """Clears all scan telemetry records from SQLite."""
        deleted_count = TelemetryRepository.purge_scans()
        return {
            "success": True,
            "deleted_count": deleted_count,
            "message": f"Successfully purged {deleted_count} scan telemetry records from session log."
        }

    # Alias for backward compatibility
    clear_scan_history = purge_history

    @classmethod
    def delete_scan_by_id(cls, scan_id: str) -> bool:
        """Deletes a single scan by ID."""
        return TelemetryRepository.delete_scan(scan_id)

    @classmethod
    def get_community_patterns(cls) -> Dict[str, Any]:
        """Returns structured community scam patterns grouped by fingerprint."""
        return TelemetryRepository.get_community_patterns()

    @classmethod
    def get_community_intelligence(cls) -> List[Dict[str, Any]]:
        """Returns documented community threat reports."""
        return TelemetryRepository.get_community_reports()

    @classmethod
    def get_community_feed(cls, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns community feed with optional category filter."""
        reports = TelemetryRepository.get_community_reports()
        if category and category.lower() != "all":
            reports = [r for r in reports if r.get("category", "").lower() == category.lower()]
        return reports

    @classmethod
    def upvote_community_report(cls, report_id: str) -> Dict[str, Any]:
        """Increments community report confirmation."""
        new_count = TelemetryRepository.upvote_report(report_id)
        if new_count is not None:
            return {"success": True, "report_id": report_id, "upvotes": new_count}
        return {"success": False, "error": f"Report ID '{report_id}' not found."}

    @classmethod
    def create_community_report(cls, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Creates an anonymized community report."""
        report_id = TelemetryRepository.insert_community_report(report_data)
        return {"success": True, "report_id": report_id}
