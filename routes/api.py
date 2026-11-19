"""
SCAM BREAKER — REST API Endpoints
Provides endpoints for threat scanning, history retrieval, data deletion, community intelligence,
speech transcription, screenshot OCR, PDF report generation, and interactive AI advisory chat.
Powered by AI safety intelligence.
"""

from flask import Blueprint, request, jsonify, current_app, make_response
from datetime import datetime

from services.scan_service import ScanService
from services.ai_service import AIService
from services.history_service import HistoryService
from services.ocr_service import OcrService
from services.transcription_service import TranscriptionService
from services.report_service import ReportService
from security.validator import InputValidator

api_bp = Blueprint("api", __name__, url_prefix="/api")
scan_service = ScanService()
ai_service = AIService()
ocr_service = OcrService()
transcription_service = TranscriptionService()


@api_bp.route("/health", methods=["GET"])
def health_check():
    """Health status and engine availability information."""
    ocr_available = scan_service.screenshot_analyzer.is_ocr_available()
    ocr_engine = scan_service.screenshot_analyzer.get_engine_name()
    ocr_languages = getattr(scan_service.screenshot_analyzer, "get_available_languages", lambda: [])()
    return jsonify({
        "status": "healthy",
        "service": "SCAM BREAKER — Smart Scam & Link Detector Backend",
        "version": "2.0.0",
        "server_time": datetime.now().isoformat(),
        "capabilities": {
            "ai_intelligence_engine": "active" if ai_service.is_configured() else "ready_for_key",
            "ai_provider": "google-genai",
            "ai_model": ai_service.model,
            "content_analysis": "active",
            "url_structure_analysis": "active",
            "trusted_intelligence": "active",
            "local_ocr_engine": "active" if ocr_available else "unavailable",
            "ocr_engine_name": ocr_engine,
            "ocr_languages": ocr_languages,
            "speech_transcription_engine": "active" if transcription_service.is_engine_available() else "unavailable",
            "pdf_report_engine": "active" if ReportService.is_available() else "unavailable"
        },
        "privacy": {
            "zero_credential_logging": True,
            "sandboxed_url_analysis": True,
            "ephemeral_media_processing": True
        }
    }), 200


@api_bp.route("/scan", methods=["GET", "POST"])
def scan_text():
    """
    Unified text & URL scanning endpoint using AI safety intelligence.
    GET: Returns endpoint status and usage information.
    POST: Analyzes input for scams, threats, and phishing.
    JSON Body:
        { "input": "...", "type": "auto|message|url|message_with_url", "source_type": "text|url|screenshot|audio" }
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER Threat Scanner",
            "endpoint": "/api/scan",
            "status": "active",
            "accepted_method": "POST",
            "description": "Send a POST request with JSON payload containing 'input' to perform threat analysis."
        }), 200

    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON format."}), 400

    data = request.get_json(silent=True) or {}
    input_text = data.get("input")
    requested_type = data.get("type", "auto")
    source_type = data.get("source_type", "text")

    # Validate
    is_valid, err_msg, sanitized_text = InputValidator.validate_text(input_text)
    if not is_valid:
        return jsonify({"error": err_msg}), 400

    try:
        result = scan_service.process_text_scan(sanitized_text, requested_type=requested_type, source_type=source_type)
        return jsonify(result), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except RuntimeError as run_err:
        return jsonify({"error": str(run_err), "code": "AI_SERVICE_ERROR"}), 503
    except Exception as exc:
        return jsonify({"error": f"An unexpected error occurred during threat analysis: {str(exc)}"}), 500


@api_bp.route("/chat", methods=["GET", "POST"])
def chat_advisory():
    """
    Interactive AI Advisory Chat endpoint for scam and fraud inquiries.
    GET: Returns endpoint status and usage information.
    POST: Processes security advisory chat query.
    JSON Body:
        { "messages": [{"role": "user"|"assistant", "content": "..."}, ...] }
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER AI Advisory Chat",
            "endpoint": "/api/chat",
            "status": "active",
            "accepted_method": "POST",
            "description": "Send a POST request with JSON payload containing 'messages' array to converse with the security advisor."
        }), 200

    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON format."}), 400

    data = request.get_json(silent=True) or {}
    messages = data.get("messages", [])
    if not messages or not isinstance(messages, list):
        return jsonify({"error": "A list of chat messages is required."}), 400

    try:
        reply = ai_service.chat_advisory(messages)
        return jsonify(reply), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except RuntimeError as run_err:
        return jsonify({"error": str(run_err), "code": "AI_SERVICE_ERROR"}), 503
    except Exception as exc:
        return jsonify({"error": f"AI chat failed: {str(exc)}"}), 500


@api_bp.route("/scan/screenshot", methods=["GET", "POST"])
def scan_screenshot():
    """
    Screenshot upload and OCR analysis endpoint.
    GET: Returns endpoint status and usage information.
    POST: Processes screenshot file.
    Multipart Form Data with field 'screenshot' or 'file'.
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER Screenshot Scanner",
            "endpoint": "/api/scan/screenshot",
            "status": "active",
            "accepted_method": "POST"
        }), 200

    file_obj = request.files.get("screenshot") or request.files.get("file")
    if not file_obj or not file_obj.filename:
        return jsonify({"error": "No screenshot file provided in upload request."}), 400

    try:
        file_bytes = file_obj.read()
        if not file_bytes:
            return jsonify({"error": "Uploaded file is empty."}), 400

        result = scan_service.process_screenshot_scan(file_bytes, filename=file_obj.filename)
        return jsonify(result), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as exc:
        return jsonify({"error": f"An error occurred during screenshot processing: {str(exc)}"}), 500


@api_bp.route("/history", methods=["GET"])
def get_history():
    """Retrieves recent scan audit records from SQLite with optional filtering and search."""
    limit = request.args.get("limit", default=50, type=int)
    category = request.args.get("category", default=None, type=str)
    risk = request.args.get("risk", default=None, type=str)
    q = request.args.get("q", default=None, type=str)
    records = HistoryService.get_scan_history(
        limit=limit,
        category=category,
        risk=risk,
        search_query=q
    )
    return jsonify({"history": records, "count": len(records)}), 200


@api_bp.route("/history/<scan_id>", methods=["GET"])
def get_single_scan(scan_id):
    """Retrieves a single scan record including complete report JSON for re-opening."""
    record = HistoryService.get_scan_by_id(scan_id)
    if record:
        return jsonify({"success": True, "scan": record, "report": record}), 200
    return jsonify({"error": "Scan report not found.", "code": "REPORT_NOT_FOUND"}), 404


@api_bp.route("/history", methods=["DELETE"])
def delete_all_history():
    """Deletes all stored scan telemetry records."""
    res = HistoryService.purge_history()
    return jsonify(res), 200


@api_bp.route("/history/<scan_id>", methods=["DELETE"])
def delete_scan_entry(scan_id):
    """Deletes a single scan audit log entry permanently."""
    success = HistoryService.delete_scan_by_id(scan_id)
    if success:
        return jsonify({
            "status": "deleted",
            "success": True,
            "scan_id": scan_id,
            "message": f"Report {scan_id} was permanently deleted."
        }), 200
    return jsonify({"error": "Scan record not found.", "success": False}), 404


@api_bp.route("/community", methods=["GET"])
def get_community_feed():
    """
    Returns verified community fraud reports and demonstration incident patterns.
    """
    category = request.args.get("category", default=None, type=str)
    reports = HistoryService.get_community_feed(category=category)
    return jsonify({"reports": reports, "count": len(reports)}), 200


@api_bp.route("/community/<report_id>/upvote", methods=["POST"])
def upvote_community_report(report_id):
    """Increments community report confirmation."""
    res = HistoryService.upvote_community_report(report_id)
    if res.get("success"):
        return jsonify(res), 200
    return jsonify(res), 404


@api_bp.route("/community/report", methods=["GET", "POST"])
def submit_community_report():
    """
    Submits a new threat incident to the community database.
    GET: Returns endpoint status and usage information.
    POST: Stores community report.
    JSON Body:
        { "category": "...", "title": "...", "reported_item": "...", "description": "..." }
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER Community Reporting",
            "endpoint": "/api/community/report",
            "status": "active",
            "accepted_method": "POST"
        }), 200

    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON format."}), 400

    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    reported_item = str(data.get("reported_item", "")).strip()

    if not title or not reported_item:
        return jsonify({"error": "Report title and content cannot be empty."}), 400

    from security.privacy import PrivacyInterceptor
    clean_item = PrivacyInterceptor.sanitize_metadata_snippet(reported_item, max_length=120)
    clean_desc = PrivacyInterceptor.sanitize_metadata_snippet(str(data.get("description", "")).strip(), max_length=300)

    res = HistoryService.create_community_report({
        "category": str(data.get("category", "General Phishing")),
        "title": title[:100],
        "reported_item": clean_item,
        "description": clean_desc,
        "risk_level": "suspicious"
    })
    return jsonify(res), 201


@api_bp.route("/radar/trends", methods=["GET"])
def get_radar_trends():
    """
    Returns authentic category trend analytics based strictly on stored SQLite incidents.
    """
    from database.models import TelemetryRepository
    data = TelemetryRepository.get_radar_trends()
    return jsonify(data), 200


@api_bp.route("/community/patterns", methods=["GET"])
def get_community_patterns():
    """
    Returns structured community scam patterns grouped by fingerprint with statistical thresholding.
    """
    patterns_data = HistoryService.get_community_patterns()
    return jsonify(patterns_data), 200


@api_bp.route("/extract/ocr", methods=["GET", "POST"])
def extract_ocr():
    """
    Dedicated OCR text extraction endpoint.
    GET: Returns endpoint status.
    POST: Extracts text from uploaded screenshot.
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER Screenshot OCR Engine",
            "endpoint": "/api/extract/ocr",
            "status": "active",
            "accepted_method": "POST"
        }), 200

    file_obj = request.files.get("image") or request.files.get("screenshot") or request.files.get("file")
    if not file_obj or not file_obj.filename:
        return jsonify({"error": "No screenshot file provided in upload request."}), 400

    try:
        file_bytes = file_obj.read()
        res = ocr_service.extract_text(file_bytes, filename=file_obj.filename)
        return jsonify(res), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except Exception as exc:
        return jsonify({"error": f"Failed to extract text from image: {str(exc)}"}), 500


@api_bp.route("/transcribe", methods=["GET", "POST"])
def transcribe_audio():
    """
    Audio recording transcription endpoint.
    GET: Returns endpoint status.
    POST: Transcribes uploaded audio (MP3, WAV, M4A, AAC, OGG, CAF, FLAC) to text.
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER Audio Transcription Engine",
            "endpoint": "/api/transcribe",
            "status": "active",
            "accepted_method": "POST"
        }), 200

    file_obj = request.files.get("audio") or request.files.get("file")
    if not file_obj and request.files:
        file_obj = next(iter(request.files.values()), None)

    if not file_obj:
        return jsonify({
            "error": "No audio recording file provided in upload request. Please attach an audio file or blob under 'audio' or 'file'.",
            "code": "MISSING_AUDIO_FILE",
            "error_code": "MISSING_AUDIO_FILE"
        }), 400

    filename = file_obj.filename or "recording.webm"
    language = request.form.get("language", "ta-IN")
    try:
        file_bytes = file_obj.read()
        if not file_bytes:
            return jsonify({
                "error": "Uploaded audio recording is empty (0 bytes). Please record or select an audio file with audible content.",
                "code": "EMPTY_AUDIO_FILE",
                "error_code": "EMPTY_AUDIO_FILE"
            }), 400

        res = transcription_service.transcribe(file_bytes, filename=filename, language=language)
        return jsonify(res), 200
    except ValueError as val_err:
        return jsonify({"error": str(val_err)}), 400
    except RuntimeError as run_err:
        return jsonify({"error": str(run_err)}), 503
    except Exception as exc:
        return jsonify({"error": f"Audio transcription error: {str(exc)}"}), 500


@api_bp.route("/report/pdf", methods=["GET", "POST"])
@api_bp.route("/report/generate", methods=["GET", "POST"])
def download_pdf_report():
    """
    Generates and returns an authentic, downloadable PDF threat intelligence report.
    GET: Returns endpoint status.
    POST: Generates PDF from assessment JSON.
    """
    if request.method == "GET":
        return jsonify({
            "service": "SCAM BREAKER PDF Threat Report Engine",
            "endpoint": "/api/report/pdf",
            "status": "active",
            "accepted_method": "POST"
        }), 200

    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON format.", "code": "INVALID_JSON"}), 400

    data = request.get_json(silent=True) or {}
    try:
        # Check if scan_id or scanId or id was supplied
        sid = data.get("scan_id") or data.get("scanId") or data.get("id")
        has_direct_content = bool(
            data.get("explanation") or data.get("summary") or
            data.get("detected_indicators") or data.get("indicators") or
            data.get("submitted_item") or data.get("display_item") or
            data.get("target") or data.get("extracted_text") or data.get("ocr_text")
        )

        if sid:
            from services.history_service import HistoryService
            existing = HistoryService.get_scan_by_id(str(sid))
            if existing and isinstance(existing, dict):
                merged = dict(existing)
                if isinstance(existing.get("fullReport"), dict):
                    merged.update(existing["fullReport"])
                elif isinstance(existing.get("full_report_json"), dict):
                    merged.update(existing["full_report_json"])
                elif isinstance(existing.get("structured_data"), dict):
                    merged.update(existing["structured_data"])

                # Overlay user-provided data, preserving existing non-empty values
                for k, v in data.items():
                    if v is not None and v != "":
                        merged[k] = v
                data = merged
            elif not has_direct_content:
                return jsonify({
                    "error": f"Scan report '{sid}' not found in audit history.",
                    "code": "REPORT_NOT_FOUND"
                }), 404
        elif not has_direct_content and not data.get("risk_level") and not data.get("riskLevel"):
            return jsonify({
                "error": "No scan assessment data or valid scan ID provided.",
                "code": "MISSING_REPORT_DATA"
            }), 400

        # Normalize key aliases between frontend, SQLite models, and ReportLab generator
        if not data.get("scan_id") and sid:
            data["scan_id"] = sid

        if not data.get("risk_level"):
            data["risk_level"] = (
                data.get("riskLevel") or
                data.get("risk_category") or
                data.get("riskCategory") or
                data.get("risk") or
                data.get("classification") or
                "caution"
            )

        if not data.get("risk_score"):
            score = (
                data.get("riskScore") or
                data.get("threat_score") or
                data.get("threatScore")
            )
            if score is None and isinstance(data.get("scoring_breakdown"), dict):
                score = data["scoring_breakdown"].get("total_score")
            if score is not None:
                data["risk_score"] = score

        if not data.get("explanation"):
            data["explanation"] = (
                data.get("summary") or
                data.get("short_summary") or
                data.get("shortSummary") or
                data.get("ai_summary") or
                data.get("reasoning")
            )

        if not data.get("why_it_matters"):
            data["why_it_matters"] = (
                data.get("whyItMatters") or
                data.get("why_suspicious") or
                data.get("threat_breakdown") or
                data.get("reasoning")
            )

        if not data.get("submitted_item"):
            data["submitted_item"] = (
                data.get("displayItem") or
                data.get("display_item") or
                data.get("target") or
                data.get("input_snippet") or
                data.get("input")
            )

        if not data.get("detected_indicators"):
            data["detected_indicators"] = (
                data.get("indicators") or
                data.get("red_flags") or
                data.get("redFlags") or
                data.get("detailed_indicators") or
                []
            )

        if not data.get("recommended_actions"):
            data["recommended_actions"] = (
                data.get("recommended_steps") or
                data.get("recommendedSteps") or
                data.get("next_steps") or
                data.get("action_plan") or
                []
            )

        if not data.get("extracted_text"):
            extracted = data.get("ocr_text") or data.get("ocrText")
            if not extracted and isinstance(data.get("layers"), dict):
                screen_layer = data["layers"].get("screenshot")
                if isinstance(screen_layer, dict):
                    extracted = screen_layer.get("extracted_text")
            if extracted:
                data["extracted_text"] = extracted

        if not data.get("scam_category") and not data.get("category"):
            data["category"] = data.get("threat_category") or data.get("scam_type") or "General Threat"

        if not data.get("impersonated_entity"):
            data["impersonated_entity"] = data.get("impersonatedEntity") or "None / Unspecified"

        if not data.get("verification_advice"):
            data["verification_advice"] = data.get("verificationAdvice") or data.get("safety_guidance")

        if not data.get("important_uncertainties"):
            data["important_uncertainties"] = data.get("limitations")

        pdf_bytes = ReportService.generate_pdf_report(data)
        scan_id = data.get("scan_id") or sid or "scam_breaker_report"
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="SCAM_BREAKER_Report_{scan_id}.pdf"'
        return response
    except Exception as exc:
        return jsonify({"error": f"Failed to generate PDF report: {str(exc)}"}), 500
