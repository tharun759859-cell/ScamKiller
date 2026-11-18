"""
SCAM KILLER — Backend Application Module
Serves the REST API, OCR, Audio Transcription, PDF Report Generation, and Frontend assets.
"""

import os
from flask import Flask, send_from_directory, jsonify, request, make_response

from database.db import init_db
from database.models import TelemetryRepository
from routes.api import api_bp

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")


def create_app() -> Flask:
    """Application factory for SCAM KILLER."""
    # Use frontend directory as static folder if available
    static_dir = FRONTEND_DIR if os.path.exists(FRONTEND_DIR) else PROJECT_ROOT
    app = Flask(__name__, static_folder=static_dir, static_url_path="")

    # Load .env file from project root
    env_file = os.path.join(PROJECT_ROOT, ".env")
    if os.path.exists(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=True)
        except Exception:
            pass

    # Request payload limit (32MB for media uploads)
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

    # Initialize SQLite database & seed initial telemetry records
    init_db()
    TelemetryRepository.seed_initial_data_if_empty()

    # Register API Blueprint
    app.register_blueprint(api_bp)

    # Handle preflight OPTIONS requests
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            from flask import make_response
            response = make_response()
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            return response, 200

    # Global CORS Header Support
    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        return response

    # Frontend Route: Serve index.html
    @app.route("/", methods=["GET"])
    def serve_frontend():
        target_dir = FRONTEND_DIR if os.path.exists(os.path.join(FRONTEND_DIR, "index.html")) else PROJECT_ROOT
        return send_from_directory(target_dir, "index.html")

    # Static Assets Handler (CSS, JS, Assets)
    @app.route("/<path:path>", methods=["GET"])
    def serve_static(path):
        # Check frontend/ first, then PROJECT_ROOT
        for base in [FRONTEND_DIR, PROJECT_ROOT]:
            full_path = os.path.join(base, path)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                return send_from_directory(base, path)
        return jsonify({"error": "Resource not found."}), 404

    # Generic JSON Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request: " + str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "error": "HTTP 405 Method Not Allowed: The requested method is not supported for this endpoint.",
            "code": "METHOD_NOT_ALLOWED"
        }), 405

    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify({"error": "Payload exceeds maximum allowed limit of 32MB. Please upload a smaller file."}), 413

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[*] SCAM KILLER Backend running on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
