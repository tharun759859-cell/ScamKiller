"""
SCAM KILLER — Flask Application Entry Point
Modular, secure backend for Smart Scam & Link Detector.
Serves both the REST API and the frontend dashboard.
"""

import os
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path, override=True)
else:
    load_dotenv()

from backend.app import create_app, app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[*] SCAM KILLER Backend running on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
