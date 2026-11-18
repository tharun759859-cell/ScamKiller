# =============================================================================
# SCAM KILLER — Production Docker Container for Cloud Deployment (Render / Linux)
# Includes Python 3.11, Tesseract OCR (English + Tamil), FFmpeg & Gunicorn
# =============================================================================

FROM python:3.11-slim

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies:
# - tesseract-ocr, tesseract-ocr-eng, tesseract-ocr-tam for multi-language visual text extraction
# - ffmpeg for universal audio/voice note conversion
# - libgl1 and libglib2.0-0 for robust image processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-tam \
    ffmpeg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app

# Install Python requirements
COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set dynamic port support (Render injects $PORT, defaults to 5001)
ENV PORT=5001
EXPOSE 5001

# Launch production WSGI Gunicorn server (1 worker + 4 threads to fit within Render Free 512MB limit)
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5001} --workers 1 --threads 4 --timeout 120 backend.app:app"]
