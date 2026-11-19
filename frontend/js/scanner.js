// SCAM BREAKER — Client-Side Scanner & Threat API Integration Controller

class ScamBreakerScanner {
  constructor() {
    this.apiBase = this._resolveApiBase();
  }

  // Dynamically resolves backend API base URL
  _resolveApiBase() {
    try {
      // 1. Explicit configuration override
      if (typeof window !== "undefined" && (window.__SCAM_BREAKER_API_URL__ || window.__SCAM_KILLER_API_URL__)) {
        const customUrl = String(window.__SCAM_BREAKER_API_URL__ || window.__SCAM_KILLER_API_URL__).trim().replace(/\/+$/, "");
        return customUrl.endsWith("/api") ? customUrl : `${customUrl}/api`;
      }

      const loc = window.location;
      const hostname = (loc.hostname || "").toLowerCase();

      // 2. Production Vercel deployment -> Route to Render backend
      if (hostname === "scamkiller07.vercel.app" || hostname.endsWith(".vercel.app")) {
        return "https://scamkiller07.onrender.com/api";
      }

      // 3. Accessed directly from the Flask backend (port 5001 or 5000)
      if (loc.protocol.startsWith("http") && (loc.port === "5001" || loc.port === "5000")) {
        return "/api";
      }

      // 4. Local development (VS Code Live Server on port 5500, localhost, 127.0.0.1, or file://)
      if (hostname === "localhost" || hostname === "127.0.0.1" || loc.protocol === "file:") {
        const port = window.__SCAM_KILLER_PORT__ || "5001";
        return `http://127.0.0.1:${port}/api`;
      }

      // 5. Any other production HTTPS host fallback
      if (loc.protocol === "https:") {
        return "https://scamkiller07.onrender.com/api";
      }

      return "/api";
    } catch (_) {
      return "https://scamkiller07.onrender.com/api";
    }
  }

  // Fast client-side privacy guard to intercept sensitive credentials before submission
  checkSensitiveData(input) {
    const raw = String(input || "").trim();
    const lower = raw.toLowerCase();

    // Check payment card format (16 digits)
    const cardPattern = /\b(?:\d{4}[ -]?){3}\d{4}\b/;
    if (cardPattern.test(raw)) {
      return {
        warning: true,
        message: "SAFETY ALERT: You entered what resembles a payment card number. For your security, this analysis has halted. Never enter financial credentials into any tool."
      };
    }

    // Standalone OTP or phrases containing OTP with numeric code
    const isSingleOtp = /^\d{4,8}$/.test(raw);
    const mentionsOtpCode = /\b(otp|one[- ]time password|cvv|secret pin|password is)\b/i.test(lower) && /\b\d{4,8}\b/.test(raw);

    if (isSingleOtp || mentionsOtpCode) {
      return {
        warning: true,
        message: "SAFETY ALERT: You entered sensitive authentication data (e.g. an OTP or PIN). Never share One-Time Passwords or secret credentials with any scanner, caller, or website."
      };
    }

    return { warning: false };
  }

  // Helper for safe JSON response parsing
  async _parseResponse(response, defaultErrMsg = "Request failed") {
    const contentType = response.headers.get("content-type") || "";
    let data = {};
    if (contentType.includes("application/json")) {
      data = await response.json();
    } else {
      const text = await response.text();
      if (!response.ok) {
        if (response.status === 405) {
          throw new Error("HTTP 405 Method Not Allowed: If you opened this page via VS Code Live Server (port 5500), please ensure the Python Flask backend is running on http://127.0.0.1:5001 or open http://127.0.0.1:5001/ directly in your browser.");
        }
        throw new Error(`Server returned HTTP ${response.status}: ${text.slice(0, 120)}`);
      }
      return text;
    }

    if (!response.ok) {
      throw new Error(data.error || `${defaultErrMsg} (${response.status})`);
    }
    return data;
  }

  // Extracts text from uploaded screenshot via backend Apple Vision / Tesseract engine
  async extractTextFromImage(file, onProgress) {
    if (!file) {
      throw new Error("No image file provided.");
    }

    if (onProgress) onProgress(25, "Uploading image to secure OCR pipeline...");

    const formData = new FormData();
    formData.append("image", file);

    if (onProgress) onProgress(50, "Running text recognition engine...");

    const response = await fetch(`${this.apiBase}/extract/ocr`, {
      method: "POST",
      body: formData
    });

    if (onProgress) onProgress(90, "Finalizing extracted text...");

    const data = await this._parseResponse(response, "Failed to extract text from image");
    if (onProgress) onProgress(100, "Extraction complete.");
    return data;
  }

  // Transcribes uploaded voice recording via backend Speech-to-Text engine
  // Supports Tamil (ta-IN — default) and English (en-IN / en-US)
  async transcribeAudio(fileOrBlob, language = "ta-IN", onProgress) {
    if (!fileOrBlob) {
      throw new Error("No audio recording provided.");
    }

    if (onProgress) onProgress(20, "Uploading audio");

    let formData;
    if (typeof FormData !== "undefined" && fileOrBlob instanceof FormData) {
      formData = fileOrBlob;
      if (!formData.has("language")) {
        formData.append("language", language);
      }
    } else {
      formData = new FormData();
      let filename = (fileOrBlob && fileOrBlob.name) ? fileOrBlob.name : "";
      if (!filename) {
        const mime = (fileOrBlob && fileOrBlob.type) ? String(fileOrBlob.type).toLowerCase() : "";
        if (mime.includes("webm")) filename = "recording.webm";
        else if (mime.includes("mp4") || mime.includes("m4a")) filename = "recording.mp4";
        else if (mime.includes("ogg") || mime.includes("opus")) filename = "recording.ogg";
        else if (mime.includes("wav")) filename = "recording.wav";
        else if (mime.includes("aac")) filename = "recording.aac";
        else filename = "recording.webm";
      }
      formData.append("audio", fileOrBlob, filename);
      formData.append("language", language);
    }

    if (onProgress) onProgress(45, "Detecting audio format");

    // Send to backend (browser automatically attaches multipart boundary)
    const responsePromise = fetch(`${this.apiBase}/transcribe`, {
      method: "POST",
      body: formData
    });

    // Provide natural transition indicator
    const timer = setTimeout(() => {
      if (onProgress) onProgress(70, "Converting audio");
    }, 600);

    const timer2 = setTimeout(() => {
      if (onProgress) onProgress(85, "Transcribing speech");
    }, 1400);

    let response;
    try {
      response = await responsePromise;
    } finally {
      clearTimeout(timer);
      clearTimeout(timer2);
    }

    const data = await this._parseResponse(response, "Audio transcription failed");
    if (onProgress) onProgress(100, "Transcription completed");
    return data;
  }

  // Submits input text to backend DeepSeek AI analysis pipeline
  async analyzeText(input, requestedType = "auto", sourceType = "text") {
    const raw = String(input || "").trim();
    if (!raw) {
      throw new Error("Please enter a message, URL, or upload a screenshot/audio recording to analyze.");
    }

    // Client-side privacy safeguard check
    const privacyCheck = this.checkSensitiveData(raw);
    if (privacyCheck.warning) {
      return {
        scan_id: `alert-${Date.now()}`,
        scan_type: "privacy_alert",
        risk_level: "suspicious",
        classification: "Suspicious",
        risk_label: "Suspicious",
        badge_class: "badge-suspicious",
        badge_icon: "warning",
        submitted_item: raw.slice(0, 45) + "...",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        explanation: privacyCheck.message,
        summary: privacyCheck.message,
        detected_indicators: [
          { title: "Private authentication secret / OTP pattern detected", severity: "high", explanation: "Sensitive credential detected in submitted text." },
          { title: "Direct credential hazard — analysis halted", severity: "high", explanation: "Live credentials should never be submitted." }
        ],
        why_it_matters: "Entering real authentication codes into web forms or scanners poses an immediate account compromise risk.",
        recommended_actions: [
          "Never paste or transmit passwords, OTPs, or CVVs into any scanner or message.",
          "If you received this code via SMS, check why it was requested before taking any action.",
          "Change your passwords immediately if you suspect unauthorized account access."
        ],
        recommended_steps: [
          "Never paste or transmit passwords, OTPs, or CVVs into any scanner or message.",
          "If you received this code via SMS, check why it was requested before taking any action.",
          "Change your passwords immediately if you suspect unauthorized account access."
        ],
        engine_status: "Privacy Intercept Active"
      };
    }

    // Submit to /api/scan with source_type
    const response = await fetch(`${this.apiBase}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: raw, type: requestedType, source_type: sourceType })
    });

    const data = await this._parseResponse(response, "AI threat analysis failed");
    return data;
  }

  // Submits conversational query to AI Advisory Chat endpoint with 30s timeout
  async sendChatMessage(messages) {
    if (!messages || !messages.length) {
      throw new Error("No chat message provided.");
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch(`${this.apiBase}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages }),
        signal: controller.signal
      });

      const data = await this._parseResponse(response, "AI Advisory Chat failed");
      return data;
    } catch (err) {
      if (err.name === "AbortError") {
        throw new Error("The AI Advisory service took too long to respond (30s timeout). Please check your connection or retry in a moment.");
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Generates and triggers browser download of an authentic ReportLab PDF report
  async downloadPdfReport(reportData) {
    if (!reportData) {
      throw new Error("No assessment data available to generate report.");
    }

    const payload = typeof reportData === "string" ? { scan_id: reportData } : reportData;

    const response = await fetch(`${this.apiBase}/report/pdf`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Failed to generate PDF report (${response.status})`);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = `SCAM_BREAKER_Report_${payload.scan_id || payload.scanId || (typeof reportData === "string" ? reportData : "assessment")}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  }

  // Retrieves scan audit history with optional filters
  async getScanHistory(limit = 50, category = null, risk = null, q = null) {
    const params = new URLSearchParams();
    if (limit) params.set("limit", limit);
    if (category && category !== "all") params.set("category", category);
    if (risk && risk !== "all") params.set("risk", risk);
    if (q) params.set("q", q);

    const response = await fetch(`${this.apiBase}/history?${params.toString()}`);
    return await this._parseResponse(response, "Failed to load scan history");
  }

  // Retrieves single complete scan report by ID for re-opening
  async getScanById(scanId) {
    if (!scanId) throw new Error("No scan ID provided.");
    const response = await fetch(`${this.apiBase}/history/${encodeURIComponent(scanId)}`);
    return await this._parseResponse(response, "Failed to retrieve scan report");
  }

  // Permanently deletes a single scan by ID
  async deleteScan(scanId) {
    if (!scanId) throw new Error("No scan ID provided.");
    const response = await fetch(`${this.apiBase}/history/${encodeURIComponent(scanId)}`, {
      method: "DELETE"
    });
    return await this._parseResponse(response, "Failed to delete scan record");
  }

  // Purges all scan history
  async purgeHistory() {
    const response = await fetch(`${this.apiBase}/history`, { method: "DELETE" });
    return await this._parseResponse(response, "Failed to clear scan history");
  }

  // Retrieves structured community threat patterns grouped by fingerprint
  async getCommunityPatterns() {
    const response = await fetch(`${this.apiBase}/community/patterns`);
    return await this._parseResponse(response, "Failed to load community patterns");
  }
}

// Instantiate global scanner instance
window.scamBreakerScanner = new ScamBreakerScanner();
window.scamKillerScanner = window.scamBreakerScanner;

// Global API base helper
window.getScamBreakerApiBase = function() {
  return window.scamBreakerScanner ? window.scamBreakerScanner.apiBase : "/api";
};
window.getScamKillerApiBase = window.getScamBreakerApiBase;
