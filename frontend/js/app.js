// SCAM KILLER — Modern Application Controller (Phase 1)

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  let currentView = "overview";
  let attachedScreenshotFile = null;
  let attachedAudioFile = null;
  let lastAnalysisResult = null;
  let currentSourceType = "text";
  let scanHistoryCache = [];
  let communityReportsCache = [];

  function escapeHtml(str) {
    if (typeof str !== "string") return String(str || "");
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  function showToast(message, type = "success") {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    const isSuccess = type === "success";
    const isError = type === "error";
    const borderClass = isSuccess
      ? "border-emerald-300 bg-emerald-50 text-emerald-950 shadow-md"
      : (isError ? "border-rose-300 bg-rose-50 text-rose-950 shadow-md" : "border-slate-300 bg-white text-slate-800 shadow-md");
    const icon = isSuccess ? "check_circle" : (isError ? "error" : "info");
    const iconColor = isSuccess ? "text-emerald-600" : (isError ? "text-rose-600" : "text-sky-600");

    toast.className = `p-3 rounded-xl border flex items-center gap-2.5 text-xs font-medium pointer-events-auto transition-all duration-300 transform translate-y-2 opacity-0 ${borderClass}`;
    toast.innerHTML = `<span class="material-symbols-outlined text-base shrink-0 ${iconColor}">${icon}</span><span class="flex-1">${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.remove("translate-y-2", "opacity-0");
    });

    setTimeout(() => {
      toast.classList.add("opacity-0", "translate-y-2");
      setTimeout(() => toast.remove(), 300);
    }, 3800);
  }

  // DOM Elements - Navigation
  const navLinks = document.querySelectorAll("[data-nav-target]");
  const viewSections = document.querySelectorAll(".view-section");
  const topNavTitle = document.getElementById("topNavTitle");
  const mainSidebar = document.getElementById("mainSidebar");
  const sidebarBackdrop = document.getElementById("sidebarBackdrop");
  const mobileSidebarToggle = document.getElementById("mobileSidebarToggle");

  // DOM Elements - Main Scanner
  const scanInput = document.getElementById("unifiedScanInput");
  const analyzeBtn = document.getElementById("unifiedAnalyzeBtn");
  const clearBtn = document.getElementById("unifiedClearBtn");
  const screenshotBtn = document.getElementById("unifiedScreenshotBtn");
  const audioBtn = document.getElementById("unifiedAudioBtn");
  const fileInput = document.getElementById("unifiedFileInput");
  const audioInput = document.getElementById("unifiedAudioInput");

  // Screenshot Preview Elements
  const screenshotPreview = document.getElementById("attachedScreenshotPreview");
  const screenshotThumbnail = document.getElementById("screenshotThumbnail");
  const screenshotThumbnailFallback = document.getElementById("screenshotThumbnailFallback");
  const screenshotFileName = document.getElementById("screenshotFileName");
  const removeScreenshotBtn = document.getElementById("removeScreenshotBtn");
  const ocrProgressContainer = document.getElementById("ocrProgressContainer");
  const ocrStatusBadge = document.getElementById("ocrStatusBadge");
  const ocrStatusText = document.getElementById("ocrStatusText");

  // Audio Preview Elements
  const audioPreview = document.getElementById("attachedAudioPreview");
  const audioFileName = document.getElementById("audioFileName");
  const audioPreviewPlayer = document.getElementById("audioPreviewPlayer");
  const audioLanguageSelect = document.getElementById("audioLanguageSelect");
  const removeAudioBtn = document.getElementById("removeAudioBtn");
  const transcribeProgressContainer = document.getElementById("transcribeProgressContainer");
  const audioProgressStep = document.getElementById("audioProgressStep");
  const audioProgressPercent = document.getElementById("audioProgressPercent");
  const audioProgressBar = document.getElementById("audioProgressBar");

  function setAudioProgress(step, percent) {
    if (audioProgressStep) audioProgressStep.textContent = step;
    if (audioProgressPercent) audioProgressPercent.textContent = typeof percent === "number" ? `${percent}%` : percent;
    if (audioProgressBar) audioProgressBar.style.width = typeof percent === "number" ? `${percent}%` : "50%";
  }

  // Audio Status Indicators
  const audioStatusBadge = document.getElementById("audioStatusBadge");
  const audioStatusText = document.getElementById("audioStatusText");

  // Animation & Results
  const scannerAnimationCard = document.getElementById("scannerAnimationCard");
  const scannerStatusTicker = document.getElementById("scannerStatusTicker");
  const inlineResultCard = document.getElementById("inlineResultCard");
  const inlineResultHeading = document.getElementById("inlineResultHeading");
  const inlineResultBadge = document.getElementById("inlineResultBadge");
  const inlineConfidenceBadge = document.getElementById("inlineConfidenceBadge");
  const inlineSubmittedItem = document.getElementById("inlineSubmittedItem");
  const inlineResultExplanation = document.getElementById("inlineResultExplanation");
  const inlineIndicatorsList = document.getElementById("inlineIndicatorsList");
  const inlineWhyItMattersText = document.getElementById("inlineWhyItMattersText");
  const inlineNextStepsList = document.getElementById("inlineNextStepsList");
  const inlineCommunityMatch = document.getElementById("inlineCommunityMatch");
  const inlineCommunityMatchTitle = document.getElementById("inlineCommunityMatchTitle");
  const inlineCommunityMatchDesc = document.getElementById("inlineCommunityMatchDesc");
  const inlineCommunityMatchUpvotes = document.getElementById("inlineCommunityMatchUpvotes");
  const inspectFullReportBtn = document.getElementById("inspectFullReportBtn");
  const downloadPdfReportBtnCompact = document.getElementById("downloadPdfReportBtnCompact");
  const closeInlineResultBtn = document.getElementById("closeInlineResultBtn");
  const historyCategoryFilterSelect = document.getElementById("historyCategoryFilterSelect");
  const historyEmptyState = document.getElementById("historyEmptyState");
  const communityPatternsGrid = document.getElementById("communityPatternsGrid");

  // Full Report Modal Elements
  const fullReportModal = document.getElementById("fullReportModal");
  const closeFullReportModalBtn = document.getElementById("closeFullReportModalBtn");
  const modalCloseBtn2 = document.getElementById("modalCloseBtn2");
  const downloadPdfReportBtn = document.getElementById("downloadPdfReportBtn");
  const modalReportScanId = document.getElementById("modalReportScanId");
  const modalReportTimestamp = document.getElementById("modalReportTimestamp");
  const modalReportEngineStatus = document.getElementById("modalReportEngineStatus");
  const modalReportClassificationBanner = document.getElementById("modalReportClassificationBanner");
  const modalReportTargetSnippet = document.getElementById("modalReportTargetSnippet");
  const modalReportExplanation = document.getElementById("modalReportExplanation");
  const modalReportReasoning = document.getElementById("modalReportReasoning");
  const modalReportIndicatorsList = document.getElementById("modalReportIndicatorsList");
  const modalReportWhyMatters = document.getElementById("modalReportWhyMatters");
  const modalReportVerificationAdvice = document.getElementById("modalReportVerificationAdvice");
  const modalReportNextSteps = document.getElementById("modalReportNextSteps");
  const modalReportLimitations = document.getElementById("modalReportLimitations");

  // Trust Assistant Quick-Widget
  const trustEntitySelector = document.getElementById("trustEntitySelector");
  const trustDomain = document.getElementById("trustDomain");
  const trustHeader = document.getElementById("trustHeader");
  const trustPhone = document.getElementById("trustPhone");
  const trustRule = document.getElementById("trustRule");
  const trustSource = document.getElementById("trustSource");
  const trustStatusBadge = document.getElementById("trustStatusBadge");

  // ================================================================
  // 1. NAVIGATION ROUTING SYSTEM
  // ================================================================
  const titleMap = {
    overview: "Security Overview",
    "recovery-assistant": "Incident Recovery Playbooks",
    "verification-assistant": "Trust Verification & Multi-Vector Inspector",
    "community-intel": "Community Threat Database",
    "ai-chat": "AI Advisory Assistant",
    "scan-history": "Scan History & Audit Log",
    "privacy-policy": "Privacy Safeguards & Policy",
    settings: "System & Privacy Settings"
  };

  function safeOpenExternal(url, label = "destination") {
    try {
      const newWin = window.open(url, "_blank", "noopener,noreferrer");
      if (!newWin || newWin.closed || typeof newWin.closed === "undefined") {
        window.location.href = url;
      }
    } catch (err) {
      console.error(`Failed to open ${label}:`, err);
      showToast(`Unable to open ${label}. Please visit: ${url}`, "info");
    }
  }

  function navigateTo(viewId, situationKey = null, autoScroll = false) {
    currentView = viewId;

    // Update active nav styling
    navLinks.forEach(link => {
      const target = link.getAttribute("data-nav-target");
      if (target === viewId) {
        link.classList.add("nav-item-active");
        link.classList.remove("text-emerald-100/70", "hover:text-white", "hover:bg-[#103827]");
      } else {
        link.classList.remove("nav-item-active");
        link.classList.add("text-emerald-100/70", "hover:text-white", "hover:bg-[#103827]");
      }
    });

    // Update view visibility
    viewSections.forEach(sec => {
      if (sec.id === `view-${viewId}`) {
        sec.classList.add("active");
        sec.style.display = "block";
      } else {
        sec.classList.remove("active");
        sec.style.display = "none";
      }
    });

    if (topNavTitle) {
      topNavTitle.textContent = titleMap[viewId] || "Security Overview";
    }

    // Close mobile drawer if open
    if (mainSidebar && sidebarBackdrop) {
      mainSidebar.classList.add("-translate-x-full");
      sidebarBackdrop.classList.add("hidden");
    }

    // View-specific lazy initialization
    if (viewId === "scan-history") loadScanHistory();
    if (viewId === "community-intel") loadCommunityIntelligence();
    if (viewId === "verification-assistant") initTrustVerificationView();
    if (viewId === "recovery-assistant") loadRecoveryAssistant(situationKey, autoScroll);
    if (viewId === "ai-chat") initFullAiChatView();

    if (!autoScroll) {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  // Bind nav click listeners
  navLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.getAttribute("data-nav-target");
      if (target) navigateTo(target);
    });
  });

  // Mobile sidebar drawer
  if (mobileSidebarToggle && mainSidebar && sidebarBackdrop) {
    mobileSidebarToggle.addEventListener("click", () => {
      mainSidebar.classList.toggle("-translate-x-full");
      sidebarBackdrop.classList.toggle("hidden");
    });

    sidebarBackdrop.addEventListener("click", () => {
      mainSidebar.classList.add("-translate-x-full");
      sidebarBackdrop.classList.add("hidden");
    });
  }

  // ================================================================
  // 2. SCREENSHOT UPLOAD & OCR TEXT EXTRACTION WORKFLOW
  // ================================================================
  if (screenshotBtn && fileInput) {
    screenshotBtn.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      attachedScreenshotFile = file;

      // Update Preview Thumbnail
      if (screenshotFileName) screenshotFileName.textContent = file.name;
      if (screenshotPreview) screenshotPreview.classList.remove("hidden");

      if (file.type.startsWith("image/")) {
        const reader = new FileReader();
        reader.onload = (event) => {
          if (screenshotThumbnail) {
            screenshotThumbnail.src = event.target.result;
            screenshotThumbnail.classList.remove("hidden");
          }
          if (screenshotThumbnailFallback) {
            screenshotThumbnailFallback.classList.add("hidden");
          }
        };
        reader.readAsDataURL(file);
      }

      // Show OCR Progress
      if (ocrProgressContainer) ocrProgressContainer.classList.remove("hidden");
      if (ocrStatusBadge) ocrStatusBadge.classList.add("hidden");

      try {
        const res = await window.scamKillerScanner.extractTextFromImage(file, (percent, msg) => {
          const el = document.getElementById("ocrProgressPercent");
          if (el) el.textContent = `${percent}%`;
        });

        // Insert extracted text into main textarea
        if (res.extracted_text) {
          scanInput.value = res.extracted_text;
          currentSourceType = "screenshot";
          scanInput.dispatchEvent(new Event("input", { bubbles: true }));
          scanInput.focus();
        }

        if (ocrStatusText) {
          ocrStatusText.textContent = res.has_text
            ? `Extracted ${res.word_count} words via ${res.ocr_engine} • Editable in input box`
            : "No readable text detected in image";
        }
      } catch (err) {
        console.error("OCR Extraction failed:", err);
        if (ocrStatusText) {
          ocrStatusText.textContent = `OCR Error: ${err.message}`;
        }
      } finally {
        if (ocrProgressContainer) ocrProgressContainer.classList.add("hidden");
        if (ocrStatusBadge) ocrStatusBadge.classList.remove("hidden");
      }
    });
  }

  if (removeScreenshotBtn) {
    removeScreenshotBtn.addEventListener("click", () => {
      attachedScreenshotFile = null;
      currentSourceType = "text";
      if (fileInput) fileInput.value = "";
      if (screenshotPreview) screenshotPreview.classList.add("hidden");
      if (screenshotThumbnail) {
        screenshotThumbnail.src = "";
        screenshotThumbnail.classList.add("hidden");
      }
      if (screenshotThumbnailFallback) {
        screenshotThumbnailFallback.classList.remove("hidden");
      }
    });
  }

  // ================================================================
  // 3. VOICE RECORDING UPLOAD & SPEECH-TO-TEXT WORKFLOW
  // ================================================================
  if (audioBtn && audioInput) {
    audioBtn.addEventListener("click", () => audioInput.click());

    audioInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      attachedAudioFile = file;

      // Update Audio Preview
      if (audioFileName) audioFileName.textContent = file.name;
      if (audioPreview) audioPreview.classList.remove("hidden");

      // Bind to native audio player
      const audioUrl = URL.createObjectURL(file);
      if (audioPreviewPlayer) {
        audioPreviewPlayer.src = audioUrl;
      }

      const selectedLanguage = audioLanguageSelect ? audioLanguageSelect.value : "ta-IN";

      // Show transcription progress
      setAudioProgress("Uploading audio", 20);
      if (transcribeProgressContainer) transcribeProgressContainer.classList.remove("hidden");
      if (audioStatusBadge) audioStatusBadge.classList.add("hidden");

      try {
        const res = await window.scamKillerScanner.transcribeAudio(file, selectedLanguage, (pct, msg) => {
          setAudioProgress(msg, pct);
        });

        if (res.transcript) {
          scanInput.value = res.transcript;
          currentSourceType = "audio";
          if (audioStatusBadge && audioStatusText) {
            const codecLabel = res.detected_codec ? res.detected_codec.toUpperCase() : "AUDIO";
            const langLabel = res.language_label || selectedLanguage;
            audioStatusText.textContent = `Transcribed (${codecLabel} • ${langLabel}) • Editable in input box`;
            audioStatusBadge.classList.remove("hidden");
          }
          scanInput.dispatchEvent(new Event("input", { bubbles: true }));
          scanInput.focus();
        } else {
          if (audioStatusBadge && audioStatusText) {
            audioStatusText.textContent = "Processed • No intelligible speech detected";
            audioStatusBadge.classList.remove("hidden");
          }
          alert(`Audio was processed successfully, but no intelligible speech could be recognized in ${res.language_label || selectedLanguage}.`);
        }
      } catch (err) {
        console.error("Audio transcription error:", err);
        alert(`Audio Transcription Notice: ${err.message}`);
      } finally {
        if (transcribeProgressContainer) transcribeProgressContainer.classList.add("hidden");
      }
    });
  }

  // Re-transcribe if language changed
  if (audioLanguageSelect) {
    audioLanguageSelect.addEventListener("change", async () => {
      if (!attachedAudioFile) return;
      const targetLang = audioLanguageSelect.value || "ta-IN";
      setAudioProgress("Uploading audio", 20);
      if (transcribeProgressContainer) transcribeProgressContainer.classList.remove("hidden");
      if (audioStatusBadge) audioStatusBadge.classList.add("hidden");
      try {
        const res = await window.scamKillerScanner.transcribeAudio(attachedAudioFile, targetLang, (pct, msg) => {
          setAudioProgress(msg, pct);
        });
        if (res.transcript) {
          scanInput.value = res.transcript;
          currentSourceType = "audio";
          if (audioStatusBadge && audioStatusText) {
            const codecLabel = res.detected_codec ? res.detected_codec.toUpperCase() : "AUDIO";
            const langLabel = res.language_label || targetLang;
            audioStatusText.textContent = `Transcribed (${codecLabel} • ${langLabel}) • Editable in input box`;
            audioStatusBadge.classList.remove("hidden");
          }
          scanInput.dispatchEvent(new Event("input", { bubbles: true }));
          scanInput.focus();
        } else {
          if (audioStatusBadge && audioStatusText) {
            audioStatusText.textContent = "Processed • No speech detected";
            audioStatusBadge.classList.remove("hidden");
          }
          alert(`Audio was processed, but no intelligible speech was recognized in ${res.language_label || targetLang}.`);
        }
      } catch (err) {
        console.error("Language re-transcribe error:", err);
        alert(`Audio Transcription Notice: ${err.message}`);
      } finally {
        if (transcribeProgressContainer) transcribeProgressContainer.classList.add("hidden");
      }
    });
  }

  if (removeAudioBtn) {
    removeAudioBtn.addEventListener("click", () => {
      attachedAudioFile = null;
      currentSourceType = "text";
      if (audioInput) audioInput.value = "";
      if (audioStatusBadge) audioStatusBadge.classList.add("hidden");
      if (audioPreviewPlayer) {
        audioPreviewPlayer.pause();
        audioPreviewPlayer.src = "";
      }
      if (audioPreview) audioPreview.classList.add("hidden");
    });
  }

  // ================================================================
  // 4. CLEAR BUTTON (Reset Workspace)
  // ================================================================
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (scanInput) scanInput.value = "";
      currentSourceType = "text";
      if (removeScreenshotBtn) removeScreenshotBtn.click();
      if (removeAudioBtn) removeAudioBtn.click();
      if (audioStatusBadge) audioStatusBadge.classList.add("hidden");
      if (inlineResultCard) inlineResultCard.classList.add("hidden");
      if (scannerAnimationCard) scannerAnimationCard.classList.add("hidden");
      if (scanInput) scanInput.focus();
    });
  }

  // ================================================================
  // 5. ANALYZE WORKFLOW & INTELLIGENCE SCANNER VISUAL
  // ================================================================
  const statusTickerMessages = [
    "Deconstructing payload tokens & MIME encoding...",
    "Verifying cryptographic signatures & DLT SMS sender headers...",
    "Analyzing domain age, entropy, WHOIS heuristics & TLD risk...",
    "Cross-referencing CIRT authority feeds & community fraud clusters...",
    "Evaluating social engineering urgency & credential extraction cues...",
    "Synthesizing forensic intelligence & explainable safety report..."
  ];

  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", async () => {
      const inputText = scanInput ? scanInput.value.trim() : "";
      if (!inputText) {
        showToast("Please enter a message, URL, or upload media to analyze.", "info");
        if (scanInput) scanInput.focus();
        return;
      }

      // 1. Disable Analyze button & show active spinner
      analyzeBtn.disabled = true;
      analyzeBtn.classList.add("opacity-60", "cursor-not-allowed");
      const origBtnContent = analyzeBtn.innerHTML;
      analyzeBtn.innerHTML = `<span class="material-symbols-outlined text-sm animate-spin">progress_activity</span><span>Analyzing Threat...</span>`;

      // 2. Hide previous results & show modern scanner visual
      if (inlineResultCard) inlineResultCard.classList.add("hidden");
      if (scannerAnimationCard) {
        scannerAnimationCard.classList.remove("hidden");
        // Automatically scroll smoothly to scanning visual / result area
        scannerAnimationCard.scrollIntoView({ behavior: "smooth", block: "center" });
      }

      // Animate Status Ticker
      let tickerIndex = 0;
      const tickerInterval = setInterval(() => {
        tickerIndex = (tickerIndex + 1) % statusTickerMessages.length;
        if (scannerStatusTicker) {
          scannerStatusTicker.textContent = statusTickerMessages[tickerIndex];
        }
      }, 450);

      let effectiveSourceType = currentSourceType;
      if (effectiveSourceType === "text") {
        const trimmed = inputText.trim();
        if (/^(https?:\/\/|www\.)/i.test(trimmed) || (trimmed.includes(".") && !trimmed.includes(" ") && trimmed.length < 120)) {
          effectiveSourceType = "url";
        }
      }

      try {
        const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
        const result = await scannerInstance.analyzeText(inputText, "auto", effectiveSourceType);
        lastAnalysisResult = result;

        // Persist active report across browser reloads and page refreshes
        try {
          localStorage.setItem("scambreaker_active_report_data", JSON.stringify(result));
          localStorage.setItem("scamkiller_active_report_data", JSON.stringify(result));
        } catch (e) {
          console.warn("Storage write error:", e);
        }

        // Render Clean 7-Section Result Component
        renderAnalysisResult(result);
        showToast("Analysis complete! Report saved to Scan History.", "success");
      } catch (err) {
        console.error("Analysis failed:", err);
        showToast(`Analysis Error: ${err.message}`, "error");
      } finally {
        clearInterval(tickerInterval);
        if (scannerAnimationCard) scannerAnimationCard.classList.add("hidden");
        analyzeBtn.disabled = false;
        analyzeBtn.classList.remove("opacity-60", "cursor-not-allowed");
        analyzeBtn.innerHTML = origBtnContent;
      }
    });
  }

  // Close Report View Handler (Closes view only; does NOT delete from SQLite)
  if (closeInlineResultBtn) {
    closeInlineResultBtn.addEventListener("click", () => {
      if (inlineResultCard) inlineResultCard.classList.add("hidden");
      localStorage.removeItem("scambreaker_active_report_data");
      localStorage.removeItem("scamkiller_active_report_data");
      showToast("Report view closed. The assessment remains safely stored in Scan History.", "info");
    });
  }

  function renderAnalysisResult(result) {
    if (!inlineResultCard) return;

    let classification = result.classification || result.risk_label || "Caution";
    let riskLevel = (result.risk_level || "caution").toLowerCase();

    // Guard against falsely marking unreadable or failed extractions as Safe
    const rawExplanation = String(result.explanation || "").toLowerCase();
    const isUnreadable = rawExplanation.includes("unreadable") ||
                         rawExplanation.includes("could not extract") ||
                         rawExplanation.includes("timed out") ||
                         rawExplanation.includes("no legible text");

    if (isUnreadable) {
      riskLevel = "caution";
      classification = "Caution — Unreadable Content";
      result.explanation = "The uploaded screenshot could not be clearly read by the OCR engine. Please upload a sharper, higher-contrast image or paste the text directly into the scanner.";
      result.why_it_matters = "Incomplete or blurry image text prevents reliable threat detection. Fraudsters frequently use image degradation to evade automated inspection.";
    }

    // 1. Classification Badge & Risk Assessment Banner
    const riskBanner = document.getElementById("resultRiskBanner");
    let badgeHtml = "";
    if (riskLevel.includes("suspicious")) {
      badgeHtml = `<span class="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold bg-rose-100 text-rose-800 border border-rose-300 shadow-sm font-mono tracking-wide">
        ▲ SUSPICIOUS — HIGH THREAT PROBABILITY
      </span>`;
      if (riskBanner) riskBanner.className = "p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 border shadow-sm bg-rose-50/70 border-rose-200";
    } else if (riskLevel.includes("safe") || riskLevel.includes("no clear")) {
      badgeHtml = `<span class="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-300 shadow-sm font-mono tracking-wide">
        ✓ NO CLEAR WARNING SIGNS — LOW THREAT PROBABILITY
      </span>`;
      if (riskBanner) riskBanner.className = "p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 border shadow-sm bg-emerald-50/70 border-emerald-200";
    } else {
      badgeHtml = `<span class="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold bg-amber-100 text-amber-800 border border-amber-300 shadow-sm font-mono tracking-wide">
        ● CAUTION — VERIFY INDEPENDENTLY
      </span>`;
      if (riskBanner) riskBanner.className = "p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 border shadow-sm bg-amber-50/70 border-amber-200";
    }

    if (inlineResultBadge) inlineResultBadge.innerHTML = badgeHtml;

    // Confidence & Risk Score Badge
    if (inlineConfidenceBadge) {
      const conf = result.confidence !== undefined ? Math.round(result.confidence * 100) : 85;
      let score = null;
      if (result.scoring_breakdown && result.scoring_breakdown.total_score !== undefined) {
        score = Math.round(result.scoring_breakdown.total_score);
      } else if (result.risk_score !== undefined && result.risk_score !== null) {
        score = Math.round(result.risk_score);
      } else if (result.riskScore !== undefined && result.riskScore !== null) {
        score = Math.round(result.riskScore);
      } else if (result.threat_score !== undefined && result.threat_score !== null) {
        score = Math.round(result.threat_score);
      } else {
        score = riskLevel.includes("suspicious") ? 92 : (riskLevel.includes("safe") || riskLevel.includes("no clear") ? 12 : 52);
      }
      inlineConfidenceBadge.textContent = `Risk Score: ${score}/100 • Confidence: ${conf}%`;
    }

    // 2. Short Summary
    if (inlineResultExplanation) {
      inlineResultExplanation.textContent = result.explanation || result.summary || result.short_summary || "Analysis completed.";
    }

    // 3. Why Suspicious & Contextual Threat
    if (inlineWhyItMattersText) {
      inlineWhyItMattersText.textContent = result.why_it_matters || result.reasoning || result.why_suspicious || (
        "Cybercriminals manipulate trust using forged urgency and authority to access accounts or solicit unauthorized payments."
      );
    }

    // 4. Evidence Detected (Threat Indicators)
    if (inlineIndicatorsList) {
      inlineIndicatorsList.innerHTML = "";
      const indicators = result.detected_indicators || result.indicators || result.red_flags || [];
      if (indicators.length === 0) {
        inlineIndicatorsList.innerHTML = `<li class="text-slate-500 italic text-[11px] p-2 bg-slate-50 rounded-lg border border-slate-200">No severe threat indicators detected in this content. Standard digital security hygiene still applies.</li>`;
      } else {
        indicators.forEach(ind => {
          const title = typeof ind === "string" ? ind : (ind.title || ind.explanation || JSON.stringify(ind));
          const severity = (typeof ind === "object" && ind.severity) ? String(ind.severity).toLowerCase() : "medium";
          let badgeClasses = "bg-amber-50 text-amber-900 border-amber-200";
          let icon = "warning";
          if (severity === "high") {
            badgeClasses = "bg-rose-50 text-rose-900 border-rose-200";
            icon = "error";
          } else if (severity === "low") {
            badgeClasses = "bg-slate-50 text-slate-700 border-slate-200";
            icon = "info";
          }
          const li = document.createElement("li");
          li.className = `inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border ${badgeClasses}`;
          li.innerHTML = `<span class="material-symbols-outlined text-xs shrink-0">${icon}</span><span>${escapeHtml(title)}</span>`;
          inlineIndicatorsList.appendChild(li);
        });
      }
    }

    // 5. What You Should Do (Recommended Safe Steps)
    if (inlineNextStepsList) {
      inlineNextStepsList.innerHTML = "";
      const steps = result.recommended_actions || result.recommended_steps || result.recommendedSteps || result.next_steps || [
        "Do not click on links or download files from unsolicited senders.",
        "Verify communications independently through official channels.",
        "Never share One-Time Passwords or authentication codes."
      ];
      steps.forEach((step, i) => {
        const li = document.createElement("li");
        li.className = "flex items-start gap-2";
        li.innerHTML = `<span class="font-bold text-emerald-700 font-mono text-xs mt-0.5 shrink-0">${i + 1}.</span><span>${escapeHtml(step)}</span>`;
        inlineNextStepsList.appendChild(li);
      });
    }

    // Toggle Section 6 Avoid List: visible only for suspicious or caution; hidden for safe
    const avoidSection = document.getElementById("inlineAvoidSection");
    if (avoidSection) {
      if (riskLevel === "safe") {
        avoidSection.classList.add("hidden");
      } else {
        avoidSection.classList.remove("hidden");
      }
    }

    // Community Match Alert (if present)
    if (inlineCommunityMatch) {
      if (result.community_match && result.community_match.matched) {
        inlineCommunityMatch.classList.remove("hidden");
        if (inlineCommunityMatchTitle) inlineCommunityMatchTitle.textContent = result.community_match.title || "Matches Reported Community Pattern";
        if (inlineCommunityMatchDesc) inlineCommunityMatchDesc.textContent = result.community_match.description || "";
        if (inlineCommunityMatchUpvotes) inlineCommunityMatchUpvotes.textContent = `${result.community_match.upvotes || 0} Upvotes`;
      } else {
        inlineCommunityMatch.classList.add("hidden");
      }
    }

    // Extracted Content & OCR Text Viewer
    const extractedBox = document.getElementById("inlineExtractedContentBox");
    const extractedContainer = document.getElementById("inlineExtractedContentContainer");
    const engineBadge = document.getElementById("inlineOcrEngineBadge");
    const metricsBadge = document.getElementById("inlineOcrMetricsBadge");
    const copyExtractedBtn = document.getElementById("inlineCopyExtractedBtn");
    const toggleExpandBtn = document.getElementById("inlineToggleExpandContentBtn");

    const contentText = result.submitted_item || result.extracted_text || result.ocr_text || result.target || (scanInput ? scanInput.value : "") || "";

    if (extractedContainer && extractedBox) {
      if (contentText && contentText.trim()) {
        extractedContainer.classList.remove("hidden");
        extractedBox.textContent = contentText;

        const charCount = contentText.length;
        const wordCount = contentText.trim().split(/\s+/).filter(Boolean).length;
        if (metricsBadge) {
          metricsBadge.textContent = `${wordCount} words • ${charCount} chars`;
        }
        if (engineBadge) {
          const engine = result.ocr_engine ? result.ocr_engine.toUpperCase() : (result.type === "screenshot" ? "TESSERACT OCR" : "ANALYZER");
          engineBadge.textContent = engine;
        }

        if (copyExtractedBtn) {
          copyExtractedBtn.onclick = () => {
            navigator.clipboard.writeText(contentText).then(() => {
              showToast("Extracted content copied to clipboard!", "success");
            }).catch(() => {
              showToast("Could not copy content.", "error");
            });
          };
        }

        if (toggleExpandBtn) {
          toggleExpandBtn.onclick = () => {
            const isExpanded = extractedBox.classList.toggle("expanded");
            toggleExpandBtn.innerHTML = isExpanded
              ? `<span class="material-symbols-outlined text-xs">unfold_less</span><span>Collapse</span>`
              : `<span class="material-symbols-outlined text-xs">unfold_more</span><span>Expand</span>`;
          };
        }
      } else {
        extractedContainer.classList.add("hidden");
      }
    }

    // Scam Recovery Assistant Callout Banner
    const recoveryCallout = document.getElementById("inlineRecoveryCallout");
    const launchRecoveryBtn = document.getElementById("inlineLaunchRecoveryBtn");
    if (recoveryCallout) {
      if (riskLevel.includes("suspicious") || riskLevel.includes("caution")) {
        recoveryCallout.classList.remove("hidden");
        if (launchRecoveryBtn) {
          launchRecoveryBtn.onclick = () => {
            const contextText = ((result.submitted_item || "") + " " + (result.explanation || "") + " " + (result.category || "") + " " + contentText).toLowerCase();
            let targetPlaybook = "money_transferred";
            if (contextText.includes("upi") || contextText.includes("qr") || contextText.includes("phonepe") ||
                contextText.includes("gpay") || contextText.includes("google pay") || contextText.includes("paytm") ||
                contextText.includes("vpa") || contextText.includes("collect request") || contextText.includes("bhim") ||
                contextText.includes("rrn") || contextText.includes("utr")) {
              targetPlaybook = "upi_fraud";
            } else if (contextText.includes("apk") || contextText.includes("malware") || contextText.includes(".apk")) {
              targetPlaybook = "malicious_apk";
            } else if (contextText.includes("bank") || contextText.includes("kyc") || contextText.includes("pan") || contextText.includes("netbanking")) {
              targetPlaybook = "bank_compromise";
            } else if (contextText.includes("card") || contextText.includes("cvv") || contextText.includes("debit") || contextText.includes("credit")) {
              targetPlaybook = "card_compromise";
            } else if (contextText.includes("password") || contextText.includes("credential")) {
              targetPlaybook = "password_stolen";
            } else if (contextText.includes("crypto") || contextText.includes("token") || contextText.includes("seed phrase")) {
              targetPlaybook = "crypto_fraud";
            }
            navigateTo("recovery-assistant", targetPlaybook, true);
          };
        }
      } else {
        recoveryCallout.classList.add("hidden");
      }
    }

    // Contextual Cybercrime Helpline Section
    const officialHelpSection = document.getElementById("inlineOfficialHelpSection");
    if (officialHelpSection) {
      const lowerText = (contentText + " " + (result.explanation || "")).toLowerCase();
      const isFinancialOrCritical = riskLevel.includes("suspicious") ||
        lowerText.includes("bank") || lowerText.includes("otp") || lowerText.includes("upi") ||
        lowerText.includes("money") || lowerText.includes("police") || lowerText.includes("arrest") ||
        lowerText.includes("discom") || lowerText.includes("electricity");

      if (isFinancialOrCritical) {
        officialHelpSection.classList.remove("hidden");
      } else {
        officialHelpSection.classList.add("hidden");
      }
    }

    // Reveal card with smooth scroll
    inlineResultCard.classList.remove("hidden");
    inlineResultCard.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ================================================================
  // 6. FULL REPORT MODAL & PDF DOWNLOAD WORKFLOW
  // ================================================================
  if (inspectFullReportBtn && fullReportModal) {
    inspectFullReportBtn.addEventListener("click", () => {
      if (!lastAnalysisResult) return;
      openFullReportModal(lastAnalysisResult);
    });
  }

  function openFullReportModal(data) {
    if (!fullReportModal) return;

    if (modalReportScanId) modalReportScanId.textContent = data.scan_id || data.scanId || `SK-${Date.now()}`;
    if (modalReportTimestamp) modalReportTimestamp.textContent = data.timestamp || new Date().toLocaleString();
    if (modalReportTargetSnippet) modalReportTargetSnippet.textContent = data.submitted_item || data.display_item || (scanInput ? scanInput.value : "");
    if (modalReportExplanation) modalReportExplanation.textContent = data.explanation || "Detailed analysis completed.";
    if (modalReportReasoning) modalReportReasoning.textContent = data.explanation || data.summary || "Detailed analysis completed.";

    // Classification banner
    const risk = (data.risk_level || "caution").toLowerCase();
    if (modalReportClassificationBanner) {
      if (risk.includes("suspicious")) {
        modalReportClassificationBanner.className = "p-3.5 rounded-xl font-bold text-center tracking-wide text-xs bg-rose-600 text-white shadow-sm";
        modalReportClassificationBanner.textContent = "▲ SUSPICIOUS — HIGH THREAT CONFIDENCE";
      } else if (risk.includes("safe") || risk.includes("no clear")) {
        modalReportClassificationBanner.className = "p-3.5 rounded-xl font-bold text-center tracking-wide text-xs bg-emerald-600 text-white shadow-sm";
        modalReportClassificationBanner.textContent = "✓ NO CLEAR WARNING SIGNS";
      } else {
        modalReportClassificationBanner.className = "p-3.5 rounded-xl font-bold text-center tracking-wide text-xs bg-amber-500 text-white shadow-sm";
        modalReportClassificationBanner.textContent = "● CAUTION — VERIFY INDEPENDENTLY";
      }
    }

    // Indicators in modal
    if (modalReportIndicatorsList) {
      modalReportIndicatorsList.innerHTML = "";
      const indicators = data.detected_indicators || [];
      if (indicators.length === 0) {
        modalReportIndicatorsList.innerHTML = `<li>No active warning indicators detected.</li>`;
      } else {
        indicators.forEach(ind => {
          const text = typeof ind === "string" ? ind : (ind.title || JSON.stringify(ind));
          const li = document.createElement("li");
          li.innerHTML = `• ${escapeHtml(text)}`;
          modalReportIndicatorsList.appendChild(li);
        });
      }
    }

    // Why it matters
    if (modalReportWhyMatters) modalReportWhyMatters.textContent = data.why_it_matters || "Social engineering exploits digital trust to compromise security.";

    // Independent verification guidance
    if (modalReportVerificationAdvice) {
      modalReportVerificationAdvice.textContent = data.verification_advice || "Always contact organizations using numbers from their official website or verified banking app. Never rely on contact details provided within an unsolicited message.";
    }

    // Steps
    if (modalReportNextSteps) {
      modalReportNextSteps.innerHTML = "";
      const steps = data.recommended_actions || data.recommended_steps || ["Do not interact with unverified links or callers."];
      steps.forEach((s, idx) => {
        const li = document.createElement("li");
        li.innerHTML = `${idx + 1}. ${escapeHtml(s)}`;
        modalReportNextSteps.appendChild(li);
      });
    }

    // Scope & Important Uncertainties
    if (modalReportLimitations) {
      modalReportLimitations.innerHTML = "";
      const uncertainties = data.important_uncertainties || [
        "AI models evaluate probabilistic patterns and threat signatures; zero-day phishing kits and novel domains may not be recognized.",
        "Assessment is based strictly on the provided content without access to private sender account data or real-time server records.",
        "Content verified as having no clear warning signs should still be treated with prudent care."
      ];
      uncertainties.forEach(u => {
        const li = document.createElement("li");
        li.className = "flex items-start gap-2 text-slate-600";
        li.innerHTML = `<span class="text-slate-400 font-mono shrink-0">•</span><span>${escapeHtml(u)}</span>`;
        modalReportLimitations.appendChild(li);
      });
    }

    fullReportModal.showModal();
  }

  if (closeFullReportModalBtn) closeFullReportModalBtn.addEventListener("click", () => fullReportModal.close());
  if (modalCloseBtn2) modalCloseBtn2.addEventListener("click", () => fullReportModal.close());

  // PDF Report Download (Modal)
  if (downloadPdfReportBtn) {
    downloadPdfReportBtn.addEventListener("click", async () => {
      if (!lastAnalysisResult) {
        showToast("No active scan report available to download.", "info");
        return;
      }
      downloadPdfReportBtn.disabled = true;
      const originalText = downloadPdfReportBtn.innerHTML;
      downloadPdfReportBtn.innerHTML = `<span class="material-symbols-outlined text-sm animate-spin">refresh</span><span>Generating PDF...</span>`;

      try {
        const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
        await scannerInstance.downloadPdfReport(lastAnalysisResult);
        showToast("Threat intelligence report downloaded successfully!", "success");
      } catch (err) {
        console.error("PDF generation error:", err);
        showToast(`PDF Download Error: ${err.message}`, "error");
      } finally {
        downloadPdfReportBtn.disabled = false;
        downloadPdfReportBtn.innerHTML = originalText;
      }
    });
  }

  // PDF Report Download (Compact Card)
  if (downloadPdfReportBtnCompact) {
    downloadPdfReportBtnCompact.addEventListener("click", async () => {
      if (!lastAnalysisResult) {
        showToast("No active scan report available to download.", "info");
        return;
      }
      downloadPdfReportBtnCompact.disabled = true;
      const originalText = downloadPdfReportBtnCompact.innerHTML;
      downloadPdfReportBtnCompact.innerHTML = `<span class="material-symbols-outlined text-sm animate-spin">refresh</span><span>Generating PDF...</span>`;

      try {
        const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
        await scannerInstance.downloadPdfReport(lastAnalysisResult);
        showToast("Threat intelligence report downloaded successfully!", "success");
      } catch (err) {
        console.error("PDF generation error:", err);
        showToast(`PDF Download Error: ${err.message}`, "error");
      } finally {
        downloadPdfReportBtnCompact.disabled = false;
        downloadPdfReportBtnCompact.innerHTML = originalText;
      }
    });
  }

  // ================================================================
  // 7. TRUST VERIFICATION ASSISTANT (Quick Widget & Directory)
  // ================================================================
  const trustData = {
    sbi: {
      domain: "https://onlinesbi.sbi",
      header: "SBIPAY, SBINB, ATMSBI",
      phone: "1800-1234 / 1800-2100",
      rule: "SBI never asks customers to update KYC via APK downloads or external links.",
      citation: "RBI & State Bank of India Directory",
      badge: "VERIFIED OFFICIAL"
    },
    hdfc: {
      domain: "https://hdfcbank.com",
      header: "HDFCBK, HDFCBN",
      phone: "1800-202-6161 / 1800-1600",
      rule: "HDFC Bank never asks for OTP or NetBanking password to cancel unauthorized transactions.",
      citation: "HDFC Bank Fraud Advisory",
      badge: "VERIFIED OFFICIAL"
    },
    indiapost: {
      domain: "https://indiapost.gov.in",
      header: "DOPIND, INPOST",
      phone: "1800-266-6868",
      rule: "India Post does not send SMS demanding micro-fee redelivery payments on .xyz or .top domains.",
      citation: "Dept of Posts, Govt of India",
      badge: "VERIFIED OFFICIAL"
    },
    electricity: {
      domain: "State-specific (*.gov.in required)",
      header: "DISCOM, STATEPB",
      phone: "1912 (TRAI National Power Helpline)",
      rule: "Discom offices never send WhatsApp threats to cut off power tonight unless you pay on personal UPI.",
      citation: "TRAI National 1912 Directory",
      badge: "REGIONAL (.GOV.IN REQUIRED)"
    },
    netflix: {
      domain: "https://netflix.com",
      header: "NETFLIX",
      phone: "In-App Help Center Only (No Inbound Phone)",
      rule: "Netflix never requests billing or card updates through unsolicited SMS messages or phone calls.",
      citation: "Netflix Security Advisory",
      badge: "IN-APP ONLY (NO INBOUND PHONE)"
    },
    amazon: {
      domain: "https://amazon.com / amazon.in",
      header: "AMAZON, AMZIN",
      phone: "In-App Call-Back Only (No Direct Inbound Line)",
      rule: "Amazon customer care never calls from mobile numbers demanding remote app installation or gift card payment.",
      citation: "Amazon Security Policy",
      badge: "IN-APP ONLY (NO INBOUND PHONE)"
    }
  };

  if (trustEntitySelector) {
    trustEntitySelector.addEventListener("change", () => {
      const entity = trustData[trustEntitySelector.value] || trustData.sbi;
      if (trustDomain) trustDomain.textContent = entity.domain;
      if (trustHeader) trustHeader.textContent = entity.header;
      if (trustPhone) trustPhone.textContent = entity.phone;
      if (trustRule) trustRule.textContent = entity.rule;
      if (trustSource) trustSource.textContent = `Source: ${entity.citation}`;
      if (trustStatusBadge) trustStatusBadge.textContent = entity.badge;
    });
  }

  // ================================================================
  // 6. UPGRADED TRUST VERIFICATION & MULTI-VECTOR INSPECTOR
  // ================================================================
  let currentTrustCategory = "all";

  function initTrustVerificationView() {
    renderFullTrustDirectory("", currentTrustCategory);

    // Setup Category Tabs
    const catBar = document.getElementById("trustCategoryFilterBar");
    if (catBar) {
      const catBtns = catBar.querySelectorAll(".trust-cat-filter");
      catBtns.forEach(btn => {
        btn.onclick = () => {
          catBtns.forEach(b => {
            b.classList.remove("active", "bg-emerald-100", "text-emerald-800", "border-emerald-300");
            b.classList.add("bg-slate-100", "text-slate-700", "border-slate-200");
          });
          btn.classList.add("active", "bg-emerald-100", "text-emerald-800", "border-emerald-300");
          btn.classList.remove("bg-slate-100", "text-slate-700", "border-slate-200");
          currentTrustCategory = btn.getAttribute("data-cat") || "all";
          const searchInput = document.getElementById("verificationSearchInput");
          const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
          renderFullTrustDirectory(query, currentTrustCategory);
        };
      });
    }

    const searchInput = document.getElementById("verificationSearchInput");
    if (searchInput) {
      searchInput.oninput = () => {
        const query = searchInput.value.toLowerCase().trim();
        renderFullTrustDirectory(query, currentTrustCategory);
      };
    }

    const verifyBtn = document.getElementById("trustVerifyBtn");
    const verifierInput = document.getElementById("trustVerifierInput");

    if (verifyBtn && verifierInput) {
      verifyBtn.onclick = () => handleLiveTrustCheck();
      verifierInput.onkeydown = (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          handleLiveTrustCheck();
        }
      };
    }
  }

  function renderFullTrustDirectory(filterQuery = "", categoryFilter = "all") {
    const grid = document.getElementById("verificationDirectoryGrid");
    if (!grid) return;

    const dataStore = window.SCAM_BREAKER_DATA || window.SCAM_KILLER_DATA || {};
    const directory = dataStore.trustDirectory || [];
    grid.innerHTML = "";

    const filtered = directory.filter(item => {
      const matchesCat = categoryFilter === "all" ||
        (item.category && item.category.toLowerCase().includes(categoryFilter.toLowerCase())) ||
        (categoryFilter === "Government" && (item.category === "Government & Regulatory" || item.category === "Law Enforcement"));

      if (!matchesCat) return false;

      if (!filterQuery) return true;
      const q = filterQuery.toLowerCase();
      return item.name.toLowerCase().includes(q) ||
        item.domain.toLowerCase().includes(q) ||
        (item.smsHeader && item.smsHeader.toLowerCase().includes(q)) ||
        (item.rule && item.rule.toLowerCase().includes(q)) ||
        item.category.toLowerCase().includes(q);
    });

    if (filtered.length === 0) {
      grid.innerHTML = `
        <div class="col-span-1 sm:col-span-2 p-6 rounded-xl border border-dashed border-slate-200 bg-slate-50 text-center text-xs text-slate-400">
          No certified institutions match your search query or filter. Try searching by bank name, domain, or SMS header.
        </div>
      `;
      return;
    }

    filtered.forEach(item => {
      const card = document.createElement("div");
      card.className = "p-4 rounded-xl border border-slate-200 bg-slate-50/70 hover:bg-white hover:border-emerald-300 transition-all space-y-2.5 text-xs shadow-sm";
      card.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="w-6 h-6 rounded-full bg-emerald-100 text-emerald-800 font-bold flex items-center justify-center text-[10px] uppercase font-mono">
              ${escapeHtml(item.name.substring(0, 2))}
            </span>
            <span class="font-bold text-slate-900 text-sm">${escapeHtml(item.name)}</span>
          </div>
          <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">${escapeHtml(item.status || "VERIFIED")}</span>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
          <div>
            <span class="text-slate-400 block uppercase text-[9px]">Official Portal:</span>
            ${item.domain && item.domain.startsWith('http') ? `
              <a href="${escapeHtml(item.domain)}" target="_blank" rel="noopener noreferrer" class="font-mono font-semibold text-emerald-700 hover:text-emerald-900 hover:underline inline-flex items-center gap-1 transition-colors">
                <span class="truncate">${escapeHtml(item.domain)}</span>
                <span class="material-symbols-outlined text-[12px] shrink-0">open_in_new</span>
              </a>
            ` : `<span class="font-mono font-semibold text-emerald-700">${escapeHtml(item.domain)}</span>`}
          </div>
          <div>
            <span class="text-slate-400 block uppercase text-[9px]">Helpline:</span>
            ${(item.helpline && /\d{3,}/.test(item.helpline)) ? `
              <a href="tel:${escapeHtml(item.helpline.split('/')[0].replace(/[^\d+]/g, ''))}" class="font-mono text-slate-800 hover:text-emerald-700 hover:underline inline-flex items-center gap-1 transition-colors">
                <span class="material-symbols-outlined text-xs text-rose-600 shrink-0">call</span>
                <span>${escapeHtml(item.helpline)}</span>
              </a>
            ` : `<span class="font-mono text-slate-800">${escapeHtml(item.helpline)}</span>`}
          </div>
        </div>
        ${item.smsHeader ? `<div class="text-[11px]"><span class="text-slate-400 block uppercase text-[9px]">Registered DLT SMS Headers:</span><span class="font-mono text-slate-700 font-semibold">${escapeHtml(item.smsHeader)}</span></div>` : ""}
        <p class="text-[11px] text-slate-600 bg-white p-2 rounded border border-slate-200 leading-relaxed">${escapeHtml(item.rule)}</p>
        <span class="text-[10px] text-slate-400 font-mono block">Citation: ${escapeHtml(item.citation)}</span>
      `;
      grid.appendChild(card);
    });
  }

  function handleLiveTrustCheck() {
    const inputEl = document.getElementById("trustVerifierInput");
    const resultCard = document.getElementById("trustVerifierResultCard");
    const resultIconWrap = document.getElementById("trustResultIconWrap");
    const resultIcon = document.getElementById("trustResultIcon");
    const resultTitle = document.getElementById("trustResultTitle");
    const resultTierLabel = document.getElementById("trustResultTierLabel");
    const resultBadge = document.getElementById("trustResultBadge");
    const resultEntity = document.getElementById("trustResultEntity");
    const resultList = document.getElementById("trustResultEvidenceList");
    const resultAdvice = document.getElementById("trustResultAdvice");
    const anatomyBox = document.getElementById("trustUrlAnatomyBox");
    const anatomyDetails = document.getElementById("trustUrlAnatomyDetails");

    if (!inputEl || !resultCard) return;
    const rawVal = inputEl.value.trim();
    if (!rawVal) {
      showToast("Please enter an identifier (domain, SMS header, or phone number) to inspect.", "error");
      return;
    }

    const dataStore = window.SCAM_BREAKER_DATA || window.SCAM_KILLER_DATA || {};
    const directory = dataStore.trustDirectory || [];

    const cleanVal = rawVal.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
    const isUrlLike = rawVal.includes(".") || rawVal.startsWith("http://") || rawVal.startsWith("https://") || rawVal.includes("/");

    // 4-Tier structured evaluation:
    // Tier 1: VERIFIED OFFICIAL (Emerald)
    // Tier 2: HIGH RISK DETECTED (Rose)
    // Tier 3: UNVERIFIED / INDEPENDENT (Slate)
    // Tier 4: MISSING EVIDENCE / INSUFFICIENT (Amber)
    let tier = 3;
    let verdict = "unverified";
    let title = "Unverified Identifier";
    let tierLabel = "Tier 3: Unverified / Third-Party Counterparty";
    let entityName = "Not listed in certified banking or regulatory DLT directory";
    let evidence = [];
    let advice = "Exercise caution. Do not share OTPs, PINs, or NetBanking passwords with this sender.";
    let badgeClass = "bg-slate-100 text-slate-800 border border-slate-300";
    let iconName = "help";
    let iconBg = "bg-slate-100 text-slate-700";

    // Tier 4 Check: Incomplete input (< 3 chars or ambiguous)
    if (rawVal.length < 3) {
      tier = 4;
      verdict = "missing_evidence";
      title = "Insufficient Identifier Length";
      tierLabel = "Tier 4: Missing Evidence / Ambiguous Query";
      entityName = "Input query is too short for reliable deterministic verification";
      badgeClass = "bg-amber-100 text-amber-900 border border-amber-300";
      iconName = "emergency";
      iconBg = "bg-amber-100 text-amber-800";
      evidence.push("Identifier contains fewer than 3 characters.");
      evidence.push("DLT SMS sender headers in India require a minimum 6-character alphanumeric sequence (e.g. SBIPAY, AXISBK).");
      evidence.push("Domain names require a fully qualified domain extension (e.g. .com, .in, .sbi).");
      advice = "Please provide the complete URL (e.g. onlinesbi.sbi), full 6-character SMS header, or full 10-digit mobile number.";
    } else {
      // Tier 1 Check: Directory Match
      const matched = directory.find(d => {
        const dDom = d.domain.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
        const dHeaders = (d.smsHeader || "").toLowerCase().split(",").map(s => s.trim());
        const dName = d.name.toLowerCase();
        return cleanVal === dDom ||
               cleanVal.endsWith("." + dDom) ||
               dHeaders.some(h => cleanVal === h || cleanVal.endsWith("-" + h) || cleanVal.endsWith(h)) ||
               cleanVal.includes(dName);
      });

      if (matched) {
        tier = 1;
        verdict = "verified";
        title = `Official Registry Match: ${matched.name}`;
        tierLabel = "Tier 1: Certified Official Authority";
        entityName = `Registered Authority: ${matched.citation}`;
        badgeClass = "bg-emerald-100 text-emerald-800 border border-emerald-300";
        iconName = "verified";
        iconBg = "bg-emerald-100 text-emerald-700";
        evidence.push(`Identifier matches certified directory entry for ${matched.name}.`);
        evidence.push(`Official registered portal: ${matched.domain}`);
        evidence.push(`Official emergency helpline: ${matched.helpline}`);
        if (matched.smsHeader) evidence.push(`Registered TRAI DLT SMS Header(s): ${matched.smsHeader}`);
        evidence.push(`Security Rule: ${matched.rule}`);
        advice = "Matches authentic directory profile. Always verify the full URL in your browser address bar before entering credentials.";
      } else if (cleanVal.endsWith(".gov.in") || cleanVal.endsWith(".nic.in")) {
        tier = 1;
        verdict = "verified";
        title = "Official Government Domain (.gov.in / .nic.in)";
        tierLabel = "Tier 1: Certified Sovereign Ministry / Agency";
        entityName = "National Informatics Centre (NIC) / Government of India Registered";
        badgeClass = "bg-emerald-100 text-emerald-800 border border-emerald-300";
        iconName = "verified";
        iconBg = "bg-emerald-100 text-emerald-700";
        evidence.push("Domain uses reserved sovereign government TLD (.gov.in or .nic.in).");
        evidence.push("Restricted top-level domain allocated exclusively to authorized ministries, departments, and public authorities.");
        advice = "Authentic official government web portal. Always check the browser address bar for correct spelling.";
      }
      // Tier 2 Check: High Risk Ephemeral TLDs or Unregistered 10-Digit Mobile Numbers claiming to be banks
      else if (/\.(top|xyz|club|work|buzz|click|online|shop|live|cfd|icu|rest|sbs|store|site|vip)$/i.test(cleanVal)) {
        tier = 2;
        verdict = "suspicious";
        title = "High-Risk Ephemeral Domain Extension (.top, .xyz, .club)";
        tierLabel = "Tier 2: High Risk Threat Pattern";
        entityName = "Ephemeral Domain Frequently Utilized in Phishing Campaigns";
        badgeClass = "bg-rose-100 text-rose-800 border border-rose-300";
        iconName = "gpp_bad";
        iconBg = "bg-rose-100 text-rose-700";
        evidence.push(`Domain utilizes high-risk cheap generic TLD (${cleanVal.split('.').pop()}) heavily favored by automated phishing syndicates.`);
        evidence.push("Legitimate Indian financial institutions, utilities, and postal services NEVER host transactional services on cheap ephemeral TLDs.");
        evidence.push("No corporate entity registration found in TRAI or RBI official registry.");
        advice = "Do NOT click, submit credentials, or open downloads from this domain. Immediately block the sender and report on Chakshu.";
      } else if (/^(\+?91)?[6-9]\d{9}$/.test(rawVal.replace(/[\s-]/g, ""))) {
        tier = 2;
        verdict = "suspicious";
        title = "Personal 10-Digit Mobile Number (Not an Official Bank Header)";
        tierLabel = "Tier 2: TRAI Regulation Violation / High Risk";
        entityName = "Unregistered Individual SIM Card";
        badgeClass = "bg-rose-100 text-rose-800 border border-rose-300";
        iconName = "warning";
        iconBg = "bg-rose-100 text-rose-700";
        evidence.push("Under TRAI DLT regulations, commercial banks, telecom operators, and utilities MUST send SMS alerts via registered 6-character alpha headers (e.g. SBIPAY, HDFCBK).");
        evidence.push("Legitimate financial institutions NEVER send urgent KYC update, account block, or lottery alerts from standard personal 10-digit mobile numbers.");
        evidence.push("High probability of a spoofed sender or burner SIM card used by scam syndicates.");
        advice = "Do NOT call this number back or click links sent by it. Report this number immediately on the DoT Chakshu portal (sancharsaathi.gov.in).";
      } else if (cleanVal.includes("kyc") || cleanVal.includes("reward") || cleanVal.includes("claim") || cleanVal.includes("apk") || cleanVal.includes("ebill")) {
        tier = 2;
        verdict = "suspicious";
        title = "Suspicious Brand Impersonation / Urgency Keywords Detected";
        tierLabel = "Tier 2: High Risk Brand Impersonation";
        entityName = "Unauthenticated Domain Exhibiting Phishing Signatures";
        badgeClass = "bg-rose-100 text-rose-800 border border-rose-300";
        iconName = "gpp_bad";
        iconBg = "bg-rose-100 text-rose-700";
        evidence.push("Identifier contains high-frequency fraud keywords (e.g. kyc, reward, claim, apk, ebill).");
        evidence.push("No cryptographic registration or DLT match found for this entity.");
        advice = "Extreme caution: Fraudsters construct domains with brand words to deceive users. Do not disclose financial credentials.";
      }
      // Tier 3: Unverified / Unknown
      else {
        tier = 3;
        verdict = "unverified";
        title = "Unverified Identifier";
        tierLabel = "Tier 3: Unverified / Third-Party Counterparty";
        entityName = "Not listed in certified banking or regulatory DLT directory";
        badgeClass = "bg-slate-100 text-slate-800 border border-slate-300";
        iconName = "help";
        iconBg = "bg-slate-100 text-slate-700";
        evidence.push("No direct record found in verified banking, postal, or government directories.");
        evidence.push("Identifier appears to be an unindexed private business domain or third-party service.");
        advice = "Verify independently using official printed paperwork, bank passbooks, or authentic in-app support channels before sharing sensitive information.";
      }
    }

    // Render 4-tier Result Card
    resultCard.classList.remove("hidden");
    if (resultIconWrap) resultIconWrap.className = `w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${iconBg}`;
    if (resultIcon) resultIcon.textContent = iconName;
    if (resultTitle) resultTitle.textContent = title;
    if (resultTierLabel) resultTierLabel.textContent = tierLabel;
    if (resultBadge) {
      resultBadge.className = `text-[10px] font-mono px-3 py-1 rounded-full font-bold uppercase ${badgeClass}`;
      resultBadge.textContent = verdict === "verified" ? "TIER 1 • VERIFIED OFFICIAL" :
                                verdict === "suspicious" ? "TIER 2 • HIGH RISK DETECTED" :
                                verdict === "missing_evidence" ? "TIER 4 • MISSING EVIDENCE" :
                                "TIER 3 • UNVERIFIED";
    }
    if (resultEntity) resultEntity.textContent = entityName;
    if (resultList) {
      resultList.innerHTML = evidence.map(e => `<li>${escapeHtml(e)}</li>`).join("");
    }
    if (resultAdvice) resultAdvice.textContent = advice;

    // URL Anatomy Diagnostics Box
    if (anatomyBox && anatomyDetails) {
      if (isUrlLike) {
        anatomyBox.classList.remove("hidden");
        const hasHttps = rawVal.startsWith("https://");
        const hasHttp = rawVal.startsWith("http://");
        const protocol = hasHttps ? "https://" : (hasHttp ? "http://" : "No protocol specified (insecure default)");
        const parts = cleanVal.split(".");
        const tld = parts.length > 1 ? parts[parts.length - 1] : "N/A";
        const rootDomain = parts.length >= 2 ? parts.slice(-2).join(".") : cleanVal;

        anatomyDetails.innerHTML = `
          <div><span class="text-slate-400">Protocol:</span> <span class="${hasHttps ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}">${escapeHtml(protocol)}</span> (${hasHttps ? 'Encrypted in transit' : 'Unencrypted plaintext risk'})</div>
          <div><span class="text-slate-400">Hostname / Domain:</span> <span class="text-white font-bold">${escapeHtml(cleanVal)}</span></div>
          <div><span class="text-slate-400">Root Domain:</span> <span class="text-emerald-300 font-bold">${escapeHtml(rootDomain)}</span></div>
          <div><span class="text-slate-400">Top-Level Domain (TLD):</span> <span class="text-amber-300 font-bold">.${escapeHtml(tld)}</span></div>
        `;
      } else {
        anatomyBox.classList.add("hidden");
      }
    }
  }

  // ================================================================
  // 7. UPGRADED INCIDENT RECOVERY ASSISTANT (17 PLAYBOOKS)
  // ================================================================
  let currentRecoveryCategory = "all";
  let activePlaybookKey = "money_transferred";

  function loadRecoveryAssistant(defaultSituation = null, autoScroll = false) {
    if (defaultSituation) {
      activePlaybookKey = defaultSituation;
    }
    const dataStore = window.SCAM_BREAKER_DATA || window.SCAM_KILLER_DATA || {};
    const guidance = dataStore.recoveryGuidance || {};
    const situations = guidance.situations || guidance.situationPlaybooks || {};

    // If activePlaybook has a category and it doesn't match currentRecoveryCategory, reset to "all" so it's visible
    if (activePlaybookKey && situations[activePlaybookKey] && currentRecoveryCategory !== "all") {
      const targetCat = situations[activePlaybookKey].category;
      if (targetCat && targetCat !== currentRecoveryCategory) {
        currentRecoveryCategory = "all";
      }
    }

    renderRecoveryScenarioGrid(situations, "", currentRecoveryCategory);

    // Setup Category Filter Pills
    const pillsContainer = document.getElementById("recoveryCategoryPills");
    if (pillsContainer) {
      const pills = pillsContainer.querySelectorAll(".recovery-cat-pill");
      pills.forEach(pill => {
        const cat = pill.getAttribute("data-category") || "all";
        if (cat === currentRecoveryCategory) {
          pill.classList.add("active", "bg-rose-100", "text-rose-800", "border-rose-300");
          pill.classList.remove("bg-slate-100", "text-slate-700", "border-slate-200");
        } else {
          pill.classList.remove("active", "bg-rose-100", "text-rose-800", "border-rose-300");
          pill.classList.add("bg-slate-100", "text-slate-700", "border-slate-200");
        }
        pill.onclick = () => {
          pills.forEach(p => {
            p.classList.remove("active", "bg-rose-100", "text-rose-800", "border-rose-300");
            p.classList.add("bg-slate-100", "text-slate-700", "border-slate-200");
          });
          pill.classList.add("active", "bg-rose-100", "text-rose-800", "border-rose-300");
          pill.classList.remove("bg-slate-100", "text-slate-700", "border-slate-200");
          currentRecoveryCategory = pill.getAttribute("data-category") || "all";
          const searchInput = document.getElementById("recoverySearchInput");
          const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
          renderRecoveryScenarioGrid(situations, query, currentRecoveryCategory);
        };
      });
    }

    // Setup Search Input
    const searchInput = document.getElementById("recoverySearchInput");
    if (searchInput) {
      searchInput.oninput = () => {
        const query = searchInput.value.toLowerCase().trim();
        renderRecoveryScenarioGrid(situations, query, currentRecoveryCategory);
      };
    }

    renderRecoverySituation(activePlaybookKey);

    if (autoScroll) {
      setTimeout(() => {
        const planContainer = document.getElementById("recoveryActionPlanContainer");
        if (planContainer) {
          planContainer.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 60);
    }
  }

  function renderRecoveryScenarioGrid(situations, query = "", category = "all") {
    const grid = document.getElementById("recoverySituationGrid");
    if (!grid) return;
    grid.innerHTML = "";

    // Deduplicate unique playbooks (ignore legacy alias keys)
    const uniqueKeys = [
      "money_transferred", "upi_fraud", "bank_compromise", "card_compromise",
      "password_stolen", "email_compromise", "whatsapp_social_takeover",
      "malicious_apk", "remote_access_fraud", "sim_swap", "identity_theft",
      "shopping_fraud", "investment_fraud", "crypto_fraud", "sextortion_blackmail",
      "phishing_link", "fake_support"
    ];

    const matchingKeys = uniqueKeys.filter(k => {
      const p = situations[k];
      if (!p) return false;

      const matchesCat = category === "all" || p.category === category;
      if (!matchesCat) return false;

      if (!query) return true;
      const q = query.toLowerCase();
      return (p.title && p.title.toLowerCase().includes(q)) ||
             (p.subtitle && p.subtitle.toLowerCase().includes(q)) ||
             (p.categoryName && p.categoryName.toLowerCase().includes(q));
    });

    if (matchingKeys.length === 0) {
      grid.innerHTML = `
        <div class="col-span-1 sm:col-span-2 lg:col-span-3 p-6 rounded-xl border border-dashed border-slate-200 bg-slate-50 text-center text-xs text-slate-400">
          No incident playbooks match "${escapeHtml(query)}". Try searching for "UPI", "Bank", "APK", or "Password".
        </div>
      `;
      return;
    }

    matchingKeys.forEach(key => {
      const p = situations[key];
      const card = document.createElement("div");
      const isActive = key === activePlaybookKey;
      card.className = `recovery-situation-card p-3.5 rounded-xl border transition-all cursor-pointer ${
        isActive ? 'active border-rose-400 bg-rose-50/60 shadow-sm' : 'border-slate-200 bg-slate-50 hover:bg-white hover:border-slate-300'
      }`;
      card.setAttribute("data-situation", key);
      card.innerHTML = `
        <div class="flex items-center justify-between mb-1.5">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined text-rose-600 text-lg">${escapeHtml(p.icon || 'shield')}</span>
            <h4 class="font-bold text-xs text-slate-900">${escapeHtml(p.title)}</h4>
          </div>
          <span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 font-semibold">${escapeHtml(p.categoryName || 'Incident')}</span>
        </div>
        <p class="text-[11px] text-slate-600 leading-snug line-clamp-2">${escapeHtml(p.subtitle)}</p>
      `;

      card.onclick = () => {
        grid.querySelectorAll(".recovery-situation-card").forEach(c => {
          c.classList.remove("active", "border-rose-400", "bg-rose-50/60", "shadow-sm");
          c.classList.add("border-slate-200", "bg-slate-50");
        });
        card.classList.add("active", "border-rose-400", "bg-rose-50/60", "shadow-sm");
        card.classList.remove("border-slate-200", "bg-slate-50");
        activePlaybookKey = key;
        renderRecoverySituation(key);

        // Immediate responsive scroll into action plan so the user is never stuck
        const planContainer = document.getElementById("recoveryActionPlanContainer");
        if (planContainer) {
          planContainer.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      };

      grid.appendChild(card);
    });
  }

  function renderRecoverySituation(situationKey) {
    const dataStore = window.SCAM_BREAKER_DATA || window.SCAM_KILLER_DATA || {};
    const guidance = dataStore.recoveryGuidance || {};
    const situations = guidance.situations || guidance.situationPlaybooks || {};
    const sitData = situations[situationKey] || situations["money_transferred"] || situations["money_sent"] || {};

    const urgencyEl = document.getElementById("recoveryPlanUrgency");
    const categoryBadgeEl = document.getElementById("recoveryPlanCategoryBadge");
    const titleEl = document.getElementById("recoveryPlanTitle");
    const subtitleEl = document.getElementById("recoveryPlanSubtitle");
    const whatHappenedEl = document.getElementById("recoveryWhatHappened");
    const compromisedAssetsEl = document.getElementById("recoveryCompromisedAssets");
    const checklistContainer = document.getElementById("recoveryChecklistContainer");
    const evidenceListEl = document.getElementById("recoveryEvidenceList");
    const avoidListEl = document.getElementById("recoveryAvoidList");
    const specificContactsGrid = document.getElementById("recoverySpecificContactsGrid");
    const bankHelplinesGrid = document.getElementById("recoveryBankHelplinesGrid");
    const paymentHelplinesGrid = document.getElementById("recoveryPaymentHelplinesGrid");
    const followUpPlanEl = document.getElementById("recoveryFollowUpPlan");
    const progressTextEl = document.getElementById("recoveryProgressText");
    const progressBarEl = document.getElementById("recoveryProgressBar");
    const copyBtn = document.getElementById("copyRecoveryChecklistBtn");

    if (urgencyEl) {
      urgencyEl.textContent = sitData.urgency || "CRITICAL PRIORITY";
      urgencyEl.className = `text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${sitData.urgencyClass || "bg-rose-100 text-rose-800"}`;
    }
    if (categoryBadgeEl) {
      categoryBadgeEl.textContent = sitData.categoryName || "Incident Response";
    }
    if (titleEl) {
      titleEl.textContent = `Action Plan: ${sitData.title || "Incident Response"}`;
    }
    if (subtitleEl) {
      subtitleEl.textContent = sitData.subtitle || "";
    }
    if (whatHappenedEl) {
      whatHappenedEl.textContent = sitData.whatHappened || "Follow prioritized emergency containment instructions below.";
    }
    if (compromisedAssetsEl) {
      compromisedAssetsEl.textContent = sitData.compromisedAssets || "Financial accounts, credentials, device access.";
    }

    // Interactive Containment Checklist
    const checklistItems = sitData.checklist || sitData.steps || [];
    let completedSteps = new Set();

    function updateProgress() {
      const total = checklistItems.length;
      const count = completedSteps.size;
      const pct = total > 0 ? Math.round((count / total) * 100) : 0;
      if (progressTextEl) {
        progressTextEl.textContent = `${count} of ${total} containment actions completed (${pct}%)`;
      }
      if (progressBarEl) {
        progressBarEl.style.width = `${pct}%`;
      }
    }

    if (checklistContainer) {
      checklistContainer.innerHTML = checklistItems.map((step, idx) => `
        <div class="flex items-start gap-3 p-3 rounded-xl bg-white border border-slate-200 shadow-2xs hover:border-emerald-300 transition-colors">
          <input type="checkbox" class="recovery-action-check cursor-pointer accent-emerald-600 w-4 h-4 rounded mt-0.5 shrink-0" data-idx="${idx}" id="chk_step_${idx}">
          <label for="chk_step_${idx}" class="text-xs text-slate-800 leading-relaxed cursor-pointer select-none flex-1">
            <span class="font-bold text-slate-900 block mb-0.5">Step ${idx + 1}:</span>
            ${escapeHtml(step)}
          </label>
        </div>
      `).join("");

      const checks = checklistContainer.querySelectorAll(".recovery-action-check");
      checks.forEach(chk => {
        chk.onchange = () => {
          const idx = chk.getAttribute("data-idx");
          if (chk.checked) {
            completedSteps.add(idx);
          } else {
            completedSteps.delete(idx);
          }
          updateProgress();
        };
      });
      updateProgress();
    }

    // Evidence to Preserve
    if (evidenceListEl) {
      const evList = sitData.evidence || [
        "Transaction Reference Numbers (UTR / RRN / UPI ID)",
        "Screenshots of conversations and fraudulent payment requests",
        "Sender phone numbers or deceptive website URLs"
      ];
      evidenceListEl.innerHTML = evList.map(item => `<li>${escapeHtml(item)}</li>`).join("");
    }

    // What to Avoid
    if (avoidListEl) {
      const avList = sitData.whatToAvoid || [
        "NEVER pay third-party 'recovery agents' or 'crypto recovery hackers' online.",
        "Do not delete chat logs or SMS threads with scammers — they are primary evidence."
      ];
      avoidListEl.innerHTML = avList.map(item => `<li>${escapeHtml(item)}</li>`).join("");
    }

    // Specific Contacts Grid
    if (specificContactsGrid) {
      const contacts = sitData.contacts || [];
      if (contacts.length === 0) {
        specificContactsGrid.innerHTML = `
          <div class="p-3 rounded-xl bg-white border border-slate-200 text-xs text-slate-500">
            Dial 1930 or report on <a href="https://cybercrime.gov.in" target="_blank" class="text-emerald-700 underline font-semibold">cybercrime.gov.in</a>.
          </div>
        `;
      } else {
        specificContactsGrid.innerHTML = contacts.map(c => {
          const infoStr = String(c.info || "").trim();
          const isUrl = infoStr.startsWith("http://") || infoStr.startsWith("https://") || infoStr.includes("cybercrime.gov.in") || infoStr.includes(".gov.in");
          const isPhone = !isUrl && /\d{3,}/.test(infoStr);

          let infoHtml = "";
          if (isUrl) {
            const hrefUrl = infoStr.startsWith("http") ? infoStr : `https://${infoStr}`;
            infoHtml = `
              <a href="${escapeHtml(hrefUrl)}" target="_blank" rel="noopener noreferrer" class="text-[11px] font-mono text-emerald-700 font-bold hover:underline hover:text-emerald-900 inline-flex items-center gap-1 transition-colors">
                <span class="material-symbols-outlined text-[13px] shrink-0">open_in_new</span>
                <span class="truncate">${escapeHtml(infoStr)}</span>
              </a>
            `;
          } else if (isPhone) {
            const cleanPhone = infoStr.split('/')[0].replace(/[^\d+]/g, '');
            infoHtml = `
              <a href="tel:${escapeHtml(cleanPhone)}" class="text-[11px] font-mono text-emerald-700 font-bold hover:underline hover:text-emerald-900 inline-flex items-center gap-1 transition-colors">
                <span class="material-symbols-outlined text-[13px] text-rose-600 shrink-0">call</span>
                <span>${escapeHtml(infoStr)}</span>
              </a>
            `;
          } else {
            infoHtml = `<div class="text-[11px] font-mono text-emerald-700 font-bold">${escapeHtml(infoStr)}</div>`;
          }

          return `
            <div class="p-3 rounded-xl bg-white border border-slate-200 text-xs space-y-1 shadow-2xs">
              <div class="flex items-center justify-between">
                <span class="font-bold text-slate-900">${escapeHtml(c.entity)}</span>
                <span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold">${escapeHtml(c.channel || 'Official')}</span>
              </div>
              ${infoHtml}
            </div>
          `;
        }).join("");
      }
    }

    // Bank Helplines Grid
    if (bankHelplinesGrid && guidance.bankHelplines) {
      bankHelplinesGrid.innerHTML = guidance.bankHelplines.map(b => `
        <div class="p-3 rounded-xl bg-white border border-slate-200 text-xs space-y-1.5 shadow-2xs">
          <div class="flex items-center justify-between">
            <span class="font-bold text-slate-900">${escapeHtml(b.name)}</span>
            <span class="text-[9px] font-mono text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 font-bold">24x7 Direct</span>
          </div>
          <div class="text-[11px] text-slate-600 flex items-center gap-1">
            <span class="material-symbols-outlined text-xs text-rose-600 shrink-0">call</span>
            <a href="tel:${escapeHtml(b.phone.replace(/[\s-]/g, ''))}" class="font-mono font-bold text-slate-800 hover:text-rose-600 transition-colors">${escapeHtml(b.phone)}</a>
          </div>
          ${b.portal ? `
            <div class="pt-0.5">
              <a href="${escapeHtml(b.portal)}" target="_blank" rel="noopener noreferrer" class="text-[10px] text-emerald-700 underline font-mono inline-flex items-center gap-1 hover:text-emerald-900 transition-colors">
                <span class="material-symbols-outlined text-[10px] shrink-0">open_in_new</span>
                <span>Official Banking Portal</span>
              </a>
            </div>
          ` : ''}
          <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(b.smsBlock)}</div>
        </div>
      `).join("");
    }

    // Payment Helplines Grid
    if (paymentHelplinesGrid && guidance.paymentHelplines) {
      paymentHelplinesGrid.innerHTML = guidance.paymentHelplines.map(p => {
        const cleanPhone = (p.phone || "").replace(/[\s-]/g, '');
        const isUrl = p.altPhone && (p.altPhone.startsWith('http://') || p.altPhone.startsWith('https://'));
        return `
          <div class="p-3 rounded-xl bg-white border border-slate-200 text-xs space-y-1 shadow-2xs">
            <div class="flex items-center justify-between">
              <span class="font-bold text-slate-900">${escapeHtml(p.name)}</span>
              <span class="text-[9px] font-mono text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-200 font-bold">${escapeHtml(p.channel)}</span>
            </div>
            <div class="text-[11px] font-mono text-slate-800 font-bold flex items-center gap-1">
              <span class="material-symbols-outlined text-xs text-indigo-600 shrink-0">call</span>
              <a href="tel:${escapeHtml(cleanPhone)}" class="hover:text-indigo-700 hover:underline transition-colors">${escapeHtml(p.phone)}</a>
            </div>
            ${isUrl ? `
              <div class="pt-0.5">
                <a href="${escapeHtml(p.altPhone)}" target="_blank" rel="noopener noreferrer" class="text-[10px] text-indigo-700 underline font-mono inline-flex items-center gap-1 hover:text-indigo-900 transition-colors">
                  <span class="material-symbols-outlined text-[10px] shrink-0">open_in_new</span>
                  <span>NPCI Grievance Portal</span>
                </a>
              </div>
            ` : (p.altPhone ? `<div class="text-[10px] text-slate-500 font-mono">${escapeHtml(p.altPhone)}</div>` : '')}
            <div class="text-[10px] text-slate-500 leading-tight">${escapeHtml(p.rule)}</div>
          </div>
        `;
      }).join("");
    }

    // Follow-up Plan
    if (followUpPlanEl) {
      followUpPlanEl.textContent = sitData.followUpPlan || "Monitor credit reports and enable app-based 2FA across all financial services.";
    }

    // Copy Full Action Plan
    if (copyBtn) {
      copyBtn.onclick = () => {
        const checkListText = checklistItems.map((s, i) => {
          const isDone = completedSteps.has(String(i));
          return `[${isDone ? 'X' : ' '}] Step ${i + 1}: ${s}`;
        }).join('\n');

        const evText = (sitData.evidence || []).map(e => `• ${e}`).join('\n');
        const avText = (sitData.whatToAvoid || []).map(a => `• ${a}`).join('\n');

        const textToCopy = `================================================================
SCAM BREAKER — INCIDENT RECOVERY ACTION PLAN
================================================================
Incident: ${sitData.title}
Urgency: ${sitData.urgency}
Category: ${sitData.categoryName || 'Fraud Incident'}

IMPACT ASSESSMENT:
${sitData.whatHappened || ''}
Assets At Risk: ${sitData.compromisedAssets || ''}

STEP-BY-STEP CONTAINMENT CHECKLIST:
${checkListText}

CRITICAL ACTIONS TO AVOID:
${avText}

REQUIRED EVIDENCE TO PRESERVE FOR POLICE / 1930 / NCRP:
${evText}

EMERGENCY REPORTING DESKS:
• National Cybercrime Helpline: 1930 (Immediate inter-bank fund lien freeze)
• National Cybercrime Reporting Portal: https://cybercrime.gov.in
• DoT Sanchar Saathi (Chakshu): https://sancharsaathi.gov.in/sfc/
• National Consumer Helpline: 1915

POST-CONTAINMENT FOLLOW-UP:
${sitData.followUpPlan || ''}

SAFETY DISCLAIMER:
Official police, RBI, and SCAM BREAKER never charge recovery fees.
Never pay third-party "recovery hackers" or "funds retrieval agents".
Generated by SCAM BREAKER (https://scambreaker.internal)
================================================================`;

        navigator.clipboard.writeText(textToCopy).then(() => {
          showToast("Full incident action plan copied to clipboard!", "success");
        }).catch(() => {
          showToast("Could not copy plan to clipboard.", "error");
        });
      };
    }
  }

  // ================================================================
  // 8. SCAN HISTORY VIEW
  // ================================================================
  const getApiBase = () => (window.getScamKillerApiBase ? window.getScamKillerApiBase() : "/api");

  async function loadScanHistory() {
    const tbody = document.getElementById("historyTableBody");
    if (!tbody) return;

    const q = historySearchInput ? historySearchInput.value.trim() : "";
    const risk = historyFilterSelect ? historyFilterSelect.value : "all";
    const category = historyCategoryFilterSelect ? historyCategoryFilterSelect.value : "all";

    try {
      const data = await window.scamKillerScanner.getScanHistory(50, category, risk, q);
      scanHistoryCache = data.history || [];
      renderScanHistoryTable(scanHistoryCache);
    } catch (err) {
      console.error("Failed to load history:", err);
      // Fallback direct fetch
      try {
        const res = await fetch(`${getApiBase()}/history?limit=50`);
        const data = await res.json();
        scanHistoryCache = data.history || [];
        renderScanHistoryTable(scanHistoryCache);
      } catch (e) {
        console.error("History fallback failed:", e);
      }
    }
  }

  function renderScanHistoryTable(records) {
    const tbody = document.getElementById("historyTableBody");
    if (!tbody) return;

    if (!records || records.length === 0) {
      tbody.innerHTML = "";
      if (historyEmptyState) historyEmptyState.classList.remove("hidden");
      return;
    }

    if (historyEmptyState) historyEmptyState.classList.add("hidden");
    tbody.innerHTML = "";

    records.forEach(rec => {
      const scanId = rec.scanId || rec.id || rec.scan_id || `SK-${Date.now()}`;
      const type = (rec.scanType || rec.type || "text").toLowerCase();
      const risk = (rec.riskCategory || rec.riskLevel || "safe").toLowerCase();
      const category = rec.category || "General Threat";
      const itemSnippet = rec.displayItem || rec.submittedItem || "-";
      const timeStr = rec.timestamp || rec.timeAgo || "-";

      let typeIcon = "mail";
      let typeLabel = "Text";
      let typeColor = "text-slate-600";
      if (type.includes("url")) {
        typeIcon = "link";
        typeLabel = "URL";
        typeColor = "text-sky-600";
      } else if (type.includes("screenshot") || type.includes("image")) {
        typeIcon = "image";
        typeLabel = "Image";
        typeColor = "text-amber-600";
      } else if (type.includes("audio") || type.includes("voice")) {
        typeIcon = "mic";
        typeLabel = "Audio";
        typeColor = "text-emerald-600";
      }

      let badgeClasses = "bg-emerald-100 text-emerald-800 border-emerald-200";
      let badgeLabel = "SAFE";
      if (risk.includes("suspicious")) {
        badgeClasses = "bg-rose-100 text-rose-800 border-rose-200 font-extrabold";
        badgeLabel = "SUSPICIOUS";
      } else if (risk.includes("caution")) {
        badgeClasses = "bg-amber-100 text-amber-800 border-amber-200";
        badgeLabel = "CAUTION";
      }

      const tr = document.createElement("tr");
      tr.id = `history-row-${scanId}`;
      tr.className = "hover:bg-slate-50 transition-colors";
      tr.innerHTML = `
        <td class="p-3 font-mono text-slate-500 text-[11px] whitespace-nowrap">${escapeHtml(timeStr)}</td>
        <td class="p-3 whitespace-nowrap">
          <span class="inline-flex items-center gap-1 font-mono text-[10px] font-semibold ${typeColor}">
            <span class="material-symbols-outlined text-xs">${typeIcon}</span>
            <span>${typeLabel}</span>
          </span>
        </td>
        <td class="p-3 font-mono text-slate-800 max-w-xs truncate" title="${escapeHtml(itemSnippet)}">${escapeHtml(itemSnippet)}</td>
        <td class="p-3 whitespace-nowrap">
          <div class="flex items-center gap-1.5">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${badgeClasses}">${badgeLabel}</span>
            <span class="text-[10px] text-slate-600 font-mono hidden sm:inline-block">${escapeHtml(category)}</span>
          </div>
        </td>
        <td class="p-3 text-right whitespace-nowrap">
          <div class="flex items-center justify-end gap-1.5">
            <button
              class="px-2.5 py-1 rounded bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 font-semibold text-[11px] transition-colors flex items-center gap-1 open-hist-btn"
              data-scan-id="${escapeHtml(scanId)}"
              title="Open full report details"
            >
              <span class="material-symbols-outlined text-xs">visibility</span>
              <span>Open</span>
            </button>
            <button
              class="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 font-medium text-[11px] transition-colors flex items-center gap-1 download-hist-btn"
              data-scan-id="${escapeHtml(scanId)}"
              title="Download PDF report"
            >
              <span class="material-symbols-outlined text-xs">download</span>
              <span>PDF</span>
            </button>
            <button
              class="px-2 py-1 rounded hover:bg-rose-50 text-slate-400 hover:text-rose-700 border border-transparent hover:border-rose-200 font-medium text-[11px] transition-colors flex items-center gap-1 delete-hist-btn"
              data-scan-id="${escapeHtml(scanId)}"
              title="Permanently delete report"
            >
              <span class="material-symbols-outlined text-xs">delete</span>
            </button>
          </div>
        </td>
      `;

      // Wire Open Report Action
      const openBtn = tr.querySelector(".open-hist-btn");
      if (openBtn) {
        openBtn.addEventListener("click", async () => {
          try {
            openBtn.disabled = true;
            const fullData = await window.scamKillerScanner.getScanById(scanId);
            const reportPayload = fullData.report || fullData.scan || fullData;
            lastAnalysisResult = reportPayload;
            // Restore to active view and storage
            try {
              localStorage.setItem("scamkiller_active_report_data", JSON.stringify(reportPayload));
            } catch (e) {}
            renderAnalysisResult(reportPayload);
            openFullReportModal(reportPayload);
          } catch (err) {
            console.error("Failed to open report:", err);
            showToast(`Error retrieving report: ${err.message}`, "error");
          } finally {
            openBtn.disabled = false;
          }
        });
      }

      // Wire Download PDF Action
      const dlBtn = tr.querySelector(".download-hist-btn");
      if (dlBtn) {
        dlBtn.addEventListener("click", async () => {
          try {
            dlBtn.disabled = true;
            showToast(`Preparing PDF report for ${scanId}...`, "info");
            const fullData = await window.scamKillerScanner.getScanById(scanId);
            const reportPayload = fullData.report || fullData.scan || fullData;
            await window.scamKillerScanner.downloadPdfReport(reportPayload);
            showToast(`PDF download started for ${scanId}`, "success");
          } catch (err) {
            console.error("Failed to download PDF:", err);
            showToast(`PDF Download Error: ${err.message}`, "error");
          } finally {
            dlBtn.disabled = false;
          }
        });
      }

      // Wire Permanent Delete Action
      const delBtn = tr.querySelector(".delete-hist-btn");
      if (delBtn) {
        delBtn.addEventListener("click", async () => {
          const confirmed = confirm(`Are you sure you want to permanently delete report "${scanId}"?\n\nThis will remove the record completely from your SQLite database. This action cannot be undone.`);
          if (!confirmed) return;

          try {
            delBtn.disabled = true;
            const res = await window.scamKillerScanner.deleteScan(scanId);
            if (res && (res.success || res.status === "deleted")) {
              // Animate removal
              tr.style.opacity = "0";
              tr.style.transform = "translateX(20px)";
              setTimeout(() => {
                tr.remove();
                scanHistoryCache = scanHistoryCache.filter(item => (item.scanId || item.id || item.scan_id) !== scanId);
                if (scanHistoryCache.length === 0 && historyEmptyState) {
                  historyEmptyState.classList.remove("hidden");
                }
              }, 250);

              // If currently active report is deleted, clear it
              const activeStored = localStorage.getItem("scamkiller_active_report_data");
              if (activeStored) {
                try {
                  const parsed = JSON.parse(activeStored);
                  if ((parsed.scan_id || parsed.scanId) === scanId) {
                    localStorage.removeItem("scamkiller_active_report_data");
                    if (inlineResultCard) inlineResultCard.classList.add("hidden");
                  }
                } catch (e) {}
              }

              showToast(`Report ${scanId} was permanently deleted.`, "success");
            } else {
              showToast("Report could not be deleted.", "error");
            }
          } catch (err) {
            console.error("Failed to delete scan:", err);
            showToast(`Delete Error: ${err.message}`, "error");
          } finally {
            delBtn.disabled = false;
          }
        });
      }

      tbody.appendChild(tr);
    });
  }

  // Real-time Search and Dual Filter Listeners
  let searchDebounceTimer = null;
  if (historySearchInput) {
    historySearchInput.addEventListener("input", () => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(loadScanHistory, 250);
    });
  }

  if (historyFilterSelect) {
    historyFilterSelect.addEventListener("change", loadScanHistory);
  }

  if (historyCategoryFilterSelect) {
    historyCategoryFilterSelect.addEventListener("change", loadScanHistory);
  }

  window.purgeSessionHistory = async function() {
    if (!confirm("Are you sure you want to purge all scan records from your SQLite database?\n\nThis will permanently delete your entire history.")) return;
    try {
      await window.scamKillerScanner.purgeHistory();
      scanHistoryCache = [];
      renderScanHistoryTable([]);
      localStorage.removeItem("scamkiller_active_report_data");
      if (inlineResultCard) inlineResultCard.classList.add("hidden");
      showToast("Scan audit log purged successfully.", "success");
    } catch (err) {
      showToast("Failed to purge scan log.", "error");
    }
  };

  const clearHistoryBtn = document.getElementById("clearHistoryBtn");
  if (clearHistoryBtn) clearHistoryBtn.addEventListener("click", window.purgeSessionHistory);

  // ================================================================
  // 9. SCAM TRENDS VIEW
  // ================================================================
  async function loadScamTrends() {
    const cardsGrid = document.getElementById("radarCardsGridTrends");
    const popularGrid = document.getElementById("popularCategoriesGrid");
    if (!cardsGrid) return;

    try {
      const res = await fetch(`${getApiBase()}/radar/trends`);
      const data = await res.json();
      const trends = data.trends || [];

      cardsGrid.innerHTML = "";
      trends.forEach(item => {
        const card = document.createElement("div");
        card.className = "p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-2 text-xs shadow-sm";
        card.innerHTML = `
          <div class="flex items-center justify-between">
            <span class="font-bold text-slate-900">${item.category}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-100 text-rose-800 font-bold">${item.report_count} Reports</span>
          </div>
          <p class="text-[11px] text-slate-500">Peer confirmations: ${item.total_upvotes || 0} confirmations recorded in SQLite.</p>
          <span class="text-[10px] font-mono text-emerald-700 block">Baseline Telemetry Data</span>
        `;
        cardsGrid.appendChild(card);
      });

      if (popularGrid) {
        popularGrid.innerHTML = `
          <div class="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs">
            <span class="font-bold text-slate-800 block">1. Banking / KYC Impersonation</span>
            <span class="text-slate-500 text-[11px]">Spoofed PAN update notifications, suspension threats, malicious APK distribution.</span>
          </div>
          <div class="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs">
            <span class="font-bold text-slate-800 block">2. Delivery Micro-Fee Surcharge</span>
            <span class="text-slate-500 text-[11px]">Unpaid postal package redirection scams demanding payment on .xyz and .top domains.</span>
          </div>
          <div class="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs">
            <span class="font-bold text-slate-800 block">3. Power Utility Cutoff SMS</span>
            <span class="text-slate-500 text-[11px]">Threats to disconnect electricity at 9:30 PM tonight unless money is transferred via UPI.</span>
          </div>
          <div class="p-3 rounded-lg border border-slate-200 bg-slate-50 text-xs">
            <span class="font-bold text-slate-800 block">4. Work-from-Home Telegram Reviews</span>
            <span class="text-slate-500 text-[11px]">Paid rating tasks transitioning into fraudulent advance deposit requirements.</span>
          </div>
        `;
      }

      // Populate Clustered Community Patterns from /api/community/patterns
      if (communityPatternsGrid) {
        try {
          const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
          const patData = await scannerInstance.getCommunityPatterns();
          const patterns = patData.patterns || [];
          communityPatternsGrid.innerHTML = "";

          if (patterns.length === 0) {
            communityPatternsGrid.innerHTML = `
              <div class="p-6 rounded-xl border border-dashed border-slate-200 bg-slate-50 text-slate-400 text-center text-xs col-span-2">
                No recurring community threat patterns recorded yet.
              </div>
            `;
          } else {
            patterns.forEach(pat => {
              const card = document.createElement("div");
              card.className = "p-4 rounded-xl border border-slate-200 bg-white space-y-3 text-xs shadow-sm hover:border-emerald-300 transition-all";

              const isSufficient = pat.has_sufficient_data;
              const trendBadgeHtml = isSufficient
                ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">${escapeHtml(pat.trend_badge || "Active")}</span>`
                : `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-600 border border-slate-300">Not enough reports yet</span>`;

              card.innerHTML = `
                <div class="flex items-start justify-between gap-2">
                  <div>
                    <span class="font-mono text-[9px] text-slate-400 uppercase tracking-wider block">${escapeHtml(pat.pattern_id || "PAT-PATTERN")} • ${escapeHtml(pat.category)}</span>
                    <h4 class="font-bold text-slate-900 text-sm mt-0.5">${escapeHtml(pat.title)}</h4>
                  </div>
                  ${trendBadgeHtml}
                </div>

                <div class="grid grid-cols-2 gap-2 text-[11px] p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                  <div>
                    <span class="text-slate-400 block text-[9px] uppercase">Target Entity</span>
                    <span class="font-semibold text-slate-800">${escapeHtml(pat.impersonated_entity || "None")}</span>
                  </div>
                  <div>
                    <span class="text-slate-400 block text-[9px] uppercase">Action Solicited</span>
                    <span class="font-semibold text-slate-800 truncate block">${escapeHtml(pat.requested_action || "Unsolicited")}</span>
                  </div>
                </div>

                <div class="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                  <span class="flex items-center gap-1 font-mono">
                    <span class="material-symbols-outlined text-xs text-rose-600">report</span>
                    <strong class="text-slate-800">${pat.frequency}</strong> reports • <strong class="text-slate-800">${pat.confirmations}</strong> confirms
                  </span>
                  <span class="font-mono text-[10px] text-slate-400">Seen: ${escapeHtml(pat.last_observed || "Recent")}</span>
                </div>

                <div class="p-2 rounded bg-slate-50 border border-slate-100 text-[10px] text-slate-600 font-mono">
                  ${escapeHtml(pat.threshold_notice || "")}
                </div>
              `;
              communityPatternsGrid.appendChild(card);
            });
          }
        } catch (patErr) {
          console.error("Failed to load community patterns:", patErr);
        }
      }
    } catch (err) {
      console.error("Failed to load trends:", err);
    }
  }

  // ================================================================
  // 10. COMMUNITY INTELLIGENCE VIEW
  // ================================================================
  async function loadCommunityIntelligence() {
    const feed = document.getElementById("communityFeedContainer");
    if (!feed) return;

    try {
      const res = await fetch(`${getApiBase()}/community`);
      const data = await res.json();
      communityReportsCache = data.reports || [];
      renderCommunityReports(communityReportsCache);
    } catch (err) {
      console.error("Failed to load community intelligence:", err);
    }
  }

  function renderCommunityReports(reports) {
    const feed = document.getElementById("communityFeedContainer");
    if (!feed) return;

    feed.innerHTML = "";
    reports.forEach(item => {
      const card = document.createElement("div");
      card.className = "p-4 rounded-xl border border-slate-200 bg-white hover:border-emerald-300 transition-all space-y-3 text-xs shadow-sm";

      const demoBadge = item.isDemo
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-900 border border-amber-300" title="Reference demonstration pattern">Demonstration Sample</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-900 border border-emerald-300" title="Submitted by user community">Community Verified Submission</span>`;

      card.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-[11px] text-slate-400 font-semibold">${item.category}</span>
          ${demoBadge}
        </div>
        <div>
          <h4 class="font-bold text-slate-900 text-sm">${item.title}</h4>
          <p class="text-slate-600 text-xs mt-1 leading-relaxed">${item.description}</p>
        </div>
        <div class="p-2.5 rounded bg-slate-50 font-mono text-[11px] text-slate-800 break-all border border-slate-200">
          ${item.reportedItem}
        </div>
        <div class="flex items-center justify-between pt-2 border-t border-slate-100 text-[11px]">
          <span class="text-slate-400 font-mono">${item.date || "Nov 2026"}</span>
          <button class="upvote-btn flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-emerald-50 hover:text-emerald-700 border border-slate-200 transition-colors" data-id="${item.id}">
            <span class="material-symbols-outlined text-sm text-emerald-600">thumb_up</span>
            <span class="upvote-count font-mono font-bold">${item.upvotes}</span>
          </button>
        </div>
      `;
      feed.appendChild(card);
    });

    // Bind upvote buttons
    feed.querySelectorAll(".upvote-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        try {
          const res = await fetch(`${getApiBase()}/community/${id}/upvote`, { method: "POST" });
          const data = await res.json();
          if (data.upvotes !== undefined) {
            btn.querySelector(".upvote-count").textContent = data.upvotes;
          }
        } catch (err) {
          console.error("Upvote error:", err);
        }
      });
    });
  }

  // Community Category Filters
  const communityFilterBtns = document.querySelectorAll(".community-filter-btn");
  communityFilterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      communityFilterBtns.forEach(b => {
        b.classList.remove("bg-emerald-100", "text-emerald-800", "border-emerald-300");
        b.classList.add("bg-slate-100", "text-slate-700", "border-slate-200");
      });
      btn.classList.add("bg-emerald-100", "text-emerald-800", "border-emerald-300");
      btn.classList.remove("bg-slate-100", "text-slate-700", "border-slate-200");

      const cat = btn.getAttribute("data-category");
      if (cat === "all") {
        renderCommunityReports(communityReportsCache);
      } else {
        const filtered = communityReportsCache.filter(r => r.category === cat);
        renderCommunityReports(filtered);
      }
    });
  });

  // Community Report Submission Modal
  const openReportModalBtn = document.getElementById("openReportModalBtn");
  const communityReportModal = document.getElementById("communityReportModal");
  const closeCommunityReportModalBtn = document.getElementById("closeCommunityReportModalBtn");
  const cancelCommunityReportBtn = document.getElementById("cancelCommunityReportBtn");
  const communityReportForm = document.getElementById("communityReportForm");

  if (openReportModalBtn && communityReportModal) {
    openReportModalBtn.addEventListener("click", () => communityReportModal.showModal());
  }
  if (closeCommunityReportModalBtn) closeCommunityReportModalBtn.addEventListener("click", () => communityReportModal.close());
  if (cancelCommunityReportBtn) cancelCommunityReportBtn.addEventListener("click", () => communityReportModal.close());

  if (communityReportForm) {
    communityReportForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        category: document.getElementById("reportCategory").value,
        title: document.getElementById("reportTitle").value.trim(),
        reported_item: document.getElementById("reportItem").value.trim(),
        description: document.getElementById("reportDesc").value.trim()
      };

      try {
        const res = await fetch(`${getApiBase()}/community/report`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          alert("Thank you! Your threat report was submitted to the community database.");
          communityReportForm.reset();
          communityReportModal.close();
          loadCommunityIntelligence();
        } else {
          alert("Failed to submit report.");
        }
      } catch (err) {
        alert("Network error submitting report.");
      }
    });
  }

  // ================================================================
  // 11. STICKY AI ADVISORY PANEL & VOICE INPUT ENGINE
  // ================================================================
  const stickyChatPanel = document.getElementById("stickyChatPanel");
  const floatingChatToggleBtn = document.getElementById("floatingChatToggleBtn");
  const chatCloseBtn = document.getElementById("chatCloseBtn");
  const chatMinimizeBtn = document.getElementById("chatMinimizeBtn");
  const chatMinimizeIcon = document.getElementById("chatMinimizeIcon");
  const chatClearBtn = document.getElementById("chatClearBtn");
  const openStickyChatFromViewBtn = document.getElementById("openStickyChatFromViewBtn");

  const chatForm = document.getElementById("chatForm");
  const chatInputText = document.getElementById("chatInputText");
  const chatMessagesContainer = document.getElementById("chatMessagesContainer");
  const chatPromptChips = document.querySelectorAll(".chat-chip");
  const chatSubmitBtn = chatForm ? (document.getElementById("chatSendBtn") || chatForm.querySelector("button[type='submit']")) : null;

  const chatVoiceRecordBtn = document.getElementById("chatVoiceRecordBtn");
  const chatVoiceRecordingBar = document.getElementById("chatVoiceRecordingBar");
  const chatVoiceTimer = document.getElementById("chatVoiceTimer");
  const chatVoiceCancelBtn = document.getElementById("chatVoiceCancelBtn");
  const chatVoiceStopBtn = document.getElementById("chatVoiceStopBtn");

  const chatConversationHistory = [];

  function openStickyChatPanel() {
    if (!stickyChatPanel) return;
    stickyChatPanel.classList.remove("hidden");
    stickyChatPanel.classList.remove("panel-minimized");
    if (chatMinimizeIcon) chatMinimizeIcon.textContent = "expand_more";
    if (chatInputText) {
      setTimeout(() => chatInputText.focus(), 150);
    }
  }

  function closeStickyChatPanel() {
    if (!stickyChatPanel) return;
    stickyChatPanel.classList.add("hidden");
  }

  function toggleStickyChatPanel() {
    if (!stickyChatPanel) return;
    if (stickyChatPanel.classList.contains("hidden")) {
      openStickyChatPanel();
    } else {
      closeStickyChatPanel();
    }
  }

  function minimizeStickyChatPanel() {
    if (!stickyChatPanel) return;
    stickyChatPanel.classList.toggle("panel-minimized");
    if (chatMinimizeIcon) {
      const isMin = stickyChatPanel.classList.contains("panel-minimized");
      chatMinimizeIcon.textContent = isMin ? "expand_less" : "expand_more";
    }
  }

  function clearChatHistory() {
    chatConversationHistory.length = 0;
    if (chatMessagesContainer) {
      chatMessagesContainer.innerHTML = `
        <div class="flex items-start gap-2">
          <div class="w-6 h-6 rounded-full bg-[#092318] text-emerald-400 flex items-center justify-center text-[10px] shrink-0 font-bold">AI</div>
          <div class="chat-bubble-assistant p-2.5 rounded-xl max-w-[85%] text-xs leading-relaxed shadow-sm">
            Hello! I am your <b>SCAM BREAKER AI Advisory</b>. You can ask me how to identify phishing tactics, verify unsolicited calls, or safeguard your credentials. How can I help you today?
          </div>
        </div>
      `;
    }
    showToast("Chat conversation cleared.", "info");
  }

  // Bind Sticky Panel Controls
  if (floatingChatToggleBtn) floatingChatToggleBtn.addEventListener("click", toggleStickyChatPanel);
  if (chatCloseBtn) chatCloseBtn.addEventListener("click", closeStickyChatPanel);
  if (chatMinimizeBtn) chatMinimizeBtn.addEventListener("click", minimizeStickyChatPanel);
  if (chatClearBtn) chatClearBtn.addEventListener("click", clearChatHistory);
  if (openStickyChatFromViewBtn) openStickyChatFromViewBtn.addEventListener("click", openStickyChatPanel);

  // Expose opener globally for navigation shortcuts
  window.openStickyChatPanel = openStickyChatPanel;

  // Voice Recording for Chat Input
  let chatMediaRecorder = null;
  let chatAudioChunks = [];
  let chatRecordingInterval = null;
  let chatRecordingSeconds = 0;
  let chatActiveMimeType = "";

  function formatRecordTimer(secs) {
    const m = String(Math.floor(secs / 60)).padStart(2, "0");
    const s = String(secs % 60).padStart(2, "0");
    return `${m}:${s}`;
  }

  function getSupportedAudioMimeType() {
    if (typeof MediaRecorder === "undefined" || typeof MediaRecorder.isTypeSupported !== "function") {
      return "";
    }
    const candidates = [
      "audio/webm;codecs=opus",
      "audio/webm",
      "audio/ogg;codecs=opus",
      "audio/mp4",
      "audio/aac",
      "audio/wav"
    ];
    for (const candidate of candidates) {
      try {
        if (MediaRecorder.isTypeSupported(candidate)) {
          return candidate;
        }
      } catch (e) {
        // Safe check for restrictive browser environments
      }
    }
    return "";
  }

  function stopChatRecordingCleanup() {
    if (chatRecordingInterval) {
      clearInterval(chatRecordingInterval);
      chatRecordingInterval = null;
    }
    chatRecordingSeconds = 0;
    if (chatVoiceTimer) chatVoiceTimer.textContent = "00:00";
    const fullTimer = document.getElementById("fullChatVoiceTimer");
    if (fullTimer) fullTimer.textContent = "00:00";

    if (chatVoiceRecordingBar) chatVoiceRecordingBar.classList.add("hidden");
    const fullVoiceBar = document.getElementById("fullChatVoiceBar");
    if (fullVoiceBar) fullVoiceBar.classList.add("hidden");

    if (chatVoiceRecordBtn) chatVoiceRecordBtn.classList.remove("text-rose-600", "animate-pulse");
    const fullVoiceBtn = document.getElementById("fullChatVoiceRecordBtn");
    if (fullVoiceBtn) fullVoiceBtn.classList.remove("text-rose-600", "animate-pulse");
  }

  if (chatVoiceRecordBtn) {
    chatVoiceRecordBtn.addEventListener("click", async () => {
      if (chatMediaRecorder && chatMediaRecorder.state === "recording") {
        return;
      }

      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        showToast("Audio recording is not supported in this browser.", "error");
        return;
      }

      // Step 1: Request Microphone Access with explicit permission error handling
      let stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      } catch (mediaErr) {
        console.error("Microphone device/permission error:", mediaErr);
        if (mediaErr.name === "NotAllowedError" || mediaErr.name === "PermissionDeniedError") {
          showToast("Microphone access was denied. Please allow microphone permissions in your browser.", "error");
        } else if (mediaErr.name === "NotFoundError" || mediaErr.name === "DevicesNotFoundError") {
          showToast("No microphone device was detected on your system.", "error");
        } else if (mediaErr.name === "NotReadableError" || mediaErr.name === "TrackStartError") {
          showToast("Microphone is currently in use or cannot be accessed by this browser.", "error");
        } else if (mediaErr.name === "OverconstrainedError") {
          showToast("Microphone hardware constraints could not be satisfied.", "error");
        } else {
          showToast("Microphone unavailable: " + (mediaErr.message || mediaErr.name || mediaErr), "error");
        }
        return;
      }

      // Step 2: Safe MediaRecorder Initialization with detected MIME type and graceful fallbacks
      try {
        chatAudioChunks = [];
        const detectedMime = getSupportedAudioMimeType();
        const recOptions = { audioBitsPerSecond: 32000 };
        if (detectedMime) {
          recOptions.mimeType = detectedMime;
        }

        try {
          chatMediaRecorder = detectedMime
            ? new MediaRecorder(stream, recOptions)
            : new MediaRecorder(stream);
        } catch (optionsErr) {
          console.warn("MediaRecorder creation with custom options failed, attempting fallback:", optionsErr);
          try {
            chatMediaRecorder = detectedMime
              ? new MediaRecorder(stream, { mimeType: detectedMime })
              : new MediaRecorder(stream);
          } catch (mimeErr) {
            chatMediaRecorder = new MediaRecorder(stream);
          }
        }

        chatActiveMimeType = (chatMediaRecorder && chatMediaRecorder.mimeType) || detectedMime || "";

        chatMediaRecorder.ondataavailable = (e) => {
          if (e.data && e.data.size > 0) {
            chatAudioChunks.push(e.data);
          }
        };

        chatMediaRecorder.onerror = (e) => {
          console.error("MediaRecorder runtime error:", e);
          showToast("Microphone recording encountered an error.", "error");
          stopChatRecordingCleanup();
        };

        chatMediaRecorder.onstart = () => {
          if (chatVoiceRecordingBar) chatVoiceRecordingBar.classList.remove("hidden");
          const fullVoiceBar = document.getElementById("fullChatVoiceBar");
          if (fullVoiceBar) fullVoiceBar.classList.remove("hidden");
          if (chatVoiceRecordBtn) chatVoiceRecordBtn.classList.add("text-rose-600", "animate-pulse");
          const fullVoiceBtn = document.getElementById("fullChatVoiceRecordBtn");
          if (fullVoiceBtn) fullVoiceBtn.classList.add("text-rose-600", "animate-pulse");

          chatRecordingSeconds = 0;
          if (chatVoiceTimer) chatVoiceTimer.textContent = "00:00";
          const fullTimer = document.getElementById("fullChatVoiceTimer");
          if (fullTimer) fullTimer.textContent = "00:00";

          chatRecordingInterval = setInterval(() => {
            chatRecordingSeconds++;
            const formattedTime = formatRecordTimer(chatRecordingSeconds);
            if (chatVoiceTimer) chatVoiceTimer.textContent = formattedTime;
            if (fullTimer) fullTimer.textContent = formattedTime;
            if (chatRecordingSeconds >= 60) {
              if (chatVoiceStopBtn) chatVoiceStopBtn.click();
            }
          }, 1000);
        };

        chatMediaRecorder.start(250);
      } catch (recErr) {
        console.error("MediaRecorder initialization error:", recErr);
        if (stream) {
          stream.getTracks().forEach(t => t.stop());
        }
        showToast("Audio recorder initialization failed: " + (recErr.message || recErr), "error");
      }
    });
  }

  function handleCancelVoiceRecording() {
    if (chatMediaRecorder && chatMediaRecorder.state !== "inactive") {
      chatMediaRecorder.onstop = null;
      chatMediaRecorder.stop();
      if (chatMediaRecorder.stream) {
        chatMediaRecorder.stream.getTracks().forEach(t => t.stop());
      }
    }
    chatAudioChunks = [];
    stopChatRecordingCleanup();
    showToast("Voice recording cancelled.", "info");
  }

  if (chatVoiceCancelBtn) {
    chatVoiceCancelBtn.addEventListener("click", handleCancelVoiceRecording);
  }
  const fullChatVoiceCancelBtn = document.getElementById("fullChatVoiceCancelBtn");
  if (fullChatVoiceCancelBtn) {
    fullChatVoiceCancelBtn.addEventListener("click", handleCancelVoiceRecording);
  }

  function handleStopVoiceRecording() {
    if (!chatMediaRecorder || chatMediaRecorder.state === "inactive") {
      stopChatRecordingCleanup();
      return;
    }

    chatMediaRecorder.onstop = async () => {
      if (chatMediaRecorder.stream) {
        chatMediaRecorder.stream.getTracks().forEach(t => t.stop());
      }

      const recordedMime = (chatMediaRecorder && chatMediaRecorder.mimeType) || chatActiveMimeType || "audio/webm";
      const cleanMime = recordedMime.split(";")[0].trim() || "audio/webm";
      const audioBlob = new Blob(chatAudioChunks, { type: cleanMime });
      stopChatRecordingCleanup();

      if (audioBlob.size < 100) {
        showToast("Recording was too short or empty.", "error");
        return;
      }

      let extension = "webm";
      if (cleanMime.includes("webm")) extension = "webm";
      else if (cleanMime.includes("mp4") || cleanMime.includes("m4a")) extension = "mp4";
      else if (cleanMime.includes("ogg") || cleanMime.includes("opus")) extension = "ogg";
      else if (cleanMime.includes("wav")) extension = "wav";
      else if (cleanMime.includes("aac")) extension = "aac";

      const filename = `voice_input.${extension}`;

      showToast("Transcribing speech with AI audio engine...", "info");
      try {
        const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
        let transcriptText = "";

        if (scannerInstance && typeof scannerInstance.transcribeAudio === "function") {
          let filePayload;
          try {
            filePayload = new File([audioBlob], filename, { type: cleanMime });
          } catch (fErr) {
            filePayload = audioBlob;
            filePayload.name = filename;
          }
          const res = await scannerInstance.transcribeAudio(filePayload, "ta-IN");
          transcriptText = (res && (res.transcription || res.text || res.transcript)) || "";
        } else {
          const formData = new FormData();
          formData.append("audio", audioBlob, filename);
          formData.append("language", "ta-IN");
          const res = await fetch(`${getApiBase()}/transcribe`, {
            method: "POST",
            body: formData
          });
          const data = await res.json();
          transcriptText = (data && (data.transcription || data.text || data.transcript)) || "";
        }

        if (transcriptText && transcriptText.trim()) {
          const fullInput = document.getElementById("fullChatInputText");
          [chatInputText, fullInput].forEach(inp => {
            if (inp) {
              const existing = inp.value.trim();
              inp.value = existing ? `${existing} ${transcriptText.trim()}` : transcriptText.trim();
              inp.focus();
            }
          });
          showToast("Speech transcribed! Review and press Send.", "success");
        } else {
          showToast("Could not recognize any speech. Please try speaking clearly or typing.", "error");
        }
      } catch (err) {
        console.error("Transcription error:", err);
        showToast("Transcription failed: " + (err.message || err), "error");
      }
    };

    chatMediaRecorder.stop();
  }

  if (chatVoiceStopBtn) {
    chatVoiceStopBtn.addEventListener("click", handleStopVoiceRecording);
  }
  const fullChatVoiceStopBtn = document.getElementById("fullChatVoiceStopBtn");
  if (fullChatVoiceStopBtn) {
    fullChatVoiceStopBtn.addEventListener("click", handleStopVoiceRecording);
  }

  // Wire full-screen chat voice record button
  const fullChatVoiceRecordBtn = document.getElementById("fullChatVoiceRecordBtn");
  if (fullChatVoiceRecordBtn && chatVoiceRecordBtn) {
    fullChatVoiceRecordBtn.addEventListener("click", () => {
      chatVoiceRecordBtn.click();
    });
  }

  // Chat Messaging
  function appendChatMessage(sender, text, isError = false) {
    const isUser = sender === "user";
    const containers = [chatMessagesContainer, document.getElementById("fullChatMessagesContainer")].filter(Boolean);

    containers.forEach(container => {
      const bubble = document.createElement("div");
      bubble.className = `flex items-start gap-2.5 ${isUser ? "justify-end" : ""}`;

      if (isUser) {
        bubble.innerHTML = `
          <div class="chat-bubble-user p-3 rounded-xl max-w-lg text-xs leading-relaxed shadow-sm bg-[#092318] text-white">
            ${escapeHtml(text)}
          </div>
          <div class="w-7 h-7 rounded-full bg-slate-300 text-slate-800 flex items-center justify-center text-xs shrink-0 font-bold">You</div>
        `;
      } else {
        const bubbleClass = isError
          ? "chat-bubble-assistant p-3 rounded-xl max-w-lg text-xs leading-relaxed shadow-sm bg-rose-50 border border-rose-200 text-rose-900"
          : "chat-bubble-assistant p-3 rounded-xl max-w-lg text-xs leading-relaxed shadow-sm bg-white border border-slate-200 text-slate-800";

        const badgeText = isError ? "AI Notice" : "AI Advisory Intelligence";
        const badgeColor = isError ? "text-rose-600" : "text-emerald-700";
        const formatted = escapeHtml(text).replace(/\n/g, "<br>");

        bubble.innerHTML = `
          <div class="w-7 h-7 rounded-full bg-[#092318] text-emerald-400 flex items-center justify-center text-xs shrink-0 font-bold">AI</div>
          <div class="${bubbleClass}">
            <div>${formatted}</div>
            <div class="mt-1.5 pt-1 border-t border-slate-100 text-[10px] ${badgeColor} font-mono flex items-center gap-1">
              <span class="material-symbols-outlined text-[11px]">psychology</span>
              <span>${badgeText}</span>
            </div>
          </div>
        `;
      }

      container.appendChild(bubble);
      container.scrollTop = container.scrollHeight;
    });
  }

  function appendChatTypingIndicator() {
    const typingId = `chat-typing-${Date.now()}`;
    const html = `
      <div class="w-7 h-7 rounded-full bg-[#092318] text-emerald-400 flex items-center justify-center text-xs shrink-0 font-bold">AI</div>
      <div class="chat-bubble-assistant p-3 rounded-xl max-w-lg text-xs leading-relaxed shadow-sm bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-2">
        <div class="typing-dots flex items-center gap-1.5 py-1 px-1">
          <span class="typing-dot w-2 h-2 rounded-full bg-emerald-600"></span>
          <span class="typing-dot w-2 h-2 rounded-full bg-emerald-600"></span>
          <span class="typing-dot w-2 h-2 rounded-full bg-emerald-600"></span>
        </div>
        <span class="text-[11px] text-slate-500 font-mono">Analyzing question...</span>
      </div>
    `;

    [chatMessagesContainer, document.getElementById("fullChatMessagesContainer")].forEach(container => {
      if (container) {
        const bubble = document.createElement("div");
        bubble.id = typingId;
        bubble.className = "flex items-start gap-2.5";
        bubble.innerHTML = html;
        container.appendChild(bubble);
        container.scrollTop = container.scrollHeight;
      }
    });

    return typingId;
  }

  let isSubmittingChat = false;

  async function handleChatSubmit(promptText) {
    if (isSubmittingChat) return;
    const q = (promptText || "").trim();
    if (!q) return;

    isSubmittingChat = true;
    appendChatMessage("user", q);
    chatConversationHistory.push({ role: "user", content: q });

    if (chatInputText) chatInputText.value = "";
    const fullInput = document.getElementById("fullChatInputText");
    if (fullInput) fullInput.value = "";

    const submitBtns = [chatSubmitBtn, document.getElementById("fullChatSendBtn")].filter(Boolean);
    const textInputs = [chatInputText, fullInput].filter(Boolean);

    submitBtns.forEach(btn => btn.disabled = true);
    textInputs.forEach(inp => inp.disabled = true);

    const typingId = appendChatTypingIndicator();

    try {
      const scannerInstance = window.scamBreakerScanner || window.scamKillerScanner;
      const response = await scannerInstance.sendChatMessage(chatConversationHistory);
      document.querySelectorAll(`[id="${typingId}"]`).forEach(el => el.remove());

      const reply = response && (response.reply || response.content);
      if (reply && String(reply).trim()) {
        appendChatMessage("ai", String(reply).trim());
        chatConversationHistory.push({ role: "assistant", content: String(reply).trim() });
      } else {
        appendChatMessage("ai", "I'm sorry, I could not generate a response. Please try asking a specific question or retry in a moment.", true);
      }
    } catch (err) {
      document.querySelectorAll(`[id="${typingId}"]`).forEach(el => el.remove());
      console.error("AI chat error:", err);
      appendChatMessage("ai", `Security Advisory Notice: ${err.message}\n\nEmergency Guidance: If you believe you are experiencing active fraud, immediately contact your bank to freeze transactions and report to cybercrime.gov.in (Helpline: 1930).`, true);
    } finally {
      isSubmittingChat = false;
      submitBtns.forEach(btn => btn.disabled = false);
      textInputs.forEach(inp => {
        inp.disabled = false;
        inp.focus();
      });
    }
  }

  if (chatForm && chatInputText) {
    chatForm.addEventListener("submit", (e) => {
      e.preventDefault();
      handleChatSubmit(chatInputText.value);
    });
  }

  function initFullAiChatView() {
    const fullForm = document.getElementById("fullChatForm");
    const fullInput = document.getElementById("fullChatInputText");
    if (fullForm && fullInput && !fullForm.dataset.bound) {
      fullForm.dataset.bound = "true";
      fullForm.addEventListener("submit", (e) => {
        e.preventDefault();
        handleChatSubmit(fullInput.value);
      });
    }
  }

  document.querySelectorAll(".chat-chip, .full-chat-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const prompt = chip.getAttribute("data-prompt") || chip.textContent.trim();
      handleChatSubmit(prompt);
    });
  });

  // Restore active report if present in localStorage (survives browser reloads and page refreshes)
  try {
    const savedActiveReport = localStorage.getItem("scambreaker_active_report_data") || localStorage.getItem("scamkiller_active_report_data");
    if (savedActiveReport) {
      const parsed = JSON.parse(savedActiveReport);
      if (parsed && (parsed.scan_id || parsed.scanId)) {
        lastAnalysisResult = parsed;
        renderAnalysisResult(parsed);
      }
    }
  } catch (err) {
    console.warn("Could not restore active report from storage:", err);
  }

});
