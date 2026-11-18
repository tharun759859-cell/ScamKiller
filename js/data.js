// SCAM KILLER — Data Stores & Preset Demonstration Payloads

const SCAM_KILLER_DATA = {
  // Recent scans matching the primary reference image
  recentScans: [
    {
      id: "scan-001",
      type: "url",
      icon: "link",
      submittedItem: "https://free-reward-claim.xyz",
      timeAgo: "2 min ago",
      timestamp: "2026-11-16 22:38",
      riskLevel: "suspicious", // 'suspicious' | 'caution' | 'safe'
      riskLabel: "Suspicious",
      badgeClass: "badge-suspicious",
      badgeIcon: "warning",
      layers: {
        content: {
          status: "flagged",
          summary: "Aggressive reward claim triggers and unsolicited lottery incentive detected.",
          indicators: ["Incentive lure", "Urgency language", "Unverified prize"]
        },
        urlStructure: {
          status: "flagged",
          summary: "High-risk cheap TLD (.xyz) registered 2 days ago. No legitimate organizational SSL identity.",
          indicators: ["Newly registered domain (48h)", "High-risk TLD (.xyz)", "Hidden WHOIS registrant"]
        },
        screenshot: {
          status: "skipped",
          summary: "Not applicable for standalone URL submission.",
          indicators: []
        },
        trustedIntel: {
          status: "flagged",
          summary: "Matches 4 global community phishing blacklists and CIRT warning advisories.",
          indicators: ["Flagged in OpenPhish feed", "Blacklisted by 4 SecOps feeds"]
        }
      },
      explanation: "This link uses a classic lure tactic offering unearned financial rewards hosted on an ephemeral domain (.xyz) created within the last 48 hours. Multiple threat databases have already marked this exact domain pattern for credential credential solicitation.",
      recommendedSteps: [
        "Do not click, open, or submit credentials on this link.",
        "Block the sender number or address that transmitted this link.",
        "Report the URL to your service provider or cyber crime portal."
      ]
    },
    {
      id: "scan-002",
      type: "message",
      icon: "mail",
      submittedItem: "You won a ₹10,000 gift card!",
      timeAgo: "5 min ago",
      timestamp: "2026-11-16 22:35",
      riskLevel: "caution",
      riskLabel: "Caution",
      badgeClass: "badge-caution",
      badgeIcon: "error",
      layers: {
        content: {
          status: "flagged",
          summary: "Promotional urgency and high-value unexpected gift voucher incentive.",
          indicators: ["High-value cash prize", "Unsolicited reward offer", "Vague redemption context"]
        },
        urlStructure: {
          status: "passed",
          summary: "No links detected inside this snippet.",
          indicators: []
        },
        screenshot: {
          status: "skipped",
          summary: "Text format scan.",
          indicators: []
        },
        trustedIntel: {
          status: "flagged",
          summary: "Text pattern matches common mass-SMS marketing and pre-phishing hooks.",
          indicators: ["Gift card lure signature: 82% similarity with known SMS spam"]
        }
      },
      explanation: "Unsolicited notifications announcing prizes, vouchers, or large sums of money often precede requests for 'processing fees' or banking credentials. Even without a direct link, interacting with this sender may expose your active contact to further social engineering.",
      recommendedSteps: [
        "Do not reply or confirm your phone number or identity.",
        "Never pay any 'processing fee' or deposit to claim a prize.",
        "Delete the message and block the sender."
      ]
    },
    {
      id: "scan-003",
      type: "url",
      icon: "link",
      submittedItem: "https://indian-bank-update.com",
      timeAgo: "10 min ago",
      timestamp: "2026-11-16 22:30",
      riskLevel: "safe",
      riskLabel: "No clear warning signs",
      badgeClass: "badge-safe",
      badgeIcon: "check_circle",
      layers: {
        content: {
          status: "passed",
          summary: "Standard portal structure without obvious credential scraping markers.",
          indicators: ["No active credential traps detected at audit time"]
        },
        urlStructure: {
          status: "caution",
          summary: "Generic name pattern inspected. Domain possesses standard SSL certificate.",
          indicators: ["Domain age > 14 months", "Valid Wildcard TLS certificate"]
        },
        screenshot: {
          status: "skipped",
          summary: "Not applicable.",
          indicators: []
        },
        trustedIntel: {
          status: "passed",
          summary: "Not currently reported on major phishing or malware blacklists.",
          indicators: ["Zero active CIRT warnings reported in past 30 days"]
        }
      },
      explanation: "While automated heuristic analysis detected no active malware or blacklist flags at this moment, automated checks cannot guarantee complete safety. Always verify that you are communicating directly with your bank's verified official portal.",
      recommendedSteps: [
        "Ensure your browser address bar shows the exact official corporate domain.",
        "Never enter OTPs or passwords if redirected unexpectedly.",
        "Contact your bank's official helpline printed on your debit card if uncertain."
      ]
    },
    {
      id: "scan-004",
      type: "message",
      icon: "chat",
      submittedItem: "USPS: Package ID #920182-US is on hold. Pay $1.95 redelivery fee at usps-customs-hold.online",
      timeAgo: "28 min ago",
      timestamp: "2026-11-16 22:12",
      riskLevel: "suspicious",
      riskLabel: "Suspicious",
      badgeClass: "badge-suspicious",
      badgeIcon: "warning",
      layers: {
        content: {
          status: "flagged",
          summary: "Impersonation of postal carrier demanding immediate micro-payment.",
          indicators: ["Postal carrier spoofing", "Fee solicitation ($1.95)", "Urgency deadline"]
        },
        urlStructure: {
          status: "flagged",
          summary: "Spoofed postal domain using generic TLD (.online) instead of official .com/.gov.",
          indicators: ["Fake brand domain", "Non-governmental TLD", "Cloudflare masked origin"]
        },
        screenshot: {
          status: "skipped",
          summary: "Raw text message.",
          indicators: []
        },
        trustedIntel: {
          status: "flagged",
          summary: "High volume smashishing campaign reported across multiple security forums.",
          indicators: ["Smishing campaign ID: US-POST-88", "1,400+ reports this week"]
        }
      },
      explanation: "Postal carriers do not notify customers of held packages via arbitrary text messages demanding credit card redelivery fees. This is a credential and credit-card harvesting scam.",
      recommendedSteps: [
        "Do not input payment card details on this website.",
        "Track package directly through the official carrier website or app.",
        "Forward spam SMS to your carrier's 7726 (SPAM) reporting service."
      ]
    },
    {
      id: "scan-005",
      type: "screenshot",
      icon: "image",
      submittedItem: "HDFC_Urgent_KYC_Suspension_Notice.png (OCR Text)",
      timeAgo: "42 min ago",
      timestamp: "2026-11-16 21:58",
      riskLevel: "suspicious",
      riskLabel: "Suspicious",
      badgeClass: "badge-suspicious",
      badgeIcon: "warning",
      layers: {
        content: {
          status: "flagged",
          summary: "Extracted text contains urgent threats of bank account freeze within 24 hours.",
          indicators: ["Account block threat", "Mandatory KYC link", "24-hour ultimatum"]
        },
        urlStructure: {
          status: "flagged",
          summary: "Extracted link leads to raw IP address / unverified redirect server.",
          indicators: ["Direct IP address URL in graphic", "No HTTPS encryption"]
        },
        screenshot: {
          status: "flagged",
          summary: "OCR extracted 3 fraud signals, mismatched font rendering, and spoofed bank logo.",
          indicators: ["Low-resolution official bank logo", "Typographical spelling errors", "Urgent CTA button"]
        },
        trustedIntel: {
          status: "flagged",
          summary: "Matches widespread PAN/Aadhaar banking KYC scam templates.",
          indicators: ["National cybercrime advisory issued for this graphic template"]
        }
      },
      explanation: "Banks in India never ask customers to update PAN/KYC details via unverified links sent in SMS or WhatsApp. Legitimate KYC updates require visiting a branch or the verified official banking app.",
      recommendedSteps: [
        "Never click or scan QR codes provided in unsolicited messages.",
        "Do not download any APK file suggested for 'remote support'.",
        "Report the fraudulent sender number to the cyber crime portal (cybercrime.gov.in)."
      ]
    }
  ],

  // Demo presets for easy testing in each scanner module
  presets: {
    messages: [
      {
        title: "Bank KYC Alert (Suspicious)",
        badge: "Suspicious",
        text: "Dear Customer, Your SBI account will be blocked today due to pending PAN KYC. Click here immediately to update: http://sbi-kyc-verify-portal.top/auth"
      },
      {
        title: "Lottery Prize Hook (Caution)",
        badge: "Caution",
        text: "Congratulations! Your mobile number won 2nd prize of ₹25,00,000 in KBC Lucky Draw. Contact Manager Vikram Sharma on WhatsApp +91-9876543210 to claim."
      },
      {
        title: "Legitimate Meeting Invite (No Clear Signs)",
        badge: "No Clear Signs",
        text: "Hi Alex, please confirm your attendance for the Q4 cybersecurity sync scheduled for tomorrow at 10:00 AM on Google Meet."
      },
      {
        title: "Part-time Job Scam (Suspicious)",
        badge: "Suspicious",
        text: "Work from home! Earn ₹3,000 to ₹8,000 daily by liking YouTube videos. No experience needed. Join our Telegram group @crypto_daily_cash now!"
      }
    ],

    urls: [
      {
        title: "Fake Netflix Billing (Suspicious)",
        badge: "Suspicious",
        url: "https://netflix-subscription-update-account.xyz/billing"
      },
      {
        title: "Shortened Link (Caution)",
        badge: "Caution",
        url: "https://bit.ly/claim-special-offer-2026"
      },
      {
        title: "Official Tech Documentation (No Clear Signs)",
        badge: "No Clear Signs",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security"
      },
      {
        title: "Cryptocurrency Airdrop (Suspicious)",
        badge: "Suspicious",
        url: "https://eth-free-airdrop-claim-now.online/connect-wallet"
      }
    ],

    screenshots: [
      {
        title: "Fake Electricity Bill Disconnection Alert",
        type: "suspicious",
        filename: "power_disconnection_notice.jpg",
        extractedText: "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please immediately contact our electricity officer Mr. Sharma at 9182374612.",
        notes: "High urgency threat, personal phone number instead of official utility board portal."
      },
      {
        title: "Fake Courier Delivery Failed SMS",
        type: "suspicious",
        filename: "courier_customs_failed.png",
        extractedText: "FEDEX: Package #FD-8921 is pending clearance. Surcharge of $2.40 unpaid. Visit http://fedex-clearance-tax.info/pay within 6 hours to prevent return to sender.",
        notes: "Brand spoofing, fake domain, artificial deadline."
      },
      {
        title: "Legitimate Order Confirmation Email",
        type: "safe",
        filename: "amazon_receipt_clean.png",
        extractedText: "Amazon.in: Your order #402-9182741-102948 has been shipped and will arrive on Thursday. Track your package in the Amazon app. Thank you for shopping with us.",
        notes: "Standard notification, does not solicit passwords or external third-party payment."
      }
    ]
  },

  // Community Intelligence reported cases
  communityReports: [
    {
      id: "REP-4091",
      category: "Banking / KYC",
      title: "HDFC Urgent PAN Update SMS with APK attachment",
      reportedItem: "sms: 'Your HDFC account KYC suspended. Install HDFC_Support.apk to reactivate'",
      date: "Nov 16, 2026",
      upvotes: 412,
      riskLevel: "suspicious",
      status: "Active Threat",
      description: "Fraudsters distributing remote access trojans (RAT) masquerading as banking utilities to intercept OTPs."
    },
    {
      id: "REP-4088",
      category: "Delivery Phishing",
      title: "India Post Delivery Address Update Scam",
      reportedItem: "https://indiapost-parcel-redirection[.]xyz",
      date: "Nov 15, 2026",
      upvotes: 285,
      riskLevel: "suspicious",
      status: "Active Threat",
      description: "Phishing page clones the official postal color scheme and prompts for credit card details for a ₹5 token redelivery fee."
    },
    {
      id: "REP-4075",
      category: "Work-from-Home",
      title: "Telegram Hotel Review Task Scam",
      reportedItem: "Telegram: @global_ratings_task_portal",
      date: "Nov 14, 2026",
      upvotes: 198,
      riskLevel: "suspicious",
      status: "Under Investigation",
      description: "Victims are paid small amounts (₹150-₹300) before being requested to deposit ₹50,000 for 'premium VIP merchant level'."
    },
    {
      id: "REP-4062",
      category: "Utility Bill",
      title: "Discom Power Disconnection WhatsApp Alert",
      reportedItem: "whatsapp: +91-9481928371",
      date: "Nov 13, 2026",
      upvotes: 350,
      riskLevel: "suspicious",
      status: "Active Threat",
      description: "Fake discom alerts demanding payment via AnyDesk/TeamViewer remote desktop installation."
    }
  ],

  // Comprehensive Trust Verification Directory
  trustDirectory: [
    {
      id: "sbi",
      name: "State Bank of India (SBI)",
      category: "Banking",
      domain: "https://onlinesbi.sbi",
      smsHeader: "SBIPAY, SBINB, ATMSBI",
      helpline: "1800-1234 / 1800-2100",
      rule: "SBI never asks customers to update KYC via APK downloads or third-party links.",
      citation: "RBI & State Bank of India Directory",
      status: "VERIFIED OFFICIAL"
    },
    {
      id: "hdfc",
      name: "HDFC Bank",
      category: "Banking",
      domain: "https://hdfcbank.com",
      smsHeader: "HDFCBK, HDFCBN",
      helpline: "1800-202-6161 / 1800-1600",
      rule: "HDFC Bank never asks for OTP or NetBanking password to cancel unauthorized transactions.",
      citation: "HDFC Bank Fraud Advisory",
      status: "VERIFIED OFFICIAL"
    },
    {
      id: "icici",
      name: "ICICI Bank",
      category: "Banking",
      domain: "https://icicibank.com",
      smsHeader: "ICICIB, ICICIN",
      helpline: "1800-1080",
      rule: "ICICI Bank never sends APK files or asks customers to install screen-sharing tools.",
      citation: "ICICI Bank Security Center",
      status: "VERIFIED OFFICIAL"
    },
    {
      id: "indiapost",
      name: "India Post (Department of Posts)",
      category: "Postal",
      domain: "https://indiapost.gov.in",
      smsHeader: "DOPIND, INPOST",
      helpline: "1800-266-6868",
      rule: "India Post does not send SMS demanding micro-fee redelivery payments on .xyz or .top domains.",
      citation: "Dept of Posts, Govt of India",
      status: "VERIFIED OFFICIAL"
    },
    {
      id: "electricity",
      name: "State Electricity Board (BESCOM / Discom)",
      category: "Utilities",
      domain: "State-specific (*.gov.in required)",
      smsHeader: "DISCOM, STATEPB",
      helpline: "1912 (TRAI National Power Helpline)",
      rule: "Discom offices never send WhatsApp threats to cut off power tonight unless you pay on personal UPI.",
      citation: "TRAI National 1912 Directory",
      status: "REGIONAL (.GOV.IN REQUIRED)"
    },
    {
      id: "netflix",
      name: "Netflix",
      category: "Streaming",
      domain: "https://netflix.com",
      smsHeader: "NETFLIX",
      helpline: "In-App Help Center Only (No Inbound Phone)",
      rule: "Netflix never requests billing or card updates through unsolicited SMS messages or phone calls.",
      citation: "Netflix Security Advisory",
      status: "IN-APP ONLY (NO INBOUND PHONE)"
    },
    {
      id: "amazon",
      name: "Amazon Customer Service",
      category: "E-Commerce",
      domain: "https://amazon.com / amazon.in",
      smsHeader: "AMAZON, AMZIN",
      helpline: "In-App Call-Back Only (No Direct Inbound Line)",
      rule: "Amazon customer care never calls from mobile numbers demanding remote app installation or gift card payment.",
      citation: "Amazon Security Policy",
      status: "IN-APP ONLY (NO INBOUND PHONE)"
    },
    {
      id: "paypal",
      name: "PayPal",
      category: "Banking",
      domain: "https://paypal.com",
      smsHeader: "PAYPAL",
      helpline: "In-App Resolution Center",
      rule: "PayPal never sends invoices demanding immediate cryptocurrency or gift card payments to dispute charges.",
      citation: "PayPal Security Center",
      status: "VERIFIED OFFICIAL"
    }
  ]
};

// Export to window for vanilla JS access
window.SCAM_KILLER_DATA = SCAM_KILLER_DATA;
