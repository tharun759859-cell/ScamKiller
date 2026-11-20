// SCAM BREAKER — Data Stores & Preset Demonstration Payloads

const SCAM_BREAKER_DATA = {
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

  // Comprehensive Trust Verification Directory (20 Certified Institutions)
  trustDirectory: [
    {
        "id": "sbi",
        "name": "State Bank of India (SBI)",
        "category": "Banking",
        "domain": "https://onlinesbi.sbi",
        "smsHeader": "SBIPAY, SBINB, ATMSBI, SBISMS",
        "helpline": "1800-1234 / 1800-2100 / 1800-11-2211",
        "rule": "SBI never sends APK downloads or asks for NetBanking passwords/OTPs to update KYC or reactivate accounts.",
        "citation": "RBI & State Bank of India Security Bureau",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "hdfc",
        "name": "HDFC Bank",
        "category": "Banking",
        "domain": "https://hdfcbank.com",
        "smsHeader": "HDFCBK, HDFCBN, HDFCLO",
        "helpline": "1800-202-6161 / 1800-1600 / 1800-258-3838",
        "rule": "HDFC Bank never asks customers to share OTP or password to cancel unauthorized transactions.",
        "citation": "HDFC Bank Cyber Security Advisory",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "icici",
        "name": "ICICI Bank",
        "category": "Banking",
        "domain": "https://icicibank.com",
        "smsHeader": "ICICIB, ICICIN, ICICIP",
        "helpline": "1800-1080 / 1800-200-3344",
        "rule": "ICICI Bank never sends WhatsApp attachments or asks users to install AnyDesk/QuickSupport.",
        "citation": "ICICI Bank Security Center",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "axis",
        "name": "Axis Bank",
        "category": "Banking",
        "domain": "https://axisbank.com",
        "smsHeader": "AXISBK, AXISBN",
        "helpline": "1800-419-5577 / 1800-103-5577",
        "rule": "Axis Bank representatives never ask customers to disclose 16-digit card numbers or CVV on support calls.",
        "citation": "Axis Bank Customer Safeguards",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "pnb",
        "name": "Punjab National Bank (PNB)",
        "category": "Banking",
        "domain": "https://pnbindia.in / netpnb.com",
        "smsHeader": "PNBSMS, PUNBNB",
        "helpline": "1800-180-2222 / 1800-103-2222",
        "rule": "PNB strictly notifies via official registered alphanumeric DLT SMS headers, never via personal 10-digit mobile numbers.",
        "citation": "Punjab National Bank Fraud Directorate",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "bob",
        "name": "Bank of Baroda",
        "category": "Banking",
        "domain": "https://bankofbaroda.in / bobibanking.com",
        "smsHeader": "BOBSMS, BOBTXN",
        "helpline": "1800-570-0 / 1800-258-4455",
        "rule": "Bank of Baroda never requires external software downloads for reward point redemptions.",
        "citation": "Bank of Baroda Security Directorate",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "kotak",
        "name": "Kotak Mahindra Bank",
        "category": "Banking",
        "domain": "https://kotak.com",
        "smsHeader": "KOTAKB, KMBOTP",
        "helpline": "1860-266-2666 / 1800-209-0000",
        "rule": "Kotak 811 account reactivations are conducted strictly inside the authentic Kotak mobile application.",
        "citation": "Kotak Mahindra Bank Cyber Cell",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "phonepe",
        "name": "PhonePe",
        "category": "Payments & UPI",
        "domain": "https://phonepe.com",
        "smsHeader": "PHONEP, PHPAYM",
        "helpline": "080-68727374 / In-App Support",
        "rule": "Receiving cashback or payments in PhonePe NEVER requires scanning a QR code or entering your UPI PIN.",
        "citation": "PhonePe Trust & Safety Advisory",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "gpay",
        "name": "Google Pay (GPay)",
        "category": "Payments & UPI",
        "domain": "https://pay.google.com",
        "smsHeader": "GOOGLP, GPAYIN",
        "helpline": "1800-419-0157 / In-App Support",
        "rule": "UPI PIN is entered exclusively to DEBIT money from your bank account. No PIN is required to receive money.",
        "citation": "Google Pay Security & NPCI Guidelines",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "paytm",
        "name": "Paytm Payments Bank",
        "category": "Payments & UPI",
        "domain": "https://paytm.com",
        "smsHeader": "PAYTM, PYTMSM",
        "helpline": "0120-4456-456",
        "rule": "Paytm customer agents never call from personal WhatsApp numbers to conduct KYC updates.",
        "citation": "Paytm Safety & Consumer Protection",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "indiapost",
        "name": "India Post (Department of Posts)",
        "category": "Government & Postal",
        "domain": "https://indiapost.gov.in",
        "smsHeader": "DOPIND, INPOST",
        "helpline": "1800-266-6868",
        "rule": "India Post does not send SMS demanding micro-fee redelivery payments on .xyz, .top, or .shop domains.",
        "citation": "Department of Posts, Ministry of Communications",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "incometax",
        "name": "Income Tax Department of India",
        "category": "Government & Tax",
        "domain": "https://incometax.gov.in",
        "smsHeader": "ITDEPT, CPCITR",
        "helpline": "1800-180-1961 / 1800-103-0025",
        "rule": "Tax refunds are deposited directly into pre-validated bank accounts. The IT department never sends refund links requesting card details.",
        "citation": "Central Board of Direct Taxes (CBDT)",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "uidai",
        "name": "UIDAI (Aadhaar)",
        "category": "Government & Identity",
        "domain": "https://uidai.gov.in / resident.uidai.gov.in",
        "smsHeader": "AADAAR, UIDAIP",
        "helpline": "1947",
        "rule": "UIDAI never asks citizens to email photocopies of documents or share OTPs over the phone to verify identity.",
        "citation": "Unique Identification Authority of India (UIDAI)",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "electricity",
        "name": "State Electricity Boards (Discoms)",
        "category": "Utilities",
        "domain": "State-specific official *.gov.in or authorized portal",
        "smsHeader": "DISCOM, STATEPB",
        "helpline": "1912 (National Power Consumer Helpline)",
        "rule": "Discoms never send WhatsApp messages threatening power disconnection tonight unless money is sent to a personal UPI ID.",
        "citation": "Ministry of Power & TRAI 1912 Advisory",
        "status": "REGIONAL (*.GOV.IN REQUIRED)"
    },
    {
        "id": "amazon",
        "name": "Amazon Customer Support",
        "category": "E-Commerce",
        "domain": "https://amazon.com / amazon.in",
        "smsHeader": "AMAZON, AMZIN",
        "helpline": "In-App Call-Back strictly (No published direct inbound toll-free line)",
        "rule": "Amazon never calls from personal numbers asking you to install AnyDesk or pay courier delivery release fees with Google Play gift cards.",
        "citation": "Amazon Consumer Security Policy",
        "status": "IN-APP ONLY (NO INBOUND PHONE)"
    },
    {
        "id": "flipkart",
        "name": "Flipkart",
        "category": "E-Commerce",
        "domain": "https://flipkart.com",
        "smsHeader": "FLPKRT, FKINDO",
        "helpline": "1800-202-9898 / In-App Support",
        "rule": "Flipkart lottery winnings or mystery gift cards demanding processing fees are fraudulent impersonations.",
        "citation": "Flipkart Consumer Protection Desk",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "microsoft",
        "name": "Microsoft Technical Support",
        "category": "Technology Support",
        "domain": "https://microsoft.com / support.microsoft.com",
        "smsHeader": "MSFT, MSFTIN",
        "helpline": "In-App / Official Portal Only (Never through search engine popups)",
        "rule": "Microsoft error popups on browsers locking your screen with a phone number are 100% tech support scams.",
        "citation": "Microsoft Threat Intelligence Center (MSTIC)",
        "status": "PORTAL ONLY (NO POPUP NUMBERS)"
    },
    {
        "id": "apple",
        "name": "Apple Support",
        "category": "Technology Support",
        "domain": "https://apple.com / support.apple.com",
        "smsHeader": "APPLE, AAPL",
        "helpline": "000800 1009009 / In-App Apple Support",
        "rule": "Apple Support never calls customers unrequested stating that iCloud or Apple ID is breached and requesting gift cards.",
        "citation": "Apple Privacy & Security Policy",
        "status": "VERIFIED OFFICIAL"
    },
    {
        "id": "netflix",
        "name": "Netflix",
        "category": "Streaming Services",
        "domain": "https://netflix.com",
        "smsHeader": "NETFLIX",
        "helpline": "In-App Resolution strictly",
        "rule": "Netflix membership suspension notices containing .top, .buzz, or .xyz links are phishing lures.",
        "citation": "Netflix Security Directorate",
        "status": "IN-APP ONLY (NO INBOUND PHONE)"
    },
    {
        "id": "telegram",
        "name": "Telegram",
        "category": "Social & Messaging",
        "domain": "https://telegram.org",
        "smsHeader": "TELEGR",
        "helpline": "In-App Settings -> Ask a Question",
        "rule": "Telegram has no official investment clubs, hotel review task portals, or high-yield trading bot managers.",
        "citation": "Telegram Security Advisory",
        "status": "NO OFFICIAL INVESTMENT CHANNELS"
    }
],

  // Authentic Regulatory & Cybersecurity Advisories (RBI, I4C, CERT-In, Sanchar Saathi, Interpol)
  officialAdvisories: [
    {
      id: "ADV-2026-01",
      category: "Digital Arrest & Fake Police Calls",
      source: "MHA / I4C National Cybercrime Advisory",
      sourceUrl: "https://cybercrime.gov.in",
      recency: "November 2026",
      type: "official",
      jurisdiction: "India (National Law Enforcement)",
      region: "South Asia",
      mapCoordinates: { x: 68.5, y: 45.2, label: "India (National)" },
      summary: "Fraudsters pose as CBI, ED, Police, or Customs officers over Skype/WhatsApp video calls wearing forged uniforms and fake ID badges, claiming your Aadhaar or parcel is linked to illegal narcotics or money laundering.",
      howItWorks: [
        "1. Impersonation Call: Automated IVR or WhatsApp video call claiming a parcel or SIM is tied to drugs or illegal money transfers.",
        "2. Coercion & Fake Studio: Caller wears police uniform against a fake police station background, showing forged Supreme Court arrest warrants.",
        "3. Isolation: Victim is ordered to stay on continuous video surveillance ('Digital Arrest') and forbidden from contacting family.",
        "4. Clearing Account Trap: Victim is coerced into transferring funds to an 'RBI verification account' with false promises of return after 2 hours."
      ],
      commonApproaches: [
        "High-definition fake police sets with forged Supreme Court seals",
        "Threatening immediate arrest and public humiliation",
        "Coerced continuous video call under the guise of judicial custody"
      ],
      warningSigns: [
        "Demands to stay on continuous video call under 'digital arrest'",
        "Display of forged arrest warrants, court orders, or Supreme Court letters",
        "Threatening immediate arrest unless money is transferred to 'safe RBI clearing accounts'",
        "Caller demands absolute secrecy from family members"
      ],
      safetyRecommendations: [
        "Remember: Indian law and police agencies DO NOT have any concept of 'digital arrest'.",
        "Police or CBI never interrogate citizens via Skype, WhatsApp, or video calls.",
        "Disconnect the call immediately and dial 1930 or visit cybercrime.gov.in.",
        "Never transfer money to any personal or unknown account claiming to be 'verification/clearing'."
      ]
    },
    {
      id: "ADV-2026-02",
      category: "Banking / KYC Suspension Threat",
      source: "Reserve Bank of India (RBI) Caution Notice",
      sourceUrl: "https://rbi.org.in",
      recency: "November 2026",
      type: "official",
      jurisdiction: "India (Banking & Financial)",
      region: "South Asia",
      mapCoordinates: { x: 67.2, y: 47.0, label: "India (Banking Hubs)" },
      summary: "Phishing SMS claiming your bank account or debit card will be suspended within 24 hours due to non-updated PAN/KYC, prompting you to click a link or download an APK file.",
      howItWorks: [
        "1. Panic SMS: Message alleges account blockage or card deactivation tonight unless PAN is linked.",
        "2. Deceptive Domain: Directs victim to a spoofed NetBanking page hosted on .top, .xyz, or .club.",
        "3. Credential Harvesting: Form steals username, password, date of birth, and triggers an OTP interception.",
        "4. Malicious APK: In advanced variants, prompts user to install 'Bank_KYC_Update.apk' which intercepts SMS OTPs in the background."
      ],
      commonApproaches: [
        "SMS sent from personal 10-digit mobile numbers (+91-9xxxxxxxxx) mimicking banks",
        "Fake PAN/Aadhaar re-verification web forms",
        "Sideloaded Android APKs with READ_SMS permissions"
      ],
      warningSigns: [
        "SMS sent from personal 10-digit mobile numbers instead of official bank header (e.g. SBIPAY, HDFCBK)",
        "Urgent 12-hour or 24-hour account suspension ultimatum",
        "Links pointing to unverified domains (.top, .xyz, .online, .club)",
        "Requests to install unknown Android APK files"
      ],
      safetyRecommendations: [
        "Never click links sent via SMS claiming to update KYC.",
        "Legitimate banks never request credentials, passwords, or OTPs via SMS or phone.",
        "Complete KYC only inside your official bank branch or official NetBanking portal.",
        "Report fraudulent SMS on the Chakshu portal (sancharsaathi.gov.in)."
      ]
    },
    {
      id: "ADV-2026-03",
      category: "Electricity Power Cutoff Threat",
      source: "Ministry of Power & State Discoms Warning",
      sourceUrl: "https://cybercrime.gov.in",
      recency: "November 2026",
      type: "official",
      jurisdiction: "India (State Power Utilities)",
      region: "South Asia",
      mapCoordinates: { x: 69.5, y: 43.5, label: "Northern & Western India" },
      summary: "Mass SMS/WhatsApp notices warning that your electricity connection will be disconnected tonight at 9:30 PM due to unpaid previous month bills, instructing you to call a personal phone number.",
      howItWorks: [
        "1. Evening Disconnection Warning: Mass SMS sent at late afternoon warning of power cutoff at 9:30 PM.",
        "2. Fake Officer Contact: SMS provides a personal phone number for the 'Executive Power Officer'.",
        "3. Screen-Sharing Lure: Fake officer claims system needs verification and directs victim to download QuickSupport or AnyDesk to pay ₹10 token bill.",
        "4. Screen Capture: Once remote access is active, fraudster monitors NetBanking or UPI PIN entry and drains accounts."
      ],
      commonApproaches: [
        "Artificial deadline timed for evening when official utility offices are closed",
        "Request to install remote screen-sharing tools to 'recharge ₹10'",
        "Payment requested to a personal UPI ID rather than registered utility biller"
      ],
      warningSigns: [
        "Specific artificial deadline ('disconnected tonight at 9:30 PM')",
        "Personal mobile number given to contact the 'Electricity Officer'",
        "Caller directs you to install AnyDesk, TeamViewer, or QuickSupport app",
        "Payment requested to a personal UPI ID rather than official utility biller"
      ],
      safetyRecommendations: [
        "Discoms never disconnect power without prior written official notices and registered biller alerts.",
        "Check your electricity bill status only on your state utility's official consumer portal or national 1912 helpline.",
        "Never install screen-sharing software on your phone upon a caller's request.",
        "Never make payments to personal mobile UPI IDs."
      ]
    },
    {
      id: "ADV-2026-04",
      category: "Fake Customs / Courier Parcel Surcharge",
      source: "India Post & Central Board of Indirect Taxes (CBIC)",
      sourceUrl: "https://indiapost.gov.in",
      recency: "November 2026",
      type: "official",
      jurisdiction: "India / International Transit",
      region: "Global Transit",
      mapCoordinates: { x: 52.0, y: 35.0, label: "Cross-Border Transit" },
      summary: "Fake SMS masquerading as India Post, FedEx, or DHL alleging an undelivered parcel due to incomplete address details, demanding a small ₹5 to ₹50 token fee to reschedule delivery.",
      howItWorks: [
        "1. Delivery Failure Alert: Smishing SMS claims postal parcel could not be delivered due to missing house number.",
        "2. Deceptive URL: Link leads to spoofed postal tracking portal with cloned logos.",
        "3. Address + Card Form: Form requests address update followed by a nominal redelivery micro-fee.",
        "4. Card Details Harvesting: Steals credit/debit card number, CVV, expiry, and intercepts dynamic transaction OTP."
      ],
      commonApproaches: [
        "Low micro-fee hurdle (₹25–₹50) to lower victim vigilance",
        "Shortened URL or lookalike domain (e.g., indiapost-redeliver.top)",
        "Fake parcel tracking timeline showing package stuck at regional sorting hub"
      ],
      warningSigns: [
        "SMS contains short or deceptive link (e.g., indiapost-track.top/pay)",
        "Token redelivery fee requested via credit/debit card on an insecure web form",
        "Form harvests full card numbers, CVVs, expiry dates, and then intercepts OTP"
      ],
      safetyRecommendations: [
        "India Post never requests micro-fee payments via external SMS links to update addresses.",
        "Track packages exclusively on official portals: indiapost.gov.in or official courier apps.",
        "Never enter banking card numbers on unfamiliar third-party websites."
      ]
    },
    {
      id: "ADV-2026-05",
      category: "Work-from-Home Telegram Review Task Fraud",
      source: "I4C CyberDost / Ministry of Home Affairs",
      sourceUrl: "https://cybercrime.gov.in",
      recency: "November 2026",
      type: "official",
      jurisdiction: "Cross-Border / Southeast Asia VoIP Hubs",
      region: "Southeast Asia",
      mapCoordinates: { x: 78.0, y: 52.0, label: "Cross-Border Call Hubs" },
      summary: "Unsolicited WhatsApp/Telegram offers promising ₹2,000–₹5,000 daily for liking YouTube videos or writing Google hotel reviews. Victims receive initial small payouts before being trapped into depositing large sums for 'VIP tasks'.",
      howItWorks: [
        "1. Cold Outreach: Recruiter contacts victim via WhatsApp from +62, +84, +234, or +1 claiming flexible part-time work.",
        "2. Bait Tasks: Victim completes 3 simple tasks (e.g. YouTube likes) and receives ₹300–₹500 in UPI to build trust.",
        "3. Telegram Group Escalation: Victim is migrated to a Telegram group filled with accomplices pretending to earn lakhs.",
        "4. Deposit Trap: Victim must deposit ₹5,000 to unlock 'prepaid merchant tasks', then ₹50,000 to 'withdraw frozen profits', losing everything."
      ],
      commonApproaches: [
        "Unsolicited job offer from international numbers on WhatsApp or Telegram",
        "Legitimate initial small payout sent to deceive victim into believing it is genuine",
        "High-pressure investment tiers with fabricated account balance dashboards"
      ],
      warningSigns: [
        "Unsolicited job offer from international numbers on WhatsApp or Telegram",
        "Initial small payout sent to gain victim trust",
        "Victim added to a Telegram 'task group' with fake members posting screenshots of huge earnings",
        "Demand to deposit personal money for 'prepaid crypto trading' or 'VIP merchant rating tasks'"
      ],
      safetyRecommendations: [
        "Legitimate employers never demand payment or deposits from employees for tasks.",
        "Stop interacting immediately if asked to deposit funds to withdraw earnings.",
        "Report fraudulent Telegram handles and bank account numbers to 1930 and cybercrime.gov.in."
      ]
    },
    {
      id: "ADV-2026-06",
      category: "Cross-Border Pig Butchering & Crypto Investment Fraud",
      source: "Interpol Purple Notice / Global Anti-Scam Alliance (GASA)",
      sourceUrl: "https://www.interpol.int",
      recency: "November 2026",
      type: "official",
      jurisdiction: "International Crime Syndicates",
      region: "Global",
      mapCoordinates: { x: 80.5, y: 48.0, label: "International Syndicate Networks" },
      summary: "Syndicate romance and high-yield investment scams where scammers build trust over weeks before introducing manipulated cryptocurrency trading platforms with fabricated profit charts.",
      howItWorks: [
        "1. Wrong Number / Social Encounter: Scammer reaches out on LinkedIn, dating apps, or WhatsApp pretending to be a wealthy investor.",
        "2. Long Grooming Period: Scammer shares daily life, wins trust, and gradually mentions insider crypto trading algorithms.",
        "3. Manipulated Exchange: Directs victim to a cloned web platform showing fabricated 200% returns.",
        "4. Exit Scam: When victim attempts withdrawal, platform demands 30% advance tax fee, locking all capital."
      ],
      commonApproaches: [
        "Weeks of polite, affluent persona building without early financial requests",
        "Proprietary fake MT5 or web trading portals with backend-manipulated candlestick graphs",
        "Extortionate 'liquidity fees' or 'tax clearance' demanded to release funds"
      ],
      warningSigns: [
        "Online acquaintance enthusiastically recommends an unlisted cryptocurrency platform",
        "Guaranteed 10%–30% daily returns with zero market downside",
        "Demands for upfront 'tax payments' or 'margin deposit' to process withdrawals"
      ],
      safetyRecommendations: [
        "Never invest money in unregulated third-party exchanges recommended by online contacts.",
        "Legitimate exchanges never require users to deposit additional capital to withdraw their own funds.",
        "Report cross-border fraud accounts to your bank and file an international IC3/Interpol notice."
      ]
    }
  ],

  // Comprehensive Scam Recovery Database (17 Playbooks, Helplines & Authorities)
  recoveryGuidance: {
    "bankHelplines": [
        {
            "name": "State Bank of India (SBI)",
            "phone": "1800 1234",
            "altPhone": "1800 2100 / 1800 11 2211",
            "smsBlock": "BLOCK <Account Number> to 567676",
            "portal": "https://onlinesbi.sbi"
        },
        {
            "name": "HDFC Bank",
            "phone": "1800 202 6161",
            "altPhone": "1800 1600 / 1800 258 3838",
            "smsBlock": "Call 1800 258 3838 immediately",
            "portal": "https://netbanking.hdfcbank.com"
        },
        {
            "name": "ICICI Bank",
            "phone": "1800 1080",
            "altPhone": "1800 200 3344",
            "smsBlock": "SMS BLOCK to 9215676766",
            "portal": "https://infinity.icicibank.com"
        },
        {
            "name": "Axis Bank",
            "phone": "1800 419 5577",
            "altPhone": "1800 103 5577",
            "smsBlock": "SMS BLOCK to 5676782",
            "portal": "https://axisbank.com"
        },
        {
            "name": "Punjab National Bank (PNB)",
            "phone": "1800 180 2222",
            "altPhone": "1800 103 2222",
            "smsBlock": "SMS HOTCARD <Card Number> to 5607040",
            "portal": "https://netpnb.com"
        },
        {
            "name": "Bank of Baroda",
            "phone": "1800 570 0",
            "altPhone": "1800 258 4455",
            "smsBlock": "Call 1800 570 0 to freeze NetBanking",
            "portal": "https://bobibanking.com"
        },
        {
            "name": "Kotak Mahindra Bank",
            "phone": "1860 266 2666",
            "altPhone": "1800 209 0000",
            "smsBlock": "Call 1860 266 2666 to hotlist",
            "portal": "https://kotak.com"
        }
    ],
    "paymentHelplines": [
        {
            "name": "PhonePe Fraud Escalation",
            "phone": "080-68727374",
            "altPhone": "In-App Dispute Center",
            "channel": "App / Phone",
            "rule": "Never approve collect requests to receive payments."
        },
        {
            "name": "Google Pay Dispute Team",
            "phone": "1800-419-0157",
            "altPhone": "In-App Support Chat",
            "channel": "App / Phone",
            "rule": "GPay does not ask for UPI PIN to process refunds."
        },
        {
            "name": "Paytm Cyber Helpdesk",
            "phone": "0120-3888388",
            "altPhone": "24x7 In-App Help",
            "channel": "App / Phone",
            "rule": "Never share Paytm passcode or OTP on incoming calls."
        },
        {
            "name": "NPCI / BHIM Escalation",
            "phone": "1800-120-1740",
            "altPhone": "https://npci.org.in",
            "channel": "Regulatory",
            "rule": "Central clearing grievance portal for inter-bank UPI issues."
        }
    ],
    "officialAuthorities": [
        {
            "name": "National Cyber Crime Helpline",
            "contact": "1930",
            "url": "https://cybercrime.gov.in",
            "note": "Citizen Financial Cyber Fraud Reporting System — Immediate fund freezing mechanism (Golden Hour)."
        },
        {
            "name": "DoT Sanchar Saathi (Chakshu)",
            "contact": "Online Portal",
            "url": "https://sancharsaathi.gov.in/sfc/",
            "note": "Official portal for reporting fraudulent mobile numbers, spoofed SMS, and scam callers."
        },
        {
            "name": "National Consumer Helpline",
            "contact": "1915",
            "url": "https://consumerhelpline.gov.in",
            "note": "E-commerce dispute resolution, merchant fraud, and non-delivery of purchased goods."
        },
        {
            "name": "CERT-In Cyber Incident Reporting",
            "contact": "1800-11-4949",
            "url": "https://cert-in.org.in",
            "note": "National incident coordination team for malware, system breaches, and advanced cyber threats."
        }
    ],
    "situations": {
        "money_transferred": {
            "id": "money_transferred",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Money Transferred / Financial Fraud",
            "subtitle": "Direct fund loss via IMPS, NEFT, RTGS, NetBanking or wire transfer",
            "urgency": "CRITICAL PRIORITY — GOLDEN HOUR PROTOCOL",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "payments",
            "goldenHourNotice": "Transactions reported within the first 2-3 hours have a significantly higher probability of inter-bank lien freezing before cash is withdrawn at destination ATMs.",
            "whatHappened": "You transferred funds to a scammer or unauthorized beneficiary following deceptive claims (KYC update, bill cutoff, fake job fee, or emergency family call).",
            "compromisedAssets": "Transferred capital, bank account number, sender IFSC, and potential mobile number exposure.",
            "immediateActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ],
            "checklist": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "Dial 1930 (Toll-Free, 24x7)",
                    "channel": "Phone"
                },
                {
                    "entity": "NCRP Citizen Portal",
                    "info": "https://cybercrime.gov.in",
                    "channel": "Web Portal"
                },
                {
                    "entity": "Your Bank Fraud Desk",
                    "info": "Phone number printed on back of Debit/Credit card",
                    "channel": "Direct Bank"
                }
            ],
            "evidence": [
                "Transaction Reference Number (UTR / RRN / IMPS Reference ID)",
                "Bank SMS notification received immediately after the debit",
                "Account statement or mini-statement showing debit timestamp and beneficiary details",
                "Screenshots of communication (WhatsApp, Telegram, SMS, or call log) with the perpetrator",
                "Beneficiary account number, IFSC code, or UPI ID where money was directed"
            ],
            "whatToAvoid": [
                "NEVER pay 'recovery clearance fees' or hire 'online ethical hackers' promising to retrieve lost funds. They are secondary scammers.",
                "Do NOT delete chat history, call recordings, or SMS threads with the perpetrator.",
                "Do NOT share OTPs with anyone claiming to represent your bank's 'reversal division'."
            ],
            "followUpPlan": "Monitor account statement weekly for recurring mandates. File an insurance claim if you hold cyber insurance. Maintain the police FIR copy for future banking dispute resolution.",
            "steps": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "priorityActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ]
        },
        "upi_fraud": {
            "id": "upi_fraud",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "UPI Fraud & Fake QR Code Scams",
            "subtitle": "Funds debited via UPI PIN entry, collect requests, or deceptive QR codes",
            "urgency": "CRITICAL PRIORITY — IMMEDIATE CONTAINMENT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "qr_code_scanner",
            "goldenHourNotice": "UPI transfers are instantaneous, but destination wallets and accounts can be frozen if reported to 1930 and payment apps within 2 hours.",
            "whatHappened": "You were induced to scan a QR code, approve a UPI collect request, or enter your secret UPI PIN under the false pretext of receiving a refund, cashback, or OLX buyer payment.",
            "compromisedAssets": "UPI PIN, primary linked bank account, UPI ID / VPA, phone number.",
            "immediateActions": [
                "Open your UPI app (PhonePe, GPay, Paytm) and immediately change/reset your UPI PIN using debit card details.",
                "Report the fraudulent transaction inside the UPI app's transaction history ('Report a Problem').",
                "Call National Cybercrime Helpline 1930 with the UPI Transaction ID (12-digit numeric RRN).",
                "Block the scammer's UPI handle (VPA) and mobile number."
            ],
            "checklist": [
                "Reset your UPI PIN immediately across all linked bank accounts.",
                "Open transaction details in PhonePe / GPay / Paytm and tap 'Raise Dispute / Report Fraud'.",
                "Dial 1930 and submit the 12-digit UPI RRN / Transaction ID.",
                "File an acknowledgment complaint at cybercrime.gov.in.",
                "Deregister UPI on your phone if unexpected collect requests keep arriving (Settings -> Deregister UPI).",
                "Check for unauthorized auto-debit mandates (Settings -> Autopay / Recurring Mandates -> Revoke)."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Phone"
                },
                {
                    "entity": "NPCI / BHIM Toll-Free",
                    "info": "1800-120-1740",
                    "channel": "NPCI Helpline"
                },
                {
                    "entity": "PhonePe Fraud Desk",
                    "info": "080-68727374",
                    "channel": "Payment App"
                },
                {
                    "entity": "Google Pay Security",
                    "info": "1800-419-0157",
                    "channel": "Payment App"
                },
                {
                    "entity": "Paytm Cyber Support",
                    "info": "0120-4456-456",
                    "channel": "Payment App"
                }
            ],
            "evidence": [
                "12-digit UPI Reference Number (RRN) from app transaction screen",
                "Beneficiary UPI VPA (e.g., fraudster@ybl, refund.desk@oksbi)",
                "Screenshot of the QR code scanned or collect request screen",
                "SMS received from bank confirming UPI debit",
                "Listing screenshot or marketplace chat (OLX, Quikr, Facebook Marketplace)"
            ],
            "whatToAvoid": [
                "REMEMBER: Entering your UPI PIN NEVER credits money to you. PIN is strictly for DEBITING funds.",
                "Never scan a QR code received on WhatsApp to 'receive' money or refunds.",
                "Do not accept incoming collect requests from unverified handles."
            ],
            "followUpPlan": "Audit all active UPI auto-pay authorizations. Set lower daily UPI transaction limits in your bank app (e.g. ₹10,000 max).",
            "steps": [
                "Reset your UPI PIN immediately across all linked bank accounts.",
                "Open transaction details in PhonePe / GPay / Paytm and tap 'Raise Dispute / Report Fraud'.",
                "Dial 1930 and submit the 12-digit UPI RRN / Transaction ID.",
                "File an acknowledgment complaint at cybercrime.gov.in.",
                "Deregister UPI on your phone if unexpected collect requests keep arriving (Settings -> Deregister UPI).",
                "Check for unauthorized auto-debit mandates (Settings -> Autopay / Recurring Mandates -> Revoke)."
            ],
            "priorityActions": [
                "Open your UPI app (PhonePe, GPay, Paytm) and immediately change/reset your UPI PIN using debit card details.",
                "Report the fraudulent transaction inside the UPI app's transaction history ('Report a Problem').",
                "Call National Cybercrime Helpline 1930 with the UPI Transaction ID (12-digit numeric RRN).",
                "Block the scammer's UPI handle (VPA) and mobile number."
            ]
        },
        "bank_compromise": {
            "id": "bank_compromise",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Bank Account & NetBanking Compromise",
            "subtitle": "Customer ID, NetBanking login password, or OTP disclosed",
            "urgency": "CRITICAL EMERGENCY — ACTIVE ACCOUNT RISK",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "account_balance",
            "goldenHourNotice": "Perpetrators with login access can register new beneficiaries, change mobile numbers, or apply for instant pre-approved loans.",
            "whatHappened": "You entered your bank Customer ID, password, or security questions on a cloned bank website or disclosed them to an impersonator over the phone.",
            "compromisedAssets": "NetBanking access, Customer ID, transaction passwords, security questions, linked accounts.",
            "immediateActions": [
                "Call your bank's 24x7 emergency helpline immediately to freeze your NetBanking access and user ID.",
                "If still logged in from a clean device, change login and transaction passwords immediately.",
                "Verify that no new unauthorized beneficiary has been added under your transfer limits.",
                "Review transaction limits and lower them to zero until security is re-established."
            ],
            "checklist": [
                "Call bank emergency hotline and instruct agent: 'Freeze my NetBanking access immediately due to compromise'.",
                "Request temporary block on all outward NEFT, RTGS, IMPS, and UPI transfers.",
                "Visit the official bank branch to reset Customer ID credentials and submit a written incident report.",
                "Check 'Manage Beneficiaries' and delete any unknown accounts added in the last 24-48 hours.",
                "Review registered email address and mobile number in profile settings to confirm they weren't altered.",
                "File an incident record on cybercrime.gov.in."
            ],
            "contacts": [
                {
                    "entity": "SBI Emergency Desk",
                    "info": "1800-11-2211 / SMS BLOCK <Acc> to 567676",
                    "channel": "Bank"
                },
                {
                    "entity": "HDFC Fraud Control",
                    "info": "1800-202-6161 / 1800-258-3838",
                    "channel": "Bank"
                },
                {
                    "entity": "ICICI Emergency Line",
                    "info": "1800-1080",
                    "channel": "Bank"
                },
                {
                    "entity": "National Cybercrime",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "National"
                }
            ],
            "evidence": [
                "URL of the spoofed banking website visited",
                "Phone numbers from which calls were received",
                "SMS logs showing OTP requests or unauthorized login attempts",
                "Timestamps of unauthorized login alerts"
            ],
            "whatToAvoid": [
                "Never read OTPs aloud to any caller claiming to be 'restoring your account'.",
                "Do not access banking accounts from public Wi-Fi or compromised phones.",
                "Do not re-use the compromised password on any other service."
            ],
            "followUpPlan": "Switch to hardware token or authenticator app 2FA. Re-enable SMS email debit alerts. Request new debit card and checkbook.",
            "steps": [
                "Call bank emergency hotline and instruct agent: 'Freeze my NetBanking access immediately due to compromise'.",
                "Request temporary block on all outward NEFT, RTGS, IMPS, and UPI transfers.",
                "Visit the official bank branch to reset Customer ID credentials and submit a written incident report.",
                "Check 'Manage Beneficiaries' and delete any unknown accounts added in the last 24-48 hours.",
                "Review registered email address and mobile number in profile settings to confirm they weren't altered.",
                "File an incident record on cybercrime.gov.in."
            ],
            "priorityActions": [
                "Call your bank's 24x7 emergency helpline immediately to freeze your NetBanking access and user ID.",
                "If still logged in from a clean device, change login and transaction passwords immediately.",
                "Verify that no new unauthorized beneficiary has been added under your transfer limits.",
                "Review transaction limits and lower them to zero until security is re-established."
            ]
        },
        "card_compromise": {
            "id": "card_compromise",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Credit / Debit Card Compromise",
            "subtitle": "16-digit card number, CVV, expiry date, or ATM PIN exposed",
            "urgency": "HIGH URGENCY — IMMEDIATE CARD HOTLISTING",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "credit_card",
            "goldenHourNotice": "Hotlisting your card stops automated e-commerce and international POS transactions immediately.",
            "whatHappened": "Card details were entered on a fraudulent payment checkout page, captured by a card skimmer, or exposed via an unencrypted form.",
            "compromisedAssets": "Card number, CVV, expiration date, cardholder name, linked credit line.",
            "immediateActions": [
                "Open your mobile banking app and toggle 'Card Lock / Block Card' immediately.",
                "Disable International Transactions and Online E-commerce Transactions in card controls.",
                "Call your card issuer helpline to hotlist the card and request a replacement card with a new number.",
                "Dispute any unauthorized transactions with your bank under zero-liability guidelines."
            ],
            "checklist": [
                "Block card instantly via mobile app (Card Controls -> Permanent Block / Hotlist).",
                "Alternatively, send emergency SMS block command (e.g. BLOCK <Last 4 Digits> to bank SMS shortcode).",
                "Call issuer to confirm card cancellation and request replacement with refreshed CVV.",
                "Review pending transactions on your card statement and mark unauthorized charges.",
                "Submit a formal Transaction Dispute Form (Chargeback Request) to your bank within 3 days for zero liability.",
                "File a complaint at cybercrime.gov.in with transaction details."
            ],
            "contacts": [
                {
                    "entity": "Card Issuer 24x7 Desk",
                    "info": "Number on back of physical card",
                    "channel": "Direct"
                },
                {
                    "entity": "RBI Ombudsman",
                    "info": "https://cms.rbi.org.in",
                    "channel": "Escalation"
                },
                {
                    "entity": "National Cyber Helpline",
                    "info": "1930",
                    "channel": "National"
                }
            ],
            "evidence": [
                "Merchant names and amounts of unauthorized charges from statement",
                "SMS alerts received with OTP or international currency debit alerts",
                "URL of the checkout portal where card details were typed"
            ],
            "whatToAvoid": [
                "Do not keep the card active thinking 'only a small amount was taken' — fraudsters test with ₹1 before draining limits.",
                "Never share new card replacement details over WhatsApp."
            ],
            "followUpPlan": "Keep International and Contactless (NFC) limits disabled by default when not traveling. Set low daily spending caps.",
            "steps": [
                "Block card instantly via mobile app (Card Controls -> Permanent Block / Hotlist).",
                "Alternatively, send emergency SMS block command (e.g. BLOCK <Last 4 Digits> to bank SMS shortcode).",
                "Call issuer to confirm card cancellation and request replacement with refreshed CVV.",
                "Review pending transactions on your card statement and mark unauthorized charges.",
                "Submit a formal Transaction Dispute Form (Chargeback Request) to your bank within 3 days for zero liability.",
                "File a complaint at cybercrime.gov.in with transaction details."
            ],
            "priorityActions": [
                "Open your mobile banking app and toggle 'Card Lock / Block Card' immediately.",
                "Disable International Transactions and Online E-commerce Transactions in card controls.",
                "Call your card issuer helpline to hotlist the card and request a replacement card with a new number.",
                "Dispute any unauthorized transactions with your bank under zero-liability guidelines."
            ]
        },
        "password_stolen": {
            "id": "password_stolen",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Stolen Password & Account Takeover",
            "subtitle": "Primary account password disclosed, phished, or leaked in data breach",
            "urgency": "HIGH URGENCY — CREDENTIAL CONTAINMENT",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "vpn_key",
            "goldenHourNotice": "Attackers leverage stolen passwords across multiple platforms via automated credential stuffing scripts.",
            "whatHappened": "Your password was captured on a phishing page, intercepted on unsecured public Wi-Fi, or surfaced in a credential dump.",
            "compromisedAssets": "Login access to affected service, potentially other accounts sharing the same password.",
            "immediateActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ],
            "checklist": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "contacts": [
                {
                    "entity": "Google Account Recovery",
                    "info": "https://accounts.google.com/signin/recovery",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Microsoft Security",
                    "info": "https://account.live.com/password/reset",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Apple ID Support",
                    "info": "https://iforgot.apple.com",
                    "channel": "Self-Service"
                }
            ],
            "evidence": [
                "Security alert emails received notifying of login from unknown IP or city",
                "Phishing email or URL where the credential was typed",
                "Timestamp when access was lost or changed"
            ],
            "whatToAvoid": [
                "Never re-use passwords across email, banking, and social accounts.",
                "Do not store passwords in unencrypted plaintext notes or screenshots."
            ],
            "followUpPlan": "Run a scan on haveibeenpwned.com to check for leaked accounts. Rotate all critical service credentials.",
            "steps": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "priorityActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ]
        },
        "email_compromise": {
            "id": "email_compromise",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Email Account Compromise",
            "subtitle": "Gmail, Outlook, Yahoo or corporate email account accessed by unauthorized parties",
            "urgency": "CRITICAL EMERGENCY — ROOT IDENTITY AT RISK",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "mark_email_unread",
            "goldenHourNotice": "Email is the root of your digital identity. Attackers use it to trigger password resets on your banks and shopping portals.",
            "whatHappened": "An attacker gained access to your primary email address and can read private communications and reset passwords on linked accounts.",
            "compromisedAssets": "Primary inbox, password reset mechanisms for all linked banking, social, and government portals.",
            "immediateActions": [
                "Initiate official account recovery immediately via Google / Microsoft / Yahoo recovery portals.",
                "Inspect and remove unauthorized forwarding rules and email filters (attackers create rules to hide bank alerts).",
                "Revoke all active device sessions and OAuth tokens.",
                "Change password and configure hardware or authenticator app 2FA."
            ],
            "checklist": [
                "Recover account using trusted phone number or recovery email.",
                "Navigate to Settings -> Forwarding & POP/IMAP: Delete any unauthorized forwarding addresses.",
                "Navigate to Settings -> Filters and Blocked Addresses: Delete filters routing bank emails to Trash.",
                "Go to Security -> Your Devices: Revoke all unrecognized phones, laptops, and locations.",
                "Review Security -> Third-party apps with account access: Revoke unknown application permissions.",
                "Alert your banks and primary financial institutions that your email was compromised.",
                "Update contact email addresses across banking portals if recovery is delayed."
            ],
            "contacts": [
                {
                    "entity": "Google Security Team",
                    "info": "https://myaccount.google.com/security-checkup",
                    "channel": "Portal"
                },
                {
                    "entity": "Microsoft Account Care",
                    "info": "https://account.microsoft.com/security",
                    "channel": "Portal"
                },
                {
                    "entity": "CERT-In Incident Desk",
                    "info": "incident@cert-in.org.in",
                    "channel": "Email"
                }
            ],
            "evidence": [
                "IP addresses and browser user-agents listed in recent security activity logs",
                "Headers of unauthorized emails sent from your account to your contacts",
                "Screenshots of malicious forwarding rules configured"
            ],
            "whatToAvoid": [
                "Do not overlook inbox rules and forwarding filters — attackers rely on them to silently intercept OTPs even after password changes.",
                "Never use your compromised email to receive password reset tokens until it is fully sanitized."
            ],
            "followUpPlan": "Download account audit logs. Set up Passkeys for hardware-backed, phishing-resistant authentication.",
            "steps": [
                "Recover account using trusted phone number or recovery email.",
                "Navigate to Settings -> Forwarding & POP/IMAP: Delete any unauthorized forwarding addresses.",
                "Navigate to Settings -> Filters and Blocked Addresses: Delete filters routing bank emails to Trash.",
                "Go to Security -> Your Devices: Revoke all unrecognized phones, laptops, and locations.",
                "Review Security -> Third-party apps with account access: Revoke unknown application permissions.",
                "Alert your banks and primary financial institutions that your email was compromised.",
                "Update contact email addresses across banking portals if recovery is delayed."
            ],
            "priorityActions": [
                "Initiate official account recovery immediately via Google / Microsoft / Yahoo recovery portals.",
                "Inspect and remove unauthorized forwarding rules and email filters (attackers create rules to hide bank alerts).",
                "Revoke all active device sessions and OAuth tokens.",
                "Change password and configure hardware or authenticator app 2FA."
            ]
        },
        "whatsapp_social_takeover": {
            "id": "whatsapp_social_takeover",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "WhatsApp & Social Media Hijacking",
            "subtitle": "WhatsApp 6-digit registration PIN tricked, or Instagram/Facebook hijacked",
            "urgency": "HIGH URGENCY — PREVENT CONTACT FRAUD",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "forum",
            "goldenHourNotice": "Scammers immediately message your close family, friends, and colleagues begging for urgent medical or emergency UPI transfers.",
            "whatHappened": "You shared a 6-digit SMS code or fell for a call forwarding code (*21*...), giving an attacker access to your WhatsApp or social account.",
            "compromisedAssets": "Chat history, personal contact list, ability to impersonate you to friends and family.",
            "immediateActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ],
            "checklist": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "contacts": [
                {
                    "entity": "WhatsApp Support Email",
                    "info": "support@whatsapp.com",
                    "channel": "Email"
                },
                {
                    "entity": "Instagram Hacked Recovery",
                    "info": "https://instagram.com/hacked",
                    "channel": "Portal"
                },
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Reporting"
                }
            ],
            "evidence": [
                "Phone numbers from which verification codes were requested",
                "Screenshots of messages sent by hacker to your contacts demanding funds",
                "UPI handles where the hacker asked your friends to transfer money"
            ],
            "whatToAvoid": [
                "Never pay ransom to anyone claiming they will return your account for money.",
                "Never share 6-digit verification codes sent to your phone with anyone, even contacts who appear to be friends."
            ],
            "followUpPlan": "Enable biometric app lock. Educate close contacts on your verified emergency communication protocol.",
            "steps": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "priorityActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ]
        },
        "malicious_apk": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "remote_access_fraud": {
            "id": "remote_access_fraud",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Remote Access App Fraud",
            "subtitle": "Installed AnyDesk, TeamViewer, RustDesk, or QuickSupport at caller request",
            "urgency": "IMMEDIATE ACTIVE THREAT — SEVER CONNECTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "phonelink_lock",
            "goldenHourNotice": "The scammer has active, direct remote viewing and touch control of your phone or computer screen.",
            "whatHappened": "A caller claiming to represent customer care, bank support, or electricity board guided you to install a remote desktop app and share your 9-digit session code.",
            "compromisedAssets": "Full screen visibility, input control, banking screens, incoming OTP banners.",
            "immediateActions": [
                "Turn on AIRPLANE MODE immediately or physically power off the device to cut the attacker's connection.",
                "Uninstall AnyDesk, TeamViewer, QuickSupport, or RustDesk immediately.",
                "Call your bank from another phone immediately to freeze your NetBanking and debit card.",
                "Do NOT log into your bank until the application is confirmed uninstalled and permissions revoked."
            ],
            "checklist": [
                "Turn on Airplane Mode immediately or turn off Wi-Fi router / mobile hotspot.",
                "Terminate the active remote access session inside the app.",
                "Uninstall the remote access software (AnyDesk, TeamViewer, RustDesk, Splashtop).",
                "Revoke screen recording and accessibility permissions under Settings.",
                "Call bank emergency hotline immediately and report: 'Remote access tool was installed, freeze my accounts'.",
                "Check recent outgoing SMS and calls to ensure the caller did not execute background commands.",
                "From a separate trusted device, change your NetBanking and primary email passwords."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime",
                    "info": "1930",
                    "channel": "National"
                },
                {
                    "entity": "AnyDesk Fraud Reporting",
                    "info": "https://anydesk.com/en/contact/abuse",
                    "channel": "Vendor Abuse"
                },
                {
                    "entity": "TeamViewer Security",
                    "info": "https://www.teamviewer.com/en/support/report-a-scam/",
                    "channel": "Vendor Abuse"
                }
            ],
            "evidence": [
                "9-digit or 10-digit remote session code shared with the caller",
                "Incoming caller phone number and time of the remote session",
                "App version and download link provided by caller"
            ],
            "whatToAvoid": [
                "Legitimate customer support NEVER asks you to install AnyDesk or TeamViewer to process a refund.",
                "Do not enter passwords or open banking apps while anyone has remote access to your device."
            ],
            "followUpPlan": "Install an authentic mobile antivirus (Sophos, Bitdefender). Never share 9-digit session codes with inbound callers.",
            "steps": [
                "Turn on Airplane Mode immediately or turn off Wi-Fi router / mobile hotspot.",
                "Terminate the active remote access session inside the app.",
                "Uninstall the remote access software (AnyDesk, TeamViewer, RustDesk, Splashtop).",
                "Revoke screen recording and accessibility permissions under Settings.",
                "Call bank emergency hotline immediately and report: 'Remote access tool was installed, freeze my accounts'.",
                "Check recent outgoing SMS and calls to ensure the caller did not execute background commands.",
                "From a separate trusted device, change your NetBanking and primary email passwords."
            ],
            "priorityActions": [
                "Turn on AIRPLANE MODE immediately or physically power off the device to cut the attacker's connection.",
                "Uninstall AnyDesk, TeamViewer, QuickSupport, or RustDesk immediately.",
                "Call your bank from another phone immediately to freeze your NetBanking and debit card.",
                "Do NOT log into your bank until the application is confirmed uninstalled and permissions revoked."
            ]
        },
        "sim_swap": {
            "id": "sim_swap",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "SIM Swap & Sudden Mobile Disconnection",
            "subtitle": "Phone unexpectedly displays 'No Service' or invalid SIM while attacker controls number",
            "urgency": "CRITICAL EMERGENCY — PHYSICAL CARRIER ACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "sim_card_alert",
            "goldenHourNotice": "Once a SIM swap succeeds, attackers intercept all SMS-based banking OTPs and login codes.",
            "whatHappened": "An attacker tricked your mobile carrier into porting your phone number or converting it to an eSIM using forged identity documents.",
            "compromisedAssets": "Phone number, SMS OTP reception, two-factor authentication for all accounts.",
            "immediateActions": [
                "If your phone shows 'No Service' where coverage is normally strong, contact your mobile operator immediately from another phone.",
                "Immediately notify your banks to freeze accounts linked to that mobile number.",
                "Visit the nearest physical telecom store (Jio, Airtel, Vi) with your original government ID to reclaim your SIM.",
                "Access email and cloud accounts to switch 2FA from SMS to an Authenticator App."
            ],
            "checklist": [
                "Call telecom customer care (Jio: 198, Airtel: 121, Vi: 199) and demand immediate block on the SIM swap.",
                "Notify your bank emergency desk: 'I am experiencing a SIM swap fraud, block all mobile banking OTP transactions'.",
                "Visit the nearest physical branch of your telecom provider with original Aadhaar / voter ID.",
                "Re-issue a new physical SIM card to regain control of your mobile number.",
                "Once restored, verify bank balances and call 1930 if unauthorized transactions occurred.",
                "Check Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to verify all mobile numbers registered in your name."
            ],
            "contacts": [
                {
                    "entity": "Airtel Emergency Desk",
                    "info": "121 / 198",
                    "channel": "Telecom"
                },
                {
                    "entity": "Jio Care",
                    "info": "198 / 1800-889-9999",
                    "channel": "Telecom"
                },
                {
                    "entity": "Vodafone Idea (Vi)",
                    "info": "199",
                    "channel": "Telecom"
                },
                {
                    "entity": "DoT Sanchar Saathi TAFCOP",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                }
            ],
            "evidence": [
                "Timestamp when phone signal abruptly disappeared",
                "Any SMS received prior to disconnection (e.g. 'eSIM request initiated' or 'PORT request')",
                "New SIM ICCID number provided upon store reissuance"
            ],
            "whatToAvoid": [
                "Do NOT dismiss unexpected 'No Service' as a routine network glitch if others nearby have good coverage.",
                "Never approve or forward SIM upgrade or eSIM conversion SMS messages."
            ],
            "followUpPlan": "Ask telecom carrier to place a 'SIM Lock' or PIN protection on your account. Migrate all critical 2FA away from SMS to hardware Passkeys.",
            "steps": [
                "Call telecom customer care (Jio: 198, Airtel: 121, Vi: 199) and demand immediate block on the SIM swap.",
                "Notify your bank emergency desk: 'I am experiencing a SIM swap fraud, block all mobile banking OTP transactions'.",
                "Visit the nearest physical branch of your telecom provider with original Aadhaar / voter ID.",
                "Re-issue a new physical SIM card to regain control of your mobile number.",
                "Once restored, verify bank balances and call 1930 if unauthorized transactions occurred.",
                "Check Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to verify all mobile numbers registered in your name."
            ],
            "priorityActions": [
                "If your phone shows 'No Service' where coverage is normally strong, contact your mobile operator immediately from another phone.",
                "Immediately notify your banks to freeze accounts linked to that mobile number.",
                "Visit the nearest physical telecom store (Jio, Airtel, Vi) with your original government ID to reclaim your SIM.",
                "Access email and cloud accounts to switch 2FA from SMS to an Authenticator App."
            ]
        },
        "identity_theft": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "shopping_fraud": {
            "id": "shopping_fraud",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Online Shopping & Fake E-Commerce Fraud",
            "subtitle": "Paid for goods on a fake Instagram/Facebook store or deceptive clone site with no delivery",
            "urgency": "MODERATE PRIORITY — TRANSACTION DISPUTE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "shopping_bag",
            "goldenHourNotice": "Card and payment gateway chargebacks must be initiated within the scheme's specified dispute window (typically 30-60 days).",
            "whatHappened": "You purchased products from an unverified social media advertisement or cloned retail portal offering unrealistic 80-90% discounts.",
            "compromisedAssets": "Payment funds, postal address, phone number, potentially payment card details.",
            "immediateActions": [
                "Contact your card issuer or payment gateway (Razorpay, Cashfree, PayU) to initiate a chargeback for 'goods not delivered'.",
                "Document the product advertisement, payment receipt, and order confirmation.",
                "File a consumer grievance on the National Consumer Helpline (1915 / consumerhelpline.gov.in).",
                "Report the fraudulent Instagram/Facebook page or website domain to the hosting registrar and DoT Chakshu."
            ],
            "checklist": [
                "Request a formal chargeback from your credit/debit card provider for non-receipt of merchandise.",
                "Check payment receipt to identify the payment aggregator (Razorpay, PayU, CCavenue) and file a fraud report directly with them.",
                "File a complaint on National Consumer Helpline (consumerhelpline.gov.in or call 1915).",
                "Report the seller account on Instagram / Facebook using their built-in reporting tools (Report -> Scam or Fraud).",
                "File a cyber fraud report on cybercrime.gov.in if the amount exceeds threshold limits.",
                "Post reviews on Google Safe Browsing and Trustpilot to alert other potential victims."
            ],
            "contacts": [
                {
                    "entity": "National Consumer Helpline",
                    "info": "1915 / consumerhelpline.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "Payment Aggregator Dispute",
                    "info": "Contact Razorpay / PayU fraud support",
                    "channel": "Payment Gateway"
                },
                {
                    "entity": "National Cybercrime",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                }
            ],
            "evidence": [
                "URL of the fraudulent online storefront",
                "Screenshot of the advertisement, product page, and checkout screen",
                "Payment transaction ID and merchant name from your bank statement",
                "Email or WhatsApp communication with the seller requesting updates",
                "Fake courier tracking number provided"
            ],
            "whatToAvoid": [
                "Do NOT pay additional 'customs clearance', 'insurance', or 'courier release' fees to get the item delivered.",
                "Never purchase high-value electronics from social media stores without Cash on Delivery (COD) or verified escrow."
            ],
            "followUpPlan": "Check domain age on whois before buying from new stores. Stick to established, verified e-commerce platforms.",
            "steps": [
                "Request a formal chargeback from your credit/debit card provider for non-receipt of merchandise.",
                "Check payment receipt to identify the payment aggregator (Razorpay, PayU, CCavenue) and file a fraud report directly with them.",
                "File a complaint on National Consumer Helpline (consumerhelpline.gov.in or call 1915).",
                "Report the seller account on Instagram / Facebook using their built-in reporting tools (Report -> Scam or Fraud).",
                "File a cyber fraud report on cybercrime.gov.in if the amount exceeds threshold limits.",
                "Post reviews on Google Safe Browsing and Trustpilot to alert other potential victims."
            ],
            "priorityActions": [
                "Contact your card issuer or payment gateway (Razorpay, Cashfree, PayU) to initiate a chargeback for 'goods not delivered'.",
                "Document the product advertisement, payment receipt, and order confirmation.",
                "File a consumer grievance on the National Consumer Helpline (1915 / consumerhelpline.gov.in).",
                "Report the fraudulent Instagram/Facebook page or website domain to the hosting registrar and DoT Chakshu."
            ]
        },
        "investment_fraud": {
            "id": "investment_fraud",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Fake Investment, Task & Stock Group Scams",
            "subtitle": "Telegram stock trading groups, hotel review task apps, and guaranteed return schemes",
            "urgency": "CRITICAL PRIORITY — ASSET RECOVERY ACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "trending_up",
            "goldenHourNotice": "Stop transferring capital immediately. Fraudulent platforms display fabricated profit numbers to solicit larger deposits.",
            "whatHappened": "You were added to a VIP WhatsApp/Telegram trading group promising 200-500% returns on 'institutional IPO allocations' or paid hotel rating tasks.",
            "compromisedAssets": "Invested capital, bank accounts used for transfers, identity documents submitted for 'KYC'.",
            "immediateActions": [
                "STOP all further payments immediately. Do NOT pay 'withdrawal taxes', 'margin calls', or 'VIP upgrade fees'.",
                "Document all beneficiary bank accounts, UPI IDs, and cryptocurrency wallet addresses provided for deposits.",
                "Call National Cybercrime Helpline 1930 and report every individual transaction UTR number.",
                "File a formal report on cybercrime.gov.in detailing the investment syndicate."
            ],
            "checklist": [
                "Cease all payments immediately regardless of threats from 'mentors' or 'fund managers'.",
                "Compile a complete chronological spreadsheet of all deposits made, including dates, amounts, and UTR numbers.",
                "Dial 1930 and register the cumulative financial loss with law enforcement.",
                "Submit a detailed cybercrime.gov.in complaint with all chat logs, screenshots of the fake trading app, and beneficiary accounts.",
                "Report the fraudulent investment scheme to SEBI SCORES (scores.gov.in / 1800 266 7575).",
                "Report the WhatsApp group and Telegram channels using the DoT Chakshu portal.",
                "Contact your bank to report the transactions as fraud."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Police"
                },
                {
                    "entity": "SEBI Investor Grievances (SCORES)",
                    "info": "1800 266 7575 / scores.gov.in",
                    "channel": "Regulator"
                },
                {
                    "entity": "RBI Sachet Portal",
                    "info": "https://sachet.rbi.org.in",
                    "channel": "Regulator"
                }
            ],
            "evidence": [
                "Complete chat export of the WhatsApp / Telegram group",
                "Screenshots of the fake web portal showing the fabricated portfolio balance",
                "Bank statements showing all outgoing transfers with beneficiary account numbers",
                "Contact details and profile handles of the 'analysts' and 'customer managers'"
            ],
            "whatToAvoid": [
                "NEVER pay 'withdrawal taxes', 'SEBI clearance fees', or 'security deposits' to release your funds. They are 100% fake.",
                "Do NOT engage with 'recovery lawyers' or 'ethical hackers' online who guarantee fund recovery for a fee."
            ],
            "followUpPlan": "Only invest through SEBI-registered brokers and official mutual fund platforms. Verify SEBI registration at sebi.gov.in.",
            "steps": [
                "Cease all payments immediately regardless of threats from 'mentors' or 'fund managers'.",
                "Compile a complete chronological spreadsheet of all deposits made, including dates, amounts, and UTR numbers.",
                "Dial 1930 and register the cumulative financial loss with law enforcement.",
                "Submit a detailed cybercrime.gov.in complaint with all chat logs, screenshots of the fake trading app, and beneficiary accounts.",
                "Report the fraudulent investment scheme to SEBI SCORES (scores.gov.in / 1800 266 7575).",
                "Report the WhatsApp group and Telegram channels using the DoT Chakshu portal.",
                "Contact your bank to report the transactions as fraud."
            ],
            "priorityActions": [
                "STOP all further payments immediately. Do NOT pay 'withdrawal taxes', 'margin calls', or 'VIP upgrade fees'.",
                "Document all beneficiary bank accounts, UPI IDs, and cryptocurrency wallet addresses provided for deposits.",
                "Call National Cybercrime Helpline 1930 and report every individual transaction UTR number.",
                "File a formal report on cybercrime.gov.in detailing the investment syndicate."
            ]
        },
        "crypto_fraud": {
            "id": "crypto_fraud",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Crypto Phishing, Fake DEX & Wallet Drainers",
            "subtitle": "12/24-word seed phrase compromised, malicious smart contract signed, or funds sent to fake exchange",
            "urgency": "CRITICAL EMERGENCY — WALLET ABANDONMENT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "currency_bitcoin",
            "goldenHourNotice": "Blockchain transactions are irreversible. Immediate token transfer to a fresh hardware wallet is required for remaining assets.",
            "whatHappened": "You typed your seed phrase on a fake support website, connected your wallet to a malicious token drainer, or sent crypto to an unverified broker.",
            "compromisedAssets": "Private keys, 12/24-word secret seed phrase, all tokens on that wallet address across all chains.",
            "immediateActions": [
                "Immediately transfer any remaining tokens or NFTs to a brand new, clean wallet generated on an uncompromised device.",
                "Revoke all active smart contract approvals using revoke.cash or etherscan.io/tokenapprovalchecker.",
                "Consider the compromised wallet address permanently burnt; never use it again.",
                "Trace the destination transaction hash (TxHash) on block explorers (Etherscan, BscScan, Solscan)."
            ],
            "checklist": [
                "Create a fresh wallet on a clean device (preferably a hardware wallet: Ledger, Trezor).",
                "Move all uncompromised assets from the breached wallet immediately.",
                "Revoke ERC-20 / BEP-20 token allowances on revoke.cash to stop automated drainer scripts.",
                "Document all transaction hashes (TxHash), destination addresses, and timestamps.",
                "Report the fraud with TxHash to the receiving centralized exchange (Binance, CoinDCX, WazirX) if funds were moved to an exchange.",
                "File a complaint on cybercrime.gov.in with blockchain transaction evidence."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "Chainalysis / Etherscan Reporting",
                    "info": "etherscan.io/contactus",
                    "channel": "Explorer Flagging"
                },
                {
                    "entity": "Crypto Exchange Security Desks",
                    "info": "Contact exchange where destination wallet belongs",
                    "channel": "Exchange"
                }
            ],
            "evidence": [
                "Blockchain Transaction Hashes (TxHash) of all unauthorized transfers",
                "Attacker's destination wallet address",
                "URL of the phishing dApp, fake airdrop, or drainer website connected to",
                "Chat logs with support imposters requesting seed phrases"
            ],
            "whatToAvoid": [
                "NEVER deposit more crypto into the compromised wallet to 'pay gas fees for asset return'.",
                "Do NOT trust 'private crypto recovery detectives' on Telegram or Twitter. Private keys cannot be forced backwards."
            ],
            "followUpPlan": "Store seed phrases exclusively on offline physical paper or stamped metal plates. Never store seed phrases in cloud drives or screenshots.",
            "steps": [
                "Create a fresh wallet on a clean device (preferably a hardware wallet: Ledger, Trezor).",
                "Move all uncompromised assets from the breached wallet immediately.",
                "Revoke ERC-20 / BEP-20 token allowances on revoke.cash to stop automated drainer scripts.",
                "Document all transaction hashes (TxHash), destination addresses, and timestamps.",
                "Report the fraud with TxHash to the receiving centralized exchange (Binance, CoinDCX, WazirX) if funds were moved to an exchange.",
                "File a complaint on cybercrime.gov.in with blockchain transaction evidence."
            ],
            "priorityActions": [
                "Immediately transfer any remaining tokens or NFTs to a brand new, clean wallet generated on an uncompromised device.",
                "Revoke all active smart contract approvals using revoke.cash or etherscan.io/tokenapprovalchecker.",
                "Consider the compromised wallet address permanently burnt; never use it again.",
                "Trace the destination transaction hash (TxHash) on block explorers (Etherscan, BscScan, Solscan)."
            ]
        },
        "sextortion_blackmail": {
            "id": "sextortion_blackmail",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Sextortion, 'Digital Arrest' & Coercion Blackmail",
            "subtitle": "Blackmailed with compromised video clips, fake morphing, or threats of arrest by fake police",
            "urgency": "HIGH SAFETY PROTOCOL — DO NOT PAY",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "gavel",
            "goldenHourNotice": "Blackmailers rely on panic and shame. Paying money does NOT stop extortion; it guarantees escalating demands.",
            "whatHappened": "You received a compromised video call where your face was recorded, or an imposter claiming to be CBI, ED, or Cyber Police threatened you with immediate arrest.",
            "compromisedAssets": "Personal reputation, emotional well-being, contacts list (if malware was installed), financial assets.",
            "immediateActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ],
            "checklist": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "National Emergency Helpline",
                    "info": "112",
                    "channel": "Emergency Police"
                },
                {
                    "entity": "StopNCII (Non-Consensual Imagery)",
                    "info": "https://stopncii.org",
                    "channel": "Image Prevention Hub"
                },
                {
                    "entity": "National Commission for Women (NCW)",
                    "info": "7827170170",
                    "channel": "Support Desk"
                }
            ],
            "evidence": [
                "Screenshots of the threatening messages, demands, and countdown timers",
                "Phone numbers, WhatsApp accounts, and email addresses of the extortionist",
                "Bank account details or UPI IDs provided for extortion payments",
                "Any audio or video recordings of the threatening call"
            ],
            "whatToAvoid": [
                "NEVER pay money. Extortionists never delete compromising media after payment; they treat paying victims as recurring revenue.",
                "Do not delete chat logs before capturing complete evidence.",
                "Do not harm yourself or suffer in silence — law enforcement treats you as the VICTIM of organized extortion."
            ],
            "followUpPlan": "Deactivate social accounts temporarily. Keep device cameras covered when not in active use. Seek mental health counseling support.",
            "steps": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "priorityActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ]
        },
        "phishing_link": {
            "id": "phishing_link",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Phishing Link Clicked / Suspicious Website Visited",
            "subtitle": "Clicked an unknown link from SMS or email; uncertain if credentials or device were compromised",
            "urgency": "PRECAUTIONARY TRIAGE — AUDIT & SECURE",
            "urgencyClass": "bg-slate-100 text-slate-800 border-slate-300",
            "icon": "link_off",
            "goldenHourNotice": "If you merely visited the webpage without typing credentials or downloading files, your risk is low. Follow precautionary hygiene.",
            "whatHappened": "You clicked an unsolicited link in an SMS, email, or social media DM directing to an unverified domain.",
            "compromisedAssets": "IP address, browser user-agent, potential cookies, credentials (if typed into form).",
            "immediateActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ],
            "checklist": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "Google Safe Browsing Report",
                    "info": "https://safebrowsing.google.com/safebrowsing/report_phish/",
                    "channel": "Global Defense"
                }
            ],
            "evidence": [
                "Full URL of the phishing link (copied without clicking)",
                "Sender mobile number or email address",
                "Screenshot of the SMS or email containing the deceptive link"
            ],
            "whatToAvoid": [
                "Do NOT enter test passwords or personal info on the page to 'check if it works'.",
                "Do not click 'Allow' on notification popups or permission prompts from unknown websites."
            ],
            "followUpPlan": "Enable enhanced safe browsing in your browser. Use DNS filtering (NextDNS, Cloudflare 1.1.1.2) to block known phishing domains.",
            "steps": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "priorityActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ]
        },
        "fake_support": {
            "id": "fake_support",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Fake Customer Support & Search Ad Scams",
            "subtitle": "Searched Google for airline, bank, or courier customer care and called a fraudulent number",
            "urgency": "HIGH URGENCY — HALT INTERACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "support_agent",
            "goldenHourNotice": "Fraudsters purchase search ads or edit Google Maps listings to substitute their phone numbers for genuine corporate helplines.",
            "whatHappened": "You searched Google for customer support (Swiggy, Indigo, Amazon, SBI) and dialed a sponsored search result or manipulated Maps contact.",
            "compromisedAssets": "Disclosed banking details, OTPs, remote access permissions, payment funds.",
            "immediateActions": [
                "Disconnect the phone call immediately. The person you are speaking with is NOT a company representative.",
                "If you installed AnyDesk, TeamViewer, or shared any code, turn on Airplane Mode and uninstall the app.",
                "If you authorized a payment on their instruction, call your bank immediately to dispute the charge.",
                "Only contact companies through their verified in-app help centers or verified physical paperwork."
            ],
            "checklist": [
                "Hang up the call immediately. Cease all further conversation with that phone number.",
                "If you opened a link or downloaded an app sent by the fake agent, uninstall it immediately.",
                "If you made a payment via UPI or card, contact your bank fraud desk immediately to file a chargeback.",
                "Report the fraudulent phone number on the DoT Chakshu portal (sancharsaathi.gov.in).",
                "Report the deceptive Google search ad or fraudulent Google Maps listing (Suggest an edit -> Mark as fraudulent).",
                "Access the authentic company customer support strictly via their verified mobile app."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Police"
                },
                {
                    "entity": "Google Ad Complaints",
                    "info": "https://support.google.com/google-ads/troubleshooter/4578507",
                    "channel": "Search Engine"
                }
            ],
            "evidence": [
                "Phone number dialed from your call history",
                "Search query used on Google that displayed the fake result",
                "Screenshot of the search engine ad or Google Maps business profile",
                "Payment receipts or UPI reference numbers if money was transferred"
            ],
            "whatToAvoid": [
                "NEVER trust top search results on Google blindly — scammers routinely purchase Google Sponsored Ads to impersonate brands.",
                "Genuine customer care never asks you to download screen-sharing tools or transfer a '₹5 test verification charge'."
            ],
            "followUpPlan": "Bookmark official brand portals. Always initiate support requests from inside official banking or e-commerce apps.",
            "steps": [
                "Hang up the call immediately. Cease all further conversation with that phone number.",
                "If you opened a link or downloaded an app sent by the fake agent, uninstall it immediately.",
                "If you made a payment via UPI or card, contact your bank fraud desk immediately to file a chargeback.",
                "Report the fraudulent phone number on the DoT Chakshu portal (sancharsaathi.gov.in).",
                "Report the deceptive Google search ad or fraudulent Google Maps listing (Suggest an edit -> Mark as fraudulent).",
                "Access the authentic company customer support strictly via their verified mobile app."
            ],
            "priorityActions": [
                "Disconnect the phone call immediately. The person you are speaking with is NOT a company representative.",
                "If you installed AnyDesk, TeamViewer, or shared any code, turn on Airplane Mode and uninstall the app.",
                "If you authorized a payment on their instruction, call your bank immediately to dispute the charge.",
                "Only contact companies through their verified in-app help centers or verified physical paperwork."
            ]
        },
        "money_sent": {
            "id": "money_transferred",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Money Transferred / Financial Fraud",
            "subtitle": "Direct fund loss via IMPS, NEFT, RTGS, NetBanking or wire transfer",
            "urgency": "CRITICAL PRIORITY — GOLDEN HOUR PROTOCOL",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "payments",
            "goldenHourNotice": "Transactions reported within the first 2-3 hours have a significantly higher probability of inter-bank lien freezing before cash is withdrawn at destination ATMs.",
            "whatHappened": "You transferred funds to a scammer or unauthorized beneficiary following deceptive claims (KYC update, bill cutoff, fake job fee, or emergency family call).",
            "compromisedAssets": "Transferred capital, bank account number, sender IFSC, and potential mobile number exposure.",
            "immediateActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ],
            "checklist": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "Dial 1930 (Toll-Free, 24x7)",
                    "channel": "Phone"
                },
                {
                    "entity": "NCRP Citizen Portal",
                    "info": "https://cybercrime.gov.in",
                    "channel": "Web Portal"
                },
                {
                    "entity": "Your Bank Fraud Desk",
                    "info": "Phone number printed on back of Debit/Credit card",
                    "channel": "Direct Bank"
                }
            ],
            "evidence": [
                "Transaction Reference Number (UTR / RRN / IMPS Reference ID)",
                "Bank SMS notification received immediately after the debit",
                "Account statement or mini-statement showing debit timestamp and beneficiary details",
                "Screenshots of communication (WhatsApp, Telegram, SMS, or call log) with the perpetrator",
                "Beneficiary account number, IFSC code, or UPI ID where money was directed"
            ],
            "whatToAvoid": [
                "NEVER pay 'recovery clearance fees' or hire 'online ethical hackers' promising to retrieve lost funds. They are secondary scammers.",
                "Do NOT delete chat history, call recordings, or SMS threads with the perpetrator.",
                "Do NOT share OTPs with anyone claiming to represent your bank's 'reversal division'."
            ],
            "followUpPlan": "Monitor account statement weekly for recurring mandates. File an insurance claim if you hold cyber insurance. Maintain the police FIR copy for future banking dispute resolution.",
            "steps": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "priorityActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ]
        },
        "credentials_shared": {
            "id": "password_stolen",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Stolen Password & Account Takeover",
            "subtitle": "Primary account password disclosed, phished, or leaked in data breach",
            "urgency": "HIGH URGENCY — CREDENTIAL CONTAINMENT",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "vpn_key",
            "goldenHourNotice": "Attackers leverage stolen passwords across multiple platforms via automated credential stuffing scripts.",
            "whatHappened": "Your password was captured on a phishing page, intercepted on unsecured public Wi-Fi, or surfaced in a credential dump.",
            "compromisedAssets": "Login access to affected service, potentially other accounts sharing the same password.",
            "immediateActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ],
            "checklist": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "contacts": [
                {
                    "entity": "Google Account Recovery",
                    "info": "https://accounts.google.com/signin/recovery",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Microsoft Security",
                    "info": "https://account.live.com/password/reset",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Apple ID Support",
                    "info": "https://iforgot.apple.com",
                    "channel": "Self-Service"
                }
            ],
            "evidence": [
                "Security alert emails received notifying of login from unknown IP or city",
                "Phishing email or URL where the credential was typed",
                "Timestamp when access was lost or changed"
            ],
            "whatToAvoid": [
                "Never re-use passwords across email, banking, and social accounts.",
                "Do not store passwords in unencrypted plaintext notes or screenshots."
            ],
            "followUpPlan": "Run a scan on haveibeenpwned.com to check for leaked accounts. Rotate all critical service credentials.",
            "steps": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "priorityActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ]
        },
        "apk_installed": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "app_installed": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "account_compromised": {
            "id": "whatsapp_social_takeover",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "WhatsApp & Social Media Hijacking",
            "subtitle": "WhatsApp 6-digit registration PIN tricked, or Instagram/Facebook hijacked",
            "urgency": "HIGH URGENCY — PREVENT CONTACT FRAUD",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "forum",
            "goldenHourNotice": "Scammers immediately message your close family, friends, and colleagues begging for urgent medical or emergency UPI transfers.",
            "whatHappened": "You shared a 6-digit SMS code or fell for a call forwarding code (*21*...), giving an attacker access to your WhatsApp or social account.",
            "compromisedAssets": "Chat history, personal contact list, ability to impersonate you to friends and family.",
            "immediateActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ],
            "checklist": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "contacts": [
                {
                    "entity": "WhatsApp Support Email",
                    "info": "support@whatsapp.com",
                    "channel": "Email"
                },
                {
                    "entity": "Instagram Hacked Recovery",
                    "info": "https://instagram.com/hacked",
                    "channel": "Portal"
                },
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Reporting"
                }
            ],
            "evidence": [
                "Phone numbers from which verification codes were requested",
                "Screenshots of messages sent by hacker to your contacts demanding funds",
                "UPI handles where the hacker asked your friends to transfer money"
            ],
            "whatToAvoid": [
                "Never pay ransom to anyone claiming they will return your account for money.",
                "Never share 6-digit verification codes sent to your phone with anyone, even contacts who appear to be friends."
            ],
            "followUpPlan": "Enable biometric app lock. Educate close contacts on your verified emergency communication protocol.",
            "steps": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "priorityActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ]
        },
        "link_clicked": {
            "id": "phishing_link",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Phishing Link Clicked / Suspicious Website Visited",
            "subtitle": "Clicked an unknown link from SMS or email; uncertain if credentials or device were compromised",
            "urgency": "PRECAUTIONARY TRIAGE — AUDIT & SECURE",
            "urgencyClass": "bg-slate-100 text-slate-800 border-slate-300",
            "icon": "link_off",
            "goldenHourNotice": "If you merely visited the webpage without typing credentials or downloading files, your risk is low. Follow precautionary hygiene.",
            "whatHappened": "You clicked an unsolicited link in an SMS, email, or social media DM directing to an unverified domain.",
            "compromisedAssets": "IP address, browser user-agent, potential cookies, credentials (if typed into form).",
            "immediateActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ],
            "checklist": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "Google Safe Browsing Report",
                    "info": "https://safebrowsing.google.com/safebrowsing/report_phish/",
                    "channel": "Global Defense"
                }
            ],
            "evidence": [
                "Full URL of the phishing link (copied without clicking)",
                "Sender mobile number or email address",
                "Screenshot of the SMS or email containing the deceptive link"
            ],
            "whatToAvoid": [
                "Do NOT enter test passwords or personal info on the page to 'check if it works'.",
                "Do not click 'Allow' on notification popups or permission prompts from unknown websites."
            ],
            "followUpPlan": "Enable enhanced safe browsing in your browser. Use DNS filtering (NextDNS, Cloudflare 1.1.1.2) to block known phishing domains.",
            "steps": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "priorityActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ]
        },
        "personal_info_leaked": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "personal_info_shared": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "other_threat": {
            "id": "sextortion_blackmail",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Sextortion, 'Digital Arrest' & Coercion Blackmail",
            "subtitle": "Blackmailed with compromised video clips, fake morphing, or threats of arrest by fake police",
            "urgency": "HIGH SAFETY PROTOCOL — DO NOT PAY",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "gavel",
            "goldenHourNotice": "Blackmailers rely on panic and shame. Paying money does NOT stop extortion; it guarantees escalating demands.",
            "whatHappened": "You received a compromised video call where your face was recorded, or an imposter claiming to be CBI, ED, or Cyber Police threatened you with immediate arrest.",
            "compromisedAssets": "Personal reputation, emotional well-being, contacts list (if malware was installed), financial assets.",
            "immediateActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ],
            "checklist": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "National Emergency Helpline",
                    "info": "112",
                    "channel": "Emergency Police"
                },
                {
                    "entity": "StopNCII (Non-Consensual Imagery)",
                    "info": "https://stopncii.org",
                    "channel": "Image Prevention Hub"
                },
                {
                    "entity": "National Commission for Women (NCW)",
                    "info": "7827170170",
                    "channel": "Support Desk"
                }
            ],
            "evidence": [
                "Screenshots of the threatening messages, demands, and countdown timers",
                "Phone numbers, WhatsApp accounts, and email addresses of the extortionist",
                "Bank account details or UPI IDs provided for extortion payments",
                "Any audio or video recordings of the threatening call"
            ],
            "whatToAvoid": [
                "NEVER pay money. Extortionists never delete compromising media after payment; they treat paying victims as recurring revenue.",
                "Do not delete chat logs before capturing complete evidence.",
                "Do not harm yourself or suffer in silence — law enforcement treats you as the VICTIM of organized extortion."
            ],
            "followUpPlan": "Deactivate social accounts temporarily. Keep device cameras covered when not in active use. Seek mental health counseling support.",
            "steps": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "priorityActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ]
        }
    },
    "situationPlaybooks": {
        "money_transferred": {
            "id": "money_transferred",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Money Transferred / Financial Fraud",
            "subtitle": "Direct fund loss via IMPS, NEFT, RTGS, NetBanking or wire transfer",
            "urgency": "CRITICAL PRIORITY — GOLDEN HOUR PROTOCOL",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "payments",
            "goldenHourNotice": "Transactions reported within the first 2-3 hours have a significantly higher probability of inter-bank lien freezing before cash is withdrawn at destination ATMs.",
            "whatHappened": "You transferred funds to a scammer or unauthorized beneficiary following deceptive claims (KYC update, bill cutoff, fake job fee, or emergency family call).",
            "compromisedAssets": "Transferred capital, bank account number, sender IFSC, and potential mobile number exposure.",
            "immediateActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ],
            "checklist": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "Dial 1930 (Toll-Free, 24x7)",
                    "channel": "Phone"
                },
                {
                    "entity": "NCRP Citizen Portal",
                    "info": "https://cybercrime.gov.in",
                    "channel": "Web Portal"
                },
                {
                    "entity": "Your Bank Fraud Desk",
                    "info": "Phone number printed on back of Debit/Credit card",
                    "channel": "Direct Bank"
                }
            ],
            "evidence": [
                "Transaction Reference Number (UTR / RRN / IMPS Reference ID)",
                "Bank SMS notification received immediately after the debit",
                "Account statement or mini-statement showing debit timestamp and beneficiary details",
                "Screenshots of communication (WhatsApp, Telegram, SMS, or call log) with the perpetrator",
                "Beneficiary account number, IFSC code, or UPI ID where money was directed"
            ],
            "whatToAvoid": [
                "NEVER pay 'recovery clearance fees' or hire 'online ethical hackers' promising to retrieve lost funds. They are secondary scammers.",
                "Do NOT delete chat history, call recordings, or SMS threads with the perpetrator.",
                "Do NOT share OTPs with anyone claiming to represent your bank's 'reversal division'."
            ],
            "followUpPlan": "Monitor account statement weekly for recurring mandates. File an insurance claim if you hold cyber insurance. Maintain the police FIR copy for future banking dispute resolution.",
            "steps": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "priorityActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ]
        },
        "upi_fraud": {
            "id": "upi_fraud",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "UPI Fraud & Fake QR Code Scams",
            "subtitle": "Funds debited via UPI PIN entry, collect requests, or deceptive QR codes",
            "urgency": "CRITICAL PRIORITY — IMMEDIATE CONTAINMENT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "qr_code_scanner",
            "goldenHourNotice": "UPI transfers are instantaneous, but destination wallets and accounts can be frozen if reported to 1930 and payment apps within 2 hours.",
            "whatHappened": "You were induced to scan a QR code, approve a UPI collect request, or enter your secret UPI PIN under the false pretext of receiving a refund, cashback, or OLX buyer payment.",
            "compromisedAssets": "UPI PIN, primary linked bank account, UPI ID / VPA, phone number.",
            "immediateActions": [
                "Open your UPI app (PhonePe, GPay, Paytm) and immediately change/reset your UPI PIN using debit card details.",
                "Report the fraudulent transaction inside the UPI app's transaction history ('Report a Problem').",
                "Call National Cybercrime Helpline 1930 with the UPI Transaction ID (12-digit numeric RRN).",
                "Block the scammer's UPI handle (VPA) and mobile number."
            ],
            "checklist": [
                "Reset your UPI PIN immediately across all linked bank accounts.",
                "Open transaction details in PhonePe / GPay / Paytm and tap 'Raise Dispute / Report Fraud'.",
                "Dial 1930 and submit the 12-digit UPI RRN / Transaction ID.",
                "File an acknowledgment complaint at cybercrime.gov.in.",
                "Deregister UPI on your phone if unexpected collect requests keep arriving (Settings -> Deregister UPI).",
                "Check for unauthorized auto-debit mandates (Settings -> Autopay / Recurring Mandates -> Revoke)."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Phone"
                },
                {
                    "entity": "NPCI / BHIM Toll-Free",
                    "info": "1800-120-1740",
                    "channel": "NPCI Helpline"
                },
                {
                    "entity": "PhonePe Fraud Desk",
                    "info": "080-68727374",
                    "channel": "Payment App"
                },
                {
                    "entity": "Google Pay Security",
                    "info": "1800-419-0157",
                    "channel": "Payment App"
                },
                {
                    "entity": "Paytm Cyber Support",
                    "info": "0120-4456-456",
                    "channel": "Payment App"
                }
            ],
            "evidence": [
                "12-digit UPI Reference Number (RRN) from app transaction screen",
                "Beneficiary UPI VPA (e.g., fraudster@ybl, refund.desk@oksbi)",
                "Screenshot of the QR code scanned or collect request screen",
                "SMS received from bank confirming UPI debit",
                "Listing screenshot or marketplace chat (OLX, Quikr, Facebook Marketplace)"
            ],
            "whatToAvoid": [
                "REMEMBER: Entering your UPI PIN NEVER credits money to you. PIN is strictly for DEBITING funds.",
                "Never scan a QR code received on WhatsApp to 'receive' money or refunds.",
                "Do not accept incoming collect requests from unverified handles."
            ],
            "followUpPlan": "Audit all active UPI auto-pay authorizations. Set lower daily UPI transaction limits in your bank app (e.g. ₹10,000 max).",
            "steps": [
                "Reset your UPI PIN immediately across all linked bank accounts.",
                "Open transaction details in PhonePe / GPay / Paytm and tap 'Raise Dispute / Report Fraud'.",
                "Dial 1930 and submit the 12-digit UPI RRN / Transaction ID.",
                "File an acknowledgment complaint at cybercrime.gov.in.",
                "Deregister UPI on your phone if unexpected collect requests keep arriving (Settings -> Deregister UPI).",
                "Check for unauthorized auto-debit mandates (Settings -> Autopay / Recurring Mandates -> Revoke)."
            ],
            "priorityActions": [
                "Open your UPI app (PhonePe, GPay, Paytm) and immediately change/reset your UPI PIN using debit card details.",
                "Report the fraudulent transaction inside the UPI app's transaction history ('Report a Problem').",
                "Call National Cybercrime Helpline 1930 with the UPI Transaction ID (12-digit numeric RRN).",
                "Block the scammer's UPI handle (VPA) and mobile number."
            ]
        },
        "bank_compromise": {
            "id": "bank_compromise",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Bank Account & NetBanking Compromise",
            "subtitle": "Customer ID, NetBanking login password, or OTP disclosed",
            "urgency": "CRITICAL EMERGENCY — ACTIVE ACCOUNT RISK",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "account_balance",
            "goldenHourNotice": "Perpetrators with login access can register new beneficiaries, change mobile numbers, or apply for instant pre-approved loans.",
            "whatHappened": "You entered your bank Customer ID, password, or security questions on a cloned bank website or disclosed them to an impersonator over the phone.",
            "compromisedAssets": "NetBanking access, Customer ID, transaction passwords, security questions, linked accounts.",
            "immediateActions": [
                "Call your bank's 24x7 emergency helpline immediately to freeze your NetBanking access and user ID.",
                "If still logged in from a clean device, change login and transaction passwords immediately.",
                "Verify that no new unauthorized beneficiary has been added under your transfer limits.",
                "Review transaction limits and lower them to zero until security is re-established."
            ],
            "checklist": [
                "Call bank emergency hotline and instruct agent: 'Freeze my NetBanking access immediately due to compromise'.",
                "Request temporary block on all outward NEFT, RTGS, IMPS, and UPI transfers.",
                "Visit the official bank branch to reset Customer ID credentials and submit a written incident report.",
                "Check 'Manage Beneficiaries' and delete any unknown accounts added in the last 24-48 hours.",
                "Review registered email address and mobile number in profile settings to confirm they weren't altered.",
                "File an incident record on cybercrime.gov.in."
            ],
            "contacts": [
                {
                    "entity": "SBI Emergency Desk",
                    "info": "1800-11-2211 / SMS BLOCK <Acc> to 567676",
                    "channel": "Bank"
                },
                {
                    "entity": "HDFC Fraud Control",
                    "info": "1800-202-6161 / 1800-258-3838",
                    "channel": "Bank"
                },
                {
                    "entity": "ICICI Emergency Line",
                    "info": "1800-1080",
                    "channel": "Bank"
                },
                {
                    "entity": "National Cybercrime",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "National"
                }
            ],
            "evidence": [
                "URL of the spoofed banking website visited",
                "Phone numbers from which calls were received",
                "SMS logs showing OTP requests or unauthorized login attempts",
                "Timestamps of unauthorized login alerts"
            ],
            "whatToAvoid": [
                "Never read OTPs aloud to any caller claiming to be 'restoring your account'.",
                "Do not access banking accounts from public Wi-Fi or compromised phones.",
                "Do not re-use the compromised password on any other service."
            ],
            "followUpPlan": "Switch to hardware token or authenticator app 2FA. Re-enable SMS email debit alerts. Request new debit card and checkbook.",
            "steps": [
                "Call bank emergency hotline and instruct agent: 'Freeze my NetBanking access immediately due to compromise'.",
                "Request temporary block on all outward NEFT, RTGS, IMPS, and UPI transfers.",
                "Visit the official bank branch to reset Customer ID credentials and submit a written incident report.",
                "Check 'Manage Beneficiaries' and delete any unknown accounts added in the last 24-48 hours.",
                "Review registered email address and mobile number in profile settings to confirm they weren't altered.",
                "File an incident record on cybercrime.gov.in."
            ],
            "priorityActions": [
                "Call your bank's 24x7 emergency helpline immediately to freeze your NetBanking access and user ID.",
                "If still logged in from a clean device, change login and transaction passwords immediately.",
                "Verify that no new unauthorized beneficiary has been added under your transfer limits.",
                "Review transaction limits and lower them to zero until security is re-established."
            ]
        },
        "card_compromise": {
            "id": "card_compromise",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Credit / Debit Card Compromise",
            "subtitle": "16-digit card number, CVV, expiry date, or ATM PIN exposed",
            "urgency": "HIGH URGENCY — IMMEDIATE CARD HOTLISTING",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "credit_card",
            "goldenHourNotice": "Hotlisting your card stops automated e-commerce and international POS transactions immediately.",
            "whatHappened": "Card details were entered on a fraudulent payment checkout page, captured by a card skimmer, or exposed via an unencrypted form.",
            "compromisedAssets": "Card number, CVV, expiration date, cardholder name, linked credit line.",
            "immediateActions": [
                "Open your mobile banking app and toggle 'Card Lock / Block Card' immediately.",
                "Disable International Transactions and Online E-commerce Transactions in card controls.",
                "Call your card issuer helpline to hotlist the card and request a replacement card with a new number.",
                "Dispute any unauthorized transactions with your bank under zero-liability guidelines."
            ],
            "checklist": [
                "Block card instantly via mobile app (Card Controls -> Permanent Block / Hotlist).",
                "Alternatively, send emergency SMS block command (e.g. BLOCK <Last 4 Digits> to bank SMS shortcode).",
                "Call issuer to confirm card cancellation and request replacement with refreshed CVV.",
                "Review pending transactions on your card statement and mark unauthorized charges.",
                "Submit a formal Transaction Dispute Form (Chargeback Request) to your bank within 3 days for zero liability.",
                "File a complaint at cybercrime.gov.in with transaction details."
            ],
            "contacts": [
                {
                    "entity": "Card Issuer 24x7 Desk",
                    "info": "Number on back of physical card",
                    "channel": "Direct"
                },
                {
                    "entity": "RBI Ombudsman",
                    "info": "https://cms.rbi.org.in",
                    "channel": "Escalation"
                },
                {
                    "entity": "National Cyber Helpline",
                    "info": "1930",
                    "channel": "National"
                }
            ],
            "evidence": [
                "Merchant names and amounts of unauthorized charges from statement",
                "SMS alerts received with OTP or international currency debit alerts",
                "URL of the checkout portal where card details were typed"
            ],
            "whatToAvoid": [
                "Do not keep the card active thinking 'only a small amount was taken' — fraudsters test with ₹1 before draining limits.",
                "Never share new card replacement details over WhatsApp."
            ],
            "followUpPlan": "Keep International and Contactless (NFC) limits disabled by default when not traveling. Set low daily spending caps.",
            "steps": [
                "Block card instantly via mobile app (Card Controls -> Permanent Block / Hotlist).",
                "Alternatively, send emergency SMS block command (e.g. BLOCK <Last 4 Digits> to bank SMS shortcode).",
                "Call issuer to confirm card cancellation and request replacement with refreshed CVV.",
                "Review pending transactions on your card statement and mark unauthorized charges.",
                "Submit a formal Transaction Dispute Form (Chargeback Request) to your bank within 3 days for zero liability.",
                "File a complaint at cybercrime.gov.in with transaction details."
            ],
            "priorityActions": [
                "Open your mobile banking app and toggle 'Card Lock / Block Card' immediately.",
                "Disable International Transactions and Online E-commerce Transactions in card controls.",
                "Call your card issuer helpline to hotlist the card and request a replacement card with a new number.",
                "Dispute any unauthorized transactions with your bank under zero-liability guidelines."
            ]
        },
        "password_stolen": {
            "id": "password_stolen",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Stolen Password & Account Takeover",
            "subtitle": "Primary account password disclosed, phished, or leaked in data breach",
            "urgency": "HIGH URGENCY — CREDENTIAL CONTAINMENT",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "vpn_key",
            "goldenHourNotice": "Attackers leverage stolen passwords across multiple platforms via automated credential stuffing scripts.",
            "whatHappened": "Your password was captured on a phishing page, intercepted on unsecured public Wi-Fi, or surfaced in a credential dump.",
            "compromisedAssets": "Login access to affected service, potentially other accounts sharing the same password.",
            "immediateActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ],
            "checklist": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "contacts": [
                {
                    "entity": "Google Account Recovery",
                    "info": "https://accounts.google.com/signin/recovery",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Microsoft Security",
                    "info": "https://account.live.com/password/reset",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Apple ID Support",
                    "info": "https://iforgot.apple.com",
                    "channel": "Self-Service"
                }
            ],
            "evidence": [
                "Security alert emails received notifying of login from unknown IP or city",
                "Phishing email or URL where the credential was typed",
                "Timestamp when access was lost or changed"
            ],
            "whatToAvoid": [
                "Never re-use passwords across email, banking, and social accounts.",
                "Do not store passwords in unencrypted plaintext notes or screenshots."
            ],
            "followUpPlan": "Run a scan on haveibeenpwned.com to check for leaked accounts. Rotate all critical service credentials.",
            "steps": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "priorityActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ]
        },
        "email_compromise": {
            "id": "email_compromise",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Email Account Compromise",
            "subtitle": "Gmail, Outlook, Yahoo or corporate email account accessed by unauthorized parties",
            "urgency": "CRITICAL EMERGENCY — ROOT IDENTITY AT RISK",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "mark_email_unread",
            "goldenHourNotice": "Email is the root of your digital identity. Attackers use it to trigger password resets on your banks and shopping portals.",
            "whatHappened": "An attacker gained access to your primary email address and can read private communications and reset passwords on linked accounts.",
            "compromisedAssets": "Primary inbox, password reset mechanisms for all linked banking, social, and government portals.",
            "immediateActions": [
                "Initiate official account recovery immediately via Google / Microsoft / Yahoo recovery portals.",
                "Inspect and remove unauthorized forwarding rules and email filters (attackers create rules to hide bank alerts).",
                "Revoke all active device sessions and OAuth tokens.",
                "Change password and configure hardware or authenticator app 2FA."
            ],
            "checklist": [
                "Recover account using trusted phone number or recovery email.",
                "Navigate to Settings -> Forwarding & POP/IMAP: Delete any unauthorized forwarding addresses.",
                "Navigate to Settings -> Filters and Blocked Addresses: Delete filters routing bank emails to Trash.",
                "Go to Security -> Your Devices: Revoke all unrecognized phones, laptops, and locations.",
                "Review Security -> Third-party apps with account access: Revoke unknown application permissions.",
                "Alert your banks and primary financial institutions that your email was compromised.",
                "Update contact email addresses across banking portals if recovery is delayed."
            ],
            "contacts": [
                {
                    "entity": "Google Security Team",
                    "info": "https://myaccount.google.com/security-checkup",
                    "channel": "Portal"
                },
                {
                    "entity": "Microsoft Account Care",
                    "info": "https://account.microsoft.com/security",
                    "channel": "Portal"
                },
                {
                    "entity": "CERT-In Incident Desk",
                    "info": "incident@cert-in.org.in",
                    "channel": "Email"
                }
            ],
            "evidence": [
                "IP addresses and browser user-agents listed in recent security activity logs",
                "Headers of unauthorized emails sent from your account to your contacts",
                "Screenshots of malicious forwarding rules configured"
            ],
            "whatToAvoid": [
                "Do not overlook inbox rules and forwarding filters — attackers rely on them to silently intercept OTPs even after password changes.",
                "Never use your compromised email to receive password reset tokens until it is fully sanitized."
            ],
            "followUpPlan": "Download account audit logs. Set up Passkeys for hardware-backed, phishing-resistant authentication.",
            "steps": [
                "Recover account using trusted phone number or recovery email.",
                "Navigate to Settings -> Forwarding & POP/IMAP: Delete any unauthorized forwarding addresses.",
                "Navigate to Settings -> Filters and Blocked Addresses: Delete filters routing bank emails to Trash.",
                "Go to Security -> Your Devices: Revoke all unrecognized phones, laptops, and locations.",
                "Review Security -> Third-party apps with account access: Revoke unknown application permissions.",
                "Alert your banks and primary financial institutions that your email was compromised.",
                "Update contact email addresses across banking portals if recovery is delayed."
            ],
            "priorityActions": [
                "Initiate official account recovery immediately via Google / Microsoft / Yahoo recovery portals.",
                "Inspect and remove unauthorized forwarding rules and email filters (attackers create rules to hide bank alerts).",
                "Revoke all active device sessions and OAuth tokens.",
                "Change password and configure hardware or authenticator app 2FA."
            ]
        },
        "whatsapp_social_takeover": {
            "id": "whatsapp_social_takeover",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "WhatsApp & Social Media Hijacking",
            "subtitle": "WhatsApp 6-digit registration PIN tricked, or Instagram/Facebook hijacked",
            "urgency": "HIGH URGENCY — PREVENT CONTACT FRAUD",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "forum",
            "goldenHourNotice": "Scammers immediately message your close family, friends, and colleagues begging for urgent medical or emergency UPI transfers.",
            "whatHappened": "You shared a 6-digit SMS code or fell for a call forwarding code (*21*...), giving an attacker access to your WhatsApp or social account.",
            "compromisedAssets": "Chat history, personal contact list, ability to impersonate you to friends and family.",
            "immediateActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ],
            "checklist": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "contacts": [
                {
                    "entity": "WhatsApp Support Email",
                    "info": "support@whatsapp.com",
                    "channel": "Email"
                },
                {
                    "entity": "Instagram Hacked Recovery",
                    "info": "https://instagram.com/hacked",
                    "channel": "Portal"
                },
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Reporting"
                }
            ],
            "evidence": [
                "Phone numbers from which verification codes were requested",
                "Screenshots of messages sent by hacker to your contacts demanding funds",
                "UPI handles where the hacker asked your friends to transfer money"
            ],
            "whatToAvoid": [
                "Never pay ransom to anyone claiming they will return your account for money.",
                "Never share 6-digit verification codes sent to your phone with anyone, even contacts who appear to be friends."
            ],
            "followUpPlan": "Enable biometric app lock. Educate close contacts on your verified emergency communication protocol.",
            "steps": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "priorityActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ]
        },
        "malicious_apk": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "remote_access_fraud": {
            "id": "remote_access_fraud",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Remote Access App Fraud",
            "subtitle": "Installed AnyDesk, TeamViewer, RustDesk, or QuickSupport at caller request",
            "urgency": "IMMEDIATE ACTIVE THREAT — SEVER CONNECTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "phonelink_lock",
            "goldenHourNotice": "The scammer has active, direct remote viewing and touch control of your phone or computer screen.",
            "whatHappened": "A caller claiming to represent customer care, bank support, or electricity board guided you to install a remote desktop app and share your 9-digit session code.",
            "compromisedAssets": "Full screen visibility, input control, banking screens, incoming OTP banners.",
            "immediateActions": [
                "Turn on AIRPLANE MODE immediately or physically power off the device to cut the attacker's connection.",
                "Uninstall AnyDesk, TeamViewer, QuickSupport, or RustDesk immediately.",
                "Call your bank from another phone immediately to freeze your NetBanking and debit card.",
                "Do NOT log into your bank until the application is confirmed uninstalled and permissions revoked."
            ],
            "checklist": [
                "Turn on Airplane Mode immediately or turn off Wi-Fi router / mobile hotspot.",
                "Terminate the active remote access session inside the app.",
                "Uninstall the remote access software (AnyDesk, TeamViewer, RustDesk, Splashtop).",
                "Revoke screen recording and accessibility permissions under Settings.",
                "Call bank emergency hotline immediately and report: 'Remote access tool was installed, freeze my accounts'.",
                "Check recent outgoing SMS and calls to ensure the caller did not execute background commands.",
                "From a separate trusted device, change your NetBanking and primary email passwords."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime",
                    "info": "1930",
                    "channel": "National"
                },
                {
                    "entity": "AnyDesk Fraud Reporting",
                    "info": "https://anydesk.com/en/contact/abuse",
                    "channel": "Vendor Abuse"
                },
                {
                    "entity": "TeamViewer Security",
                    "info": "https://www.teamviewer.com/en/support/report-a-scam/",
                    "channel": "Vendor Abuse"
                }
            ],
            "evidence": [
                "9-digit or 10-digit remote session code shared with the caller",
                "Incoming caller phone number and time of the remote session",
                "App version and download link provided by caller"
            ],
            "whatToAvoid": [
                "Legitimate customer support NEVER asks you to install AnyDesk or TeamViewer to process a refund.",
                "Do not enter passwords or open banking apps while anyone has remote access to your device."
            ],
            "followUpPlan": "Install an authentic mobile antivirus (Sophos, Bitdefender). Never share 9-digit session codes with inbound callers.",
            "steps": [
                "Turn on Airplane Mode immediately or turn off Wi-Fi router / mobile hotspot.",
                "Terminate the active remote access session inside the app.",
                "Uninstall the remote access software (AnyDesk, TeamViewer, RustDesk, Splashtop).",
                "Revoke screen recording and accessibility permissions under Settings.",
                "Call bank emergency hotline immediately and report: 'Remote access tool was installed, freeze my accounts'.",
                "Check recent outgoing SMS and calls to ensure the caller did not execute background commands.",
                "From a separate trusted device, change your NetBanking and primary email passwords."
            ],
            "priorityActions": [
                "Turn on AIRPLANE MODE immediately or physically power off the device to cut the attacker's connection.",
                "Uninstall AnyDesk, TeamViewer, QuickSupport, or RustDesk immediately.",
                "Call your bank from another phone immediately to freeze your NetBanking and debit card.",
                "Do NOT log into your bank until the application is confirmed uninstalled and permissions revoked."
            ]
        },
        "sim_swap": {
            "id": "sim_swap",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "SIM Swap & Sudden Mobile Disconnection",
            "subtitle": "Phone unexpectedly displays 'No Service' or invalid SIM while attacker controls number",
            "urgency": "CRITICAL EMERGENCY — PHYSICAL CARRIER ACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "sim_card_alert",
            "goldenHourNotice": "Once a SIM swap succeeds, attackers intercept all SMS-based banking OTPs and login codes.",
            "whatHappened": "An attacker tricked your mobile carrier into porting your phone number or converting it to an eSIM using forged identity documents.",
            "compromisedAssets": "Phone number, SMS OTP reception, two-factor authentication for all accounts.",
            "immediateActions": [
                "If your phone shows 'No Service' where coverage is normally strong, contact your mobile operator immediately from another phone.",
                "Immediately notify your banks to freeze accounts linked to that mobile number.",
                "Visit the nearest physical telecom store (Jio, Airtel, Vi) with your original government ID to reclaim your SIM.",
                "Access email and cloud accounts to switch 2FA from SMS to an Authenticator App."
            ],
            "checklist": [
                "Call telecom customer care (Jio: 198, Airtel: 121, Vi: 199) and demand immediate block on the SIM swap.",
                "Notify your bank emergency desk: 'I am experiencing a SIM swap fraud, block all mobile banking OTP transactions'.",
                "Visit the nearest physical branch of your telecom provider with original Aadhaar / voter ID.",
                "Re-issue a new physical SIM card to regain control of your mobile number.",
                "Once restored, verify bank balances and call 1930 if unauthorized transactions occurred.",
                "Check Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to verify all mobile numbers registered in your name."
            ],
            "contacts": [
                {
                    "entity": "Airtel Emergency Desk",
                    "info": "121 / 198",
                    "channel": "Telecom"
                },
                {
                    "entity": "Jio Care",
                    "info": "198 / 1800-889-9999",
                    "channel": "Telecom"
                },
                {
                    "entity": "Vodafone Idea (Vi)",
                    "info": "199",
                    "channel": "Telecom"
                },
                {
                    "entity": "DoT Sanchar Saathi TAFCOP",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                }
            ],
            "evidence": [
                "Timestamp when phone signal abruptly disappeared",
                "Any SMS received prior to disconnection (e.g. 'eSIM request initiated' or 'PORT request')",
                "New SIM ICCID number provided upon store reissuance"
            ],
            "whatToAvoid": [
                "Do NOT dismiss unexpected 'No Service' as a routine network glitch if others nearby have good coverage.",
                "Never approve or forward SIM upgrade or eSIM conversion SMS messages."
            ],
            "followUpPlan": "Ask telecom carrier to place a 'SIM Lock' or PIN protection on your account. Migrate all critical 2FA away from SMS to hardware Passkeys.",
            "steps": [
                "Call telecom customer care (Jio: 198, Airtel: 121, Vi: 199) and demand immediate block on the SIM swap.",
                "Notify your bank emergency desk: 'I am experiencing a SIM swap fraud, block all mobile banking OTP transactions'.",
                "Visit the nearest physical branch of your telecom provider with original Aadhaar / voter ID.",
                "Re-issue a new physical SIM card to regain control of your mobile number.",
                "Once restored, verify bank balances and call 1930 if unauthorized transactions occurred.",
                "Check Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to verify all mobile numbers registered in your name."
            ],
            "priorityActions": [
                "If your phone shows 'No Service' where coverage is normally strong, contact your mobile operator immediately from another phone.",
                "Immediately notify your banks to freeze accounts linked to that mobile number.",
                "Visit the nearest physical telecom store (Jio, Airtel, Vi) with your original government ID to reclaim your SIM.",
                "Access email and cloud accounts to switch 2FA from SMS to an Authenticator App."
            ]
        },
        "identity_theft": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "shopping_fraud": {
            "id": "shopping_fraud",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Online Shopping & Fake E-Commerce Fraud",
            "subtitle": "Paid for goods on a fake Instagram/Facebook store or deceptive clone site with no delivery",
            "urgency": "MODERATE PRIORITY — TRANSACTION DISPUTE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "shopping_bag",
            "goldenHourNotice": "Card and payment gateway chargebacks must be initiated within the scheme's specified dispute window (typically 30-60 days).",
            "whatHappened": "You purchased products from an unverified social media advertisement or cloned retail portal offering unrealistic 80-90% discounts.",
            "compromisedAssets": "Payment funds, postal address, phone number, potentially payment card details.",
            "immediateActions": [
                "Contact your card issuer or payment gateway (Razorpay, Cashfree, PayU) to initiate a chargeback for 'goods not delivered'.",
                "Document the product advertisement, payment receipt, and order confirmation.",
                "File a consumer grievance on the National Consumer Helpline (1915 / consumerhelpline.gov.in).",
                "Report the fraudulent Instagram/Facebook page or website domain to the hosting registrar and DoT Chakshu."
            ],
            "checklist": [
                "Request a formal chargeback from your credit/debit card provider for non-receipt of merchandise.",
                "Check payment receipt to identify the payment aggregator (Razorpay, PayU, CCavenue) and file a fraud report directly with them.",
                "File a complaint on National Consumer Helpline (consumerhelpline.gov.in or call 1915).",
                "Report the seller account on Instagram / Facebook using their built-in reporting tools (Report -> Scam or Fraud).",
                "File a cyber fraud report on cybercrime.gov.in if the amount exceeds threshold limits.",
                "Post reviews on Google Safe Browsing and Trustpilot to alert other potential victims."
            ],
            "contacts": [
                {
                    "entity": "National Consumer Helpline",
                    "info": "1915 / consumerhelpline.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "Payment Aggregator Dispute",
                    "info": "Contact Razorpay / PayU fraud support",
                    "channel": "Payment Gateway"
                },
                {
                    "entity": "National Cybercrime",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                }
            ],
            "evidence": [
                "URL of the fraudulent online storefront",
                "Screenshot of the advertisement, product page, and checkout screen",
                "Payment transaction ID and merchant name from your bank statement",
                "Email or WhatsApp communication with the seller requesting updates",
                "Fake courier tracking number provided"
            ],
            "whatToAvoid": [
                "Do NOT pay additional 'customs clearance', 'insurance', or 'courier release' fees to get the item delivered.",
                "Never purchase high-value electronics from social media stores without Cash on Delivery (COD) or verified escrow."
            ],
            "followUpPlan": "Check domain age on whois before buying from new stores. Stick to established, verified e-commerce platforms.",
            "steps": [
                "Request a formal chargeback from your credit/debit card provider for non-receipt of merchandise.",
                "Check payment receipt to identify the payment aggregator (Razorpay, PayU, CCavenue) and file a fraud report directly with them.",
                "File a complaint on National Consumer Helpline (consumerhelpline.gov.in or call 1915).",
                "Report the seller account on Instagram / Facebook using their built-in reporting tools (Report -> Scam or Fraud).",
                "File a cyber fraud report on cybercrime.gov.in if the amount exceeds threshold limits.",
                "Post reviews on Google Safe Browsing and Trustpilot to alert other potential victims."
            ],
            "priorityActions": [
                "Contact your card issuer or payment gateway (Razorpay, Cashfree, PayU) to initiate a chargeback for 'goods not delivered'.",
                "Document the product advertisement, payment receipt, and order confirmation.",
                "File a consumer grievance on the National Consumer Helpline (1915 / consumerhelpline.gov.in).",
                "Report the fraudulent Instagram/Facebook page or website domain to the hosting registrar and DoT Chakshu."
            ]
        },
        "investment_fraud": {
            "id": "investment_fraud",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Fake Investment, Task & Stock Group Scams",
            "subtitle": "Telegram stock trading groups, hotel review task apps, and guaranteed return schemes",
            "urgency": "CRITICAL PRIORITY — ASSET RECOVERY ACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "trending_up",
            "goldenHourNotice": "Stop transferring capital immediately. Fraudulent platforms display fabricated profit numbers to solicit larger deposits.",
            "whatHappened": "You were added to a VIP WhatsApp/Telegram trading group promising 200-500% returns on 'institutional IPO allocations' or paid hotel rating tasks.",
            "compromisedAssets": "Invested capital, bank accounts used for transfers, identity documents submitted for 'KYC'.",
            "immediateActions": [
                "STOP all further payments immediately. Do NOT pay 'withdrawal taxes', 'margin calls', or 'VIP upgrade fees'.",
                "Document all beneficiary bank accounts, UPI IDs, and cryptocurrency wallet addresses provided for deposits.",
                "Call National Cybercrime Helpline 1930 and report every individual transaction UTR number.",
                "File a formal report on cybercrime.gov.in detailing the investment syndicate."
            ],
            "checklist": [
                "Cease all payments immediately regardless of threats from 'mentors' or 'fund managers'.",
                "Compile a complete chronological spreadsheet of all deposits made, including dates, amounts, and UTR numbers.",
                "Dial 1930 and register the cumulative financial loss with law enforcement.",
                "Submit a detailed cybercrime.gov.in complaint with all chat logs, screenshots of the fake trading app, and beneficiary accounts.",
                "Report the fraudulent investment scheme to SEBI SCORES (scores.gov.in / 1800 266 7575).",
                "Report the WhatsApp group and Telegram channels using the DoT Chakshu portal.",
                "Contact your bank to report the transactions as fraud."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Police"
                },
                {
                    "entity": "SEBI Investor Grievances (SCORES)",
                    "info": "1800 266 7575 / scores.gov.in",
                    "channel": "Regulator"
                },
                {
                    "entity": "RBI Sachet Portal",
                    "info": "https://sachet.rbi.org.in",
                    "channel": "Regulator"
                }
            ],
            "evidence": [
                "Complete chat export of the WhatsApp / Telegram group",
                "Screenshots of the fake web portal showing the fabricated portfolio balance",
                "Bank statements showing all outgoing transfers with beneficiary account numbers",
                "Contact details and profile handles of the 'analysts' and 'customer managers'"
            ],
            "whatToAvoid": [
                "NEVER pay 'withdrawal taxes', 'SEBI clearance fees', or 'security deposits' to release your funds. They are 100% fake.",
                "Do NOT engage with 'recovery lawyers' or 'ethical hackers' online who guarantee fund recovery for a fee."
            ],
            "followUpPlan": "Only invest through SEBI-registered brokers and official mutual fund platforms. Verify SEBI registration at sebi.gov.in.",
            "steps": [
                "Cease all payments immediately regardless of threats from 'mentors' or 'fund managers'.",
                "Compile a complete chronological spreadsheet of all deposits made, including dates, amounts, and UTR numbers.",
                "Dial 1930 and register the cumulative financial loss with law enforcement.",
                "Submit a detailed cybercrime.gov.in complaint with all chat logs, screenshots of the fake trading app, and beneficiary accounts.",
                "Report the fraudulent investment scheme to SEBI SCORES (scores.gov.in / 1800 266 7575).",
                "Report the WhatsApp group and Telegram channels using the DoT Chakshu portal.",
                "Contact your bank to report the transactions as fraud."
            ],
            "priorityActions": [
                "STOP all further payments immediately. Do NOT pay 'withdrawal taxes', 'margin calls', or 'VIP upgrade fees'.",
                "Document all beneficiary bank accounts, UPI IDs, and cryptocurrency wallet addresses provided for deposits.",
                "Call National Cybercrime Helpline 1930 and report every individual transaction UTR number.",
                "File a formal report on cybercrime.gov.in detailing the investment syndicate."
            ]
        },
        "crypto_fraud": {
            "id": "crypto_fraud",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Crypto Phishing, Fake DEX & Wallet Drainers",
            "subtitle": "12/24-word seed phrase compromised, malicious smart contract signed, or funds sent to fake exchange",
            "urgency": "CRITICAL EMERGENCY — WALLET ABANDONMENT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "currency_bitcoin",
            "goldenHourNotice": "Blockchain transactions are irreversible. Immediate token transfer to a fresh hardware wallet is required for remaining assets.",
            "whatHappened": "You typed your seed phrase on a fake support website, connected your wallet to a malicious token drainer, or sent crypto to an unverified broker.",
            "compromisedAssets": "Private keys, 12/24-word secret seed phrase, all tokens on that wallet address across all chains.",
            "immediateActions": [
                "Immediately transfer any remaining tokens or NFTs to a brand new, clean wallet generated on an uncompromised device.",
                "Revoke all active smart contract approvals using revoke.cash or etherscan.io/tokenapprovalchecker.",
                "Consider the compromised wallet address permanently burnt; never use it again.",
                "Trace the destination transaction hash (TxHash) on block explorers (Etherscan, BscScan, Solscan)."
            ],
            "checklist": [
                "Create a fresh wallet on a clean device (preferably a hardware wallet: Ledger, Trezor).",
                "Move all uncompromised assets from the breached wallet immediately.",
                "Revoke ERC-20 / BEP-20 token allowances on revoke.cash to stop automated drainer scripts.",
                "Document all transaction hashes (TxHash), destination addresses, and timestamps.",
                "Report the fraud with TxHash to the receiving centralized exchange (Binance, CoinDCX, WazirX) if funds were moved to an exchange.",
                "File a complaint on cybercrime.gov.in with blockchain transaction evidence."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "Chainalysis / Etherscan Reporting",
                    "info": "etherscan.io/contactus",
                    "channel": "Explorer Flagging"
                },
                {
                    "entity": "Crypto Exchange Security Desks",
                    "info": "Contact exchange where destination wallet belongs",
                    "channel": "Exchange"
                }
            ],
            "evidence": [
                "Blockchain Transaction Hashes (TxHash) of all unauthorized transfers",
                "Attacker's destination wallet address",
                "URL of the phishing dApp, fake airdrop, or drainer website connected to",
                "Chat logs with support imposters requesting seed phrases"
            ],
            "whatToAvoid": [
                "NEVER deposit more crypto into the compromised wallet to 'pay gas fees for asset return'.",
                "Do NOT trust 'private crypto recovery detectives' on Telegram or Twitter. Private keys cannot be forced backwards."
            ],
            "followUpPlan": "Store seed phrases exclusively on offline physical paper or stamped metal plates. Never store seed phrases in cloud drives or screenshots.",
            "steps": [
                "Create a fresh wallet on a clean device (preferably a hardware wallet: Ledger, Trezor).",
                "Move all uncompromised assets from the breached wallet immediately.",
                "Revoke ERC-20 / BEP-20 token allowances on revoke.cash to stop automated drainer scripts.",
                "Document all transaction hashes (TxHash), destination addresses, and timestamps.",
                "Report the fraud with TxHash to the receiving centralized exchange (Binance, CoinDCX, WazirX) if funds were moved to an exchange.",
                "File a complaint on cybercrime.gov.in with blockchain transaction evidence."
            ],
            "priorityActions": [
                "Immediately transfer any remaining tokens or NFTs to a brand new, clean wallet generated on an uncompromised device.",
                "Revoke all active smart contract approvals using revoke.cash or etherscan.io/tokenapprovalchecker.",
                "Consider the compromised wallet address permanently burnt; never use it again.",
                "Trace the destination transaction hash (TxHash) on block explorers (Etherscan, BscScan, Solscan)."
            ]
        },
        "sextortion_blackmail": {
            "id": "sextortion_blackmail",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Sextortion, 'Digital Arrest' & Coercion Blackmail",
            "subtitle": "Blackmailed with compromised video clips, fake morphing, or threats of arrest by fake police",
            "urgency": "HIGH SAFETY PROTOCOL — DO NOT PAY",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "gavel",
            "goldenHourNotice": "Blackmailers rely on panic and shame. Paying money does NOT stop extortion; it guarantees escalating demands.",
            "whatHappened": "You received a compromised video call where your face was recorded, or an imposter claiming to be CBI, ED, or Cyber Police threatened you with immediate arrest.",
            "compromisedAssets": "Personal reputation, emotional well-being, contacts list (if malware was installed), financial assets.",
            "immediateActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ],
            "checklist": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "National Emergency Helpline",
                    "info": "112",
                    "channel": "Emergency Police"
                },
                {
                    "entity": "StopNCII (Non-Consensual Imagery)",
                    "info": "https://stopncii.org",
                    "channel": "Image Prevention Hub"
                },
                {
                    "entity": "National Commission for Women (NCW)",
                    "info": "7827170170",
                    "channel": "Support Desk"
                }
            ],
            "evidence": [
                "Screenshots of the threatening messages, demands, and countdown timers",
                "Phone numbers, WhatsApp accounts, and email addresses of the extortionist",
                "Bank account details or UPI IDs provided for extortion payments",
                "Any audio or video recordings of the threatening call"
            ],
            "whatToAvoid": [
                "NEVER pay money. Extortionists never delete compromising media after payment; they treat paying victims as recurring revenue.",
                "Do not delete chat logs before capturing complete evidence.",
                "Do not harm yourself or suffer in silence — law enforcement treats you as the VICTIM of organized extortion."
            ],
            "followUpPlan": "Deactivate social accounts temporarily. Keep device cameras covered when not in active use. Seek mental health counseling support.",
            "steps": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "priorityActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ]
        },
        "phishing_link": {
            "id": "phishing_link",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Phishing Link Clicked / Suspicious Website Visited",
            "subtitle": "Clicked an unknown link from SMS or email; uncertain if credentials or device were compromised",
            "urgency": "PRECAUTIONARY TRIAGE — AUDIT & SECURE",
            "urgencyClass": "bg-slate-100 text-slate-800 border-slate-300",
            "icon": "link_off",
            "goldenHourNotice": "If you merely visited the webpage without typing credentials or downloading files, your risk is low. Follow precautionary hygiene.",
            "whatHappened": "You clicked an unsolicited link in an SMS, email, or social media DM directing to an unverified domain.",
            "compromisedAssets": "IP address, browser user-agent, potential cookies, credentials (if typed into form).",
            "immediateActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ],
            "checklist": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "Google Safe Browsing Report",
                    "info": "https://safebrowsing.google.com/safebrowsing/report_phish/",
                    "channel": "Global Defense"
                }
            ],
            "evidence": [
                "Full URL of the phishing link (copied without clicking)",
                "Sender mobile number or email address",
                "Screenshot of the SMS or email containing the deceptive link"
            ],
            "whatToAvoid": [
                "Do NOT enter test passwords or personal info on the page to 'check if it works'.",
                "Do not click 'Allow' on notification popups or permission prompts from unknown websites."
            ],
            "followUpPlan": "Enable enhanced safe browsing in your browser. Use DNS filtering (NextDNS, Cloudflare 1.1.1.2) to block known phishing domains.",
            "steps": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "priorityActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ]
        },
        "fake_support": {
            "id": "fake_support",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Fake Customer Support & Search Ad Scams",
            "subtitle": "Searched Google for airline, bank, or courier customer care and called a fraudulent number",
            "urgency": "HIGH URGENCY — HALT INTERACTION",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "support_agent",
            "goldenHourNotice": "Fraudsters purchase search ads or edit Google Maps listings to substitute their phone numbers for genuine corporate helplines.",
            "whatHappened": "You searched Google for customer support (Swiggy, Indigo, Amazon, SBI) and dialed a sponsored search result or manipulated Maps contact.",
            "compromisedAssets": "Disclosed banking details, OTPs, remote access permissions, payment funds.",
            "immediateActions": [
                "Disconnect the phone call immediately. The person you are speaking with is NOT a company representative.",
                "If you installed AnyDesk, TeamViewer, or shared any code, turn on Airplane Mode and uninstall the app.",
                "If you authorized a payment on their instruction, call your bank immediately to dispute the charge.",
                "Only contact companies through their verified in-app help centers or verified physical paperwork."
            ],
            "checklist": [
                "Hang up the call immediately. Cease all further conversation with that phone number.",
                "If you opened a link or downloaded an app sent by the fake agent, uninstall it immediately.",
                "If you made a payment via UPI or card, contact your bank fraud desk immediately to file a chargeback.",
                "Report the fraudulent phone number on the DoT Chakshu portal (sancharsaathi.gov.in).",
                "Report the deceptive Google search ad or fraudulent Google Maps listing (Suggest an edit -> Mark as fraudulent).",
                "Access the authentic company customer support strictly via their verified mobile app."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930",
                    "channel": "Police"
                },
                {
                    "entity": "Google Ad Complaints",
                    "info": "https://support.google.com/google-ads/troubleshooter/4578507",
                    "channel": "Search Engine"
                }
            ],
            "evidence": [
                "Phone number dialed from your call history",
                "Search query used on Google that displayed the fake result",
                "Screenshot of the search engine ad or Google Maps business profile",
                "Payment receipts or UPI reference numbers if money was transferred"
            ],
            "whatToAvoid": [
                "NEVER trust top search results on Google blindly — scammers routinely purchase Google Sponsored Ads to impersonate brands.",
                "Genuine customer care never asks you to download screen-sharing tools or transfer a '₹5 test verification charge'."
            ],
            "followUpPlan": "Bookmark official brand portals. Always initiate support requests from inside official banking or e-commerce apps.",
            "steps": [
                "Hang up the call immediately. Cease all further conversation with that phone number.",
                "If you opened a link or downloaded an app sent by the fake agent, uninstall it immediately.",
                "If you made a payment via UPI or card, contact your bank fraud desk immediately to file a chargeback.",
                "Report the fraudulent phone number on the DoT Chakshu portal (sancharsaathi.gov.in).",
                "Report the deceptive Google search ad or fraudulent Google Maps listing (Suggest an edit -> Mark as fraudulent).",
                "Access the authentic company customer support strictly via their verified mobile app."
            ],
            "priorityActions": [
                "Disconnect the phone call immediately. The person you are speaking with is NOT a company representative.",
                "If you installed AnyDesk, TeamViewer, or shared any code, turn on Airplane Mode and uninstall the app.",
                "If you authorized a payment on their instruction, call your bank immediately to dispute the charge.",
                "Only contact companies through their verified in-app help centers or verified physical paperwork."
            ]
        },
        "money_sent": {
            "id": "money_transferred",
            "category": "financial",
            "categoryName": "Financial & Banking",
            "title": "Money Transferred / Financial Fraud",
            "subtitle": "Direct fund loss via IMPS, NEFT, RTGS, NetBanking or wire transfer",
            "urgency": "CRITICAL PRIORITY — GOLDEN HOUR PROTOCOL",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "payments",
            "goldenHourNotice": "Transactions reported within the first 2-3 hours have a significantly higher probability of inter-bank lien freezing before cash is withdrawn at destination ATMs.",
            "whatHappened": "You transferred funds to a scammer or unauthorized beneficiary following deceptive claims (KYC update, bill cutoff, fake job fee, or emergency family call).",
            "compromisedAssets": "Transferred capital, bank account number, sender IFSC, and potential mobile number exposure.",
            "immediateActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ],
            "checklist": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "Dial 1930 (Toll-Free, 24x7)",
                    "channel": "Phone"
                },
                {
                    "entity": "NCRP Citizen Portal",
                    "info": "https://cybercrime.gov.in",
                    "channel": "Web Portal"
                },
                {
                    "entity": "Your Bank Fraud Desk",
                    "info": "Phone number printed on back of Debit/Credit card",
                    "channel": "Direct Bank"
                }
            ],
            "evidence": [
                "Transaction Reference Number (UTR / RRN / IMPS Reference ID)",
                "Bank SMS notification received immediately after the debit",
                "Account statement or mini-statement showing debit timestamp and beneficiary details",
                "Screenshots of communication (WhatsApp, Telegram, SMS, or call log) with the perpetrator",
                "Beneficiary account number, IFSC code, or UPI ID where money was directed"
            ],
            "whatToAvoid": [
                "NEVER pay 'recovery clearance fees' or hire 'online ethical hackers' promising to retrieve lost funds. They are secondary scammers.",
                "Do NOT delete chat history, call recordings, or SMS threads with the perpetrator.",
                "Do NOT share OTPs with anyone claiming to represent your bank's 'reversal division'."
            ],
            "followUpPlan": "Monitor account statement weekly for recurring mandates. File an insurance claim if you hold cyber insurance. Maintain the police FIR copy for future banking dispute resolution.",
            "steps": [
                "Dial 1930 and provide Transaction UTR Number, source account, and beneficiary account details.",
                "Call your bank's dedicated fraud control unit and request an immediate dispute / lien marking.",
                "Log into your bank portal and change your NetBanking login password and transaction password.",
                "File an official complaint on cybercrime.gov.in (National Cyber Crime Reporting Portal).",
                "Collect and organize all digital evidence (bank SMS, mini-statement, debit advice, WhatsApp chats).",
                "Visit your home bank branch with a physical copy of the cybercrime acknowledgment letter.",
                "Submit a written letter to the branch manager requesting beneficiary account freezing under RBI guidelines."
            ],
            "priorityActions": [
                "Call National Cybercrime Helpline 1930 immediately with transaction UTR / Reference numbers.",
                "Contact your bank's 24x7 emergency fraud helpline to dispute the transfer and request inter-bank recall.",
                "File a formal digital fraud complaint on cybercrime.gov.in and obtain your acknowledgment number.",
                "Freeze NetBanking and change account access credentials immediately."
            ]
        },
        "credentials_shared": {
            "id": "password_stolen",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Stolen Password & Account Takeover",
            "subtitle": "Primary account password disclosed, phished, or leaked in data breach",
            "urgency": "HIGH URGENCY — CREDENTIAL CONTAINMENT",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "vpn_key",
            "goldenHourNotice": "Attackers leverage stolen passwords across multiple platforms via automated credential stuffing scripts.",
            "whatHappened": "Your password was captured on a phishing page, intercepted on unsecured public Wi-Fi, or surfaced in a credential dump.",
            "compromisedAssets": "Login access to affected service, potentially other accounts sharing the same password.",
            "immediateActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ],
            "checklist": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "contacts": [
                {
                    "entity": "Google Account Recovery",
                    "info": "https://accounts.google.com/signin/recovery",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Microsoft Security",
                    "info": "https://account.live.com/password/reset",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Apple ID Support",
                    "info": "https://iforgot.apple.com",
                    "channel": "Self-Service"
                }
            ],
            "evidence": [
                "Security alert emails received notifying of login from unknown IP or city",
                "Phishing email or URL where the credential was typed",
                "Timestamp when access was lost or changed"
            ],
            "whatToAvoid": [
                "Never re-use passwords across email, banking, and social accounts.",
                "Do not store passwords in unencrypted plaintext notes or screenshots."
            ],
            "followUpPlan": "Run a scan on haveibeenpwned.com to check for leaked accounts. Rotate all critical service credentials.",
            "steps": [
                "Change password immediately using a unique, complex combination of words, numbers, and symbols.",
                "Terminate all existing logged-in sessions in account settings (Security -> Active Sessions -> Sign Out All).",
                "Enable 2FA via Authenticator App; avoid SMS 2FA if SIM swap is a concern.",
                "Check recovery email and phone number to verify the attacker did not substitute their own details.",
                "Audit connected third-party apps (Security -> Third-Party Access -> Revoke Unknown).",
                "Adopt a dedicated password manager (Bitwarden, 1Password, Apple Keychain)."
            ],
            "priorityActions": [
                "Log into the affected service and change password to a unique 16+ character passphrase.",
                "Select 'Log out of all other devices / active sessions' across security settings.",
                "Enable Two-Factor Authentication (2FA) using an Authenticator app (Google Authenticator, Microsoft Authenticator, or YubiKey).",
                "Change passwords on any other account that shared this password (especially email and banking)."
            ]
        },
        "apk_installed": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "app_installed": {
            "id": "malicious_apk",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Malicious APK & Android Malware Installation",
            "subtitle": "Installed an untrusted .apk file from WhatsApp, SMS, or deceptive webpage",
            "urgency": "IMMEDIATE DEVICE THREAT — NETWORK DISCONNECT",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "android",
            "goldenHourNotice": "Malicious APKs contain SMS-forwarders and banking trojans that intercept OTPs and log screen touches in real time.",
            "whatHappened": "You downloaded and sideloaded an APK file (e.g. 'HDFC_KYC.apk', 'PM_Yojana.apk', 'Discom_Update.apk') masquerading as an official service.",
            "compromisedAssets": "Device SMS access, contact list, accessibility controls, screen contents, bank credentials.",
            "immediateActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ],
            "checklist": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "contacts": [
                {
                    "entity": "CERT-In Malware Bureau",
                    "info": "incident@cert-in.org.in / 1800-11-4949",
                    "channel": "National Response"
                },
                {
                    "entity": "Google Play Protect Help",
                    "info": "https://support.google.com/googleplay/answer/2812853",
                    "channel": "Self-Service"
                },
                {
                    "entity": "Your Bank Fraud Cell",
                    "info": "Number on back of debit card",
                    "channel": "Bank"
                }
            ],
            "evidence": [
                "Name of the APK file and exact download URL",
                "Phone number or WhatsApp group from where the APK was shared",
                "List of permissions requested by the application"
            ],
            "whatToAvoid": [
                "Do NOT turn internet back on until the malicious app is fully removed.",
                "Never enter NetBanking passwords or open banking apps while the malware is present."
            ],
            "followUpPlan": "Keep 'Install unknown apps' disabled in Android settings. Do not download files from WhatsApp attachments.",
            "steps": [
                "Disconnect device from internet instantly (Airplane Mode ON, Wi-Fi OFF, SIM removed if necessary).",
                "Navigate to Settings -> Security -> Device Admin Apps: Revoke admin privileges for the rogue APK.",
                "Navigate to Settings -> Accessibility: Turn OFF accessibility services granted to suspicious apps.",
                "Boot into Safe Mode and uninstall the APK file.",
                "Open Downloads folder and delete the raw .apk installer file.",
                "Run a full security scan using Google Play Protect (Play Store -> Play Protect -> Scan).",
                "If the app cannot be removed or requested root privileges, perform a complete Factory Data Reset.",
                "Using a clean device, contact your bank to verify no unauthorized transfers were queued."
            ],
            "priorityActions": [
                "Immediately turn on AIRPLANE MODE and disable Wi-Fi to stop malware from sending your SMS and credentials to the attacker.",
                "Reboot your phone into Safe Mode (press and hold Power, then tap and hold 'Power off').",
                "Navigate to Settings -> Apps and locate the rogue app (often has no icon or generic gear icon); uninstall it.",
                "Using a separate, uninfected phone or laptop, change passwords for all banking and email accounts."
            ]
        },
        "account_compromised": {
            "id": "whatsapp_social_takeover",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "WhatsApp & Social Media Hijacking",
            "subtitle": "WhatsApp 6-digit registration PIN tricked, or Instagram/Facebook hijacked",
            "urgency": "HIGH URGENCY — PREVENT CONTACT FRAUD",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "forum",
            "goldenHourNotice": "Scammers immediately message your close family, friends, and colleagues begging for urgent medical or emergency UPI transfers.",
            "whatHappened": "You shared a 6-digit SMS code or fell for a call forwarding code (*21*...), giving an attacker access to your WhatsApp or social account.",
            "compromisedAssets": "Chat history, personal contact list, ability to impersonate you to friends and family.",
            "immediateActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ],
            "checklist": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "contacts": [
                {
                    "entity": "WhatsApp Support Email",
                    "info": "support@whatsapp.com",
                    "channel": "Email"
                },
                {
                    "entity": "Instagram Hacked Recovery",
                    "info": "https://instagram.com/hacked",
                    "channel": "Portal"
                },
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Reporting"
                }
            ],
            "evidence": [
                "Phone numbers from which verification codes were requested",
                "Screenshots of messages sent by hacker to your contacts demanding funds",
                "UPI handles where the hacker asked your friends to transfer money"
            ],
            "whatToAvoid": [
                "Never pay ransom to anyone claiming they will return your account for money.",
                "Never share 6-digit verification codes sent to your phone with anyone, even contacts who appear to be friends."
            ],
            "followUpPlan": "Enable biometric app lock. Educate close contacts on your verified emergency communication protocol.",
            "steps": [
                "Warn your primary WhatsApp groups and close contacts through phone calls or SMS.",
                "Dial ##002# and ##21# on your phone to cancel conditional and unconditional call forwarding.",
                "Re-install WhatsApp and complete SMS verification to regain master session control.",
                "Once restored, enable Two-Step Verification (Settings -> Account -> Two-Step Verification -> Set PIN).",
                "For Instagram / Facebook, go to Security -> Where You're Logged In -> Log Out All Sessions.",
                "Report hijacked profile to WhatsApp support (support@whatsapp.com with 'Lost/Stolen: Please deactivate my account' + phone number in international format).",
                "Report imposter accounts requesting funds to 1930."
            ],
            "priorityActions": [
                "Immediately post on other social channels or call family members warning them: 'My WhatsApp is hacked. Do NOT send money!'.",
                "Re-register WhatsApp: Enter your phone number, request SMS code, and enter it (this automatically logs out the intruder).",
                "If the hacker set a Two-Step Verification PIN, you must wait 7 days to access chats, but the intruder is still kicked out immediately.",
                "Dial ##002# on your phone dialer to cancel any active call forwarding."
            ]
        },
        "link_clicked": {
            "id": "phishing_link",
            "category": "malware",
            "categoryName": "Device & Malware",
            "title": "Phishing Link Clicked / Suspicious Website Visited",
            "subtitle": "Clicked an unknown link from SMS or email; uncertain if credentials or device were compromised",
            "urgency": "PRECAUTIONARY TRIAGE — AUDIT & SECURE",
            "urgencyClass": "bg-slate-100 text-slate-800 border-slate-300",
            "icon": "link_off",
            "goldenHourNotice": "If you merely visited the webpage without typing credentials or downloading files, your risk is low. Follow precautionary hygiene.",
            "whatHappened": "You clicked an unsolicited link in an SMS, email, or social media DM directing to an unverified domain.",
            "compromisedAssets": "IP address, browser user-agent, potential cookies, credentials (if typed into form).",
            "immediateActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ],
            "checklist": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "contacts": [
                {
                    "entity": "DoT Sanchar Saathi Chakshu",
                    "info": "https://sancharsaathi.gov.in/sfc/",
                    "channel": "Government"
                },
                {
                    "entity": "Google Safe Browsing Report",
                    "info": "https://safebrowsing.google.com/safebrowsing/report_phish/",
                    "channel": "Global Defense"
                }
            ],
            "evidence": [
                "Full URL of the phishing link (copied without clicking)",
                "Sender mobile number or email address",
                "Screenshot of the SMS or email containing the deceptive link"
            ],
            "whatToAvoid": [
                "Do NOT enter test passwords or personal info on the page to 'check if it works'.",
                "Do not click 'Allow' on notification popups or permission prompts from unknown websites."
            ],
            "followUpPlan": "Enable enhanced safe browsing in your browser. Use DNS filtering (NextDNS, Cloudflare 1.1.1.2) to block known phishing domains.",
            "steps": [
                "Close the malicious browser tab immediately.",
                "Inspect your device's Downloads folder; delete any unrequested downloaded files without opening them.",
                "Open browser Settings -> Clear Browsing Data: Clear Cookies and Cached Images.",
                "If you entered credentials (username, password, phone, card), immediately change that password on the authentic website.",
                "Run a device security scan using Google Play Protect (Android) or Windows Defender (PC).",
                "Block the sender number or email address that transmitted the phishing link.",
                "Submit the deceptive URL to SCAM BREAKER and report it on Sanchar Saathi Chakshu."
            ],
            "priorityActions": [
                "Close the browser tab immediately.",
                "Check your browser Downloads folder to verify no file (.apk, .exe, .zip) was downloaded automatically; delete it if found.",
                "Clear your browser cache, history, and stored cookies.",
                "If you entered any password on that page, change that password immediately on the genuine service website."
            ]
        },
        "personal_info_leaked": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "personal_info_shared": {
            "id": "identity_theft",
            "category": "account",
            "categoryName": "Account & Identity",
            "title": "Identity Document Misuse (Aadhaar / PAN)",
            "subtitle": "Photocopies or numbers of Aadhaar, PAN card, or passport shared with fraudsters",
            "urgency": "MODERATE URGENCY — IDENTITY VIGILANCE",
            "urgencyClass": "bg-amber-100 text-amber-800 border-amber-300",
            "icon": "badge",
            "goldenHourNotice": "Identity misuse unfolds over weeks or months via fraudulent mobile connections, credit cards, or instant micro-loans.",
            "whatHappened": "You uploaded or emailed identity documents to an unverified loan app, job scam portal, or deceptive rental platform.",
            "compromisedAssets": "Aadhaar number, PAN card number, biometric credentials, address, date of birth.",
            "immediateActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ],
            "checklist": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "contacts": [
                {
                    "entity": "UIDAI Biometric Lock",
                    "info": "1947 / https://resident.uidai.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "DoT TAFCOP SIM Verification",
                    "info": "https://tafcop.sancharsaathi.gov.in",
                    "channel": "Government"
                },
                {
                    "entity": "CIBIL Dispute Center",
                    "info": "https://www.cibil.com/dispute-center",
                    "channel": "Credit Bureau"
                }
            ],
            "evidence": [
                "Screenshots of the website, app, or email thread where documents were uploaded",
                "Dates and specific documents shared (front/back of Aadhaar, PAN card, selfie)",
                "Names of entities the scammer claimed to represent"
            ],
            "whatToAvoid": [
                "Never share color, unmasked photocopies of your Aadhaar card.",
                "Always cross out physical photocopies with: 'Provided exclusively for [Purpose] on [Date]'."
            ],
            "followUpPlan": "Set up credit monitoring alerts. Keep Aadhaar biometrics locked until you physically visit a center for verification.",
            "steps": [
                "Lock Aadhaar biometrics via UIDAI portal (prevents unauthorized fingerprint-based AePS withdrawals).",
                "Generate a Virtual ID (VID) and use Masked Aadhaar for future identity verifications.",
                "Log into TAFCOP portal and report any mobile numbers listed under your identity that you do not own.",
                "Check your PAN card linkages on the Income Tax e-filing portal.",
                "Review your credit score report for unknown consumer loan accounts (Dhani, Bajaj, KreditBee).",
                "File a preventive cybercrime report noting that your identity documents were fraudulently obtained."
            ],
            "priorityActions": [
                "Open the UIDAI mAadhaar app or visit resident.uidai.gov.in to LOCK your Aadhaar Biometrics immediately.",
                "Visit Sanchar Saathi TAFCOP (tafcop.sancharsaathi.gov.in) to check all mobile connections issued under your Aadhaar.",
                "Pull your free credit reports from CIBIL, Experian, or CRIF High Mark to check for unauthorized loan inquiries.",
                "File a digital information report at cybercrime.gov.in recording the document compromise."
            ]
        },
        "other_threat": {
            "id": "sextortion_blackmail",
            "category": "extortion",
            "categoryName": "Deception & Extortion",
            "title": "Sextortion, 'Digital Arrest' & Coercion Blackmail",
            "subtitle": "Blackmailed with compromised video clips, fake morphing, or threats of arrest by fake police",
            "urgency": "HIGH SAFETY PROTOCOL — DO NOT PAY",
            "urgencyClass": "bg-rose-100 text-rose-800 border-rose-300",
            "icon": "gavel",
            "goldenHourNotice": "Blackmailers rely on panic and shame. Paying money does NOT stop extortion; it guarantees escalating demands.",
            "whatHappened": "You received a compromised video call where your face was recorded, or an imposter claiming to be CBI, ED, or Cyber Police threatened you with immediate arrest.",
            "compromisedAssets": "Personal reputation, emotional well-being, contacts list (if malware was installed), financial assets.",
            "immediateActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ],
            "checklist": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "contacts": [
                {
                    "entity": "National Cybercrime Helpline",
                    "info": "1930 / cybercrime.gov.in",
                    "channel": "Police"
                },
                {
                    "entity": "National Emergency Helpline",
                    "info": "112",
                    "channel": "Emergency Police"
                },
                {
                    "entity": "StopNCII (Non-Consensual Imagery)",
                    "info": "https://stopncii.org",
                    "channel": "Image Prevention Hub"
                },
                {
                    "entity": "National Commission for Women (NCW)",
                    "info": "7827170170",
                    "channel": "Support Desk"
                }
            ],
            "evidence": [
                "Screenshots of the threatening messages, demands, and countdown timers",
                "Phone numbers, WhatsApp accounts, and email addresses of the extortionist",
                "Bank account details or UPI IDs provided for extortion payments",
                "Any audio or video recordings of the threatening call"
            ],
            "whatToAvoid": [
                "NEVER pay money. Extortionists never delete compromising media after payment; they treat paying victims as recurring revenue.",
                "Do not delete chat logs before capturing complete evidence.",
                "Do not harm yourself or suffer in silence — law enforcement treats you as the VICTIM of organized extortion."
            ],
            "followUpPlan": "Deactivate social accounts temporarily. Keep device cameras covered when not in active use. Seek mental health counseling support.",
            "steps": [
                "Do NOT send any money, cryptocurrency, or gift cards under any circumstances.",
                "Take screenshots of all threats, demands, phone numbers, and payment details before blocking.",
                "Immediately block the perpetrator on WhatsApp, Telegram, Skype, and phone calls.",
                "Set all personal social media profiles to strictly Private; restrict who can see your friends list.",
                "Dial National Cybercrime Helpline 1930 and ask for the specialized Women/Cyber Extortion division.",
                "File a formal complaint on cybercrime.gov.in under 'Report Cyber Crime Related to Women/Children' or 'Other Cyber Crime'.",
                "Confide in a trusted family member, counselor, or lawyer — break the psychological isolation.",
                "Use StopNCII.org to generate digital hashes and prevent intimate image distribution across major tech platforms."
            ],
            "priorityActions": [
                "DO NOT PAY ANY MONEY. Paying guarantees the extortionist will demand exponentially larger amounts.",
                "Disconnect and block the blackmailer immediately across all platforms.",
                "Lock your social media profiles (Facebook Profile Lock, set Instagram to Private) to prevent contact harvesting.",
                "Dial 1930 or 112 immediately and report the extortion to the National Cybercrime Reporting Portal."
            ]
        }
    }
}
};

// Export to window for vanilla JS access with backwards-compatible alias
window.SCAM_BREAKER_DATA = SCAM_BREAKER_DATA;
window.SCAM_KILLER_DATA = SCAM_BREAKER_DATA;
