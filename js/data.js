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

  // Comprehensive Scam Recovery Database (Institutions, Helplines, and Action Trees)
  recoveryGuidance: {
    bankHelplines: [
      { name: "State Bank of India (SBI)", phone: "1800 11 2211", altPhone: "1800 425 3800", smsBlock: "BLOCK <Account Number> to 567676", portal: "https://onlinesbi.sbi" },
      { name: "HDFC Bank", phone: "1800 202 6161", altPhone: "1800 258 3838", smsBlock: "Call 1800 258 3838 immediately", portal: "https://netbanking.hdfcbank.com" },
      { name: "ICICI Bank", phone: "1800 1080", altPhone: "1800 200 3344", smsBlock: "SMS BLOCK to 9215676766", portal: "https://infinity.icicibank.com" },
      { name: "Axis Bank", phone: "1800 419 5577", altPhone: "1800 103 5577", smsBlock: "SMS BLOCK to 5676782", portal: "https://axisbank.com" },
      { name: "Punjab National Bank (PNB)", phone: "1800 180 2222", altPhone: "1800 103 2222", smsBlock: "SMS HOTCARD <Card Number> to 5607040", portal: "https://netpnb.com" },
      { name: "Bank of Baroda", phone: "1800 570 0", altPhone: "1800 258 4455", smsBlock: "Call 1800 570 0 to freeze NetBanking", portal: "https://bobibanking.com" }
    ],
    officialAuthorities: [
      { name: "National Cyber Crime Helpline", contact: "1930", url: "https://cybercrime.gov.in", note: "Citizen Financial Cyber Fraud Reporting System — Immediate fund freezing mechanism." },
      { name: "DoT Chakshu (Sanchar Saathi)", contact: "Online Portal", url: "https://sancharsaathi.gov.in/sfc/", note: "Official platform for reporting fraudulent mobile numbers, SMS, and WhatsApp callers." },
      { name: "National Consumer Helpline", contact: "1915", url: "https://consumerhelpline.gov.in", note: "E-commerce and false advertising dispute resolution." }
    ],
    situationPlaybooks: {
      money_sent: {
        title: "Money Sent / Financial Loss",
        subtitle: "Unauthorized or coerced transfer via UPI, NetBanking, IMPS, or Card",
        urgency: "CRITICAL — Golden Hour Protocol",
        goldenHourNotice: "Transactions reported within 2 hours have a significantly higher probability of being frozen in destination beneficiary accounts by law enforcement and partner banks.",
        priorityActions: [
          "Call National Cybercrime Helpline 1930 immediately to register the transaction UTR number and beneficiary account.",
          "Call your bank's dedicated fraud emergency desk (printed on debit card or listed below) to freeze your NetBanking and debit card.",
          "File an official police acknowledgment on cybercrime.gov.in and save the acknowledgment token.",
          "Preserve all transaction receipts, SMS alerts, UPI transaction IDs, and chat screenshots as evidence."
        ],
        whatToAvoid: [
          "NEVER pay 'refund clearance fees' or hire 'crypto recovery agents' online. They are secondary scammers.",
          "Do not delete chat logs or SMS threads with the scammer — they are criminal evidence."
        ]
      },
      credentials_shared: {
        title: "OTP, PIN or Password Disclosed",
        subtitle: "Shared authentication credentials with an unsolicited caller or website",
        urgency: "HIGH EMERGENCY",
        goldenHourNotice: "Attackers with credentials can initiate unauthorized transactions at any moment. Act before transactions occur.",
        priorityActions: [
          "Immediately log into your official NetBanking portal and change your login password and transaction passwords.",
          "If locked out, immediately call your bank's toll-free helpline to freeze NetBanking and hotlist your cards.",
          "For UPI compromise, open your UPI app and reset your UPI PIN using your ATM debit card details.",
          "Enable two-factor authentication (2FA) with an authenticator app (Google/Microsoft Authenticator) instead of SMS."
        ],
        whatToAvoid: [
          "Never read new OTPs aloud to any caller claiming to 'reverse the compromised transaction'.",
          "Do not use the same password across multiple financial or email accounts."
        ]
      },
      app_installed: {
        title: "Suspicious App or APK Installed",
        subtitle: "Installed an unknown APK file or remote desktop tool (AnyDesk, QuickSupport, TeamViewer)",
        urgency: "IMMEDIATE DEVICE THREAT",
        goldenHourNotice: "Malicious APKs and remote tools can intercept OTPs in real time and capture banking screens.",
        priorityActions: [
          "Immediately turn on AIRPLANE MODE and disconnect from Wi-Fi to stop remote command transmission.",
          "Boot your phone in Safe Mode (or power off) and uninstall the suspicious application or APK.",
          "Navigate to Settings → Security → Device Admin Apps and revoke permissions for any unknown managers.",
          "Using a different clean device, change your primary email and banking passwords.",
          "If the app had root or deep administrative privileges, perform a full Factory Reset."
        ],
        whatToAvoid: [
          "Do not open banking apps while the infected device is connected to the internet.",
          "Never approve unknown accessibility service prompts or screen-recording permissions."
        ]
      },
      account_compromised: {
        title: "Account Access Compromised",
        subtitle: "WhatsApp, Google, social media, or email account hijacked or locked out",
        urgency: "HIGH URGENCY",
        goldenHourNotice: "Hijacked accounts are rapidly leveraged to solicit emergency funds from your family and contacts.",
        priorityActions: [
          "Immediately alert your family, friends, and colleagues via phone or SMS not to send money to anyone claiming to be you.",
          "Initiate account recovery via the official platform's account recovery flow (e.g. WhatsApp verification code, Google Account Recovery).",
          "Revoke all active device sessions: Settings → Linked Devices → Log out from all sessions.",
          "If your mobile network disconnected unexpectedly, visit your telecom provider branch immediately to check for an unauthorized SIM Swap."
        ],
        whatToAvoid: [
          "Do not pay ransoms demanded by hijackers. They rarely restore access upon payment.",
          "Never share verification PINs sent to your phone during recovery."
        ]
      },
      link_clicked: {
        title: "Suspicious Link Clicked / Spoofed Site Visited",
        subtitle: "Opened a phishing URL or potential malware download link",
        urgency: "MODERATE CAUTION",
        goldenHourNotice: "If you did not enter credentials or download files, device risk is low. Follow precautionary containment.",
        priorityActions: [
          "Close the browser tab immediately and clear your browser's cookies and cached site data.",
          "Check your Downloads folder and immediately delete any downloaded .apk, .exe, or .zip files without opening them.",
          "Run a scan using your device's built-in security scanner (Google Play Protect on Android, Apple Security on iOS).",
          "If you entered your password on the page, change that password immediately on the genuine official website."
        ],
        whatToAvoid: [
          "Do not click 'Allow' on notification popups or permission prompts from unknown websites.",
          "Do not enter test credentials or personal details to 'see what happens'."
        ]
      },
      personal_info_shared: {
        title: "Personal Information Disclosed",
        subtitle: "Shared Aadhaar, PAN card, address, or ID documents with a fraudster",
        urgency: "MODERATE — IDENTITY VIGILANCE",
        goldenHourNotice: "Identity theft occurs over weeks or months. Implement preventative credit and biometric locks.",
        priorityActions: [
          "Lock your Aadhaar biometrics using the official UIDAI portal (m-Aadhaar app or resident.uidai.gov.in).",
          "Check Sanchar Saathi TAFCOP (sancharsaathi.gov.in) to verify all mobile numbers issued under your Aadhaar.",
          "Monitor your monthly bank account statements and CIBIL/Experian credit reports for unauthorized loan applications.",
          "File an information report on cybercrime.gov.in stating that your ID documents were fraudulently collected."
        ],
        whatToAvoid: [
          "Do not share color photocopies of national IDs without crossing out purpose and adding self-attested watermarks."
        ]
      },
      other_threat: {
        title: "Other Scam Incident / Coercion Threat",
        subtitle: "Extortion, blackmail, deepfake calls, lottery claims, or unexpected threats",
        urgency: "URGENT SAFETY PROTOCOL",
        goldenHourNotice: "Scammers rely on psychological shock and isolation. Break the isolation immediately.",
        priorityActions: [
          "Disconnect the call and block the sender. Cease all communication immediately.",
          "Speak to a trusted family member, legal advisor, or senior police officer. Do not keep it a secret.",
          "Report the caller's phone number on the DoT Chakshu portal (sancharsaathi.gov.in).",
          "If threatened with physical harm or immediate arrest, dial 112 (National Emergency) or 1930."
        ],
        whatToAvoid: [
          "NEVER transfer money under threat. Scammers will only demand larger sums once a payment is made.",
          "Do not engage in arguments or emotional exchanges with the extortionist."
        ]
      }
    }
  }
};

// Export to window for vanilla JS access with backwards-compatible alias
window.SCAM_BREAKER_DATA = SCAM_BREAKER_DATA;
window.SCAM_KILLER_DATA = SCAM_BREAKER_DATA;
