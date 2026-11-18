-- =============================================================================
-- SCAM KILLER — PostgreSQL Production Database Schema
-- Provides high-performance persistent telemetry, audit logs, and community intelligence.
-- =============================================================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Threat Scans Table (Strictly Non-Sensitive Metadata)
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) UNIQUE NOT NULL,
    scan_type VARCHAR(32) NOT NULL,
    risk_category VARCHAR(32) NOT NULL,
    timestamp VARCHAR(64) NOT NULL,
    time_ago VARCHAR(64) DEFAULT 'Just now',
    display_item TEXT NOT NULL,
    content_status VARCHAR(32),
    url_status VARCHAR(32),
    screenshot_status VARCHAR(32),
    intel_status VARCHAR(32),
    indicator_count INTEGER DEFAULT 0,
    explanation TEXT,
    metadata_json TEXT,
    source_type VARCHAR(32) DEFAULT 'text',
    confidence REAL DEFAULT 0.8,
    ai_summary TEXT DEFAULT '',
    structured_data TEXT DEFAULT '',
    full_report_json TEXT DEFAULT '',
    pattern_fingerprint VARCHAR(64) DEFAULT '',
    impersonated_entity VARCHAR(128) DEFAULT 'None',
    category VARCHAR(64) DEFAULT 'General Phishing',
    message_theme VARCHAR(128) DEFAULT '',
    urgency_or_reward_pattern VARCHAR(128) DEFAULT '',
    requested_action VARCHAR(128) DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Community Threat Reports Table
CREATE TABLE IF NOT EXISTS community_reports (
    id SERIAL PRIMARY KEY,
    report_id VARCHAR(64) UNIQUE NOT NULL,
    category VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    reported_item TEXT NOT NULL,
    date_reported VARCHAR(64) NOT NULL,
    upvotes INTEGER DEFAULT 0,
    risk_level VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    description TEXT,
    is_demo INTEGER DEFAULT 0,
    source VARCHAR(32) DEFAULT 'community',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. High-Performance Query Indexes
CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_category);
CREATE INDEX IF NOT EXISTS idx_scans_category ON scans(category);
CREATE INDEX IF NOT EXISTS idx_scans_fingerprint ON scans(pattern_fingerprint);
CREATE INDEX IF NOT EXISTS idx_community_report_id ON community_reports(report_id);
CREATE INDEX IF NOT EXISTS idx_community_category ON community_reports(category);
CREATE INDEX IF NOT EXISTS idx_community_upvotes ON community_reports(upvotes DESC);

-- 4. Initial Verified Community Intelligence Seed Data
INSERT INTO community_reports (report_id, category, title, reported_item, date_reported, upvotes, risk_level, status, description, is_demo, source)
VALUES
('CR-9041', 'Banking / KYC', 'Fake SBI Account Suspension APK', 'sbi-reward-yono.apk (bit.ly/sbi-rewards-2024)', '2024-03-24', 42, 'suspicious', 'Verified Phish', 'SMS claiming YONO reward points are expiring. Demands download of malware APK that steals incoming 2FA OTPs.', 1, 'verified_intel'),
('CR-9042', 'Delivery Phishing', 'India Post Address Update Phishing Link', 'indapost-redirection-service.top/update', '2024-03-24', 38, 'suspicious', 'Active Campaign', 'Urgent SMS claiming parcel cannot be delivered due to incomplete pin code. Traps users on credential harvesting portal.', 1, 'verified_intel'),
('CR-9043', 'Work-from-Home', 'Telegram YouTube Video Like Task Fraud', 't.me/youtube_commission_tasks_hr', '2024-03-23', 29, 'suspicious', 'Confirmed Scam', 'Victims paid Rs. 150 for 3 video likes, then coerced into investing Rs. 50,000 in prepaid cryptocurrency trading tasks.', 1, 'verified_intel'),
('CR-9044', 'Utility Bill', 'Urgent Electricity Disconnection Threat', 'Call 98210-XXXXX or bill update link', '2024-03-23', 19, 'suspicious', 'Active Threat', 'SMS warning power will be disconnected at 9:30 PM tonight due to unpaid bill. Fraudster demands installing remote screen-share app.', 1, 'verified_intel')
ON CONFLICT (report_id) DO NOTHING;
