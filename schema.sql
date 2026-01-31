-- ============================================
-- Security Logging Database Schema (PostgreSQL)
-- File: schema.sql
-- ============================================

-- Drop tables if they already exist (for reset)
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS api_requests;
DROP TABLE IF EXISTS auth_events;
DROP TABLE IF EXISTS users;

-- ============================================
-- Users Table
-- ============================================
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- Authentication Events Table
-- ============================================
CREATE TABLE auth_events (
    event_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    event_type TEXT NOT NULL,   -- login/logout/password_reset
    success BOOLEAN,
    event_time TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- API Request Logs Table
-- ============================================
CREATE TABLE api_requests (
    request_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    ip_address TEXT NOT NULL,
    method TEXT,
    path TEXT,
    status_code INT,
    latency_ms INT,
    event_time TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- Audit Log Table (Critical Actions)
-- ============================================
CREATE TABLE audit_log (
    audit_id SERIAL PRIMARY KEY,
    actor_id INT REFERENCES users(user_id),
    action TEXT NOT NULL,       -- role_change, delete_user, export_data
    target_type TEXT,
    target_id TEXT,
    details JSONB,
    event_time TIMESTAMP DEFAULT NOW()
);
