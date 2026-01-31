-- ============================================
-- Indexes for Security Logging Lab (PostgreSQL)
-- File: 03_indexes.sql
-- ============================================

-- USERS
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- AUTH EVENTS (common queries: time window, user/ip, success)
CREATE INDEX IF NOT EXISTS idx_auth_events_time ON auth_events(event_time);
CREATE INDEX IF NOT EXISTS idx_auth_events_user_time ON auth_events(user_id, event_time);
CREATE INDEX IF NOT EXISTS idx_auth_events_ip_time ON auth_events(ip_address, event_time);
CREATE INDEX IF NOT EXISTS idx_auth_events_type_success_time ON auth_events(event_type, success, event_time);

-- API REQUESTS (common queries: time window, ip, user, status, path)
CREATE INDEX IF NOT EXISTS idx_api_requests_time ON api_requests(event_time);
CREATE INDEX IF NOT EXISTS idx_api_requests_ip_time ON api_requests(ip_address, event_time);
CREATE INDEX IF NOT EXISTS idx_api_requests_user_time ON api_requests(user_id, event_time);
CREATE INDEX IF NOT EXISTS idx_api_requests_status_time ON api_requests(status_code, event_time);
CREATE INDEX IF NOT EXISTS idx_api_requests_path_time ON api_requests(path, event_time);

-- AUDIT LOG (common queries: time window, action, actor, target)
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(event_time);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_time ON audit_log(action, event_time);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_time ON audit_log(actor_id, event_time);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id);

-- JSONB field index (useful if you query keys inside details)
CREATE INDEX IF NOT EXISTS idx_audit_log_details_gin ON audit_log USING GIN (details);
