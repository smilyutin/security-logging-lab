-- ============================================
-- Drop Indexes for Security Logging Lab
-- File: indexes_down.sql
-- ============================================

-- USERS
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_created_at;

-- AUTH EVENTS
DROP INDEX IF EXISTS idx_auth_events_time;
DROP INDEX IF EXISTS idx_auth_events_user_time;
DROP INDEX IF EXISTS idx_auth_events_ip_time;
DROP INDEX IF EXISTS idx_auth_events_type_success_time;

-- API REQUESTS
DROP INDEX IF EXISTS idx_api_requests_time;
DROP INDEX IF EXISTS idx_api_requests_ip_time;
DROP INDEX IF EXISTS idx_api_requests_user_time;
DROP INDEX IF EXISTS idx_api_requests_status_time;
DROP INDEX IF EXISTS idx_api_requests_path_time;

-- AUDIT LOG
DROP INDEX IF EXISTS idx_audit_log_time;
DROP INDEX IF EXISTS idx_audit_log_action_time;
DROP INDEX IF EXISTS idx_audit_log_actor_time;
DROP INDEX IF EXISTS idx_audit_log_target;
DROP INDEX IF EXISTS idx_audit_log_details_gin;
