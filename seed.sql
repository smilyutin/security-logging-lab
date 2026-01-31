-- ============================================
-- Sample Data Seed File
-- File: seed.sql
-- ============================================

-- Insert sample users
INSERT INTO users (email, status)
VALUES
('admin@test.com', 'ACTIVE'),
('user1@test.com', 'ACTIVE'),
('user2@test.com', 'ACTIVE'),
('suspended@test.com', 'SUSPENDED');

-- Insert authentication events
INSERT INTO auth_events (user_id, ip_address, user_agent, event_type, success)
VALUES
(1, '192.168.1.10', 'Chrome', 'login', true),
(2, '192.168.1.11', 'Safari', 'login', false),
(2, '192.168.1.11', 'Safari', 'login', false),
(2, '192.168.1.11', 'Safari', 'login', false),
(3, '10.0.0.5', 'Firefox', 'login', true);

-- Insert API request logs
INSERT INTO api_requests (user_id, ip_address, method, path, status_code, latency_ms)
VALUES
(1, '192.168.1.10', 'GET', '/admin', 200, 120),
(2, '192.168.1.11', 'POST', '/login', 401, 90),
(3, '10.0.0.5', 'GET', '/profile', 200, 75),
(3, '10.0.0.5', 'GET', '/export/data', 403, 130);

-- Insert audit log actions
INSERT INTO audit_log (actor_id, action, target_type, target_id, details)
VALUES
(1, 'role_change', 'user', '2', '{"new_role":"ADMIN"}'),
(1, 'export_data', 'report', '2026', '{"format":"csv","records":5000}'),
(2, 'failed_login_alert', 'system', 'auth', '{"attempts":3}');
