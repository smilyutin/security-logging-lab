-- ============================================
-- Security & Anomaly Detection Queries (PostgreSQL)
-- File: security_checks.sql
-- ============================================

-- 1) Brute-force login attempts (many failures in last 15 minutes)
SELECT user_id, ip_address, COUNT(*) AS failed_attempts
FROM auth_events
WHERE event_type = 'login'
  AND success = false
  AND event_time >= NOW() - INTERVAL '15 minutes'
GROUP BY user_id, ip_address
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC;

-- 2) Password spraying / credential stuffing (many distinct users from one IP)
SELECT ip_address,
       COUNT(DISTINCT user_id) AS targeted_users,
       COUNT(*) AS attempts
FROM auth_events
WHERE event_type = 'login'
  AND event_time >= NOW() - INTERVAL '30 minutes'
GROUP BY ip_address
HAVING COUNT(DISTINCT user_id) >= 10
ORDER BY targeted_users DESC;

-- 3) Successful logins from multiple IPs recently (possible account takeover)
SELECT user_id,
       COUNT(DISTINCT ip_address) AS distinct_ips,
       MIN(event_time) AS first_seen,
       MAX(event_time) AS last_seen
FROM auth_events
WHERE event_type = 'login'
  AND success = true
  AND event_time >= NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(DISTINCT ip_address) >= 3
ORDER BY distinct_ips DESC;

-- 4) New user-agent for a user in the last 24 hours (device anomaly)
WITH recent AS (
  SELECT DISTINCT user_id, user_agent
  FROM auth_events
  WHERE event_type = 'login'
    AND success = true
    AND event_time >= NOW() - INTERVAL '24 hours'
),
baseline AS (
  SELECT DISTINCT user_id, user_agent
  FROM auth_events
  WHERE event_type = 'login'
    AND success = true
    AND event_time < NOW() - INTERVAL '24 hours'
)
SELECT r.user_id, r.user_agent
FROM recent r
LEFT JOIN baseline b
  ON b.user_id = r.user_id AND b.user_agent = r.user_agent
WHERE b.user_id IS NULL;

-- 5) Access to sensitive endpoints (admin/export/users)
SELECT user_id, ip_address, path, COUNT(*) AS hits
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '24 hours'
  AND (
       path ILIKE '/admin%' OR
       path ILIKE '%/export%' OR
       path ILIKE '/users%'
  )
GROUP BY user_id, ip_address, path
ORDER BY hits DESC;

-- 6) Spike of 401/403 responses by hour (attack or authz regression)
SELECT date_trunc('hour', event_time) AS hour,
       COUNT(*) FILTER (WHERE status_code = 401) AS cnt_401,
       COUNT(*) FILTER (WHERE status_code = 403) AS cnt_403
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '48 hours'
GROUP BY 1
ORDER BY 1;

-- 7) High request volume by IP (scraping / DDoS indicator)
SELECT ip_address, COUNT(*) AS requests
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '10 minutes'
GROUP BY ip_address
HAVING COUNT(*) >= 1000
ORDER BY requests DESC;

-- 8) Slow requests (performance anomaly)
SELECT request_id, user_id, ip_address, method, path, status_code, latency_ms, event_time
FROM api_requests
WHERE latency_ms >= 2000
ORDER BY latency_ms DESC
LIMIT 50;

-- 9) Admin actions and privilege changes (audit critical events)
SELECT *
FROM audit_log
WHERE action IN ('role_change', 'permission_granted', 'admin_enabled', 'user_deleted', 'export_data')
  AND event_time >= NOW() - INTERVAL '30 days'
ORDER BY event_time DESC;

-- 10) Logging coverage check: transactions created but missing audit entry (template)
-- NOTE: Replace 'transactions' with your real business table and event mapping.
-- SELECT t.transaction_id
-- FROM transactions t
-- LEFT JOIN audit_log a
--   ON a.target_type = 'transaction'
--  AND a.target_id = t.transaction_id::text
--  AND a.action = 'transaction_created'
-- WHERE t.created_at >= NOW() - INTERVAL '7 days'
--   AND a.audit_id IS NULL;

-- 11) Suspicious activity from suspended users
SELECT ar.request_id, ar.user_id, u.status, ar.ip_address, ar.path, ar.status_code, ar.event_time
FROM api_requests ar
JOIN users u ON u.user_id = ar.user_id
WHERE u.status <> 'ACTIVE'
  AND ar.event_time >= NOW() - INTERVAL '7 days'
ORDER BY ar.event_time DESC;

-- 12) Audit log gaps (requires sequential ids; flags missing rows)
SELECT audit_id + 1 AS gap_start,
       LEAD(audit_id) OVER (ORDER BY audit_id) - 1 AS gap_end
FROM audit_log
WHERE LEAD(audit_id) OVER (ORDER BY audit_id) IS NOT NULL
  AND LEAD(audit_id) OVER (ORDER BY audit_id) <> audit_id + 1
ORDER BY gap_start;
