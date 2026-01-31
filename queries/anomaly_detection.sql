/* ============================================================
   SECURITY LOGGING LAB – ANOMALY DETECTION QUERIES
   Database: security_logs
   Tables: users, auth_events, api_requests, audit_log
   ============================================================

   How to use:
   - Open this file in VS Code (recommended) and run sections in pgAdmin Query Tool
   - Or run all at once:
       psql -h localhost -p 5432 -U postgres security_logs < anomaly_detection.sql

   Notes:
   - Tune thresholds (counts/intervals) to your traffic volume.
   - Some queries use STDDEV_POP; it can be NULL with small samples.
*/


/* ============================================================
   0) QUICK CONTEXT / SANITY
   ============================================================ */

-- Confirm database + tables
-- SELECT current_database();
-- \dt


/* ============================================================
   1) BRUTE FORCE / PASSWORD GUESSING
   ============================================================ */

-- 1A) IPs with many failed logins in last 15 minutes
SELECT
  ip_address,
  COUNT(*) AS failed_logins,
  MIN(event_time) AS first_seen,
  MAX(event_time) AS last_seen
FROM auth_events
WHERE event_type = 'login'
  AND success = false
  AND event_time >= NOW() - INTERVAL '15 minutes'
GROUP BY ip_address
HAVING COUNT(*) >= 10
ORDER BY failed_logins DESC;

-- 1B) Users with many failed logins in last 24 hours
SELECT
  u.email,
  COUNT(*) AS failed_logins,
  MAX(a.event_time) AS last_failed
FROM auth_events a
JOIN users u ON u.user_id = a.user_id
WHERE a.event_type = 'login'
  AND a.success = false
  AND a.event_time >= NOW() - INTERVAL '24 hours'
GROUP BY u.email
HAVING COUNT(*) >= 8
ORDER BY failed_logins DESC;

-- 1C) Password spraying: one IP failing across many users (last 30 minutes)
SELECT
  a.ip_address,
  COUNT(*) AS failed_logins,
  COUNT(DISTINCT a.user_id) AS distinct_users
FROM auth_events a
WHERE a.event_type = 'login'
  AND a.success = false
  AND a.event_time >= NOW() - INTERVAL '30 minutes'
GROUP BY a.ip_address
HAVING COUNT(DISTINCT a.user_id) >= 5
   AND COUNT(*) >= 15
ORDER BY distinct_users DESC, failed_logins DESC;


/* ============================================================
   2) UNUSUAL IP CHURN / NEW IPs
   ============================================================ */

-- 2A) Users logging in from many distinct IPs in last 24 hours
SELECT
  u.email,
  COUNT(DISTINCT a.ip_address) AS distinct_ips,
  MIN(a.event_time) AS first_seen,
  MAX(a.event_time) AS last_seen
FROM auth_events a
JOIN users u ON u.user_id = a.user_id
WHERE a.event_type = 'login'
  AND a.success = true
  AND a.event_time >= NOW() - INTERVAL '24 hours'
GROUP BY u.email
HAVING COUNT(DISTINCT a.ip_address) >= 4
ORDER BY distinct_ips DESC;

-- 2B) New IP per user in last 24 hours (not seen before that)
WITH recent AS (
  SELECT user_id, ip_address, MAX(event_time) AS last_seen
  FROM auth_events
  WHERE event_type='login' AND success=true
    AND event_time >= NOW() - INTERVAL '24 hours'
  GROUP BY user_id, ip_address
),
history AS (
  SELECT DISTINCT user_id, ip_address
  FROM auth_events
  WHERE event_type='login' AND success=true
    AND event_time < NOW() - INTERVAL '24 hours'
)
SELECT
  u.email,
  r.ip_address,
  r.last_seen
FROM recent r
JOIN users u ON u.user_id = r.user_id
LEFT JOIN history h
  ON h.user_id = r.user_id AND h.ip_address = r.ip_address
WHERE h.ip_address IS NULL
ORDER BY r.last_seen DESC;


/* ============================================================
   3) API ABUSE / RATE ANOMALIES
   ============================================================ */

-- 3A) High request rate per IP (last 5 minutes)
SELECT
  ip_address,
  COUNT(*) AS requests_5m
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '5 minutes'
GROUP BY ip_address
HAVING COUNT(*) >= 300
ORDER BY requests_5m DESC;

-- 3B) High request rate per user (last 5 minutes)
SELECT
  u.email,
  COUNT(*) AS requests_5m
FROM api_requests r
JOIN users u ON u.user_id = r.user_id
WHERE r.event_time >= NOW() - INTERVAL '5 minutes'
GROUP BY u.email
HAVING COUNT(*) >= 200
ORDER BY requests_5m DESC;

-- 3C) Endpoint hot spots (top paths in last 15 minutes)
SELECT
  path,
  COUNT(*) AS hits_15m
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '15 minutes'
GROUP BY path
ORDER BY hits_15m DESC
LIMIT 20;


/* ============================================================
   4) ERROR SPIKES / PROBING
   ============================================================ */

-- 4A) IPs generating lots of 401/403 (last 30 minutes)
SELECT
  ip_address,
  COUNT(*) AS auth_errors
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '30 minutes'
  AND status_code IN (401, 403)
GROUP BY ip_address
HAVING COUNT(*) >= 30
ORDER BY auth_errors DESC;

-- 4B) 5xx spike by endpoint (last 60 minutes)
SELECT
  path,
  COUNT(*) AS errors_5xx
FROM api_requests
WHERE event_time >= NOW() - INTERVAL '60 minutes'
  AND status_code >= 500
GROUP BY path
HAVING COUNT(*) >= 10
ORDER BY errors_5xx DESC;


/* ============================================================
   5) LATENCY ANOMALIES (DYNAMIC THRESHOLD PER ENDPOINT)
   ============================================================ */

-- 5A) Requests slower than endpoint baseline (mean + 3*std),
--     baseline window: last 24 hours, recent window: last 30 minutes
WITH baseline AS (
  SELECT
    path,
    AVG(latency_ms)::numeric AS mean_ms,
    STDDEV_POP(latency_ms)::numeric AS std_ms
  FROM api_requests
  WHERE event_time >= NOW() - INTERVAL '24 hours'
    AND latency_ms IS NOT NULL
  GROUP BY path
),
recent AS (
  SELECT *
  FROM api_requests
  WHERE event_time >= NOW() - INTERVAL '30 minutes'
    AND latency_ms IS NOT NULL
)
SELECT
  r.request_id,
  r.path,
  r.latency_ms,
  b.mean_ms,
  b.std_ms,
  r.event_time
FROM recent r
JOIN baseline b ON b.path = r.path
WHERE b.std_ms IS NOT NULL
  AND r.latency_ms > (b.mean_ms + 3 * b.std_ms)
ORDER BY r.latency_ms DESC;


/* ============================================================
   6) AUDIT LOG ANOMALIES (HIGH RISK ACTIONS)
   ============================================================ */

-- 6A) Critical actions in last 24 hours
SELECT
  u.email AS actor,
  al.action,
  al.target_type,
  al.target_id,
  al.details,
  al.event_time
FROM audit_log al
JOIN users u ON u.user_id = al.actor_id
WHERE al.event_time >= NOW() - INTERVAL '24 hours'
  AND al.action IN ('delete_user', 'role_change', 'export_data')
ORDER BY al.event_time DESC;

-- 6B) Burst of admin actions by same actor (last 15 minutes)
SELECT
  u.email AS actor,
  COUNT(*) AS actions_15m,
  MIN(al.event_time) AS first_seen,
  MAX(al.event_time) AS last_seen
FROM audit_log al
JOIN users u ON u.user_id = al.actor_id
WHERE al.event_time >= NOW() - INTERVAL '15 minutes'
GROUP BY u.email
HAVING COUNT(*) >= 10
ORDER BY actions_15m DESC;


/* ============================================================
   7) CROSS-SIGNAL DETECTIONS (AUTH + API)
   ============================================================ */

-- 7A) Successful login followed by many 401/403 from same user+IP (last 2 hours)
WITH logins AS (
  SELECT user_id, ip_address, event_time
  FROM auth_events
  WHERE event_type='login' AND success=true
    AND event_time >= NOW() - INTERVAL '2 hours'
),
errors AS (
  SELECT user_id, ip_address, COUNT(*) AS auth_errors
  FROM api_requests
  WHERE event_time >= NOW() - INTERVAL '2 hours'
    AND status_code IN (401,403)
  GROUP BY user_id, ip_address
)
SELECT
  u.email,
  l.ip_address,
  l.event_time AS login_time,
  e.auth_errors
FROM logins l
JOIN errors e ON e.user_id = l.user_id AND e.ip_address = l.ip_address
JOIN users u ON u.user_id = l.user_id
WHERE e.auth_errors >= 20
ORDER BY e.auth_errors DESC, l.event_time DESC;


/* ============================================================
   8) NEW BEHAVIOR (SIMPLE BASELINES)
   ============================================================ */

-- 8A) New endpoint accessed by user in last 24 hours (never accessed before)
WITH recent AS (
  SELECT DISTINCT user_id, path
  FROM api_requests
  WHERE event_time >= NOW() - INTERVAL '24 hours'
),
history AS (
  SELECT DISTINCT user_id, path
  FROM api_requests
  WHERE event_time < NOW() - INTERVAL '24 hours'
)
SELECT
  u.email,
  r.path
FROM recent r
JOIN users u ON u.user_id = r.user_id
LEFT JOIN history h ON h.user_id = r.user_id AND h.path = r.path
WHERE h.path IS NULL
ORDER BY u.email, r.path;


/* ============================================================
   9) OPTIONAL INDEXES (PERFORMANCE)
   Run once; safe to re-run with IF NOT EXISTS.
   ============================================================ */

-- CREATE INDEX IF NOT EXISTS idx_auth_events_time ON auth_events(event_time);
-- CREATE INDEX IF NOT EXISTS idx_auth_events_ip ON auth_events(ip_address);
-- CREATE INDEX IF NOT EXISTS idx_auth_events_user_time ON auth_events(user_id, event_time);

-- CREATE INDEX IF NOT EXISTS idx_api_requests_time ON api_requests(event_time);
-- CREATE INDEX IF NOT EXISTS idx_api_requests_ip ON api_requests(ip_address);
-- CREATE INDEX IF NOT EXISTS idx_api_requests_user_time ON api_requests(user_id, event_time);
-- CREATE INDEX IF NOT EXISTS idx_api_requests_path_time ON api_requests(path, event_time);

-- CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(event_time);
-- CREATE INDEX IF NOT EXISTS idx_audit_log_actor_time ON audit_log(actor_id, event_time);

/* ======================= END FILE ========================== */
