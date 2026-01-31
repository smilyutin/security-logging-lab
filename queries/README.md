## Overview
Security logging lab using PostgreSQL, Docker, and anomaly-detection SQL.

## Architecture
- PostgreSQL 16
- pgAdmin
- Docker Compose

## Database Schema
- users
- auth_events
- api_requests
- audit_log

## Anomaly Detection
Queries located in `/queries/anomaly_detection.sql`

## Usage
docker compose up -d

# Security Checks Query Pack (What each query detects)

This folder contains `security_checks.sql`, a practical set of PostgreSQL queries used for security logging databases.

## How to run
Using psql:

```bash
psql "postgresql://postgres:postgres@localhost:5432/security_logs" -f queries/security_checks.sql
```

Or via Makefile:

```bash
make checks
```

---

## Query Index

### 1) Brute-force login attempts (many failures)
**Detects:** repeated failed logins for the same `user_id` and `ip_address` in a short time window.  
**Use when:** looking for brute-force attacks or bots guessing passwords.  
**Key signal:** `failed_attempts` above the threshold.

### 2) Password spraying / credential stuffing (many distinct users from one IP)
**Detects:** one IP attempting logins across many accounts.  
**Use when:** attackers try common passwords against many users (spraying) or use leaked credentials (stuffing).  
**Key signal:** high `targeted_users` from the same IP.

### 3) Multiple successful logins from multiple IPs (possible account takeover)
**Detects:** a single user logging in successfully from several IPs within a short window.  
**Use when:** investigating possible compromised accounts.  
**Key signal:** `distinct_ips` for a user above a threshold.

### 4) New user-agent for a user (device anomaly)
**Detects:** successful logins from a user-agent not seen before for that user.  
**Use when:** identifying new devices/browsers used by an account.  
**Key signal:** user-agent in the recent period missing from the baseline.

### 5) Access to sensitive endpoints (/admin, /export, /users)
**Detects:** hits to high-risk endpoints that should be limited or monitored.  
**Use when:** monitoring admin access, data exports, or user management routes.  
**Key signal:** repeated hits from a user/IP to sensitive paths.

### 6) Spike in 401/403 responses (attack or authorization regression)
**Detects:** increases in unauthorized/forbidden responses over time.  
**Use when:** spotting attack traffic, misconfigured permissions, or auth regressions after deployment.  
**Key signal:** sudden increase in `cnt_401` or `cnt_403` for an hour.

### 7) High request volume by IP (scraping / DDoS indicator)
**Detects:** unusually high request counts from a single IP in a short window.  
**Use when:** investigating scraping bots or denial-of-service patterns.  
**Key signal:** requests above a high threshold.

### 8) Slow requests (performance anomaly)
**Detects:** API requests exceeding a latency threshold.  
**Use when:** identifying performance regressions or endpoints under stress.  
**Key signal:** `latency_ms` above threshold, sorted by highest latency.

### 9) Admin actions and privilege changes (audit critical events)
**Detects:** privileged actions recorded in `audit_log` (role changes, exports, deletes).  
**Use when:** investigating insider risk or validating proper audit logging.  
**Key signal:** presence and timing of critical actions.

### 10) Logging coverage check (template)
**Detects:** business records created/changed without corresponding audit log entries.  
**Use when:** validating that “must-audit” actions are actually logged.  
**Note:** This is a template—replace with your real business tables and mappings.

### 11) Suspicious activity from suspended users
**Detects:** API activity tied to users who are not ACTIVE (e.g., suspended/disabled).  
**Use when:** verifying enforcement of account disablement or detecting bypasses.  
**Key signal:** requests from non-ACTIVE users.

### 12) Audit log gaps (missing IDs)
**Detects:** missing sequential IDs in the audit log (can indicate missing inserts or ingestion gaps).  
**Use when:** validating completeness of audit ingestion.  
**Key signal:** a gap between consecutive `audit_id` values.

---

## Tips
- Tune thresholds (`>= 5`, `>= 1000`, etc.) based on your normal traffic.
- Ensure indexes exist for time-window queries (see `db/init/03_indexes.sql`).
- For production-grade detection, combine these queries with alerting rules and dashboards.
