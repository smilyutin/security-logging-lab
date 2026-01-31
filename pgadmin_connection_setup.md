# pgAdmin Connection Setup Guide

This guide explains how to connect pgAdmin to PostgreSQL for the Security Logging Lab using Docker.

---

## Architecture Overview

- PostgreSQL runs in a Docker container
- pgAdmin runs in a Docker container
- Containers communicate over a Docker bridge network
- pgAdmin connects using the PostgreSQL container name (not localhost)

---

## Prerequisites

- Docker Desktop running
- Containers started with `docker compose up -d`
- pgAdmin accessible at http://localhost:5050

---

## Step 1: Open pgAdmin

1. Open a browser
2. Go to http://localhost:5050
3. Log in using credentials from docker-compose.yml:
   - PGADMIN_DEFAULT_EMAIL
   - PGADMIN_DEFAULT_PASSWORD

---

## Step 2: Register a Server

In pgAdmin:
1. Right-click Servers
2. Select Register → Server

---

## Step 3: General Tab

| Field | Value |
|------|------|
| Name | Security Logging Lab |
| Server group | Servers |

---

## Step 4: Connection Tab (Important)

Use the following values exactly:

| Field | Value |
|------|------|
| Host name/address | security-logs-postgres |
| Port | 5432 |
| Maintenance database | postgres |
| Username | postgres |
| Password | POSTGRES_PASSWORD value |
| Save password | Enabled |

Do NOT use localhost.

---

## Step 5: Verify Connection

After saving:
Servers → Security Logging Lab → Databases

You should see:
- postgres
- security_logs

---

## Step 6: Test Query

```sql
SELECT version();
SELECT current_database();
```

---

## Common Errors

### Name does not resolve
Cause: Incorrect hostname  
Fix: Use the PostgreSQL container name

### Password authentication failed
Fix: Check POSTGRES_PASSWORD environment variable

---

## Best Practices

- Keep SQL files in Git
- Use pgAdmin only as a client
- Avoid multiple PostgreSQL containers

---

You are now ready to use pgAdmin with PostgreSQL.
