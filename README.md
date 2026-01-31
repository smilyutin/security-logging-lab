# Security Logging Lab (PostgreSQL + Docker)

A small, realistic security logging database you can run locally on any Mac (or Linux/Windows) using Docker.
Includes:
- PostgreSQL schema (users, auth_events, api_requests, audit_log)
- Seed data
- A pack of real security/anomaly detection queries

## Prerequisites
- Docker Desktop installed and running

## Quick Start

### 1) Start the lab
```bash
docker compose up -d
```

### 2) Verify containers are running
```bash
docker compose ps
```

### 3) Connect with psql (optional)
If you have `psql` installed locally:
```bash
psql "postgresql://postgres:postgres@localhost:5432/security_logs"
```

### 4) Use pgAdmin (GUI)
Open:
- http://localhost:5050

Login:
- Email: admin@local.test
- Password: admin

Add a server:
- Host name/address: postgres
- Port: 5432
- Username: postgres
- Password: postgres
- Database: security_logs

## Run Security Checks
You can run the query pack via pgAdmin or psql.

### With psql (recommended)
```bash
psql "postgresql://postgres:postgres@localhost:5432/security_logs" -f queries/security_checks.sql
```

## Reset Everything
Stops containers and deletes volumes (data):
```bash
docker compose down -v
```

Then start again:
```bash
docker compose up -d
```

## Project Layout
- `db/init/01_schema.sql` - schema (auto-runs on first init)
- `db/init/02_seed.sql`   - sample data (auto-runs on first init)
- `queries/security_checks.sql` - anomaly/security queries pack

## Notes
- The SQL in `db/init/` only runs automatically when the database is created the first time.
  If you want to re-run schema/seed, do a reset with `docker compose down -v`.


## Indexes
The lab includes `db/init/03_indexes.sql` which creates helpful indexes for common security log queries.
These run automatically on first database initialization.

## Makefile shortcuts
If you like shorter commands:

```bash
make up
make ps
make logs
make checks
make reset
```



## Drop indexes (optional)
If you want to remove the lab indexes:

```bash
psql "postgresql://postgres:postgres@localhost:5432/security_logs" -f indexes_down.sql
```

## Query documentation
See `queries/README.md` for explanations of what each security check detects.
