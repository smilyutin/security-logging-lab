## Correct pgAdmin Settings (Copy Exactly)

Use the following settings when registering the PostgreSQL server in pgAdmin.

---

### Register → Server

#### General tab
- **Name:** Security Logging Lab

---

#### Connection tab (**THIS IS THE FIX**)

| Field | Value |
|------|------|
| Host name/address | `security-logs-postgres` |
| Port | `5432` |
| Maintenance database | `postgres` |
| Username | `postgres` |
| Password | the `POSTGRES_PASSWORD` you set |
| Save password |  ON |

---

### Important Notes
-  Do **NOT** use `localhost`
-  Do **NOT** use `security-logs`
-  Always use the **PostgreSQL container name** when pgAdmin runs in Docker

If these values are set correctly, pgAdmin should connect immediately.
