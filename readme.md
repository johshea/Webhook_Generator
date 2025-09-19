# Webhook Manager — User Guide

A lightweight Flask app for **creating, managing, and sending webhooks** with auth, admin controls, CSRF protection, audit logs, **inactivity timeout**, **roles**, **JSON Schema** validation, **custom header sets**, **rate limiting**, and **CSV export**.

---

## 1) Quick Start

### Download & unzip
```bash
unzip flask_webhook_manager.zip
cd flask_webhook_manager
```

### (Recommended) Create a virtual env
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### Install dependencies
> The app will auto-install missing packages on first run, but this is faster.
```bash
pip install -r requirements.txt
```

### Initialize the database (optional done at runtime with defaults)
```bash
flask --app main.py init-db
# Creates SQLite DB and a default admin user: admin / admin
```

### Run the app
```bash
python main.py
# open http://127.0.0.1:5000
```

> **Default admin:** `admin / admin` — **change this immediately**.

---

## 2) Configuration (optional, done at runtime wiht defaults)

Set via environment variables before running the app:

```bash
# Security / DB
export SECRET_KEY="super-long-random-string"
export DATABASE_URL="sqlite:///webhooks.db"   # or your SQLAlchemy URL

# Rate limiting (per user)
export RATE_LIMIT_MAX=30                      # max sends per window
export RATE_LIMIT_WINDOW_SECONDS=300         # window size (seconds)
```

SQLite DB file defaults to `webhooks.db` in the project root.

---

## 3) Features Overview

- **Bootstrap UI** with left sidebar; current page hidden from nav.
- **Authentication** (Landing page).
- **Roles**: `admin`, `sender`, `viewer`.
  - `admin`: full access (Manage + Send).
  - `sender`: can send; cannot access Manage.
  - `viewer`: sign in only.
- **Inactivity logout** after **15 minutes** (server-enforced + client-side timer).
- **CSRF protection** on all forms.
- **Audit logs**, latest 100 visible in Manage; full CSV export.
- **Webhook Targets**: named endpoints to POST JSON to.
- **Functions**: reusable **JSON templates**; optional **JSON Schema** for validation.
- **Header Sets**: reusable HTTP headers (e.g., `Authorization`), admin-managed.
- **Rate limiting** for sending webhooks (per-user).

---

## 4) Routes & CLI

| Path / Command | Method(s) | Purpose |
|---|---|---|
| `/` | GET/POST | Landing page + Sign in |
| `/logout` | GET | Sign out |
| `/send` | GET/POST | Webhook Generator (send JSON to a target) |
| `/send?function_id=<id>` | GET (AJAX) | Returns function JSON template (+ schema) |
| `/manage` | GET/POST | Admin Management hub |
| `/manage/function/update` | POST | Edit existing Function (name/desc/template/schema) |
| `/manage/function/duplicate` | POST | Duplicate an existing Function |
| `/logs/export.csv` | GET | Export all audit logs as CSV (admin only) |
| `flask --app main.py init-db` | CLI | Initialize DB + default admin |

---

## 5) Using the App

### A) Sign In
- Go to `/` and sign in.
- If your role is `sender` or `admin`, you’ll see **Send Webhook**.
- If your role is `admin`, you’ll also see **Manage**.
- If idle for >15 minutes, you’ll be logged out automatically.

### B) Manage (Admin Only)
<img width="983" height="619" alt="Screenshot 2025-08-24 at 11 57 42 AM" src="https://github.com/user-attachments/assets/57a653d7-c678-4df5-b41d-b0f0a0a8224b" />

Organized into four areas:

#### 1) Webhook Targets
- **Add**: Name + URL.
- **Delete**: Select a target and remove it.
> The app will `POST` JSON to the URL you provide.

#### 2) Functions (JSON Templates + Schema)
- **Add Function**: Name, Description (optional), JSON **Template** (required), JSON **Schema** (optional).  
  - Live JSON checker prevents invalid JSON submissions.
  - Schema is used to validate payloads on the Send page if the function is selected.
- **Edit Function**: Choose a function, edit name/desc/template/schema, then save.
- **Duplicate Function**: Clone an existing function (optionally rename).
- **Delete Function**: Remove a function.

#### 3) Header Sets
- **Add Header Set**: Name, Description (optional), **Headers JSON** (object) e.g.:
  ```json
  { "Authorization": "Bearer <token>", "Content-Type": "application/json" }
  ```
- **Delete Header Set**: Remove an existing header set.
> Header **values are not displayed** later for safety, but **are sent** with requests.

#### 4) Users & Roles
- **Add User**: Username, Password, Role.
- **Delete User**: You cannot delete yourself.
- **Set Role**: Switch a user between `viewer`, `sender`, `admin`.  
  You cannot demote yourself here.

#### 5) Audit Logs
- Shows last 100 events (Time, User, Action, Details, IP).
- **Export CSV**: Download the complete history via `/logs/export.csv`.

### C) Send Webhooks
<img width="983" height="619" alt="Screenshot 2025-08-24 at 11 56 09 AM" src="https://github.com/user-attachments/assets/31f03509-7319-4bf9-b814-601e20bdf64c" />

1. **Target** — choose a saved endpoint.
2. **Function** (optional) — pre-fills the **JSON Payload** and (if present) enables **schema validation**.
3. **Header Set** (optional) — adds admin-configured headers to the request.
4. **JSON Payload** — edit as needed; must be valid JSON.
5. Click **Send Webhook**.

Results:
- **HTTP Status** — the response status code (or `ERROR` on network issues).
- **Payload Sent** — pretty-printed JSON body.
- **Response (truncated)** — first 5,000 chars of response body.

> **Timeout**: outbound request timeout is **10s**.  
> **Headers**: logged as a **list of header names only** (values are not logged).  
> **Rate Limit**: defaults to 30 sends per 5 minutes per user (configurable).

---

## 6) Security Notes

- **Change the default admin password** immediately.
- Set a strong `SECRET_KEY`.
- Prefer HTTPS: run behind a TLS-terminating reverse proxy.
- CSRF protection is enabled by default.
- Sessions are invalidated after **15 minutes** of inactivity (and the UI timer redirects to logout).

> If you need encrypted-at-rest header values (KMS/Fernet), consider adding field-level encryption before saving `HeaderSet.headers_json`.

---

## 7) Deployment

**Development**
```bash
python app.py  # debug server
```

**Production (example with gunicorn)**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```
- Put **nginx/Traefik/Apache** in front for TLS.
- Set `DATABASE_URL` for your production database (if not using SQLite).
- Provide environment vars via systemd, Docker, or your PaaS.

---

## 8) Troubleshooting

- **“Invalid credentials.”**  
  Check username/password. If DB is empty, run `flask --app app.py init-db`.

- **“Security check failed (CSRF).”**  
  The session likely expired; sign in again and retry.

- **“Payload is not valid JSON.”**  
  Fix your JSON. Live validators in Manage prevent invalid Templates/Schemas.

- **“Schema validation failed: …”**  
  The payload doesn’t match the selected function’s JSON Schema.

- **HTTP 401/403**  
  Endpoint likely needs auth; create a **Header Set** with `Authorization` or extend headers.

- **HTTP 5xx**  
  Endpoint error; examine the **Response** panel for details.

- **`ERROR` status**  
  Network/DNS/timeout; ensure the target is reachable and the URL is correct.

- **Port already in use**  
  Change the port in `app.run(..., port=5001)` or stop the other process.

---

## 9) Data & Backups

- SQLite DB file: `webhooks.db` (default location: project root).
- Backup the DB routinely if it holds critical configuration/history.

---




