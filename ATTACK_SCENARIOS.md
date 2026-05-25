# Attack Scenarios

EduVibe implements ten intentional attack scenarios (**A1–A10**). This document has two parts:

| Part | Purpose |
|---|---|
| **[Part I — Simulation run](#part-i--simulation-run)** | Exact steps executed by `attack_simulation.sh` (thesis lab run). |
| **[Part II — Additional implemented vulnerabilities](#part-ii--additional-implemented-vulnerabilities)** | Same scenarios **A1–A10**, but routes, methods, or variants present in the application **not** triggered by the script. |

Table 4 in the thesis describes the **full implemented scope** (Part I + Part II). The simulation script exercises a **subset** for a repeatable demo.

Source code marks vulnerabilities with `(A1)`–`(A10)`; `[sim]` means that path is exercised by `attack_simulation.sh`.

## Prerequisites

- Seeded database from `python3 database/init_db.py` (alice, admin, bob, course id `1`)
- Running EduVibe instance (for example `http://127.0.0.1:5001`)
- For Part I: `bash` and `curl`

## Detection types

| Attack | Detection type | Wazuh rules (examples) |
|---|---|---|
| A1 Brute-force authentication | Threshold-based | 100201, 100217, 100300 |
| A1+ Account state enforced | Threshold / state-based | 100216 |
| A2 SQL injection | Pattern-based | 100202 |
| A3 Cross-site scripting (XSS) | Pattern-based | 100203 |
| A4 Command injection | Pattern-based | 100204 |
| A5 Path traversal | Pattern-based | 100205, 100215 |
| A6 File upload abuse | Pattern-based | 100206 |
| A7 Authorization bypass | Correlation-based | 100213, 100214 |
| A8 Open redirect | Pattern-based | 100208 |
| A9 Suspicious User-Agent | Pattern-based | 100207 |
| A10 HTTP method abuse | Pattern-based | 100209 |

---

# Part I — Simulation run

Canonical automated run: **`attack_simulation.sh`** (human-readable companion to the script).

```bash
chmod +x attack_simulation.sh
TARGET=http://127.0.0.1:5001 DELAY=2 ./attack_simulation.sh
```

| Variable | Default | Purpose |
|---|---|---|
| `TARGET` | `http://172.20.10.2` | Base URL of the EduVibe app |
| `DELAY` | `3` | Pause (seconds) between scenario blocks |

**Important:** step **A1+** intentionally locks `bob@instructor.local` until an admin unlocks the account in the admin UI.

## SETUP — sessions and baseline telemetry

Before attack scenarios, the script:

1. **Health check** — `GET /health`  
   Watch for: `health_check` (rule 100210)

2. **Login as alice (student)** — `POST /login`  
   `email=alice@student.local&password=alice123`  
   Session cookie saved for later XSS and authorization tests.

3. **Login as admin** — `POST /login`  
   `email=admin@eduvibe.local&password=admin123`  
   Session cookie saved for command injection and file upload.

## A1 — Brute-force authentication

**Endpoint:** `POST /login` (6 attempts)

```http
email=attacker@test.com&password=wrongpass1
...
email=attacker@test.com&password=wrongpass6
```

Uses a non-existent email so seeded accounts are not locked during this step.

Watch for: `login_attempt`, `login_failed`; correlation rule 100300 on repeated failures from the same IP.

## A1+ — Account state enforced (Bob lockout)

**Endpoint:** `POST /login` (5 wrong attempts + 1 correct attempt)

```http
email=bob@instructor.local&password=wrong1
...
email=bob@instructor.local&password=wrong5
email=bob@instructor.local&password=bob123
```

Watch for: `login_attempt`, `login_failed`, `account_state_enforced` (`status=locked`).

## A2 — SQL injection

**Login:** `POST /login` — `email=' or '1'='1&password=anything`

**Search:** `GET /courses?search=...` — `' OR 1=1--`, `1 union select 1,2,3--`

Watch for: `sqli_pattern_detected`, `login_attempt` (login payload).

## A3 — Cross-site scripting (XSS)

Requires alice session cookie.

| Endpoint | Payload |
|---|---|
| `POST /profile` | `bio=<script>alert('xss')</script>`, `bio=<img src=x onerror=alert(1)>` |
| `POST /courses/1/review` | `content=<script>alert('xss')</script>&rating=5` |

After `POST /profile`, stored bio can execute when you open your own profile or dashboard (`|safe` in templates). Part II adds `PUT /courses/<id>/review`. Foreign profiles are covered under **A7** (`GET /profile/<id>`).

Watch for: `xss_payload_detected`

## A4 — Command injection

Requires admin session cookie.

**Endpoint:** `POST /admin/run`

```http
host=127.0.0.1;whoami
host=127.0.0.1;cat /etc/passwd
```

Watch for: `command_exec`

## A5 — Path traversal

**Endpoint:** `GET /files/view?path=...`

```text
../../etc/passwd
../../../etc/shadow
../../../../eduvibe_nonexistent_traversal_404.bin
```

Watch for: `path_traversal_attempt`, `file_access_error` (missing-file probe).

## A6 — File upload abuse

Requires admin session cookie.

**Endpoint:** `POST /admin/upload` — uploads `eduvibe_shell.php` and `eduvibe_malicious.sh`.

Watch for: `file_upload_attempt`

## A7 — Authorization bypass / IDOR

| Request | Session |
|---|---|
| `GET /admin`, `GET /dashboard` | none |
| `GET /admin`, `GET /dashboard?user_id=3`, `GET /profile/3` | alice |

Watch for: `unauthorized_access_attempt`, `authorization_bypass`

## A8 — Open redirect

**Endpoint:** `GET /redirect?url=...` — `http://evil.com`, `https://attacker.example.com/phishing`

Watch for: `open_redirect`

## A9 — Suspicious User-Agent

| User-Agent | Target |
|---|---|
| `sqlmap/1.8` | `GET /` |
| `Nikto/2.1.6` | `GET /login` |
| `Hydra/9.0` | `GET /login` |
| `nmap scripting engine` | `GET /` |
| `Burp Suite Professional` | `GET /` |

Watch for: `suspicious_user_agent`

## A10 — HTTP method abuse (simulation subset)

| Method | Endpoint | Session |
|---|---|---|
| `TRACE`, `DELETE`, `PUT` | `/login` | none |
| `DELETE`, `POST` | `/files/view` | none |
| `TRACE` | `/admin` | admin |
| `TRACE` | `/admin/run` | admin |

Watch for: `http_method_abuse`

## After the simulation

```bash
tail -f logs/app.log
# Wazuh example:
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

---

# Part II — Additional implemented vulnerabilities

These are **intentionally vulnerable** in the application (see Table 4) but **not** sent by `attack_simulation.sh`. Use any HTTP client to probe them in the lab.

## A1 — Brute-force authentication

No additional routes beyond Part I. Lockout behavior (5 failures → 15-minute lock) applies to any existing account email on `POST /login`.

## A2 — SQL injection

No additional endpoints beyond Part I. Pattern detection uses tokens such as `' or `, `union`, `--`, `/*`, `1=1` in login input and course search.

## A3 — Cross-site scripting (XSS)

| Endpoint | Notes |
|---|---|
| `PUT /courses/<id>/review` | Same stored-XSS behavior as `POST`; also logs `http_method_abuse` when method is not `POST`. |

Detection patterns: `<script`, `onerror=`, `javascript:` in bio or review content.

## A4 — Command injection

| Endpoint | Notes |
|---|---|
| `GET /admin/run` | `host` from query string; command still built and executed via `os.popen()`. |
| `TRACE /admin/run` | Same handler path after `http_method_abuse` is logged. |

`DELETE` is **not** accepted on `/admin/run` (405).

## A5 — Path traversal

| Endpoint | Notes |
|---|---|
| `POST /files/view?path=...` | Same path handling as `GET`. |
| `DELETE /files/view?path=...` | Same path handling as `GET`. |

Table 4 **expected log evidence** for A5: `path_traversal_attempt`, `file_access_error` (simulation uses traversal paths).

## A6 — File upload abuse

| Endpoint | Notes |
|---|---|
| `PUT /admin/upload` | Same upload flow as `POST`; logs `http_method_abuse` then processes upload. |

## A7 — Authorization bypass

| Endpoint | Notes |
|---|---|
| `/admin` with `POST`, `PUT`, `DELETE`, or `TRACE` | As a logged-in non-admin (e.g. student): `authorization_bypass` is logged and the panel may still render. `PUT`, `DELETE`, and `TRACE` also emit `http_method_abuse`. |

IDOR on `GET /dashboard?user_id=<other>` and `GET /profile/<id>` is exercised in Part I; the vulnerability is that foreign data is still returned after `authorization_bypass` is logged.

## A8 — Open redirect

Fully covered by Part I (`GET /redirect?url=...` only).

## A9 — Suspicious User-Agent

Fully covered by Part I in principle: **any** route with a matching User-Agent triggers `suspicious_user_agent`. The script only samples `/` and `/login`.

## A10 — HTTP method abuse (full application scope)

Routes below accept non-standard methods (`PUT`, `DELETE`, and/or `TRACE` where listed) and log `http_method_abuse`. Handlers may still run afterward (notably `/admin/run`, `/files/view`, `/login`).

### Course and enrollment routes

| Route | Non-standard methods |
|---|---|
| `/enroll/<id>` | `GET`, `DELETE` |
| `/withdraw/<id>` | `GET`, `DELETE` |
| `/wishlist/<id>/add` | `GET`, `DELETE` |
| `/wishlist/<id>/remove` | `GET`, `DELETE` |
| `/courses/<id>/review` | `PUT` |
| `/learn/<id>/progress` | `PUT`, `TRACE` |

### Admin panel routes

| Route | Non-standard methods |
|---|---|
| `/admin` | `PUT`, `DELETE` (simulation uses `TRACE` only) |
| `/admin/upload` | `PUT` |
| `/admin/users/create` | `PUT` |
| `/admin/users/<id>/edit` | `PUT` |
| `/admin/users/<id>/delete` | `DELETE` |
| `/admin/courses/<id>/edit` | `PUT` |
| `/admin/courses/create` | `PUT` |
| `/admin/courses/<id>/delete` | `DELETE` |
| `/admin/sections/<id>/edit` | `PUT` |
| `/admin/sections/<id>/delete` | `DELETE` |
| `/admin/lessons/<id>/edit` | `PUT` |
| `/admin/lessons/<id>/delete` | `DELETE` |
| `/admin/materials/<id>/delete` | `DELETE` |

`/admin/run` in the simulation: `TRACE` only. Part II adds `GET` under A4.

---

## Table 4 reference (thesis)

**Table 4. Implemented attack scenarios and vulnerabilities in EduVibe** (source: made by author). Part I + Part II = full implementation; `attack_simulation.sh` = Part I subset.

| ID | Attack type | Target component | Implemented vulnerability | Expected log evidence |
|---|---|---|---|---|
| A1 | Brute-force authentication | `POST /login` | No rate limiting on `/login`. After 5 failures the account is locked for 15 minutes, but attempts continue to be logged. Locked, suspended, and archived accounts are blocked on login. | `login_attempt`, `login_failed` (always); `account_state_enforced` (when account status is enforced: locked/suspended/archived) |
| A2 | SQL injection (SQLi) | `POST /login`; `GET /courses?search=...` | SQL string interpolation used in authentication and course search queries without parameterization. | `sqli_pattern_detected` |
| A3 | Cross-site scripting (XSS) | `POST /profile`; `POST /courses/<id>/review`; `PUT /courses/<id>/review` | User-controlled HTML accepted in bio and review fields without sanitization. Script and event-handler patterns are detected and logged. | `xss_payload_detected` |
| A4 | Command injection | `POST /admin/run`; `GET /admin/run`; `TRACE /admin/run` | Host input concatenated into a shell command and executed via `os.popen()` without sanitization. | `command_exec` |
| A5 | Path traversal | `GET /files/view?path=...`; `POST /files/view?path=...`; `DELETE /files/view?path=...` | User-supplied path joined with the application root without strict directory restriction. Traversal sequences are detected and logged. | `path_traversal_attempt`, `file_access_error` |
| A6 | File upload abuse | `POST /admin/upload`; `PUT /admin/upload` | Upload flow accepts any file type without validation. File metadata including type, MIME, size, and stored filename is logged. | `file_upload_attempt` |
| A7 | Authorization bypass | `/admin` (GET, POST, PUT, DELETE, TRACE); `GET /dashboard`; `GET /dashboard?user_id=...`; `GET /profile/<id>` | `/admin` does not strictly enforce role checks. Dashboard and profile endpoints accept arbitrary user identifiers without ownership validation. | `authorization_bypass`, `unauthorized_access_attempt` |
| A8 | Open redirect | `GET /redirect?url=...` | User-controlled URL passed directly to `redirect()` without validation or allowlist. | `open_redirect` |
| A9 | Suspicious User-Agent | Global pre-request inspection across all routes | Global pre-request hook matches User-Agent against known offensive tool tokens: sqlmap, nikto, hydra, nmap, burp. | `suspicious_user_agent` |
| A10 | HTTP method abuse | `/login`; `/admin`; `/admin/run`; `/admin/upload`; `/enroll/<id>`; `/withdraw/<id>`; `/wishlist/<id>/add`; `/wishlist/<id>/remove`; `/courses/<id>/review`; `/learn/<id>/progress`; `/files/view` | Non-standard HTTP methods (PUT, DELETE, TRACE) accepted on vulnerable routes and logged as `http_method_abuse`. On some endpoints the handler still executes business logic. | `http_method_abuse` |

**Simulation note:** A10 in `attack_simulation.sh` exercises `/login`, `/files/view`, `/admin`, and `/admin/run` only. All other A10 routes are implemented in code (Part II) and marked `(A10)` without `[sim]`.

**Code map:** search the repository for `(A1)` … `(A10)` in `routes/*.py` and templates; `[sim]` = exercised by `attack_simulation.sh`.

---

## Example log lines

```text
2026-03-26 12:00:01 | WARNING | event=login_attempt | ip=127.0.0.1 | user=anonymous | method=POST | path=/login | ua=curl/8.5.0
2026-03-26 12:00:02 | WARNING | event=sqli_pattern_detected | ip=127.0.0.1 | user=anonymous | method=POST | path=/login | ua=curl/8.5.0
2026-03-26 12:00:03 | WARNING | event=command_exec | ip=127.0.0.1 | user=admin | method=POST | path=/admin/run | ua=curl/8.5.0
2026-03-26 12:00:04 | WARNING | event=path_traversal_attempt | ip=127.0.0.1 | user=anonymous | method=GET | path=/files/view | ua=curl/8.5.0
2026-03-26 12:00:05 | WARNING | event=file_upload_attempt | ip=127.0.0.1 | user=admin | method=POST | path=/admin/upload | ua=curl/8.5.0
2026-03-26 12:00:06 | WARNING | event=authorization_bypass | ip=127.0.0.1 | user=alice | method=GET | path=/profile/3 | ua=curl/8.5.0
2026-03-26 12:00:07 | WARNING | event=open_redirect | ip=127.0.0.1 | user=anonymous | method=GET | path=/redirect | ua=curl/8.5.0
2026-03-26 12:00:08 | WARNING | event=suspicious_user_agent | ip=127.0.0.1 | user=anonymous | method=GET | path=/ | ua=sqlmap/1.8
2026-03-26 12:00:09 | WARNING | event=http_method_abuse | ip=127.0.0.1 | user=anonymous | method=TRACE | path=/login | ua=curl/8.5.0
```
