from datetime import datetime, timedelta, timezone

from flask import Blueprint, redirect, render_template, request, session

from database.db import get_db_connection
from utils.logger import log_event

# Intentional vulnerabilities: A1, A1+, A2, A8, A9, A10 (see ATTACK_SCENARIOS.md; [sim] = attack_simulation.sh)

auth_bp = Blueprint("auth", __name__)

# (A9) Suspicious User-Agent tokens — global check in detect_suspicious_user_agent [sim]
SUSPICIOUS_UA_TOKENS = ["sqlmap", "nikto", "hydra", "nmap", "burp"]


def _parse_db_datetime(raw_value):
    if not raw_value:
        return None
    try:
        normalized = raw_value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


@auth_bp.before_app_request
def detect_suspicious_user_agent():
    # (A9) Suspicious User-Agent — any route [sim]
    ua = (request.headers.get("User-Agent", "") or "").lower()
    if any(token in ua for token in SUSPICIOUS_UA_TOKENS):
        log_event("suspicious_user_agent", level="warning")
    user_id = session.get("user_id")
    if not user_id:
        return
    conn = get_db_connection()
    state = conn.execute(
        "SELECT status, archived_at, locked_until FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not state:
        session.clear()
        return
    now = datetime.now(timezone.utc)
    locked_until = _parse_db_datetime(state["locked_until"])
    # (A1) account_state_enforced for locked/suspended/archived active session
    if state["archived_at"]:
        log_event("account_state_enforced", level="warning", status="archived")
        session.clear()
    elif state["status"] == "suspended":
        log_event("account_state_enforced", level="warning", status="suspended")
        session.clear()
    elif state["status"] == "locked" and locked_until and locked_until > now:
        log_event("account_state_enforced", level="warning", status="locked", locked_until=state["locked_until"])
        session.clear()
    elif state["status"] == "locked" and locked_until and locked_until <= now:
        conn.execute(
            "UPDATE users SET status = 'active', locked_until = NULL, failed_login_attempts = 0 WHERE id = ?",
            (user_id,),
        )
        conn.commit()


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error=None)

    username = request.form.get("username", "")
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, 'student', datetime('now'))",
            (username, email, password),
        )
        conn.commit()
        log_event("register_attempt", status="success")
        return redirect("/login")
    except Exception as exc:
        log_event("register_attempt", level="error", status="failure", error=str(exc))
        return render_template("register.html", error=f"Registration error: {exc}"), 400


# (A1) Brute-force / (A2) SQLi / (A10) HTTP method abuse on POST /login [sim]
@auth_bp.route("/login", methods=["GET", "POST", "PUT", "DELETE", "TRACE"])
def login():
    # (A10) Non-standard methods on /login [sim: TRACE, DELETE, PUT]
    if request.method not in ("GET", "POST"):
        log_event("http_method_abuse", level="warning")

    if request.method == "GET":
        return render_template("login.html", error=None)

    email = request.values.get("email", "")
    password = request.values.get("password", "")

    # (A2) SQL injection — string interpolation in authentication query [sim]
    raw_query = f"SELECT id, username, role, status, archived_at, locked_until, failed_login_attempts FROM users WHERE email = '{email}' AND password = '{password}'"
    user_input = f"{email} {password}".lower()
    if any(token in user_input for token in ["' or ", "union", "--", "/*", "1=1"]):
        log_event("sqli_pattern_detected", level="warning", email=email, password=password)

    conn = get_db_connection()
    raw_account_state = conn.execute(
        "SELECT archived_at FROM users WHERE email = ? LIMIT 1",
        (email,),
    ).fetchone()
    if raw_account_state and raw_account_state["archived_at"]:
        # (A1) Archived account blocked on login — account_state_enforced
        log_event("login_attempt", level="warning", status="archived", email=email)
        log_event("login_failed", level="warning", status="archived", email=email)
        log_event("account_state_enforced", level="warning", status="archived", email=email)
        return render_template("login.html", error="This account is archived."), 403

    user = conn.execute(raw_query).fetchone()
    account_row = conn.execute(
        "SELECT id, username, role, status, archived_at, locked_until, failed_login_attempts FROM users WHERE email = ? LIMIT 1",
        (email,),
    ).fetchone()

    if user:
        status = user["status"] or "active"
        locked_until = _parse_db_datetime(user["locked_until"])
        now = datetime.now(timezone.utc)
        if user["archived_at"]:
            log_event("login_attempt", level="warning", status="archived", email=email)
            log_event("login_failed", level="warning", status="archived", email=email)
            log_event("account_state_enforced", level="warning", status="archived", email=email)
            return render_template("login.html", error="This account is archived."), 403
        if status == "suspended":
            # (A1) Suspended account blocked on login — account_state_enforced
            log_event("login_attempt", level="warning", status="suspended", email=email)
            log_event("login_failed", level="warning", status="suspended", email=email)
            log_event("account_state_enforced", level="warning", status="suspended", email=email)
            return render_template("login.html", error="This account is suspended."), 403
        # (A1) Locked account blocked on login; further attempts still logged [sim A1+]
        if status == "locked" and locked_until and locked_until > now:
            log_event("login_attempt", level="warning", status="locked", email=email, locked_until=user["locked_until"])
            log_event("login_failed", level="warning", status="locked", email=email, locked_until=user["locked_until"])
            log_event("account_state_enforced", level="warning", status="locked", email=email, locked_until=user["locked_until"])
            return render_template("login.html", error="This account is temporarily locked."), 403

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        if status == "locked":
            conn.execute(
                "UPDATE users SET status = 'active', locked_until = NULL, failed_login_attempts = 0 WHERE id = ?",
                (user["id"],),
            )
        else:
            conn.execute("UPDATE users SET failed_login_attempts = 0 WHERE id = ?", (user["id"],))
        conn.commit()
        log_event("login_attempt", status="success")
        return redirect("/dashboard")

    if account_row:
        # (A1) No rate limiting; lock after 5 failures for 15 min; attempts still logged [sim]
        attempts = int(account_row["failed_login_attempts"] or 0) + 1
        lock_status = "failure"
        updates = ["failed_login_attempts = ?"]
        params = [attempts]
        if attempts >= 5:
            lock_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            updates.extend(["status = 'locked'", "locked_until = ?"])
            params.append(lock_until.isoformat())
            lock_status = "locked"
        params.append(account_row["id"])
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
        log_event("login_attempt", level="warning", status=lock_status, attempts=attempts, email=email)
        log_event("login_failed", level="warning", status=lock_status, attempts=attempts, email=email)
        return render_template("login.html", error="Invalid email or password"), 401

    # (A1) Failed login attempts always logged (unknown email) [sim]
    log_event("login_attempt", level="warning", status="failure", email=email)
    log_event("login_failed", level="warning", status="failure", email=email)
    return render_template("login.html", error="Invalid email or password"), 401


@auth_bp.route("/logout")
def logout():
    session.clear()
    log_event("logout")
    return redirect("/")


# (A8) Open redirect — unvalidated url= parameter [sim]
@auth_bp.route("/redirect")
def open_redirect():
    target = request.args.get("url", "/")
    log_event("open_redirect", level="warning", target=target)
    return redirect(target)
