import os

from flask import Blueprint, current_app, redirect, render_template, request, session

from database.db import get_db_connection
from utils.logger import log_event


# Intentional vulnerabilities: A3 (POST /profile), A5, A7 (incl. GET /profile/<id>), A10 (see ATTACK_SCENARIOS.md; [sim] = attack_simulation.sh)
profile_bp = Blueprint("profile", __name__)


def _course_lesson_keys(conn, course_id: int):
    rows = conn.execute(
        "SELECT id FROM course_lessons WHERE course_id = ? ORDER BY section_id, position",
        (course_id,),
    ).fetchall()
    return [f"lesson_{row['id']}" for row in rows]


# (A7) Authorization bypass / IDOR on GET /dashboard [sim]
@profile_bp.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("user_id"):
        # (A7) Guest blocked on protected dashboard [sim: GET /dashboard]
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    # (A7) user_id query parameter trusted without ownership enforcement [sim: ?user_id=3]
    requested_user_id = request.args.get("user_id", session.get("user_id"))
    conn = get_db_connection()
    user = conn.execute(
        f"SELECT id, username, email, role, bio FROM users WHERE id = {requested_user_id}"
    ).fetchone()

    if session.get("user_id") and str(session.get("user_id")) != str(requested_user_id):
        # (A7) Logged but foreign dashboard data is still returned [sim]
        log_event("authorization_bypass", level="warning", status="failure", target_user_id=requested_user_id)

    if not user:
        return "User not found", 404

    enrollments = conn.execute(
        """
        SELECT c.id, c.title, c.category, e.enrolled_at
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        WHERE e.user_id = ?
        ORDER BY e.id DESC
        """,
        (requested_user_id,),
    ).fetchall()

    wishlist = conn.execute(
        """
        SELECT c.id, c.title, c.category, w.created_at
        FROM wishlists w
        JOIN courses c ON c.id = w.course_id
        WHERE w.user_id = ?
        ORDER BY w.id DESC
        """,
        (requested_user_id,),
    ).fetchall()

    continue_learning = []
    for course in enrollments:
        course_id = course["id"]
        lesson_keys = _course_lesson_keys(conn, course_id)
        if not lesson_keys:
            continue
        completed_rows = conn.execute(
            """
            SELECT lesson_key
            FROM lesson_progress
            WHERE user_id = ? AND course_id = ? AND completed = 1
            """,
            (requested_user_id, course_id),
        ).fetchall()
        completed_keys = {row["lesson_key"] for row in completed_rows}
        completed_count = sum(1 for key in lesson_keys if key in completed_keys)
        progress_pct = int((completed_count / len(lesson_keys)) * 100)
        next_key = next((key for key in lesson_keys if key not in completed_keys), lesson_keys[-1])
        continue_learning.append(
            {
                "course_id": course_id,
                "title": course["title"],
                "progress_pct": progress_pct,
                "next_key": next_key,
            }
        )

    return render_template(
        "dashboard.html",
        user=user,
        enrollments=enrollments,
        wishlist=wishlist,
        continue_learning=continue_learning,
    )


# (A3) Stored XSS in profile bio — POST /profile [sim]
@profile_bp.route("/profile", methods=["GET", "POST"])
def my_profile():
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()

    if request.method == "POST":
        # (A3) Stored XSS in profile bio — unsanitized storage [sim]
        bio = request.form.get("bio", "")
        if "<script" in bio.lower() or "onerror=" in bio.lower() or "javascript:" in bio.lower():
            log_event("xss_payload_detected", level="warning", payload=bio)
        conn.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
        conn.commit()
        log_event("profile_updated", status="success")

    user = conn.execute(
        "SELECT id, username, email, role, bio FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        return "User not found", 404

    notifications = conn.execute(
        """
        SELECT id, type, message, is_read, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 20
        """,
        (user_id,),
    ).fetchall()
    return render_template("profile.html", user=user, notifications=notifications)


# (A7) IDOR on GET /profile/<id> [sim: /profile/3]
@profile_bp.route("/profile/<int:user_id>", methods=["GET"])
def public_profile(user_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if session.get("user_id") and session.get("user_id") != user_id:
        # (A7) Logged but foreign profile is still returned [sim: /profile/3]
        log_event("authorization_bypass", level="warning", status="failure", target_user_id=user_id)

    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, email, role, bio FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        return "User not found", 404
    # (A7) Foreign profile returned without ownership check; bio rendered unsafely in HTML
    return f"<h2>{user['username']}</h2><p>{user['bio']}</p><p>{user['email']}</p>"


# (A5) Path traversal / (A10) HTTP method abuse on /files/view
@profile_bp.route("/files/view", methods=["GET", "POST", "DELETE"])
def file_view():
    # (A10) Non-standard methods [sim: POST, DELETE without path; GET uses A5 paths]
    if request.method != "GET":
        log_event("http_method_abuse", level="warning")

    # (A5) User-controlled path joined to app root without strict jail [sim: GET ?path=../...]
    requested_path = request.values.get("path", "logs/app.log")
    if "../" in requested_path or "..\\" in requested_path:
        log_event("path_traversal_attempt", level="warning", requested_path=requested_path)
    else:
        # Normal file read (Table 4 A5 evidence: path_traversal_attempt, file_access_error)
        log_event("file_access_attempt", status="success", requested_path=requested_path)

    try:
        base_dir = current_app.root_path
        absolute_path = os.path.join(base_dir, requested_path)
        with open(absolute_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
        return f"<h2>File: {requested_path}</h2><pre>{content}</pre>"
    except Exception as exc:
        # (A5) Missing or unreadable path after traversal probe [sim: 404.bin probe]
        log_event("file_access_error", level="error", status="failure", error=str(exc), requested_path=requested_path)
        return f"Error reading file: {exc}", 500


@profile_bp.route("/password/change", methods=["POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    conn = get_db_connection()

    if not current_password and not new_password:
        log_event("password_change", status="no_change")
        return redirect("/profile")

    user_row = conn.execute("SELECT password FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row or user_row["password"] != current_password:
        log_event("password_change", level="warning", status="denied")
        return redirect("/profile")

    if len(new_password) < 4:
        log_event("password_change", level="warning", status="too_short")
        return redirect("/profile")

    conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
    conn.execute(
        "INSERT INTO notifications (user_id, type, message, is_read, created_at) VALUES (?, 'security', ?, 0, datetime('now'))",
        (user_id, "Password was changed."),
    )
    conn.commit()
    log_event("password_change", status="success")
    log_event("notification_event", status="success", notification_type="security")
    return redirect("/profile")


@profile_bp.route("/notifications/<int:notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id: int):
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()
    conn.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        (notification_id, user_id),
    )
    conn.commit()
    log_event("notification_event", status="success", action="read", notification_id=notification_id)
    return redirect("/profile")


@profile_bp.route("/audit-timeline", methods=["GET"])
def audit_timeline():
    # Show recent log lines for the logged-in user (reads logs/app.log).
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    log_path = os.path.join(current_app.root_path, "logs", "app.log")
    entries = []
    username = session.get("username", "anonymous")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as logfile:
            for line in logfile:
                if f"user={username}" in line and "event=" in line:
                    entries.append(line.strip())
    entries = entries[-50:][::-1]
    log_event("audit_timeline_viewed", status="success")
    return render_template("audit_timeline.html", entries=entries)


@profile_bp.route("/detection-status", methods=["GET"])
def detection_status():
    # Count attack-related events in logs/app.log for the detection status page.
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    log_path = os.path.join(current_app.root_path, "logs", "app.log")
    tracked = [
        "sqli_pattern_detected",
        "xss_payload_detected",
        "path_traversal_attempt",
        "http_method_abuse",
        "authorization_bypass",
        "suspicious_user_agent",
    ]
    counters = {key: 0 for key in tracked}
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as logfile:
            for line in logfile:
                for key in tracked:
                    if f"event={key}" in line:
                        counters[key] += 1

    status_rows = []
    for key in tracked:
        severity = "high" if counters[key] >= 5 else "medium" if counters[key] >= 2 else "low"
        status_rows.append({"rule": key, "count": counters[key], "severity": severity})
    status_rows.sort(key=lambda item: item["count"], reverse=True)
    log_event("detection_status_viewed", status="success")
    return render_template("detection_status.html", status_rows=status_rows)
