import os
import sqlite3
import uuid
import json
from collections import defaultdict
from pathlib import Path

from flask import Blueprint, current_app, redirect, render_template, request, session
from werkzeug.utils import secure_filename

from database.db import get_db_connection
from utils.logger import log_event


# Intentional vulnerabilities: A4, A6, A7, A10 (see ATTACK_SCENARIOS.md; [sim] = attack_simulation.sh)
admin_bp = Blueprint("admin", __name__)


def _latest_user_activity():
    # Read logs/app.log — show last action per user on the admin page.
    activity = {}
    log_path = os.path.join(current_app.root_path, "logs", "app.log")
    if not os.path.exists(log_path):
        return activity
    with open(log_path, "r", encoding="utf-8", errors="ignore") as logfile:
        for line in logfile:
            if "| user=" not in line or "| event=" not in line:
                continue
            try:
                timestamp = line.split(" | ", 1)[0].strip()
                event_name = line.split("event=", 1)[1].split(" | ", 1)[0].strip()
                username = line.split("| user=", 1)[1].split(" | ", 1)[0].strip()
            except Exception:
                continue
            if not username or username in {"-", "anonymous"}:
                continue
            activity[username] = f"{timestamp} - {event_name}"
    return activity


def _load_admin_lists(
    conn,
    user_search="",
    user_role="",
    user_visibility="all",
    course_search="",
    course_category="",
    course_visibility="all",
):
    user_sql = "SELECT id, username, email, role, status, archived_at, locked_until, failed_login_attempts, bio, created_at FROM users"
    user_where = []
    user_params = []
    if user_search:
        user_where.append("(username LIKE ? OR email LIKE ?)")
        like = f"%{user_search}%"
        user_params.extend([like, like])
    if user_role:
        user_where.append("role = ?")
        user_params.append(user_role)
    if user_visibility == "active":
        user_where.append("archived_at IS NULL")
    elif user_visibility == "archived":
        user_where.append("archived_at IS NOT NULL")
    if user_where:
        user_sql += " WHERE " + " AND ".join(user_where)
    user_sql += " ORDER BY id DESC"
    users = conn.execute(user_sql, tuple(user_params)).fetchall()

    course_sql = "SELECT id, title, description, category, level, duration_hours, instructor_id, archived_at FROM courses"
    course_where = []
    course_params = []
    if course_search:
        course_where.append("title LIKE ?")
        course_params.append(f"%{course_search}%")
    if course_category:
        course_where.append("category = ?")
        course_params.append(course_category)
    if course_visibility == "active":
        course_where.append("archived_at IS NULL")
    elif course_visibility == "archived":
        course_where.append("archived_at IS NOT NULL")
    if course_where:
        course_sql += " WHERE " + " AND ".join(course_where)
    course_sql += " ORDER BY id DESC"
    courses = conn.execute(course_sql, tuple(course_params)).fetchall()

    uploads = conn.execute(
        """
        SELECT id, course_id, lesson_id, original_filename, stored_filename, uploaded_at
        FROM uploads
        WHERE course_id IS NOT NULL
        ORDER BY id DESC
        """
    ).fetchall()
    course_materials = defaultdict(list)
    lesson_materials = defaultdict(list)
    for item in uploads:
        course_materials[item["course_id"]].append(item)
        if item["lesson_id"] is not None:
            lesson_materials[item["lesson_id"]].append(item)

    sections = conn.execute(
        "SELECT id, course_id, title, position FROM course_sections ORDER BY course_id, position"
    ).fetchall()
    lesson_rows = conn.execute(
        """
        SELECT id, course_id, section_id, title, lesson_type, content, position
        FROM course_lessons
        ORDER BY course_id, section_id, position
        """
    ).fetchall()
    lessons = []
    for row in lesson_rows:
        item = dict(row)
        raw = (item.get("content") or "").strip()
        pretty = raw
        if raw.startswith("{") and raw.endswith("}"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    pretty = json.dumps(parsed, ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                pretty = raw
        item["content_pretty"] = pretty
        lessons.append(item)
    publish_rows = conn.execute(
        "SELECT course_id, status FROM course_publish_state"
    ).fetchall()
    publish_states = {row["course_id"]: row["status"] for row in publish_rows}

    instructors = conn.execute(
        "SELECT id, username FROM users WHERE role IN ('instructor', 'admin') ORDER BY username"
    ).fetchall()
    categories = [
        row["category"]
        for row in conn.execute("SELECT DISTINCT category FROM courses ORDER BY category").fetchall()
    ]
    user_last_action = _latest_user_activity()

    return (
        users,
        courses,
        course_materials,
        lesson_materials,
        sections,
        lessons,
        publish_states,
        instructors,
        categories,
        user_last_action,
    )


def _validate_lesson_content(raw_content: str):
    content = (raw_content or "").strip()
    if not content:
        return "", None
    if content.startswith("{"):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return None, f"Lesson material JSON is invalid: {exc.msg}."
        if not isinstance(parsed, dict):
            return None, "Lesson material JSON must be an object."
        return json.dumps(parsed, ensure_ascii=False), None
    return content, None


def _build_reporting(conn):
    # Aggregate suspicious event names from logs/app.log for the admin report panel.
    active_users = conn.execute(
        "SELECT COUNT(DISTINCT user_id) AS count FROM enrollments WHERE enrolled_at >= datetime('now', '-7 day')"
    ).fetchone()["count"]
    enrollments_day = conn.execute(
        "SELECT COUNT(*) AS count FROM enrollments WHERE enrolled_at >= datetime('now', '-1 day')"
    ).fetchone()["count"]
    uploads_day = conn.execute(
        "SELECT COUNT(*) AS count FROM uploads WHERE uploaded_at >= datetime('now', '-1 day')"
    ).fetchone()["count"]

    suspicious_events = defaultdict(int)
    log_path = os.path.join(current_app.root_path, "logs", "app.log")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as logfile:
            for line in logfile:
                if "event=" not in line:
                    continue
                event_name = line.split("event=", 1)[1].split(" | ", 1)[0].strip()
                if any(token in event_name for token in ["warning", "sqli", "xss", "unauthorized", "abuse", "exception"]):
                    suspicious_events[event_name] += 1

    top_suspicious = sorted(suspicious_events.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "active_users_7d": active_users,
        "enrollments_24h": enrollments_day,
        "uploads_24h": uploads_day,
        "suspicious_summary": top_suspicious,
    }


def _render_admin(conn, command_result=None, upload_message=None, admin_message=None):
    user_search = request.args.get("user_search", "").strip()
    user_role = request.args.get("user_role", "").strip()
    user_visibility = request.args.get("user_visibility", "all").strip() or "all"
    course_search = request.args.get("course_search", "").strip()
    course_category = request.args.get("course_category", "").strip()
    course_visibility = request.args.get("course_visibility", "all").strip() or "all"

    (
        users,
        courses,
        course_materials,
        lesson_materials,
        sections,
        lessons,
        publish_states,
        instructors,
        categories,
        user_last_action,
    ) = _load_admin_lists(
        conn,
        user_search=user_search,
        user_role=user_role,
        user_visibility=user_visibility,
        course_search=course_search,
        course_category=course_category,
        course_visibility=course_visibility,
    )
    reporting = _build_reporting(conn)
    return render_template(
        "admin.html",
        users=users,
        courses=courses,
        course_materials=course_materials,
        lesson_materials=lesson_materials,
        command_result=command_result,
        upload_message=upload_message,
        admin_message=admin_message,
        reporting=reporting,
        sections=sections,
        lessons=lessons,
        publish_states=publish_states,
        instructors=instructors,
        categories=categories,
        user_last_action=user_last_action,
        user_search=user_search,
        user_role=user_role,
        user_visibility=user_visibility,
        course_search=course_search,
        course_category=course_category,
        course_visibility=course_visibility,
    )
# (A7) Authorization bypass — /admin (GET, POST, PUT, DELETE, TRACE) / (A10)
@admin_bp.route("/admin", methods=["GET", "POST", "PUT", "DELETE", "TRACE"])
def admin_panel():
    if not session.get("user_id"):
        # (A7) Guest blocked on /admin [sim: GET /admin]
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    # (A7) Non-admin access logged, not blocked [sim: GET /admin as alice]
    if session.get("role") != "admin":
        log_event("authorization_bypass", level="warning", status="failure")

    # (A10) PUT/DELETE/TRACE; simulation uses TRACE with admin cookie [sim: TRACE]
    if request.method not in ("GET", "POST"):
        log_event("http_method_abuse", level="warning")

    conn = get_db_connection()
    log_event("admin_report_viewed", status="success")
    log_event("admin_panel_access", status="success")
    return _render_admin(conn)


# (A4) Command injection / (A10) HTTP method abuse on /admin/run
@admin_bp.route("/admin/run", methods=["POST", "GET", "TRACE"])
def run_command():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    # (A10) GET/TRACE; simulation uses POST for A4 and TRACE for method abuse [sim: POST, TRACE]
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    host = request.values.get("host", "127.0.0.1")

    # (A4) Host input concatenated into shell command via os.popen() [sim]
    cmd = f"ping -c 1 {host}"
    log_event("command_exec", level="warning", input=host, command=cmd)
    result = os.popen(cmd).read()
    conn = get_db_connection()
    return _render_admin(conn, command_result=result)


# (A6) File upload abuse / (A10) HTTP method abuse on /admin/upload
@admin_bp.route("/admin/upload", methods=["POST", "PUT"])
def upload_file():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    # (A10) PUT; simulation uses POST only [sim: POST]
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    if "file" not in request.files:
        log_event("file_upload_attempt", level="warning", status="failure", upload_filename="missing_file_field")
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":
        log_event("file_upload_attempt", level="warning", status="failure", upload_filename="empty_filename")
        return "No selected file", 400

    # (A6) No file-type validation; upload details go to the log [sim]
    original_name = file.filename
    file_type = (Path(original_name).suffix or "").lower() or "unknown"
    mime_type = file.mimetype or "unknown"
    size = len(file.read())
    file.seek(0)
    saved_name = f"{uuid.uuid4().hex}_{secure_filename(original_name)}"
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "static/uploads")
    os.makedirs(upload_dir, exist_ok=True)
    save_path = os.path.join(upload_dir, saved_name)
    file.save(save_path)

    conn = get_db_connection()
    user_id = session.get("user_id", 0)
    course_id = request.form.get("course_id")
    lesson_id = request.form.get("lesson_id")
    try:
        conn.execute(
            """
            INSERT INTO uploads (user_id, course_id, lesson_id, original_filename, stored_filename, uploaded_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (user_id, course_id if course_id else None, lesson_id if lesson_id else None, original_name, saved_name),
        )
    except Exception:
        # Backward compatibility if database was not migrated yet.
        conn.execute(
            "INSERT INTO uploads (user_id, original_filename, stored_filename, uploaded_at) VALUES (?, ?, ?, datetime('now'))",
            (user_id, original_name, saved_name),
        )
    conn.commit()

    log_event(
        "file_upload_attempt",
        level="warning",
        status="success",
        course_id=course_id if course_id else "-",
        lesson_id=lesson_id if lesson_id else "-",
        upload_filename=original_name,
        file_type=file_type,
        mime_type=mime_type,
        stored_filename=saved_name,
        size=size,
    )
    message = f"Uploaded: {original_name} as {saved_name}"
    return _render_admin(conn, upload_message=message)



# (A10) HTTP method abuse — PUT on /admin/users/create
@admin_bp.route("/admin/users/create", methods=["POST", "PUT"])
def create_user():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    username = request.values.get("username", "").strip()
    email = request.values.get("email", "").strip()
    password = request.values.get("password", "").strip()
    role = request.values.get("role", "student").strip() or "student"
    account_status = request.values.get("status", "active").strip() or "active"
    bio = request.values.get("bio", "").strip()

    conn = get_db_connection()
    if not username or not email or not password:
        return _render_admin(conn, admin_message="Username, email, and password are required.")
    if role not in {"student", "instructor", "admin"}:
        return _render_admin(conn, admin_message="Select a valid role for the new user.")
    if account_status not in {"active", "locked", "suspended"}:
        return _render_admin(conn, admin_message="Select a valid account status.")

    try:
        conn.execute(
            """
            INSERT INTO users (username, email, password, role, status, bio, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (username, email, password, role, account_status, bio),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return _render_admin(conn, admin_message="Username or email already exists.")

    log_event(
        "admin_action",
        status="success",
        action="create_user",
        username=username,
        role=role,
        account_status=account_status,
    )
    return _render_admin(conn, admin_message=f"Created user: {username}")


# (A10) HTTP method abuse — PUT on /admin/users/<id>/edit
@admin_bp.route("/admin/users/<int:user_id>/edit", methods=["POST", "PUT"])
def edit_user(user_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    username = request.values.get("username", "").strip()
    email = request.values.get("email", "").strip()
    role = request.values.get("role", "student").strip() or "student"
    account_status = request.values.get("status", "active").strip() or "active"
    bio = request.values.get("bio", "").strip()
    new_password = request.values.get("password", "").strip()

    conn = get_db_connection()
    if not username or not email:
        return _render_admin(conn, admin_message="Username and email are required for edits.")
    if role not in {"student", "instructor", "admin"}:
        return _render_admin(conn, admin_message="Select a valid role before saving user edits.")
    if account_status not in {"active", "locked", "suspended"}:
        return _render_admin(conn, admin_message="Select a valid account status before saving user edits.")

    try:
        conn.execute(
            """
            UPDATE users
            SET username = ?, email = ?, role = ?, status = ?, bio = ?
            WHERE id = ?
            """,
            (username, email, role, account_status, bio, user_id),
        )
        if account_status == "active":
            conn.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,),
            )
        if new_password:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
        conn.commit()
    except sqlite3.IntegrityError:
        return _render_admin(conn, admin_message="Username or email already exists.")

    log_event(
        "admin_action",
        status="success",
        action="edit_user",
        target_user_id=user_id,
        role=role,
        account_status=account_status,
    )
    return _render_admin(conn, admin_message=f"Updated user #{user_id}.")


# (A10) HTTP method abuse — DELETE on /admin/users/<id>/delete
@admin_bp.route("/admin/users/<int:user_id>/delete", methods=["POST", "DELETE"])
def delete_user(user_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    conn = get_db_connection()
    if session.get("user_id") == user_id:
        return _render_admin(conn, admin_message="You cannot archive the currently signed-in admin.")

    target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        return _render_admin(conn, admin_message="User not found.")

    if target["role"] == "admin":
        admin_count = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'admin'").fetchone()["total"]
        if admin_count <= 1:
            return _render_admin(conn, admin_message="Cannot archive the last admin account.")

    conn.execute(
        "UPDATE users SET archived_at = datetime('now'), status = 'suspended' WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    log_event("admin_action", status="success", action="archive_user", target_user_id=user_id)
    return _render_admin(conn, admin_message=f"Archived user #{user_id}.")


@admin_bp.route("/admin/users/<int:user_id>/restore", methods=["POST"])
def restore_user(user_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET archived_at = NULL, status = 'active', locked_until = NULL, failed_login_attempts = 0 WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    log_event("admin_action", status="success", action="restore_user", target_user_id=user_id)
    return _render_admin(conn, admin_message=f"Restored user #{user_id}.")


# (A10) HTTP method abuse — PUT on /admin/courses/<id>/edit
@admin_bp.route("/admin/courses/<int:course_id>/edit", methods=["POST", "PUT"])
def edit_course(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    title = request.values.get("title", "")
    description = request.values.get("description", "")
    category = request.values.get("category", "General")
    level = request.values.get("level", "Beginner")
    duration = request.values.get("duration_hours", "10")
    instructor_id = request.values.get("instructor_id", "").strip()

    conn = get_db_connection()
    conn.execute(
        """
        UPDATE courses
        SET title = ?, description = ?, category = ?, level = ?, duration_hours = ?, instructor_id = ?
        WHERE id = ?
        """,
        (title, description, category, level, duration, instructor_id if instructor_id else None, course_id),
    )
    conn.commit()
    log_event("admin_action", status="success", action="edit_course", course_id=course_id, title=title)

    return _render_admin(conn, admin_message=f"Updated course #{course_id}.")


@admin_bp.route("/admin/courses/<int:course_id>/section/add", methods=["POST"])
def add_section(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    title = request.form.get("title", "").strip()
    if not title:
        return _render_admin(get_db_connection(), admin_message="Section title cannot be empty.")

    conn = get_db_connection()
    last = conn.execute(
        "SELECT COALESCE(MAX(position), 0) AS max_pos FROM course_sections WHERE course_id = ?",
        (course_id,),
    ).fetchone()
    position = int(last["max_pos"]) + 1
    conn.execute(
        "INSERT INTO course_sections (course_id, title, position, created_at) VALUES (?, ?, ?, datetime('now'))",
        (course_id, title, position),
    )
    conn.commit()
    log_event("curriculum_updated", status="success", action="add_section", course_id=course_id)
    return _render_admin(conn, admin_message=f"Section added to course #{course_id}.")


# (A10) HTTP method abuse — PUT on /admin/sections/<id>/edit
@admin_bp.route("/admin/sections/<int:section_id>/edit", methods=["POST", "PUT"])
def edit_section(section_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    title = request.form.get("title", "").strip()
    position = request.form.get("position", "").strip()
    if not title:
        return _render_admin(get_db_connection(), admin_message="Section title cannot be empty.")

    conn = get_db_connection()
    if position.isdigit():
        conn.execute("UPDATE course_sections SET title = ?, position = ? WHERE id = ?", (title, int(position), section_id))
    else:
        conn.execute("UPDATE course_sections SET title = ? WHERE id = ?", (title, section_id))
    conn.commit()
    log_event("curriculum_updated", status="success", action="edit_section", section_id=section_id)
    return _render_admin(conn, admin_message=f"Section #{section_id} updated.")


# (A10) HTTP method abuse — DELETE on /admin/sections/<id>/delete
@admin_bp.route("/admin/sections/<int:section_id>/delete", methods=["POST", "DELETE"])
def delete_section(section_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()
    conn.execute("DELETE FROM course_lessons WHERE section_id = ?", (section_id,))
    conn.execute("DELETE FROM course_sections WHERE id = ?", (section_id,))
    conn.commit()
    log_event("curriculum_updated", status="success", action="delete_section", section_id=section_id)
    return _render_admin(conn, admin_message=f"Section #{section_id} deleted.")


@admin_bp.route("/admin/courses/<int:course_id>/lesson/add", methods=["POST"])
def add_lesson(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    section_id = request.form.get("section_id", "").strip()
    title = request.form.get("title", "").strip()
    lesson_type = request.form.get("lesson_type", "video").strip() or "video"
    content_input = request.form.get("content", "")
    content, content_error = _validate_lesson_content(content_input)
    if content_error:
        return _render_admin(get_db_connection(), admin_message=content_error)
    if not section_id or not title:
        return _render_admin(get_db_connection(), admin_message="Section and lesson title are required.")

    conn = get_db_connection()
    last = conn.execute(
        "SELECT COALESCE(MAX(position), 0) AS max_pos FROM course_lessons WHERE section_id = ?",
        (section_id,),
    ).fetchone()
    position = int(last["max_pos"]) + 1
    conn.execute(
        """
        INSERT INTO course_lessons (
            course_id, section_id, title, lesson_type, content, position,
            is_preview, created_at, duration_minutes
        )
        VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'), 25)
        """,
        (course_id, section_id, title, lesson_type, content, position),
    )
    conn.commit()
    log_event("curriculum_updated", status="success", action="add_lesson", course_id=course_id)
    return _render_admin(conn, admin_message=f"Lesson added to course #{course_id}.")


# (A10) HTTP method abuse — PUT on /admin/lessons/<id>/edit
@admin_bp.route("/admin/lessons/<int:lesson_id>/edit", methods=["POST", "PUT"])
def edit_lesson(lesson_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    title = request.form.get("title", "").strip()
    lesson_type = request.form.get("lesson_type", "video").strip() or "video"
    content_input = request.form.get("content", "")
    content, content_error = _validate_lesson_content(content_input)
    if content_error:
        return _render_admin(get_db_connection(), admin_message=content_error)
    content = content or title
    position = request.form.get("position", "").strip()
    if not title:
        return _render_admin(get_db_connection(), admin_message="Lesson title cannot be empty.")

    conn = get_db_connection()
    if position.isdigit():
        conn.execute(
            "UPDATE course_lessons SET title = ?, lesson_type = ?, content = ?, position = ? WHERE id = ?",
            (title, lesson_type, content, int(position), lesson_id),
        )
    else:
        conn.execute(
            "UPDATE course_lessons SET title = ?, lesson_type = ?, content = ? WHERE id = ?",
            (title, lesson_type, content, lesson_id),
        )
    conn.commit()
    log_event("curriculum_updated", status="success", action="edit_lesson", lesson_id=lesson_id)
    return _render_admin(conn, admin_message=f"Lesson #{lesson_id} updated.")


# (A10) HTTP method abuse — DELETE on /admin/lessons/<id>/delete
@admin_bp.route("/admin/lessons/<int:lesson_id>/delete", methods=["POST", "DELETE"])
def delete_lesson(lesson_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()
    conn.execute("DELETE FROM course_lessons WHERE id = ?", (lesson_id,))
    conn.commit()
    log_event("curriculum_updated", status="success", action="delete_lesson", lesson_id=lesson_id)
    return _render_admin(conn, admin_message=f"Lesson #{lesson_id} deleted.")


@admin_bp.route("/admin/courses/<int:course_id>/publish", methods=["POST"])
def set_publish_state(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    status = request.form.get("status", "draft")
    if status not in {"draft", "published"}:
        status = "draft"
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO course_publish_state (course_id, status, updated_by, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(course_id)
        DO UPDATE SET status = excluded.status, updated_by = excluded.updated_by, updated_at = datetime('now')
        """,
        (course_id, status, session.get("user_id")),
    )
    conn.execute(
        """
        INSERT INTO notifications (user_id, type, message, is_read, created_at)
        SELECT c.instructor_id, 'course_update', ?, 0, datetime('now')
        FROM courses c
        WHERE c.id = ? AND c.instructor_id IS NOT NULL
        """,
        (f"Publish state changed to {status} for course #{course_id}.", course_id),
    )
    conn.commit()
    log_event("course_publish_state_changed", status="success", course_id=course_id, publish_state=status)
    log_event("notification_event", status="success", notification_type="course_update")
    return _render_admin(conn, admin_message=f"Course #{course_id} is now {status}.")


@admin_bp.route("/admin/users/bulk", methods=["POST"])
def bulk_users_action():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    selected_ids = request.form.getlist("user_ids")
    action = request.form.get("bulk_action", "").strip()
    role = request.form.get("bulk_role", "").strip()
    account_status = request.form.get("bulk_status", "").strip()
    if not selected_ids:
        return _render_admin(get_db_connection(), admin_message="Select at least one user for bulk action.")

    conn = get_db_connection()
    ids = [int(x) for x in selected_ids if str(x).isdigit()]
    if not ids:
        return _render_admin(conn, admin_message="Invalid user selection.")

    placeholders = ",".join(["?"] * len(ids))
    if action == "set_role":
        if role not in {"student", "instructor", "admin"}:
            return _render_admin(conn, admin_message="Choose a valid role for bulk update.")
        conn.execute(f"UPDATE users SET role = ? WHERE id IN ({placeholders})", (role, *ids))
        conn.commit()
        return _render_admin(conn, admin_message=f"Updated roles for {len(ids)} users.")
    if action == "set_status":
        if account_status not in {"active", "locked", "suspended"}:
            return _render_admin(conn, admin_message="Choose a valid status for bulk update.")
        conn.execute(f"UPDATE users SET status = ? WHERE id IN ({placeholders})", (account_status, *ids))
        if account_status == "active":
            conn.execute(
                f"UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id IN ({placeholders})",
                tuple(ids),
            )
        conn.commit()
        log_event("admin_action", status="success", action="bulk_set_status", account_status=account_status, target_count=len(ids))
        return _render_admin(conn, admin_message=f"Updated status for {len(ids)} users.")
    if action == "archive":
        # avoid archiving current user in bulk
        ids = [uid for uid in ids if uid != session.get("user_id")]
        if not ids:
            return _render_admin(conn, admin_message="Cannot archive the currently signed-in user.")

        admin_ids = {
            row["id"]
            for row in conn.execute(
                f"SELECT id FROM users WHERE role = 'admin' AND id IN ({','.join(['?'] * len(ids))})",
                tuple(ids),
            ).fetchall()
        }
        total_admins = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'admin'").fetchone()["total"]
        if total_admins - len(admin_ids) < 1:
            return _render_admin(conn, admin_message="Bulk archive would remove the last admin. Action cancelled.")

        conn.execute(
            f"UPDATE users SET archived_at = datetime('now'), status = 'suspended' WHERE id IN ({placeholders})",
            tuple(ids),
        )
        conn.commit()
        log_event("admin_action", status="success", action="bulk_archive_users", target_count=len(ids))
        return _render_admin(conn, admin_message=f"Archived {len(ids)} users.")
    if action == "restore":
        conn.execute(
            f"UPDATE users SET archived_at = NULL, status = 'active', locked_until = NULL, failed_login_attempts = 0 WHERE id IN ({placeholders})",
            tuple(ids),
        )
        conn.commit()
        log_event("admin_action", status="success", action="bulk_restore_users", target_count=len(ids))
        return _render_admin(conn, admin_message=f"Restored {len(ids)} users.")
    return _render_admin(conn, admin_message="Select a valid bulk user action.")


@admin_bp.route("/admin/courses/bulk", methods=["POST"])
def bulk_courses_action():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    selected_ids = request.form.getlist("course_ids")
    action = request.form.get("bulk_action", "").strip()
    if not selected_ids:
        return _render_admin(get_db_connection(), admin_message="Select at least one course for bulk action.")

    conn = get_db_connection()
    ids = [int(x) for x in selected_ids if str(x).isdigit()]
    if not ids:
        return _render_admin(conn, admin_message="Invalid course selection.")
    placeholders = ",".join(["?"] * len(ids))

    if action in {"publish", "draft"}:
        for cid in ids:
            conn.execute(
                """
                INSERT INTO course_publish_state (course_id, status, updated_by, updated_at)
                VALUES (?, ?, ?, datetime('now'))
                ON CONFLICT(course_id) DO UPDATE SET status = excluded.status, updated_by = excluded.updated_by, updated_at = datetime('now')
                """,
                (cid, "published" if action == "publish" else "draft", session.get("user_id")),
            )
        conn.commit()
        return _render_admin(conn, admin_message=f"Updated publish state for {len(ids)} courses.")

    if action == "archive":
        conn.execute(f"UPDATE courses SET archived_at = datetime('now') WHERE id IN ({placeholders})", tuple(ids))
        conn.commit()
        return _render_admin(conn, admin_message=f"Archived {len(ids)} courses.")
    if action == "restore":
        conn.execute(f"UPDATE courses SET archived_at = NULL WHERE id IN ({placeholders})", tuple(ids))
        conn.commit()
        return _render_admin(conn, admin_message=f"Restored {len(ids)} courses.")

    return _render_admin(conn, admin_message="Select a valid bulk course action.")


# (A10) HTTP method abuse — PUT on /admin/courses/create
@admin_bp.route("/admin/courses/create", methods=["POST", "PUT"])
def create_course():
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    title = request.values.get("title", "")
    description = request.values.get("description", "")
    category = request.values.get("category", "General")
    level = request.values.get("level", "Beginner")
    duration = request.values.get("duration_hours", "10")
    instructor_id = request.values.get("instructor_id", "").strip()

    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO courses (title, description, category, level, duration_hours, instructor_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (title, description, category, level, duration, instructor_id if instructor_id else session.get("user_id")),
    )
    conn.commit()
    log_event("admin_action", status="success", action="create_course", title=title, category=category)

    return _render_admin(conn, admin_message=f"Created course: {title}")


# (A10) HTTP method abuse — DELETE on /admin/courses/<id>/delete
@admin_bp.route("/admin/courses/<int:course_id>/delete", methods=["POST", "DELETE"])
def delete_course(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    conn = get_db_connection()
    conn.execute("UPDATE courses SET archived_at = datetime('now') WHERE id = ?", (course_id,))
    conn.commit()
    log_event("admin_action", status="success", action="archive_course", course_id=course_id)

    return _render_admin(conn, admin_message=f"Archived course #{course_id}.")


@admin_bp.route("/admin/courses/<int:course_id>/restore", methods=["POST"])
def restore_course(course_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    conn = get_db_connection()
    conn.execute("UPDATE courses SET archived_at = NULL WHERE id = ?", (course_id,))
    conn.commit()
    log_event("admin_action", status="success", action="restore_course", course_id=course_id)
    return _render_admin(conn, admin_message=f"Restored course #{course_id}.")


# (A10) HTTP method abuse — DELETE on /admin/materials/<id>/delete
@admin_bp.route("/admin/materials/<int:upload_id>/delete", methods=["POST", "DELETE"])
def delete_material(upload_id: int):
    if not session.get("user_id"):
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    conn = get_db_connection()
    item = conn.execute(
        "SELECT id, stored_filename, original_filename FROM uploads WHERE id = ?",
        (upload_id,),
    ).fetchone()
    if item:
        upload_dir = current_app.config.get("UPLOAD_FOLDER", "static/uploads")
        file_path = os.path.join(upload_dir, item["stored_filename"])
        if os.path.exists(file_path):
            os.remove(file_path)
        conn.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
        conn.commit()
        log_event("admin_action", status="success", action="delete_material", upload_id=upload_id)
        message = f"Removed material: {item['original_filename']}"
    else:
        message = "Material not found."

    return _render_admin(conn, admin_message=message)
