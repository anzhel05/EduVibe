import json

from flask import Blueprint, redirect, render_template, request, session

from database.db import get_db_connection
from utils.logger import log_event


# Intentional vulnerabilities: A2, A3, A10 (see ATTACK_SCENARIOS.md; [sim] = attack_simulation.sh)
courses_bp = Blueprint("courses", __name__)


def _course_lessons(conn, course_id: int):
    rows = conn.execute(
        """
        SELECT
            l.id,
            l.title,
            l.lesson_type,
            l.content,
            l.position,
            l.is_preview,
            COALESCE(l.duration_minutes, 25) AS duration_minutes,
            s.id AS section_id,
            s.title AS section_title,
            s.position AS section_position
        FROM course_lessons l
        JOIN course_sections s ON s.id = l.section_id
        WHERE l.course_id = ?
        ORDER BY s.position ASC, l.position ASC
        """,
        (course_id,),
    ).fetchall()
    lessons = []
    for row in rows:
        lessons.append(
            {
                "id": row["id"],
                "key": f"lesson_{row['id']}",
                "title": row["title"],
                "type": row["lesson_type"],
                "material": _material_for_lesson(row["lesson_type"], row["content"]),
                "duration": f"{int(row['duration_minutes'])} min",
                "is_preview": row["is_preview"],
                "section_id": row["section_id"],
                "section_title": row["section_title"],
            }
        )
    return lessons


def _material_for_lesson(lesson_type: str, content: str):
    raw = (content or "").strip()
    base = {"summary": raw}
    if not raw:
        return base
    try:
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("format") == "material_v1":
            return payload
    except (json.JSONDecodeError, TypeError):
        pass
    if lesson_type == "quiz":
        return {"summary": raw, "questions": []}
    return base


def _progress_snapshot(conn, user_id: int, course_id: int):
    lessons = _course_lessons(conn, course_id)
    if not lessons:
        return [], set(), 0, None
    completed_rows = conn.execute(
        """
        SELECT lesson_key
        FROM lesson_progress
        WHERE user_id = ? AND course_id = ? AND completed = 1
        """,
        (user_id, course_id),
    ).fetchall()
    completed_keys = {row["lesson_key"] for row in completed_rows}
    completed_count = sum(1 for lesson in lessons if lesson["key"] in completed_keys)
    total = len(lessons)
    progress_pct = int((completed_count / total) * 100) if total else 0
    continue_lesson = next((lesson for lesson in lessons if lesson["key"] not in completed_keys), lessons[-1])
    return lessons, completed_keys, progress_pct, continue_lesson


@courses_bp.route("/courses", methods=["GET"])
def list_courses():
    search = request.args.get("search", "")
    category = request.args.get("category", "")
    level = request.args.get("level", "")
    max_duration = request.args.get("max_duration", "")
    min_rating = request.args.get("min_rating", "")
    sort = request.args.get("sort", "newest")
    page_raw = request.args.get("page", "1")
    page_size = 6
    try:
        page = max(int(page_raw), 1)
    except ValueError:
        page = 1
    user_id = session.get("user_id")
    conn = get_db_connection()

    # (A2) SQL injection — search interpolated into course query [sim]
    base_query = """
        SELECT
            c.id,
            c.title,
            c.category,
            c.level,
            c.duration_hours,
            c.description,
            ROUND(COALESCE(AVG(r.rating), 0), 1) AS avg_rating,
            COUNT(DISTINCT r.id) AS review_count,
            COUNT(DISTINCT e.user_id) AS enrolled_count
        FROM courses c
        LEFT JOIN course_reviews r ON r.course_id = c.id
        LEFT JOIN enrollments e ON e.course_id = c.id
    """
    where_parts = ["c.archived_at IS NULL"]
    having_parts = []
    if search:
        where_parts.append(f"(c.title LIKE '%{search}%' OR c.description LIKE '%{search}%')")
        if any(token in search.lower() for token in ["' or ", "union", "--", "/*", "1=1"]):
            log_event("sqli_pattern_detected", level="warning", search=search)
    if category:
        where_parts.append("c.category = ?")
    if level:
        where_parts.append("c.level = ?")
    if max_duration:
        where_parts.append("c.duration_hours <= ?")
    if min_rating:
        having_parts.append("ROUND(COALESCE(AVG(r.rating), 0), 1) >= ?")

    raw_query = base_query
    params = []
    if where_parts:
        raw_query += " WHERE " + " AND ".join(where_parts)
    raw_query += " GROUP BY c.id"

    if category:
        params.append(category)
    if level:
        params.append(level)
    if max_duration:
        params.append(max_duration)
    if min_rating:
        params.append(min_rating)
    if having_parts:
        raw_query += " HAVING " + " AND ".join(having_parts)

    sort_map = {
        "newest": "c.id DESC",
        "rating": "avg_rating DESC, review_count DESC, c.id DESC",
        "duration_asc": "c.duration_hours ASC, c.id DESC",
        "duration_desc": "c.duration_hours DESC, c.id DESC",
        "popular": "enrolled_count DESC, review_count DESC, c.id DESC",
    }
    sort_key = sort if sort in sort_map else "newest"
    order_by = sort_map[sort_key]

    count_query = f"SELECT COUNT(*) AS total FROM ({raw_query}) base_courses"
    total_courses = int(conn.execute(count_query, tuple(params)).fetchone()["total"])
    total_pages = max((total_courses + page_size - 1) // page_size, 1)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * page_size

    page_query = raw_query + f" ORDER BY {order_by} LIMIT ? OFFSET ?"
    rows = conn.execute(page_query, tuple(params + [page_size, offset])).fetchall()

    enrolled_ids = set()
    wishlist_ids = set()
    if user_id:
        enrolled_rows = conn.execute(
            "SELECT course_id FROM enrollments WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        enrolled_ids = {row["course_id"] for row in enrolled_rows}
        wishlist_rows = conn.execute(
            "SELECT course_id FROM wishlists WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        wishlist_ids = {row["course_id"] for row in wishlist_rows}

    categories = [
        row["category"]
        for row in conn.execute(
            "SELECT DISTINCT category FROM courses WHERE archived_at IS NULL ORDER BY category"
        )
    ]
    levels = [
        row["level"]
        for row in conn.execute(
            "SELECT DISTINCT level FROM courses WHERE archived_at IS NULL ORDER BY level"
        )
    ]
    return render_template(
        "courses.html",
        courses=rows,
        search=search,
        enrolled_ids=enrolled_ids,
        wishlist_ids=wishlist_ids,
        user_id=user_id,
        category=category,
        level=level,
        max_duration=max_duration,
        min_rating=min_rating,
        sort=sort_key,
        categories=categories,
        levels=levels,
        page=page,
        total_pages=total_pages,
        total_courses=total_courses,
    )


@courses_bp.route("/courses/<int:course_id>", methods=["GET"])
def course_detail(course_id: int):
    user_id = session.get("user_id")
    conn = get_db_connection()
    course = conn.execute(
        "SELECT id, title, description, category, level, duration_hours FROM courses WHERE id = ? AND archived_at IS NULL",
        (course_id,),
    ).fetchone()
    sort_reviews = request.args.get("sort_reviews", "newest")
    review_order = "cr.id DESC" if sort_reviews != "top" else "cr.rating DESC, cr.id DESC"
    reviews = conn.execute(
        f"""
        SELECT cr.rating, cr.content, cr.created_at, u.username
        FROM course_reviews cr
        JOIN users u ON u.id = cr.user_id
        WHERE cr.course_id = ?
        ORDER BY {review_order}
        """,
        (course_id,),
    ).fetchall()
    rating_summary = conn.execute(
        "SELECT ROUND(COALESCE(AVG(rating), 0), 1) AS avg_rating, COUNT(*) AS total_reviews FROM course_reviews WHERE course_id = ?",
        (course_id,),
    ).fetchone()

    if not course:
        return "Course not found", 404

    is_enrolled = False
    is_wishlisted = False
    progress_pct = 0
    continue_lesson = None
    if user_id:
        enrolled = conn.execute(
            "SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?",
            (user_id, course_id),
        ).fetchone()
        is_enrolled = enrolled is not None
        wishlisted = conn.execute(
            "SELECT id FROM wishlists WHERE user_id = ? AND course_id = ?",
            (user_id, course_id),
        ).fetchone()
        is_wishlisted = wishlisted is not None
        if is_enrolled:
            _, _, progress_pct, continue_lesson = _progress_snapshot(conn, user_id, course_id)
    publish_row = conn.execute(
        "SELECT status FROM course_publish_state WHERE course_id = ? LIMIT 1",
        (course_id,),
    ).fetchone()
    publish_status = publish_row["status"] if publish_row else "draft"

    review_error = request.args.get("review_error")
    review_success = request.args.get("review_success")

    return render_template(
        "course_detail.html",
        course=course,
        reviews=reviews,
        sort_reviews=sort_reviews,
        rating_summary=rating_summary,
        is_enrolled=is_enrolled,
        is_wishlisted=is_wishlisted,
        progress_pct=progress_pct,
        continue_lesson=continue_lesson,
        user_id=user_id,
        review_error=review_error,
        review_success=review_success,
        publish_status=publish_status,
    )



# (A10) HTTP method abuse — GET/DELETE on enroll
@courses_bp.route("/enroll/<int:course_id>", methods=["POST", "GET", "DELETE"])
def enroll(course_id: int):
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("course_enrollment", level="warning", status="unauthenticated", course_id=course_id)
        return redirect("/login")

    conn = get_db_connection()
    course = conn.execute(
        "SELECT id FROM courses WHERE id = ? AND archived_at IS NULL",
        (course_id,),
    ).fetchone()
    if not course:
        log_event("course_enrollment", level="warning", status="course_unavailable", course_id=course_id)
        return redirect("/courses")

    existing = conn.execute(
        "SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?",
        (user_id, course_id),
    ).fetchone()
    if existing:
        log_event("course_enrollment", status="duplicate", course_id=course_id)
        return redirect(f"/learn/{course_id}")

    conn.execute(
        "INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES (?, ?, datetime('now'))",
        (user_id, course_id),
    )
    conn.execute(
        "INSERT INTO notifications (user_id, type, message, is_read, created_at) VALUES (?, 'enrollment', ?, 0, datetime('now'))",
        (user_id, f"Enrollment confirmed for course #{course_id}."),
    )
    conn.commit()
    log_event("course_enrollment", status="success", course_id=course_id)
    log_event("notification_event", status="success", notification_type="enrollment")
    return redirect(f"/learn/{course_id}")




# (A10) HTTP method abuse — GET/DELETE on withdraw
@courses_bp.route("/withdraw/<int:course_id>", methods=["POST", "GET", "DELETE"])
def withdraw(course_id: int):
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("course_withdrawal", level="warning", status="unauthenticated", course_id=course_id)
        return redirect("/login")

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?",
        (user_id, course_id),
    ).fetchone()
    if not existing:
        log_event("course_withdrawal", level="warning", status="not_enrolled", course_id=course_id)
        return redirect(request.referrer or "/courses")

    conn.execute("DELETE FROM enrollments WHERE user_id = ? AND course_id = ?", (user_id, course_id))
    conn.execute("DELETE FROM lesson_progress WHERE user_id = ? AND course_id = ?", (user_id, course_id))
    conn.execute(
        "INSERT INTO notifications (user_id, type, message, is_read, created_at) VALUES (?, 'enrollment', ?, 0, datetime('now'))",
        (user_id, f"You withdrew from course #{course_id}."),
    )
    conn.commit()
    log_event("course_withdrawal", status="success", course_id=course_id)
    log_event("notification_event", status="success", notification_type="enrollment")
    return redirect(request.referrer or "/courses")

# (A10) HTTP method abuse — GET/DELETE on wishlist add
@courses_bp.route("/wishlist/<int:course_id>/add", methods=["POST", "GET", "DELETE"])
def add_to_wishlist(course_id: int):
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("wishlist_updated", level="warning", status="unauthenticated", action="add", course_id=course_id)
        return redirect("/login")

    conn = get_db_connection()
    conn.execute(
        "INSERT OR IGNORE INTO wishlists (user_id, course_id, created_at) VALUES (?, ?, datetime('now'))",
        (user_id, course_id),
    )
    conn.commit()
    log_event("wishlist_updated", status="success", action="add", course_id=course_id)
    return redirect(request.referrer or "/courses")


# (A10) HTTP method abuse — GET/DELETE on wishlist remove
@courses_bp.route("/wishlist/<int:course_id>/remove", methods=["POST", "GET", "DELETE"])
def remove_from_wishlist(course_id: int):
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("wishlist_updated", level="warning", status="unauthenticated", action="remove", course_id=course_id)
        return redirect("/login")

    conn = get_db_connection()
    conn.execute("DELETE FROM wishlists WHERE user_id = ? AND course_id = ?", (user_id, course_id))
    conn.commit()
    log_event("wishlist_updated", status="success", action="remove", course_id=course_id)
    return redirect(request.referrer or "/courses")


# (A3) POST/PUT /courses/<id>/review — stored XSS / (A10) method abuse
@courses_bp.route("/courses/<int:course_id>/review", methods=["POST", "PUT"])
def submit_review(course_id: int):
    # (A10) PUT triggers http_method_abuse; (A3) POST used in simulation [sim: POST]
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("review_submitted", level="warning", status="unauthenticated", course_id=course_id)
        return redirect("/login")

    rating = request.values.get("rating", "").strip()
    content = request.values.get("content", "")
    if rating not in {"1", "2", "3", "4", "5"}:
        log_event("review_submitted", level="warning", status="invalid_rating", course_id=course_id)
        return redirect(f"/courses/{course_id}?review_error=Rating%20must%20be%20from%201%20to%205")
    if not content.strip():
        log_event("review_submitted", level="warning", status="empty_content", course_id=course_id)
        return redirect(f"/courses/{course_id}?review_error=Review%20text%20cannot%20be%20empty")

    # (A3) Stored XSS in review content — unsanitized storage [sim]
    if "<script" in content.lower() or "onerror=" in content.lower() or "javascript:" in content.lower():
        log_event("xss_payload_detected", level="warning", payload=content)

    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO course_reviews (user_id, course_id, rating, content, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(user_id, course_id)
        DO UPDATE SET rating = excluded.rating, content = excluded.content, created_at = datetime('now')
        """,
        (user_id, course_id, int(rating), content),
    )
    conn.execute(
        "INSERT INTO notifications (user_id, type, message, is_read, created_at) VALUES (?, 'review', ?, 0, datetime('now'))",
        (user_id, f"Review saved for course #{course_id}."),
    )
    conn.commit()
    log_event("review_submitted", status="success", course_id=course_id, rating=rating)
    log_event("notification_event", status="success", notification_type="review")
    return redirect(f"/courses/{course_id}?review_success=Review%20saved")


@courses_bp.route("/learn/<int:course_id>", methods=["GET"])
def learn_course(course_id: int):
    conn = get_db_connection()
    user_id = session.get("user_id")
    if not user_id:
        log_event("unauthorized_access_attempt", level="warning", status="guest_blocked")
        return redirect("/login")

    course = conn.execute(
        "SELECT id, title, description, category, level, duration_hours FROM courses WHERE id = ? AND archived_at IS NULL",
        (course_id,),
    ).fetchone()
    if not course:
        return "Course not found", 404

    lessons, completed_keys, progress_pct, continue_lesson = _progress_snapshot(conn, user_id, course_id)
    sections = {}
    ordered_sections = []
    for lesson in lessons:
        section_id = lesson["section_id"]
        if section_id not in sections:
            sections[section_id] = {"id": section_id, "title": lesson["section_title"], "lessons": []}
            ordered_sections.append(sections[section_id])
        sections[section_id]["lessons"].append(lesson)
    quiz_attempt_rows = conn.execute(
        """
        SELECT lesson_key, attempt_number, score, total_questions, passed, submitted_at
        FROM quiz_attempts
        WHERE user_id = ? AND course_id = ?
        ORDER BY submitted_at DESC, id DESC
        """,
        (user_id, course_id),
    ).fetchall()
    latest_quiz_attempts = {}
    for row in quiz_attempt_rows:
        lesson_key = row["lesson_key"]
        if lesson_key not in latest_quiz_attempts:
            latest_quiz_attempts[lesson_key] = dict(row)

    return render_template(
        "course_learn.html",
        course=course,
        lessons=lessons,
        sections=ordered_sections,
        completed_keys=completed_keys,
        progress_pct=progress_pct,
        continue_lesson=continue_lesson,
        latest_quiz_attempts=latest_quiz_attempts,
    )


# (A10) HTTP method abuse — PUT/TRACE on lesson progress
@courses_bp.route("/learn/<int:course_id>/progress", methods=["POST", "PUT", "TRACE"])
def update_progress(course_id: int):
    if request.method != "POST":
        log_event("http_method_abuse", level="warning")

    user_id = session.get("user_id")
    if not user_id:
        log_event("lesson_progress_updated", level="warning", status="unauthenticated", course_id=course_id)
        return redirect("/login")

    lesson_key = request.values.get("lesson_key", "")
    if not lesson_key:
        log_event("lesson_progress_updated", level="warning", status="missing_lesson", course_id=course_id)
        return redirect(f"/learn/{course_id}")

    completed = 1 if request.values.get("completed", "1") != "0" else 0
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO lesson_progress (user_id, course_id, lesson_key, completed, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(user_id, course_id, lesson_key)
        DO UPDATE SET completed = excluded.completed, updated_at = datetime('now')
        """,
        (user_id, course_id, lesson_key, completed),
    )
    conn.commit()
    log_event(
        "lesson_progress_updated",
        status="success",
        course_id=course_id,
        lesson_key=lesson_key,
        completed=completed,
    )
    return redirect(f"/learn/{course_id}")


@courses_bp.route("/learn/<int:course_id>/quiz-attempt", methods=["POST"])
def record_quiz_attempt(course_id: int):
    user_id = session.get("user_id")
    if not user_id:
        log_event("quiz_attempt", level="warning", status="unauthenticated", course_id=course_id)
        return {"ok": False, "error": "auth_required"}, 401

    payload = request.get_json(silent=True) or request.form
    lesson_key = (payload.get("lesson_key") if payload else "") or ""
    try:
        score = int(payload.get("score", 0))
        total = int(payload.get("total_questions", 0))
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid_score"}, 400
    passed_raw = payload.get("passed", False)
    passed = 1 if str(passed_raw).lower() in {"1", "true", "yes"} else 0
    answers_json = json.dumps(payload.get("answers", {}), ensure_ascii=False) if payload else "{}"

    if not lesson_key or total < 1 or score < 0 or score > total:
        log_event("quiz_attempt", level="warning", status="invalid_payload", course_id=course_id, lesson_key=lesson_key)
        return {"ok": False, "error": "invalid_payload"}, 400

    conn = get_db_connection()
    lesson = conn.execute(
        """
        SELECT l.id
        FROM course_lessons l
        JOIN enrollments e ON e.course_id = l.course_id AND e.user_id = ?
        WHERE l.course_id = ? AND ('lesson_' || l.id) = ?
        LIMIT 1
        """,
        (user_id, course_id, lesson_key),
    ).fetchone()
    if not lesson:
        log_event("quiz_attempt", level="warning", status="lesson_not_allowed", course_id=course_id, lesson_key=lesson_key)
        return {"ok": False, "error": "lesson_not_found"}, 404

    latest_attempt = conn.execute(
        """
        SELECT COALESCE(MAX(attempt_number), 0) AS max_attempt
        FROM quiz_attempts
        WHERE user_id = ? AND course_id = ? AND lesson_key = ?
        """,
        (user_id, course_id, lesson_key),
    ).fetchone()
    attempt_number = int(latest_attempt["max_attempt"] or 0) + 1
    conn.execute(
        """
        INSERT INTO quiz_attempts (
            user_id, course_id, lesson_key, attempt_number, score, total_questions, passed, answers_json, submitted_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (user_id, course_id, lesson_key, attempt_number, score, total, passed, answers_json),
    )
    conn.commit()
    log_event(
        "quiz_attempt",
        status="success",
        course_id=course_id,
        lesson_key=lesson_key,
        attempt_number=attempt_number,
        score=score,
        total_questions=total,
        passed=passed,
    )
    return {"ok": True, "attempt_number": attempt_number}
