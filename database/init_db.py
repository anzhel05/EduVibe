import os
import sqlite3
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.curriculum_seed import apply_full_curriculum, ensure_minimal_outline


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Plaintext passwords are intentional in this experimental environment.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            status TEXT NOT NULL DEFAULT 'active',
            archived_at TEXT,
            locked_until TEXT,
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            bio TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    user_columns = [row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()]
    if "status" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    if "archived_at" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN archived_at TEXT")
    if "locked_until" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    if "failed_login_attempts" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            level TEXT DEFAULT 'Beginner',
            duration_hours INTEGER DEFAULT 10,
            instructor_id INTEGER,
            archived_at TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    # Lightweight schema migration for existing databases.
    course_columns = [row[1] for row in cur.execute("PRAGMA table_info(courses)").fetchall()]
    if "level" not in course_columns:
        cur.execute("ALTER TABLE courses ADD COLUMN level TEXT DEFAULT 'Beginner'")
    if "duration_hours" not in course_columns:
        cur.execute("ALTER TABLE courses ADD COLUMN duration_hours INTEGER DEFAULT 10")
    if "archived_at" not in course_columns:
        cur.execute("ALTER TABLE courses ADD COLUMN archived_at TEXT")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrolled_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
        """
    )

    upload_columns = [row[1] for row in cur.execute("PRAGMA table_info(uploads)").fetchall()]
    if "course_id" not in upload_columns:
        cur.execute("ALTER TABLE uploads ADD COLUMN course_id INTEGER")
    if "lesson_id" not in upload_columns:
        cur.execute("ALTER TABLE uploads ADD COLUMN lesson_id INTEGER")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS lesson_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            lesson_key TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_lesson_progress_unique
        ON lesson_progress (user_id, course_id, lesson_key)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS course_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_course_reviews_unique
        ON course_reviews (user_id, course_id)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS wishlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_wishlists_unique
        ON wishlists (user_id, course_id)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS course_sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_course_sections_unique
        ON course_sections (course_id, position)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS course_lessons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            section_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            lesson_type TEXT NOT NULL DEFAULT 'video',
            content TEXT NOT NULL DEFAULT '',
            position INTEGER NOT NULL DEFAULT 1,
            is_preview INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_course_lessons_unique
        ON course_lessons (section_id, position)
        """
    )

    lesson_columns = [row[1] for row in cur.execute("PRAGMA table_info(course_lessons)").fetchall()]
    if "duration_minutes" not in lesson_columns:
        cur.execute("ALTER TABLE course_lessons ADD COLUMN duration_minutes INTEGER DEFAULT 25")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS course_publish_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'draft',
            updated_by INTEGER,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            lesson_key TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            passed INTEGER NOT NULL DEFAULT 0,
            answers_json TEXT DEFAULT '{}',
            submitted_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_quiz_attempts_lesson
        ON quiz_attempts (user_id, course_id, lesson_key, submitted_at DESC)
        """
    )

    cur.execute("DROP TABLE IF EXISTS user_settings")

    now = datetime.now(timezone.utc).isoformat()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("alice", "alice@student.local", "alice123", "student", "I love Python", now),
            ("bob", "bob@instructor.local", "bob123", "instructor", "Security instructor", now),
            ("admin", "admin@eduvibe.local", "admin123", "admin", "Platform admin", now),
        ]
        cur.executemany(
            "INSERT INTO users (username, email, password, role, bio, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            users,
        )

    cur.execute("SELECT COUNT(*) FROM courses")
    if cur.fetchone()[0] == 0:
        courses = [
            (
                "Intro to SOC",
                "Blue-team basics, SIEM workflows, and monitoring fundamentals for security operations.",
                "Cybersecurity",
                "Beginner",
                14,
                2,
                now,
            ),
            (
                "Web Pentesting Lab",
                "Hands-on vulnerable web testing scenarios, payload crafting, and attack surface analysis.",
                "Cybersecurity",
                "Intermediate",
                18,
                2,
                now,
            ),
            (
                "Python for Analysts",
                "Automation, parsing logs, and building simple detection scripts with Python.",
                "Programming",
                "Beginner",
                12,
                2,
                now,
            ),
            (
                "English for IT Communication",
                "Technical communication for meetings, incident reporting, and documentation in English.",
                "Language",
                "A2-B1",
                16,
                2,
                now,
            ),
            (
                "German for Beginners in Tech",
                "Practical German for study and work in IT environments with cybersecurity vocabulary.",
                "Language",
                "A1-A2",
                20,
                2,
                now,
            ),
        ]
        cur.executemany(
            "INSERT INTO courses (title, description, category, level, duration_hours, instructor_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            courses,
        )
    else:
        # Enrich existing courses with details and add missing language courses.
        cur.execute(
            "UPDATE courses SET level = 'Beginner', duration_hours = 14 WHERE title = 'Intro to SOC'"
        )
        cur.execute(
            "UPDATE courses SET level = 'Intermediate', duration_hours = 18 WHERE title = 'Web Pentesting Lab'"
        )
        cur.execute(
            "UPDATE courses SET level = 'Beginner', duration_hours = 12 WHERE title = 'Python for Analysts'"
        )

        cur.execute(
            """
            INSERT INTO courses (title, description, category, level, duration_hours, instructor_id, created_at)
            SELECT ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM courses WHERE title = ?)
            """,
            (
                "English for IT Communication",
                "Technical communication for meetings, incident reporting, and documentation in English.",
                "Language",
                "A2-B1",
                16,
                2,
                now,
                "English for IT Communication",
            ),
        )
        cur.execute(
            """
            INSERT INTO courses (title, description, category, level, duration_hours, instructor_id, created_at)
            SELECT ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM courses WHERE title = ?)
            """,
            (
                "German for Beginners in Tech",
                "Practical German for study and work in IT environments with cybersecurity vocabulary.",
                "Language",
                "A1-A2",
                20,
                2,
                now,
                "German for Beginners in Tech",
            ),
        )

    existing_courses = cur.execute("SELECT id FROM courses").fetchall()
    for row in existing_courses:
        course_id = row[0]
        cur.execute(
            """
            INSERT INTO course_publish_state (course_id, status, updated_by, updated_at)
            SELECT ?, 'published', 3, ?
            WHERE NOT EXISTS (SELECT 1 FROM course_publish_state WHERE course_id = ?)
            """,
            (course_id, now, course_id),
        )

    apply_full_curriculum(cur, now)
    ensure_minimal_outline(cur, now)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_database()
    print(f"[+] Database initialized at {DB_PATH}")
