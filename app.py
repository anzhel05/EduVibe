# EduVibe Flask app.
# Logging: this file sets up logs/app.log. Attack events (A1–A10) are written in routes/*.py via log_event().

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from database.db import close_db_connection, get_db_connection

from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.courses import courses_bp
from routes.profile import profile_bp


class ContextFilter(logging.Filter):
    # Fill in missing ip, user, method, path, ua so every log line has the same fields.
    def filter(self, record):
        for attr in ["ip", "user", "method", "path", "ua"]:
            if not hasattr(record, attr):
                setattr(record, attr, "-")
        return True


def configure_logging(app: Flask) -> None:
    # Write app logs to logs/app.log (Wazuh reads this file in the lab).
    os.makedirs("logs", exist_ok=True)
    log_file = os.path.join("logs", "app.log")

    # One line per event: time, event name, IP, user, method, path, browser.
    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s | %(levelname)s | event=%(message)s | "
            "ip=%(ip)s | user=%(user)s | method=%(method)s | path=%(path)s | ua=%(ua)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())

    app.logger.setLevel(logging.INFO)
    app.logger.handlers.clear()
    app.logger.addHandler(handler)

    # Turn down Flask’s own request logs so app.log stays readable.
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.setLevel(logging.WARNING)
    werkzeug_logger.handlers.clear()


def request_log_extra():
    # Extra fields added to each log line.
    return {
        "ip": request.remote_addr or "-",
        "user": session.get("username", "anonymous"),
        "method": request.method,
        "path": request.path,
        "ua": request.headers.get("User-Agent", "-"),
    }


app = Flask(__name__)

# Use real client IP when the app runs behind a proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

app.config.from_object("config")
configure_logging(app)
app.teardown_appcontext(close_db_connection)
app.register_blueprint(auth_bp)
app.register_blueprint(courses_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(profile_bp)


@app.before_request
def log_request():
    # Log every page hit (normal traffic, not an attack scenario).
    app.logger.info(
        "http_request",
        extra=request_log_extra(),
    )


@app.route("/")
def home():
    app.logger.info(
        "index_access",
        extra=request_log_extra(),
    )
    conn = get_db_connection()
    courses = conn.execute(
        "SELECT id, title, category FROM courses WHERE archived_at IS NULL ORDER BY id DESC LIMIT 6"
    ).fetchall()
    return render_template("index.html", courses=courses)


@app.route("/health")
def health():
    # Used at the start of attack_simulation.sh; writes health_check to the log.
    app.logger.info(
        "health_check",
        extra=request_log_extra(),
    )
    return {"status": "ok", "app": "eduvibe"}, 200


@app.errorhandler(Exception)
def handle_exception(exc):
    # Log unexpected server errors.
    app.logger.error(
        f"exception:{type(exc).__name__}:{str(exc)}",
        extra=request_log_extra(),
    )
    return {"error": "Internal server error", "type": type(exc).__name__}, 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
