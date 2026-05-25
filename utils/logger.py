# Helper to write security events to logs/app.log (used by attack scenarios A1–A10 in routes/).

from flask import current_app, request, session


def log_event(event_name, level="info", **kwargs):
    # Writes one line to logs/app.log with IP, user, method, path, and browser.
    payload = {
        "ip": getattr(request, "remote_addr", "-"),
        "user": session.get("username", "anonymous") if session else "anonymous",
        "method": getattr(request, "method", "-"),
        "path": getattr(request, "path", "-"),
        "ua": request.headers.get("User-Agent", "-") if request else "-",
    }
    payload.update(kwargs)
    getattr(current_app.logger, level)(event_name, extra=payload)
