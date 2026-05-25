# EduVibe

EduVibe is a small intentionally vulnerable LMS built for the thesis
**"SIEM-Based Web Application Attack Monitoring and Detection"**.

The app is meant for a controlled Wazuh/SIEM lab: users can browse courses, enroll, complete lessons, upload materials, leave reviews, and trigger realistic security events while doing so.

## Warning

This is not a production app. Several vulnerabilities are intentionally left in place so the SIEM pipeline has something useful to detect.

## Stack

- Python 3
- Flask
- SQLite
- HTML/CSS + minimal JS

## Run

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Initialize the database:

```bash
python3 database/init_db.py
```

4. Start the app:

```bash
python3 app.py
```

If port `5000` is unavailable (for example, occupied by another system service), start the app on `5001`:

```bash
python3 -m flask --app app run --host 127.0.0.1 --port 5001 --no-debugger --no-reload
```

5. Open `http://127.0.0.1:5000` in the browser.

If you used the fallback command, open `http://127.0.0.1:5001`.

## Default Accounts

- student: `alice@student.local / alice123`
- instructor: `bob@instructor.local / bob123`
- admin: `admin@eduvibe.local / admin123`

Note: login uses **email + password**.

## Logs

Application events are written to `logs/app.log`.

The SIEM events include timestamp, event type, and request context:
- ip
- user
- method
- path
- user-agent

## LMS Features

The main platform flow includes:

- Progress tracking per lesson with `% completed` and continue-learning flow
- Ratings and reviews with newest/top-rated sorting
- Wishlist/favorites from catalog, course detail, and dashboard
- DB-backed curriculum shown on learning pages
- Instructor/admin curriculum builder in `/admin` (add sections/lessons, publish/draft state)
- Notifications, password change, account states, course/user archive, quiz attempts, and admin filters
- SIEM-facing helper pages: `/audit-timeline` and `/detection-status`

## Attack simulation

The thesis lab uses the automated script **`attack_simulation.sh`**, which runs scenarios **A1–A10** (plus **A1+** account lockout) against a running EduVibe instance and writes events to `logs/app.log` for Wazuh.

1. Start the app (see **Run** above).
2. Run the simulation:

```bash
chmod +x attack_simulation.sh
TARGET=http://127.0.0.1:5001 DELAY=2 ./attack_simulation.sh
```

Set `TARGET` to your app URL. Default script target is `http://172.20.10.2` if unset.

**Requires:** fresh DB from `python3 database/init_db.py` (seeded alice, admin, bob, course id `1`).

**Side effect:** step **A1+** locks `bob@instructor.local` until an admin unlocks the account in the admin UI.

**Details:** `ATTACK_SCENARIOS.md` has two parts — **Part I** (what the script runs) and **Part II** (other implemented A1–A10 vulnerabilities in the app, not exercised by the script). Table 4 in the thesis covers the full scope. Source code uses `(A1)`–`(A10)` tags; `[sim]` marks paths hit by the script.

After running:

```bash
tail -f logs/app.log
```