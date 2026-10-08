"""
College Event Management System
-------------------------------
A small Flask + SQLite application for managing college events.

Run it with:   python app.py
Then open:     http://127.0.0.1:5000

Sections in this file
  1. Configuration
  2. Database helpers + init_db()
  3. Small helper functions
  4. Template filters / context
  5. Login + admin protection (decorators)
  6. Routes: public pages, auth, dashboard, events, admin, feedback
  7. Error pages
"""

import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "database.db"))


def load_secret_key():
    """Return the session signing key without keeping a secret in the source code.

    Use the SECRET_KEY environment variable in production. For local development
    a random key is generated once and saved in instance/secret_key.
    """
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, "instance", "secret_key")
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                saved = handle.read().strip()
            if saved:
                return saved
        saved = secrets.token_hex(32)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(saved)
        return saved
    except OSError:
        return secrets.token_hex(32)  # sessions simply reset when the app restarts


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",  # basic protection against cross-site requests
    # Set SESSION_COOKIE_SECURE=1 when the site is served over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1024 * 1024,  # forms are tiny; refuse huge uploads
)

ROLES = ("admin", "student")

CATEGORIES = ["Technical", "Cultural", "Sports", "Workshop",
              "Seminar", "Competition", "Other"]

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Checked when an unknown email is used to log in, so timing does not reveal valid emails.
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(8))

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# 2. Database helpers
# ---------------------------------------------------------------------------
def get_db_connection():
    """Open a connection to database.db. Rows can be used like dictionaries."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def query(sql, params=(), one=False):
    """Run a SELECT and return all rows (or a single row when one=True).

    Always pass user input through `params` (the ? placeholders) and never
    build the SQL string yourself. That is what prevents SQL injection.
    """
    conn = get_db_connection()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    if one:
        return rows[0] if rows else None
    return rows


def scalar(sql, params=()):
    """Return the first column of the first row (handy for COUNT queries)."""
    row = query(sql, params, one=True)
    return row[0] if row else None


def execute(sql, params=()):
    """Run INSERT / UPDATE / DELETE, save it, and return the rows affected."""
    conn = get_db_connection()
    try:
        with conn:  # commits on success, rolls back on error
            return conn.execute(sql, params).rowcount
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    venue TEXT NOT NULL,
    organizer TEXT NOT NULL,
    category TEXT NOT NULL,
    capacity INTEGER DEFAULT 100,
    image TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(event_id) REFERENCES events(id),
    UNIQUE(user_id, event_id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_registrations_event ON registrations(event_id);
CREATE INDEX IF NOT EXISTS idx_feedback_event ON feedback(event_id);
"""


def column_names(conn, table):
    """Column names of one of our own tables (the name is never user input)."""
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def migrate_db(conn):
    """Safely upgrade an existing database.db: only ADDS missing columns, never deletes data."""
    with conn:
        if "updated_at" not in column_names(conn, "events"):
            conn.execute("ALTER TABLE events ADD COLUMN updated_at TIMESTAMP")
        if "created_at" not in column_names(conn, "users"):
            # Older accounts have no recorded sign-up date; they stay NULL (shown as a dash).
            conn.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP")
        conn.execute("UPDATE users SET role = 'student' WHERE role IS NULL")


def init_db():
    """Create database.db and its tables, then add sample data if it is empty."""
    conn = get_db_connection()
    try:
        conn.executescript(SCHEMA)
        migrate_db(conn)
        seed_sample_data(conn)
    finally:
        conn.close()


def seed_sample_data(conn):
    """Insert the admin account, demo students, sample events and activity.

    Only runs when the users table is empty, so it never overwrites real data.
    Event dates are relative to today, so the sample events always look current.
    """
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return

    today = date.today()

    def day(offset):
        return (today + timedelta(days=offset)).isoformat()

    def stamp(days_ago, hour=11):
        moment = datetime.combine(today - timedelta(days=days_ago), datetime.min.time())
        return (moment + timedelta(hours=hour)).strftime("%Y-%m-%d %H:%M:%S")

    with conn:
        # --- Users (passwords are hashed, never stored as plain text) -------
        # Development accounts. Override the admin login with the ADMIN_EMAIL and
        # ADMIN_PASSWORD environment variables before the first run.
        people = [
            ("Administrator", os.environ.get("ADMIN_EMAIL", "admin@college.com"),
             os.environ.get("ADMIN_PASSWORD", "admin123"), "admin", 30),
            ("Rahul Sharma", "rahul@student.college.com", "student123", "student", 20),
            ("Priya Patil", "priya@student.college.com", "student123", "student", 18),
            ("Ananya Rao", "ananya@student.college.com", "student123", "student", 15),
        ]
        users = {}
        for name, email, password, role, days_ago in people:
            cur = conn.execute(
                "INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, generate_password_hash(password), role, stamp(days_ago)))
            users[email.split("@")[0]] = cur.lastrowid

        # --- Events -----------------------------------------------------------
        sample_events = [
            ("Tech Fest 2026",
             "A full day of hackathon sprints, project demos and talks from engineers "
             "working in the industry. Bring a laptop and a team of up to four.",
             day(9), "10:00", "Computer Lab", "Computer Department", "Technical", 150),
            ("Cultural Fest",
             "An evening of music, dance, theatre and food stalls run entirely by "
             "students. Performances begin at 5 PM sharp; gates open an hour earlier.",
             day(17), "17:00", "College Auditorium", "Cultural Committee", "Cultural", 400),
            ("Sports Day",
             "Track and field, relay races, tug of war and inter-department football. "
             "Wear your department colours and arrive early for the opening march-past.",
             day(24), "08:30", "College Ground", "Sports Department", "Sports", 250),
            ("AI Workshop",
             "A hands-on introduction to machine learning. You will train and evaluate "
             "your first model in Python. No prior experience is needed.",
             day(-6), "14:00", "Seminar Hall", "AI Department", "Workshop", 60),
            ("Career Guidance Seminar",
             "Alumni from product companies, startups and research labs discuss how to "
             "plan internships, build a portfolio and prepare for interviews.",
             day(13), "11:30", "Main Conference Room", "Training & Placement Cell", "Seminar", 120),
            ("Robotics Build Session",
             "Assemble and program a line-following robot in small groups. Seats are "
             "very limited because we build on shared kits.",
             day(5), "15:00", "Innovation Lab", "Robotics Club", "Workshop", 3),
            ("Inter-College Quiz",
             "Teams of three compete across science, technology, history and current "
             "affairs, ending with a rapid-fire buzzer round.",
             day(-18), "13:00", "Library Hall", "Literary Society", "Competition", 90),
            ("24-Hour Hackathon",
             "Build something useful for campus life in a single day and night. "
             "Mentors from the faculty will be on hand throughout.",
             day(33), "09:00", "Engineering Block", "Coding Club", "Competition", 200),
        ]
        events = {}
        for title, desc, ev_date, ev_time, venue, organizer, category, capacity in sample_events:
            cur = conn.execute(
                """INSERT INTO events (title, description, date, time, venue, organizer,
                                       category, capacity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (title, desc, ev_date, ev_time, venue, organizer, category, capacity))
            events[title] = cur.lastrowid

        # --- Registrations (Robotics Build Session is intentionally full) -----
        sample_registrations = [
            ("rahul", "AI Workshop", 12), ("priya", "AI Workshop", 11),
            ("ananya", "AI Workshop", 10),
            ("rahul", "Inter-College Quiz", 25), ("priya", "Inter-College Quiz", 24),
            ("rahul", "Robotics Build Session", 4), ("priya", "Robotics Build Session", 3),
            ("ananya", "Robotics Build Session", 2),
            ("rahul", "Tech Fest 2026", 2), ("ananya", "Tech Fest 2026", 1),
            ("priya", "Cultural Fest", 1),
        ]
        for user_key, title, days_ago in sample_registrations:
            conn.execute(
                "INSERT INTO registrations (user_id, event_id, registered_at) VALUES (?, ?, ?)",
                (users[user_key], events[title], stamp(days_ago)))

        # --- Feedback ---------------------------------------------------------
        sample_feedback = [
            ("rahul", "AI Workshop", 5, "Excellent workshop and very informative.", 5),
            ("priya", "AI Workshop", 4,
             "Great hands-on sessions. I would have liked a longer Q&A at the end.", 5),
            ("ananya", "AI Workshop", 5,
             "Clear explanations and well paced. Looking forward to the next one.", 4),
            ("rahul", "Inter-College Quiz", 4,
             "Tough questions and a well-run event. The buzzer round was the highlight.", 16),
        ]
        for user_key, title, rating, comment, days_ago in sample_feedback:
            conn.execute(
                """INSERT INTO feedback (user_id, event_id, rating, comment, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (users[user_key], events[title], rating, comment, stamp(days_ago, 16)))


# ---------------------------------------------------------------------------
# 3. Small helper functions
# ---------------------------------------------------------------------------
def now_string():
    """Current local time in the same format used to compare event dates."""
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def is_past(event_date, event_time):
    """True once an event's start time has passed (ISO strings compare correctly)."""
    return f"{event_date} {event_time}" < now_string()


def decorate_event(row):
    """Turn a database row into a dict with seat counts, status and a past/upcoming flag."""
    event = dict(row)
    capacity = event["capacity"] or 0
    event["available"] = max(capacity - event["registered_count"], 0)
    event["is_full"] = event["available"] == 0
    event["is_past"] = is_past(event["date"], event["time"])
    event["percent_filled"] = (min(100, round(event["registered_count"] * 100 / capacity))
                               if capacity else 100)
    # Status shown to admins: Completed once its day is over, Ongoing during its day
    # after the start time, otherwise Upcoming.
    if event["date"] < date.today().isoformat():
        event["status"] = "Completed"
    elif event["is_past"]:
        event["status"] = "Ongoing"
    else:
        event["status"] = "Upcoming"
    return event


def like_pattern(text):
    """Build a safe LIKE pattern: % and _ typed by the user are matched literally."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


EVENT_SQL = """
    SELECT e.*,
           (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS registered_count
    FROM events e
"""


def get_all_events():
    """Every event, soonest first, with seat information."""
    rows = query(EVENT_SQL + " ORDER BY e.date ASC, e.time ASC")
    return [decorate_event(row) for row in rows]


def get_event(event_id):
    """One event (as a dict) or None."""
    row = query(EVENT_SQL + " WHERE e.id = ?", (event_id,), one=True)
    return decorate_event(row) if row else None


def split_events(events):
    """Return (upcoming soonest-first, past most-recent-first)."""
    upcoming = [e for e in events if not e["is_past"]]
    past = [e for e in events if e["is_past"]][::-1]
    return upcoming, past


def get_registered_ids(user_id):
    """Set of event ids the given user has registered for."""
    if not user_id:
        return set()
    rows = query("SELECT event_id FROM registrations WHERE user_id = ?", (user_id,))
    return {row["event_id"] for row in rows}


def safe_next(target):
    """Only allow redirects to pages inside this site (prevents open redirects)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def validate_event_form(form, min_capacity=1):
    """Check the add/edit event form. Returns (cleaned_data, errors)."""
    fields = ["title", "description", "date", "time", "venue",
              "organizer", "category", "capacity", "image"]
    data = {name: form.get(name, "").strip() for name in fields}
    errors = {}

    if not data["title"]:
        errors["title"] = "Event title is required."
    elif len(data["title"]) > 120:
        errors["title"] = "Title must be 120 characters or fewer."

    if not data["description"]:
        errors["description"] = "Description is required."
    elif len(data["description"]) > 2000:
        errors["description"] = "Description must be 2000 characters or fewer."

    try:
        datetime.strptime(data["date"], "%Y-%m-%d")
    except ValueError:
        errors["date"] = "Choose a valid date."

    try:
        # Browsers send HH:MM, some also add seconds. Store HH:MM.
        parsed = None
        for pattern in ("%H:%M", "%H:%M:%S"):
            try:
                parsed = datetime.strptime(data["time"], pattern)
                break
            except ValueError:
                continue
        if parsed is None:
            raise ValueError
        data["time"] = parsed.strftime("%H:%M")
    except ValueError:
        errors["time"] = "Choose a valid time."

    for name, label in (("venue", "Venue"), ("organizer", "Organizer")):
        if not data[name]:
            errors[name] = f"{label} is required."
        elif len(data[name]) > 100:
            errors[name] = f"{label} must be 100 characters or fewer."

    if data["category"] not in CATEGORIES:
        errors["category"] = "Choose a category from the list."

    try:
        capacity = int(data["capacity"])
        if capacity < min_capacity:
            errors["capacity"] = (
                "Capacity must be at least 1." if min_capacity <= 1 else
                f"Capacity cannot be lower than the {min_capacity} students already registered.")
        elif capacity > 100000:
            errors["capacity"] = "Capacity is too large."
        data["capacity"] = capacity
    except ValueError:
        errors["capacity"] = "Capacity must be a whole number."

    if data["image"] and not re.match(r"^(https?://|/static/)\S+$", data["image"]):
        errors["image"] = "Use a link that starts with http:// or https://."

    return data, errors


# ---------------------------------------------------------------------------
# 4. Template filters and values available in every template
# ---------------------------------------------------------------------------
def _parse_date(value):
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d")
    except ValueError:
        return None


@app.template_filter("fdate")
def format_date(value):
    """2026-10-10 -> 10 Oct 2026"""
    if not value:
        return "\u2014"
    parsed = _parse_date(value)
    return f"{parsed.day} {parsed.strftime('%b %Y')}" if parsed else value


@app.template_filter("fdate_long")
def format_date_long(value):
    """2026-10-10 -> Saturday, 10 October 2026"""
    parsed = _parse_date(value)
    return f"{parsed.strftime('%A')}, {parsed.day} {parsed.strftime('%B %Y')}" if parsed else value


@app.template_filter("day")
def format_day(value):
    parsed = _parse_date(value)
    return parsed.day if parsed else ""


@app.template_filter("month")
def format_month(value):
    parsed = _parse_date(value)
    return parsed.strftime("%b").upper() if parsed else ""


@app.template_filter("ftime")
def format_time(value):
    """14:30 -> 2:30 PM"""
    try:
        return datetime.strptime(str(value)[:5], "%H:%M").strftime("%I:%M %p").lstrip("0")
    except ValueError:
        return value


@app.template_global()
def icon(name):
    """Draw an icon from the SVG sprite defined in base.html."""
    return Markup(f'<svg class="icon" aria-hidden="true" focusable="false">'
                  f'<use href="#i-{name}"></use></svg>')


@app.template_global()
def csrf_token():
    """A per-session token that every POST form must send back."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user"), "categories": CATEGORIES,
            "current_year": date.today().year}


@app.before_request
def load_current_user():
    """Look the logged-in user up in the database on every request.

    The session cookie only carries the user id. The name and the ROLE always
    come from the database, so a role can never be supplied or changed by the
    browser, and a deleted or demoted account loses access immediately.
    """
    g.user = None
    if request.endpoint == "static":
        return
    user_id = session.get("user_id")
    if user_id is None:
        return
    row = None
    if isinstance(user_id, int):
        row = query("SELECT id, name, role FROM users WHERE id = ?", (user_id,), one=True)
    if row is None:  # stale or forged session
        session.clear()
        return
    role = row["role"] if row["role"] in ROLES else "student"
    g.user = {"id": row["id"], "name": row["name"], "role": role}


@app.before_request
def check_csrf_token():
    """Reject state-changing requests that did not come from one of our own forms."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            abort(400)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Admin pages must not be shown again from the browser cache after logout.
    if request.path.startswith("/admin") or request.endpoint == "dashboard":
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# 5. Login and admin protection
# ---------------------------------------------------------------------------
def login_required(view):
    """Send visitors who are not logged in to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please login first.", "warning")
            next_page = request.full_path.rstrip("?") if request.method == "GET" else None
            return redirect(url_for("login", next=next_page))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Allow only admins. Anyone else gets a 403 Access Denied page.

    The role comes from the database (see load_current_user), never from the
    browser, so hiding a button in HTML is not the only protection.
    """
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def student_required(view):
    """Allow only students (admins cannot register for events or leave feedback)."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "student":
            flash("Only student accounts can do that.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# 6a. Public pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    upcoming, _ = split_events(get_all_events())

    stats = {
        "events": scalar("SELECT COUNT(*) FROM events"),
        "students": scalar("SELECT COUNT(DISTINCT user_id) FROM registrations"),
        "upcoming": len(upcoming),
        "activities": scalar("SELECT COUNT(*) FROM registrations"),
    }
    category_counts = {name: 0 for name in CATEGORIES}
    for event in upcoming:
        if event["category"] in category_counts:
            category_counts[event["category"]] += 1

    return render_template(
        "index.html",
        featured=upcoming[:6],
        next_event=upcoming[0] if upcoming else None,
        stats=stats,
        category_counts=category_counts,
        registered_ids=get_registered_ids(session.get("user_id")))


# ---------------------------------------------------------------------------
# 6b. Authentication
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    form, errors = {}, {}
    if request.method == "POST":
        form = {
            "name": request.form.get("name", "").strip(),
            "email": request.form.get("email", "").strip().lower(),
        }
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not form["name"]:
            errors["name"] = "Full name is required."
        elif len(form["name"]) > 80:
            errors["name"] = "Name must be 80 characters or fewer."

        if not form["email"]:
            errors["email"] = "Email is required."
        elif not EMAIL_PATTERN.match(form["email"]):
            errors["email"] = "Enter a valid email address."
        elif query("SELECT id FROM users WHERE email = ?", (form["email"],), one=True):
            errors["email"] = "An account with this email already exists."

        if len(password) < 6:
            errors["password"] = "Password must be at least 6 characters."
        if confirm != password:
            errors["confirm_password"] = "Passwords do not match."

        if not errors:
            try:
                execute(
                    """INSERT INTO users (name, email, password, role, created_at)
                       VALUES (?, ?, ?, 'student', CURRENT_TIMESTAMP)""",
                    (form["name"], form["email"], generate_password_hash(password)))
            except sqlite3.IntegrityError:  # someone registered the same email just now
                errors["email"] = "An account with this email already exists."
            else:
                flash("Account created successfully. You can log in now.", "success")
                return redirect(url_for("login"))

    return render_template("register.html", form=form, errors=errors)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    form = {"next": safe_next(request.values.get("next")) or ""}
    errors = {}
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        form["email"] = email

        user = query("SELECT id, password, role FROM users WHERE email = ?", (email,), one=True)
        # Always run one hash check so an unknown email takes as long as a wrong password.
        password_ok = check_password_hash(user["password"] if user else DUMMY_PASSWORD_HASH, password)
        if user is None or not password_ok:
            flash("Invalid email or password.", "error")
            errors["form"] = True
        else:
            session.clear()  # start a fresh session after login
            session["user_id"] = user["id"]  # the role is always read from the database
            session.permanent = True
            flash("Login successful.", "success")
            destination = form["next"]
            if user["role"] == "admin":
                return redirect(destination or url_for("admin_dashboard"))
            if destination.startswith("/admin"):  # students are never sent to admin pages
                destination = ""
            return redirect(destination or url_for("dashboard"))

    return render_template("login.html", form=form, errors=errors)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 6c. Dashboards
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return student_dashboard()


def student_dashboard():
    user_id = session["user_id"]
    upcoming, _ = split_events(get_all_events())
    registered_ids = get_registered_ids(user_id)

    my_events = [dict(row) for row in query(
        """SELECT e.id, e.title, e.date, e.time, e.venue, e.category, r.registered_at
           FROM registrations r JOIN events e ON e.id = r.event_id
           WHERE r.user_id = ? ORDER BY e.date ASC, e.time ASC""", (user_id,))]
    for event in my_events:
        event["is_past"] = is_past(event["date"], event["time"])

    stats = {
        "upcoming": len(upcoming),
        "registered": len(my_events),
        "available": len([e for e in upcoming
                          if not e["is_full"] and e["id"] not in registered_ids]),
        "feedback": scalar("SELECT COUNT(*) FROM feedback WHERE user_id = ?", (user_id,)),
    }
    return render_template("dashboard.html", role="student", stats=stats,
                           upcoming=upcoming[:3], my_events=my_events,
                           registered_ids=registered_ids)


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    # Every number is counted from the database each time the page loads.
    stats = {
        "events": scalar("SELECT COUNT(*) FROM events"),
        "upcoming": scalar("SELECT COUNT(*) FROM events WHERE (date || ' ' || time) >= ?",
                           (now_string(),)),
        "students": scalar("SELECT COUNT(*) FROM users WHERE role = 'student'"),
        "registrations": scalar("SELECT COUNT(*) FROM registrations"),
        "feedback": scalar("SELECT COUNT(*) FROM feedback"),
    }
    upcoming, _ = split_events(get_all_events())
    recent = query(
        """SELECT u.name AS student_name, e.id AS event_id, e.title, r.registered_at
           FROM registrations r
           JOIN users u ON u.id = r.user_id
           JOIN events e ON e.id = r.event_id
           ORDER BY r.registered_at DESC, r.id DESC LIMIT 6""")
    return render_template("admin_dashboard.html", stats=stats,
                           upcoming=upcoming[:5], recent=recent)


# ---------------------------------------------------------------------------
# 6d. Events (public list + details + student registration)
# ---------------------------------------------------------------------------
@app.route("/events")
def events():
    search = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    chosen_date = request.args.get("date", "").strip()

    def matches(event):
        """Server-side filtering (script.js also filters live while typing)."""
        if search:
            haystack = " ".join([event["title"], event["description"],
                                 event["venue"], event["organizer"]]).lower()
            if search.lower() not in haystack:
                return False
        if category and event["category"] != category:
            return False
        if chosen_date and event["date"] != chosen_date:
            return False
        return True

    upcoming, past = split_events(get_all_events())
    return render_template(
        "events.html",
        upcoming=[e for e in upcoming if matches(e)],
        past=[e for e in past if matches(e)],
        filters={"q": search, "category": category, "date": chosen_date},
        registered_ids=get_registered_ids(session.get("user_id")))


@app.route("/event/<int:event_id>")
def event_detail(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)

    user_id = session.get("user_id")
    rating = query(
        "SELECT ROUND(AVG(rating), 1) AS average, COUNT(*) AS total FROM feedback WHERE event_id = ?",
        (event_id,), one=True)
    return render_template(
        "events.html", event=event,
        is_registered=event_id in get_registered_ids(user_id),
        rating=rating if rating["total"] else None)


@app.route("/register-event/<int:event_id>", methods=["POST"])
@login_required
def register_event(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)

    destination = safe_next(request.form.get("next")) or url_for("event_detail", event_id=event_id)

    if g.user["role"] != "student":
        flash("Only students can register for events.", "error")
    elif event["is_past"]:
        flash("This event has already taken place.", "error")
    elif event_id in get_registered_ids(g.user["id"]):
        flash("You are already registered for this event.", "info")
    else:
        try:
            # One statement checks the capacity and inserts, so two students
            # clicking at the same moment cannot take the last seat together.
            # The UNIQUE(user_id, event_id) constraint blocks duplicates in the database.
            added = execute(
                """INSERT INTO registrations (user_id, event_id)
                   SELECT ?, ?
                   WHERE (SELECT COUNT(*) FROM registrations WHERE event_id = ?)
                         < (SELECT capacity FROM events WHERE id = ?)""",
                (g.user["id"], event_id, event_id, event_id))
        except sqlite3.IntegrityError:
            flash("You are already registered for this event.", "info")
        else:
            if added:
                flash(f"Event registration successful. You are registered for {event['title']}.",
                      "success")
            else:
                flash("Event is full.", "error")
    return redirect(destination)


@app.route("/cancel-registration/<int:event_id>", methods=["POST"])
@student_required
def cancel_registration(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)
    if event["is_past"]:
        flash("You cannot cancel a registration for a past event.", "error")
    elif execute("DELETE FROM registrations WHERE user_id = ? AND event_id = ?",
                 (session["user_id"], event_id)):
        flash(f"Your registration for {event['title']} has been cancelled.", "info")
    return redirect(safe_next(request.form.get("next")) or url_for("dashboard"))


# ---------------------------------------------------------------------------
# 6e. Admin: events CRUD, registrations, feedback and users.
#     Every route in this section is protected by @admin_required, so the
#     server rejects students and visitors even if they type the URL by hand.
# ---------------------------------------------------------------------------
ADMIN_PAGE_SIZE = 10


def paginate(total, page, size=ADMIN_PAGE_SIZE):
    """Return (page, total_pages, offset) with the page number kept in range."""
    pages = max(-(-total // size), 1)
    page = min(max(page, 1), pages)
    return page, pages, (page - 1) * size


# Old URLs keep working: they forward (307 keeps the method and form data) to the new ones.
@app.route("/add-event", methods=["GET", "POST"])
def legacy_add_event():
    return redirect(url_for("add_event"), 307)


@app.route("/edit-event/<int:event_id>", methods=["GET", "POST"])
def legacy_edit_event(event_id):
    return redirect(url_for("edit_event", event_id=event_id), 307)


@app.route("/delete-event/<int:event_id>", methods=["POST"])
def legacy_delete_event(event_id):
    return redirect(url_for("delete_event", event_id=event_id), 307)


@app.route("/admin/events/add", methods=["GET", "POST"])
@admin_required
def add_event():
    form, errors = {"category": "", "capacity": 100}, {}
    if request.method == "POST":
        form, errors = validate_event_form(request.form)
        if not errors:
            execute(
                """INSERT INTO events (title, description, date, time, venue, organizer,
                                       category, capacity, image)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (form["title"], form["description"], form["date"], form["time"],
                 form["venue"], form["organizer"], form["category"], form["capacity"],
                 form["image"] or None))
            flash("Event created successfully.", "success")
            return redirect(url_for("admin_events"))
    return render_template("add_event.html", form=form, errors=errors, editing=False)


@app.route("/admin/events/edit/<int:event_id>", methods=["GET", "POST"])
@admin_required
def edit_event(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)

    form, errors = event, {}
    if request.method == "POST":
        form, errors = validate_event_form(request.form, min_capacity=event["registered_count"])
        if not errors:
            # Updates the existing row by id (never inserts a duplicate). The last
            # condition re-checks that the new capacity still covers every registration.
            changed = execute(
                """UPDATE events SET title = ?, description = ?, date = ?, time = ?,
                                     venue = ?, organizer = ?, category = ?, capacity = ?,
                                     image = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE id = ?
                     AND ? >= (SELECT COUNT(*) FROM registrations WHERE event_id = ?)""",
                (form["title"], form["description"], form["date"], form["time"],
                 form["venue"], form["organizer"], form["category"], form["capacity"],
                 form["image"] or None, event_id, form["capacity"], event_id))
            if changed:
                flash("Event updated successfully.", "success")
                return redirect(url_for("admin_events"))
            if get_event(event_id) is None:  # deleted while the form was open
                abort(404)
            errors["capacity"] = "Capacity cannot be lower than the number of registered students."
    return render_template("add_event.html", form=form, errors=errors,
                           editing=True, event=event)


@app.route("/admin/events/delete/<int:event_id>", methods=["POST"])
@admin_required
def delete_event(event_id):
    if get_event(event_id) is None:
        abort(404)
    conn = get_db_connection()
    try:
        with conn:  # all three deletes succeed together or not at all
            conn.execute("DELETE FROM feedback WHERE event_id = ?", (event_id,))
            conn.execute("DELETE FROM registrations WHERE event_id = ?", (event_id,))
            conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    finally:
        conn.close()
    flash("Event deleted successfully.", "success")
    return redirect(url_for("admin_events"))


@app.route("/admin/events")
@admin_required
def admin_events():
    """Manage Events: search + filters + paging are all done by the database."""
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()
    when = request.args.get("when", "").strip()
    chosen_date = request.args.get("date", "").strip()
    if category not in CATEGORIES:
        category = ""
    if when not in ("upcoming", "past"):
        when = ""
    try:
        datetime.strptime(chosen_date, "%Y-%m-%d")
    except ValueError:
        chosen_date = ""

    where, params = [], []   # the SQL pieces are fixed text; user input only goes into params
    if q:
        pattern = like_pattern(q)
        where.append("(e.title LIKE ? ESCAPE '\\' OR e.category LIKE ? ESCAPE '\\'"
                     " OR e.venue LIKE ? ESCAPE '\\' OR e.organizer LIKE ? ESCAPE '\\')")
        params += [pattern] * 4
    if category:
        where.append("e.category = ?")
        params.append(category)
    if chosen_date:
        where.append("e.date = ?")
        params.append(chosen_date)
    if when == "upcoming":
        where.append("(e.date || ' ' || e.time) >= ?")
        params.append(now_string())
    elif when == "past":
        where.append("(e.date || ' ' || e.time) < ?")
        params.append(now_string())
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    total = scalar("SELECT COUNT(*) FROM events e" + where_sql, params)
    page, pages, offset = paginate(total, request.args.get("page", 1, type=int))
    direction = "ASC" if when == "upcoming" else "DESC"
    rows = query(EVENT_SQL + where_sql +
                 f" ORDER BY e.date {direction}, e.time {direction}, e.id {direction} LIMIT ? OFFSET ?",
                 params + [ADMIN_PAGE_SIZE, offset])

    filters = {"q": q, "category": category, "when": when, "date": chosen_date}
    return render_template(
        "admin.html", tab="events", events=[decorate_event(row) for row in rows],
        filters=filters, total=total, page=page, pages=pages,
        page_args={key: value for key, value in filters.items() if value})


@app.route("/admin/events/<int:event_id>")
@admin_required
def admin_event_view(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)
    rating = query(
        "SELECT ROUND(AVG(rating), 1) AS average, COUNT(*) AS total FROM feedback WHERE event_id = ?",
        (event_id,), one=True)
    return render_template("admin_event.html", event=event,
                           rating=rating if rating["total"] else None)


@app.route("/admin/events/<int:event_id>/registrations")
@admin_required
def admin_event_registrations(event_id):
    event = get_event(event_id)
    if event is None:
        abort(404)
    rows = query(
        """SELECT r.id, r.registered_at, u.name AS student_name, u.email
           FROM registrations r JOIN users u ON u.id = r.user_id
           WHERE r.event_id = ?
           ORDER BY r.registered_at DESC, r.id DESC""", (event_id,))
    return render_template("admin_event_registrations.html", event=event, rows=rows)


@app.route("/admin/registrations")
@admin_required
def admin_registrations():
    selected = request.args.get("event_id", type=int)
    sql = """SELECT r.id, r.registered_at, u.name AS student_name, u.email,
                    e.id AS event_id, e.title, e.date
             FROM registrations r
             JOIN users u ON u.id = r.user_id
             JOIN events e ON e.id = r.event_id"""
    params = ()
    if selected:
        sql += " WHERE e.id = ?"
        params = (selected,)
    rows = query(sql + " ORDER BY r.registered_at DESC, r.id DESC", params)
    all_events = query("SELECT id, title, date FROM events ORDER BY date DESC")
    return render_template("admin.html", tab="registrations", rows=rows,
                           all_events=all_events, selected=selected)


@app.route("/admin/feedback")
@admin_required
def admin_feedback():
    selected = request.args.get("event_id", type=int)
    where, params = "", ()
    if selected:
        where, params = " WHERE f.event_id = ?", (selected,)
    rows = query(
        """SELECT f.rating, f.comment, f.created_at, u.name AS student_name,
                  e.id AS event_id, e.title
           FROM feedback f
           JOIN users u ON u.id = f.user_id
           JOIN events e ON e.id = f.event_id""" + where +
        " ORDER BY f.created_at DESC, f.id DESC", params)
    average = scalar("SELECT ROUND(AVG(f.rating), 1) FROM feedback f" + where, params)
    all_events = query("SELECT id, title, date FROM events ORDER BY date DESC")
    return render_template("admin.html", tab="feedback", rows=rows, average=average,
                           all_events=all_events, selected=selected)


@app.route("/admin/users")
@admin_required
def admin_users():
    """Name, email, role and sign-up date. The password column is never selected."""
    q = request.args.get("q", "").strip()[:100]
    role = request.args.get("role", "").strip()
    if role not in ROLES:
        role = ""
    where, params = [], []
    if q:
        pattern = like_pattern(q)
        where.append("(u.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\')")
        params += [pattern, pattern]
    if role:
        where.append("u.role = ?")
        params.append(role)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    total = scalar("SELECT COUNT(*) FROM users u" + where_sql, params)
    page, pages, offset = paginate(total, request.args.get("page", 1, type=int))
    rows = query(
        """SELECT u.id, u.name, u.email, u.role, u.created_at,
                  (SELECT COUNT(*) FROM registrations r WHERE r.user_id = u.id) AS registrations
           FROM users u""" + where_sql +
        " ORDER BY (u.role = 'admin') DESC, u.name COLLATE NOCASE ASC LIMIT ? OFFSET ?",
        params + [ADMIN_PAGE_SIZE, offset])
    filters = {"q": q, "role": role}
    return render_template("admin.html", tab="users", rows=rows, filters=filters,
                           total=total, page=page, pages=pages,
                           page_args={key: value for key, value in filters.items() if value})


# ---------------------------------------------------------------------------
# 6f. Student feedback
# ---------------------------------------------------------------------------
@app.route("/feedback")
@login_required
def feedback():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_feedback"))

    user_id = session["user_id"]
    registered = query(
        """SELECT e.id, e.title, e.date,
                  EXISTS(SELECT 1 FROM feedback f
                         WHERE f.user_id = r.user_id AND f.event_id = e.id) AS reviewed
           FROM registrations r JOIN events e ON e.id = r.event_id
           WHERE r.user_id = ? ORDER BY e.date DESC""", (user_id,))
    mine = query(
        """SELECT f.rating, f.comment, f.created_at, e.title
           FROM feedback f JOIN events e ON e.id = f.event_id
           WHERE f.user_id = ? ORDER BY f.created_at DESC, f.id DESC""", (user_id,))
    return render_template("feedback.html", registered=registered, mine=mine,
                           selected=request.args.get("event", type=int))


@app.route("/submit-feedback", methods=["POST"])
@student_required
def submit_feedback():
    user_id = session["user_id"]
    event_id = request.form.get("event_id", type=int)
    rating = request.form.get("rating", type=int)
    comment = request.form.get("comment", "").strip()
    back = url_for("feedback", event=event_id) if event_id else url_for("feedback")

    if not event_id or event_id not in get_registered_ids(user_id):
        flash("Please choose an event you registered for.", "error")
    elif rating is None or not 1 <= rating <= 5:
        flash("Please choose a rating from 1 to 5 stars.", "error")
    elif len(comment) > 500:
        flash("Comments must be 500 characters or fewer.", "error")
    elif query("SELECT id FROM feedback WHERE user_id = ? AND event_id = ?",
               (user_id, event_id), one=True):
        flash("You have already submitted feedback for this event.", "info")
    else:
        execute("INSERT INTO feedback (user_id, event_id, rating, comment) VALUES (?, ?, ?, ?)",
                (user_id, event_id, rating, comment))
        flash("Feedback submitted successfully.", "success")
        back = url_for("feedback")
    return redirect(back)


# ---------------------------------------------------------------------------
# 7. Friendly error pages (visitors never see raw Python errors)
# ---------------------------------------------------------------------------
def error_page(code, title, message):
    return render_template("error.html", code=code, title=title, message=message), code


@app.errorhandler(400)
def bad_request(_error):
    return error_page(400, "Request Expired",
                      "Your session may have timed out. Please go back, refresh the page and try again.")


@app.errorhandler(403)
def forbidden(_error):
    return error_page(403, "Access Denied",
                      "You don't have permission to access this page.")


@app.errorhandler(404)
def not_found(_error):
    return error_page(404, "Page Not Found",
                      "The requested page does not exist.")


@app.errorhandler(405)
def method_not_allowed(_error):
    return error_page(405, "Method Not Allowed",
                      "This page can't be opened that way. Please use the buttons on the site.")


@app.errorhandler(500)
def server_error(error):
    # The details go to the server log only, never to the visitor.
    app.logger.error("Unhandled server error: %s", error, exc_info=error)
    return error_page(500, "Something Went Wrong",
                      "An unexpected error occurred on our side. Please try again in a moment.")


# Create database.db and the tables as soon as the app starts.
init_db()

if __name__ == "__main__":
    # Set FLASK_DEBUG=1 while developing to get automatic reloading.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
