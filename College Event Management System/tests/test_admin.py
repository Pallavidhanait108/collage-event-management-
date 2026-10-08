"""Automated checks for the admin system.

Run with:   python -m unittest tests.test_admin -v

The tests copy database.db to a temporary file first, so your real data is never touched
and the migration is exercised against your existing data.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_tmp = tempfile.mkdtemp()
_db = os.path.join(_tmp, "test.db")
if os.path.exists(os.path.join(ROOT, "database.db")):
    shutil.copy(os.path.join(ROOT, "database.db"), _db)
os.environ["DATABASE_PATH"] = _db
os.environ["SECRET_KEY"] = "test-secret"

import app as app_module  # noqa: E402  (imported after the environment is prepared)

TOKEN = "test-csrf-token"
FUTURE = (date.today() + timedelta(days=20)).isoformat()


def db():
    conn = sqlite3.connect(_db)
    conn.row_factory = sqlite3.Row
    return conn


class Base(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def login(self, email, password, client=None):
        client = client or self.client
        with client.session_transaction() as s:
            s["_csrf"] = TOKEN
        return client.post("/login", data={"email": email, "password": password,
                                           "csrf_token": TOKEN}, follow_redirects=False)

    def as_admin(self):
        self.login("admin@college.com", "admin123")
        return self.client

    def as_student(self, email="rahul@student.college.com"):
        self.login(email, "student123")
        return self.client

    def post(self, url, data=None, client=None):
        client = client or self.client
        with client.session_transaction() as s:
            s["_csrf"] = TOKEN
        payload = dict(data or {})
        payload["csrf_token"] = TOKEN
        return client.post(url, data=payload, follow_redirects=False)

    def event_data(self, **over):
        data = {"title": "Test Event", "description": "A <b>test</b> event.", "date": FUTURE,
                "time": "10:30", "venue": "Lab 9", "organizer": "Tester", "category": "Technical",
                "capacity": "5", "image": ""}
        data.update(over)
        return data

    def make_event(self, **over):
        resp = self.post("/admin/events/add", self.event_data(**over))
        self.assertEqual(resp.status_code, 302, resp.get_data(as_text=True)[:400])
        with db() as conn:
            return conn.execute("SELECT id FROM events ORDER BY id DESC LIMIT 1").fetchone()["id"]


class MigrationTests(Base):
    def test_columns_added_and_data_kept(self):
        with db() as conn:
            event_cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
            user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            self.assertIn("updated_at", event_cols)
            self.assertIn("created_at", user_cols)
            self.assertGreaterEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_passwords_are_hashed(self):
        with db() as conn:
            for row in conn.execute("SELECT password FROM users"):
                self.assertNotIn(row["password"], ("admin123", "student123"))
                self.assertTrue(row["password"].startswith(("scrypt:", "pbkdf2:")))


class AuthTests(Base):
    def test_invalid_login(self):
        resp = self.login("admin@college.com", "wrong")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid email or password.", resp.data)

    def test_admin_login_goes_to_admin_dashboard(self):
        resp = self.login("admin@college.com", "admin123")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/admin/dashboard"))

    def test_student_login_goes_to_student_dashboard(self):
        resp = self.login("rahul@student.college.com", "student123")
        self.assertTrue(resp.headers["Location"].endswith("/dashboard"))
        page = self.client.get("/dashboard")
        self.assertIn(b"Student dashboard", page.data)
        self.assertNotIn(b"Admin panel", page.data)
        self.assertNotIn(b"/admin/", page.data)

    def test_logout_requires_post(self):
        self.as_admin()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.post("/logout").status_code, 302)
        self.assertEqual(self.client.get("/admin/dashboard").status_code, 302)

    def test_post_without_csrf_rejected(self):
        resp = self.client.post("/login", data={"email": "admin@college.com", "password": "admin123"})
        self.assertEqual(resp.status_code, 400)

    def test_non_ascii_csrf_does_not_crash(self):
        with self.client.session_transaction() as s:
            s["_csrf"] = TOKEN
        resp = self.client.post("/login", data={"csrf_token": "caf\u00e9"})
        self.assertEqual(resp.status_code, 400)

    def test_forged_session_is_rejected(self):
        with self.client.session_transaction() as s:
            s["user_id"] = 999999
            s["user_role"] = "admin"
        resp = self.client.get("/admin/dashboard")
        self.assertEqual(resp.status_code, 302)  # sent to login

    def test_role_comes_from_database_not_session(self):
        self.as_student()
        with self.client.session_transaction() as s:
            s["user_role"] = "admin"  # tampering has no effect
        self.assertEqual(self.client.get("/admin/events").status_code, 403)


class AccessControlTests(Base):
    ADMIN_GETS = ["/admin/dashboard", "/admin/events", "/admin/events/add", "/admin/events/edit/1",
                  "/admin/events/1", "/admin/events/1/registrations", "/admin/registrations",
                  "/admin/feedback", "/admin/users"]

    def test_anonymous_redirected_to_login(self):
        for url in self.ADMIN_GETS:
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 302, url)
            self.assertIn("/login", resp.headers["Location"], url)

    def test_student_gets_403(self):
        self.as_student()
        for url in self.ADMIN_GETS:
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 403, url)
            self.assertIn(b"Access Denied", resp.data)

    def test_student_cannot_write(self):
        self.as_student()
        with db() as conn:
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(self.post("/admin/events/add", self.event_data()).status_code, 403)
        self.assertEqual(self.post("/admin/events/edit/1", self.event_data()).status_code, 403)
        self.assertEqual(self.post("/admin/events/delete/1").status_code, 403)
        # old URLs forward to the protected routes
        self.assertEqual(self.post("/delete-event/1").status_code, 307)
        with db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], before)

    def test_delete_via_get_not_allowed(self):
        self.as_admin()
        self.assertEqual(self.client.get("/admin/events/delete/1").status_code, 405)

    def test_admin_pages_render(self):
        self.as_admin()
        for url in self.ADMIN_GETS:
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 200, url)
            self.assertIn(b"Admin panel", resp.data, url)
            self.assertIn(b"no-store", resp.headers["Cache-Control"].encode(), url)

    def test_invalid_ids_404(self):
        self.as_admin()
        for url in ["/admin/events/999999", "/admin/events/edit/999999",
                    "/admin/events/999999/registrations", "/admin/events/abc",
                    "/admin/events/edit/-1", "/event/999999", "/nope"]:
            self.assertEqual(self.client.get(url).status_code, 404, url)
        self.assertEqual(self.post("/admin/events/delete/999999").status_code, 404)


class DashboardTests(Base):
    def test_stats_are_dynamic(self):
        self.as_admin()
        with db() as conn:
            students = conn.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0]
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        page = self.client.get("/admin/dashboard").get_data(as_text=True)
        for label in ("Total Events", "Upcoming Events", "Total Students",
                      "Total Registrations", "Total Feedback"):
            self.assertIn(label, page)
        self.assertIn(f'id="stat-students">{students}<', page)
        self.assertIn(f'id="stat-events">{events}<', page)
        self.make_event(title="Dynamic Stat Event")
        page = self.client.get("/admin/dashboard").get_data(as_text=True)
        self.assertIn(f'id="stat-events">{events + 1}<', page)


class CrudTests(Base):
    def test_full_crud(self):
        self.as_admin()
        event_id = self.make_event(title="CRUD Event", venue="Hall <script>")
        page = self.client.get("/admin/events?q=CRUD").get_data(as_text=True)
        self.assertIn("CRUD Event", page)
        self.assertIn("Event created successfully.", page)
        self.assertNotIn("<script>", page)          # escaped, not rendered
        self.assertIn("&lt;script&gt;", page)

        detail = self.client.get(f"/admin/events/{event_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"CRUD Event", detail.data)

        form = self.client.get(f"/admin/events/edit/{event_id}").get_data(as_text=True)
        self.assertIn('value="CRUD Event"', form)
        self.assertIn('value="Lab 9"' if "Hall" not in form else "Hall", form)

        resp = self.post(f"/admin/events/edit/{event_id}",
                         self.event_data(title="CRUD Event v2", capacity="9"))
        self.assertEqual(resp.status_code, 302)
        with db() as conn:
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            self.assertEqual(row["title"], "CRUD Event v2")
            self.assertEqual(row["capacity"], 9)
            self.assertIsNotNone(row["updated_at"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events WHERE title LIKE 'CRUD Event%'")
                             .fetchone()[0], 1)

        resp = self.post(f"/admin/events/delete/{event_id}")
        self.assertEqual(resp.status_code, 302)
        with db() as conn:
            self.assertIsNone(conn.execute("SELECT id FROM events WHERE id=?", (event_id,)).fetchone())

    def test_flash_messages(self):
        self.as_admin()
        event_id = self.make_event(title="Flash Event")
        self.assertIn(b"Event created successfully.", self.client.get("/admin/events").data)
        self.post(f"/admin/events/edit/{event_id}", self.event_data(title="Flash Event 2"))
        self.assertIn(b"Event updated successfully.", self.client.get("/admin/events").data)
        self.post(f"/admin/events/delete/{event_id}")
        self.assertIn(b"Event deleted successfully.", self.client.get("/admin/events").data)

    def test_validation(self):
        self.as_admin()
        bad = [
            {"title": ""}, {"description": ""}, {"date": "2026-13-45"}, {"date": ""},
            {"time": "25:99"}, {"venue": ""}, {"organizer": ""}, {"category": "Hacking"},
            {"capacity": "0"}, {"capacity": "-3"}, {"capacity": "abc"}, {"capacity": ""},
            {"image": "javascript:alert(1)"}, {"title": "x" * 200},
        ]
        with db() as conn:
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        for override in bad:
            resp = self.post("/admin/events/add", self.event_data(**override))
            self.assertEqual(resp.status_code, 200, override)  # form shown again with errors
            self.assertIn(b"field__error", resp.data)
        with db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], before)

    def test_valid_image_url_accepted(self):
        self.as_admin()
        self.make_event(title="Image Event", image="https://example.com/p.jpg")

    def test_capacity_cannot_drop_below_registrations(self):
        self.as_admin()
        event_id = self.make_event(title="Cap Event", capacity="3")
        with db() as conn:
            conn.executemany("INSERT INTO registrations (user_id, event_id) VALUES (?, ?)",
                             [(2, event_id), (3, event_id)])
            conn.commit()
        resp = self.post(f"/admin/events/edit/{event_id}", self.event_data(capacity="1"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"cannot be lower", resp.data)

    def test_delete_removes_related_rows(self):
        self.as_admin()
        event_id = self.make_event(title="Cascade Event")
        with db() as conn:
            conn.execute("INSERT INTO registrations (user_id, event_id) VALUES (2, ?)", (event_id,))
            conn.execute("INSERT INTO feedback (user_id, event_id, rating, comment) VALUES (2, ?, 5, 'x')",
                         (event_id,))
            conn.commit()
        self.assertEqual(self.post(f"/admin/events/delete/{event_id}").status_code, 302)
        with db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM registrations WHERE event_id=?",
                                          (event_id,)).fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM feedback WHERE event_id=?",
                                          (event_id,)).fetchone()[0], 0)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_legacy_urls_still_work(self):
        self.as_admin()
        self.assertEqual(self.client.get("/add-event").status_code, 307)
        self.assertEqual(self.client.get("/add-event", follow_redirects=True).status_code, 200)
        self.assertEqual(self.client.get("/edit-event/1", follow_redirects=True).status_code, 200)


class SearchFilterTests(Base):
    def test_search_filter(self):
        self.as_admin()
        self.make_event(title="Zebra Quest", venue="Moonbase_1", organizer="Orbit 100%",
                        category="Sports", date=FUTURE)
        get = lambda qs: self.client.get("/admin/events?" + qs).get_data(as_text=True)  # noqa: E731
        self.assertIn("Zebra Quest", get("q=zebra"))
        self.assertIn("Zebra Quest", get("q=moonbase"))
        self.assertIn("Zebra Quest", get("q=orbit"))
        self.assertIn("Zebra Quest", get("q=Sports"))
        self.assertNotIn("Zebra Quest", get("q=nomatchxyz"))
        self.assertNotIn("Zebra Quest", get("q=moonbaseX1"))   # '_' is literal, not a wildcard
        self.assertIn("Zebra Quest", get("category=Sports"))
        self.assertNotIn("Zebra Quest", get("category=Cultural"))
        self.assertIn("Zebra Quest", get(f"date={FUTURE}"))
        self.assertIn("Zebra Quest", get("q=zebra&when=upcoming"))
        self.assertNotIn("Zebra Quest", get("q=zebra&when=past"))
        self.assertEqual(self.client.get("/admin/events?q=%27%20OR%201%3D1--").status_code, 200)
        self.assertEqual(self.client.get("/admin/events?page=9999&date=bad&when=zzz").status_code, 200)


class RegistrationTests(Base):
    def test_capacity_and_duplicates(self):
        admin = app_module.app.test_client()
        self.login("admin@college.com", "admin123", admin)
        self.client = admin
        event_id = self.make_event(title="Tiny Event", capacity="2")

        def register(email):
            c = app_module.app.test_client()
            self.login(email, "student123", c)
            return c, self.post(f"/register-event/{event_id}", client=c)

        c1, r1 = register("rahul@student.college.com")
        self.assertIn(b"Event registration successful", c1.get("/dashboard").data)
        _, dup = register("rahul@student.college.com")
        c1b = app_module.app.test_client()
        self.login("rahul@student.college.com", "student123", c1b)
        self.post(f"/register-event/{event_id}", client=c1b)
        self.assertIn(b"already registered", c1b.get(f"/event/{event_id}").data + c1b.get("/dashboard").data)
        register("priya@student.college.com")

        c3 = app_module.app.test_client()
        self.login("ananya@student.college.com", "student123", c3)
        self.post(f"/register-event/{event_id}", client=c3)
        page = c3.get(f"/event/{event_id}").get_data(as_text=True)
        self.assertIn("Event is full.", page + c3.get("/dashboard").get_data(as_text=True))
        self.assertIn("Event Full", page)
        with db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM registrations WHERE event_id=?",
                                          (event_id,)).fetchone()[0], 2)

        summary = admin.get(f"/admin/events/{event_id}/registrations").get_data(as_text=True)
        self.assertIn('id="seat-capacity">2<', summary)
        self.assertIn('id="seat-registered">2<', summary)
        self.assertIn('id="seat-available">0<', summary)
        self.assertIn("rahul@student.college.com", summary)
        self.assertIn("Full", summary)

    def test_seats_available_text(self):
        self.as_admin()
        event_id = self.make_event(title="Seats Event", capacity="10")
        page = self.client.get(f"/event/{event_id}").get_data(as_text=True)
        self.assertIn("<strong>10</strong> of 10 seats available", page)

    def test_admin_cannot_register(self):
        self.as_admin()
        event_id = self.make_event(title="No Admin Reg")
        self.post(f"/register-event/{event_id}")
        with db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM registrations WHERE event_id=?",
                                          (event_id,)).fetchone()[0], 0)


class FeedbackUsersTests(Base):
    def test_feedback_page_and_filter(self):
        self.as_admin()
        page = self.client.get("/admin/feedback").get_data(as_text=True)
        self.assertIn("Excellent workshop", page)
        with db() as conn:
            ev = conn.execute("SELECT id FROM events WHERE title='Inter-College Quiz'").fetchone()
        if ev:
            filtered = self.client.get(f"/admin/feedback?event_id={ev['id']}").get_data(as_text=True)
            self.assertIn("Tough questions", filtered)
            self.assertNotIn("Excellent workshop", filtered)

    def test_student_feedback_flow(self):
        self.as_student("ananya@student.college.com")
        with db() as conn:
            ev = conn.execute("SELECT id FROM events WHERE title='Robotics Build Session'").fetchone()
        if ev is None:
            self.skipTest("sample event missing")
        resp = self.post("/submit-feedback", {"event_id": ev["id"], "rating": "4", "comment": "<b>nice</b>"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn(b"Feedback submitted successfully.", self.client.get("/feedback").data)
        self.post("/logout")
        self.as_admin()
        page = self.client.get("/admin/feedback").get_data(as_text=True)
        self.assertIn("&lt;b&gt;nice&lt;/b&gt;", page)

    def test_users_page_hides_passwords(self):
        self.as_admin()
        page = self.client.get("/admin/users").get_data(as_text=True)
        self.assertIn("rahul@student.college.com", page)
        self.assertNotIn("scrypt", page)
        self.assertNotIn("pbkdf2", page)
        self.assertNotIn("student123", page)
        self.assertIn("Registration Date", page)
        self.assertIn("rahul@student.college.com", self.client.get("/admin/users?q=rahul").get_data(as_text=True))
        self.assertEqual(self.client.get("/admin/users?role=admin").status_code, 200)


class StudentSiteTests(Base):
    def test_public_pages(self):
        for url in ["/", "/events", "/events?q=tech&category=Technical", "/login", "/register"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)
        self.assertEqual(self.client.get("/static/css/style.css").status_code, 200)
        self.assertEqual(self.client.get("/static/js/script.js").status_code, 200)
        with db() as conn:
            eid = conn.execute("SELECT id FROM events LIMIT 1").fetchone()["id"]
        self.assertEqual(self.client.get(f"/event/{eid}").status_code, 200)

    def test_student_registration_and_login(self):
        with self.client.session_transaction() as s:
            s["_csrf"] = TOKEN
        resp = self.client.post("/register", data={
            "name": "New Student", "email": "new.student@example.com",
            "password": "secret12", "confirm_password": "secret12", "csrf_token": TOKEN})
        self.assertEqual(resp.status_code, 302)
        with db() as conn:
            row = conn.execute("SELECT role, password, created_at FROM users WHERE email=?",
                               ("new.student@example.com",)).fetchone()
        self.assertEqual(row["role"], "student")
        self.assertNotEqual(row["password"], "secret12")
        self.assertIsNotNone(row["created_at"])
        self.login("new.student@example.com", "secret12")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/admin/dashboard").status_code, 403)


if __name__ == "__main__":
    unittest.main()
