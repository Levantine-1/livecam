"""End-to-end checks for livecam's gate, run against Flask's test client.

Deliberately covers the parts where a bug is silent rather than loud: a
permission that fails open, a stream token that works for the wrong user,
the egress counter charging LAN traffic. Both backends are pointed at
unroutable hosts, so nothing here touches ZoneMinder or go2rtc -- every
assertion is about this app's own decisions.

    pip install flask pyyaml requests
    python tests/test_livecam.py
"""

import os
import re
import sqlite3
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

WORK = tempfile.mkdtemp(prefix="livecam-test-")
PERMS = os.path.join(WORK, "permissions.yml")
DB = os.path.join(WORK, "egress.db")

# Both users share one hash so the fixture needs only one known password;
# what differs between them is what they're allowed to see.
PASSWORD = "test-password"
HASH = ("pbkdf2:sha256:600000$Nd1zVBBGvKfXTVBc$"
        "9c02a05b6c3e17e2e5e0c7f0f7b1a3ac1a1d80e5b60a4b8f8e0a0a9f1c2b3d4e")

with open(PERMS, "w") as f:
    f.write(
        "_monitor_id_to_name:\n"
        "  1: guinea-pig-cage-1\n"
        "  2: guinea-pig-cage-2\n"
        "admin:\n"
        f"  password_hash: \"{{HASH}}\"\n"
        "  cameras: [guinea-pig-cage-1, guinea-pig-cage-2]\n"
        "  audio: true\n"
        "guest:\n"
        f"  password_hash: \"{{HASH}}\"\n"
        "  cameras: [guinea-pig-cage-1]\n"
        "  audio: false\n"
        # A window that is already over, so "outside the window" is testable
        # without waiting for a particular time of day.
        "  time_window: {start: \"00:00:00\", end: \"00:00:01\"}\n"
    )

PUB = "livecam.levantine.io"
LAN = "livecam-lan.levantine.io"

os.environ.update(
    ZM_BACKEND_URL="http://zm.invalid",
    GO2RTC_URL="http://go2rtc.invalid:1984",
    PERMISSIONS_FILE=PERMS,
    EGRESS_DB=DB,
    FLASK_SECRET_KEY="test-secret",
    PUBLIC_HOSTNAME=PUB,
    LAN_HOSTNAME=LAN,
)

import livecam  # noqa: E402  (must follow the env setup above)
from werkzeug.security import generate_password_hash  # noqa: E402

# Rewrite the fixture with a hash this werkzeug can actually verify --
# hashes are version-portable in format but not worth hardcoding.
real_hash = generate_password_hash(PASSWORD, method="pbkdf2:sha256:600000")
with open(PERMS) as f:
    body = f.read()
with open(PERMS, "w") as f:
    f.write(body.replace("{HASH}", real_hash))

app = livecam.app
failures = []


def check(name, condition, detail=""):
    print(("PASS  " if condition else "FAIL  ") + name +
          ("" if condition else f"  -> {detail}"))
    if not condition:
        failures.append(name)


def main():
    c = app.test_client()

    # Nothing is reachable logged out -- including ZoneMinder, which is the
    # whole point of putting livecam's login in front of it.
    r = c.get("/", headers={"Host": PUB, "Accept": "text/html"})
    check("/ redirects to login when logged out",
          r.status_code == 302 and "/login" in r.headers["Location"], r.status_code)
    r = c.get("/zm/index.php", headers={"Host": PUB, "Accept": "text/html"})
    check("ZoneMinder is not reachable without a livecam session",
          r.status_code == 302 and "/login" in r.headers["Location"], r.status_code)
    # A <video> element must get a status, not a login page it would try to
    # decode as video.
    r = c.get("/live/guinea-pig-cage-1?token=x", headers={"Host": PUB})
    check("/live 401s rather than redirecting", r.status_code == 401, r.status_code)

    r = c.post("/login", data={"username": "admin", "password": "wrong"},
               headers={"Host": PUB})
    check("wrong password refused", r.status_code == 401 and b"Incorrect" in r.data,
          r.status_code)
    r = c.get("/", headers={"Host": PUB, "Accept": "text/html"})
    check("still logged out after a failed login", r.status_code == 302, r.status_code)

    r = c.post("/login",
               data={"username": "admin", "password": PASSWORD, "next": "//evil.example/x"},
               headers={"Host": PUB})
    check("off-site ?next= is not honoured", r.headers.get("Location") == "/",
          r.headers.get("Location"))

    r = c.get("/", headers={"Host": PUB})
    page = r.get_data(as_text=True)
    check("dashboard renders once logged in", r.status_code == 200, r.status_code)
    check("admin sees both cameras",
          page.count('data-camera="guinea-pig-cage-') == 4,
          page.count('data-camera='))
    check("home banner shown on the public hostname",
          'id="homeBanner"' in page and LAN in page)
    check("usage meter rendered", 'id="usage"' in page)
    token = re.search(r'const TOKEN = "([^"]+)"', page).group(1)

    r = c.get("/", headers={"Host": LAN})
    check("home banner absent on the LAN hostname",
          'id="homeBanner"' not in r.get_data(as_text=True))

    perms = livecam.load_permissions()
    allowed, audio = livecam.check_permission("admin", perms)
    check("admin: both cameras, audio on",
          allowed == {"guinea-pig-cage-1", "guinea-pig-cage-2"} and audio, (allowed, audio))
    allowed, audio = livecam.check_permission("guest", perms)
    check("guest outside their time window gets nothing",
          allowed == set() and not audio, (allowed, audio))
    check("`_`-prefixed metadata is not treated as a user",
          livecam.check_permission("_monitor_id_to_name", perms)[0] == set())
    check("unknown user gets nothing",
          livecam.check_permission("nobody", perms)[0] == set())

    # Audio gating is enforced by which go2rtc stream gets requested, so
    # these three mappings are the enforcement.
    check("tiles take the audio-free substream",
          livecam.resolve_stream_name("cam", True, "sub") == "cam_sub_noaudio")
    check("full quality with audio permission",
          livecam.resolve_stream_name("cam", True, "full") == "cam")
    check("full quality without audio permission drops the track",
          livecam.resolve_stream_name("cam", False, "full") == "cam_noaudio")

    r = c.get(f"/live/guinea-pig-cage-9?token={token}", headers={"Host": PUB})
    check("a camera not on the user's list is refused", r.status_code == 403, r.status_code)

    other = app.test_client()
    other.post("/login", data={"username": "guest", "password": PASSWORD},
               headers={"Host": PUB})
    r = other.get(f"/live/guinea-pig-cage-1?token={token}", headers={"Host": PUB})
    check("a stream token is useless to another account", r.status_code == 403, r.status_code)

    r = c.post("/api/heartbeat", json={"token": token}, headers={"Host": PUB})
    check("heartbeat accepted for one's own token", r.status_code == 200, r.status_code)
    r = app.test_client().post("/api/heartbeat", json={"token": token},
                               headers={"Host": PUB})
    check("heartbeat rejected when logged out", r.status_code == 401, r.status_code)

    # YAML gives integer keys while the query string gives strings; the
    # mismatch made every recorded clip fall through to the raw id and be
    # refused, which failing closed hid.
    ids = {str(k): v for k, v in perms["_monitor_id_to_name"].items()}
    check("numeric monitor ids map to camera names",
          ids.get("1") == "guinea-pig-cage-1", ids)

    livecam.record_egress(0, flush=True)
    before = livecam.egress_this_month()
    livecam.record_egress(5_000_000)
    livecam.record_egress(0, flush=True)
    after = livecam.egress_this_month()
    check("egress counter records bytes", after - before == 5_000_000, (before, after))

    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT month, bytes FROM egress").fetchall()
    conn.close()
    check("persisted to sqlite under a YYYY-MM key",
          len(rows) == 1 and re.fullmatch(r"\d{4}-\d{2}", rows[0][0])
          and rows[0][1] >= 5_000_000, rows)

    # Month rollover is arithmetic, so an old row must simply stop counting.
    conn = sqlite3.connect(DB)
    conn.execute("INSERT INTO egress (month, bytes) VALUES ('1999-01', 99999999999)")
    conn.commit()
    conn.close()
    check("a previous month's row is not counted as this month",
          livecam.egress_this_month() == after, livecam.egress_this_month())

    with app.test_request_context("/", headers={"Host": PUB}):
        public = livecam.is_public_request()
    with app.test_request_context("/", headers={"Host": LAN}):
        lan = livecam.is_public_request()
    check("public hostname is metered and the LAN hostname is not",
          public and not lan, (public, lan))

    r = c.get("/api/usage", headers={"Host": PUB})
    check("/api/usage reports the counter",
          r.status_code == 200 and r.json["bytes"] == after,
          r.json if r.status_code == 200 else r.status_code)

    c.get("/logout", headers={"Host": PUB})
    r = c.get("/", headers={"Host": PUB, "Accept": "text/html"})
    check("logout ends the session",
          r.status_code == 302 and "/login" in r.headers["Location"], r.status_code)

    guesser = app.test_client()
    headers = {"Host": PUB, "X-Forwarded-For": "203.0.113.9"}
    for _ in range(livecam.LOGIN_MAX_FAILURES + 2):
        last = guesser.post("/login", data={"username": "admin", "password": "no"},
                            headers=headers)
    check("repeated guessing gets throttled", b"Too many attempts" in last.data,
          last.data[:80])
    r = guesser.post("/login", data={"username": "admin", "password": PASSWORD},
                     headers=headers)
    check("the throttle holds even for the correct password",
          b"Too many attempts" in r.data)

    print()
    print("ALL PASS" if not failures else "FAILURES: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
