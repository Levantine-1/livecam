"""End-to-end checks for livecam's gate, run against Flask's test client.

Deliberately covers the parts where a bug is silent rather than loud: a
permission that fails open, a stream token that works for the wrong user,
the egress counter charging LAN traffic. Both backends are pointed at
unroutable hosts, so nothing here touches Frigate or go2rtc -- every
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
        # A `_`-prefixed key, to prove metadata is never mistaken for a user.
        "_notes:\n"
        "  purpose: metadata, not an account\n"
        "admin:\n"
        f"  password_hash: \"{{HASH}}\"\n"
        "  cameras: [guinea-pig-cage-1, guinea-pig-cage-2]\n"
        "  audio: true\n"
        "  recordings: true\n"
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
    FRIGATE_URL="http://frigate.invalid:5000",
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

    # Nothing is reachable logged out -- including Frigate, which is the
    # whole point of putting livecam's login in front of it.
    r = c.get("/", headers={"Host": PUB, "Accept": "text/html"})
    check("/ redirects to login when logged out",
          r.status_code == 302 and "/login" in r.headers["Location"], r.status_code)
    r = c.get("/frigate/", headers={"Host": PUB, "Accept": "text/html"})
    check("Frigate is not reachable without a livecam session",
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

    # Regression guard. preload="none" on the tiles is a data-saving hint that
    # mobile Chrome honours far more literally than desktop: tiles painted one
    # frame and stopped, while the expanded view worked on the same phone
    # because a tap always precedes it. Checked against the <video> tags only,
    # so the explanatory comment does not satisfy it.
    tags = re.findall(r"<video[^>]*>", page)
    tile_tags = [t for t in tags if "data-camera" in t]
    check("tiles exist to check", len(tile_tags) == 2, len(tile_tags))
    check("tiles do not carry preload=none",
          all("preload" not in t for t in tile_tags), tile_tags[:1])
    check("tiles are muted and inline, so autoplay is permitted at all",
          all("muted" in t and "playsinline" in t for t in tile_tags), tile_tags[:1])
    check("the tap-to-play fallback exists for when autoplay is refused",
          'id="tapToPlay"' in page)

    # Transport selection, checked in the page source because it decides
    # whether a whole platform can play anything at all.
    #
    # Selecting on canPlayType alone shipped a regression: Android Chrome
    # answers "maybe" for HLS because Android's media stack advertises it,
    # then cannot play what this app serves -- so every Android phone moved
    # off the working MP4 path onto a dead one. The claim now has to be
    # corroborated by the platform actually being Apple's.
    check("HLS is not chosen on canPlayType alone",
          "iPhone|iPad|iPod" in page and "maxTouchPoints" in page)
    check("Chromium and Android are explicitly excluded from the HLS path",
          "Android" in page and "CriOS" in page and "SamsungBrowser" in page)
    # A wrong guess must repair itself, since these platforms cannot all be
    # tested before shipping.
    check("a failed transport falls back to the other one",
          "TRANSPORT_TIMEOUT_MS" in page and "_abandonStream" in page)

    perms = livecam.load_permissions()
    allowed, audio = livecam.check_permission("admin", perms)
    check("admin: both cameras, audio on",
          allowed == {"guinea-pig-cage-1", "guinea-pig-cage-2"} and audio, (allowed, audio))
    allowed, audio = livecam.check_permission("guest", perms)
    check("guest outside their time window gets nothing",
          allowed == set() and not audio, (allowed, audio))
    check("`_`-prefixed metadata is not treated as a user",
          livecam.check_permission("_notes", perms)[0] == set())
    check("unknown user gets nothing",
          livecam.check_permission("nobody", perms)[0] == set())

    # Audio gating is enforced by which go2rtc stream gets requested, so
    # these mappings are the enforcement.
    check("tiles take the audio-free substream",
          livecam.resolve_stream_name("cam", True, "sub") == "cam_sub_noaudio")
    # The default has to be audio-free even for a permitted user: an unmuted
    # element carrying an AAC track is what browsers refuse to autoplay, and
    # that refusal is what froze the expanded view on its first frame.
    check("full quality is audio-free until asked for",
          livecam.resolve_stream_name("cam", True, "full") == "cam_noaudio")
    check("full quality with audio requested and permitted",
          livecam.resolve_stream_name("cam", True, "full", want_audio=True) == "cam")
    check("asking for audio without permission still drops the track",
          livecam.resolve_stream_name("cam", False, "full", want_audio=True) == "cam_noaudio")
    check("audio is never added to a substream",
          livecam.resolve_stream_name("cam", True, "sub", want_audio=True) == "cam_sub_noaudio")

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

    # The recorded archive is a separate grant from live viewing. Frigate
    # has no per-camera or per-audio gating matching this app's model, so a
    # user allowed one camera, or no audio, must not inherit the archive --
    # `guest` here is audio-free and has no `recordings` key at all.
    r = c.get("/frigate/", headers={"Host": PUB})
    check("a user granted recordings reaches Frigate",
          r.status_code != 403, r.status_code)
    denied = app.test_client()
    denied.post("/login", data={"username": "guest", "password": PASSWORD},
                headers={"Host": PUB})
    r = denied.get("/frigate/", headers={"Host": PUB})
    check("a user without the recordings grant is refused Frigate",
          r.status_code == 403, r.status_code)
    r = denied.get("/frigate/api/events", headers={"Host": PUB})
    check("the refusal covers Frigate's API, not just its index",
          r.status_code == 403, r.status_code)
    check("the archive link is hidden from users without the grant",
          "/frigate/" not in denied.get("/", headers={"Host": PUB}).get_data(as_text=True))
    check("the archive link is shown to users with the grant",
          "/frigate/" in page)

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

    # --- HLS source selection (the iOS path) ---
    # The _noaudio streams are deliberately absent here: they are ffmpeg
    # chains and go2rtc's TS muxer loses the H.264 parameter sets across
    # them, so HLS segments decode with continuous "non-existing PPS"
    # errors. Audio is excluded with a track filter on the direct stream
    # instead, which is clean.
    s, p = livecam.resolve_hls_source("cam", True, "sub")
    check("HLS tiles use the direct substream, video only",
          s == "cam_sub" and p == {"video": "h264"}, (s, p))
    s, p = livecam.resolve_hls_source("cam", True, "full")
    check("HLS full quality is video-only until audio is asked for",
          s == "cam" and p == {"video": "h264"}, (s, p))
    s, p = livecam.resolve_hls_source("cam", True, "full", want_audio=True)
    check("HLS full quality adds audio when permitted and requested",
          s == "cam" and p.get("audio") == "aac", (s, p))
    s, p = livecam.resolve_hls_source("cam", False, "full", want_audio=True)
    check("HLS never adds audio without permission",
          s == "cam" and "audio" not in p, (s, p))
    s, p = livecam.resolve_hls_source("cam", True, "sub", want_audio=True)
    check("HLS tiles never carry audio", "audio" not in p, p)
    check("no HLS source uses the parameter-set-losing _noaudio chain",
          all("_noaudio" not in livecam.resolve_hls_source("cam", a, q, w)[0]
              for a in (True, False) for q in ("sub", "full") for w in (True, False)))

    # Segment and playlist requests carry only a go2rtc session id, so the
    # id -> owner mapping is the entire authorisation story for them.
    session_probe = app.test_client()
    session_probe.post("/login", data={"username": "admin", "password": PASSWORD},
                       headers={"Host": LAN})
    with livecam._hls_lock:
        livecam._hls_sessions["testsid"] = {
            "user": "admin", "camera": "guinea-pig-cage-1",
            "quality": "sub", "metered": False, "seen": __import__("time").time(),
        }
    r = app.test_client().get("/hls/segment.ts?id=testsid", headers={"Host": LAN})
    check("HLS segment refused without a livecam session", r.status_code == 401, r.status_code)

    other_user = app.test_client()
    other_user.post("/login", data={"username": "guest", "password": PASSWORD},
                    headers={"Host": LAN})
    r = other_user.get("/hls/segment.ts?id=testsid", headers={"Host": LAN})
    check("HLS session belonging to another user is refused",
          r.status_code == 403, r.status_code)

    r = session_probe.get("/hls/segment.ts?id=nosuchsession", headers={"Host": LAN})
    check("unknown HLS session id is refused", r.status_code == 403, r.status_code)
    r = session_probe.get("/hls/segment.ts", headers={"Host": LAN})
    check("HLS request with no session id is refused", r.status_code == 403, r.status_code)
    r = session_probe.get("/hls/..%2Fapi%2Fstreams?id=testsid", headers={"Host": LAN})
    check("HLS path traversal is refused", r.status_code in (400, 404), r.status_code)

    r = app.test_client().get(
        "/live/guinea-pig-cage-1/master.m3u8", headers={"Host": LAN})
    check("HLS master requires a login", r.status_code in (302, 401), r.status_code)

    # The full-quality cap counts sessions seen *recently*, not every session
    # inside the 5-minute auth TTL. Counting over the TTL meant four expands
    # in five minutes silently downgraded the fifth long after nobody was
    # watching -- caught live, when a full-quality request came back as the
    # substream for no visible reason.
    now = __import__("time").time()
    with livecam._hls_lock:
        livecam._hls_sessions.clear()
        for i in range(livecam.MAX_FULL_QUALITY_SESSIONS + 2):
            livecam._hls_sessions[f"stale{i}"] = {
                "user": "admin", "camera": "guinea-pig-cage-1", "quality": "full",
                "metered": False, "seen": now - livecam.HLS_ACTIVE_SECONDS - 5,
            }
        stale_full = sum(
            1 for v in livecam._hls_sessions.values()
            if v["quality"] == "full" and v["seen"] >= now - livecam.HLS_ACTIVE_SECONDS)
        livecam._hls_sessions.clear()
    check("sessions idle past the activity window stop counting against the cap",
          stale_full == 0, stale_full)

    # --- LAN switch: ping, handoff ---
    fresh = app.test_client()
    r = fresh.get("/api/ping", headers={"Host": LAN})
    check("/api/ping answers without a session", r.status_code == 204, r.status_code)
    check("/api/ping allows the public origin cross-origin",
          r.headers.get("Access-Control-Allow-Origin") == f"https://{PUB}",
          r.headers.get("Access-Control-Allow-Origin"))
    check("/api/ping carries no body", r.data == b"", r.data[:40])

    session_c = app.test_client()
    session_c.post("/login", data={"username": "admin", "password": PASSWORD},
                   headers={"Host": PUB})
    r = session_c.post("/api/handoff", headers={"Host": PUB})
    check("handoff token minted for a logged-in user", r.status_code == 200, r.status_code)
    handoff = r.json["token"]

    r = app.test_client().post("/api/handoff", headers={"Host": PUB})
    check("handoff refused without a session", r.status_code == 401, r.status_code)

    # The point of the whole mechanism: arrive on the other hostname already
    # logged in, without widening the session cookie to every app on the domain.
    arriving = app.test_client()
    r = arriving.get(f"/handoff?t={handoff}", headers={"Host": LAN})
    check("handoff establishes a session on the LAN host",
          r.status_code == 302 and r.headers["Location"] == "/", r.headers.get("Location"))
    r = arriving.get("/", headers={"Host": LAN})
    check("handed-off session can load the dashboard", r.status_code == 200, r.status_code)

    replay = app.test_client()
    r = replay.get(f"/handoff?t={handoff}", headers={"Host": LAN})
    check("a handoff token cannot be replayed",
          r.status_code == 302 and "/login" in r.headers["Location"], r.headers.get("Location"))

    r = app.test_client().get("/handoff?t=not-a-real-token", headers={"Host": LAN})
    check("a forged handoff token is refused",
          r.status_code == 302 and "/login" in r.headers["Location"], r.headers.get("Location"))

    expired = livecam._handoff_serializer().dumps("admin")
    saved, livecam.HANDOFF_MAX_AGE_SECONDS = livecam.HANDOFF_MAX_AGE_SECONDS, -1
    r = app.test_client().get(f"/handoff?t={expired}", headers={"Host": LAN})
    livecam.HANDOFF_MAX_AGE_SECONDS = saved
    check("an expired handoff token is refused",
          r.status_code == 302 and "/login" in r.headers["Location"], r.headers.get("Location"))

    # Signed by this app's secret, but naming someone since removed.
    ghost = livecam._handoff_serializer().dumps("deleted-user")
    r = app.test_client().get(f"/handoff?t={ghost}", headers={"Host": LAN})
    check("handoff for a user no longer in permissions.yml is refused",
          r.status_code == 302 and "/login" in r.headers["Location"], r.headers.get("Location"))

    # The switch offer must never appear on the host it would send you to.
    r = session_c.get("/", headers={"Host": PUB})
    check("LAN switch offer rendered on the public hostname",
          "lanToast" in r.get_data(as_text=True))
    lan_c = app.test_client()
    lan_c.post("/login", data={"username": "admin", "password": PASSWORD},
               headers={"Host": LAN})
    r = lan_c.get("/", headers={"Host": LAN})
    # Assert we are looking at a real dashboard, not a login redirect --
    # otherwise "no toast here" is true for the wrong reason.
    check("LAN dashboard renders for a LAN-authenticated session",
          r.status_code == 200 and "lanToast" not in r.get_data(as_text=True),
          r.status_code)
    r = app.test_client().get("/login", headers={"Host": PUB})
    check("login page offers the switch too",
          "lanToast" in r.get_data(as_text=True))

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
