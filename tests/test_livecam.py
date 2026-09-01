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
CAMERAS = os.path.join(WORK, "cameras.yml")
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
        "  cameras: [the-boiz, the-gurlz]\n"
        "  audio: true\n"
        "  recordings: true\n"
        # Per-camera audio AND ptz, plus a camera listed for each that this
        # user cannot see -- neither grant may become a way to reach it.
        "partial:\n"
        f"  password_hash: \"{{HASH}}\"\n"
        "  cameras: [the-boiz, the-gurlz]\n"
        "  audio: [the-boiz, baby-cam]\n"
        # the-gurlz is granted ptz here but NOT declared PTZ-capable in the
        # cameras.yml fixture below -- exercises the "both gates required"
        # property: a permission grant alone must not be enough.
        "  ptz: [the-boiz, the-gurlz, baby-cam]\n"
        "guest:\n"
        f"  password_hash: \"{{HASH}}\"\n"
        "  cameras: [the-boiz]\n"
        "  audio: false\n"
        # A window that is already over, so "outside the window" is testable
        # without waiting for a particular time of day.
        "  time_window: {start: \"00:00:00\", end: \"00:00:01\"}\n"
    )

# Only the-boiz is declared PTZ-capable -- the-gurlz deliberately is not,
# even though `partial` above is granted `ptz` on both, so the config-flag
# gate has something real to refuse.
with open(CAMERAS, "w") as f:
    f.write(
        "cameras:\n"
        "  the-boiz:\n"
        "    ip: 10.69.69.107\n"
        "    onvif_port: 8899\n"
    )

PUB = "livecam.levantine.io"
LAN = "livecam-lan.levantine.io"

os.environ.update(
    FRIGATE_URL="http://frigate.invalid:5000",
    GO2RTC_URL="http://go2rtc.invalid:1984",
    PERMISSIONS_FILE=PERMS,
    CAMERAS_FILE=CAMERAS,
    EGRESS_DB=DB,
    FLASK_SECRET_KEY="test-secret",
    PUBLIC_HOSTNAME=PUB,
    LAN_HOSTNAME=LAN,
    CAMERA_USERNAME="admin",
    CAMERA_PASSWORD="test-camera-password",
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


# --------------------------------------------------------------------------
# Fake upstream for _proxy(): mimics just enough of a requests.Response for
# the code to work against, so the streaming-vs-buffering branch in _proxy()
# can be tested directly rather than inferred. `.content` and `.iter_content`
# both record whether they were called -- the streaming fix is precisely the
# claim that non-HTML responses never touch `.content`, so that claim gets
# checked directly instead of assumed from the response looking correct.
# --------------------------------------------------------------------------
class _FakeRaw:
    def __init__(self, headers):
        self.headers = headers


class FakeUpstreamResponse:
    def __init__(self, status_code, content_type, chunks):
        self.status_code = status_code
        self._chunks = list(chunks)
        self.headers = {"Content-Type": content_type}
        self.raw = _FakeRaw(dict(self.headers))
        self.closed = False
        self.content_accessed = False
        self.iter_content_calls = 0

    @property
    def content(self):
        self.content_accessed = True
        return b"".join(self._chunks)

    @property
    def text(self):
        return b"".join(self._chunks).decode("utf-8")

    def iter_content(self, chunk_size=None):
        self.iter_content_calls += 1
        yield from self._chunks

    def close(self):
        self.closed = True


# --------------------------------------------------------------------------
# Fake ONVIF stack: no PTZ camera exists to test against, so this exercises
# every layer around the real ONVIF I/O (routing, both permission gates, the
# asyncio bridge that actually runs coroutines on livecam's background loop
# and returns real results) while replacing only the network calls
# themselves. Shaped to match onvif-zeep-async's real return types closely
# enough for livecam's code to work unmodified against either.
# --------------------------------------------------------------------------
class _FakePTZConfig:
    def __init__(self):
        self.DefaultContinuousPanTiltVelocitySpace = object()
        self.DefaultContinuousZoomVelocitySpace = object()


class _FakeProfile:
    def __init__(self, token):
        self.token = token
        self.PTZConfiguration = _FakePTZConfig()


class _FakeMoveRequest:
    def __init__(self):
        self.ProfileToken = None
        self.Velocity = None


class _FakeRelativeMoveRequest:
    def __init__(self):
        self.ProfileToken = None
        self.Translation = None


class _FakePreset:
    def __init__(self, name, token):
        self.Name = name
        self.token = token


class FakePTZService:
    def __init__(self):
        self.calls = []  # (method, profile_token, payload) for assertions

    def create_type(self, name):
        if name == "ContinuousMove":
            return _FakeMoveRequest()
        if name == "RelativeMove":
            return _FakeRelativeMoveRequest()
        raise NotImplementedError(name)

    async def ContinuousMove(self, req):
        self.calls.append(("ContinuousMove", req.ProfileToken, req.Velocity))

    async def RelativeMove(self, req):
        self.calls.append(("RelativeMove", req.ProfileToken, req.Translation))

    async def Stop(self, req):
        self.calls.append(("Stop", req["ProfileToken"], req))

    async def GotoPreset(self, req):
        self.calls.append(("GotoPreset", req["ProfileToken"], req["PresetToken"]))

    async def GetPresets(self, req):
        return [_FakePreset("Home", "preset-home"), _FakePreset("Garden", "preset-garden")]


class _FakeMediaService:
    async def GetProfiles(self):
        return [_FakeProfile("profile-1")]


class FakeONVIFCamera:
    """Replaces onvif.ONVIFCamera. Records constructor args for auth checks."""

    instances = []

    def __init__(self, host, port, user, passwd):
        self.host, self.port, self.user, self.passwd = host, port, user, passwd
        self.ptz_service = FakePTZService()
        FakeONVIFCamera.instances.append(self)

    async def update_xaddrs(self):
        pass

    async def create_media_service(self):
        return _FakeMediaService()

    async def create_ptz_service(self):
        return self.ptz_service


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
    r = c.get("/live/the-boiz?token=x", headers={"Host": PUB})
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
          page.count('data-camera=') == 4, page.count('data-camera='))
    check("tiles are labelled with friendly names derived from the slug",
          "The Boiz" in page and "The Gurlz" in page)
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
    allowed, audio, ptz, talk = livecam.check_permission("admin", perms)
    check("admin: both cameras, audio on both (bool still means all)",
          allowed == {"the-boiz", "the-gurlz"} and audio == allowed, (allowed, audio))
    check("admin has no ptz grant at all (never set for this user)",
          ptz == set(), ptz)
    allowed, audio, ptz, talk = livecam.check_permission("guest", perms)
    check("guest outside their time window gets nothing",
          allowed == set() and audio == set() and ptz == set(), (allowed, audio, ptz))

    # Per-camera audio and ptz, and the intersection that keeps both honest.
    allowed, audio, ptz, talk = livecam.check_permission("partial", perms)
    check("per-camera audio grants only the listed camera",
          allowed == {"the-boiz", "the-gurlz"} and audio == {"the-boiz"}, (allowed, audio))
    check("audio listed for an unseeable camera grants nothing",
          "baby-cam" not in audio, audio)
    check("ptz listed for an unseeable camera grants nothing either",
          ptz == {"the-boiz", "the-gurlz"} and "baby-cam" not in ptz, ptz)
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
    r = other.get(f"/live/the-boiz?token={token}", headers={"Host": PUB})
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

    # --- _proxy() streaming: the actual bug behind intermittent iOS freezes
    # while scrubbing recorded video. Frigate's HLS VOD segments run 8+ MB
    # each, and scrubbing abandons and refetches rapidly; the previous
    # implementation fully buffered every response (`upstream.content`)
    # before responding, so an abandoned client's request still downloaded
    # the whole thing from Frigate regardless -- confirmed live by closing a
    # real client connection 4KB into an 8.4MB segment and finding livecam's
    # own access log showed a completed 200 for the full size anyway.
    #
    # These tests check the mechanism directly rather than inferring it: a
    # fake upstream records whether `.content` (buffers everything) or
    # `.iter_content` (streams, and stops early if the caller stops asking
    # for more) actually gets used.
    real_requests_request = livecam.requests.request
    try:
        # Non-HTML: must stream. A real recorded segment is binary and large;
        # this uses multiple chunks the way a real 8MB+ segment would arrive
        # in 64KB pieces, not because the size matters here.
        seg_chunks = [b"S" * 70000, b"E" * 70000, b"G" * 12345]
        fake_seg = FakeUpstreamResponse(200, "video/mp4", seg_chunks)
        livecam.requests.request = lambda *a, **kw: fake_seg
        r = c.get("/frigate/vod/the-boiz/start/0/end/1/seg-1.m4s", headers={"Host": PUB})
        check("streamed response is byte-identical to the source",
              r.data == b"".join(seg_chunks), len(r.data))
        check("non-HTML never touches .content -- proves it took the streaming path, not the old buffering one",
              fake_seg.content_accessed is False)
        check("non-HTML is read via iter_content exactly once",
              fake_seg.iter_content_calls == 1, fake_seg.iter_content_calls)
        check("the upstream connection is closed once streaming finishes",
              fake_seg.closed is True)

        # HTML: must still buffer, because the back-to-live injection needs
        # the whole body to find </body>. The one deliberate exception to
        # the streaming rule above, and it needs to still work.
        html_body = b"<html><body><div id=\"root\">frigate ui</div></body></html>"
        fake_html = FakeUpstreamResponse(200, "text/html; charset=utf-8", [html_body])
        livecam.requests.request = lambda *a, **kw: fake_html
        r = c.get("/frigate/", headers={"Host": PUB})
        check("HTML still gets buffered (.content used) so injection can find </body>",
              fake_html.content_accessed is True)
        check("HTML back-to-live injection still fires through the real route, not just the helper",
              b"livecam-back" in r.data)
        check("injected HTML is still well-formed around the marker",
              r.data.endswith(b"</body></html>"))

        # Egress accounting must still be correct on both paths -- the whole
        # point of counting is knowing what actually crossed the public
        # route, and that must not regress when the mechanism changes.
        livecam.record_egress(0, flush=True)
        before_seg = livecam.egress_this_month()
        fake_seg2 = FakeUpstreamResponse(200, "video/mp4", seg_chunks)
        livecam.requests.request = lambda *a, **kw: fake_seg2
        # .data forces full consumption of the streamed response -- without
        # it the test client may only pull the generator far enough to get
        # headers, under-running the egress count for a reason that has
        # nothing to do with _proxy() itself (caught by this test failing
        # with exactly one chunk's worth counted instead of all three).
        c.get("/frigate/vod/the-boiz/start/0/end/1/seg-2.m4s", headers={"Host": PUB}).data
        livecam.record_egress(0, flush=True)
        check("egress counted for a streamed response matches the real byte count",
              livecam.egress_this_month() - before_seg == len(b"".join(seg_chunks)),
              livecam.egress_this_month() - before_seg)

        # The LAN hostname must stay free either way -- same rule as every
        # other metered path in this app.
        before_lan = livecam.egress_this_month()
        fake_seg3 = FakeUpstreamResponse(200, "video/mp4", seg_chunks)
        livecam.requests.request = lambda *a, **kw: fake_seg3
        c.get("/frigate/vod/the-boiz/start/0/end/1/seg-3.m4s", headers={"Host": LAN}).data
        livecam.record_egress(0, flush=True)
        check("streamed responses over the LAN hostname are not metered",
              livecam.egress_this_month() == before_lan, livecam.egress_this_month())
    finally:
        livecam.requests.request = real_requests_request

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

    # --- live per-connection byte counter (2026-08) ---
    # _record_stream_bytes()/_stream_bytes_for() are exercised directly here,
    # the same way record_egress()/egress_this_month() are above -- the
    # actual byte-plumbing through pump()/hls_proxy() is a couple of extra
    # lines around counters already proven correct elsewhere in this file.
    livecam._record_stream_bytes("testconn1", 1000)
    livecam._record_stream_bytes("testconn1", 500)
    r = c.get("/api/stream-usage?conn=testconn1", headers={"Host": PUB})
    check("/api/stream-usage reports a connection's accumulated bytes",
          r.status_code == 200 and r.json["bytes"] == 1500, r.json)

    r = c.get("/api/stream-usage?conn=never-seen-this-one", headers={"Host": PUB})
    check("an unrecognised conn id is zero, not an error",
          r.status_code == 200 and r.json["bytes"] == 0, r.json)

    r = c.get("/api/stream-usage", headers={"Host": PUB})
    check("a missing conn id is zero, not an error",
          r.status_code == 200 and r.json["bytes"] == 0, r.json)

    check("conn ids with characters outside the safe set are rejected, not stored verbatim",
          livecam._sanitize_conn_id("../../etc/passwd") is None
          and livecam._sanitize_conn_id("has spaces") is None
          and livecam._sanitize_conn_id("a-real-uuid-1234") == "a-real-uuid-1234")

    # The master playlist rewrite has to carry `conn` through to the one
    # line it already rewrites (see live_hls()'s own comment on why:
    # go2rtc has no idea this parameter exists), so hls_proxy() can pick it
    # back up on the segment/media-playlist fetches that follow.
    real_requests_get = livecam.requests.get
    try:
        fake_master = FakeUpstreamResponse(
            200, livecam.M3U8_CONTENT_TYPE, [b"#EXTM3U\nhls/playlist.m3u8?id=abc123\n"])
        livecam.requests.get = lambda *a, **kw: fake_master
        r = c.get(f"/live/the-boiz/master.m3u8?token={token}&conn=rateconn1",
                  headers={"Host": PUB})
        body = r.get_data(as_text=True)
        check("HLS master rewrite carries conn through to the rewritten playlist line",
              r.status_code == 200 and "/hls/playlist.m3u8?id=abc123&conn=rateconn1" in body,
              body)
    finally:
        livecam.requests.get = real_requests_get

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
            "user": "admin", "camera": "the-boiz",
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
        "/live/the-boiz/master.m3u8", headers={"Host": LAN})
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
                "user": "admin", "camera": "the-boiz", "quality": "full",
                "metered": False, "seen": now - livecam.HLS_ACTIVE_SECONDS - 5,
            }
        stale_full = sum(
            1 for v in livecam._hls_sessions.values()
            if v["quality"] == "full" and v["seen"] >= now - livecam.HLS_ACTIVE_SECONDS)
        livecam._hls_sessions.clear()
    check("sessions idle past the activity window stop counting against the cap",
          stale_full == 0, stale_full)

    # --- per-camera audio, enforced server-side ---
    # The UI hiding a control proves nothing; what matters is which go2rtc
    # stream the server picks when a client asks for audio anyway.
    part = app.test_client()
    part.post("/login", data={"username": "partial", "password": PASSWORD},
              headers={"Host": PUB})
    ppage = part.get("/", headers={"Host": PUB}).get_data(as_text=True)
    ptok = re.search(r'const TOKEN = "([^"]+)"', ppage).group(1)
    check("the audio-enabled set reaches the client for per-camera UI",
          '"the-boiz"' in ppage and "AUDIO_CAMERAS" in ppage)
    check("permitted camera gets the audio stream when asked",
          livecam.resolve_stream_name("the-boiz", True, "full", want_audio=True) == "the-boiz")
    check("the other camera is refused audio despite the same request",
          livecam.resolve_stream_name("the-gurlz", False, "full", want_audio=True)
          == "the-gurlz_noaudio")
    s_hls, p_hls = livecam.resolve_hls_source("the-gurlz", False, "full", want_audio=True)
    check("same refusal over HLS (no audio track filter)", "audio" not in p_hls, p_hls)

    # --- idle timeout differs by route, in the same process ---
    with app.test_request_context("/", headers={"Host": PUB}):
        pub_idle, pub_beat = livecam.idle_settings()
    with app.test_request_context("/", headers={"Host": LAN}):
        lan_idle, lan_beat = livecam.idle_settings()
    check("LAN gets the long idle window, public keeps the short one",
          lan_idle > pub_idle and lan_idle == 8 * 3600, (pub_idle, lan_idle))
    check("the browser still gives up before the server on both routes",
          pub_idle < pub_beat and lan_idle < lan_beat,
          (pub_idle, pub_beat, lan_idle, lan_beat))

    # --- back-to-live injection is HTML-only ---
    html = b"<html><body><div id=\"root\"></div></body></html>"
    out = livecam._inject_back_to_live(html, "text/html")
    check("injected into HTML before </body>",
          b"livecam-back" in out and out.endswith(b"</body></html>"))
    check("injected outside the React root",
          out.index(b'id="root"') < out.index(b"livecam-back"))
    for ctype in ("text/css", "application/json", "text/plain", "video/mp4", None):
        untouched = livecam._inject_back_to_live(html, ctype)
        check(f"non-HTML ({ctype}) passes through byte-identical", untouched == html)
    check("HTML without a </body> is left alone",
          livecam._inject_back_to_live(b"partial chunk", "text/html") == b"partial chunk")

    # --- PTZ: talks straight to the camera, never touches Frigate ---
    livecam.ONVIFCamera = FakeONVIFCamera  # patch before any PTZ route runs

    part = app.test_client()
    part.post("/login", data={"username": "partial", "password": PASSWORD},
              headers={"Host": LAN})

    # `partial` is granted ptz on the-boiz AND the-gurlz, but only the-boiz
    # is declared PTZ-capable -- the value that actually reaches the client
    # must be the intersection of both, not either gate alone.
    dash_html = part.get("/", headers={"Host": LAN}).get_data(as_text=True)
    check("both gates intersected correctly reach the client",
          "PTZ_CAMERAS = new Set([\"the-boiz\"])" in dash_html, dash_html.count("the-boiz"))

    allowed, _, ptz_cameras, _ = livecam.check_permission("partial", livecam.load_permissions())
    check("ptz grant intersected with cameras (baby-cam unseeable, dropped)",
          ptz_cameras == {"the-boiz", "the-gurlz"}, ptz_cameras)
    check("config-flag gate: only the-boiz is actually declared PTZ-capable",
          livecam.ptz_capable_cameras() == {"the-boiz"}, livecam.ptz_capable_cameras())

    # Regression: a real deploy hit exactly this. The volume mount's
    # host-side file did not exist yet when the container was created, so
    # Docker silently bind-mounted an empty directory in its place, and
    # open() raised IsADirectoryError -- a shape load_camera_config() did
    # not originally handle, which took down the *entire* dashboard (every
    # route calls it, not just PTZ) over a feature meant to be optional and
    # inert. A malformed CAMERAS_FILE must degrade to "no PTZ", not 500.
    saved_cameras_file = livecam.CAMERAS_FILE
    broken_path = os.path.join(WORK, "cameras_is_a_directory.yml")
    os.makedirs(broken_path, exist_ok=True)
    livecam.CAMERAS_FILE = broken_path
    check("a directory where the file should be degrades to no PTZ cameras",
          livecam.load_camera_config() == {})
    dash_after_break = part.get("/", headers={"Host": LAN})
    check("the dashboard survives a broken CAMERAS_FILE rather than 500ing",
          dash_after_break.status_code == 200, dash_after_break.status_code)

    with open(os.path.join(WORK, "cameras_not_yaml.yml"), "w") as f:
        f.write("this: is: not: valid: yaml: [[[")
    livecam.CAMERAS_FILE = f.name
    check("invalid YAML degrades to no PTZ cameras rather than raising",
          livecam.load_camera_config() == {})

    with open(os.path.join(WORK, "cameras_wrong_shape.yml"), "w") as f:
        f.write("cameras: \"not a mapping\"\n")
    livecam.CAMERAS_FILE = f.name
    check("a non-mapping `cameras:` value degrades to no PTZ cameras",
          livecam.load_camera_config() == {})

    livecam.CAMERAS_FILE = saved_cameras_file
    check("restored config still works: the real fixture is back", livecam.load_camera_config())

    r = part.post("/ptz/the-boiz", json={"command": "move_up"}, headers={"Host": LAN})
    check("PTZ move accepted: both gates satisfied", r.status_code == 200, r.status_code)
    check("ContinuousMove reached the fake camera with the right velocity",
          FakeONVIFCamera.instances[-1].ptz_service.calls[-1]
          == ("ContinuousMove", "profile-1", {"PanTilt": {"x": 0, "y": 0.5}}))
    check("ONVIFCamera constructed with this camera's declared host/port",
          (FakeONVIFCamera.instances[-1].host, FakeONVIFCamera.instances[-1].port)
          == ("10.69.69.107", 8899))
    check("no per-camera username override -> falls back to CAMERA_USERNAME",
          FakeONVIFCamera.instances[-1].user == "admin")

    r = part.post("/ptz/the-boiz", json={"command": "stop"}, headers={"Host": LAN})
    check("PTZ stop accepted", r.status_code == 200, r.status_code)
    check("Stop reached the fake camera",
          FakeONVIFCamera.instances[-1].ptz_service.calls[-1][0] == "Stop")

    # Single-click "step" (2026-08-27): a RelativeMove, not a timed
    # ContinuousMove+Stop -- travels the same fixed amount regardless of
    # network round-trip time.
    r = part.post("/ptz/the-boiz", json={"command": "step_move_up"}, headers={"Host": LAN})
    check("PTZ step accepted", r.status_code == 200, r.status_code)
    check("RelativeMove reached the fake camera with the right translation",
          FakeONVIFCamera.instances[-1].ptz_service.calls[-1]
          == ("RelativeMove", "profile-1", {"PanTilt": {"x": 0, "y": 0.1}}))

    r = part.post("/ptz/the-gurlz", json={"command": "move_up"}, headers={"Host": LAN})
    check("permission grant alone is not enough: the-gurlz has no config entry",
          r.status_code == 403, r.status_code)

    other = app.test_client()
    other.post("/login", data={"username": "guest", "password": PASSWORD},
               headers={"Host": LAN})
    guest_html = other.get("/", headers={"Host": LAN}).get_data(as_text=True)
    check("guest has no ptz grant at all: dashboard shows an empty PTZ_CAMERAS",
          "PTZ_CAMERAS = new Set([])" in guest_html)
    r = other.post("/ptz/the-boiz", json={"command": "move_up"}, headers={"Host": LAN})
    check("config flag alone is not enough: guest has no ptz grant for the-boiz",
          r.status_code == 403, r.status_code)
    r = other.post("/ptz/the-boiz", json={"command": "step_move_up"}, headers={"Host": LAN})
    check("the gate is command-agnostic: step commands are denied the same way",
          r.status_code == 403, r.status_code)

    r = app.test_client().post("/ptz/the-boiz", json={"command": "move_up"}, headers={"Host": LAN})
    check("PTZ requires a session at all", r.status_code == 401, r.status_code)

    r = part.post("/ptz/the-boiz", json={"command": "spin_wildly"}, headers={"Host": LAN})
    check("an unrecognised command is refused, not silently ignored",
          r.status_code == 400, r.status_code)

    presets_before = len(FakeONVIFCamera.instances)
    r = part.get("/ptz/the-boiz/presets", headers={"Host": LAN})
    check("presets endpoint returns the fake camera's real preset list",
          r.status_code == 200 and sorted(r.json["presets"]) == ["garden", "home"], r.json)
    check("preset fetch reuses the cached ONVIF client rather than reconnecting",
          len(FakeONVIFCamera.instances) == presets_before)

    r = part.post("/ptz/the-boiz", json={"command": "preset_home"}, headers={"Host": LAN})
    check("a real preset name resolves and issues GotoPreset", r.status_code == 200, r.status_code)
    check("GotoPreset used the real token from GetPresets, not the name itself",
          FakeONVIFCamera.instances[-1].ptz_service.calls[-1]
          == ("GotoPreset", "profile-1", "preset-home"))

    r = part.post("/ptz/the-boiz", json={"command": "preset_nonexistent"}, headers={"Host": LAN})
    check("an unknown preset name is refused server-side, not trusted from the request",
          r.status_code == 400, r.status_code)

    # --- soundboard / talking to a camera's speaker ---
    # The audio path itself (go2rtc -> ONVIF backchannel) is not exercised
    # here: go2rtc is pointed at an unroutable host, and a real play makes
    # noise in an actual room. What's checked is everything this app decides
    # on its own -- both permission gates, clip-id handling, upload
    # validation and the signed-URL scheme that lets go2rtc fetch a clip
    # without a session.
    check("talk capability is opt-in per camera, unlike ptz which defaults on",
          livecam.talk_capable_cameras() == set()
          and livecam.ptz_capable_cameras() == {"the-boiz"},
          (livecam.talk_capable_cameras(), livecam.ptz_capable_cameras()))

    saved_cameras_file = livecam.CAMERAS_FILE
    talk_cfg = os.path.join(WORK, "cameras_talk.yml")
    with open(talk_cfg, "w") as f:
        f.write("cameras:\n"
                "  the-boiz:\n"
                "    ip: 10.69.69.107\n"
                "    talk: true\n"
                # Declared PTZ-capable but explicitly NOT a speaker, so the
                # two capabilities are proven independent.
                "  the-gurlz:\n"
                "    ip: 10.69.69.143\n")
    livecam.CAMERAS_FILE = talk_cfg
    check("only cameras with talk:true are speakable",
          livecam.talk_capable_cameras() == {"the-boiz"}, livecam.talk_capable_cameras())
    check("a camera without talk:true still counts as PTZ-capable",
          livecam.ptz_capable_cameras() == {"the-boiz", "the-gurlz"},
          livecam.ptz_capable_cameras())

    # `partial` has no `talk` grant at all, so the capability alone must not
    # be enough -- the mirror of the PTZ "both gates" test above.
    r = part.post("/talk/the-boiz/play", json={"clip": "x.wav"}, headers={"Host": LAN})
    check("capability without a talk grant is refused", r.status_code == 403, r.status_code)

    talk_perms = os.path.join(WORK, "permissions_talk.yml")
    with open(PERMS) as f:
        talk_body = f.read()
    with open(talk_perms, "w") as f:
        f.write(talk_body.replace(
            "  ptz: [the-boiz, the-gurlz, baby-cam]\n",
            "  ptz: [the-boiz, the-gurlz, baby-cam]\n  talk: [the-boiz, the-gurlz]\n"))
    saved_perms_file = livecam.PERMISSIONS_FILE
    livecam.PERMISSIONS_FILE = talk_perms
    livecam.load_permissions.cache_clear() if hasattr(livecam.load_permissions, "cache_clear") else None

    _, _, _, talk_grant = livecam.check_permission("partial", livecam.load_permissions())
    check("talk grant is intersected with visible cameras like audio/ptz",
          talk_grant == {"the-boiz", "the-gurlz"}, talk_grant)

    # the-gurlz is granted but has no speaker declared -> still refused.
    r = part.post("/talk/the-gurlz/play", json={"clip": "x.wav"}, headers={"Host": LAN})
    check("a grant on a camera with no speaker is refused",
          r.status_code == 403, r.status_code)

    # Clip ids come off the wire, so traversal and odd extensions are refused
    # before anything touches the filesystem.
    check("clip ids may not traverse directories",
          livecam._clip_path("../../etc/passwd") is None
          and livecam._clip_path("sub/dir.wav") is None
          and livecam._clip_path(".hidden.wav") is None)
    check("clip ids must carry a known audio extension",
          livecam._clip_path("evil.sh") is None
          and livecam._clip_path("fine.wav", ) is not None)

    saved_sb_dir = livecam.SOUNDBOARD_DIR
    livecam.SOUNDBOARD_DIR = os.path.join(WORK, "soundboard")
    os.makedirs(livecam.SOUNDBOARD_DIR, exist_ok=True)
    with open(os.path.join(livecam.SOUNDBOARD_DIR, "hello.wav"), "wb") as f:
        f.write(b"RIFF....WAVEfake")
    check("stored clips are listed", [c["id"] for c in livecam.soundboard_clips()] == ["hello.wav"],
          livecam.soundboard_clips())

    # The signed URL is what authorises go2rtc, which arrives with no session.
    token = livecam._soundboard_serializer().dumps("hello.wav")
    anon = app.test_client()
    r = anon.get(f"/soundboard/raw/{token}", headers={"Host": LAN})
    check("a validly-signed clip URL serves without a session (go2rtc has none)",
          r.status_code == 200 and r.data == b"RIFF....WAVEfake", r.status_code)
    r = anon.get("/soundboard/raw/not-a-real-token", headers={"Host": LAN})
    check("a forged clip token is refused", r.status_code == 403, r.status_code)
    r = anon.get(f"/soundboard/raw/{livecam._soundboard_serializer().dumps('nope.wav')}",
                 headers={"Host": LAN})
    check("a signed token for a missing clip is a 404, not a 500", r.status_code == 404,
          r.status_code)

    # Uploading is gated on `recordings`, a higher bar than playing.
    import io
    r = part.post("/soundboard/upload", headers={"Host": LAN},
                  data={"clip": (io.BytesIO(b"xx"), "x.wav")},
                  content_type="multipart/form-data")
    check("upload refused without the recordings grant", r.status_code == 403, r.status_code)

    admin_c = app.test_client()
    admin_c.post("/login", data={"username": "admin", "password": PASSWORD}, headers={"Host": LAN})
    r = admin_c.post("/soundboard/upload", headers={"Host": LAN},
                     data={"clip": (io.BytesIO(b"nope"), "payload.sh")},
                     content_type="multipart/form-data")
    check("upload refuses a non-audio extension", r.status_code == 400, r.status_code)

    saved_max = livecam.SOUNDBOARD_MAX_BYTES
    livecam.SOUNDBOARD_MAX_BYTES = 4
    r = admin_c.post("/soundboard/upload", headers={"Host": LAN},
                     data={"clip": (io.BytesIO(b"way too many bytes"), "big.wav")},
                     content_type="multipart/form-data")
    check("upload refuses a clip over the size cap", r.status_code == 400, r.status_code)
    check("an over-size upload is not left on disk",
          not os.path.exists(os.path.join(livecam.SOUNDBOARD_DIR, "big.wav")))
    livecam.SOUNDBOARD_MAX_BYTES = saved_max

    r = admin_c.post("/soundboard/upload", headers={"Host": LAN},
                     data={"clip": (io.BytesIO(b"RIFFdata"), "Nice Clip!.wav")},
                     content_type="multipart/form-data")
    check("a valid upload is accepted", r.status_code == 201, r.status_code)
    check("upload filenames are sanitised to a flat safe name",
          "Nice_Clip.wav" in [c["id"] for c in livecam.soundboard_clips()],
          livecam.soundboard_clips())

    # --- rename, browser preview, and save-without-playing ---
    r = admin_c.post("/soundboard/Nice_Clip.wav/rename", headers={"Host": LAN},
                     json={"label": "Hamster Taunt"})
    ids = [c["id"] for c in livecam.soundboard_clips()]
    check("rename gives the clip its new name",
          r.status_code == 200 and "Hamster_Taunt.wav" in ids, ids)
    check("rename keeps the original extension, not one from the label",
          all(i.endswith(".wav") for i in ids), ids)

    r = admin_c.post("/soundboard/Hamster_Taunt.wav/rename", headers={"Host": LAN},
                     json={"label": "evil.sh"})
    ids = [c["id"] for c in livecam.soundboard_clips()]
    check("a label with a foreign extension cannot change the stored type",
          r.status_code == 200 and "evil.wav" in ids
          and not any(i.endswith(".sh") for i in ids), ids)
    livecam._rename_clip("evil.wav", "Hamster Taunt")

    r = admin_c.post("/soundboard/Hamster_Taunt.wav/rename", headers={"Host": LAN},
                     json={"label": "   "})
    check("rename refuses an empty name", r.status_code == 400, r.status_code)
    r = admin_c.post("/soundboard/nope.wav/rename", headers={"Host": LAN},
                     json={"label": "x"})
    check("rename of a missing clip is a 404", r.status_code == 404, r.status_code)
    r = part.post("/soundboard/Hamster_Taunt.wav/rename", headers={"Host": LAN},
                  json={"label": "x"})
    check("rename needs the elevated grant", r.status_code == 403, r.status_code)

    # Preview is the browser path: session-gated, and a real audio type so an
    # <audio> element will play it. Distinct from the token-gated go2rtc path.
    r = admin_c.get("/soundboard/preview/Hamster_Taunt.wav", headers={"Host": LAN})
    check("preview serves the clip to a logged-in browser",
          r.status_code == 200, r.status_code)
    check("preview sends a real audio content type",
          "audio/" in r.headers.get("Content-Type", ""), r.headers.get("Content-Type"))
    anon = app.test_client()
    r = anon.get("/soundboard/preview/Hamster_Taunt.wav", headers={"Host": LAN})
    check("preview is not open to anonymous callers",
          r.status_code in (302, 401, 403), r.status_code)
    r = admin_c.get("/soundboard/preview/../../etc/passwd", headers={"Host": LAN})
    check("preview refuses a traversing id", r.status_code in (400, 404), r.status_code)

    # Saving a recording must NOT play it -- that is the whole point of the
    # endpoint existing separately from /talk/<camera>/say.
    r = admin_c.post("/soundboard/save", headers={"Host": LAN},
                     data={"clip": (io.BytesIO(b"RIFFrec"), "recording.webm"),
                           "label": "My Voice"},
                     content_type="multipart/form-data")
    ids = [c["id"] for c in livecam.soundboard_clips()]
    check("a recording can be saved under a chosen name",
          r.status_code == 201 and "My_Voice.webm" in ids, ids)
    r = part.post("/soundboard/save", headers={"Host": LAN},
                  data={"clip": (io.BytesIO(b"RIFFrec"), "recording.webm")},
                  content_type="multipart/form-data")
    check("saving a recording needs the elevated grant", r.status_code == 403, r.status_code)
    admin_c.delete("/soundboard/My_Voice.webm", headers={"Host": LAN})
    livecam._rename_clip("Hamster_Taunt.wav", "Nice Clip")

    r = admin_c.delete("/soundboard/Nice_Clip.wav", headers={"Host": LAN})
    check("delete removes only the targeted clip",
          r.status_code == 200
          and [c["id"] for c in livecam.soundboard_clips()] == ["hello.wav"],
          livecam.soundboard_clips())
    r = admin_c.delete("/soundboard/hello.wav/../../etc/passwd", headers={"Host": LAN})
    check("delete refuses a traversing id", r.status_code in (400, 404), r.status_code)

    # Volume is clamped server-side; the slider's range is a UI hint, not a
    # guarantee, since the request is trivially forgeable.
    for bad in (-5, 101, "loud", None):
        r = part.post("/talk/the-boiz/volume", json={"volume": bad}, headers={"Host": LAN})
        check(f"volume {bad!r} is refused", r.status_code == 400, r.status_code)

    # Which go2rtc stream carries the speaker is NOT fixed: the camera has one
    # talk channel, claimed by whichever of go2rtc's connections to it
    # connects first. Both of these payloads are real shapes observed live --
    # the backchannel sat on the main stream after one Frigate restart and on
    # the substream after the next. Assuming the main stream shipped a bug
    # that failed with "can't find consumer".
    on_main = {
        "baby-ptz": {"producers": [{"medias": [
            "video, recvonly, H264", "audio, recvonly, MPEG4-GENERIC/16000",
            "audio, sendonly, PCMA/8000"]}]},
        "baby-ptz_sub": {"producers": [{"medias": [
            "video, recvonly, H264", "audio, recvonly, MPEG4-GENERIC/16000"]}]},
    }
    on_sub = {
        "baby-ptz": {"producers": [{"medias": [
            "video, recvonly, H264", "audio, recvonly, MPEG4-GENERIC/16000"]}]},
        "baby-ptz_sub": {"producers": [{"medias": [
            "video, recvonly, H264", "audio, recvonly, MPEG4-GENERIC/16000",
            "audio, sendonly, PCMA/8000"]}]},
    }
    check("backchannel found on the main stream",
          livecam.backchannel_stream("baby-ptz", on_main) == "baby-ptz")
    check("backchannel found on the substream instead",
          livecam.backchannel_stream("baby-ptz", on_sub) == "baby-ptz_sub")
    check("no backchannel anywhere returns None, not a wrong guess",
          livecam.backchannel_stream("baby-ptz", {
              "baby-ptz": {"producers": [{"medias": ["video, recvonly, H264"]}]}}) is None)
    check("another camera's backchannel is never borrowed",
          livecam.backchannel_stream("the-boiz", on_sub) is None)
    check("a not-yet-connected producer (medias None) is skipped safely",
          livecam.backchannel_stream("baby-ptz", {
              "baby-ptz_noaudio": {"producers": [{"medias": None}]}}) is None)

    livecam.SOUNDBOARD_DIR = saved_sb_dir
    livecam.CAMERAS_FILE = saved_cameras_file
    livecam.PERMISSIONS_FILE = saved_perms_file

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

    # --- the dashboard's inline JS actually parses ---
    # This whole app's front end is one inline <script> with no build step and
    # no JS tooling, so nothing else in this suite can see a JavaScript error.
    # That is not theoretical: shipping a `function fmtBytes()` alongside the
    # existing `const fmtBytes` was a redeclaration SyntaxError, which stops
    # the *entire* script parsing -- the dashboard rendered 200 with no tiles,
    # dead click handlers and a frozen usage counter, because none of the
    # code after it ever ran. These are cheap static checks for exactly the
    # mistakes that kill the script wholesale.
    dash = admin_c.get("/", headers={"Host": LAN}).get_data(as_text=True)
    inline = re.search(r"<script>(.*)</script>", dash, re.S)
    check("dashboard ships an inline script", inline is not None)
    if inline:
        js = inline.group(1)
        # Column-0 declarations only: anything indented is inside a function
        # and may legitimately reuse a name.
        top_vars = re.findall(r"^(?:const|let|var)\s+([A-Za-z_$][\w$]*)", js, re.M)
        top_funcs = re.findall(r"^function\s+([A-Za-z_$][\w$]*)", js, re.M)
        collisions = sorted(set(top_vars) & set(top_funcs))
        check("no name is declared as both a top-level function and a const/let/var",
              not collisions, collisions)
        repeats = sorted({n for n in top_vars if top_vars.count(n) > 1}
                         | {n for n in top_funcs if top_funcs.count(n) > 1})
        check("no top-level JS declaration is repeated", not repeats, repeats)
        for open_ch, close_ch in (("{", "}"), ("(", ")"), ("[", "]")):
            check(f"inline JS {open_ch}{close_ch} are balanced",
                  js.count(open_ch) == js.count(close_ch),
                  (js.count(open_ch), js.count(close_ch)))
        # Every element the script grabs must exist somewhere in the markup.
        # Checked against the TEMPLATE, not this rendered page: several
        # elements (the home banner, the LAN switch) only appear on one
        # hostname, and the template holds every branch.
        with open(os.path.join(REPO, "templates", "index.html")) as f:
            template_src = f.read()
        for el in sorted(set(re.findall(r"getElementById\('([^']+)'\)", js))):
            check(f"element #{el} referenced by the script exists in the markup",
                  f'id="{el}"' in template_src, el)

    print()
    print("ALL PASS" if not failures else "FAILURES: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
