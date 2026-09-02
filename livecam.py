"""
livecam -- the front door to the camera stack.

Two backends on the frigate VM, deliberately split by what each is good at:

  * go2rtc  -- live view. It remuxes the camera's existing H.264 without
               decoding, which is why live view is cheap.
  * Frigate -- recording, retention, the scrub timeline and export. It
               ships the go2rtc above and records through it, so one
               connection per camera serves both jobs.

livecam owns authentication. Users log in here, against accounts declared
in permissions.yml, and Frigate's own login is disabled in favour of proxy
authentication -- livecam passes the username on. One account per person.

This replaced ZoneMinder, which recorded correctly but was event-oriented
rather than timeline-oriented (no continuous scrub bar, no live previews)
and required a second login of its own.

On top of that, this app enforces what the backends have no concept of:
per-user camera lists, a per-user time-of-day window, true per-user audio
gating, a separate grant for the recorded archive, and (for cameras that
support it) PTZ control.

PTZ is deliberately NOT routed through Frigate. Live view already bypasses
it entirely -- video comes straight from go2rtc talking to the camera's own
RTSP endpoint -- and camera control follows the same "direct to camera"
half of the app via ONVIF, rather than adding a dependency on Frigate being
up, configured, or even aware a given camera exists.

Neither backend is reachable from outside the LAN; only this app is. So the
permission checks can't be bypassed by hitting go2rtc, Frigate, or a camera
directly.
"""

import asyncio
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, time as dtime, timezone
from functools import wraps

import requests
import yaml
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, send_file, session, stream_with_context, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from onvif import ONVIFCamera
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("livecam")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

# Session cookie hardening. Secure is opt-in rather than on by default
# because plain HTTP to this container is a supported path, not an accident:
# nginx-proxy runs with HTTPS_METHOD=noredirect so http:// keeps working,
# and the public route arrives from the AWS relay over HTTP. Forcing Secure
# without that being true end to end means the browser withholds the cookie
# and login silently loops forever -- a much worse failure than the one it
# prevents on a home LAN.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower()
    in ("1", "true", "yes"),
)

FRIGATE_URL = os.environ["FRIGATE_URL"].rstrip("/")
GO2RTC_URL = os.environ["GO2RTC_URL"].rstrip("/")
PERMISSIONS_FILE = os.environ.get("PERMISSIONS_FILE", "/app/config/permissions.yml")
# Which cameras support PTZ and how to reach them over ONVIF. Deliberately a
# separate file from permissions.yml -- that file is about who may see what,
# this one is infrastructure (an IP and a port), and conflating the two would
# mean a permissions edit could accidentally touch camera wiring or vice
# versa. Empty/absent entries are the common case: today's fleet has no PTZ
# hardware, so this file is expected to declare nothing.
CAMERAS_FILE = os.environ.get("CAMERAS_FILE", "/app/config/cameras.yml")
# Assumed to be the same admin account already used for RTSP on this camera
# family -- unverified until a real PTZ camera confirms it. If a camera ever
# needs a separate ONVIF account, that becomes a per-camera override in
# CAMERAS_FILE rather than a second pair of these.
CAMERA_USERNAME = os.environ.get("CAMERA_USERNAME")
CAMERA_PASSWORD = os.environ.get("CAMERA_PASSWORD")

# --- Soundboard / talking to a camera's speaker -----------------------------
# Clips live on the one writable mount (/opt/livecam/data on the host), NOT
# beside the read-only configs, so they survive the container being recreated
# on every CI/CD deploy.
SOUNDBOARD_DIR = os.environ.get("SOUNDBOARD_DIR", "/app/data/soundboard")
SOUNDBOARD_MAX_BYTES = int(os.environ.get("SOUNDBOARD_MAX_BYTES", str(5 * 1024 ** 2)))
# Whatever the browser can record or a person is likely to upload. go2rtc's
# ffmpeg does the decode, so this list is about refusing obvious junk rather
# than about what can be played.
SOUNDBOARD_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".oga", ".opus", ".aac", ".webm", ".flac"}
# Content types for in-browser preview. The go2rtc handoff deliberately does
# NOT use these -- ffmpeg probes the bytes itself -- but an <audio> element
# needs a real type before it will admit it can play a clip at all.
SOUNDBOARD_MIME = {
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4",
    ".aac": "audio/aac", ".ogg": "audio/ogg", ".oga": "audio/ogg",
    ".opus": "audio/ogg", ".webm": "audio/webm", ".flac": "audio/flac",
}

# go2rtc fetches clips over HTTP by URL, because it runs on the Frigate VM and
# cannot see this container's filesystem. It therefore needs an address that
# resolves from *there*, not from the browser -- hence its own setting rather
# than reusing a request's Host header.
_lan_host_env = os.environ.get("LAN_HOSTNAME", "")
TALK_CLIP_BASE_URL = os.environ.get(
    "TALK_CLIP_BASE_URL", f"http://{_lan_host_env}" if _lan_host_env else ""
).rstrip("/")
# How long a signed clip URL stays valid. Only has to outlive one go2rtc fetch.
TALK_CLIP_TTL_SECONDS = int(os.environ.get("TALK_CLIP_TTL_SECONDS", "120"))
# These cameras expose exactly ONE talk channel, already held open by go2rtc's
# main connection, so two overlapping plays would fight over it. Playback is
# serialised per camera and rate-limited rather than queued: a soundboard is
# for one deliberate sound at a time, and dropping a double-tap is friendlier
# than stacking noises in a room.
TALK_MIN_GAP_SECONDS = float(os.environ.get("TALK_MIN_GAP_SECONDS", "1.5"))

# Which hostname served this request decides two things: whether to nudge the
# viewer towards the LAN URL, and whether the bytes count as billable AWS
# egress. Both hang off the same signal.
PUBLIC_HOSTNAME = os.environ.get("PUBLIC_HOSTNAME", "")
LAN_HOSTNAME = os.environ.get("LAN_HOSTNAME", "")

# A full-resolution viewer costs ~7 Mbps (~2.95 GB/hour). Past this many
# *concurrent full-quality* streams the home uplink, not the CPU, becomes
# the limit -- roughly 70 Mbps at ten viewers, more than many connections
# have. Rather than let a spike stutter for everyone, further expands are
# served the substream instead. Grid tiles are already substream and are
# never capped.
MAX_FULL_QUALITY_SESSIONS = int(os.environ.get("MAX_FULL_QUALITY_SESSIONS", "4"))

# An abandoned tab is the real cost risk, not active watching: left running
# overnight one stream is ~35 GB. The browser pings /api/heartbeat while the
# viewer is actually present; once pings stop the stream is torn down
# server-side, so closing a laptop lid ends the transfer rather than merely
# stopping the prompt.
HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get("HEARTBEAT_TIMEOUT_SECONDS", "600"))

# How long a viewer can be idle before the page stops streaming and asks
# whether they are still watching. Slightly under the server-side timeout so
# the browser gives up first and the teardown is graceful rather than the
# stream being cut mid-request.
IDLE_PROMPT_SECONDS = int(os.environ.get("IDLE_PROMPT_SECONDS", str(max(60, HEARTBEAT_TIMEOUT_SECONDS - 120))))

# On the LAN none of the above applies: the whole point of the idle prompt is
# that an abandoned tab quietly bills AWS egress, and LAN traffic costs
# nothing. So the nag is pure cost with no benefit there.
#
# Not disabled outright, though -- an abandoned tab still holds a go2rtc
# connection open, so 8 hours bounds that while being long enough that nobody
# meets the dialog in practice.
LAN_IDLE_PROMPT_SECONDS = int(os.environ.get("LAN_IDLE_PROMPT_SECONDS", str(8 * 60 * 60)))
# The browser must give up BEFORE the server or teardown happens mid-request
# rather than gracefully, so the two move together -- see the comment on
# HEARTBEAT_TIMEOUT_SECONDS above.
LAN_HEARTBEAT_TIMEOUT_SECONDS = LAN_IDLE_PROMPT_SECONDS + 600


def idle_settings():
    """(idle_prompt, heartbeat_timeout) for the route this request came in on."""
    if is_public_request():
        return IDLE_PROMPT_SECONDS, HEARTBEAT_TIMEOUT_SECONDS
    return LAN_IDLE_PROMPT_SECONDS, LAN_HEARTBEAT_TIMEOUT_SECONDS


def display_name(camera):
    """Human label for a camera, derived from its slug.

    Machine names have to be URL- and path-safe because they become go2rtc
    stream names and Frigate recording directories, so the pretty form is
    derived rather than stored: `the-boiz` -> `The Boiz`. Keeping it derived
    means there is no second list to drift out of step as cameras are added.
    An explicit `_display_names` map in permissions.yml overrides it for any
    name that does not title-case well.
    """
    override = (load_permissions().get("_display_names") or {}).get(camera)
    return override or camera.replace("-", " ").replace("_", " ").title()

_sessions_lock = threading.Lock()
_live_sessions = {}  # stream_token -> {"seen": epoch, "user": username}

# In-flight full-quality streams, so the cap below counts what is actually
# being transferred rather than how many people have a page open. Tiles are
# never counted -- they are cheap enough that grid viewing never needs
# capping.
_full_streams = set()

# --------------------------------------------------------------------------
# Egress accounting
#
# Counts bytes this app served *via the public hostname only*. Traffic over
# the LAN hostname never leaves the house and is free, so counting it would
# make the number meaningless for its one purpose: knowing how much of AWS's
# 100 GB/month free tier the cameras have eaten.
#
# Deliberately a lower bound on the account's real egress, not a substitute
# for it -- other services on this host egress too, and AWS also bills
# things this app never sees. Camera video dwarfs the rest here, which is
# what makes the number useful, but the UI says "camera traffic" rather than
# implying it is the whole bill.
#
# Keyed by UTC YYYY-MM to match how AWS bills, so the month rolls over by
# arithmetic. There is nothing to schedule and therefore nothing to miss if
# the container happens to be down at midnight on the 1st.
# --------------------------------------------------------------------------
EGRESS_DB = os.environ.get("EGRESS_DB", "/app/data/egress.db")
FREE_TIER_BYTES = int(os.environ.get("FREE_TIER_BYTES", str(100 * 1024 ** 3)))

# Streaming video would otherwise mean an sqlite write every 64 KB chunk --
# hundreds per second per viewer. Accumulate in memory and flush on size or
# age, whichever comes first, plus unconditionally when a stream ends.
EGRESS_FLUSH_BYTES = int(os.environ.get("EGRESS_FLUSH_BYTES", str(8 * 1024 ** 2)))
EGRESS_FLUSH_SECONDS = int(os.environ.get("EGRESS_FLUSH_SECONDS", "60"))

_egress_lock = threading.Lock()
_egress_pending = 0
_egress_last_flush = 0.0

# Live per-connection byte counter for the overlay's rate/total display --
# unlike record_egress() above (a global monthly aggregate with no
# per-stream dimension), this is keyed per browser-generated connection id
# so exactly one stream's own bytes are reported back to it. Swept lazily
# on read rather than via a background thread, the same shape
# _prune_hls_sessions() below already uses for _hls_sessions.
STREAM_USAGE_TTL_SECONDS = int(os.environ.get("STREAM_USAGE_TTL_SECONDS", "300"))
_stream_bytes_lock = threading.Lock()
_stream_bytes = {}  # conn_id -> {"bytes": int, "seen": epoch}
_CONN_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def _sanitize_conn_id(value):
    """A validated conn id, or None. It rides through a rewritten HLS
    playlist body as plain text (see live_hls()/hls_proxy()), so an
    unvalidated client-supplied value could otherwise inject extra lines or
    break the m3u8 format -- the client only ever sends crypto.randomUUID(),
    so this is deliberately narrow rather than permissive."""
    if value and _CONN_ID_RE.match(value):
        return value
    return None


def _record_stream_bytes(conn_id, count):
    if not conn_id:
        return
    with _stream_bytes_lock:
        entry = _stream_bytes.setdefault(conn_id, {"bytes": 0, "seen": 0.0})
        entry["bytes"] += count
        entry["seen"] = time.time()


def _stream_bytes_for(conn_id):
    cutoff = time.time() - STREAM_USAGE_TTL_SECONDS
    with _stream_bytes_lock:
        for cid in [c for c, v in _stream_bytes.items() if v["seen"] < cutoff]:
            del _stream_bytes[cid]
        entry = _stream_bytes.get(conn_id)
        return entry["bytes"] if entry else 0


def _egress_conn():
    directory = os.path.dirname(EGRESS_DB)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(EGRESS_DB, timeout=10)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS egress (month TEXT PRIMARY KEY, bytes INTEGER NOT NULL)"
    )
    return conn


def _current_month():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def record_egress(count, flush=False):
    """Add bytes to this month's total, flushing to sqlite when it's worth it."""
    global _egress_pending, _egress_last_flush

    with _egress_lock:
        _egress_pending += max(int(count), 0)
        if _egress_pending == 0:
            return
        due = (
            flush
            or _egress_pending >= EGRESS_FLUSH_BYTES
            or time.time() - _egress_last_flush >= EGRESS_FLUSH_SECONDS
        )
        if not due:
            return
        batch, _egress_pending = _egress_pending, 0
        _egress_last_flush = time.time()

    try:
        conn = _egress_conn()
        with conn:
            conn.execute(
                "INSERT INTO egress (month, bytes) VALUES (?, ?) "
                "ON CONFLICT(month) DO UPDATE SET bytes = bytes + excluded.bytes",
                (_current_month(), batch),
            )
        conn.close()
    except Exception:
        # Put the batch back rather than dropping it -- an unwritable volume
        # should make the counter lag, not silently under-report.
        with _egress_lock:
            _egress_pending += batch
        log.exception("egress flush failed (%d bytes deferred)", batch)


def egress_this_month():
    """Bytes served publicly this month, including what hasn't been flushed."""
    stored = 0
    try:
        conn = _egress_conn()
        row = conn.execute(
            "SELECT bytes FROM egress WHERE month = ?", (_current_month(),)
        ).fetchone()
        conn.close()
        stored = row[0] if row else 0
    except Exception:
        log.exception("egress read failed")
    with _egress_lock:
        return stored + _egress_pending


def lan_switch_context():
    """Template variables for the "you could be on the LAN" behaviour.

    Only meaningful on the public hostname, and only when a LAN hostname
    exists to offer. Both the banner and the reachability probe hang off
    this, so they can never disagree about which route the viewer is on.
    """
    offer = is_public_request() and bool(LAN_HOSTNAME)
    return {
        "offer_lan": offer,
        "lan_hostname": LAN_HOSTNAME,
        "lan_url": f"https://{LAN_HOSTNAME}/" if LAN_HOSTNAME else None,
        "lan_ping_url": f"https://{LAN_HOSTNAME}/api/ping" if LAN_HOSTNAME else None,
    }


def is_public_request():
    """True when this request arrived on the internet-facing hostname.

    request.host is the Host header nginx-proxy matched the vhost on, so it
    distinguishes the two names even though both land on the same container.
    """
    if not PUBLIC_HOSTNAME:
        return False
    return request.host.split(":")[0].lower() == PUBLIC_HOSTNAME.lower()


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------

# Compared against when the username is unknown, so a bad username and a bad
# password cost the same time and look the same from outside. Without it the
# response time alone tells an attacker which accounts exist.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))

# Crude, deliberately in-memory brute-force brake. Not a substitute for a
# real rate limiter, but this app is one process behind one proxy for a
# handful of family accounts, and it turns online guessing from thousands of
# tries per minute into a handful.
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "10"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))
_login_lock = threading.Lock()
_login_failures = {}  # client ip -> [failure count, window start epoch]


def load_permissions():
    with open(PERMISSIONS_FILE) as f:
        return yaml.safe_load(f) or {}


def load_camera_config():
    """PTZ-capable cameras and their ONVIF connection details.

    Read fresh on every call, like load_permissions() -- a camera can be
    added without restarting the container.

    Deliberately fails open to "no PTZ cameras configured" for ANY read
    problem, not just a missing file. A live deploy hit exactly this: the
    volume mount's host-side file did not exist yet when the container was
    created, so Docker silently bind-mounted an empty directory in its
    place, and `open()` raised IsADirectoryError -- an error shape this
    function did not originally handle, which took down the *entire*
    dashboard (every route calls this, not just the PTZ ones) over a
    feature that is supposed to be optional and inert until real hardware
    exists. A malformed or wrong-type config file for an add-on capability
    must never be able to break the rest of the app; logging a warning and
    treating it as "no PTZ" is the honest degraded state, not a 500.
    """
    try:
        with open(CAMERAS_FILE) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        # The expected steady state until real PTZ hardware exists -- not
        # worth a log line every time it's read.
        return {}
    except OSError:
        # A directory where a file should be, permissions, anything else --
        # unexpected, so worth a log line, but degrades the same way as a
        # missing file rather than taking the app down over an add-on
        # feature that is supposed to be optional.
        log.warning("cameras config unreadable at %s", CAMERAS_FILE, exc_info=True)
        return {}
    except yaml.YAMLError:
        log.warning("cameras config is not valid YAML at %s", CAMERAS_FILE, exc_info=True)
        return {}
    if not isinstance(data, dict):
        log.warning("cameras config at %s is not a mapping (got %s)",
                   CAMERAS_FILE, type(data).__name__)
        return {}
    cameras = data.get("cameras") or {}
    return cameras if isinstance(cameras, dict) else {}


def _capable_cameras(flag, default):
    """Camera names whose cameras.yml entry enables `flag` -- the config-side gate.

    Independent of any user's permission grant: both are required. A camera
    absent here has the capability regardless of what any permissions.yml
    entry says, and a user without the grant can't reach a camera that is
    present here either.

    `default` exists because `ptz` predates any capability flags: every entry
    in cameras.yml was, by definition, a PTZ camera, so presence alone meant
    PTZ and existing entries have no `ptz:` key to read. Newer capabilities
    default off, so declaring a talk-only camera doesn't silently hand it PTZ.
    """
    return {
        name for name, config in load_camera_config().items()
        if (config or {}).get(flag, default)
    }


def ptz_capable_cameras():
    """Camera names with PTZ declared. Defaults on for backwards compatibility
    -- see _capable_cameras()."""
    return _capable_cameras("ptz", True)


def talk_capable_cameras():
    """Camera names with a speaker declared (`talk: true` in cameras.yml).

    Defaults off, unlike PTZ: a camera having an ONVIF/PTZ entry says nothing
    about whether it has a speaker, and pushing audio at one that doesn't
    should not be reachable by accident.
    """
    return _capable_cameras("talk", False)


def user_entries(permissions):
    """The user records in permissions.yml, minus the `_`-prefixed metadata."""
    return {
        name: entry
        for name, entry in permissions.items()
        if isinstance(name, str) and not name.startswith("_") and isinstance(entry, dict)
    }


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "unknown"


def _login_blocked(ip):
    with _login_lock:
        record = _login_failures.get(ip)
        if not record:
            return False
        count, started = record
        if time.time() - started > LOGIN_LOCKOUT_SECONDS:
            del _login_failures[ip]
            return False
        return count >= LOGIN_MAX_FAILURES


def _note_login_failure(ip):
    with _login_lock:
        count, started = _login_failures.get(ip, [0, time.time()])
        if time.time() - started > LOGIN_LOCKOUT_SECONDS:
            count, started = 0, time.time()
        _login_failures[ip] = [count + 1, started]


def verify_login(username, password):
    """Check credentials against permissions.yml. Returns True/False only."""
    entry = user_entries(load_permissions()).get(username or "")
    stored = (entry or {}).get("password_hash")
    # Always hash-compare, even for an unknown user or one with no hash set,
    # so the work done is identical either way.
    ok = check_password_hash(stored or _DUMMY_HASH, password or "")
    return bool(stored) and ok


def current_user():
    return session.get("user")


def _safe_next(target):
    """Only allow same-site relative redirects -- never an absolute URL."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return None
    return target


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user():
            return view(*args, **kwargs)
        # A browser navigating should land on the login form; anything else
        # (the video element, fetch) gets a status it can act on rather than
        # an HTML page it will try to decode as video.
        if request.method == "GET" and "text/html" in request.headers.get("Accept", ""):
            return redirect(url_for("login", next=_safe_next(request.full_path)))
        abort(401)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    target = _safe_next(request.values.get("next")) or "/"

    if request.method == "POST":
        ip = _client_ip()
        if _login_blocked(ip):
            log.warning("login throttled ip=%s", ip)
            error = "Too many attempts. Try again in a few minutes."
        else:
            username = (request.form.get("username") or "").strip()
            if verify_login(username, request.form.get("password")):
                session.clear()
                session["user"] = username
                session.permanent = False
                with _login_lock:
                    _login_failures.pop(ip, None)
                log.info("login ok user=%s ip=%s", username, ip)
                return redirect(target)
            _note_login_failure(ip)
            log.warning("login failed user=%s ip=%s", username, ip)
            error = "Incorrect username or password."

    # Offered here too, not just on the dashboard: someone who switches
    # before typing their password needs no handoff token at all, because
    # they log in on the LAN origin to begin with.
    return render_template("login.html", error=error, next=target,
                           **lan_switch_context()), (
        200 if request.method == "GET" else 401
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Moving a viewer from the public route onto the LAN route
#
# The public page probes the LAN hostname and offers to switch. Both names
# reach this same container, but they are different origins, so the session
# cookie does not follow -- and sending someone from a working page to a
# login form is worse than leaving them where they were.
#
# The alternative was a cookie scoped to `.levantine.io`, which would have
# handed livecam's session cookie to every other app on the domain. A
# single-use signed token costs a few lines and leaks nothing.
# --------------------------------------------------------------------------
HANDOFF_MAX_AGE_SECONDS = int(os.environ.get("HANDOFF_MAX_AGE_SECONDS", "60"))
_handoff_lock = threading.Lock()
_handoff_used = set()


def _handoff_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="livecam-handoff")


@app.route("/api/ping")
def ping():
    """Reachability probe. Deliberately unauthenticated and empty.

    The public page uses this to find out whether the LAN address is
    reachable from wherever the viewer currently is. It has to answer
    cross-origin to be useful, so it says nothing at all beyond "something
    is listening here" -- no body, no session, no data.
    """
    resp = Response(status=204)
    if PUBLIC_HOSTNAME:
        resp.headers["Access-Control-Allow-Origin"] = f"https://{PUBLIC_HOSTNAME}"
        resp.headers["Vary"] = "Origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/handoff", methods=["POST"])
@login_required
def handoff_token():
    """Mint a short-lived token that moves this session to the other hostname."""
    token = _handoff_serializer().dumps(current_user())
    return jsonify({"token": token, "max_age": HANDOFF_MAX_AGE_SECONDS})


@app.route("/handoff")
def handoff():
    """Consume a handoff token and start a session for the named user."""
    token = request.args.get("t", "")
    try:
        username = _handoff_serializer().loads(
            token, max_age=HANDOFF_MAX_AGE_SECONDS
        )
    except SignatureExpired:
        log.warning("handoff token expired")
        return redirect(url_for("login"))
    except BadSignature:
        log.warning("handoff token invalid")
        return redirect(url_for("login"))

    # Single use. One gunicorn worker holds all of this, which is the same
    # reason live-stream tokens work at all here.
    with _handoff_lock:
        if token in _handoff_used:
            log.warning("handoff token replayed user=%s", username)
            return redirect(url_for("login"))
        _handoff_used.add(token)
        # The set only needs to outlive the token's own validity window.
        if len(_handoff_used) > 512:
            _handoff_used.clear()

    # A token names a user who may since have been removed from
    # permissions.yml, so re-check rather than trusting the signature alone.
    if username not in user_entries(load_permissions()):
        log.warning("handoff for unknown user=%s", username)
        return redirect(url_for("login"))

    session.clear()
    session["user"] = username
    log.info("handoff accepted user=%s host=%s", username, request.host)
    return redirect("/")


def _intersect_grant(cameras, value):
    """Resolve a true/false/list-shaped grant against the cameras a user may see.

    Shared by `audio`, `ptz` and `talk`, which all follow the same shape:

        true                 -> every permitted camera
        false                -> none
        [the-boiz, baby-cam] -> only those, intersected with `cameras`

    The intersection is the load-bearing part: naming a camera under either
    grant that the user cannot see must grant nothing. Neither can become a
    way to reach a camera the allow-list withheld.
    """
    if isinstance(value, (list, tuple, set)):
        return cameras & set(value)
    return set(cameras) if value else set()


def check_permission(username, permissions, now=None):
    """Return (allowed_cameras, audio_cameras, ptz_cameras, talk_cameras) for this user now.

    The time window is evaluated per request, not once at login, so a lapsed
    grant actually cuts a stream (or PTZ control, or the ability to push audio
    at a camera) off mid-session.
    """
    now = now or datetime.now()
    user_perms = user_entries(permissions).get(username)
    if not user_perms:
        return set(), set(), set(), set()

    window = user_perms.get("time_window")
    if window:
        start = dtime.fromisoformat(window["start"])
        end = dtime.fromisoformat(window["end"])
        if not (start <= now.time() <= end):
            return set(), set(), set(), set()

    cameras = set(user_perms.get("cameras", []))
    audio_cameras = _intersect_grant(cameras, user_perms.get("audio", False))
    ptz_cameras = _intersect_grant(cameras, user_perms.get("ptz", False))
    talk_cameras = _intersect_grant(cameras, user_perms.get("talk", False))
    return cameras, audio_cameras, ptz_cameras, talk_cameras


def _prune_stale_sessions():
    # Each session carries its own timeout: a LAN viewer gets hours, a public
    # one keeps the tight cost-control window, and both live in this same
    # process at the same time.
    now = time.time()
    with _sessions_lock:
        for token in [t for t, s in _live_sessions.items()
                      if now - s["seen"] > s.get("timeout", HEARTBEAT_TIMEOUT_SECONDS)]:
            del _live_sessions[token]
        return len(_live_sessions)


def resolve_stream_name(camera, audio_allowed, quality, want_audio=False):
    """Map (camera, permissions, requested quality) onto a go2rtc stream.

    Audio is opt-in per request, not implied by permission. The expanded
    view froze on its first frame for exactly this reason: it was handed an
    unmuted stream carrying an AAC track, and browsers block audible
    autoplay, so the element buffered ~7 Mbps of perfectly good video (the
    server logs show it delivered 10-18 MB per attempt) and never rendered
    it. Tiles worked throughout because they are muted and audio-free.
    Serving audio only when the viewer has actually asked for it -- by
    pressing a control, which is the user gesture the autoplay policy wants
    -- makes the default case behave like the tiles that already work.

    `audio_allowed` still has the final say, so asking for audio without
    permission gets the stripped stream rather than an error.

    Audio gating is enforced by *which stream is requested*: the `_noaudio`
    variants are published by go2rtc with the audio track genuinely removed
    (verified against a live camera -- the track list is video-only, not
    merely muted), so a user without audio permission cannot receive audio
    even if they tamper with the client.

    Grid tiles get the camera's own 704x480 substream (~0.65 Mbps) rather
    than the full 2960x1668 feed (~7.04 Mbps) -- about 11x cheaper, which
    matters because remote viewers traverse the home uplink and billed AWS
    egress. There is no server-side downscale involved: changing resolution
    means decode + scale + re-encode, the workload that previously pinned
    the NVR host. The camera encodes the substream itself, so it is free.

    Tiles are always muted, so they take the audio-free substream too --
    that way a tile genuinely cannot carry audio rather than relying on the
    client honouring a `muted` attribute.
    """
    if quality != "full":
        return f"{camera}_sub_noaudio"
    return camera if (audio_allowed and want_audio) else f"{camera}_noaudio"


@app.route("/api/heartbeat", methods=["POST"])
@login_required
def heartbeat():
    """Keeps a live session alive; stops being called when the viewer goes away."""
    token = request.json.get("token") if request.is_json else None
    if not token:
        abort(400)
    with _sessions_lock:
        entry = _live_sessions.get(token)
        if entry and entry["user"] == current_user():
            entry["seen"] = time.time()
    return jsonify({"ok": True})


@app.route("/api/usage")
@login_required
def usage():
    """Current month's public egress, for the dashboard meter to poll."""
    used = egress_this_month()
    return jsonify(
        {
            "month": _current_month(),
            "bytes": used,
            "free_tier_bytes": FREE_TIER_BYTES,
            "remaining_bytes": max(FREE_TIER_BYTES - used, 0),
        }
    )


@app.route("/api/stream-usage")
@login_required
def stream_usage():
    """Bytes sent so far for one overlay connection, for its live rate/total
    display. An unrecognised or missing id -- already ended, never existed,
    or invalid -- is reported as zero rather than a 404: the poller can't
    tell those apart from "hasn't sent anything yet" and shouldn't need to."""
    conn_id = _sanitize_conn_id(request.args.get("conn"))
    return jsonify({"bytes": _stream_bytes_for(conn_id) if conn_id else 0})


# --------------------------------------------------------------------------
# HLS, for Safari and every browser on iOS
#
# The fragmented-MP4 path this app was built on does not work on iOS at all
# -- not the tiles, not the expanded view. iOS Safari opens a <video> with a
# Range request and expects 206; go2rtc answers 200 with a chunked body, and
# Safari then refuses to play. Verified on a real iPhone: even tapping the
# element does nothing, which rules out autoplay policy as the cause.
#
# HLS is the native answer there, and go2rtc already speaks it. Two details
# were found the hard way and are the reason this is not simply a proxy:
#
#   * The `_noaudio` streams must NOT be used here. They are ffmpeg chains
#     (`ffmpeg:<src>#video=copy`), and go2rtc's MPEG-TS muxer loses the H.264
#     parameter sets across that chain -- the segments decode with continuous
#     "non-existing PPS" errors, while the direct stream is clean. MP4 never
#     showed it because SPS/PPS live in the container header there.
#   * Audio is instead excluded with go2rtc's own track filter: asking for
#     `video=h264` alone yields a video-only playlist. So gating still comes
#     from the URL this server builds, never from the client.
#
# Segment URLs inside a media playlist are relative, so a playlist served at
# /hls/playlist.m3u8 makes the browser ask for /hls/segment.ts -- which is
# this same route. Nothing needs rewriting except the master playlist.
# --------------------------------------------------------------------------
M3U8_CONTENT_TYPE = "application/vnd.apple.mpegurl"

# go2rtc mints a session id per master-playlist request. Mapping it back to a
# user and camera is what lets the playlist and segment requests below be
# authorised, since they carry only that id.
HLS_SESSION_TTL_SECONDS = int(os.environ.get("HLS_SESSION_TTL_SECONDS", "300"))
# How recently a session must have fetched something to count as "someone is
# watching this right now". Segments arrive every ~0.5s, so this is generous
# while still forgetting a closed tab almost immediately.
HLS_ACTIVE_SECONDS = int(os.environ.get("HLS_ACTIVE_SECONDS", "30"))
_hls_lock = threading.Lock()
_hls_sessions = {}  # go2rtc id -> {"user", "camera", "quality", "metered", "seen"}


def resolve_hls_source(camera, audio_allowed, quality, want_audio=False):
    """go2rtc (src, params) for HLS -- direct streams plus a track filter.

    Mirrors resolve_stream_name()'s decisions, but expresses "no audio" as
    the absence of an audio track filter rather than by selecting a
    separately published stream. Same guarantee, different mechanism: the
    server decides, and a client asking for audio it may not have simply
    does not get an audio track in the playlist.
    """
    params = {"video": "h264"}
    if quality != "full":
        return f"{camera}_sub", params
    if audio_allowed and want_audio:
        params["audio"] = "aac"
    return camera, params


def _prune_hls_sessions():
    cutoff = time.time() - HLS_SESSION_TTL_SECONDS
    with _hls_lock:
        for sid in [s for s, v in _hls_sessions.items() if v["seen"] < cutoff]:
            del _hls_sessions[sid]


def _authorise_hls(session_id):
    """Resolve an HLS session id to its owner, re-checking permission.

    Re-checked per request rather than trusted from playlist time, so a
    closing time window ends an iOS stream the same way it cuts an MP4 one
    off mid-transfer.
    """
    if not session_id:
        abort(403)
    with _hls_lock:
        entry = _hls_sessions.get(session_id)
        if not entry or entry["user"] != current_user():
            abort(403)
        entry["seen"] = time.time()
        camera, metered = entry["camera"], entry["metered"]

    allowed, _, _, _ = check_permission(current_user(), load_permissions())
    if camera not in allowed:
        abort(403)
    return camera, metered


@app.route("/live/<camera>/master.m3u8")
@login_required
def live_hls(camera):
    """Master playlist: authorise, ask go2rtc, and point at our own routes.

    Deliberately a separate path from /live/<camera> rather than
    /live/<camera>.m3u8 -- the latter would also match the MP4 rule with the
    suffix swallowed into the camera name.
    """
    username = current_user()
    allowed_cameras, audio_cameras, _, _ = check_permission(username, load_permissions())
    if camera not in allowed_cameras:
        abort(403)

    token = request.args.get("token")
    with _sessions_lock:
        entry = _live_sessions.get(token) if token else None
        if not entry or entry["user"] != username:
            abort(403)

    quality = "full" if request.args.get("quality") == "full" else "sub"
    want_audio = request.args.get("audio") == "1"
    _prune_hls_sessions()

    # Same cap as the MP4 path, but HLS has no connection to count, so it
    # counts sessions seen very recently instead. The window matters: a
    # player pulls a segment every half second, so anything still streaming
    # is seen constantly, while a closed tab stops appearing immediately.
    # Counting over the full session TTL instead made four expands in five
    # minutes silently downgrade the fifth to the substream long after
    # nobody was watching them -- observed while testing.
    if quality == "full":
        active_since = time.time() - HLS_ACTIVE_SECONDS
        with _hls_lock:
            active_full = sum(
                1 for v in _hls_sessions.values()
                if v["quality"] == "full" and v["seen"] >= active_since
            )
        if active_full >= MAX_FULL_QUALITY_SESSIONS:
            log.info("hls full-quality cap reached (%d active); serving substream",
                     active_full)
            quality = "sub"

    src, params = resolve_hls_source(camera, camera in audio_cameras, quality, want_audio)
    upstream = requests.get(
        f"{GO2RTC_URL}/api/stream.m3u8", params={"src": src, **params}, timeout=15
    )
    if upstream.status_code != 200:
        log.warning("hls master failed camera=%s status=%s", camera, upstream.status_code)
        abort(502)

    # The master points at `hls/playlist.m3u8?id=SESSION`; rewrite that one
    # line to our own route so the browser never talks to go2rtc directly.
    # conn (the overlay's own rate/total connection id, absent for tiles)
    # rides along here too -- hls_proxy() picks it up from this same line
    # and re-attaches it to every segment reference it hands back in turn,
    # so it keeps propagating without go2rtc ever knowing about it.
    conn_id = _sanitize_conn_id(request.args.get("conn"))
    metered = is_public_request()
    session_ids = []
    lines = []
    for line in upstream.text.splitlines():
        match = re.match(r"^hls/playlist\.m3u8\?id=(\w+)$", line.strip())
        if match:
            session_ids.append(match.group(1))
            playlist_url = f"/hls/playlist.m3u8?id={match.group(1)}"
            if conn_id:
                playlist_url += f"&conn={conn_id}"
            lines.append(playlist_url)
        else:
            lines.append(line)

    if not session_ids:
        log.warning("hls master had no playlist line camera=%s", camera)
        abort(502)

    with _hls_lock:
        for sid in session_ids:
            _hls_sessions[sid] = {
                "user": username,
                "camera": camera,
                "quality": quality,
                "metered": metered,
                "seen": time.time(),
            }

    log.info("hls start camera=%s src=%s audio=%s quality=%s user=%s metered=%s",
             camera, src, "aac" in params.values(), quality, username, metered)

    body = "\n".join(lines) + "\n"
    if metered:
        record_egress(len(body))
    resp = Response(body, content_type=M3U8_CONTENT_TYPE)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Livecam-Stream"] = f"{src}{'+aac' if 'audio' in params else ''}"
    return resp


@app.route("/hls/<path:sub>")
@login_required
def hls_proxy(sub):
    """Media playlists and segments, authorised by the go2rtc session id.

    Segment references inside a media playlist are relative, so the `id`
    they're authorised by resolves back here without needing to be
    rewritten -- the only rewriting this does is appending `conn` (the
    overlay's own rate/total id, when present) to each one, since go2rtc
    has no idea that parameter exists.
    """
    if ".." in sub or sub.startswith("/"):
        abort(400)

    camera, metered = _authorise_hls(request.args.get("id"))
    conn_id = _sanitize_conn_id(request.args.get("conn"))

    upstream = requests.get(
        f"{GO2RTC_URL}/api/hls/{sub}",
        params=request.args,
        stream=True,
        timeout=15,
    )
    body = upstream.content

    # Media playlists reference their own segments with the same ?id=...
    # this request carried (see live_hls()'s comment) -- conn needs the same
    # treatment so it keeps propagating to every segment fetch the browser
    # makes on its own, not just this one response.
    if conn_id and sub.endswith(".m3u8"):
        text = body.decode("utf-8", errors="replace")
        lines = [
            f"{line}&conn={conn_id}" if line.strip() and not line.startswith("#") else line
            for line in text.splitlines()
        ]
        body = ("\n".join(lines) + "\n").encode("utf-8")

    if metered:
        record_egress(len(body), flush=sub.endswith(".m3u8"))
    _record_stream_bytes(conn_id, len(body))

    content_type = upstream.headers.get(
        "Content-Type",
        M3U8_CONTENT_TYPE if sub.endswith(".m3u8") else "video/mp2t",
    )
    resp = Response(body, upstream.status_code, content_type=content_type)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/live/<camera>")
@login_required
def live(camera):
    username = current_user()

    permissions = load_permissions()
    allowed_cameras, audio_cameras, _, _ = check_permission(username, permissions)
    if camera not in allowed_cameras:
        abort(403)

    # The token is issued by the dashboard so the page has something to
    # heartbeat against. Minting one here per request would leave the
    # browser unable to keep its own stream alive. It is bound to the user
    # who minted it, so a leaked token is useless to another account.
    token = request.args.get("token")
    with _sessions_lock:
        entry = _live_sessions.get(token) if token else None
        known = bool(entry) and entry["user"] == username
    if not known:
        abort(403)

    _prune_stale_sessions()

    # Only traffic on the public hostname costs anything; LAN viewing is
    # free and is left out of the counter entirely.
    metered = is_public_request()

    # Defaults to the cheap stream: anything that forgets to ask for a
    # quality gets the substream rather than silently costing 7 Mbps.
    quality = "full" if request.args.get("quality") == "full" else "sub"
    stream_id = None
    if quality == "full":
        with _sessions_lock:
            if len(_full_streams) >= MAX_FULL_QUALITY_SESSIONS:
                quality = "sub"          # degrade rather than refuse
            else:
                stream_id = object()
                _full_streams.add(stream_id)

    want_audio = request.args.get("audio") == "1"
    stream = resolve_stream_name(camera, camera in audio_cameras, quality, want_audio)
    # Set by the overlay for its own rate/total display -- absent for tiles,
    # which don't track this. See _record_stream_bytes()'s own comment.
    conn_id = _sanitize_conn_id(request.args.get("conn"))

    # stream_id, if set, was already added to _full_streams above to reserve
    # a slot before this connects -- a slot reserved for a connection that
    # never happens must be released here, not just inside pump()'s finally,
    # which never runs if this raises. The HLS path below (~line 905) avoids
    # this class of bug entirely by recomputing its active count from a
    # time-windowed, self-expiring dict instead of a manually-discarded set;
    # this path predates that pattern and a leaked slot here only clears on
    # container restart.
    try:
        upstream = requests.get(
            f"{GO2RTC_URL}/api/stream.mp4",
            params={"src": stream},
            stream=True,
            timeout=15,
        )
    except Exception:
        if stream_id is not None:
            with _sessions_lock:
                _full_streams.discard(stream_id)
        raise

    log.info("live start camera=%s stream=%s quality=%s user=%s metered=%s",
             camera, stream, quality, username, metered)

    def pump():
        sent = 0
        why = "client disconnected"
        try:
            for chunk in upstream.iter_content(chunk_size=64 * 1024):
                # Re-checked per chunk so an abandoned tab, or a viewing
                # window that closes mid-stream, actually stops the transfer
                # instead of running until the client disconnects.
                with _sessions_lock:
                    entry = _live_sessions.get(token)
                    last_seen = entry["seen"] if entry else None
                    session_timeout = (entry or {}).get("timeout", HEARTBEAT_TIMEOUT_SECONDS)
                if last_seen is None or time.time() - last_seen > session_timeout:
                    why = "heartbeat expired"
                    break
                still_allowed, _, _, _ = check_permission(username, load_permissions())
                if camera not in still_allowed:
                    why = "permission revoked"
                    break
                sent += len(chunk)
                if metered:
                    record_egress(len(chunk))
                _record_stream_bytes(conn_id, len(chunk))
                yield chunk
        finally:
            upstream.close()
            if stream_id is not None:
                with _sessions_lock:
                    _full_streams.discard(stream_id)
            if metered:
                record_egress(0, flush=True)
            log.info("live end camera=%s quality=%s reason=%s bytes=%d metered=%s",
                     camera, quality, why, sent, metered)

    resp = Response(stream_with_context(pump()), content_type="video/mp4")
    resp.headers["X-Livecam-Stream"] = stream
    return resp


# --------------------------------------------------------------------------
# PTZ -- direct ONVIF control, deliberately bypassing Frigate
#
# Live view already talks straight to the camera (via go2rtc's RTSP pull);
# PTZ follows the same pattern rather than adding a dependency on Frigate
# being up, configured, or even aware a given camera supports PTZ.
#
# onvif-zeep-async is asyncio-native; this app's gunicorn workers are sync
# (gthread). Bridged the same way Frigate itself bridges its own onvif
# controller into its sync-facing API: one dedicated background thread
# running a single persistent event loop, with requests scheduled onto it
# via run_coroutine_threadsafe() and blocked on for the (sub-second)
# result. A persistent loop -- not one per request -- is what lets the
# ONVIFCamera/profile/PTZ-service objects be created once per camera and
# reused, avoiding the GetProfiles/update_xaddrs handshake on every button
# press, which would make a control that needs to feel like a joystick
# feel like a page load instead.
#
# Started lazily on first use, not at import time: on every host running
# this today, no camera declares PTZ, so the loop and its thread would
# otherwise sit idle forever for a feature nobody can use yet.
# --------------------------------------------------------------------------

_ptz_loop = None
_ptz_loop_ready = threading.Event()
_ptz_start_lock = threading.Lock()

# Connected clients, keyed by camera name. Written to and read from
# exclusively by coroutines running on _ptz_loop -- that loop runs one
# coroutine at a time, so it is its own serialization and this dict needs
# no separate lock, unlike the plain dicts/sets shared across worker
# threads elsewhere in this file.
_ptz_clients = {}

# Matches the fixed speed Frigate's own onvif.py uses for continuous moves
# (0.5 on a -1..1 axis) -- a reasonable middle speed, not something either
# codebase measured against real hardware.
_PTZ_VELOCITY = {
    "move_up": {"PanTilt": {"x": 0, "y": 0.5}},
    "move_down": {"PanTilt": {"x": 0, "y": -0.5}},
    "move_left": {"PanTilt": {"x": -0.5, "y": 0}},
    "move_right": {"PanTilt": {"x": 0.5, "y": 0}},
    "zoom_in": {"Zoom": {"x": 0.5}},
    "zoom_out": {"Zoom": {"x": -0.5}},
}

# Single-click nudge (2026-08-27), distinct from the hold-to-move commands
# above. A quick tap sent as ContinuousMove+Stop travels a distance that
# depends on the round trip between those two separate commands, which is
# exactly what makes a tap over the network hard to control precisely.
# RelativeMove is one atomic ONVIF operation -- the camera executes the
# whole displacement itself, so a step's size no longer depends on network
# timing at all. One-fifth of _PTZ_VELOCITY's magnitude, not measured
# against real hardware yet.
_PTZ_STEP = {
    "step_move_up": {"PanTilt": {"x": 0, "y": 0.1}},
    "step_move_down": {"PanTilt": {"x": 0, "y": -0.1}},
    "step_move_left": {"PanTilt": {"x": -0.1, "y": 0}},
    "step_move_right": {"PanTilt": {"x": 0.1, "y": 0}},
    "step_zoom_in": {"Zoom": {"x": 0.1}},
    "step_zoom_out": {"Zoom": {"x": -0.1}},
}


def _ptz_loop_main():
    global _ptz_loop
    _ptz_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_ptz_loop)
    _ptz_loop_ready.set()
    _ptz_loop.run_forever()


def _run_ptz(coro, timeout=10):
    """Run a coroutine on the dedicated PTZ event loop; block for its result."""
    with _ptz_start_lock:
        if _ptz_loop is None:
            threading.Thread(target=_ptz_loop_main, name="ptz-loop", daemon=True).start()
            if not _ptz_loop_ready.wait(timeout=5):
                raise RuntimeError("PTZ event loop failed to start")
    return asyncio.run_coroutine_threadsafe(coro, _ptz_loop).result(timeout=timeout)


async def _get_ptz_client(camera):
    """(ptz_service, profile_token, presets) for `camera`, connecting once and caching.

    Must only run on the PTZ event loop thread -- see the _ptz_clients
    comment above for why that alone is enough synchronization.
    """
    cached = _ptz_clients.get(camera)
    if cached:
        return cached

    config = load_camera_config().get(camera) or {}
    host = config.get("ip") or config.get("host")
    if not host:
        raise LookupError(f"{camera} has no ip/host in {CAMERAS_FILE}")
    port = config.get("onvif_port", 80)
    # Per-camera override wins; otherwise the assumed-shared RTSP account.
    # See the CAMERA_USERNAME/CAMERA_PASSWORD comment near the top of this
    # file -- unverified until real hardware confirms the assumption.
    username = config.get("username", CAMERA_USERNAME)
    password = config.get("password", CAMERA_PASSWORD)

    cam = ONVIFCamera(host, port, username, password)
    await cam.update_xaddrs()
    media = await cam.create_media_service()
    profiles = await media.GetProfiles()
    # Same selection rule as Frigate's own onvif.py: the first profile that
    # actually declares continuous PTZ support, not just any profile.
    profile = next(
        (
            p for p in profiles
            if p.PTZConfiguration
            and (
                p.PTZConfiguration.DefaultContinuousPanTiltVelocitySpace is not None
                or p.PTZConfiguration.DefaultContinuousZoomVelocitySpace is not None
            )
        ),
        None,
    )
    if profile is None:
        raise LookupError(f"{camera} has no ONVIF media profile with PTZ support")

    ptz = await cam.create_ptz_service()

    presets = {}
    try:
        preset_list = await ptz.GetPresets({"ProfileToken": profile.token})
        presets = {p.Name.lower(): p.token for p in preset_list if p.Name}
    except Exception:
        # Not every PTZ camera implements presets; absence isn't an error,
        # it just means the preset dropdown has nothing to show.
        log.warning("ptz presets unavailable camera=%s", camera, exc_info=True)

    # `media` is cached alongside the PTZ service because speaker volume lives
    # on the media service (GetAudioOutputConfigurations), and reconnecting a
    # whole second ONVIF session just to read a number would be wasteful --
    # this connection is already authenticated and open.
    client = {"ptz": ptz, "media": media, "profile_token": profile.token,
              "presets": presets}
    _ptz_clients[camera] = client
    return client


async def _audio_output_config(camera):
    """The camera's first ONVIF audio output configuration, or None.

    Absence is not an error: it just means this camera has no speaker to
    control, which is the normal case for the fixed cameras.
    """
    client = await _get_ptz_client(camera)
    configs = await client["media"].GetAudioOutputConfigurations()
    return configs[0] if configs else None


async def _get_speaker_volume(camera):
    cfg = await _audio_output_config(camera)
    return None if cfg is None else int(cfg.OutputLevel)


async def _set_speaker_volume(camera, level):
    """Set the speaker's ONVIF OutputLevel (0-100).

    The whole configuration object is round-tripped rather than sending
    OutputLevel alone: SetAudioOutputConfiguration *replaces* the
    configuration, so omitting fields (SendPrimacy, token) would blank them.
    """
    client = await _get_ptz_client(camera)
    cfg = await _audio_output_config(camera)
    if cfg is None:
        raise LookupError(f"{camera} has no ONVIF audio output")
    cfg.OutputLevel = level
    await client["media"].SetAudioOutputConfiguration(
        {"Configuration": cfg, "ForcePersistence": True}
    )
    return level


async def _ptz_command(camera, command):
    client = await _get_ptz_client(camera)
    ptz, token = client["ptz"], client["profile_token"]

    if command == "stop":
        await ptz.Stop({"ProfileToken": token, "PanTilt": True, "Zoom": True})
        return

    if command.startswith("preset_"):
        preset_token = client["presets"].get(command[len("preset_"):])
        if preset_token is None:
            raise LookupError(f"no such preset for {camera}: {command}")
        await ptz.GotoPreset({"ProfileToken": token, "PresetToken": preset_token})
        return

    step = _PTZ_STEP.get(command)
    if step is not None:
        move = ptz.create_type("RelativeMove")
        move.ProfileToken = token
        move.Translation = step
        await ptz.RelativeMove(move)
        return

    velocity = _PTZ_VELOCITY.get(command)
    if velocity is None:
        raise ValueError(f"unknown ptz command: {command}")
    # ContinuousMove keeps moving until Stop -- the client is responsible for
    # sending stop on release, which is exactly the hold-to-move UI this is
    # built for.
    move = ptz.create_type("ContinuousMove")
    move.ProfileToken = token
    move.Velocity = velocity
    await ptz.ContinuousMove(move)


def _authorise_ptz(camera):
    """Both gates, in one place: the permission grant AND the config flag.

    A camera not declared in CAMERAS_FILE has no PTZ regardless of any
    user's grant; a user without the grant can't control a camera that is
    declared. Neither alone is enough.
    """
    _, _, ptz_cameras, _ = check_permission(current_user(), load_permissions())
    if camera not in (ptz_cameras & ptz_capable_cameras()):
        abort(403)


def _authorise_talk(camera):
    """Both gates for pushing audio at a camera: the grant AND the capability.

    Same shape as _authorise_ptz above. A camera without `talk: true` in
    CAMERAS_FILE has no speaker as far as this app is concerned, no matter
    what any permissions.yml entry claims.
    """
    _, _, _, talk_cameras = check_permission(current_user(), load_permissions())
    if camera not in (talk_cameras & talk_capable_cameras()):
        abort(403)


# --------------------------------------------------------------------------
# Soundboard: short audio clips stored on the writable mount, played out of a
# camera's speaker.
#
# Nothing here decodes or transcodes audio. go2rtc already holds the camera's
# ONVIF backchannel open on its main stream (verified live: that producer
# reports an `audio, sendonly, PCMA/8000` track), so playing a clip is one
# POST asking go2rtc to pull the file and push it down that track. See
# _play_clip() for the exact call, and the note in the Frigate role's
# config.yml.j2 for why no dedicated talk stream exists.
# --------------------------------------------------------------------------
_talk_lock = threading.Lock()
_talk_last_played = {}     # camera -> epoch of the last accepted play


def _soundboard_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="livecam-soundboard")


def _clip_path(clip_id):
    """Absolute path for a clip id, or None if the id is not a plain filename.

    The id comes off the wire, so anything with a separator or a parent
    reference is refused outright rather than normalised -- clips are always
    flat files directly inside SOUNDBOARD_DIR.
    """
    if not clip_id or clip_id != os.path.basename(clip_id) or clip_id.startswith("."):
        return None
    if os.path.splitext(clip_id)[1].lower() not in SOUNDBOARD_EXTENSIONS:
        return None
    return os.path.join(SOUNDBOARD_DIR, clip_id)


def soundboard_clips():
    """Every stored clip, newest first. Missing directory means none yet."""
    try:
        names = os.listdir(SOUNDBOARD_DIR)
    except FileNotFoundError:
        return []
    except OSError:
        log.warning("soundboard directory unreadable at %s", SOUNDBOARD_DIR, exc_info=True)
        return []

    clips = []
    for name in names:
        path = _clip_path(name)
        if not path or not os.path.isfile(path):
            continue
        stat = os.stat(path)
        clips.append({
            "id": name,
            "label": os.path.splitext(name)[0].replace("_", " "),
            "bytes": stat.st_size,
            "added": int(stat.st_mtime),
        })
    return sorted(clips, key=lambda c: c["added"], reverse=True)


def _safe_clip_name(raw, fallback_ext):
    """Turn a user-supplied label into a flat, predictable filename."""
    stem = os.path.splitext(os.path.basename(raw or ""))[0]
    stem = re.sub(r"[^A-Za-z0-9 _-]+", "", stem).strip().replace(" ", "_")[:48]
    if not stem:
        stem = f"clip_{int(time.time())}"
    ext = fallback_ext if fallback_ext in SOUNDBOARD_EXTENSIONS else ".wav"
    name = f"{stem}{ext}"
    # Never silently overwrite an existing clip with the same name.
    counter = 2
    while os.path.exists(os.path.join(SOUNDBOARD_DIR, name)):
        name = f"{stem}_{counter}{ext}"
        counter += 1
    return name


def _store_clip(file_storage, label=None):
    """Persist an uploaded/recorded clip. Returns its id, or raises ValueError."""
    ext = os.path.splitext(file_storage.filename or "")[1].lower()
    if ext not in SOUNDBOARD_EXTENSIONS:
        raise ValueError(f"unsupported audio type: {ext or '(none)'}")

    os.makedirs(SOUNDBOARD_DIR, exist_ok=True)
    name = _safe_clip_name(label or file_storage.filename, ext)
    path = os.path.join(SOUNDBOARD_DIR, name)
    file_storage.save(path)

    # Size is enforced after the write rather than from Content-Length, which
    # a client controls and can lie about.
    if os.path.getsize(path) > SOUNDBOARD_MAX_BYTES:
        os.remove(path)
        raise ValueError(f"clip exceeds {SOUNDBOARD_MAX_BYTES // 1024 // 1024}MB")
    return name


def _rename_clip(clip_id, label):
    """Rename a stored clip, keeping its extension. Returns the new id.

    The extension comes from the existing file, never from the new label: the
    label is a display name, and letting it set the extension would let a
    rename mislabel a clip's actual format (and, since _clip_path gates on the
    extension, rename a clip out of existence).
    """
    old = _clip_path(clip_id)
    if not old or not os.path.isfile(old):
        raise LookupError(clip_id)

    raw = str(label or "").strip()
    # Only strip a trailing extension if it is genuinely an audio one --
    # blanket splitext would turn a name like "take 2.1" into "take 2".
    base, trailing = os.path.splitext(raw)
    if trailing.lower() in SOUNDBOARD_EXTENSIONS:
        raw = base
    if not re.sub(r"[^A-Za-z0-9 _-]+", "", raw).strip():
        raise ValueError("a name is required")

    ext = os.path.splitext(clip_id)[1].lower()
    new_id = _safe_clip_name(raw, ext)
    if new_id == clip_id:
        return clip_id
    os.rename(old, os.path.join(SOUNDBOARD_DIR, new_id))
    return new_id


def backchannel_stream(camera, streams):
    """Which go2rtc stream currently carries this camera's speaker, or None.

    NOT necessarily the stream named after the camera. These cameras expose
    exactly one ONVIF talk channel, and it is claimed by whichever of go2rtc's
    RTSP connections to that camera -- main, substream, any other variant --
    happens to establish first. Observed live: it sat on `baby-ptz` after one
    Frigate restart and on `baby-ptz_sub` after the next, with nothing else
    changed. Hardcoding the main stream worked once by luck and then failed
    with "can't find consumer" once the race went the other way.

    So the holder is discovered per play. The tell is a producer media
    marked sendonly with the PCMA (G.711 A-law) codec the backchannel uses.
    """
    for name, info in (streams or {}).items():
        if name != camera and not name.startswith(f"{camera}_"):
            continue
        for producer in (info or {}).get("producers") or []:
            for media in producer.get("medias") or []:
                if "sendonly" in media and "PCMA" in media:
                    return name
    return None


def _play_clip(camera, clip_id):
    """Ask go2rtc to push a stored clip down the camera's audio backchannel.

    go2rtc fetches the clip itself over HTTP (it cannot see this filesystem),
    so the URL is signed and short-lived: that request arrives without a
    session cookie and must still not expose the soundboard to anyone who
    guesses the path.
    """
    if not TALK_CLIP_BASE_URL:
        raise RuntimeError("TALK_CLIP_BASE_URL is not configured")

    # The gap check reserves the camera, but the reservation is rolled back
    # below if the play fails. Recording it unconditionally meant one failed
    # attempt locked out the retry with a misleading "already playing".
    now = time.time()
    with _talk_lock:
        last = _talk_last_played.get(camera, 0)
        if now - last < TALK_MIN_GAP_SECONDS:
            raise RuntimeError("a clip is already playing on this camera")
        previous = _talk_last_played.get(camera)
        _talk_last_played[camera] = now

    def _release():
        with _talk_lock:
            if _talk_last_played.get(camera) == now:
                if previous is None:
                    _talk_last_played.pop(camera, None)
                else:
                    _talk_last_played[camera] = previous

    try:
        listing = requests.get(f"{GO2RTC_URL}/api/streams", timeout=10)
        listing.raise_for_status()
        target = backchannel_stream(camera, listing.json())
        if target is None:
            log.warning("no backchannel stream for camera=%s; go2rtc holds no "
                        "sendonly PCMA track", camera)
            raise RuntimeError(
                "the camera's speaker channel isn't open right now -- "
                "another connection may be holding it")

        token = _soundboard_serializer().dumps(clip_id)
        clip_url = f"{TALK_CLIP_BASE_URL}/soundboard/raw/{token}"
        # #audio=pcma makes go2rtc transcode to G.711 A-law, which is what the
        # backchannel advertises; without it the push is refused as a codec
        # mismatch.
        resp = requests.post(
            f"{GO2RTC_URL}/api/streams",
            params={"dst": target, "src": f"ffmpeg:{clip_url}#audio=pcma"},
            timeout=15,
        )
        if resp.status_code != 200:
            log.warning("clip play rejected camera=%s stream=%s clip=%s status=%s body=%s",
                        camera, target, clip_id, resp.status_code, resp.text[:200])
            raise RuntimeError(f"go2rtc refused the clip ({resp.status_code})")
    except Exception:
        _release()
        raise
    log.info("played clip camera=%s stream=%s clip=%s user=%s",
             camera, target, clip_id, current_user())


@app.route("/ptz/<camera>", methods=["POST"])
@login_required
def ptz_control(camera):
    _authorise_ptz(camera)

    command = (request.get_json(silent=True) or {}).get("command")
    if not command:
        abort(400)

    try:
        _run_ptz(_ptz_command(camera, command))
    except LookupError as e:
        log.warning("ptz command refused camera=%s command=%s: %s", camera, command, e)
        abort(400)
    except ValueError:
        abort(400)
    except Exception:
        log.exception("ptz command failed camera=%s command=%s", camera, command)
        abort(502)

    return jsonify({"ok": True})


@app.route("/ptz/<camera>/presets")
@login_required
def ptz_presets(camera):
    _authorise_ptz(camera)

    try:
        client = _run_ptz(_get_ptz_client(camera))
    except LookupError as e:
        log.warning("ptz presets refused camera=%s: %s", camera, e)
        abort(400)
    except Exception:
        log.exception("ptz presets failed camera=%s", camera)
        abort(502)

    return jsonify({"presets": sorted(client["presets"])})


# ------------------------------------------------------------- soundboard API
@app.route("/soundboard")
@login_required
def soundboard_list():
    return jsonify({"clips": soundboard_clips()})


@app.route("/soundboard/upload", methods=["POST"])
@login_required
def soundboard_upload():
    """Add a clip. Gated on `recordings`, the existing elevated grant -- a
    stored clip is playable into a room by anyone with `talk`, so adding one
    is deliberately a higher bar than playing one."""
    permissions = load_permissions()
    if not (user_entries(permissions).get(current_user()) or {}).get("recordings"):
        abort(403)

    upload = request.files.get("clip")
    if upload is None or not upload.filename:
        abort(400)
    try:
        clip_id = _store_clip(upload, request.form.get("label"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except OSError:
        log.exception("could not store clip")
        abort(500)
    log.info("soundboard clip added id=%s user=%s", clip_id, current_user())
    return jsonify({"clip": clip_id, "clips": soundboard_clips()}), 201


@app.route("/soundboard/<clip_id>", methods=["DELETE"])
@login_required
def soundboard_delete(clip_id):
    permissions = load_permissions()
    if not (user_entries(permissions).get(current_user()) or {}).get("recordings"):
        abort(403)

    path = _clip_path(clip_id)
    if not path or not os.path.isfile(path):
        abort(404)
    try:
        os.remove(path)
    except OSError:
        log.exception("could not delete clip %s", clip_id)
        abort(500)
    log.info("soundboard clip deleted id=%s user=%s", clip_id, current_user())
    return jsonify({"clips": soundboard_clips()})


@app.route("/soundboard/<clip_id>/rename", methods=["POST"])
@login_required
def soundboard_rename(clip_id):
    permissions = load_permissions()
    if not (user_entries(permissions).get(current_user()) or {}).get("recordings"):
        abort(403)

    label = (request.get_json(silent=True) or {}).get("label")
    try:
        new_id = _rename_clip(clip_id, label)
    except LookupError:
        abort(404)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except OSError:
        log.exception("could not rename clip %s", clip_id)
        abort(500)
    log.info("soundboard clip renamed %s -> %s user=%s", clip_id, new_id, current_user())
    return jsonify({"clip": new_id, "clips": soundboard_clips()})


@app.route("/soundboard/save", methods=["POST"])
@login_required
def soundboard_save():
    """Store a recording as a permanent clip WITHOUT playing it.

    Deliberately separate from /talk/<camera>/say, which plays and only
    optionally keeps. Saving and making noise are different intentions, and
    tying them together makes it impossible to build up the board while the
    room the camera sits in has to stay quiet.
    """
    permissions = load_permissions()
    if not (user_entries(permissions).get(current_user()) or {}).get("recordings"):
        abort(403)

    upload = request.files.get("clip")
    if upload is None or not upload.filename:
        abort(400)
    try:
        clip_id = _store_clip(upload, request.form.get("label"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except OSError:
        log.exception("could not save recorded clip")
        abort(500)
    log.info("soundboard clip saved from recording id=%s user=%s", clip_id, current_user())
    return jsonify({"clip": clip_id, "clips": soundboard_clips()}), 201


@app.route("/soundboard/preview/<clip_id>")
@login_required
def soundboard_preview(clip_id):
    """Serve a clip to the BROWSER so it can be auditioned locally.

    Separate from /soundboard/raw/<token>, which exists for go2rtc and is
    authorised by a signed token because it arrives with no session. This one
    is session-gated and sends a real audio content type so an <audio> element
    will play it -- letting a clip be heard on the phone before it is pushed
    into a room where someone may be asleep.
    """
    path = _clip_path(clip_id)
    if not path or not os.path.isfile(path):
        abort(404)
    ext = os.path.splitext(clip_id)[1].lower()
    return send_file(path, mimetype=SOUNDBOARD_MIME.get(ext, "application/octet-stream"),
                     conditional=True)


@app.route("/soundboard/raw/<token>")
def soundboard_raw(token):
    """Serve a clip's bytes to go2rtc.

    Deliberately NOT @login_required: the caller is go2rtc's ffmpeg on the
    Frigate VM, which has no session. The signed, short-lived token is the
    authorisation instead, so a guessed path gets nothing and an intercepted
    URL stops working within TALK_CLIP_TTL_SECONDS.
    """
    try:
        clip_id = _soundboard_serializer().loads(token, max_age=TALK_CLIP_TTL_SECONDS)
    except SignatureExpired:
        abort(410)
    except BadSignature:
        abort(403)

    path = _clip_path(clip_id)
    if not path or not os.path.isfile(path):
        abort(404)
    with open(path, "rb") as f:
        body = f.read()
    return Response(body, content_type="application/octet-stream")


# ------------------------------------------------------- talking to a camera
@app.route("/talk/<camera>/play", methods=["POST"])
@login_required
def talk_play(camera):
    _authorise_talk(camera)

    clip_id = (request.get_json(silent=True) or {}).get("clip")
    path = _clip_path(clip_id)
    if not path or not os.path.isfile(path):
        abort(404)
    try:
        _play_clip(camera, clip_id)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    except requests.RequestException:
        log.exception("go2rtc unreachable for clip play camera=%s", camera)
        abort(502)
    return jsonify({"ok": True})


@app.route("/talk/<camera>/say", methods=["POST"])
@login_required
def talk_say(camera):
    """Play a just-recorded clip once, without keeping it.

    The recording is written to disk because go2rtc fetches it by URL rather
    than accepting bytes inline, so "ephemeral" means deleted afterwards, not
    never stored. The delete sits in a finally: a failed play must not leave
    recordings accumulating on the writable mount.
    """
    _authorise_talk(camera)

    upload = request.files.get("clip")
    if upload is None or not upload.filename:
        abort(400)
    # A kept recording gets the name the user typed; a send-once recording
    # gets a timestamp, since it is deleted moments later anyway.
    keep = request.form.get("save") == "1"
    label = request.form.get("label")
    try:
        clip_id = _store_clip(upload, label if (keep and label) else f"say_{int(time.time())}")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    try:
        _play_clip(camera, clip_id)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    except requests.RequestException:
        log.exception("go2rtc unreachable for say camera=%s", camera)
        abort(502)
    finally:
        if not keep:
            # go2rtc fetches the clip asynchronously, so deleting immediately
            # would race its download. A short grace period is enough: the
            # fetch happens within milliseconds of the POST returning.
            threading.Timer(
                TALK_CLIP_TTL_SECONDS,
                lambda p=_clip_path(clip_id): os.path.exists(p) and os.remove(p),
            ).start()
    return jsonify({"ok": True, "saved": keep, "clip": clip_id if keep else None})


@app.route("/talk/<camera>/volume", methods=["GET", "POST"])
@login_required
def talk_volume(camera):
    """Read or set the camera's speaker volume (ONVIF OutputLevel, 0-100).

    Persistent and camera-wide, not per-user: turning it down affects every
    viewer and stays that way until changed back.
    """
    _authorise_talk(camera)

    # Validation happens BEFORE the try: abort() raises an HTTPException, and
    # the broad `except Exception` below would otherwise catch a deliberate
    # 400 and re-report it as a 502 upstream failure.
    level = None
    if request.method == "POST":
        raw = (request.get_json(silent=True) or {}).get("volume")
        # bool is an int subclass, and True would silently become volume 1.
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            abort(400)
        try:
            level = int(raw)
        except (TypeError, ValueError):
            abort(400)
        if not 0 <= level <= 100:
            abort(400)

    try:
        if request.method == "GET":
            return jsonify({"volume": _run_ptz(_get_speaker_volume(camera))})
        return jsonify({"volume": _run_ptz(_set_speaker_volume(camera, level))})
    except LookupError as e:
        log.warning("speaker volume unavailable camera=%s: %s", camera, e)
        abort(400)
    except Exception:
        log.exception("speaker volume failed camera=%s", camera)
        abort(502)


@app.route("/")
@login_required
def dashboard():
    """livecam's own landing page: the permitted cameras, live."""
    username = current_user()
    permissions = load_permissions()
    allowed_cameras, audio_cameras, ptz_cameras, talk_cameras = check_permission(username, permissions)
    # Two independent gates, both required: the permission grant above, and
    # a camera actually being declared PTZ-capable in CAMERAS_FILE. Today's
    # fleet declares none, so this is always empty regardless of any user's
    # `ptz:` grant -- the feature is inert until real hardware exists.
    controllable_cameras = ptz_cameras & ptz_capable_cameras()
    # Same two-gate rule for the speaker: granted AND declared `talk: true`.
    speakable_cameras = talk_cameras & talk_capable_cameras()

    idle_prompt, heartbeat_timeout = idle_settings()
    token = secrets.token_urlsafe(24)
    with _sessions_lock:
        _live_sessions[token] = {"seen": time.time(), "user": username,
                                 "timeout": heartbeat_timeout}
    _prune_stale_sessions()

    used = egress_this_month()
    return render_template(
        "index.html",
        username=username,
        # Whether to offer the recorded archive at all. Same grant the
        # /frigate/ route enforces, so the link never points somewhere the
        # user would be refused.
        recordings_allowed=bool(
            user_entries(permissions).get(username, {}).get("recordings")),
        cameras=[{"name": c, "label": display_name(c)} for c in sorted(allowed_cameras)],
        audio_cameras=sorted(audio_cameras),
        ptz_cameras=sorted(controllable_cameras),
        talk_cameras=sorted(speakable_cameras),
        token=token,
        idle_prompt_seconds=idle_prompt,
        egress_bytes=used,
        free_tier_bytes=FREE_TIER_BYTES,
        # There is a session here, so switching hosts needs a handoff token;
        # the login page has none and needs none.
        authed=True,
        # The banner and the LAN probe are both nudges for people already at
        # home on the public URL, so both only make sense on that hostname
        # -- and only if a LAN hostname exists to send them to.
        **lan_switch_context(),
    )


# The method list is not decoration. It was GET/POST only, which silently
# broke every Frigate feature that uses another verb: deleting an export
# issues DELETE /api/export/<id>, Flask answered 405 before the request ever
# reached Frigate, and the UI surfaced nothing at all -- the button worked,
# the file never went away, and Frigate's log showed no DELETE because none
# ever arrived. Proxying the verbs Frigate's own UI uses does not widen
# access: this route is already gated on the `recordings` grant below, and
# _proxy() forwards request.method unchanged.
@app.route("/frigate/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/frigate/<path:path>",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@login_required
def frigate(path):
    """Frigate's UI: recordings, the scrub timeline, and export.

    Frigate replaced ZoneMinder, which recorded correctly but had no
    continuous scrub bar and no live previews. Live view is still not its
    job -- livecam serves that from go2rtc directly.

    Access is a separate grant from live viewing. Frigate has no per-camera
    or per-audio gating that matches this app's model: anyone who reaches
    it sees every camera and hears recorded audio. So a user who is allowed
    one camera, or no audio, must not simply inherit the archive.
    """
    if not user_entries(load_permissions()).get(current_user(), {}).get("recordings"):
        abort(403)

    # Frigate's own login is disabled; it trusts this header instead, which
    # is what keeps livecam the single login rather than repeating ZM's two
    # separate accounts. Reachable only on the LAN, so nothing outside can
    # set the header itself.
    headers = {k: v for k, v in request.headers if k.lower() not in ("host", "x-forwarded-user")}
    headers["X-Forwarded-User"] = current_user()
    # How Frigate is told it lives under a prefix, so its own asset and API
    # URLs come back rooted at /frigate rather than /.
    headers["X-Ingress-Path"] = "/frigate"

    return _proxy(f"{FRIGATE_URL}/{path}", headers=headers, inject=True)


# Frigate's own live view does not work under a subpath, which is fine --
# livecam owns live view -- but it leaves no way back from the archive. There
# is no Frigate setting for this, so it is injected into the HTML on the way
# through.
#
# Safe because it goes in before </body> and therefore OUTSIDE <div id="root">,
# which is the element React manages; React never sees or removes it.
BACK_TO_LIVE_SNIPPET = """
<a href="/" id="livecam-back" title="Back to the live view">\u2190 Live</a>
<style>
  #livecam-back {
    position: fixed; left: 0; top: 50%; transform: translateY(-50%);
    z-index: 2147483647; padding: .7rem .8rem .7rem .6rem;
    background: #2f6fd0; color: #fff; text-decoration: none;
    font: 600 .85rem/1 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    border-radius: 0 8px 8px 0; box-shadow: 0 2px 10px #0006;
  }
  #livecam-back:hover { background: #3b7ee4; }
</style>
"""


def _inject_back_to_live(body, content_type):
    """Add the back-to-live control to proxied Frigate HTML, and only to HTML.

    Guarded on content-type deliberately: a blind replace across every proxied
    response would corrupt CSS and JSON, which fail in ways that look nothing
    like this function.
    """
    if "text/html" not in (content_type or "").lower():
        return body
    marker = b"</body>"
    if marker not in body:
        return body
    return body.replace(marker, BACK_TO_LIVE_SNIPPET.encode() + marker, 1)


def _proxy(upstream_url, headers=None, inject=False):
    upstream = requests.request(
        method=request.method,
        url=upstream_url,
        params=request.args,
        headers=headers or {k: v for k, v in request.headers if k.lower() != "host"},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True,
    )
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    resp_headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in excluded]
    content_type = upstream.headers.get("Content-Type", "")
    # Recorded playback and its thumbnails are real traffic, not noise next
    # to live video, so they count when served over the public route.
    metered = is_public_request()

    # HTML is the one case that needs the whole body up front: finding
    # </body> to inject the back-to-live control can't work on a partial
    # chunk. HTML pages here are tens of KB, never the multi-megabyte media
    # this function otherwise proxies, so buffering only this case is cheap.
    if inject and "text/html" in content_type.lower():
        body = _inject_back_to_live(upstream.content, content_type)
        upstream.close()
        if metered:
            record_egress(len(body))
        return Response(body, upstream.status_code, resp_headers)

    # Everything else streams -- this is the fix for a real bug. Frigate's
    # recorded-video HLS segments run 8+ MB each (10s at full resolution),
    # and scrubbing the timeline is an abandon-and-refetch pattern: every
    # drag cancels the in-flight segment fetch and starts a new one at the
    # new position. The previous behaviour (buffer the whole body, then
    # respond) meant an abandoned request kept downloading from Frigate
    # regardless of whether the client was still there -- proven by testing
    # it directly: closing a client connection 4KB into an 8.4MB segment
    # still logged a completed 200 for the full size. Under real scrubbing,
    # enough of these pile up to starve gunicorn's thread pool and Frigate's
    # own transcoder, which is what produced the intermittent iOS freezes
    # (iOS's native HLS player is markedly more aggressive than desktop/
    # Android about firing a fresh segment request per seek).
    #
    # Streaming means the generator -- and therefore the upstream fetch --
    # stops as soon as gunicorn notices the client is gone, the same
    # reasoning already relied on for live video in /live/<camera>'s
    # pump(). Not a new technique, just applied to a second code path.
    def relay():
        try:
            for chunk in upstream.iter_content(chunk_size=64 * 1024):
                if metered:
                    record_egress(len(chunk))
                yield chunk
        finally:
            upstream.close()
            if metered:
                record_egress(0, flush=True)

    return Response(stream_with_context(relay()), upstream.status_code, resp_headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
