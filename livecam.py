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
                   request, session, stream_with_context, url_for)
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
    added without restarting the container. Missing file or empty content
    both mean "no PTZ cameras configured," which is the expected state
    until real hardware exists.
    """
    try:
        with open(CAMERAS_FILE) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    return data.get("cameras") or {}


def ptz_capable_cameras():
    """Camera names with PTZ config declared -- the config-side gate.

    Independent of any user's `ptz` permission grant: both are required.
    A camera absent here has no PTZ regardless of what any permissions.yml
    entry says, and a user without the grant can't control a camera that
    is present here either.
    """
    return set(load_camera_config())


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

    Shared by `audio` and `ptz`, which both follow the same shape:

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
    """Return (allowed_cameras, audio_cameras, ptz_cameras) for this user right now.

    The time window is evaluated per request, not once at login, so a lapsed
    grant actually cuts a stream (or PTZ control) off mid-session.
    """
    now = now or datetime.now()
    user_perms = user_entries(permissions).get(username)
    if not user_perms:
        return set(), set(), set()

    window = user_perms.get("time_window")
    if window:
        start = dtime.fromisoformat(window["start"])
        end = dtime.fromisoformat(window["end"])
        if not (start <= now.time() <= end):
            return set(), set(), set()

    cameras = set(user_perms.get("cameras", []))
    audio_cameras = _intersect_grant(cameras, user_perms.get("audio", False))
    ptz_cameras = _intersect_grant(cameras, user_perms.get("ptz", False))
    return cameras, audio_cameras, ptz_cameras


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

    allowed, _, _ = check_permission(current_user(), load_permissions())
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
    allowed_cameras, audio_cameras, _ = check_permission(username, load_permissions())
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
    metered = is_public_request()
    session_ids = []
    lines = []
    for line in upstream.text.splitlines():
        match = re.match(r"^hls/playlist\.m3u8\?id=(\w+)$", line.strip())
        if match:
            session_ids.append(match.group(1))
            lines.append(f"/hls/playlist.m3u8?id={match.group(1)}")
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

    Segment references inside a media playlist are relative, so they resolve
    back here without any rewriting -- the only thing this has to do is
    check that the id belongs to the caller before passing bytes along.
    """
    if ".." in sub or sub.startswith("/"):
        abort(400)

    camera, metered = _authorise_hls(request.args.get("id"))

    upstream = requests.get(
        f"{GO2RTC_URL}/api/hls/{sub}",
        params=request.args,
        stream=True,
        timeout=15,
    )
    body = upstream.content
    if metered:
        record_egress(len(body), flush=sub.endswith(".m3u8"))

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
    allowed_cameras, audio_cameras, _ = check_permission(username, permissions)
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

    upstream = requests.get(
        f"{GO2RTC_URL}/api/stream.mp4",
        params={"src": stream},
        stream=True,
        timeout=15,
    )

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
                still_allowed, _, _ = check_permission(username, load_permissions())
                if camera not in still_allowed:
                    why = "permission revoked"
                    break
                sent += len(chunk)
                if metered:
                    record_egress(len(chunk))
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

    client = {"ptz": ptz, "profile_token": profile.token, "presets": presets}
    _ptz_clients[camera] = client
    return client


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
    _, _, ptz_cameras = check_permission(current_user(), load_permissions())
    if camera not in (ptz_cameras & ptz_capable_cameras()):
        abort(403)


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


@app.route("/")
@login_required
def dashboard():
    """livecam's own landing page: the permitted cameras, live."""
    username = current_user()
    permissions = load_permissions()
    allowed_cameras, audio_cameras, ptz_cameras = check_permission(username, permissions)
    # Two independent gates, both required: the permission grant above, and
    # a camera actually being declared PTZ-capable in CAMERAS_FILE. Today's
    # fleet declares none, so this is always empty regardless of any user's
    # `ptz:` grant -- the feature is inert until real hardware exists.
    controllable_cameras = ptz_cameras & ptz_capable_cameras()

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


@app.route("/frigate/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/frigate/<path:path>", methods=["GET", "POST"])
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
    headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in excluded]
    body = upstream.content
    if inject:
        body = _inject_back_to_live(body, upstream.headers.get("Content-Type"))
    # Recorded playback and its thumbnails are real traffic, not noise next
    # to live video, so they count when served over the public route.
    if is_public_request():
        record_egress(len(body))
    return Response(body, upstream.status_code, headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
