"""
livecam -- a thin gate in front of the camera stack.

Two backends, deliberately split by what each is good at:

  * ZoneMinder  -- recorded playback. It hands over the stored mp4 and the
                   browser decodes it, so this costs the server nothing.
  * go2rtc      -- live view. It remuxes the camera's existing H.264 without
                   decoding, which is why live view is cheap. ZoneMinder's
                   own live path decodes every frame and is explicitly NOT
                   used here -- it pinned the NVR box hard enough to need a
                   power cycle.

Almost every request is passed straight through to ZoneMinder untouched
(login page, dashboard, event browser -- all native ZM UI, including its
own per-user per-camera restriction). This app only adds the two things ZM
has no native concept of: a per-user time-of-day window, and true per-user
audio gating.

Neither backend is reachable from outside the LAN; only this app is. So the
permission checks can't be bypassed by hitting go2rtc or ZM directly.
"""

import os
import re
import threading
import time
from datetime import datetime, time as dtime

import pymysql
import requests
import yaml
from flask import Flask, Response, jsonify, request, abort, stream_with_context

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

ZM_BACKEND_URL = os.environ["ZM_BACKEND_URL"].rstrip("/")
GO2RTC_URL = os.environ["GO2RTC_URL"].rstrip("/")
PERMISSIONS_FILE = os.environ.get("PERMISSIONS_FILE", "/app/config/permissions.yml")

# Read-only access to ZM's own database, used only to resolve "which ZM user
# does this session cookie belong to".
ZM_DB_HOST = os.environ.get("ZM_DB_HOST")
ZM_DB_USER = os.environ.get("ZM_DB_USER")
ZM_DB_PASSWORD = os.environ.get("ZM_DB_PASSWORD")
ZM_DB_NAME = os.environ.get("ZM_DB_NAME", "zm")

# A full-resolution viewer costs ~7 Mbps (~2.95 GB/hour). Past this many
# concurrent live sessions the home uplink, not the CPU, becomes the limit
# -- roughly 70 Mbps at ten viewers, more than many connections have. Rather
# than let a spike stutter for everyone, extra viewers are served the
# substream (~0.62 Mbps), which go2rtc already publishes.
MAX_FULL_QUALITY_SESSIONS = int(os.environ.get("MAX_FULL_QUALITY_SESSIONS", "4"))

# An abandoned tab is the real cost risk, not active watching: left running
# overnight one stream is ~35 GB. The browser pings /api/heartbeat while the
# viewer is actually present; once pings stop the stream is torn down
# server-side, so closing a laptop lid ends the transfer rather than merely
# stopping the prompt.
HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get("HEARTBEAT_TIMEOUT_SECONDS", "600"))

_sessions_lock = threading.Lock()
_live_sessions = {}  # stream_token -> last heartbeat epoch

# Only these carry actual video/audio. Everything else passes through to ZM
# untouched. Verify against the installed ZM version -- these were written
# without a live ZM to test against.
ZM_MEDIA_PATTERNS = (
    re.compile(r"/zm/cgi-bin/nph-zms"),
    re.compile(r"/zm/index\.php.*view=(image|video)"),
)


def load_permissions():
    with open(PERMISSIONS_FILE) as f:
        return yaml.safe_load(f) or {}


def resolve_zm_username(session_cookie):
    """Resolve a forwarded ZM session cookie to a username.

    Queries ZM's Sessions table directly rather than round-tripping through
    ZM's API. The session blob is PHP-serialized; this does a best-effort
    regex extraction. Unverified against a live ZM -- confirm the stored
    format before trusting it.
    """
    if not session_cookie:
        return None

    conn = pymysql.connect(
        host=ZM_DB_HOST, user=ZM_DB_USER, password=ZM_DB_PASSWORD, database=ZM_DB_NAME
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT data FROM Sessions WHERE id = %s", (session_cookie,))
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    match = re.search(r's:8:"username";s:\d+:"([^"]+)"', row[0])
    return match.group(1) if match else None


def check_permission(username, permissions, now=None):
    """Return (allowed_cameras, audio_allowed) for this user right now.

    The time window is evaluated per request, not once at login, so a lapsed
    grant actually cuts a stream off mid-session.
    """
    now = now or datetime.now()
    user_perms = permissions.get(username)
    if not user_perms:
        return set(), False

    window = user_perms.get("time_window")
    if window:
        start = dtime.fromisoformat(window["start"])
        end = dtime.fromisoformat(window["end"])
        if not (start <= now.time() <= end):
            return set(), False

    return set(user_perms.get("cameras", [])), bool(user_perms.get("audio", False))


def _prune_stale_sessions():
    cutoff = time.time() - HEARTBEAT_TIMEOUT_SECONDS
    with _sessions_lock:
        for token in [t for t, seen in _live_sessions.items() if seen < cutoff]:
            del _live_sessions[token]
        return len(_live_sessions)


def resolve_stream_name(camera, audio_allowed, use_substream):
    """Map (camera, permissions, load) onto one of go2rtc's stream names.

    Audio gating is enforced by *which stream is requested*: the `_noaudio`
    variants are published by go2rtc with the audio track genuinely removed
    (verified against a live camera -- the track list is video-only, not
    merely muted), so a user without audio permission cannot receive audio
    even if they tamper with the client.
    """
    name = camera
    if use_substream:
        name += "_sub"
    if not audio_allowed:
        name += "_noaudio"
    return name


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """Keeps a live session alive; stops being called when the viewer goes away."""
    token = request.json.get("token") if request.is_json else None
    if not token:
        abort(400)
    with _sessions_lock:
        if token in _live_sessions:
            _live_sessions[token] = time.time()
    return jsonify({"ok": True})


@app.route("/live/<camera>")
def live(camera):
    session_cookie = request.cookies.get("ZMSESSID")
    username = resolve_zm_username(session_cookie)
    if not username:
        abort(401)

    permissions = load_permissions()
    allowed_cameras, audio_allowed = check_permission(username, permissions)
    if camera not in allowed_cameras:
        abort(403)

    active = _prune_stale_sessions()
    use_substream = active >= MAX_FULL_QUALITY_SESSIONS
    stream = resolve_stream_name(camera, audio_allowed, use_substream)

    token = f"{username}:{camera}:{time.time()}"
    with _sessions_lock:
        _live_sessions[token] = time.time()

    upstream = requests.get(
        f"{GO2RTC_URL}/api/stream.mp4",
        params={"src": stream},
        stream=True,
        timeout=15,
    )

    def pump():
        try:
            for chunk in upstream.iter_content(chunk_size=64 * 1024):
                # Re-check both the heartbeat and the time window on every
                # chunk, so an abandoned tab or a window that closes mid-view
                # actually stops the transfer rather than running until the
                # client disconnects.
                with _sessions_lock:
                    last_seen = _live_sessions.get(token)
                if last_seen is None or time.time() - last_seen > HEARTBEAT_TIMEOUT_SECONDS:
                    break
                still_allowed, _ = check_permission(username, load_permissions())
                if camera not in still_allowed:
                    break
                yield chunk
        finally:
            upstream.close()
            with _sessions_lock:
                _live_sessions.pop(token, None)

    resp = Response(stream_with_context(pump()), content_type="video/mp4")
    resp.headers["X-Livecam-Stream"] = stream
    resp.headers["X-Livecam-Session"] = token
    return resp


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def gate(path):
    """Everything else: ZoneMinder, with recorded media gated the same way."""
    full_path = "/" + path
    upstream_url = ZM_BACKEND_URL + full_path

    if not any(p.search(full_path) for p in ZM_MEDIA_PATTERNS):
        return _proxy(upstream_url)

    username = resolve_zm_username(request.cookies.get("ZMSESSID"))
    if not username:
        abort(401)

    permissions = load_permissions()
    allowed_cameras, audio_allowed = check_permission(username, permissions)

    monitor_id = request.args.get("monitor")
    camera_name = permissions.get("_monitor_id_to_name", {}).get(monitor_id, monitor_id)
    if camera_name not in allowed_cameras:
        abort(403)

    # Recorded events are muxed by ZoneMinder with whatever the camera sent,
    # so audio can't be selected away the way it is for live. Users without
    # audio permission are refused recorded playback rather than handed a
    # stream they shouldn't hear -- deliberately failing closed.
    if not audio_allowed:
        abort(403)

    return _proxy(upstream_url)


def _proxy(upstream_url):
    upstream = requests.request(
        method=request.method,
        url=upstream_url,
        params=request.args,
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
    )
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in excluded]
    return Response(upstream.content, upstream.status_code, headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
