"""
livecam -- a thin gate in front of ZoneMinder.

Almost every request is passed straight through to ZM untouched (login page,
dashboard, monitor list, event browser -- all native ZM UI/UX, including its
own per-user per-camera restriction). This app only intercepts the two
things ZM has no native concept of: a per-user time-of-day viewing window,
and true per-user audio gating (stripping the audio track for users who
shouldn't get it, rather than a client-side mute).

ZM itself is never exposed directly to LAN or WAN clients -- only this app
is (see the `livecam` entry in ansible's VMWareDockerHosts group_vars) --
so these checks can't be bypassed by hitting ZM's own URL directly.
"""

import os
import re
import subprocess
from datetime import datetime, time as dtime

import pymysql
import requests
import yaml
from flask import Flask, Response, request, abort

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

ZM_BACKEND_URL = os.environ["ZM_BACKEND_URL"].rstrip("/")
PERMISSIONS_FILE = os.environ.get("PERMISSIONS_FILE", "/app/config/permissions.yml")

# Read-only access to ZM's own MySQL database, used only to resolve "which
# ZM user does this session cookie belong to" -- see resolve_zm_username()
# below. Exact schema/session-serialization details verified against the
# actual installed ZM version, not assumed here to be exactly right on the
# first pass.
ZM_DB_HOST = os.environ.get("ZM_DB_HOST")
ZM_DB_USER = os.environ.get("ZM_DB_USER")
ZM_DB_PASSWORD = os.environ.get("ZM_DB_PASSWORD")
ZM_DB_NAME = os.environ.get("ZM_DB_NAME", "zm")

# Paths that carry actual video/audio content -- these are the only ones
# gated by time-window/audio checks; everything else (login, dashboard,
# monitor list, event browser chrome) passes through untouched. ZM's
# streaming CGI is nph-zms; event clip downloads and frame images live
# under /zm/index.php with a view= query param. Verify these patterns
# against the actual installed ZM version's URLs before relying on this --
# flagged in the implementation plan as the one piece most likely to need
# adjustment once tested live.
MEDIA_PATH_PATTERNS = (
    re.compile(r"/zm/cgi-bin/nph-zms"),
    re.compile(r"/zm/index\.php.*view=(image|video)"),
)


def load_permissions():
    with open(PERMISSIONS_FILE) as f:
        return yaml.safe_load(f) or {}


def resolve_zm_username(session_cookie):
    """Look up which ZM user a forwarded session cookie belongs to.

    Queries ZM's own Sessions table directly (colocated on the same LAN)
    rather than trying to call one of ZM's own API endpoints with the
    forwarded cookie -- simpler and doesn't depend on guessing the right
    unauthenticated-but-session-aware API route. ZM's session data is a
    PHP-serialized blob; this does a best-effort regex extraction of the
    username field rather than a full PHP unserialize (no good stdlib
    option in Python) -- verify this still matches the real stored format
    on the installed ZM version.
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
    """Return (camera_names_allowed, audio_allowed) for this user right now.

    Time window is checked here, not just at login, so a lapsed grant
    actually cuts off access mid-session -- both for live streams and for
    browsing footage recorded outside the window.
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


def is_media_path(path):
    return any(p.search(path) for p in MEDIA_PATH_PATTERNS)


def strip_audio(content, content_type):
    """Cheap `-an` remux -- no video re-encode, just drops the audio track."""
    proc = subprocess.run(
        [
            "ffmpeg", "-y", "-i", "pipe:0",
            "-c:v", "copy", "-an",
            "-f", _format_for(content_type),
            "pipe:1",
        ],
        input=content,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return proc.stdout


def _format_for(content_type):
    # Extend as needed once tested against ZM's actual served content-types
    # for live streams vs event clip downloads.
    return "mp4" if "mp4" in (content_type or "") else "matroska"


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def gate(path):
    full_path = "/" + path
    upstream_url = ZM_BACKEND_URL + full_path

    if not is_media_path(full_path):
        # Not a stream/clip request -- pass straight through untouched.
        return _proxy(upstream_url)

    session_cookie = request.cookies.get("ZMSESSID")
    username = resolve_zm_username(session_cookie)
    if not username:
        abort(401)

    permissions = load_permissions()
    allowed_cameras, audio_allowed = check_permission(username, permissions)

    monitor_id = request.args.get("monitor")
    camera_name = permissions.get("_monitor_id_to_name", {}).get(monitor_id, monitor_id)
    if camera_name not in allowed_cameras:
        abort(403)

    resp = _proxy(upstream_url, return_response=True)

    if not audio_allowed and resp.status_code == 200:
        stripped = strip_audio(resp.content, resp.headers.get("Content-Type"))
        return Response(stripped, status=resp.status_code, content_type=resp.headers.get("Content-Type"))

    return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))


def _proxy(upstream_url, return_response=False):
    upstream = requests.request(
        method=request.method,
        url=upstream_url,
        params=request.args,
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=not return_response,
    )
    if return_response:
        return upstream

    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in excluded_headers]
    return Response(upstream.content, upstream.status_code, headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
