# livecam

A thin gate in front of the camera stack on the `cameras` VM (see the
`camera_nvr` role in the ansible repo), which is split across two backends:
[ZoneMinder](https://zoneminder.com/) does recording, storage, login and
recorded playback, while [go2rtc](https://github.com/AlexxIT/go2rtc) serves
live view by remuxing the camera stream without decoding it. ZM's own live
path is deliberately unused -- it decodes every frame and pinned the NVR box
hard enough to need a power cycle.

This app passes almost everything straight through to ZM's web console
untouched, and only intercepts stream/clip requests to add two things
neither backend enforces natively:

- A per-user **time-of-day viewing window**, re-checked continuously while a
  stream is running -- not just at login -- so a window closing mid-view
  actually cuts the stream off.
- Real per-user **audio gating**. Live view is served from go2rtc, which
  publishes a genuinely audio-free variant of each camera, so gating is a
  matter of which stream gets requested rather than anything this app does
  to the media. Verified against a live camera: the `_noaudio` track list is
  video-only, not merely muted.

Camera-level access restriction needs no code here at all -- it's handled
natively by ZM's own per-user monitor permissions.

## Deploy

Same pattern as `thisper`: push to `master`, `.github/workflows/deploy.yml`
applies this repo's own `terraform/` (ECR repo, GitHub OIDC IAM role,
`livecam.levantine.io` DNS records), builds and pushes the image to ECR,
then triggers the same Semaphore "Deploy Container" template thisper uses.
The container name (`livecam`) must already be registered in the ansible
repo's `inventories/production/group_vars/VMWareDockerHosts` before the
first deploy -- see that repo's history for this addition.

## Config

Environment variables (see `ansible`'s `VMWareDockerHosts` group_vars for
what's currently wired up as plain env vars, and what's still a follow-up
decision):

| Var | Purpose |
|---|---|
| `ZM_BACKEND_URL` | ZoneMinder on the `cameras` VM -- recorded playback only |
| `GO2RTC_URL` | go2rtc on the `cameras` VM -- live view only |
| `MAX_FULL_QUALITY_SESSIONS` | Concurrent full-res live viewers before extra ones are served the substream (default 4) |
| `HEARTBEAT_TIMEOUT_SECONDS` | Live stream is torn down after this long without a heartbeat (default 600) |
| `ZM_DB_HOST` / `ZM_DB_USER` / `ZM_DB_PASSWORD` / `ZM_DB_NAME` | Read-only access to ZM's own DB, used only to resolve a session cookie to a ZM username |
| `PERMISSIONS_FILE` | Path to the per-user permission config (default `/app/config/permissions.yml`), see `config/permissions.yml.example` |
| `FLASK_SECRET_KEY` | Flask session secret |

**Not yet wired up**: how the DB credentials and Flask secret actually get
into the running container. `ansible`'s existing per-container Vault-secret
injection (`deployDockerImage.yml`) is hardcoded to one specific env var
name for a different app (`DATA_GATEWAY_API_KEY_PATH`) and deliberately
wasn't generalized as part of adding this app, to avoid touching a role
every other production container also deploys through. The intended shape
is a dedicated Vault AppRole for `livecam` (mirroring how `service-host`
authenticates), narrowly scoped to `kv/data/livecam/*` and
`kv/data/cameras/*` read -- not yet built. Until then, these need to be
supplied some other way (e.g. a one-off env file) before this runs for
real.

## Known unverified pieces

Written without a live ZoneMinder instance to test against this session --
these are the parts most likely to need adjustment once run for real:

- `ZM_MEDIA_PATTERNS` in `livecam.py` -- the exact URL shape of ZM's live
  stream (`nph-zms`) and event-clip endpoints, which is what determines
  whether a request gets gated at all.
- `resolve_zm_username()` -- the exact format of ZM's `Sessions` table and
  its PHP-serialized session data varies by version; the regex extraction
  here is a best-effort first pass.
- The client side of the heartbeat isn't written yet -- the server will tear
  a stream down after `HEARTBEAT_TIMEOUT_SECONDS`, so until a page actually
  posts to `/api/heartbeat` every live view dies after that timeout.
