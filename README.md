# livecam

The front door to the camera stack on the `cameras` VM (see the `camera_nvr`
role in the ansible repo), which is split across two backends:
[ZoneMinder](https://zoneminder.com/) does recording, storage and recorded
playback, while [go2rtc](https://github.com/AlexxIT/go2rtc) serves live view
by remuxing the camera stream without decoding it. ZM's own live path is
deliberately unused -- it decodes every frame and pinned the NVR box hard
enough to need a power cycle.

Neither backend is reachable from outside the LAN. Only this app is, so its
checks cannot be sidestepped by hitting go2rtc or ZoneMinder directly.

What this app adds on top of the backends:

- Its **own login**, and its own dashboard of live tiles. Everyday viewing
  never touches ZoneMinder's UI, which matters because most of the people
  using this are not technical.
- A per-user **time-of-day viewing window**, re-checked continuously while a
  stream is running -- not just at login -- so a window closing mid-view
  actually cuts the stream off.
- Real per-user **audio gating**. Live view is served from go2rtc, which
  publishes a genuinely audio-free variant of each camera, so gating is a
  matter of which stream gets requested rather than anything this app does
  to the media. Verified against a live camera: the `_noaudio` track list is
  video-only, not merely muted.
- **Bandwidth discipline**: tiles use the camera's own 704x480 substream
  (~0.65 Mbps) and only the expanded view pulls the full 2960x1668 feed
  (~7 Mbps), with a cap on concurrent full-quality streams and a heartbeat
  that tears down abandoned tabs.
- An **egress counter** and a **"you're at home" banner**, both described
  below.

## Accounts

Two logins per person, on purpose:

1. **livecam's own account** -- what the dashboard uses. Nothing here is
   reachable without it, including the proxied ZoneMinder console.
2. **ZoneMinder's account** -- prompted for separately when someone opens
   *recordings & settings*. ZM keeps its own account system and its own
   native per-user monitor permissions; this app does not try to replace or
   bridge them.

An earlier version had no accounts of its own and instead resolved a
forwarded `ZMSESSID` cookie back to a ZM username by reading ZM's `Sessions`
table and regex-matching PHP's session serialization. That is gone. It was
fragile (the serialization format is version-specific, and the first version
of the regex silently matched nothing, making every request look logged
out), it forced everyone through ZM's login page first, and it never
reliably carried a session through the proxy anyway.

Accounts are provisioned by hand -- there are a handful of family users and
no self-registration. Users live in `permissions.yml` (deployed by the
ansible repo's `livecam` role), where each gains a `password_hash` beside
their `cameras` / `audio` / `time_window` entries, so one file answers both
"who exists" and "what may they see". Only the hash is committed, never the
password:

```
python3 -c "from werkzeug.security import generate_password_hash as h; import getpass; print(h(getpass.getpass()))"
```

## The two hostnames

`livecam.levantine.io` is the public route: it resolves to AWS and relays
back down into the house over WireGuard. `livecam-lan.levantine.io` resolves
straight to the Docker host on the LAN. Both are served by the same
container and both are covered by the existing `*.levantine.io` wildcard
cert -- which is exactly why the LAN name is a flat label rather than
`livecam.local.levantine.io`, since a wildcard matches only one label.

Watching from home on the *public* name sends every frame up the uplink to
Oregon and back down again, billed as egress, so the dashboard shows a
dismissible banner on that hostname only, linking to the LAN one. It is
never shown on the LAN hostname, and dismissal is remembered per browser and
per hostname in `localStorage`.

## Egress counter

Bytes served **via the public hostname only** are counted and shown against
AWS's 100 GB/month free tier. LAN traffic never leaves the house and is
excluded, which is the whole point of the number.

- Stored in SQLite on a writable volume (`/opt/livecam/data`), keyed by UTC
  `YYYY-MM`, so the month rolls over by arithmetic. Nothing is scheduled and
  so nothing is missed if the container happens to be down on the 1st.
- Accumulated in memory and flushed on size or age (and unconditionally when
  a stream ends), rather than writing per 64 KB chunk.
- Labelled *camera traffic via AWS*, not total account egress. Other
  services on the host egress too, so this is a **lower bound** on the real
  bill. Camera video dwarfs the rest here, which is what makes it useful.

## Deploy

Same pattern as `thisper`: push to `master`, `.github/workflows/deploy.yml`
applies this repo's own `terraform/` (ECR repo, GitHub OIDC IAM role, the
`livecam.levantine.io` and `livecam-lan.levantine.io` DNS records), builds
and pushes the image to ECR, then triggers the same Semaphore "Deploy
Container" template thisper uses. The container name (`livecam`) is
registered in the ansible repo's
`inventories/production/group_vars/VMWareDockerHosts`, which is also where
its env vars, Vault-injected secrets and volumes are declared.

## Config

| Var | Purpose |
|---|---|
| `ZM_BACKEND_URL` | ZoneMinder on the `cameras` VM -- recorded playback only |
| `GO2RTC_URL` | go2rtc on the `cameras` VM -- live view only |
| `PUBLIC_HOSTNAME` | Hostname that routes via AWS; drives the banner and what counts as egress |
| `LAN_HOSTNAME` | Hostname that stays on the LAN; the banner's link target |
| `PERMISSIONS_FILE` | Per-user permission config (default `/app/config/permissions.yml`), see `config/permissions.yml.example` |
| `FLASK_SECRET_KEY` | Flask session secret -- from Vault, `kv/data/livecam/admin` |
| `EGRESS_DB` | SQLite path for the egress counter (default `/app/data/egress.db`) |
| `FREE_TIER_BYTES` | Free-tier allowance the meter is drawn against (default 100 GB) |
| `MAX_FULL_QUALITY_SESSIONS` | Concurrent full-res live viewers before extra ones are served the substream (default 4) |
| `HEARTBEAT_TIMEOUT_SECONDS` | Live stream is torn down after this long without a heartbeat (default 600) |
| `SESSION_COOKIE_SECURE` | Off by default: plain HTTP to this container is a supported path (nginx-proxy runs `HTTPS_METHOD=noredirect`, and the AWS relay arrives over HTTP), and setting it without that being true end to end makes login loop silently |

## Still unverified

- `ZM_MEDIA_PATTERNS` in `livecam.py` -- the exact URL shape of ZM's
  event-clip endpoints, which determines whether a recorded-media request
  gets gated at all. The live path (`nph-zms`) is not used by this app's own
  dashboard, only reachable through the proxied ZM console.
