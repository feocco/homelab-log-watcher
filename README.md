# homelab-log-watcher

Small Docker log stream watcher for homelab phone alerts.

The service attaches to running container stdout/stderr streams, listens for
new container start events, and sends Joe a phone notification through
`homelab.notify_joe(...)` when a line matches the configured warning/error
patterns.

## Defaults

- Matches `ERROR`, `WARN`, `WARNING`, `FATAL`, `PANIC`, `Traceback`, and
  `Exception`.
- Suppresses repeated matching fingerprints for 24 hours.
- Sends at most 1 phone notification per hour globally.
- Can disable phone notifications while still forwarding incidents.
- Can emit structured incidents to a separate SRE service with its own
  per-fingerprint cooldown.
- Backfills only the last 30 seconds on startup.
- Ignores the `homelab-log-watcher` container by default.

## Configuration

Copy `.env.example` to `.env` for local runs.

```text
HOMELAB_FUNCTIONS_URL=http://nasfeo:8091
HOMELAB_FUNCTIONS_TOKEN=replace_me
LOG_WATCHER_STATE_PATH=/app/state/log-watcher-state.json
LOG_WATCHER_MATCH_PATTERNS=ERROR,WARN,WARNING,FATAL,PANIC,Traceback,Exception
LOG_WATCHER_IGNORED_CONTAINERS=homelab-log-watcher
LOG_WATCHER_FINGERPRINT_COOLDOWN_SECONDS=86400
LOG_WATCHER_GLOBAL_WINDOW_SECONDS=3600
LOG_WATCHER_GLOBAL_MAX_NOTIFICATIONS=1
LOG_WATCHER_PHONE_NOTIFICATIONS_ENABLED=true
LOG_WATCHER_INCIDENT_COOLDOWN_SECONDS=86400
LOG_WATCHER_INCIDENT_WEBHOOK_URL=http://nasfeo:8094/v1/incidents
LOG_WATCHER_INCIDENT_WEBHOOK_TOKEN=replace_me
LOG_WATCHER_STARTUP_BACKFILL_SECONDS=30
LOG_WATCHER_PUBLIC_URL=http://nasfeo:8093
LOG_WATCHER_ACTION_TOKEN=replace_me
LOG_WATCHER_MUTE_MINUTES=720
LOG_WATCHER_ISSUE_SNOOZE_MINUTES=1440
LOG_WATCHER_SERVICE_SNOOZE_MINUTES=720
LOG_WATCHER_GLOBAL_SNOOZE_MINUTES=720
SERVICE_HOST=0.0.0.0
SERVICE_PORT=8093
LOG_LEVEL=INFO
```

The watcher stores cooldown state and manual suppressions in
`LOG_WATCHER_STATE_PATH`.

Set `LOG_WATCHER_PHONE_NOTIFICATIONS_ENABLED=false` when another service, such
as `homelab-sre-agent`, owns phone notifications. Incident webhook delivery
still runs when phone notifications are disabled.

## Suppression

When `LOG_WATCHER_PUBLIC_URL` and `LOG_WATCHER_ACTION_TOKEN` are configured,
alerts include Home Assistant mobile URI buttons:

- `Snooze issue 24h`
- `Snooze service 12h`
- `Snooze all 12h`

The button opens the watcher suppression endpoint and writes a temporary rule to
the state file. The token in the button URL is separate from the
`HOMELAB_FUNCTIONS_TOKEN`.

Manual suppressions can also be added to the state file:

```json
{
  "suppressions": [
    {
      "scope": "global",
      "expires_at": "2026-05-04T00:00:00+00:00"
    },
    {
      "scope": "container",
      "container": "plant-monitor",
      "expires_at": "2026-05-04T00:00:00+00:00"
    },
    {
      "scope": "pattern",
      "pattern": "known noisy warning",
      "expires_at": null
    }
  ]
}
```

## Incident Webhook

When `LOG_WATCHER_INCIDENT_WEBHOOK_URL` is configured, each matching log line
can also emit a structured incident payload. This is intentionally separate
from phone notification suppression: snoozing phone alerts does not block the
SRE incident path. Incident delivery has its own per-fingerprint cooldown via
`LOG_WATCHER_INCIDENT_COOLDOWN_SECONDS`.

Payload shape:

```json
{
  "version": 1,
  "source": "homelab-log-watcher",
  "detected_at": "2026-05-09T04:12:32+00:00",
  "incident": {
    "container_id": "abc123",
    "container_name": "plant-monitor",
    "image": "ghcr.io/feocco/plant-monitor:latest",
    "severity": "ERROR",
    "matched_pattern": "ERROR",
    "line": "ERROR failed to call Home Assistant",
    "normalized_line": "ERROR failed to call Home Assistant",
    "fingerprint": "abcdef123456...",
    "occurred_at": "2026-05-09T04:12:32+00:00"
  }
}
```

## Run Locally

```bash
python -m pip install -e /Users/feocco/code/homelab-functions
python -m pip install -e .[test]
python -m pytest
python -m homelab_log_watcher --once
```

Health check:

```bash
curl http://localhost:8093/health
```
