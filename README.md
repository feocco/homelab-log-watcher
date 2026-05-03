# homelab-log-watcher

Small Docker log stream watcher for homelab phone alerts.

The service attaches to running container stdout/stderr streams, listens for
new container start events, and sends Joe a phone notification through
`homelab.notify_joe(...)` when a line matches the configured warning/error
patterns.

## Defaults

- Matches `ERROR`, `WARN`, `WARNING`, `FATAL`, `PANIC`, `Traceback`, and
  `Exception`.
- Suppresses repeated matching fingerprints for 1 hour.
- Sends at most 3 phone notifications per 15 minutes globally.
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
LOG_WATCHER_FINGERPRINT_COOLDOWN_SECONDS=3600
LOG_WATCHER_GLOBAL_WINDOW_SECONDS=900
LOG_WATCHER_GLOBAL_MAX_NOTIFICATIONS=3
LOG_WATCHER_STARTUP_BACKFILL_SECONDS=30
LOG_WATCHER_PUBLIC_URL=http://nasfeo:8093
LOG_WATCHER_ACTION_TOKEN=replace_me
LOG_WATCHER_MUTE_MINUTES=60
SERVICE_HOST=0.0.0.0
SERVICE_PORT=8093
LOG_LEVEL=INFO
```

The watcher stores cooldown state and manual suppressions in
`LOG_WATCHER_STATE_PATH`.

## Suppression

When `LOG_WATCHER_PUBLIC_URL` and `LOG_WATCHER_ACTION_TOKEN` are configured,
alerts include Home Assistant mobile URI buttons:

- `Mute issue 1h`
- `Mute container 1h`

The button opens the watcher suppression endpoint and writes a temporary rule to
the state file. The token in the button URL is separate from the
`HOMELAB_FUNCTIONS_TOKEN`.

Manual suppressions can also be added to the state file:

```json
{
  "suppressions": [
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
