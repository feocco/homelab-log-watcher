from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


DEFAULT_PATTERNS = ("ERROR", "WARN", "WARNING", "FATAL", "PANIC", "Traceback", "Exception")


@dataclass(frozen=True)
class Config:
    state_path: Path
    match_patterns: tuple[str, ...]
    ignored_containers: tuple[str, ...]
    fingerprint_cooldown_seconds: int
    global_window_seconds: int
    global_max_notifications: int
    incident_cooldown_seconds: int
    incident_webhook_url: str | None
    incident_webhook_token: str | None
    startup_backfill_seconds: int
    public_url: str | None
    action_token: str | None
    mute_minutes: int
    issue_snooze_minutes: int
    service_snooze_minutes: int
    global_snooze_minutes: int
    service_host: str
    service_port: int
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            state_path=Path(os.environ.get("LOG_WATCHER_STATE_PATH", "/app/state/log-watcher-state.json")),
            match_patterns=parse_csv(os.environ.get("LOG_WATCHER_MATCH_PATTERNS"), DEFAULT_PATTERNS),
            ignored_containers=parse_csv(os.environ.get("LOG_WATCHER_IGNORED_CONTAINERS"), ("homelab-log-watcher",)),
            fingerprint_cooldown_seconds=parse_int("LOG_WATCHER_FINGERPRINT_COOLDOWN_SECONDS", 86400),
            global_window_seconds=parse_int("LOG_WATCHER_GLOBAL_WINDOW_SECONDS", 3600),
            global_max_notifications=parse_int("LOG_WATCHER_GLOBAL_MAX_NOTIFICATIONS", 1),
            incident_cooldown_seconds=parse_int("LOG_WATCHER_INCIDENT_COOLDOWN_SECONDS", 86400),
            incident_webhook_url=parse_optional_str(os.environ.get("LOG_WATCHER_INCIDENT_WEBHOOK_URL")),
            incident_webhook_token=parse_optional_str(os.environ.get("LOG_WATCHER_INCIDENT_WEBHOOK_TOKEN")),
            startup_backfill_seconds=parse_int("LOG_WATCHER_STARTUP_BACKFILL_SECONDS", 30),
            public_url=parse_optional_str(os.environ.get("LOG_WATCHER_PUBLIC_URL")),
            action_token=parse_optional_str(os.environ.get("LOG_WATCHER_ACTION_TOKEN")),
            mute_minutes=parse_int("LOG_WATCHER_MUTE_MINUTES", 720),
            issue_snooze_minutes=parse_int("LOG_WATCHER_ISSUE_SNOOZE_MINUTES", 1440),
            service_snooze_minutes=parse_int("LOG_WATCHER_SERVICE_SNOOZE_MINUTES", 720),
            global_snooze_minutes=parse_int("LOG_WATCHER_GLOBAL_SNOOZE_MINUTES", 720),
            service_host=os.environ.get("SERVICE_HOST", "0.0.0.0"),
            service_port=parse_int("SERVICE_PORT", 8093),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )


def parse_csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None or not value.strip():
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


def parse_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{name} must be >= 0")
    return parsed


def parse_optional_str(value: str | None) -> str | None:
    if value is None or not value.strip() or value.strip() == "replace_me":
        return None
    return value.strip()
