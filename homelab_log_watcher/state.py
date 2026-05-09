from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class Suppression:
    scope: str
    container: str | None = None
    fingerprint: str | None = None
    pattern: str | None = None
    expires_at: datetime | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Suppression":
        return cls(
            scope=str(payload.get("scope") or ""),
            container=str(payload["container"]) if payload.get("container") else None,
            fingerprint=str(payload["fingerprint"]) if payload.get("fingerprint") else None,
            pattern=str(payload["pattern"]).lower() if payload.get("pattern") else None,
            expires_at=parse_dt(payload.get("expires_at")),
        )

    def active(self, now: datetime) -> bool:
        return self.expires_at is None or self.expires_at > now


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        with self.path.open(encoding="utf-8") as state_file:
            payload = json.load(state_file)
        if not isinstance(payload, dict):
            return self._empty()
        payload.setdefault("version", 1)
        payload.setdefault("fingerprints", {})
        payload.setdefault("incident_sent_at", {})
        payload.setdefault("global_sent_at", [])
        payload.setdefault("global_suppressed_count", 0)
        payload.setdefault("suppressions", [])
        return payload

    def _empty(self) -> dict[str, Any]:
        return {
            "version": 1,
            "fingerprints": {},
            "incident_sent_at": {},
            "global_sent_at": [],
            "global_suppressed_count": 0,
            "suppressions": [],
        }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.path.parent,
            delete=False,
        ) as tmp_file:
            json.dump(self.data, tmp_file, indent=2, sort_keys=True)
            tmp_file.write("\n")
            tmp_name = tmp_file.name
        Path(tmp_name).replace(self.path)

    def suppressions(self, now: datetime) -> list[Suppression]:
        active: list[dict[str, Any]] = []
        parsed: list[Suppression] = []
        for item in self.data.get("suppressions", []):
            if not isinstance(item, dict):
                continue
            suppression = Suppression.from_payload(item)
            if not suppression.active(now):
                continue
            active.append(item)
            parsed.append(suppression)
        if len(active) != len(self.data.get("suppressions", [])):
            self.data["suppressions"] = active
            self.save()
        return parsed

    def is_suppressed(
        self,
        *,
        container_name: str,
        fingerprint_value: str,
        normalized_line: str,
        now: datetime,
    ) -> bool:
        for suppression in self.suppressions(now):
            if suppression.scope == "global":
                return True
            if suppression.scope == "container" and suppression.container == container_name:
                return True
            if suppression.scope == "fingerprint" and suppression.fingerprint == fingerprint_value:
                return True
            if suppression.scope == "pattern" and suppression.pattern and suppression.pattern in normalized_line:
                if suppression.container is None or suppression.container == container_name:
                    return True
        return False

    def fingerprint_allowed(self, fingerprint_value: str, now: datetime, cooldown_seconds: int) -> tuple[bool, int]:
        records = self.data.setdefault("fingerprints", {})
        record = records.setdefault(fingerprint_value, {"last_sent_at": None, "suppressed_count": 0})
        last_sent = parse_dt(record.get("last_sent_at"))
        if last_sent is not None and now - last_sent < timedelta(seconds=cooldown_seconds):
            record["suppressed_count"] = int(record.get("suppressed_count") or 0) + 1
            self.save()
            return False, int(record["suppressed_count"])
        return True, int(record.get("suppressed_count") or 0)

    def global_allowed(self, now: datetime, window_seconds: int, max_notifications: int) -> tuple[bool, int]:
        cutoff = now - timedelta(seconds=window_seconds)
        sent_at = [value for value in (parse_dt(item) for item in self.data.get("global_sent_at", [])) if value and value >= cutoff]
        self.data["global_sent_at"] = [format_dt(value) for value in sent_at]
        if max_notifications > 0 and len(sent_at) >= max_notifications:
            self.data["global_suppressed_count"] = int(self.data.get("global_suppressed_count") or 0) + 1
            self.save()
            return False, int(self.data["global_suppressed_count"])
        return True, int(self.data.get("global_suppressed_count") or 0)

    def incident_allowed(self, fingerprint_value: str, now: datetime, cooldown_seconds: int) -> bool:
        records = self.data.setdefault("incident_sent_at", {})
        last_sent = parse_dt(records.get(fingerprint_value))
        if last_sent is not None and now - last_sent < timedelta(seconds=cooldown_seconds):
            return False
        return True

    def mark_incident_sent(self, fingerprint_value: str, now: datetime) -> None:
        self.data.setdefault("incident_sent_at", {})[fingerprint_value] = format_dt(now)
        self.save()

    def mark_sent(self, fingerprint_value: str, now: datetime) -> tuple[int, int]:
        records = self.data.setdefault("fingerprints", {})
        record = records.setdefault(fingerprint_value, {})
        suppressed = int(record.get("suppressed_count") or 0)
        global_suppressed = int(self.data.get("global_suppressed_count") or 0)
        record["last_sent_at"] = format_dt(now)
        record["suppressed_count"] = 0
        self.data["global_suppressed_count"] = 0
        self.data.setdefault("global_sent_at", []).append(format_dt(now))
        self.save()
        return suppressed, global_suppressed

    def add_suppression(
        self,
        *,
        scope: str,
        now: datetime,
        minutes: int,
        container: str | None = None,
        fingerprint_value: str | None = None,
        pattern: str | None = None,
    ) -> dict[str, Any]:
        expires_at = None if minutes <= 0 else now + timedelta(minutes=minutes)
        payload = {
            "scope": scope,
            "container": container,
            "fingerprint": fingerprint_value,
            "pattern": pattern,
            "expires_at": format_dt(expires_at) if expires_at is not None else None,
        }
        self.data.setdefault("suppressions", []).append({key: value for key, value in payload.items() if value is not None})
        self.save()
        return payload
