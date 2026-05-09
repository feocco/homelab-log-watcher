from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Iterable
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import Config
from .fingerprint import clean_line, fingerprint, normalize_line
from .state import StateStore, utc_now


LOGGER = logging.getLogger("homelab-log-watcher")
ERROR_WORDS = ("ERROR", "FATAL", "PANIC", "TRACEBACK", "EXCEPTION")


@dataclass(frozen=True)
class Alert:
    container_id: str
    container_name: str
    image: str
    severity: str
    matched_pattern: str
    line: str
    normalized_line: str
    fingerprint: str
    occurred_at: datetime


class LogMatcher:
    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns = tuple(patterns)
        self.regexes = tuple((pattern, re.compile(pattern, re.IGNORECASE)) for pattern in self.patterns)

    def match(
        self,
        *,
        container_id: str,
        container_name: str,
        image: str,
        line: bytes | str,
        occurred_at: datetime | None = None,
    ) -> Alert | None:
        cleaned = clean_line(line)
        if not cleaned:
            return None
        for pattern, regex in self.regexes:
            if not regex.search(cleaned):
                continue
            upper_line = cleaned.upper()
            upper_pattern = pattern.upper()
            severity = "ERROR" if upper_pattern in ERROR_WORDS or any(word in upper_line for word in ERROR_WORDS) else "WARN"
            normalized = normalize_line(cleaned)
            return Alert(
                container_id=container_id,
                container_name=container_name,
                image=image,
                severity=severity,
                matched_pattern=pattern,
                line=cleaned,
                normalized_line=normalized,
                fingerprint=fingerprint(container_name, severity, normalized),
                occurred_at=occurred_at or utc_now(),
            )
        return None


class HomelabNotifier:
    def __init__(
        self,
        notify_func: Callable[..., dict[str, Any]] | None = None,
        *,
        action_base_url: str | None = None,
        action_token: str | None = None,
        mute_minutes: int = 60,
        issue_snooze_minutes: int = 1440,
        service_snooze_minutes: int = 720,
        global_snooze_minutes: int = 720,
    ) -> None:
        if notify_func is None:
            import homelab

            notify_func = homelab.notify_joe
        self.notify_func = notify_func
        self.action_base_url = action_base_url.rstrip("/") if action_base_url else None
        self.action_token = action_token
        self.mute_minutes = mute_minutes
        self.issue_snooze_minutes = issue_snooze_minutes
        self.service_snooze_minutes = service_snooze_minutes
        self.global_snooze_minutes = global_snooze_minutes

    def send(self, alert: Alert, *, suppressed_count: int, global_suppressed_count: int) -> dict[str, Any]:
        title = f"log watcher - {alert.container_name}"
        details = [
            f"Timestamp: {format_timestamp(alert.occurred_at)}",
            f"Log level: {alert.severity}",
            f"Message: {truncate(alert.line, 700)}",
            f"Fingerprint: {alert.fingerprint[:12]}",
        ]
        if suppressed_count:
            details.append(f"Suppressed repeats: {suppressed_count}")
        if global_suppressed_count:
            details.append(f"Global suppressed while cooling down: {global_suppressed_count}")

        kwargs: dict[str, Any] = {
            "tag": f"log-watcher-{alert.fingerprint[:16]}",
            "group": "log-watcher",
        }
        buttons = self._buttons(alert)
        if buttons:
            kwargs["buttons"] = buttons

        return self.notify_func(title, "\n".join(details), **kwargs)

    def _buttons(self, alert: Alert) -> list[dict[str, str]]:
        if not self.action_base_url or not self.action_token:
            return []
        return [
            {
                "title": "Snooze issue 24h",
                "action": "URI",
                "uri": self._suppression_url(
                    scope="fingerprint",
                    container=alert.container_name,
                    fingerprint_value=alert.fingerprint,
                    minutes=self.issue_snooze_minutes,
                ),
            },
            {
                "title": "Snooze service 12h",
                "action": "URI",
                "uri": self._suppression_url(
                    scope="container",
                    container=alert.container_name,
                    minutes=self.service_snooze_minutes,
                ),
            },
            {
                "title": "Snooze all 12h",
                "action": "URI",
                "uri": self._suppression_url(
                    scope="global",
                    container=alert.container_name,
                    minutes=self.global_snooze_minutes,
                ),
            },
        ]

    def _suppression_url(
        self,
        *,
        scope: str,
        container: str,
        minutes: int,
        fingerprint_value: str | None = None,
    ) -> str:
        params = {
            "token": self.action_token or "",
            "scope": scope,
            "container": container,
            "minutes": str(minutes),
        }
        if fingerprint_value is not None:
            params["fingerprint"] = fingerprint_value
        return f"{self.action_base_url}/v1/suppress?{urlencode(params)}"


class IncidentEmitter:
    def __init__(
        self,
        *,
        webhook_url: str | None,
        token: str | None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url
        self.token = token
        self.timeout_seconds = timeout_seconds

    def configured(self) -> bool:
        return self.webhook_url is not None

    def send(self, alert: Alert, *, detected_at: datetime) -> None:
        if self.webhook_url is None:
            return

        body = json.dumps(
            {
                "version": 1,
                "source": "homelab-log-watcher",
                "detected_at": format_timestamp(detected_at),
                "incident": {
                    "container_id": alert.container_id,
                    "container_name": alert.container_name,
                    "image": alert.image,
                    "severity": alert.severity,
                    "matched_pattern": alert.matched_pattern,
                    "line": truncate(alert.line, 2000),
                    "normalized_line": alert.normalized_line,
                    "fingerprint": alert.fingerprint,
                    "occurred_at": format_timestamp(alert.occurred_at),
                },
            },
            sort_keys=True,
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(self.webhook_url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response.read()
        except URLError:
            raise


class AlertProcessor:
    def __init__(
        self,
        *,
        config: Config,
        state: StateStore,
        notifier: HomelabNotifier,
        incident_emitter: IncidentEmitter | None = None,
        now_func: Callable[[], datetime] = utc_now,
    ) -> None:
        self.config = config
        self.state = state
        self.notifier = notifier
        self.incident_emitter = incident_emitter
        self.now_func = now_func

    def process(self, alert: Alert) -> bool:
        now = self.now_func()
        self._emit_incident(alert, now)

        if self.state.is_suppressed(
            container_name=alert.container_name,
            fingerprint_value=alert.fingerprint,
            normalized_line=alert.normalized_line,
            now=now,
        ):
            LOGGER.debug("Suppressed alert by manual rule: %s %s", alert.container_name, alert.fingerprint[:12])
            return False

        fingerprint_allowed, suppressed_count = self.state.fingerprint_allowed(
            alert.fingerprint,
            now,
            self.config.fingerprint_cooldown_seconds,
        )
        if not fingerprint_allowed:
            LOGGER.debug("Suppressed alert by fingerprint cooldown: %s %s", alert.container_name, alert.fingerprint[:12])
            return False

        global_allowed, global_suppressed_count = self.state.global_allowed(
            now,
            self.config.global_window_seconds,
            self.config.global_max_notifications,
        )
        if not global_allowed:
            LOGGER.warning("Suppressed alert by global rate limit: %s %s", alert.container_name, alert.fingerprint[:12])
            return False

        try:
            self.notifier.send(
                alert,
                suppressed_count=suppressed_count,
                global_suppressed_count=global_suppressed_count,
            )
        except Exception:
            LOGGER.exception("Failed to send alert notification")
            raise

        self.state.mark_sent(alert.fingerprint, now)
        LOGGER.info("Sent alert for %s fingerprint=%s", alert.container_name, alert.fingerprint[:12])
        return True

    def _emit_incident(self, alert: Alert, now: datetime) -> None:
        if self.incident_emitter is None or not self.incident_emitter.configured():
            return
        if not self.state.incident_allowed(alert.fingerprint, now, self.config.incident_cooldown_seconds):
            LOGGER.debug("Suppressed incident webhook by cooldown: %s %s", alert.container_name, alert.fingerprint[:12])
            return
        try:
            self.incident_emitter.send(alert, detected_at=now)
        except Exception:
            LOGGER.exception("Failed to send incident webhook")
            return
        self.state.mark_incident_sent(alert.fingerprint, now)
        LOGGER.info("Sent incident webhook for %s fingerprint=%s", alert.container_name, alert.fingerprint[:12])


class DockerLogWatcher:
    def __init__(
        self,
        *,
        docker_client: Any,
        config: Config,
        matcher: LogMatcher,
        processor: AlertProcessor,
    ) -> None:
        self.docker_client = docker_client
        self.config = config
        self.matcher = matcher
        self.processor = processor
        self.threads: dict[str, threading.Thread] = {}
        self.lock = threading.Lock()

    def run_forever(self) -> None:
        self.attach_existing()
        while True:
            try:
                self.watch_events()
            except Exception:
                LOGGER.exception("Docker event stream failed; reconnecting")
                time.sleep(5)

    def attach_existing(self) -> None:
        for container in self.docker_client.containers.list():
            self.attach(container, since_seconds=self.config.startup_backfill_seconds)

    def watch_events(self) -> None:
        for event in self.docker_client.events(decode=True, filters={"type": "container"}):
            action = event.get("Action")
            container_id = event.get("id")
            if action not in {"start", "restart"} or not container_id:
                continue
            try:
                container = self.docker_client.containers.get(container_id)
            except Exception:
                LOGGER.exception("Could not inspect started container %s", container_id[:12])
                continue
            self.attach(container, since_seconds=self.config.startup_backfill_seconds)

    def attach(self, container: Any, *, since_seconds: int) -> None:
        name = getattr(container, "name", "")
        if name in self.config.ignored_containers:
            LOGGER.debug("Skipping ignored container %s", name)
            return
        container_id = getattr(container, "id", "")
        with self.lock:
            existing = self.threads.get(container_id)
            if existing is not None and existing.is_alive():
                return
            thread = threading.Thread(
                target=self._stream_container,
                args=(container, since_seconds),
                name=f"log-stream-{name}",
                daemon=True,
            )
            self.threads[container_id] = thread
            thread.start()
        LOGGER.info("Attached log stream for %s", name)

    def _stream_container(self, container: Any, since_seconds: int) -> None:
        name = getattr(container, "name", "")
        container_id = getattr(container, "id", "")
        image = container_image(container)
        since = max(0, int(time.time()) - since_seconds)
        try:
            for raw_line in container.logs(stream=True, follow=True, stdout=True, stderr=True, since=since):
                alert = self.matcher.match(
                    container_id=container_id,
                    container_name=name,
                    image=image,
                    line=raw_line,
                )
                if alert is None:
                    continue
                self.processor.process(alert)
        except Exception as exc:
            if expected_stream_close(exc):
                LOGGER.info("Log stream ended for stopped container %s: %s", name, exc)
            else:
                LOGGER.exception("Log stream ended unexpectedly for %s", name)
        finally:
            with self.lock:
                self.threads.pop(container_id, None)


def container_image(container: Any) -> str:
    attrs = getattr(container, "attrs", {}) or {}
    config = attrs.get("Config") if isinstance(attrs, dict) else None
    image = config.get("Image") if isinstance(config, dict) else None
    if isinstance(image, str) and image:
        return image
    image_obj = getattr(container, "image", None)
    tags = getattr(image_obj, "tags", None)
    if isinstance(tags, list) and tags:
        return str(tags[0])
    return "unknown"


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def expected_stream_close(exc: Exception) -> bool:
    text = str(exc).lower()
    expected_fragments = (
        "dead or marked for removal",
        "container is not running",
        "no such container",
    )
    return any(fragment in text for fragment in expected_fragments)
