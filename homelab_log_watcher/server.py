from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import logging
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .config import Config
from .state import StateStore


LOGGER = logging.getLogger("homelab-log-watcher.server")


class SuppressionServer:
    def __init__(self, *, config: Config, state: StateStore) -> None:
        self.config = config
        self.state = state
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        handler = self._handler()
        self.httpd = ThreadingHTTPServer((self.config.service_host, self.config.service_port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="suppression-server", daemon=True)
        self.thread.start()
        LOGGER.info("Suppression server listening on %s:%s", self.config.service_host, self.config.service_port)

    def _handler(self):
        config = self.config
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                if parsed.path == "/health":
                    write_json(self, HTTPStatus.OK, {"ok": True})
                    return
                if parsed.path != "/v1/suppress":
                    write_json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return

                if not config.action_token:
                    write_json(self, HTTPStatus.SERVICE_UNAVAILABLE, {"error": "suppression actions are disabled"})
                    return

                params = parse_qs(parsed.query)
                token = first(params, "token")
                if not token or not hmac.compare_digest(token, config.action_token):
                    write_json(self, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return

                scope = first(params, "scope")
                container = first(params, "container")
                fingerprint_value = first(params, "fingerprint")
                pattern = first(params, "pattern")
                minutes = parse_minutes(first(params, "minutes"), config.mute_minutes)

                if scope == "container" and not container:
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "container is required"})
                    return
                if scope == "fingerprint" and not fingerprint_value:
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "fingerprint is required"})
                    return
                if scope == "pattern" and not pattern:
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "pattern is required"})
                    return
                if scope not in {"container", "fingerprint", "global", "pattern"}:
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "unsupported scope"})
                    return

                payload = state.add_suppression(
                    scope=scope,
                    now=datetime.now(timezone.utc),
                    minutes=minutes,
                    container=container,
                    fingerprint_value=fingerprint_value,
                    pattern=pattern,
                )
                write_json(self, HTTPStatus.OK, {"ok": True, "suppression": payload})

            def log_message(self, format: str, *args: Any) -> None:
                LOGGER.debug(format, *args)

        return Handler


def first(params: dict[str, list[str]], key: str) -> str | None:
    values = params.get(key)
    if not values:
        return None
    value = values[0].strip()
    return value or None


def parse_minutes(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(0, parsed)


def write_json(handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
