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

DOCS_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>homelab-log-watcher API</title>
    <style>
      :root { color-scheme: light dark; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        line-height: 1.5;
        margin: 2rem auto;
        max-width: 56rem;
        padding: 0 1rem 3rem;
      }
      code { font-family: "SFMono-Regular", Menlo, monospace; }
      h1, h2 { line-height: 1.2; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #9993; padding: 0.6rem; text-align: left; vertical-align: top; }
      th { font-weight: 600; }
    </style>
  </head>
  <body>
    <h1>homelab-log-watcher API</h1>
    <p>Small HTTP surface for service health, machine-readable API metadata, and manual suppression actions.</p>

    <h2>Endpoints</h2>
    <table>
      <thead>
        <tr><th>Method</th><th>Path</th><th>Purpose</th></tr>
      </thead>
      <tbody>
        <tr><td><code>GET</code></td><td><code>/health</code></td><td>Returns <code>{"ok": true}</code> when the server is reachable.</td></tr>
        <tr><td><code>GET</code></td><td><code>/docs</code></td><td>Returns this HTML reference.</td></tr>
        <tr><td><code>GET</code></td><td><code>/openapi.json</code></td><td>Returns the OpenAPI 3.1 schema for this service.</td></tr>
        <tr><td><code>GET</code></td><td><code>/v1/suppress</code></td><td>Creates a temporary suppression rule for phone alert actions.</td></tr>
      </tbody>
    </table>

    <h2>Suppression Actions</h2>
    <p><code>/v1/suppress</code> requires the query parameter <code>token</code>. When <code>LOG_WATCHER_ACTION_TOKEN</code> is unset the endpoint returns <code>503</code>. When the token is missing or wrong it returns <code>401</code>.</p>
    <p>Supported <code>scope</code> values are <code>global</code>, <code>container</code>, <code>fingerprint</code>, and <code>pattern</code>. Additional query parameters depend on scope:</p>
    <ul>
      <li><code>container</code>: requires <code>container</code></li>
      <li><code>fingerprint</code>: requires <code>fingerprint</code></li>
      <li><code>pattern</code>: requires <code>pattern</code></li>
    </ul>
    <p><code>minutes</code> is optional. Invalid values fall back to the configured mute default.</p>
    <p>See <code>/openapi.json</code> for the precise request and response schema.</p>
  </body>
</html>
"""

OPENAPI_SCHEMA: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {
        "title": "homelab-log-watcher API",
        "version": "0.1.0",
        "description": (
            "HTTP endpoints exposed by homelab-log-watcher for health checks, "
            "service documentation, and manual suppression actions."
        ),
    },
    "paths": {
        "/health": {
            "get": {
                "summary": "Health check",
                "responses": {
                    "200": {
                        "description": "Service health",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"ok": {"type": "boolean", "const": True}},
                                    "required": ["ok"],
                                    "additionalProperties": False,
                                }
                            }
                        },
                    }
                },
            }
        },
        "/docs": {
            "get": {
                "summary": "Human-readable service documentation",
                "responses": {
                    "200": {
                        "description": "Service documentation",
                        "content": {
                            "text/html": {
                                "schema": {"type": "string"}
                            }
                        },
                    }
                },
            }
        },
        "/openapi.json": {
            "get": {
                "summary": "OpenAPI schema",
                "responses": {
                    "200": {
                        "description": "OpenAPI schema",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        },
                    }
                },
            }
        },
        "/v1/suppress": {
            "get": {
                "summary": "Create a temporary suppression rule",
                "description": (
                    "This endpoint is intended for Home Assistant mobile action links. "
                    "It requires the action token in the query string."
                ),
                "security": [{"ActionToken": []}],
                "parameters": [
                    {
                        "name": "token",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                        "description": "Action token configured by LOG_WATCHER_ACTION_TOKEN.",
                    },
                    {
                        "name": "scope",
                        "in": "query",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "enum": ["container", "fingerprint", "global", "pattern"],
                        },
                    },
                    {
                        "name": "container",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Required when scope=container.",
                    },
                    {
                        "name": "fingerprint",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Required when scope=fingerprint.",
                    },
                    {
                        "name": "pattern",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": "Required when scope=pattern.",
                    },
                    {
                        "name": "minutes",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer", "minimum": 0},
                        "description": "Optional suppression duration. Invalid values fall back to the configured default.",
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Suppression created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SuppressionCreated"}
                            }
                        },
                    },
                    "400": {
                        "description": "Missing or invalid scope-specific parameters",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                            }
                        },
                    },
                    "401": {
                        "description": "Missing or invalid action token",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                            }
                        },
                    },
                    "503": {
                        "description": "Suppression actions are disabled because no action token is configured",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                            }
                        },
                    },
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "ActionToken": {
                "type": "apiKey",
                "in": "query",
                "name": "token",
                "description": "Shared secret used by Home Assistant action links.",
            }
        },
        "schemas": {
            "ErrorResponse": {
                "type": "object",
                "properties": {"error": {"type": "string"}},
                "required": ["error"],
                "additionalProperties": False,
            },
            "Suppression": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string"},
                    "container": {"type": "string"},
                    "fingerprint": {"type": "string"},
                    "pattern": {"type": "string"},
                    "expires_at": {"type": "string", "format": "date-time"},
                },
                "required": ["scope", "expires_at"],
                "additionalProperties": False,
            },
            "SuppressionCreated": {
                "type": "object",
                "properties": {
                    "ok": {"type": "boolean", "const": True},
                    "suppression": {"$ref": "#/components/schemas/Suppression"},
                },
                "required": ["ok", "suppression"],
                "additionalProperties": False,
            },
        },
    },
}


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
                if parsed.path == "/docs":
                    write_text(self, HTTPStatus.OK, DOCS_HTML, "text/html; charset=utf-8")
                    return
                if parsed.path == "/openapi.json":
                    write_json(self, HTTPStatus.OK, OPENAPI_SCHEMA)
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
    write_bytes(handler, status, body, "application/json")


def write_text(handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: str, content_type: str) -> None:
    write_bytes(handler, status, payload.encode("utf-8"), content_type)


def write_bytes(handler: BaseHTTPRequestHandler, status: HTTPStatus, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
