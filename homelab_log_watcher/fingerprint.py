from __future__ import annotations

import hashlib
import re


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
ISO_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[t ][0-9:.+-]+z?\b", re.IGNORECASE)
TIME_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
HEX_RE = re.compile(r"\b(?:sha256:)?[0-9a-fA-F]{12,}\b")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
URL_RE = re.compile(r"https?://\S+")
KEY_VALUE_RE = re.compile(
    r"\b(?:id|request_id|trace_id|span_id|token|session|uuid|ts|timestamp)=['\"]?[^'\"\s,]+['\"]?",
    re.IGNORECASE,
)
NUMBER_RE = re.compile(r"(?<![A-Za-z])[-+]?\d+(?:\.\d+)?(?![A-Za-z])")
WHITESPACE_RE = re.compile(r"\s+")


def clean_line(line: bytes | str, *, limit: int = 1000) -> str:
    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="replace")
    else:
        text = line
    text = ANSI_RE.sub("", text).strip()
    return text[:limit]


def normalize_line(line: bytes | str) -> str:
    text = clean_line(line).lower()
    replacements = [
        (URL_RE, "<url>"),
        (KEY_VALUE_RE, "<kv>"),
        (ISO_TIME_RE, "<ts>"),
        (TIME_RE, "<time>"),
        (UUID_RE, "<uuid>"),
        (HEX_RE, "<hex>"),
        (IP_RE, "<ip>"),
        (NUMBER_RE, "<num>"),
    ]
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    return WHITESPACE_RE.sub(" ", text).strip()


def fingerprint(container_name: str, severity: str, normalized_line: str) -> str:
    source = f"{container_name}|{severity}|{normalized_line}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()
