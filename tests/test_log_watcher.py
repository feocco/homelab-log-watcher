from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from unittest import TestCase

from homelab_log_watcher.config import Config
from homelab_log_watcher.fingerprint import normalize_line
from homelab_log_watcher.server import parse_minutes
from homelab_log_watcher.state import StateStore
from homelab_log_watcher.watcher import AlertProcessor, HomelabNotifier, LogMatcher, expected_stream_close


class FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 5, 3, 12, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class FakeNotifier:
    def __init__(self) -> None:
        self.calls = []

    def notify(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


def make_config(path: Path) -> Config:
    return Config(
        state_path=path,
        match_patterns=("ERROR", "WARN"),
        ignored_containers=("homelab-log-watcher",),
        fingerprint_cooldown_seconds=3600,
        global_window_seconds=900,
        global_max_notifications=2,
        startup_backfill_seconds=30,
        public_url=None,
        action_token=None,
        mute_minutes=60,
        service_host="127.0.0.1",
        service_port=8093,
        log_level="INFO",
    )


class FingerprintTests(TestCase):
    def test_normalization_removes_volatile_values(self) -> None:
        first = "2026-05-03T12:00:01Z ERROR request_id=abc123 user=42 failed after 10.5 seconds"
        second = "2026-05-03T12:00:02Z ERROR request_id=xyz789 user=43 failed after 11.9 seconds"

        self.assertEqual(normalize_line(first), normalize_line(second))


class ProcessorTests(TestCase):
    def make_processor(self):
        tmp = tempfile.TemporaryDirectory()
        state_path = Path(tmp.name) / "state.json"
        clock = FakeClock()
        fake_notifier = FakeNotifier()
        processor = AlertProcessor(
            config=make_config(state_path),
            state=StateStore(state_path),
            notifier=HomelabNotifier(fake_notifier.notify),
            now_func=clock.now,
        )
        matcher = LogMatcher(("ERROR", "WARN"))
        return tmp, clock, fake_notifier, processor, matcher

    def test_fingerprint_cooldown_suppresses_repeat(self) -> None:
        tmp, clock, fake_notifier, processor, matcher = self.make_processor()
        self.addCleanup(tmp.cleanup)

        alert = matcher.match(
            container_id="abc",
            container_name="plant-monitor",
            image="image",
            line="ERROR request_id=1 failed to call Home Assistant",
        )
        assert alert is not None

        self.assertTrue(processor.process(alert))
        self.assertFalse(processor.process(alert))
        self.assertEqual(len(fake_notifier.calls), 1)

        clock.advance(3601)
        self.assertTrue(processor.process(alert))
        self.assertEqual(len(fake_notifier.calls), 2)
        self.assertIn("Suppressed repeats: 1", fake_notifier.calls[-1][0][1])

    def test_global_rate_limit_caps_unique_alerts(self) -> None:
        tmp, _clock, fake_notifier, processor, matcher = self.make_processor()
        self.addCleanup(tmp.cleanup)

        for index in range(4):
            alert = matcher.match(
                container_id=str(index),
                container_name=f"service-{index}",
                image="image",
                line=f"ERROR unique failure {index}",
            )
            assert alert is not None
            processor.process(alert)

        self.assertEqual(len(fake_notifier.calls), 2)


class NotificationButtonTests(TestCase):
    def test_suppression_buttons_are_uri_buttons_when_configured(self) -> None:
        fake_notifier = FakeNotifier()
        notifier = HomelabNotifier(
            fake_notifier.notify,
            action_base_url="http://nasfeo:8093/",
            action_token="secret",
            mute_minutes=60,
        )
        matcher = LogMatcher(("ERROR",))
        alert = matcher.match(
            container_id="abc",
            container_name="plant-monitor",
            image="image",
            line="ERROR request_id=1 failed",
        )
        assert alert is not None

        notifier.send(alert, suppressed_count=0, global_suppressed_count=0)

        buttons = fake_notifier.calls[0][1]["buttons"]
        self.assertEqual(buttons[0]["action"], "URI")
        self.assertIn("scope=fingerprint", buttons[0]["uri"])
        self.assertIn("scope=container", buttons[1]["uri"])


class ServerHelperTests(TestCase):
    def test_parse_minutes_falls_back_to_default(self) -> None:
        self.assertEqual(parse_minutes(None, 60), 60)
        self.assertEqual(parse_minutes("bad", 60), 60)
        self.assertEqual(parse_minutes("-1", 60), 0)

    def test_expected_stream_close_matches_container_removal(self) -> None:
        self.assertTrue(expected_stream_close(RuntimeError("can not get logs from container which is dead or marked for removal")))
        self.assertFalse(expected_stream_close(RuntimeError("connection reset by peer")))
