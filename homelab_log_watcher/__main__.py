from __future__ import annotations

import argparse
import logging
import sys

import docker

from .config import Config
from .server import SuppressionServer
from .state import StateStore
from .watcher import AlertProcessor, DockerLogWatcher, HomelabNotifier, LogMatcher


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watch Docker logs and notify on warning/error lines.")
    parser.add_argument("--once", action="store_true", help="attach to current containers and exit after setup")
    args = parser.parse_args(argv)

    config = Config.from_env()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    state = StateStore(config.state_path)
    matcher = LogMatcher(config.match_patterns)
    notifier = HomelabNotifier(
        action_base_url=config.public_url,
        action_token=config.action_token,
        mute_minutes=config.mute_minutes,
    )
    processor = AlertProcessor(config=config, state=state, notifier=notifier)
    SuppressionServer(config=config, state=state).start()
    client = docker.from_env()
    watcher = DockerLogWatcher(
        docker_client=client,
        config=config,
        matcher=matcher,
        processor=processor,
    )

    if args.once:
        watcher.attach_existing()
        return 0

    watcher.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
