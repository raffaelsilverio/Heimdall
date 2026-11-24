"""Run the loopback browser worker."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading

from .driver import UnavailableDriver
from .server import LOOPBACK_HOST, build_server
from .sessions import DEFAULT_MAX_SESSIONS, SessionManager


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Heimdall browser worker")
    parser.add_argument("--host", default=LOOPBACK_HOST, help="Loopback bind address")
    parser.add_argument("--port", type=int, default=8090, help="Loopback port")
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=DEFAULT_MAX_SESSIONS,
        help="Maximum concurrent isolated browser sessions",
    )
    args = parser.parse_args(argv)

    token = os.environ.get("HEIMDALL_BROWSER_TOKEN", "")
    try:
        manager = SessionManager(UnavailableDriver(), max_sessions=args.max_sessions)
        server = build_server(manager, token=token, host=args.host, port=args.port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s level=%(levelname)s logger=%(name)s %(message)s",
    )

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print(f"heimdall browser worker listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        manager.close_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
