"""Isolated browser session lifecycle.

One live session exists per (program, test account) pair. Session metadata never
contains cookies, tokens, storage state, or credentials: those stay inside the
driver's browser context. The manager is the only component allowed to assign
session ids or reuse a pair.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict

from .driver import Driver, DriverUnavailable
from .protocol import PROTOCOL_VERSION, Session, SessionRequest

MIN_SESSIONS = 1
MAX_SESSIONS = 32
DEFAULT_MAX_SESSIONS = 8


class SessionError(Exception):
    code = "internal_error"
    status = 500


class SessionExists(SessionError):
    code = "session_exists"
    status = 409


class SessionLimitReached(SessionError):
    code = "session_limit"
    status = 429


class SessionNotFound(SessionError):
    code = "session_not_found"
    status = 404


class DriverFailure(SessionError):
    code = "driver_failure"
    status = 502


class DriverUnavailableError(SessionError):
    code = "driver_unavailable"
    status = 503


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionManager:
    def __init__(
        self,
        driver: Driver,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not MIN_SESSIONS <= max_sessions <= MAX_SESSIONS:
            raise ValueError(
                f"max_sessions must be between {MIN_SESSIONS} and {MAX_SESSIONS}"
            )
        self._driver = driver
        self._max_sessions = max_sessions
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}

    def health(self) -> dict[str, object]:
        return {
            "version": PROTOCOL_VERSION,
            "driver": {
                "name": self._driver.name,
                "browser": self._driver.browser,
                "available": bool(self._driver.available()),
            },
        }

    def open(self, request: SessionRequest) -> Session:
        with self._lock:
            if not self._driver.available():
                raise DriverUnavailableError("browser driver is unavailable")
            for existing in self._sessions.values():
                if (
                    existing.request.program_id == request.program_id
                    and existing.request.test_account_id == request.test_account_id
                ):
                    raise SessionExists(
                        "a session already exists for this program and test account"
                    )
            if len(self._sessions) >= self._max_sessions:
                raise SessionLimitReached("the browser worker session limit was reached")
            session = Session(
                session_id=str(uuid.uuid4()),
                request=request,
                created_at=self._clock(),
            )
            try:
                self._driver.open(session)
            except DriverUnavailable as exc:
                raise DriverUnavailableError(str(exc)) from exc
            except Exception as exc:  # pragma: no cover - re-raised with a safe code
                raise DriverFailure("the browser driver could not open the session") from exc
            self._sessions[session.session_id] = session
            return session

    def get(self, session_id: str) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound("session not found")
            return session

    def close(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound("session not found")
            try:
                self._driver.close(session_id)
            except Exception as exc:
                raise DriverFailure("the browser driver could not close the session") from exc
            del self._sessions[session_id]

    def close_all(self) -> None:
        with self._lock:
            for session_id in list(self._sessions):
                try:
                    self._driver.close(session_id)
                except Exception:
                    pass
                del self._sessions[session_id]
