from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timezone

from heimdall_browser.driver import DriverUnavailable
from heimdall_browser.protocol import Session, SessionRequest
from heimdall_browser.sessions import (
    DriverFailure,
    DriverUnavailableError,
    SessionExists,
    SessionLimitReached,
    SessionManager,
    SessionNotFound,
)

SCOPE_HASH = "b" * 64
NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)


class FakeDriver:
    name = "fake"
    browser = "chromium"

    def __init__(self) -> None:
        self.is_available = True
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.fail_open = False
        self.fail_close = False

    def available(self) -> bool:
        return self.is_available

    def open(self, session: Session) -> None:
        if self.fail_open:
            raise RuntimeError("open failed")
        self.opened.append(session.session_id)

    def close(self, session_id: str) -> None:
        if self.fail_close:
            raise RuntimeError("close failed")
        self.closed.append(session_id)


def request(program: str = "program-1", account: str = "account-1") -> SessionRequest:
    return SessionRequest(
        program_id=program,
        test_account_id=account,
        scope_hash=SCOPE_HASH,
        policy_revision=3,
    )


class SessionManagerTests(unittest.TestCase):
    def manager(self, max_sessions: int = 8) -> tuple[SessionManager, FakeDriver]:
        driver = FakeDriver()
        return SessionManager(driver, max_sessions=max_sessions, clock=lambda: NOW), driver

    def test_opens_and_closes_isolated_sessions(self) -> None:
        manager, driver = self.manager()
        session = manager.open(request())
        uuid.UUID(session.session_id)
        self.assertEqual(session.created_at, NOW)
        self.assertEqual(driver.opened, [session.session_id])
        self.assertEqual(manager.get(session.session_id), session)
        manager.close(session.session_id)
        self.assertEqual(driver.closed, [session.session_id])
        with self.assertRaises(SessionNotFound):
            manager.get(session.session_id)

    def test_enforces_one_session_per_program_account_pair(self) -> None:
        manager, _ = self.manager()
        manager.open(request("program-1", "account-1"))
        with self.assertRaises(SessionExists):
            manager.open(request("program-1", "account-1"))
        manager.open(request("program-1", "account-2"))
        manager.open(request("program-2", "account-1"))

    def test_enforces_session_limit(self) -> None:
        manager, _ = self.manager(max_sessions=2)
        manager.open(request("program-1", "account-1"))
        manager.open(request("program-2", "account-2"))
        with self.assertRaises(SessionLimitReached):
            manager.open(request("program-3", "account-3"))

    def test_fails_closed_when_driver_is_unavailable(self) -> None:
        manager, driver = self.manager()
        driver.is_available = False
        with self.assertRaises(DriverUnavailableError):
            manager.open(request())
        self.assertFalse(manager.health()["driver"]["available"])  # type: ignore[index]

    def test_driver_open_failure_creates_no_session(self) -> None:
        manager, driver = self.manager()
        driver.fail_open = True
        with self.assertRaises(DriverFailure):
            manager.open(request())
        with self.assertRaises(SessionNotFound):
            manager.get("00000000-0000-4000-8000-000000000000")

    def test_driver_close_failure_keeps_the_session_for_retry(self) -> None:
        manager, driver = self.manager()
        session = manager.open(request())
        driver.fail_close = True
        with self.assertRaises(DriverFailure):
            manager.close(session.session_id)
        self.assertEqual(manager.get(session.session_id), session)
        driver.fail_close = False
        manager.close(session.session_id)
        with self.assertRaises(SessionNotFound):
            manager.close(session.session_id)

    def test_close_all_releases_sessions(self) -> None:
        manager, driver = self.manager()
        first = manager.open(request("program-1", "account-1"))
        second = manager.open(request("program-2", "account-2"))
        manager.close_all()
        self.assertCountEqual(driver.closed, [first.session_id, second.session_id])
        with self.assertRaises(SessionNotFound):
            manager.get(first.session_id)

    def test_rejects_invalid_session_limits(self) -> None:
        for value in (0, 33):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    SessionManager(FakeDriver(), max_sessions=value)


class UnavailableDriverTests(unittest.TestCase):
    def test_default_driver_is_unavailable_and_fails_closed(self) -> None:
        from heimdall_browser.driver import UnavailableDriver

        driver = UnavailableDriver()
        self.assertFalse(driver.available())
        with self.assertRaises(DriverUnavailable):
            driver.open(
                Session(
                    session_id=str(uuid.uuid4()),
                    request=request(),
                    created_at=NOW,
                )
            )


if __name__ == "__main__":
    unittest.main()
