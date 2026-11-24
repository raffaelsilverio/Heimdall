"""Browser driver boundary.

The real Playwright/Chromium driver lands in the next increment. Until then the
worker runs with an unavailable driver so it fails closed: it can report health
and enforce its protocol, but it cannot create a browser context.
"""

from __future__ import annotations

from typing import Protocol

from .protocol import Session


class DriverUnavailable(Exception):
    """Raised when no reviewed browser driver can serve the request."""


class Driver(Protocol):
    name: str
    browser: str

    def available(self) -> bool:
        ...

    def open(self, session: Session) -> None:
        ...

    def close(self, session_id: str) -> None:
        ...


class UnavailableDriver:
    """Default fail-closed driver used until Playwright is integrated."""

    name = "playwright"
    browser = "chromium"

    def available(self) -> bool:
        return False

    def open(self, session: Session) -> None:
        raise DriverUnavailable("Playwright driver is not integrated yet")

    def close(self, session_id: str) -> None:
        return None
