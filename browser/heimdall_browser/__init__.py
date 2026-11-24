"""Heimdall browser worker package."""

from .protocol import PROTOCOL_VERSION
from .sessions import SessionManager

__all__ = ["PROTOCOL_VERSION", "SessionManager"]
