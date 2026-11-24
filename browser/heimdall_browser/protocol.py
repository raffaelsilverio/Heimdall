"""Versioned wire protocol shared with the Go core."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

PROTOCOL_VERSION = "1"
MAX_BODY_BYTES = 16 * 1024
MAX_POLICY_REVISION = 1_000_000_000

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCOPE_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SESSION_KEYS = frozenset(
    {"program_id", "test_account_id", "scope_hash", "policy_revision"}
)


class ValidationError(ValueError):
    """A request body that must be rejected without echoing its contents."""

    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class SessionRequest:
    program_id: str
    test_account_id: str
    scope_hash: str
    policy_revision: int


@dataclass(frozen=True)
class Session:
    session_id: str
    request: SessionRequest
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "program_id": self.request.program_id,
            "test_account_id": self.request.test_account_id,
            "scope_hash": self.request.scope_hash,
            "policy_revision": self.request.policy_revision,
            "created_at": self.created_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }


def _require_object(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("body must be a JSON object")
    return payload


def _canonical_identifier(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValidationError(f"{key} must be a string")
    if not _ID_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} is not a canonical identifier")
    return value


def parse_session_request(payload: Any) -> SessionRequest:
    body = _require_object(payload)
    if set(body) != _SESSION_KEYS:
        raise ValidationError(
            "body must contain exactly program_id, test_account_id, scope_hash, and policy_revision"
        )
    program_id = _canonical_identifier(body, "program_id")
    test_account_id = _canonical_identifier(body, "test_account_id")
    scope_hash = body.get("scope_hash")
    if not isinstance(scope_hash, str) or not _SCOPE_HASH_PATTERN.fullmatch(scope_hash):
        raise ValidationError("scope_hash must be 64 lowercase hexadecimal characters")
    policy_revision = body.get("policy_revision")
    if (
        isinstance(policy_revision, bool)
        or not isinstance(policy_revision, int)
        or not 1 <= policy_revision <= MAX_POLICY_REVISION
    ):
        raise ValidationError(
            f"policy_revision must be an integer between 1 and {MAX_POLICY_REVISION}"
        )
    return SessionRequest(
        program_id=program_id,
        test_account_id=test_account_id,
        scope_hash=scope_hash,
        policy_revision=policy_revision,
    )


def _reject_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant {value}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def decode_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError("body must be valid UTF-8 JSON") from exc
    try:
        return json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicate_keys,
        )
    except (ValueError, TypeError) as exc:
        raise ValidationError("body must be a single JSON value") from exc


def error_payload(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}
