"""Loopback-only HTTP worker for browser sessions.

The listener must bind a literal IPv4 loopback address. Every request needs the
operator-provided bearer token. Responses never include cookies, tokens, storage
state, or credentials, and access logs never include headers or bodies.
"""

from __future__ import annotations

import hmac
import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from .protocol import (
    MAX_BODY_BYTES,
    PROTOCOL_VERSION,
    ValidationError,
    decode_json,
    error_payload,
    parse_session_request,
)
from .sessions import SessionError, SessionManager

LOGGER = logging.getLogger("heimdall_browser")

MIN_TOKEN_BYTES = 32
MAX_TOKEN_BYTES = 256
MIN_PORT = 1024
MAX_PORT = 65535
LOOPBACK_HOST = "127.0.0.1"


class WorkerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        manager: SessionManager,
        token: str,
    ) -> None:
        super().__init__(address, WorkerRequestHandler)
        self.manager = manager
        self.token = token


class _NotFound(Exception):
    pass


class WorkerRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HeimdallBrowser/" + PROTOCOL_VERSION
    sys_version = ""

    # BaseHTTPRequestHandler logs the raw request line. Override it so headers,
    # query strings, and bodies can never reach the log.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return None

    @property
    def worker(self) -> WorkerHTTPServer:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_HEAD(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._respond(HTTPStatus.METHOD_NOT_ALLOWED, error_payload("method_not_allowed", "method not allowed"))

    def _handle(self, method: str) -> None:
        route = "unknown"
        try:
            self._authenticate()
            route, session_id = self._route()
            if method == "GET" and route == "health":
                self._respond(HTTPStatus.OK, self.worker.manager.health())
                return
            if method == "POST" and route == "sessions":
                payload = decode_json(self._read_body())
                session = self.worker.manager.open(parse_session_request(payload))
                self._respond(HTTPStatus.CREATED, session.to_dict())
                return
            if method == "GET" and route == "session":
                self._respond(HTTPStatus.OK, self.worker.manager.get(session_id).to_dict())
                return
            if method == "DELETE" and route == "session":
                self.worker.manager.close(session_id)
                self._respond(HTTPStatus.NO_CONTENT, None)
                return
            self._respond(
                HTTPStatus.METHOD_NOT_ALLOWED,
                error_payload("method_not_allowed", "method not allowed for this route"),
            )
        except ValidationError as exc:
            self._respond(HTTPStatus.BAD_REQUEST, error_payload(exc.code, str(exc)), route)
        except SessionError as exc:
            status = HTTPStatus(exc.status)
            self._respond(status, error_payload(exc.code, str(exc)), route)
        except _NotFound:
            self._respond(HTTPStatus.NOT_FOUND, error_payload("not_found", "route not found"), route)
        except _Unauthorized:
            self._respond(
                HTTPStatus.UNAUTHORIZED,
                error_payload("unauthorized", "a valid bearer token is required"),
                route,
            )
        except _BodyTooLarge:
            self._respond(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                error_payload("body_too_large", f"body exceeds {MAX_BODY_BYTES} bytes"),
                route,
            )
        except _BadRequest as exc:
            self._respond(HTTPStatus.BAD_REQUEST, error_payload(exc.code, exc.message), route)
        except Exception:
            LOGGER.exception("browser worker request failed")
            self._respond(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                error_payload("internal_error", "the browser worker could not complete the request"),
                route,
            )

    def _authenticate(self) -> None:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise _Unauthorized
        try:
            provided = header[len(prefix) :].encode("ascii")
        except UnicodeEncodeError as exc:
            raise _Unauthorized from exc
        if not hmac.compare_digest(provided, self.worker.token.encode("ascii")):
            raise _Unauthorized

    def _route(self) -> tuple[str, str]:
        parts = urlsplit(self.path)
        if parts.query or parts.fragment:
            raise _NotFound
        if parts.path == "/healthz":
            return "health", ""
        if parts.path == "/v1/sessions":
            return "sessions", ""
        prefix = "/v1/sessions/"
        if parts.path.startswith(prefix):
            session_id = parts.path[len(prefix) :]
            if not session_id or "/" in session_id:
                raise _NotFound
            return "session", session_id
        raise _NotFound

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise _BadRequest("invalid_request", "chunked transfer encoding is not supported")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise _BadRequest("invalid_request", "a Content-Length header is required")
        try:
            length = int(raw_length, 10)
        except ValueError as exc:
            raise _BadRequest("invalid_request", "Content-Length must be a decimal integer") from exc
        if length <= 0:
            raise _BadRequest("invalid_request", "the request body must not be empty")
        if length > MAX_BODY_BYTES:
            raise _BodyTooLarge
        body = self.rfile.read(length)
        if len(body) != length:
            raise _BadRequest("invalid_request", "the request body ended unexpectedly")
        return body

    def _respond(self, status: HTTPStatus, payload: Optional[Mapping[str, Any]], route: str = "unknown") -> None:
        body = b""
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.close_connection = True
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        LOGGER.info("browser worker request route=%s status=%d", route, int(status))


class _BadRequest(Exception):
    code = "invalid_request"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _Unauthorized(Exception):
    pass


class _BodyTooLarge(Exception):
    pass


def build_server(
    manager: SessionManager,
    token: str,
    host: str = LOOPBACK_HOST,
    port: int = 8090,
) -> WorkerHTTPServer:
    if host != LOOPBACK_HOST:
        raise ValueError(f"the browser worker may only bind {LOOPBACK_HOST}")
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port must be between {MIN_PORT} and {MAX_PORT}")
    if not MIN_TOKEN_BYTES <= len(token) <= MAX_TOKEN_BYTES or any(
        character < "!" or character > "~" for character in token
    ):
        raise ValueError(
            f"HEIMDALL_BROWSER_TOKEN must be {MIN_TOKEN_BYTES}-{MAX_TOKEN_BYTES} printable ASCII bytes"
        )
    return WorkerHTTPServer((host, port), manager, token)
