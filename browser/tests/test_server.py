from __future__ import annotations

import http.client
import json
import threading
import unittest

from heimdall_browser.protocol import PROTOCOL_VERSION
from heimdall_browser.server import WorkerHTTPServer
from heimdall_browser.sessions import SessionManager

SCOPE_HASH = "c" * 64
TOKEN = "t" * 40


class FakeDriver:
    name = "fake"
    browser = "chromium"

    def available(self) -> bool:
        return True

    def open(self, session: object) -> None:
        return None

    def close(self, session_id: str) -> None:
        return None


class WorkerServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SessionManager(FakeDriver())
        self.server = WorkerHTTPServer(("127.0.0.1", 0), self.manager, TOKEN)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def call(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        token: str | None = TOKEN,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=2)
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
            request_headers.setdefault("Content-Length", str(len(body)))
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            payload = response.read()
            return response.status, dict(response.getheaders()), payload
        finally:
            connection.close()

    def open_session(self, program: str = "program-1", account: str = "account-1") -> dict[str, object]:
        body = json.dumps(
            {
                "program_id": program,
                "test_account_id": account,
                "scope_hash": SCOPE_HASH,
                "policy_revision": 4,
            }
        ).encode()
        status, _, payload = self.call("POST", "/v1/sessions", body)
        self.assertEqual(status, 201, payload)
        return json.loads(payload)

    def test_health_requires_the_bearer_token(self) -> None:
        status, _, payload = self.call("GET", "/healthz", token=None)
        self.assertEqual(status, 401, payload)
        self.assertNotIn(TOKEN.encode(), payload)
        status, _, payload = self.call("GET", "/healthz", token="x" * 40)
        self.assertEqual(status, 401, payload)

        status, headers, payload = self.call("GET", "/healthz")
        self.assertEqual(status, 200, payload)
        self.assertEqual(json.loads(payload)["version"], PROTOCOL_VERSION)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertNotIn(TOKEN.encode(), payload)

    def test_session_lifecycle_never_returns_secrets(self) -> None:
        session = self.open_session()
        self.assertEqual(session["program_id"], "program-1")
        self.assertEqual(session["test_account_id"], "account-1")
        self.assertEqual(session["scope_hash"], SCOPE_HASH)
        self.assertEqual(session["policy_revision"], 4)
        for forbidden in ("cookie", "token", "authorization", "storage_state", "credential"):
            self.assertNotIn(forbidden, json.dumps(session).lower())

        status, _, payload = self.call("GET", f"/v1/sessions/{session['session_id']}")
        self.assertEqual(status, 200, payload)
        self.assertEqual(json.loads(payload), session)

        status, _, payload = self.call("DELETE", f"/v1/sessions/{session['session_id']}")
        self.assertEqual(status, 204, payload)
        status, _, payload = self.call("GET", f"/v1/sessions/{session['session_id']}")
        self.assertEqual(status, 404, payload)

    def test_duplicate_session_is_rejected(self) -> None:
        self.open_session()
        body = json.dumps(
            {
                "program_id": "program-1",
                "test_account_id": "account-1",
                "scope_hash": SCOPE_HASH,
                "policy_revision": 4,
            }
        ).encode()
        status, _, payload = self.call("POST", "/v1/sessions", body)
        self.assertEqual(status, 409, payload)
        self.assertEqual(json.loads(payload)["error"]["code"], "session_exists")

    def test_rejects_malformed_bodies(self) -> None:
        cases = [
            b"not json",
            b'{"program_id":"p","program_id":"q"}',
            b'{"program_id":"p"}',
            b'{"program_id":"program-1","test_account_id":"account-1","scope_hash":"short","policy_revision":1}',
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                status, _, payload = self.call("POST", "/v1/sessions", raw)
                self.assertEqual(status, 400, payload)
                self.assertEqual(json.loads(payload)["error"]["code"], "invalid_request")

    def test_rejects_oversized_and_chunked_bodies(self) -> None:
        status, _, payload = self.call(
            "POST",
            "/v1/sessions",
            b"",
            headers={"Content-Length": str(17 * 1024)},
        )
        self.assertEqual(status, 413, payload)

        status, _, payload = self.call(
            "POST",
            "/v1/sessions",
            b"{}",
            headers={"Transfer-Encoding": "chunked", "Content-Length": "2"},
        )
        self.assertEqual(status, 400, payload)

    def test_rejects_unknown_routes_and_methods(self) -> None:
        for path in ("/", "/v1/unknown", "/v1/sessions/abc/extra"):
            with self.subTest(path=path):
                status, _, payload = self.call("GET", path)
                self.assertEqual(status, 404, payload)
        status, _, payload = self.call("PUT", "/v1/sessions")
        self.assertEqual(status, 405, payload)
        status, _, payload = self.call("POST", "/healthz", b"{}")
        self.assertEqual(status, 405, payload)

    def test_rejects_query_strings_without_reflecting_them(self) -> None:
        status, _, payload = self.call("GET", "/healthz?token=secret")
        self.assertEqual(status, 404, payload)
        self.assertNotIn(b"secret", payload)

    def test_build_server_rejects_unsafe_bindings(self) -> None:
        from heimdall_browser.server import build_server

        for host in ("0.0.0.0", "localhost", "::1", "example.com"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    build_server(self.manager, TOKEN, host=host, port=8090)
        for token in ("", "short", "x" * 33 + " "):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    build_server(self.manager, token, port=8090)


if __name__ == "__main__":
    unittest.main()
