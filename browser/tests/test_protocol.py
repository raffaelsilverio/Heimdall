from __future__ import annotations

import unittest

from heimdall_browser.protocol import (
    ValidationError,
    decode_json,
    parse_session_request,
)

SCOPE_HASH = "a" * 64


def valid_body() -> dict[str, object]:
    return {
        "program_id": "program-1",
        "test_account_id": "account-1",
        "scope_hash": SCOPE_HASH,
        "policy_revision": 2,
    }


class ParseSessionRequestTests(unittest.TestCase):
    def test_accepts_canonical_request(self) -> None:
        request = parse_session_request(valid_body())
        self.assertEqual(request.program_id, "program-1")
        self.assertEqual(request.test_account_id, "account-1")
        self.assertEqual(request.scope_hash, SCOPE_HASH)
        self.assertEqual(request.policy_revision, 2)

    def test_rejects_non_object_and_wrong_keys(self) -> None:
        cases = [
            [],
            "body",
            {},
            {**valid_body(), "extra": True},
            {key: value for key, value in valid_body().items() if key != "scope_hash"},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ValidationError):
                    parse_session_request(payload)

    def test_rejects_unsafe_identifiers(self) -> None:
        for field in ("program_id", "test_account_id"):
            for value in ("", "-leading", "has space", "x" * 129, "semi;colon", 12):
                with self.subTest(field=field, value=value):
                    body = valid_body()
                    body[field] = value
                    with self.assertRaises(ValidationError):
                        parse_session_request(body)

    def test_rejects_invalid_scope_hash(self) -> None:
        for value in ("", "A" * 64, "a" * 63, "g" * 64, 12):
            with self.subTest(value=value):
                body = valid_body()
                body["scope_hash"] = value
                with self.assertRaises(ValidationError):
                    parse_session_request(body)

    def test_rejects_invalid_policy_revision(self) -> None:
        for value in (True, False, 0, -1, 1_000_000_001, 1.5, "2"):
            with self.subTest(value=value):
                body = valid_body()
                body["policy_revision"] = value
                with self.assertRaises(ValidationError):
                    parse_session_request(body)


class DecodeJSONTests(unittest.TestCase):
    def test_decodes_single_object(self) -> None:
        self.assertEqual(decode_json(b'{"a":1}'), {"a": 1})

    def test_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(ValidationError):
            decode_json(b'{"a":1,"a":2}')

    def test_rejects_non_finite_constants(self) -> None:
        for raw in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError):
                    decode_json(raw)

    def test_rejects_invalid_utf8_and_trailing_data(self) -> None:
        for raw in (b"\xff", b'{"a":1} trailing', b""):
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError):
                    decode_json(raw)


if __name__ == "__main__":
    unittest.main()
