import base64
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import plus_api


class PlusAPITests(unittest.TestCase):
    def test_large_token_record_is_encrypted_and_round_trips(self):
        credentials = {}

        def get_password(service, account):
            return credentials.get((service, account))

        def set_password(service, account, value):
            credentials[(service, account)] = value

        def delete_password(service, account):
            credentials.pop((service, account), None)

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(plus_api, "DATA_DIR", Path(directory)), \
             patch.object(plus_api, "SESSION_PATH", Path(directory) / "session.enc"), \
             patch.object(plus_api.keyring, "get_password", side_effect=get_password), \
             patch.object(plus_api.keyring, "set_password", side_effect=set_password), \
             patch.object(plus_api.keyring, "delete_password", side_effect=delete_password):
            record = {"client_id": "oaiapp_test", "access_token": "secret-" + "x" * 10000}
            plus_api._save_auth(record)
            self.assertEqual(plus_api._load_auth(), record)
            self.assertNotIn(b"secret-", (Path(directory) / "session.enc").read_bytes())
            self.assertLess(len(credentials[(plus_api.KEYRING_SERVICE, plus_api.KEYRING_KEY_ACCOUNT)]), 100)

    def test_id_token_requires_valid_signature_audience_and_nonce(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        jwk["kid"] = "test-key"
        now = int(time.time())
        claims = {
            "iss": plus_api.AUTH_BASE,
            "aud": "oaiapp_test",
            "sub": "account-1",
            "nonce": "expected-nonce",
            "iat": now,
            "exp": now + 600,
        }
        token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"keys": [jwk]}
        response.raise_for_status.return_value = None
        with patch.object(plus_api, "_discovery", return_value={
            "issuer": plus_api.AUTH_BASE,
            "jwks_uri": "https://auth.openai.com/test-jwks",
        }), patch.object(plus_api, "_request", return_value=response):
            self.assertEqual(plus_api._verify_id_token(token, "oaiapp_test", "expected-nonce")["sub"], "account-1")
            with self.assertRaises(plus_api.PlusAPIError):
                plus_api._verify_id_token(token, "oaiapp_other", "expected-nonce")
            with self.assertRaises(plus_api.PlusAPIError):
                plus_api._verify_id_token(token, "oaiapp_test", "wrong-nonce")

    def test_login_uses_official_registration_parameters_and_pkce(self):
        saved = []
        opened = []
        token_bodies = []

        class FakeServer:
            server_address = ("127.0.0.1", 43210)

            def server_close(self):
                pass

        def fake_callback(state):
            return FakeServer(), {"state_for_test": state}

        def fake_wait(_server, _result, _timeout):
            return {"code": "test-code", "client_id": "oaiapp_test"}

        def fake_token(body):
            token_bodies.append(body)
            return {
                "token_type": "Bearer",
                "id_token": "id-token",
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "scope": plus_api.SCOPES,
                "expires_in": 3600,
            }

        with patch.object(plus_api, "_host_id", return_value="urn:uuid:00000000-0000-4000-8000-000000000000"), \
             patch.object(plus_api, "_load_auth", return_value=None), \
             patch.object(plus_api, "_callback_server", side_effect=fake_callback), \
             patch.object(plus_api, "_wait_for_callback", side_effect=fake_wait), \
             patch.object(plus_api.webbrowser, "open", side_effect=lambda url, new: opened.append(url) or True), \
             patch.object(plus_api, "_token_request", side_effect=fake_token), \
             patch.object(plus_api, "_verify_id_token", return_value={"sub": "account-1", "email": "a@example.com"}), \
             patch.object(plus_api, "_save_auth", side_effect=saved.append), \
             redirect_stdout(StringIO()):
            plus_api.login()

        params = parse_qs(urlparse(opened[0]).query)
        self.assertEqual(params["client_id"], ["dynamic_agent_client"])
        self.assertEqual(params["resource"], [plus_api.API_BASE])
        self.assertEqual(params["redirect_uri"], ["http://127.0.0.1:43210/auth/callback"])
        self.assertIn("chatgpt.tokens.use.direct", params["scope"][0].split())
        self.assertEqual(params["code_challenge_method"], ["S256"])
        verifier = token_bodies[0]["code_verifier"]
        expected = base64.urlsafe_b64encode(__import__("hashlib").sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(params["code_challenge"], [expected])
        self.assertEqual(token_bodies[0]["client_id"], "oaiapp_test")
        self.assertEqual(saved[0]["client_id"], "oaiapp_test")
        self.assertEqual(saved[1]["access_token"], "access-token")

    def test_stream_requires_completed_event(self):
        class FakeResponse:
            ok = True

            def __init__(self, lines):
                self.lines = lines

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def iter_lines(self, decode_unicode=True):
                return iter(self.lines)

        events = [
            'data: ' + json.dumps({"type": "response.output_text.delta", "delta": "hello"}),
            'data: ' + json.dumps({"type": "response.completed"}),
            'data: [DONE]',
        ]
        with patch.object(plus_api, "_authorization_headers", return_value={"Authorization": "Bearer test"}), \
             patch.object(plus_api.requests, "post", return_value=FakeResponse(events)) as post, \
             redirect_stdout(StringIO()) as output:
            plus_api.ask("say hello", "gpt-test")
        self.assertEqual(output.getvalue(), "hello\n")
        self.assertEqual(post.call_args.kwargs["json"]["store"], False)
        self.assertEqual(post.call_args.kwargs["json"]["stream"], True)

        with patch.object(plus_api, "_authorization_headers", return_value={"Authorization": "Bearer test"}), \
             patch.object(plus_api.requests, "post", return_value=FakeResponse(events[:1])), \
             redirect_stdout(StringIO()):
            with self.assertRaisesRegex(plus_api.PlusAPIError, "without response.completed"):
                plus_api.ask("say hello", "gpt-test")

    def test_run_passes_refreshed_token_only_to_child_environment(self):
        child = Mock(returncode=7)
        with patch.object(plus_api, "_active_auth", return_value={"access_token": "oauth-secret"}), \
             patch.object(plus_api.subprocess, "run", return_value=child) as run:
            result = plus_api.run_with_plan_token(["--", "python", "third_party.py"])
        self.assertEqual(result, 7)
        self.assertEqual(run.call_args.args[0], ["python", "third_party.py"])
        self.assertEqual(run.call_args.kwargs["env"]["OPENAI_API_KEY"], "oauth-secret")
        self.assertNotEqual(os.environ.get("OPENAI_API_KEY"), "oauth-secret")
        with self.assertRaises(plus_api.PlusAPIError):
            plus_api.run_with_plan_token(["--"])


if __name__ == "__main__":
    unittest.main()
