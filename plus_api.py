"""Use an eligible ChatGPT plan with the documented Sign in with ChatGPT flow.

Run from Git Bash: python plus_api.py --help
This is a local, single-account example, not an API-platform key generator.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import keyring
import requests
from cryptography.fernet import Fernet, InvalidToken


APP_NAME = "Plus Responses Local"
KEYRING_SERVICE = "plus-responses-local"
KEYRING_KEY_ACCOUNT = "storage-key"
LEGACY_KEYRING_ACCOUNT = "default"
AUTH_BASE = "https://auth.openai.com"
API_BASE = "https://api.openai.com/v1"
DISCOVERY_URL = f"{AUTH_BASE}/.well-known/openid-configuration"
TOKEN_URL = f"{AUTH_BASE}/api/accounts/oauth/token"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
REQUIRED_SCOPE = "chatgpt.tokens.use.direct"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "plus-responses-local"
CONFIG_PATH = DATA_DIR / "config.json"
SESSION_PATH = DATA_DIR / "session.enc"
HTTP_TIMEOUT = 30


class PlusAPIError(Exception):
    pass


def _json_response(response: requests.Response) -> dict:
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        try:
            body = response.json()
            detail = body.get("error", body)
            if isinstance(detail, dict):
                detail = detail.get("message") or detail.get("code") or detail
        except ValueError:
            detail = response.text[:300]
        raise PlusAPIError(f"HTTP {response.status_code}: {detail}") from exc
    try:
        data = response.json()
    except ValueError as exc:
        raise PlusAPIError("Server returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise PlusAPIError("Server returned an unexpected JSON response")
    return data


def _request(method: str, url: str, **kwargs) -> requests.Response:
    try:
        return requests.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise PlusAPIError(f"Network request failed: {exc}") from exc


def _discovery() -> dict:
    data = _json_response(_request("GET", DISCOVERY_URL))
    if data.get("issuer") != AUTH_BASE:
        raise PlusAPIError("Unexpected OpenID issuer")
    for field in ("jwks_uri", "revocation_endpoint"):
        if not str(data.get(field, "")).startswith("https://auth.openai.com/"):
            raise PlusAPIError(f"Unexpected {field} in OpenID discovery")
    return data


def _write_config(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, CONFIG_PATH)


def _host_id() -> str:
    if CONFIG_PATH.exists():
        try:
            value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["host_id"]
            if isinstance(value, str) and value.startswith("urn:uuid:"):
                uuid.UUID(value.removeprefix("urn:uuid:"))
                return value
        except (ValueError, KeyError, TypeError) as exc:
            raise PlusAPIError(f"Invalid host config at {CONFIG_PATH}") from exc
        raise PlusAPIError(f"Invalid host ID at {CONFIG_PATH}")
    value = f"urn:uuid:{uuid.uuid4()}"
    _write_config({"host_id": value})
    return value


def _load_auth() -> dict | None:
    if SESSION_PATH.exists():
        try:
            key = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_ACCOUNT)
            if not key:
                raise PlusAPIError("The Windows credential encryption key is missing")
            plaintext = Fernet(key.encode("ascii")).decrypt(SESSION_PATH.read_bytes())
            data = json.loads(plaintext)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            return data
        except (InvalidToken, ValueError) as exc:
            raise PlusAPIError("Saved encrypted credential record is invalid") from exc
        except PlusAPIError:
            raise
        except Exception as exc:
            raise PlusAPIError(f"Could not read encrypted credentials: {exc}") from exc

    # Read a small provisional registration from the first version of this
    # example, if one was saved before full token storage proved too large.
    try:
        raw = keyring.get_password(KEYRING_SERVICE, LEGACY_KEYRING_ACCOUNT)
    except Exception as exc:
        raise PlusAPIError(f"Windows credential storage is unavailable: {exc}") from exc
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("not an object")
        return data
    except ValueError as exc:
        raise PlusAPIError("Saved credential record is invalid") from exc


def _save_auth(data: dict) -> None:
    try:
        key = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_ACCOUNT)
        if not key:
            key = Fernet.generate_key().decode("ascii")
            keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_ACCOUNT, key)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        ciphertext = Fernet(key.encode("ascii")).encrypt(json.dumps(data).encode("utf-8"))
        temporary = SESSION_PATH.with_suffix(".tmp")
        temporary.write_bytes(ciphertext)
        os.replace(temporary, SESSION_PATH)
        try:
            keyring.delete_password(KEYRING_SERVICE, LEGACY_KEYRING_ACCOUNT)
        except keyring.errors.PasswordDeleteError:
            pass
    except Exception as exc:
        raise PlusAPIError(f"Could not save encrypted credentials: {exc}") from exc


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _verify_id_token(token: str, client_id: str, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise PlusAPIError("Invalid ID token header") from exc
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise PlusAPIError("Unexpected ID token signing algorithm or key ID")

    discovery = _discovery()
    jwks = _json_response(_request("GET", discovery["jwks_uri"]))
    matches = [
        key for key in jwks.get("keys", [])
        if key.get("kid") == header["kid"] and key.get("kty") == "RSA"
    ]
    if len(matches) != 1:
        raise PlusAPIError("ID token signing key was not found uniquely")
    try:
        signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(matches[0]))
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=discovery["issuer"],
            options={"require": ["iss", "sub", "aud", "exp"]},
            leeway=60,
        )
    except (jwt.PyJWTError, ValueError) as exc:
        raise PlusAPIError(f"ID token verification failed: {exc}") from exc
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise PlusAPIError("ID token nonce did not match")
    return claims


def _token_request(body: dict) -> dict:
    data = _json_response(_request("POST", TOKEN_URL, data=body))
    if data.get("token_type", "Bearer").lower() != "bearer":
        raise PlusAPIError("Unexpected OAuth token type")
    return data


def _has_plan_scope(scope: str) -> bool:
    return REQUIRED_SCOPE in scope.split()


def _callback_server(state: str):
    result: dict = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/auth/callback":
                self.send_error(404)
                return
            query = parse_qs(parsed.query, keep_blank_values=True)
            returned_state = query.get("state", [""])[0]
            if not hmac.compare_digest(returned_state, state):
                result["error"] = "OAuth state did not match"
            elif query.get("error"):
                result["error"] = f"Authorization was declined: {query['error'][0]}"
            else:
                result["code"] = query.get("code", [""])[0]
                result["client_id"] = query.get("client_id", [""])[0]
                if not result["code"]:
                    result["error"] = "Authorization callback had no code"
            message = (
                "Authorization received. You may return to Git Bash."
                if not result.get("error") else "Authorization failed. Return to Git Bash for details."
            )
            body = f"<!doctype html><meta charset='utf-8'><title>ChatGPT sign-in</title><p>{message}</p>".encode()
            self.send_response(200 if not result.get("error") else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass  # Never log the authorization code or callback URL.

    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    server.timeout = 1
    return server, result


def _wait_for_callback(server: HTTPServer, result: dict, seconds: int = 600) -> dict:
    deadline = time.monotonic() + seconds
    while not result and time.monotonic() < deadline:
        server.handle_request()
    if not result:
        raise PlusAPIError(f"Sign-in timed out after {seconds} seconds")
    if result.get("error"):
        raise PlusAPIError(result["error"])
    return result


def login(manual: bool = False, timeout: int = 600) -> None:
    host_id = _host_id()  # Persist this before opening authorization.
    previous = _load_auth()
    state = _b64url(secrets.token_bytes(32))
    nonce = _b64url(secrets.token_bytes(32))
    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    server, callback = _callback_server(state)
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/auth/callback"

    client_id = previous["client_id"] if previous else "dynamic_agent_client"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "resource": API_BASE,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
        "ext_agent_host_id": host_id,
    }
    if previous is None:
        params["agent_name_hint"] = APP_NAME
    authorize_url = f"{AUTH_BASE}/api/accounts/authorize?{urlencode(params)}"
    try:
        print("Opening the official ChatGPT authorization page in your browser.", flush=True)
        print("Sign in yourself and approve ChatGPT plan usage for this local app.", flush=True)
        if manual or not webbrowser.open(authorize_url, new=2):
            print(f"Open this URL manually:\n{authorize_url}", flush=True)
        returned = _wait_for_callback(server, callback, timeout)
    finally:
        server.server_close()

    issued_id = returned["client_id"] or (previous or {}).get("client_id", "")
    if previous and issued_id != previous["client_id"]:
        raise PlusAPIError("Returning sign-in supplied a different client ID")
    if not issued_id or issued_id == "dynamic_agent_client":
        raise PlusAPIError("Registration did not return an issued client ID")

    # Keep the issued registration even if the short-lived code expires before
    # exchange. The next login can reuse the issued client ID.
    if previous is None:
        _save_auth({"client_id": issued_id, "subject": None, "email": None})

    token = _token_request({
        "grant_type": "authorization_code",
        "client_id": issued_id,
        "code": returned["code"],
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": API_BASE,
    })
    if not token.get("id_token") or not token.get("access_token") or not token.get("refresh_token"):
        raise PlusAPIError("Authorization did not return all required tokens")
    if not _has_plan_scope(token.get("scope", "")):
        raise PlusAPIError("ChatGPT plan usage was not granted")
    identity = _verify_id_token(token["id_token"], issued_id, nonce)
    if previous and previous.get("subject") and identity["sub"] != previous["subject"]:
        raise PlusAPIError("Returning sign-in used a different ChatGPT account")

    _save_auth({
        "client_id": issued_id,
        "subject": identity["sub"],
        "email": identity.get("email", ""),
        "id_token": token["id_token"],
        "access_token": token["access_token"],
        "refresh_token": token["refresh_token"],
        "scope": token["scope"],
        "expires_at": time.time() + int(token.get("expires_in", 3600)),
    })
    print(f"Connected: {identity.get('email') or identity['sub']}")
    print("Run `python plus_api.py models` to see available model slugs.")


def _active_auth() -> dict:
    auth = _load_auth()
    if not auth or not auth.get("refresh_token"):
        raise PlusAPIError("Not signed in. Run `python plus_api.py login` first")
    if not _has_plan_scope(auth.get("scope", "")):
        raise PlusAPIError("Saved authorization lacks ChatGPT plan usage")
    if time.time() + 120 < float(auth.get("expires_at", 0)):
        return auth

    # Re-read under a Windows file lock so two local invocations cannot rotate
    # the same refresh token at the same time.
    import msvcrt

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with (DATA_DIR / "refresh.lock").open("a+b") as lock_file:
        lock_file.seek(0)
        if lock_file.read(1) == b"":
            lock_file.seek(0)
            lock_file.write(b"0")
            lock_file.flush()
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        try:
            auth = _load_auth()
            if not auth or not auth.get("refresh_token"):
                raise PlusAPIError("Sign-in was removed during token refresh")
            if time.time() + 120 >= float(auth.get("expires_at", 0)):
                token = _token_request({
                    "grant_type": "refresh_token",
                    "client_id": auth["client_id"],
                    "refresh_token": auth["refresh_token"],
                    "resource": API_BASE,
                })
                if not token.get("access_token") or not token.get("refresh_token"):
                    raise PlusAPIError("Refresh did not return replacement tokens")
                scope = token.get("scope", auth["scope"])
                if not _has_plan_scope(scope):
                    raise PlusAPIError("Renewed authorization lacks ChatGPT plan usage")
                auth.update({
                    "access_token": token["access_token"],
                    "refresh_token": token["refresh_token"],
                    "scope": scope,
                    "expires_at": time.time() + int(token.get("expires_in", 3600)),
                })
                _save_auth(auth)
        finally:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
    return auth


def _authorization_headers() -> dict:
    return {"Authorization": f"Bearer {_active_auth()['access_token']}"}


def _available_models() -> list[dict]:
    data = _json_response(_request("GET", f"{API_BASE}/models", headers=_authorization_headers()))
    models = data.get("models", [])
    if not isinstance(models, list):
        raise PlusAPIError("Unexpected models response")
    return [model for model in models if model.get("visibility") == "list"]


def list_models() -> None:
    models = _available_models()
    if not models:
        print("No displayable models were returned for this account.")
        return
    for model in models:
        print(f"{model.get('slug', ''):<30} {model.get('display_name', '')}")


def ask(prompt: str, model: str | None) -> None:
    if not prompt.strip():
        raise PlusAPIError("Prompt cannot be empty")
    if model is None:
        models = _available_models()
        if not models:
            raise PlusAPIError("No model is available; run `models` to inspect access")
        model = models[0]["slug"]
        print(f"Using model: {model}", file=sys.stderr)

    payload = {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "store": False,
        "stream": True,
    }
    try:
        response = requests.post(
            f"{API_BASE}/responses",
            headers=_authorization_headers(),
            json=payload,
            stream=True,
            timeout=(HTTP_TIMEOUT, 180),
        )
    except requests.RequestException as exc:
        raise PlusAPIError(f"Request failed: {exc}") from exc
    with response:
        if not response.ok:
            _json_response(response)
        completed = False
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            if isinstance(line, bytes):
                line = line.decode("utf-8")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except ValueError:
                continue
            kind = event.get("type")
            if kind == "response.output_text.delta":
                print(event.get("delta", ""), end="", flush=True)
            elif kind == "response.failed":
                error = (event.get("response") or {}).get("error") or {}
                raise PlusAPIError(f"Response failed: {error.get('code') or error.get('message') or error}")
            elif kind == "response.incomplete":
                raise PlusAPIError("Response was incomplete")
            elif kind == "response.completed":
                completed = True
        print()
        if not completed:
            raise PlusAPIError("Stream ended without response.completed")


def run_with_plan_token(command: list[str]) -> int:
    """Launch a local program with the current short-lived OAuth token."""
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise PlusAPIError("Provide a command after `run --`, for example: run -- python third_party.py")
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = _active_auth()["access_token"]
    try:
        return subprocess.run(command, env=env, check=False).returncode
    except OSError as exc:
        raise PlusAPIError(f"Could not start the command: {exc}") from exc


def status() -> None:
    print(f"Host ID: {_host_id()}")
    auth = _load_auth()
    if not auth:
        print("Status: not registered")
    elif not auth.get("subject"):
        print("Status: client registered; sign-in needs to finish")
    elif not auth.get("refresh_token"):
        print(f"Status: signed out ({auth.get('email') or auth.get('subject')})")
    else:
        print(f"Status: connected ({auth.get('email') or auth.get('subject')})")
        print(f"ChatGPT plan usage: {'granted' if _has_plan_scope(auth.get('scope', '')) else 'not granted'}")
        print(f"Access token expires in: {max(0, int(float(auth.get('expires_at', 0)) - time.time()))}s")


def logout() -> None:
    auth = _load_auth()
    if not auth or not auth.get("refresh_token"):
        print("Already signed out.")
        return
    endpoint = _discovery()["revocation_endpoint"]
    for attempt in range(3):
        try:
            response = _request("POST", endpoint, data={
                "token": auth["refresh_token"],
                "token_type_hint": "refresh_token",
                "client_id": auth["client_id"],
            })
        except PlusAPIError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
            continue
        if response.status_code == 200:
            break
        if response.status_code < 500 or attempt == 2:
            raise PlusAPIError(f"Remote revocation failed (HTTP {response.status_code}); local tokens were retained")
        time.sleep(2 ** attempt)
    for field in ("access_token", "refresh_token", "id_token"):
        auth[field] = None
    auth["expires_at"] = 0
    _save_auth(auth)
    print("Renewable session revoked and local tokens cleared.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Use ChatGPT plan usage through official local OAuth")
    commands = parser.add_subparsers(dest="command", required=True)
    login_parser = commands.add_parser("login", help="Open browser sign-in and authorize this local app")
    login_parser.add_argument("--manual", action="store_true", help="Print the authorization URL instead of opening a browser")
    login_parser.add_argument("--timeout", type=int, default=600, help="Seconds to wait for browser authorization (default: 600)")
    commands.add_parser("models", help="List models available to this ChatGPT account")
    ask_parser = commands.add_parser("ask", help="Make a streaming Responses API request")
    ask_parser.add_argument("prompt", help="Text to send to the selected model")
    ask_parser.add_argument("--model", help="Model slug from the models command")
    run_parser = commands.add_parser("run", help="Run a local command with the OAuth access token in OPENAI_API_KEY")
    run_parser.add_argument("child_command", nargs=argparse.REMAINDER, help="Command to launch after --")
    serve_parser = commands.add_parser("serve", help="Start a loopback bridge for the YuKeTang browser userscript")
    serve_parser.add_argument("--port", type=int, default=8765, help="Local TCP port (default: 8765)")
    commands.add_parser("status", help="Show connection status without exposing tokens")
    commands.add_parser("logout", help="Revoke the renewable session and clear local tokens")
    args = parser.parse_args()
    try:
        if args.command == "login":
            if args.timeout < 30:
                raise PlusAPIError("--timeout must be at least 30 seconds")
            login(manual=args.manual, timeout=args.timeout)
        elif args.command == "models":
            list_models()
        elif args.command == "ask":
            ask(args.prompt, args.model)
        elif args.command == "run":
            return run_with_plan_token(args.child_command)
        elif args.command == "serve":
            from browser_bridge import serve
            serve(args.port)
        elif args.command == "status":
            status()
        elif args.command == "logout":
            logout()
    except PlusAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
