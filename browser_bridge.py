"""Loopback Chat Completions adapter for the YuKeTang userscript.

The browser receives only a local bridge key. OpenAI OAuth tokens remain in
the Python process and are refreshed by plus_api as needed.
"""

from __future__ import annotations

import hmac
import json
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import keyring
import requests

import plus_api


HOST = "127.0.0.1"
DEFAULT_PORT = 8765
KEYRING_ACCOUNT = "browser-bridge-key"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_ANSWER_CHARS = 2 * 1024 * 1024


def _local_key() -> str:
    try:
        key = keyring.get_password(plus_api.KEYRING_SERVICE, KEYRING_ACCOUNT)
        if not key:
            key = "local-" + secrets.token_urlsafe(32)
            keyring.set_password(plus_api.KEYRING_SERVICE, KEYRING_ACCOUNT, key)
        return key
    except Exception as exc:
        raise plus_api.PlusAPIError(f"Could not access the local bridge key: {exc}") from exc


def _to_responses_request(body: dict) -> dict:
    model = body.get("model")
    messages = body.get("messages")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("model must be a non-empty model slug")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")

    instructions = []
    history = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("each message must be an object")
        role = message.get("role")
        content = message.get("content")
        if not isinstance(content, str):
            raise ValueError("this bridge supports text message content only")
        if role in ("system", "developer"):
            instructions.append(content)
        elif role in ("user", "assistant"):
            history.append({"role": role, "content": content})
        else:
            raise ValueError(f"unsupported message role: {role}")
    if not history:
        raise ValueError("messages must contain a user or assistant message")

    payload = {"model": model, "input": history, "store": False, "stream": True}
    if instructions:
        payload["instructions"] = "\n\n".join(instructions)
    # The userscript sends temperature, which this ChatGPT plan route does not
    # support. Do not forward unsupported Chat Completions fields.
    return payload


def _complete_response(payload: dict) -> str:
    try:
        response = requests.post(
            f"{plus_api.API_BASE}/responses",
            headers=plus_api._authorization_headers(),
            json=payload,
            stream=True,
            timeout=(plus_api.HTTP_TIMEOUT, 180),
        )
    except requests.RequestException as exc:
        raise plus_api.PlusAPIError(f"OpenAI request failed: {exc}") from exc

    with response:
        if not response.ok:
            plus_api._json_response(response)
        chunks = []
        size = 0
        completed = False
        try:
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
                    delta = event.get("delta", "")
                    size += len(delta)
                    if size > MAX_ANSWER_CHARS:
                        raise plus_api.PlusAPIError("OpenAI answer exceeded the local bridge size limit")
                    chunks.append(delta)
                elif kind == "response.failed":
                    error = (event.get("response") or {}).get("error") or {}
                    raise plus_api.PlusAPIError(f"OpenAI response failed: {error.get('code') or error.get('message') or error}")
                elif kind in ("response.incomplete", "error"):
                    raise plus_api.PlusAPIError(f"OpenAI response did not complete: {kind}")
                elif kind == "response.completed":
                    completed = True
        except requests.RequestException as exc:
            raise plus_api.PlusAPIError(f"OpenAI stream failed: {exc}") from exc
    if not completed:
        raise plus_api.PlusAPIError("OpenAI stream ended without response.completed")
    return "".join(chunks)


def _handler(local_key: str):
    class BridgeHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self._send(404, {"error": {"message": "Unknown local endpoint"}})
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {local_key}"):
                self._send(401, {"error": {"message": "Invalid local bridge key"}})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    raise ValueError("request body is empty or too large")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("request body must be an object")
                payload = _to_responses_request(body)
            except (ValueError, UnicodeDecodeError) as exc:
                self._send(400, {"error": {"message": str(exc)}})
                return
            try:
                content = _complete_response(payload)
            except plus_api.PlusAPIError as exc:
                self._send(502, {"error": {"message": str(exc)}})
                return
            self._send(200, {
                "id": "chatcmpl-local-" + uuid.uuid4().hex,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": payload["model"],
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }],
            })

        def _send(self, status: int, data: dict):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass  # Never log browser requests or credentials.

    return BridgeHandler


def serve(port: int = DEFAULT_PORT) -> None:
    if not 1 <= port <= 65535:
        raise plus_api.PlusAPIError("Port must be between 1 and 65535")
    plus_api._active_auth()  # Fail before showing a local key if sign-in is missing.
    key = _local_key()
    try:
        server = ThreadingHTTPServer((HOST, port), _handler(key))
    except OSError as exc:
        raise plus_api.PlusAPIError(f"Could not start local bridge: {exc}") from exc
    server.daemon_threads = True
    print(f"API URL: http://{HOST}:{port}/v1/chat/completions", flush=True)
    print(f"Local API KEY: {key}", flush=True)
    print("API Format: OpenAI Format (Chat Completions)", flush=True)
    print("Auth Method: Bearer Token", flush=True)
    print("Keep this Git Bash window open; press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLocal bridge stopped.")
    finally:
        server.server_close()
