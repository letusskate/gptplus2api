import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import requests

import browser_bridge


class BrowserBridgeTests(unittest.TestCase):
    def test_upstream_text_is_returned_only_after_completed_event(self):
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
            'data: {"type":"response.output_text.delta","delta":"hello"}',
            'data: {"type":"response.completed"}',
        ]
        with patch.object(browser_bridge.plus_api, "_authorization_headers", return_value={"Authorization": "Bearer test"}), \
             patch.object(browser_bridge.requests, "post", return_value=FakeResponse(events)) as post:
            self.assertEqual(browser_bridge._complete_response({"model": "test"}), "hello")
            self.assertEqual(post.call_args.kwargs["json"], {"model": "test"})

        with patch.object(browser_bridge.plus_api, "_authorization_headers", return_value={"Authorization": "Bearer test"}), \
             patch.object(browser_bridge.requests, "post", return_value=FakeResponse(events[:1])):
            with self.assertRaisesRegex(browser_bridge.plus_api.PlusAPIError, "without response.completed"):
                browser_bridge._complete_response({"model": "test"})

    def test_userscript_request_maps_to_responses_and_requires_local_key(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), browser_bridge._handler("local-test-secret"))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
        body = {
            "model": "gpt-6-luna",
            "messages": [
                {"role": "system", "content": "Only reply with an answer"},
                {"role": "user", "content": "What is 2+2?"},
            ],
            "temperature": 0.1,
        }
        try:
            with patch.object(browser_bridge, "_complete_response", return_value="4") as upstream:
                denied = requests.post(url, json=body, headers={"Authorization": "Bearer wrong"}, timeout=5)
                self.assertEqual(denied.status_code, 401)
                upstream.assert_not_called()

                allowed = requests.post(url, json=body, headers={"Authorization": "Bearer local-test-secret"}, timeout=5)
                self.assertEqual(allowed.status_code, 200)
                self.assertEqual(allowed.json()["choices"][0]["message"]["content"], "4")
                sent = upstream.call_args.args[0]
                self.assertEqual(sent["instructions"], "Only reply with an answer")
                self.assertEqual(sent["input"], [{"role": "user", "content": "What is 2+2?"}])
                self.assertEqual(sent["model"], "gpt-6-luna")
                self.assertIs(sent["store"], False)
                self.assertIs(sent["stream"], True)
                self.assertNotIn("temperature", sent)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
