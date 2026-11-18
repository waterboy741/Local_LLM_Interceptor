#!/usr/bin/env python3
"""Serve synthetic chat completions for the single-Mac explicit proxy demo."""

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    timeout = 5

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid body length")
            request = json.loads(self.rfile.read(length))
            content = request["messages"][-1]["content"]
            if request.get("stream") is not True or not isinstance(content, str):
                raise ValueError("expected a streaming request with text content")
        except (ValueError, KeyError, IndexError, TypeError):
            self.send_error(400, "Expected stream=true and a final message with text content")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        try:
            for delta in ({"role": "assistant", "content": "Mock received: "}, {"content": content}):
                event = {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta}]}
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.8)
            self.wfile.write(b"data: [DONE]\n\n")
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    with HTTPServer(("127.0.0.1", 0), DemoHandler) as server:
        print(f"Mock Ollama listening on 127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
