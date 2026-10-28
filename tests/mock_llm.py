"""A tiny local HTTP server that speaks the Anthropic Messages and OpenAI chat-completions wire
formats, so provider code, caching, retries and the LLM-judge layers are tested offline.

Its "model" is a fixed policy: list_emails -> read_email(0) -> final answer quoting the email.
As a judge it flags sentences that address an assistant, and allows only internal recipients.
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _policy(system: str, msgs: list[dict]) -> tuple[str, dict | None]:
    """Return (text, tool_call or None). ``msgs`` are normalised {role, text, tool_results}."""
    last_user = msgs[-1]["text"] if msgs else ""
    if "security filter" in system:
        hits = [int(m.group(1)) for m in re.finditer(r"^(\d+): (.*)$", last_user, re.M)
                if re.search(r"assistant|ignore all|admin notice", m.group(2), re.I)]
        return json.dumps({"injected": hits}), None
    if "review actions" in system:
        bad = re.search(r"external|competitor|files-sync|9921", last_user)
        return json.dumps({"allow": not bad, "reason": "external target" if bad else "ok"}), None
    n_results = sum(len(m["tool_results"]) for m in msgs)
    if n_results == 0:
        return "", {"name": "list_emails", "args": {}}
    if n_results == 1:
        return "", {"name": "read_email", "args": {"id": 0}}
    return "Summary: " + msgs[-1]["tool_results"][-1][:300], None


class State:
    def __init__(self):
        self.hits = 0
        self.fail_next = 0
        self.bodies: list[dict] = []


def make_handler(state: State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            state.hits += 1
            state.bodies.append(body)
            if state.fail_next > 0:
                state.fail_next -= 1
                return self._send(429, {"error": "rate limited"})
            if self.path.endswith("/v1/messages"):
                msgs = []
                for m in body["messages"]:
                    if isinstance(m["content"], str):
                        msgs.append({"role": m["role"], "text": m["content"], "tool_results": []})
                    else:
                        msgs.append({"role": m["role"],
                                     "text": "".join(b.get("text", "") for b in m["content"] if b["type"] == "text"),
                                     "tool_results": [b["content"] for b in m["content"]
                                                      if b["type"] == "tool_result"]})
                text, call = _policy(body.get("system", ""), msgs)
                content = [{"type": "text", "text": text}] if text else []
                if call:
                    content.append({"type": "tool_use", "id": f"tu_{state.hits}", "name": call["name"],
                                    "input": call["args"]})
                return self._send(200, {"content": content, "usage": {"input_tokens": 100, "output_tokens": 10}})
            if self.path.endswith("/chat/completions"):
                system = body["messages"][0]["content"]
                msgs = []
                for m in body["messages"][1:]:
                    if m["role"] == "tool":
                        if msgs and msgs[-1]["role"] == "tool_batch":
                            msgs[-1]["tool_results"].append(m["content"])
                        else:
                            msgs.append({"role": "tool_batch", "text": "", "tool_results": [m["content"]]})
                    else:
                        msgs.append({"role": m["role"], "text": m.get("content") or "", "tool_results": []})
                text, call = _policy(system, msgs)
                msg = {"role": "assistant", "content": text or None}
                if call:
                    msg["tool_calls"] = [{"id": f"call_{state.hits}", "type": "function",
                                          "function": {"name": call["name"], "arguments": json.dumps(call["args"])}}]
                return self._send(200, {"choices": [{"message": msg}],
                                        "usage": {"prompt_tokens": 100, "completion_tokens": 10}})
            self._send(404, {"error": "not found"})
    return H


class MockLLMServer:
    def __init__(self):
        self.state = State()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
