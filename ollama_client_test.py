"""Offline tests for ollama_client.py using a local fake Ollama server.
Run:  python -m pytest ollama_client_test.py
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent import Agent, ToolRegistry
from ollama_client import ApiError, OllamaClient
from tools_memory import MemoryTools


class FakeBackend:
    def __init__(self):
        self.added = []

    def add_memory(self, text, **kw):
        self.added.append(text)
        return True


@pytest.fixture
def server():
    state = {"responses": [], "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append(body)
            status, payload = state["responses"].pop(0)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield state
    httpd.shutdown()


def chat(message):
    return 200, {"choices": [{"message": message}]}


def test_text_reply_is_parsed(server):
    server["responses"] = [chat({"role": "assistant", "content": "hello"})]
    client = OllamaClient(server["url"])
    reply = client.chat.completions.create(model="m", messages=[])
    assert reply.choices[0].message.content == "hello"
    assert getattr(reply.choices[0].message, "tool_calls", None) is None


def test_tool_call_gets_id_and_string_arguments(server):
    server["responses"] = [chat({"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": "remember", "arguments": {"text": "x"}}}]})]
    reply = OllamaClient(server["url"]).chat.completions.create(model="m", messages=[])
    call = reply.choices[0].message.tool_calls[0]
    assert call.id and call.function.name == "remember"
    assert json.loads(call.function.arguments) == {"text": "x"}


def test_http_error_becomes_api_error_with_status(server):
    server["responses"] = [(404, {"error": "model not found"})]
    with pytest.raises(ApiError) as info:
        OllamaClient(server["url"]).chat.completions.create(model="m", messages=[])
    assert info.value.status_code == 404


def test_connection_refused_gives_friendly_error():
    with pytest.raises(ApiError) as info:
        OllamaClient("http://127.0.0.1:1").chat.completions.create(model="m", messages=[])
    assert "Ollama" in str(info.value)


def test_full_agent_turn_through_ollama_client(server):
    server["responses"] = [
        chat({"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "remember",
                          "arguments": json.dumps({"text": "user studies mechanics"})}}]}),
        chat({"role": "assistant", "content": "Saved."}),
    ]
    backend = FakeBackend()
    registry = ToolRegistry()
    MemoryTools(backend).register_into(registry)
    agent = Agent(OllamaClient(server["url"]), "llama3.2:3b", registry)
    assert agent.run_turn("I study mechanics") == "Saved."
    assert backend.added == ["user studies mechanics"]
    second_request = server["requests"][1]["messages"]
    assert [m["role"] for m in second_request][-2:] == ["assistant", "tool"]


def test_local_ollama_ignores_proxy_environment(server, monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # nothing listens here
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    server["responses"] = [chat({"role": "assistant", "content": "still works"})]
    reply = OllamaClient(server["url"]).chat.completions.create(model="m", messages=[])
    assert reply.choices[0].message.content == "still works"