"""Offline tests for auto_memory.py.  Run:  python -m pytest auto_memory_test.py"""

import json
from types import SimpleNamespace as NS

from agent import SYSTEM_PROMPT_AUTO, Agent, ToolRegistry
from auto_memory import AutoMemory, parse_facts
from tools_memory import MemoryTools


def reply(text):
    return NS(choices=[NS(message=NS(content=text, tool_calls=None))])


class FakeClient:
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self.script.pop(0)


class FakeBackend:
    def __init__(self):
        self.added = []

    def add_memory(self, text, **kw):
        self.added.append((text, kw))
        return True

    def search_memory(self, query, max_results=5, threshold=0.35):
        return []

    def get_memory(self):
        return [{"memory": t, "updated_at": "1"} for t, _ in self.added]


FACT = {"facts": [{"text": "The user's name is Alireza.", "type": "person", "importance": 5}]}


def test_parse_valid_and_wrapped_json():
    assert parse_facts(json.dumps(FACT))[0]["text"] == "The user's name is Alireza."
    wrapped = "Sure! Here you go:\n" + json.dumps(FACT) + "\nHope that helps."
    assert len(parse_facts(wrapped)) == 1


def test_parse_garbage_never_raises():
    for raw in [None, "", "no json here", "{broken", '{"facts": "nope"}', '[1,2]',
                '{"name":"remember","parameters\':{}}']:
        assert parse_facts(raw) == []


def test_parse_skips_secrets_long_and_non_dict_items():
    raw = json.dumps({"facts": [
        {"text": "The user's password is hunter2."},
        {"text": "api key: abc"},
        {"text": "x" * 400},
        42,
        "The user likes tea.",
    ]})
    assert [f["text"] for f in parse_facts(raw)] == ["The user likes tea."]


def test_auto_memory_saves_facts_and_sends_extraction_prompt():
    backend, client = FakeBackend(), FakeClient([reply(json.dumps(FACT))])
    saved = AutoMemory(client, "m", MemoryTools(backend))("Remember that my name is Alireza.")
    assert saved == ["The user's name is Alireza."]
    text, kw = backend.added[0]
    assert kw["memory_type"] == "person" and kw["importance"] == 5
    assert client.calls[0]["temperature"] == 0
    assert client.calls[0]["messages"][-1]["content"].endswith("Alireza.")


def test_auto_memory_skips_tiny_messages_and_caps_facts():
    backend, client = FakeBackend(), FakeClient([reply(json.dumps(
        {"facts": [{"text": f"The user fact {i}."} for i in range(10)]}))])
    auto = AutoMemory(client, "m", MemoryTools(backend), max_facts=3)
    assert auto("hi") == [] and client.calls == []
    assert len(auto("a longer message")) == 3


def test_agent_reports_saved_facts_and_survives_extraction_failure():
    events = []
    ok = Agent(FakeClient([reply("Nice to meet you!")]), "m", ToolRegistry(),
               system_prompt=SYSTEM_PROMPT_AUTO,
               before_turn=lambda t: ["The user's name is Alireza."],
               on_event=lambda *a: events.append(a))
    assert ok.run_turn("my name is Alireza") == "Nice to meet you!"
    assert events[0][:2] == ("auto_memory", "The user's name is Alireza.")

    def broken(_):
        raise RuntimeError("model offline")
    events.clear()
    bad = Agent(FakeClient([reply("still works")]), "m", ToolRegistry(),
                before_turn=broken, on_event=lambda *a: events.append(a))
    assert bad.run_turn("hello there") == "still works"
    assert events[0][0] == "warning" and "model offline" in events[0][2]


def test_no_tools_are_sent_when_registry_is_empty():
    client = FakeClient([reply("ok")])
    Agent(client, "m", ToolRegistry()).run_turn("hello")
    assert "tools" not in client.calls[0]
