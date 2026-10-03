"""Offline tests (no API key, no model download).  Run:  python -m pytest agent_loop_test.py"""

import json
from types import SimpleNamespace as NS

from agent import Agent, ToolRegistry
from tools_memory import MemoryTools


# ---------- fakes ----------

def reply(text):
    return NS(choices=[NS(message=NS(content=text, tool_calls=None))])


def call(name, args, call_id="c1", raw=None):
    fn = NS(name=name, arguments=raw if raw is not None else json.dumps(args))
    return NS(choices=[NS(message=NS(content=None,
                                     tool_calls=[NS(id=call_id, function=fn)]))])


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self.script.pop(0)


class FakeBackend:
    def __init__(self):
        self.added, self.items = [], []

    def add_memory(self, text, **kw):
        self.added.append((text, kw))
        return True

    def search_memory(self, query, max_results=5, threshold=0.35):
        return [{"memory": "likes tea", "type": "preference", "importance": 3,
                 "similarity": 0.9, "valid_from": None, "extra": "dropped"}]

    def update_memory(self, old, new, **kw):
        return True

    def end_memory(self, text, **kw):
        return True

    def delete_memory(self, text, **kw):
        return True

    def get_memory(self):
        return self.items


def make_agent(script, backend=None, **kw):
    backend = backend or FakeBackend()
    registry = ToolRegistry()
    MemoryTools(backend).register_into(registry)
    client = FakeClient(script)
    return Agent(client, "m", registry, **kw), client, backend


# ---------- agent loop ----------

def test_plain_answer_no_tools():
    agent, client, _ = make_agent([reply("hi")])
    assert agent.run_turn("hello") == "hi"
    assert len(client.calls) == 1


def test_tool_call_then_answer_and_history_is_clean():
    agent, client, backend = make_agent([
        call("remember", {"text": "user likes tea", "type": "preference", "importance": 9}),
        reply("Saved."),
    ])
    assert agent.run_turn("I like tea") == "Saved."
    text, kw = backend.added[0]
    assert text == "user likes tea" and kw["memory_type"] == "preference"
    assert kw["importance"] == 5  # clamped
    assert [m["role"] for m in agent.history] == ["user", "assistant"]
    roles = [m["role"] for m in client.calls[1]["messages"]]
    assert roles[-2:] == ["assistant", "tool"]


def test_malformed_json_arguments_do_not_crash():
    agent, client, _ = make_agent([call("remember", {}, raw="{not json"), reply("ok")])
    assert agent.run_turn("x") == "ok"
    tool_msg = client.calls[1]["messages"][-1]
    assert "invalid JSON" in tool_msg["content"]


def test_unknown_tool_and_bad_arguments():
    agent, client, _ = make_agent([call("hack", {}), call("recall", {"wrong": 1}), reply("done")])
    assert agent.run_turn("x") == "done"
    msgs = [m for m in client.calls[2]["messages"] if m["role"] == "tool"]
    assert "unknown tool" in msgs[0]["content"] and "bad arguments" in msgs[1]["content"]


def test_step_limit_returns_fallback():
    agent, _, _ = make_agent([call("recall", {"query": "a"}, f"c{i}") for i in range(3)],
                             max_steps=3)
    assert "step limit" in agent.run_turn("x")


def test_confirmation_declined_blocks_dangerous_tool():
    ran = []
    registry = ToolRegistry()
    registry.register({"type": "function", "function": {"name": "danger", "parameters": {}}},
                      lambda: ran.append(1) or {"ok": True}, needs_confirmation=True)
    client = FakeClient([call("danger", {}), reply("ok")])
    agent = Agent(client, "m", registry, confirm=lambda n, a: False)
    agent.run_turn("x")
    assert not ran
    assert "declined" in client.calls[1]["messages"][-1]["content"]


def test_history_is_trimmed_and_context_injected():
    agent, client, _ = make_agent([reply("a")] * 3, max_history=4,
                                  context_provider=lambda t: "- likes tea")
    for _ in range(3):
        agent.run_turn("q")
    assert len(agent.history) == 4
    assert "likes tea" in client.calls[0]["messages"][0]["content"]


# ---------- memory tools ----------

def test_memory_tools_validation_and_trimming():
    tools = MemoryTools(FakeBackend())
    assert tools.remember("  ")["ok"] is False
    assert tools.remember("x", type="weird")["ok"] is True
    res = tools.recall("tea")["results"][0]
    assert "extra" not in res and res["memory"] == "likes tea"
    assert tools.update("", "new")["ok"] is False
    assert tools.forget("likes tea")["ok"] is True
