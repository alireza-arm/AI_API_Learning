"""Offline tests for telegram_bot.py (fake Telegram via httpx.MockTransport).
Run:  python -m pytest telegram_bot_test.py
"""

import json
from types import SimpleNamespace as NS

import httpx
import pytest

from agent import Agent, ToolRegistry
from telegram_bot import Bot, TelegramAPI, TelegramError, make_client, split_message
from tools_files import FileTools

TOKEN = "123456:SECRET-TOKEN"
ME = 42


class FakeTelegram:
    """Records requests; `updates` are handed out by getUpdates."""
    def __init__(self):
        self.sent, self.calls, self.updates, self.fail = [], [], [], None

    def handler(self, request):
        method = request.url.path.rsplit("/", 1)[1]
        body = json.loads(request.content or b"{}")
        self.calls.append((method, body))
        if self.fail:
            return httpx.Response(401, json={"ok": False, "description": self.fail})
        if method == "getUpdates":
            batch, self.updates = self.updates, []
            return httpx.Response(200, json={"ok": True, "result": batch})
        if method == "sendMessage":
            self.sent.append(body)
        return httpx.Response(200, json={"ok": True, "result": {"username": "mybot"}})

    def api(self):
        client = httpx.Client(transport=httpx.MockTransport(self.handler))
        return TelegramAPI(TOKEN, client=client)


class FakeLLM:
    def __init__(self, text="agent says hi", error=None):
        self.text, self.error, self.calls = text, error, []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return NS(choices=[NS(message=NS(content=self.text, tool_calls=None))])


def update(text, user=ME, chat_type="private", update_id=1):
    return {"update_id": update_id, "message": {
        "text": text, "from": {"id": user}, "chat": {"id": user, "type": chat_type}}}


@pytest.fixture
def setup(tmp_path):
    tg, llm = FakeTelegram(), FakeLLM()
    files = FileTools(tmp_path / "ws")
    (files.root / "todo.txt").write_text("buy milk", encoding="utf-8")
    agent = Agent(llm, "m", ToolRegistry())
    logs = []
    bot = Bot(tg.api(), agent, files, ME, log=logs.append, sleep=lambda s: logs.append(f"sleep {s}"))
    return NS(tg=tg, llm=llm, bot=bot, logs=logs, agent=agent)


def texts(setup):
    return [m["text"] for m in setup.tg.sent]


# ---------- helpers / API ----------

def test_split_message_respects_limit():
    chunks = split_message("a" * 9000)
    assert [len(c) for c in chunks] == [4000, 4000, 1000]
    assert split_message("") == ["(empty reply)"]


def test_telegram_error_never_contains_the_token():
    tg = FakeTelegram()
    tg.fail = f"Unauthorized {TOKEN}"
    with pytest.raises(TelegramError) as info:
        tg.api().get_me()
    assert TOKEN not in str(info.value) and "<token>" in str(info.value)

    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")
    api = TelegramAPI(TOKEN, client=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(TelegramError) as info:
        api.get_me()
    assert TOKEN not in str(info.value)


def test_client_ignores_system_proxy_settings(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert make_client("http://127.0.0.1:10808").trust_env is False
    assert make_client().trust_env is False


# ---------- security ----------

def test_messages_from_other_users_or_groups_are_ignored(setup):
    for upd in (update("hello", user=999), update("hello", chat_type="group"),
                {"update_id": 5, "message": {"from": {"id": ME}, "chat": {"id": ME, "type": "private"}}}):
        setup.bot.handle_update(upd)
    assert setup.tg.sent == [] and setup.llm.calls == []
    assert any("999" in line for line in setup.logs)
    assert not any("hello" in line for line in setup.logs)  # content is never logged


# ---------- behaviour ----------

def test_normal_message_goes_to_agent_and_reply_is_sent(setup):
    setup.bot.handle_update(update("hello there"))
    assert texts(setup) == ["agent says hi"]
    assert ("sendChatAction", {"chat_id": ME, "action": "typing"}) in setup.tg.calls


def test_commands_work_including_botname_suffix(setup):
    setup.bot.handle_update(update("/ls@mybot"))
    assert "todo.txt" in texts(setup)[0]
    setup.bot.handle_update(update("/read todo.txt"))
    assert "Attached todo.txt" in texts(setup)[1]
    setup.bot.handle_update(update("/start"))
    assert "/ls" in texts(setup)[2] and "/exit" not in texts(setup)[2]
    setup.bot.handle_update(update("/exit"))
    assert "terminal" in texts(setup)[3]
    assert setup.llm.calls == []


def test_agent_failure_gives_friendly_message_without_details(setup):
    setup.llm.error = RuntimeError(f"boom {TOKEN}")
    setup.bot.handle_update(update("hi"))
    assert "something went wrong" in texts(setup)[0]
    assert TOKEN not in texts(setup)[0] and not any(TOKEN in line for line in setup.logs)


# ---------- polling ----------

def test_poll_once_handles_updates_and_advances_offset(setup):
    setup.tg.updates = [update("one", update_id=10), update("two", update_id=11)]
    assert setup.bot.poll_once() == 2
    assert setup.bot.offset == 12 and len(setup.tg.sent) == 2
    setup.bot.poll_once()
    assert setup.tg.calls[-1][1]["offset"] == 12  # already-handled updates are not fetched again


def test_poll_failures_back_off_then_recover(setup):
    setup.tg.fail = "Bad Gateway"
    for _ in range(3):
        assert setup.bot.poll_once() == 0
    assert [l for l in setup.logs if l.startswith("sleep")] == ["sleep 2", "sleep 4", "sleep 8"]
    setup.tg.fail = None
    setup.tg.updates = [update("back", update_id=1)]
    assert setup.bot.poll_once() == 1 and setup.bot.failures == 0


def test_poll_wait_is_short_by_default_and_configurable(setup):
    setup.bot.poll_once()
    assert setup.tg.calls[-1][1]["timeout"] == 10
    setup.bot.poll_timeout = 3
    setup.bot.poll_once()
    assert setup.tg.calls[-1][1]["timeout"] == 3


def test_client_does_not_reuse_connections():
    client = make_client("http://127.0.0.1:10808")
    pool = client._transport._pool
    assert pool._max_keepalive_connections == 0


def test_activity_is_logged_without_message_content(setup):
    setup.bot.handle_update(update("my secret question"))
    setup.bot.handle_update(update("/start"))
    handled = [l for l in setup.logs if l.startswith("handled a message")]
    assert len(handled) == 2 and all("replied in" in l for l in handled)
    assert not any("secret" in l for l in setup.logs)