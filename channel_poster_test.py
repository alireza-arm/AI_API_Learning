"""Offline tests for channel_poster.py and the bot's channel commands.
Run:  python -m pytest channel_poster_test.py
"""

import json
from types import SimpleNamespace as NS

import httpx
import pytest

from agent import Agent, ToolRegistry
from channel_poster import ANGLES, TOPICS, PostGenerator, Poster, clean_post, pick
from telegram_bot import Bot, TelegramAPI, TelegramError, check_channel
from tools_files import FileTools

ME, CHANNEL, TOKEN = 42, "@mech_channel", "1:SECRET"
GOOD = ("Why beams bend\n\nA beam bends because its top fibres are compressed while the bottom fibres "
        "stretch. The deeper the beam, the stiffer it is. A ruler flexes easily flat but not on its edge.")


class FakeTelegram:
    def __init__(self):
        self.sent, self.fail_channel = [], False
        self.api = TelegramAPI(TOKEN, client=httpx.Client(transport=httpx.MockTransport(self.handler)))

    def handler(self, request):
        method = request.url.path.rsplit("/", 1)[1]
        body = json.loads(request.content or b"{}")
        if method == "sendMessage":
            if self.fail_channel and body["chat_id"] == CHANNEL:
                return httpx.Response(403, json={"ok": False, "description": "Forbidden: bot is not a member"})
            self.sent.append(body)
        if method == "getChatMember":
            return httpx.Response(200, json={"ok": True, "result": self.member})
        if method == "getChat":
            return httpx.Response(200, json={"ok": True, "result": {"title": "Mech"}})
        return httpx.Response(200, json={"ok": True, "result": {}})

    member = {"status": "administrator", "can_post_messages": True}


class FakeLLM:
    def __init__(self, outputs):
        self.outputs, self.calls = list(outputs), []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        text = self.outputs.pop(0) if self.outputs else GOOD
        return NS(choices=[NS(message=NS(content=text, tool_calls=None))])


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    tg, clock, logs = FakeTelegram(), Clock(), []
    llm = FakeLLM([])
    poster = Poster(tg.api, PostGenerator(llm, "m"), CHANNEL, 7200, tmp_path / "state.json",
                    now=clock, log=logs.append, retry_seconds=600)
    return NS(tg=tg, clock=clock, logs=logs, llm=llm, poster=poster, tmp=tmp_path)


# ---------- cleaning / rotation ----------

def test_clean_post_strips_markdown_links_and_rejects_bad_output():
    cleaned = clean_post("# Title\n\n**Bold** idea see https://evil.example/x and `code`. " + "word " * 20)
    assert "http" not in cleaned and "**" not in cleaned and "#" not in cleaned and "`" not in cleaned
    for bad in [None, "", "short", "Sorry, I can't help with that. " + "x" * 100, "y" * 4000]:
        assert clean_post(bad) is None


def test_rotation_covers_all_topics_then_changes_angle():
    first_round = [pick(i) for i in range(len(TOPICS))]
    assert {t for t, _ in first_round} == set(TOPICS) and len({a for _, a in first_round}) == 1
    assert pick(len(TOPICS))[1] != pick(0)[1] and pick(0)[0] == pick(len(TOPICS))[0]
    assert len(ANGLES) >= 4


# ---------- generation ----------

def test_generator_sends_no_memory_and_retries_bad_output():
    llm = FakeLLM(["sorry I can't", GOOD])
    assert PostGenerator(llm, "m", language="Persian").generate("beams", "tip") == GOOD
    assert len(llm.calls) == 2
    roles = [m["role"] for m in llm.calls[0]["messages"]]
    assert roles == ["system", "user"]                       # nothing else: no memory, no files
    assert "Persian" in llm.calls[0]["messages"][0]["content"]
    assert PostGenerator(FakeLLM(["no", "no"]), "m").generate("a", "b") is None


# ---------- scheduling ----------

def test_not_due_until_interval_passes_then_posts_once(env):
    p, clock = env.poster, env.clock
    assert p.tick() is False and env.tg.sent == []           # first run: wait a full interval
    clock.t += 7199
    assert p.tick() is False
    clock.t += 2
    assert p.tick() is True
    assert env.tg.sent[0]["chat_id"] == CHANNEL and env.tg.sent[0]["text"] == GOOD
    assert p.tick() is False and len(env.tg.sent) == 1       # not due again straight away
    clock.t += 7200 * 5                                      # laptop was off for 10 hours
    assert p.tick() is True and len(env.tg.sent) == 2        # ONE post, no catch-up spam
    assert p.tick() is False


def test_state_survives_restart_and_topic_advances(env):
    env.clock.t += 7300
    env.poster.tick()
    again = Poster(env.tg.api, PostGenerator(env.llm, "m"), CHANNEL, 7200, env.tmp / "state.json",
                   now=env.clock, log=env.logs.append)
    assert again.state["index"] == 1 and again.tick() is False  # not due right after restart
    assert pick(1)[0] in again.status()


def test_pause_and_resume(env):
    env.clock.t += 8000
    env.poster.set_paused(True)
    assert env.poster.tick() is False and env.tg.sent == []
    env.poster.set_paused(False)
    assert env.poster.tick() is True


def test_send_failure_retries_later_without_advancing(env):
    env.clock.t += 8000
    env.tg.fail_channel = True
    assert env.poster.tick() is False
    assert any("posting failed" in l for l in env.logs) and TOKEN not in " ".join(env.logs)
    assert env.poster.state.get("index", 0) == 0
    env.tg.fail_channel = False
    assert env.poster.tick() is False                        # still inside the 10 minute pause
    env.clock.t += 601
    assert env.poster.tick() is True and env.poster.state["index"] == 1


def test_unusable_generation_is_retried_later(env):
    env.clock.t += 8000
    env.llm.outputs = ["bad", "bad"]
    assert env.poster.tick() is False and env.tg.sent == []
    env.clock.t += 601
    assert env.poster.tick() is True


# ---------- bot commands ----------

def make_bot(env, with_poster=True):
    agent = Agent(FakeLLM([]), "m", ToolRegistry())
    bot = Bot(env.tg.api, agent, FileTools(env.tmp / "ws"), ME, log=env.logs.append,
              poster=env.poster if with_poster else None)
    return bot


def say(bot, env, text):
    before = len(env.tg.sent)
    bot.handle_update({"update_id": 1, "message": {"text": text, "from": {"id": ME},
                                                   "chat": {"id": ME, "type": "private"}}})
    return env.tg.sent[before:]


def test_preview_goes_to_owner_not_channel(env):
    sent = say(make_bot(env), env, "/preview")
    assert sent[0]["chat_id"] == ME and "NOT posted" in sent[0]["text"] and GOOD in sent[0]["text"]
    assert "/approve" in sent[0]["text"]
    assert env.poster.state.get("index", 0) == 0


def test_post_now_pause_resume_status(env):
    bot = make_bot(env)
    sent = say(bot, env, "/post_now")
    assert [m["chat_id"] for m in sent] == [CHANNEL, ME] and "Posted" in sent[1]["text"]
    assert "paused" in say(bot, env, "/post_pause")[0]["text"] and env.poster.paused
    assert "PAUSED" in say(bot, env, "/post_status")[0]["text"]
    assert "resumed" in say(bot, env, "/post_resume")[0]["text"] and not env.poster.paused
    assert "/preview" in say(bot, env, "/start")[0]["text"]


def test_post_now_reports_telegram_error_to_owner(env):
    env.tg.fail_channel = True
    reply = say(make_bot(env), env, "/post_now")[0]["text"]
    assert reply.startswith("Could not post") and TOKEN not in reply


def test_commands_without_poster_explain_how_to_enable(env):
    reply = say(make_bot(env, with_poster=False), env, "/post_now")[0]["text"]
    assert "TELEGRAM_CHANNEL_ID" in reply


# ---------- channel check ----------

def test_check_channel_reports_permissions(env):
    assert check_channel(env.tg.api, CHANNEL, 7)[0] is True
    env.tg.member = {"status": "administrator", "can_post_messages": False}
    ok, message = check_channel(env.tg.api, CHANNEL, 7)
    assert not ok and "Post messages" in message
    env.tg.member = {"status": "left"}
    assert "not an administrator" in check_channel(env.tg.api, CHANNEL, 7)[1]


POST_A = ("Free body diagrams\n\nA free body diagram shows an object alone with every external force on it drawn "
          "as an arrow. Draw the weight downwards and the support force upwards to check the balance.")
POST_B = ("Centre of gravity\n\nThe centre of gravity is the point where the whole weight of a body can be "
          "treated as acting. A suspended object hangs with its centre of gravity directly below the hook.")


def test_post_now_publishes_exactly_the_previewed_text(env):
    env.llm.outputs = [POST_A, POST_B]          # a second generation would give a DIFFERENT post
    bot = make_bot(env)
    preview = say(bot, env, "/preview")[0]["text"]
    assert POST_A in preview and "/approve" in preview
    sent = say(bot, env, "/post_now")
    assert sent[0]["chat_id"] == CHANNEL and sent[0]["text"] == POST_A     # same text as the preview
    assert "approved" in sent[1]["text"] and env.poster.pending is None
    assert len(env.llm.calls) == 1                                          # no second generation


def test_post_now_without_preview_generates_fresh_and_scheduler_ignores_stale_preview(env):
    env.llm.outputs = [POST_A, POST_B]
    bot = make_bot(env)
    say(bot, env, "/preview")                   # draft A is pending but never approved
    env.clock.t += 8000
    assert env.poster.tick() is True            # the scheduler writes its own fresh post (B)
    assert env.tg.sent[-1]["text"] == POST_B and env.poster.pending is None
    env.llm.outputs = [POST_A]
    assert "Posted to the channel." in say(bot, env, "/post_now")[1]["text"]


# ---------- review mode ----------

@pytest.fixture
def renv(tmp_path):
    tg, clock, logs = FakeTelegram(), Clock(), []
    llm = FakeLLM([])
    notified = []

    def notify(text):
        notified.append(text)
        tg.api.send_message(ME, text)

    def build():
        return Poster(tg.api, PostGenerator(llm, "m"), CHANNEL, 7200, tmp_path / "state.json",
                      now=clock, log=logs.append, retry_seconds=600, mode="review", notify=notify)

    return NS(tg=tg, clock=clock, logs=logs, llm=llm, poster=build(), build=build,
              notified=notified, tmp=tmp_path)


def channel_posts(env):
    return [m for m in env.tg.sent if m["chat_id"] == CHANNEL]


def test_review_mode_sends_a_draft_to_the_owner_and_publishes_nothing(renv):
    p = renv.poster
    renv.clock.t += 7000
    assert p.tick() is False and renv.notified == []             # not time yet
    renv.clock.t += 300
    assert p.tick() is True
    assert len(renv.notified) == 1 and GOOD in renv.notified[0] and "/approve" in renv.notified[0]
    assert channel_posts(renv) == []                              # NOTHING published
    assert p.pending is not None
    renv.clock.t += 600
    assert p.tick() is False and len(renv.notified) == 1          # no second draft while one waits


def test_approve_publishes_exactly_the_draft_then_waits_a_full_interval(renv):
    renv.llm.outputs = [POST_A, POST_B]
    renv.clock.t += 8000
    renv.poster.tick()
    bot = make_bot(renv)
    reply = say(bot, renv, "/approve")
    assert channel_posts(renv)[0]["text"] == POST_A and "approved" in reply[-1]["text"]
    assert renv.poster.pending is None and renv.poster.state["index"] == 1
    renv.clock.t += 7000
    assert renv.poster.tick() is False                            # next draft only after 2 h
    renv.clock.t += 300
    assert renv.poster.tick() is True and channel_posts(renv) == channel_posts(renv)[:1]


def test_skip_discards_and_moves_on(renv):
    renv.clock.t += 8000
    renv.poster.tick()
    bot = make_bot(renv)
    assert "discarded" in say(bot, renv, "/skip")[0]["text"]
    assert channel_posts(renv) == [] and renv.poster.pending is None
    assert renv.poster.state["index"] == 1
    assert "No draft" in say(bot, renv, "/skip")[0]["text"]
    renv.clock.t += 7300
    assert renv.poster.tick() is True and len(renv.notified) == 2   # a new draft after a full interval


def test_redraft_replaces_the_waiting_draft(renv):
    renv.llm.outputs = [POST_A, POST_B]
    renv.clock.t += 8000
    renv.poster.tick()
    bot = make_bot(renv)
    assert POST_B in say(bot, renv, "/redraft")[0]["text"]
    say(bot, renv, "/approve")
    assert channel_posts(renv)[0]["text"] == POST_B


def test_approve_without_a_draft_and_failed_approve_keeps_the_draft(renv):
    bot = make_bot(renv)
    assert "No draft" in say(bot, renv, "/approve")[0]["text"]
    renv.clock.t += 8000
    renv.poster.tick()
    renv.tg.fail_channel = True
    reply = say(bot, renv, "/approve")[0]["text"]
    assert reply.startswith("Could not post") and renv.poster.pending is not None
    renv.tg.fail_channel = False
    assert "approved" in say(bot, renv, "/approve")[-1]["text"]


def test_pending_draft_survives_restart_and_stale_drafts_are_replaced(renv):
    renv.clock.t += 8000
    renv.poster.tick()
    again = renv.build()                                            # "restart"
    assert again.pending is not None and again.tick() is False
    renv.clock.t += 7300                                            # owner ignored it for > 2 h
    assert again.tick() is True and len(renv.notified) == 2


def test_review_mode_pause_and_delivery_failures(renv):
    renv.clock.t += 8000
    renv.poster.set_paused(True)
    assert renv.poster.tick() is False and renv.notified == []
    renv.poster.set_paused(False)

    def broken(text):
        raise TelegramError("cannot reach you")
    renv.poster.notify = broken
    assert renv.poster.tick() is False
    assert renv.poster.pending is None and any("could not send the draft" in l for l in renv.logs)
    renv.poster.notify = lambda t: renv.notified.append(t)
    assert renv.poster.tick() is False                              # waits out the retry delay
    renv.clock.t += 601
    assert renv.poster.tick() is True


def test_status_mentions_mode_and_waiting_draft(renv):
    assert "Mode: review" in renv.poster.status() and "Draft waiting: no" in renv.poster.status()
    renv.clock.t += 8000
    renv.poster.tick()
    assert "Draft waiting: yes" in renv.poster.status()