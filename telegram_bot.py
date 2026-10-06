"""Telegram front-end for the agent (long polling, only httpx needed).

.env settings:
    TELEGRAM_BOT_TOKEN=...            (from @BotFather - keep it secret)
    TELEGRAM_ALLOWED_USER_ID=123456   (your numeric id from @userinfobot)
    TELEGRAM_PROXY=http://127.0.0.1:10808   (optional)
    TELEGRAM_POLL_TIMEOUT=10          (optional, seconds to wait per poll)
    TELEGRAM_CHANNEL_ID=@my_channel   (optional, enables scheduled channel posts)
    POST_INTERVAL_HOURS=2             (optional)
    POST_LANGUAGE=English             (optional, e.g. Persian)
    POST_MODE=review                  (optional: review = you approve every post, auto = no review)

Run:   py telegram_bot.py --check   (tests token, connection and channel, then exits)
       py telegram_bot.py           (starts the bot)
"""

import os
import sys
import time

import httpx

from commands import HELP, handle_command

POST_COMMANDS = ("/preview", "/approve", "/skip", "/redraft", "/post_now",
                 "/post_pause", "/post_resume", "/post_status")
POST_HELP = """Channel posting:
  /preview       write a draft (not published)
  /approve       publish the waiting draft exactly as shown
  /skip          discard the waiting draft
  /redraft       rewrite the draft
  /post_now      publish now (the waiting draft, or a fresh one)
  /post_pause    stop automatic posts / drafts
  /post_resume   restart them
  /post_status   show mode and schedule"""

MAX_MESSAGE = 4000  # Telegram's limit is 4096 characters


class TelegramError(Exception):
    pass


def split_message(text, limit=MAX_MESSAGE):
    text = text or "(empty reply)"
    return [text[i:i + limit] for i in range(0, len(text), limit)]


def make_client(proxy=None, timeout=60.0):
    # trust_env=False: ignore Windows/system proxy settings (they can point to a dead port);
    # only TELEGRAM_PROXY is used. No connection reuse: proxies/VPNs often cut idle
    # keep-alive connections ("Server disconnected without sending a response").
    options = dict(timeout=timeout, trust_env=False,
                   limits=httpx.Limits(max_keepalive_connections=0))
    if proxy:
        try:
            return httpx.Client(proxy=proxy, **options)
        except TypeError:  # older httpx
            return httpx.Client(proxies=proxy, **options)
    return httpx.Client(**options)


class TelegramAPI:
    def __init__(self, token, proxy=None, client=None):
        self.token = token
        self.client = client or make_client(proxy)
        self.base = f"https://api.telegram.org/bot{token}"

    def _clean(self, text):
        return str(text).replace(self.token, "<token>")

    def call(self, method, **params):
        try:
            response = self.client.post(f"{self.base}/{method}", json=params)
            data = response.json()
        except Exception as exc:  # never leak the token (it is part of the URL)
            raise TelegramError(f"{method} failed: {type(exc).__name__}: {self._clean(exc)}") from None
        if not data.get("ok"):
            raise TelegramError(f"{method} failed: {self._clean(data.get('description', 'unknown error'))}")
        return data["result"]

    def get_me(self):
        return self.call("getMe")

    def get_chat(self, chat_id):
        return self.call("getChat", chat_id=chat_id)

    def get_chat_member(self, chat_id, user_id):
        return self.call("getChatMember", chat_id=chat_id, user_id=user_id)

    def get_updates(self, offset=None, timeout=30):
        params = {"timeout": timeout, "allowed_updates": ["message"]}
        if offset is not None:
            params["offset"] = offset
        return self.call("getUpdates", **params)

    def send_message(self, chat_id, text):
        for chunk in split_message(text):
            self.call("sendMessage", chat_id=chat_id, text=chunk)
            
    def send_rich_message(self, chat_id, markdown=None, html=None):
        """Send one rich message (Bot API 10.1+). Limit is ~32768 chars, so no splitting.
        Raises TelegramError on failure (the caller can fall back to plain text)."""
        rich = {"markdown": markdown} if markdown is not None else {"html": html}
        return self.call("sendRichMessage", chat_id=chat_id, rich_message=rich)        

    def send_typing(self, chat_id):
        try:
            self.call("sendChatAction", chat_id=chat_id, action="typing")
        except TelegramError:
            pass


def check_channel(api, channel_id, bot_id):
    """Return (ok, message) about whether the bot can post to the channel."""
    try:
        chat = api.get_chat(channel_id)
        member = api.get_chat_member(channel_id, bot_id)
    except TelegramError as exc:
        return False, f"Cannot access channel {channel_id}: {exc}"
    title = chat.get("title", channel_id)
    status = member.get("status")
    if status == "creator" or (status == "administrator" and member.get("can_post_messages")):
        return True, f"Channel OK: '{title}' (the bot can post)"
    if status == "administrator":
        return False, f"The bot is admin of '{title}' but lacks the 'Post messages' permission."
    return False, f"The bot is not an administrator of '{title}'. Add it as admin with 'Post messages'."


class Bot:
    def __init__(self, api, agent, files, allowed_user_id, log=print, sleep=time.sleep,
                 poll_timeout=10, poster=None):
        self.api, self.agent, self.files = api, agent, files
        self.poll_timeout = poll_timeout  # short on purpose: proxies cut long idle waits
        self.poster = poster              # optional channel_poster.Poster
        self.allowed_user_id = int(allowed_user_id)
        self.log, self.sleep = log, sleep
        self.offset = None
        self.failures = 0

    def handle_update(self, update):
        message = update.get("message") or {}
        text = message.get("text")
        sender = (message.get("from") or {}).get("id")
        chat = message.get("chat") or {}
        if not text:
            return
        if sender != self.allowed_user_id or chat.get("type") != "private":
            self.log(f"ignored a message from user id {sender}")  # no reply, never log content
            return

        started = time.monotonic()
        chat_id = chat["id"]
        command, _, rest = text.partition(" ")
        text = command.split("@")[0] + (" " + rest if rest else "")  # "/ls@mybot" -> "/ls"
        word = text.split()[0] if text.split() else ""
        if word in ("/start", "/help"):
            output = HELP.replace("  /exit          quit", "").strip()
            if self.poster:
                output += "\n" + POST_HELP
        elif word == "/exit":
            output = "/exit only works in the terminal."
        elif word in POST_COMMANDS:
            self.api.send_typing(chat_id)
            output = self.handle_post_command(word, chat_id)
        else:
            output = handle_command(text, self.files, self.agent)
        if output is None:
            self.api.send_typing(chat_id)
            try:
                output = self.agent.run_turn(text)
            except Exception as exc:
                self.log(f"agent error: {type(exc).__name__}")
                output = "Sorry, something went wrong while answering. Try again."
        self.api.send_message(chat_id, output)
        self.log(f"handled a message, replied in {time.monotonic() - started:.1f}s")  # no content logged

    def handle_post_command(self, command, chat_id):
        if not self.poster:
            return "Channel posting is not configured (set TELEGRAM_CHANNEL_ID in .env)."
        poster = self.poster
        if command in ("/preview", "/redraft"):
            draft = poster.draft()
            if not draft:
                return "Could not generate a usable draft. Try again."
            if poster.rich:
                try:
                    self.api.send_rich_message(chat_id, markdown=draft[0])
                except TelegramError as exc:
                    return f"The draft could not be shown as a rich message: {exc}"
            return poster.draft_message(draft[0], draft[1], rich=poster.rich)
        if command == "/approve" and not poster.pending:
            return "No draft is waiting. Use /preview to write one."
        if command in ("/approve", "/post_now"):
            had_draft = poster.pending is not None
            try:
                if not poster.post(use_pending=True):
                    return "Could not generate a usable post. Try again."
            except TelegramError as exc:
                return f"Could not post: {exc}"
            return "Published the draft you approved." if had_draft else "Posted to the channel."
        if command == "/skip":
            if not poster.skip():
                return "No draft is waiting."
            return f"Draft discarded. The next one comes in about {poster.interval / 3600:g} h."
        if command == "/post_pause":
            poster.set_paused(True)
            return "Automatic posting paused."
        if command == "/post_resume":
            poster.set_paused(False)
            return "Automatic posting resumed."
        return poster.status()

    def poll_once(self, timeout=None):
        """Fetch and handle one batch. Returns how many updates were handled."""
        try:
            updates = self.api.get_updates(self.offset, timeout=timeout or self.poll_timeout)
        except TelegramError as exc:
            self.failures += 1
            wait = min(2 ** self.failures, 60)
            self.log(f"{exc} - retrying in {wait}s")
            self.sleep(wait)
            return 0
        self.failures = 0
        for update in updates:
            self.offset = update["update_id"] + 1
            try:
                self.handle_update(update)
            except TelegramError as exc:
                self.log(str(exc))
        return len(updates)

    def run_forever(self):
        while True:
            self.poll_once()
            if self.poster:
                self.poster.tick()


def main():
    from dotenv import load_dotenv
    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    user_id = os.getenv("TELEGRAM_ALLOWED_USER_ID", "").strip()
    proxy = os.getenv("TELEGRAM_PROXY", "").strip() or None
    if not token or not user_id.isdigit():
        print("Set TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_USER_ID (digits only) in .env")
        return 1

    api = TelegramAPI(token, proxy)
    try:
        me = api.get_me()
    except TelegramError as exc:
        print(f"Could not reach Telegram: {exc}")
        print("Check that your VPN/proxy is on and TELEGRAM_PROXY is correct.")
        return 1
    print(f"Connected as @{me.get('username')}")

    channel = os.getenv("TELEGRAM_CHANNEL_ID", "").strip()
    if channel:
        ok, message = check_channel(api, channel, me["id"])
        print(message)
        if not ok:
            channel = ""   # run the chat bot anyway, but without channel posting
    if "--check" in sys.argv:
        print("Check OK. Run without --check to start the bot.")
        return 0

    from run_agent import build_agent
    agent, files = build_agent(interactive=False)
    poll_timeout = int(os.getenv("TELEGRAM_POLL_TIMEOUT", "10") or 10)
    poster = None
    if channel:
        from pathlib import Path
        from channel_poster import PostGenerator, Poster
        hours = float(os.getenv("POST_INTERVAL_HOURS", "2") or 2)
        language = os.getenv("POST_LANGUAGE", "English") or "English"
        mode = "auto" if os.getenv("POST_MODE", "review").strip().lower() == "auto" else "review"
        state_file = os.getenv("POST_STATE_FILE") or str(Path(__file__).with_name("post_state.json"))
        rich = os.getenv("POST_RICH", "off").strip().lower() in ("1", "true", "on", "yes")
        poster = Poster(api, PostGenerator(agent.client, agent.model, language, rich=rich),
                        channel, hours * 3600, state_file, log=print, mode=mode,
                        notify=lambda text: api.send_message(int(user_id), text),
                        rich=rich,
                        notify_rich=lambda text: api.send_rich_message(int(user_id), markdown=text))
        if mode == "review":
            print(f"Channel posting: REVIEW mode. Every {hours:g} h a draft is sent to you in Telegram; "
                  f"nothing is published until you send /approve.")
        else:
            print(f"Channel posting: AUTO mode, every {hours:g} h to {channel} ({language}), no review.")
    bot = Bot(api, agent, files, user_id, poll_timeout=poll_timeout, poster=poster)
    print(f"Workspace: {files.root}\nBot is running. Message it on Telegram. Press Ctrl+C to stop.")
    try:
        bot.run_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())