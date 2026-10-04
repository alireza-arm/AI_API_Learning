"""Telegram front-end for the agent (long polling, only httpx needed).

.env settings:
    TELEGRAM_BOT_TOKEN=...            (from @BotFather - keep it secret)
    TELEGRAM_ALLOWED_USER_ID=123456   (your numeric id from @userinfobot)
    TELEGRAM_PROXY=http://127.0.0.1:10808   (optional)
    TELEGRAM_POLL_TIMEOUT=10          (optional, seconds to wait per poll)

Run:   py telegram_bot.py --check   (tests token + connection, then exits)
       py telegram_bot.py           (starts the bot)
"""

import os
import sys
import time

import httpx

from commands import HELP, handle_command

MAX_MESSAGE = 4000  # Telegram's limit is 4096 characters


class TelegramError(Exception):
    pass


def split_message(text, limit=MAX_MESSAGE):
    text = text or "(empty reply)"
    return [text[i:i + limit] for i in range(0, len(text), limit)]


def make_client(proxy=None, timeout=60.0):
    # trust_env=False: ignore Windows/system proxy settings (they can point to a dead port);
    # only TELEGRAM_PROXY is used.
    # No connection reuse: proxies/VPNs often cut idle keep-alive connections, which shows up
    # as "Server disconnected without sending a response".
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

    def get_updates(self, offset=None, timeout=30):
        params = {"timeout": timeout, "allowed_updates": ["message"]}
        if offset is not None:
            params["offset"] = offset
        return self.call("getUpdates", **params)

    def send_message(self, chat_id, text):
        for chunk in split_message(text):
            self.call("sendMessage", chat_id=chat_id, text=chunk)

    def send_typing(self, chat_id):
        try:
            self.call("sendChatAction", chat_id=chat_id, action="typing")
        except TelegramError:
            pass


class Bot:
    def __init__(self, api, agent, files, allowed_user_id, log=print, sleep=time.sleep,
                 poll_timeout=10):
        self.api, self.agent, self.files = api, agent, files
        self.poll_timeout = poll_timeout  # short on purpose: proxies cut long idle waits
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
        if text.strip() in ("/start", "/help"):
            output = HELP.replace("  /exit          quit", "").strip()
        elif text.strip() == "/exit":
            output = "/exit only works in the terminal."
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
    if "--check" in sys.argv:
        print("Check OK. Run without --check to start the bot.")
        return 0

    from run_agent import build_agent
    agent, files = build_agent(interactive=False)
    poll_timeout = int(os.getenv("TELEGRAM_POLL_TIMEOUT", "10") or 10)
    bot = Bot(api, agent, files, user_id, poll_timeout=poll_timeout)
    print(f"Workspace: {files.root}\nBot is running. Message it on Telegram. Press Ctrl+C to stop.")
    try:
        bot.run_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())