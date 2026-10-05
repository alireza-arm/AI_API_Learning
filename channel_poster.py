"""Scheduled posts to a Telegram channel (e.g. one mechanical-engineering post every 2 hours).

Privacy: posts are written by calling the model directly with a fixed prompt. The agent's
memory and attached files are NEVER included, so nothing personal can end up in a public channel.
"""

import json
import re
import time
from pathlib import Path

from telegram_bot import TelegramError

TOPICS = [
    "statics and equilibrium", "dynamics of particles and rigid bodies", "strength of materials",
    "stress and strain", "beam bending and deflection", "shear and torsion", "fatigue and fracture",
    "material selection", "metals and alloys", "heat treatment of steel", "polymers and composites",
    "thermodynamics basics", "the Carnot cycle and efficiency", "internal combustion engines",
    "refrigeration and heat pumps", "conduction, convection and radiation", "heat exchangers",
    "fluid statics", "Bernoulli's equation", "pipe flow and pressure loss", "pumps and turbines",
    "machine design and gears", "bearings and lubrication", "shafts, keys and couplings",
    "fasteners and bolted joints", "springs", "vibrations and resonance", "control systems basics",
    "manufacturing processes", "machining and CNC", "casting and welding", "3D printing / additive manufacturing",
    "CAD and engineering drawings", "tolerances and fits", "finite element analysis basics",
    "robotics and mechanisms", "HVAC basics", "renewable energy systems", "engineering safety factors",
    "famous engineering failures and lessons",
]
ANGLES = [
    "explain the core idea simply", "a common mistake students make", "a real-world everyday example",
    "a quick way to estimate or sanity-check an answer", "why it matters in industry", "a short practical tip",
]

SYSTEM_PROMPT = """You write short posts for a Telegram channel about mechanical engineering.
Write in {language}. Length: 70 to 120 words.
Structure: a one-line title, then 2 or 3 short paragraphs explaining ONE idea clearly, with a simple real-world example.
Plain text only: no markdown, no links, no hashtags, no emojis.
Be accurate. If you are not sure about a number, a standard or a fact, leave it out. Never invent studies, quotes or standards.
No greeting and no closing question. Output only the post."""

MIN_CHARS, MAX_CHARS = 60, 3500
REFUSAL_RE = re.compile(r"^\s*(sorry|i can't|i cannot|i'm sorry|as an ai)", re.IGNORECASE)


def clean_post(text):
    """Return a publishable post, or None if the model output is unusable."""
    if not text:
        return None
    text = re.sub(r"https?://\S+", "", text)             # models invent links
    text = re.sub(r"(\*\*|__|`)", "", text)               # markdown would show as raw symbols
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) < MIN_CHARS or len(text) > MAX_CHARS or REFUSAL_RE.match(text):
        return None
    return text


def pick(index):
    """Deterministic rotation: every topic once, then again with the next angle."""
    topic = TOPICS[index % len(TOPICS)]
    angle = ANGLES[(index // len(TOPICS)) % len(ANGLES)]
    return topic, angle


class PostGenerator:
    def __init__(self, client, model, language="English", attempts=2):
        self.client, self.model = client, model
        self.language, self.attempts = language, attempts

    def generate(self, topic, angle):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(language=self.language)},
            {"role": "user", "content": f"Topic: {topic}. Angle: {angle}. Choose one specific sub-topic."},
        ]
        for _ in range(self.attempts):
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0.7)
            post = clean_post(response.choices[0].message.content)
            if post:
                return post
        return None


class Poster:
    """Publishes posts to the channel.

    mode="auto":   every `interval` the post is written and published by itself.
    mode="review": every `interval` a draft is sent to the owner (via `notify`) and
                   NOTHING is published until the owner approves it.
    """

    def __init__(self, api, generator, channel_id, interval_seconds, state_path,
                 now=time.time, log=print, retry_seconds=600, mode="auto", notify=None):
        self.api, self.generator, self.channel_id = api, generator, channel_id
        self.interval, self.state_path = interval_seconds, Path(state_path)
        self.now, self.log, self.retry_seconds = now, log, retry_seconds
        self.mode, self.notify = mode, notify
        self.retry_at = 0
        self.state = self._load()
        if "last_post_ts" not in self.state:   # first run: first post/draft after one full interval
            self.state["last_post_ts"] = self.now()
            self._save()

    # ---- state ----
    def _load(self):
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self):
        temp = self.state_path.with_name(self.state_path.name + ".tmp")
        temp.write_text(json.dumps(self.state), encoding="utf-8")
        temp.replace(self.state_path)

    @property
    def paused(self):
        return bool(self.state.get("paused"))

    def set_paused(self, value):
        self.state["paused"] = bool(value)
        self._save()

    @property
    def pending(self):
        """The draft waiting for approval as (text, topic, angle), or None. Survives restarts."""
        item = self.state.get("pending")
        return (item["text"], item["topic"], item["angle"]) if item else None

    @staticmethod
    def draft_message(text, topic):
        return (f"Draft (NOT posted) - topic: {topic}\n\n{text}\n\n"
                "/approve to publish exactly this - /skip to discard - /redraft to rewrite")

    # ---- drafting / posting ----
    def draft(self):
        """Write a new draft and keep it as the pending draft (the old one is kept if this fails)."""
        topic, angle = pick(self.state.get("index", 0))
        post = self.generator.generate(topic, angle)
        if not post:
            return None
        self.state["pending"] = {"text": post, "topic": topic, "angle": angle, "ts": self.now()}
        self._save()
        return post, topic, angle

    def post(self, use_pending=False):
        """Publish one post. With use_pending=True the pending draft is published unchanged.
        Returns the text, or None if no usable draft."""
        draft = self.pending if (use_pending and self.pending) else self.draft()
        if not draft:
            return None
        text, topic, angle = draft
        self.api.send_message(self.channel_id, text)   # may raise TelegramError
        self.state.pop("pending", None)
        self.state["last_post_ts"] = self.now()
        self.state["index"] = self.state.get("index", 0) + 1
        self._save()
        self.log(f"posted to channel (topic: {topic})")
        return text

    def skip(self):
        """Discard the pending draft; the next draft comes after a full interval."""
        if not self.pending:
            return False
        self.state.pop("pending", None)
        self.state["index"] = self.state.get("index", 0) + 1
        self.state["last_post_ts"] = self.now()
        self._save()
        return True

    # ---- scheduling ----
    def due(self):
        return (not self.paused and self.now() >= self.retry_at
                and self.now() - self.state["last_post_ts"] >= self.interval)

    def tick(self):
        """Call often. At most ONE post (auto) or ONE draft (review) per interval,
        and no catch-up spam after downtime."""
        if self.paused or self.now() < self.retry_at:
            return False
        if self.mode == "review":
            return self._tick_review()
        return self._tick_auto()

    def _tick_auto(self):
        if not self.due():
            return False
        try:
            if self.post():
                return True
            self.log("could not generate a usable post, will retry later")
        except TelegramError as exc:
            self.log(f"posting failed: {exc}")
        self.retry_at = self.now() + self.retry_seconds
        return False

    def _tick_review(self):
        item = self.state.get("pending")
        if item:
            if self.now() - item["ts"] < self.interval:
                return False                      # a draft is still waiting for the owner
        elif self.now() - self.state["last_post_ts"] < self.interval:
            return False
        try:
            draft = self.draft()
            if not draft:
                self.log("could not generate a usable draft, will retry later")
                self.retry_at = self.now() + self.retry_seconds
                return False
            self.notify(self.draft_message(draft[0], draft[1]))
        except TelegramError as exc:
            self.log(f"could not send the draft to you: {exc}")
            self.state.pop("pending", None)       # the owner never saw it
            self._save()
            self.retry_at = self.now() + self.retry_seconds
            return False
        self.log("a draft is waiting for your approval (/approve or /skip)")
        return True

    def status(self):
        left = max(0, self.interval - (self.now() - self.state["last_post_ts"]))
        topic, angle = pick(self.state.get("index", 0))
        lines = [f"Channel: {self.channel_id}",
                 f"Mode: {self.mode}" + (" (drafts are sent to you; /approve publishes)" if self.mode == "review" else ""),
                 f"Posting: {'PAUSED' if self.paused else 'on'}",
                 f"Posts so far: {self.state.get('index', 0)}",
                 f"Draft waiting: {'yes' if self.pending else 'no'}",
                 f"Next {'draft' if self.mode == 'review' else 'post'} in about {int(left // 60)} min (topic: {topic})"]
        return "\n".join(lines)