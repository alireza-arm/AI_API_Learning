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

RICH_SYSTEM_PROMPT = """You write posts for a Telegram channel about mechanical engineering.
The post is written in Rich Markdown, which Telegram renders natively.
Write in {language}. Length: 100 to 250 words.

Structure: start with one "## " heading (the title), then short paragraphs explaining ONE idea clearly, with a simple real-world example.

Use these elements ONLY where they really help the reader. Many posts need just two or three of them:
- Bold (**text**) for key terms; ==text== to highlight the single most important takeaway.
- Lists ("- " for properties, "1. " for ordered steps) instead of long sentences that list things.
- Formulas in LaTeX: inline $...$ and standalone $$...$$ on its own line. Write fractions with \\frac{{a}}{{b}}. Include a formula only if you are sure it is correct.
- A table, only when comparing 2 or more items on the same attributes. Standard pipe table with a header separator row, at most 5 columns and 6 rows, short cells, never the | character inside a cell.
- A quote ("> text") for one rule of thumb or warning. If that note is longer than about three lines, write it as one single paragraph inside <blockquote expandable>...</blockquote> instead.
- Optional deeper explanation as a collapsible block: <details><summary>Short title</summary>, a blank line, the explanation, a blank line, </details>. The main text must make sense without opening it.

Strict rules:
- No links, no images, no hashtags, no emojis. Links are added by the system.
- No other HTML tags except those above (and <sub> / <sup>).
- Do not wrap the whole post in a code block.
- Be accurate. If you are not sure about a number, a standard or a fact, leave it out. Never invent studies, quotes or standards.
- No greeting and no closing question. Output only the post."""

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

ALLOWED_TAGS = {"details", "summary", "blockquote", "sub", "sup", "u"}
MATH_RE = re.compile(r"\$\$.*?\$\$|\$[^$\n]+\$", re.DOTALL)
TAG_RE = re.compile(r"<(/?)([a-zA-Z][\w-]*)([^>]*)>")
SEP_RE = re.compile(r"^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?$")
MAX_RICH_CHARS, MAX_TABLE_COLS = 6000, 6  # Telegram itself allows 32768 chars / 20 columns


def _tables_ok(lines):
    """Every pipe table needs a separator row, equal column counts and few columns."""
    block = []
    for line in lines + [""]:
        if line.strip().startswith("|"):
            block.append(line.strip())
            continue
        if block:
            counts = {len(row.strip("|").split("|")) for row in block}
            if len(block) < 2 or not SEP_RE.match(block[1]) or len(counts) != 1 or max(counts) > MAX_TABLE_COLS:
                return False
            block = []
    return True


def clean_rich_post(text):
    """Return a publishable Rich Markdown post, or None if the model output is unusable."""
    if not text:
        return None
    text = re.sub(r"^```(?:markdown|md)?\s*\n(.*)\n```$", r"\1", text.strip(), flags=re.DOTALL)
    text = re.sub(r"\[([^\]]*)\]\(https?://[^)]*\)", r"\1", text)  # models invent links
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) < MIN_CHARS or len(text) > MAX_RICH_CHARS or REFUSAL_RE.match(text):
        return None
    flat = MATH_RE.sub("M", text)
    if "$" in flat:  # an unclosed formula
        return None
    depth = {}
    for closing, name, _ in TAG_RE.findall(flat):
        name = name.lower()
        if name not in ALLOWED_TAGS:
            return None
        depth[name] = depth.get(name, 0) + (-1 if closing else 1)
    if any(depth.values()):  # unbalanced <details> / <blockquote> ...
        return None
    return text if _tables_ok(text.splitlines()) else None

def pick(index):
    """Deterministic rotation: every topic once, then again with the next angle."""
    topic = TOPICS[index % len(TOPICS)]
    angle = ANGLES[(index // len(TOPICS)) % len(ANGLES)]
    return topic, angle


class PostGenerator:
    def __init__(self, client, model, language="English", attempts=2, rich=False):
        self.client, self.model = client, model
        self.language, self.attempts, self.rich = language, attempts, rich

    def generate(self, topic, angle):
        prompt = RICH_SYSTEM_PROMPT if self.rich else SYSTEM_PROMPT
        clean = clean_rich_post if self.rich else clean_post
        messages = [
            {"role": "system", "content": prompt.format(language=self.language)},
            {"role": "user", "content": f"Topic: {topic}. Angle: {angle}. Choose one specific sub-topic."},
        ]
        for _ in range(self.attempts):
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0.7)
            post = clean(response.choices[0].message.content)
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
                 now=time.time, log=print, retry_seconds=600, mode="auto", notify=None,
                 rich=False, notify_rich=None):
        self.api, self.generator, self.channel_id = api, generator, channel_id
        self.interval, self.state_path = interval_seconds, Path(state_path)
        self.now, self.log, self.retry_seconds = now, log, retry_seconds
        self.mode, self.notify = mode, notify
        self.rich, self.notify_rich = rich, notify_rich
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
    def draft_message(text, topic, rich=False):
        controls = "/approve to publish exactly this - /skip to discard - /redraft to rewrite"
        if rich:  # the post itself was sent just before, as a rich message
            return f"Draft above (NOT posted) - topic: {topic}\n\n{controls}"
        return f"Draft (NOT posted) - topic: {topic}\n\n{text}\n\n{controls}"

    def _publish(self, text):
        footer = '\n\n<blockquote expandable><a href="https://t.me/mechanical_engineering_ai">mechanical_engineering_ai</a></blockquote>'
        full_text = text + footer
        if self.rich:
            self.api.send_rich_message(self.channel_id, markdown=full_text)
        else:
            self.api.send_message(self.channel_id, text)  

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
        self._publish(text)  # may raise TelegramError
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
            if self.rich:
                self.notify_rich(draft[0])
            self.notify(self.draft_message(draft[0], draft[1], rich=self.rich))
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