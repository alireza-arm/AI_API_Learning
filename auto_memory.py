"""Automatic memory saving for small local models.

Small models (e.g. llama3.2:3b) are unreliable at tool calling, so instead of letting
the chat model decide when to call `remember`, we run a separate, simple extraction
step on every user message: ask the model for JSON facts, parse them, save them.
"""

import json
import re

EXTRACT_PROMPT = """You extract long-term memory notes from ONE user message.
Save only durable facts about the user: name, studies or job, projects, preferences, goals, important people.
Do NOT save: questions, greetings, small talk, one-off requests, or secrets (passwords, keys, tokens).
Write each fact in English as one short sentence starting with "The user".
Answer with JSON only: {"facts":[{"text":"...","type":"fact","importance":3}]}
type is one of: preference, fact, goal, project, person, other. importance is 1 to 5.
If there is nothing worth saving, answer {"facts":[]}.

Message: Remember that my name is Alireza.
{"facts":[{"text":"The user's name is Alireza.","type":"person","importance":5}]}
Message: what is the capital of France?
{"facts":[]}
Message: I'm building a Telegram bot and I prefer Python.
{"facts":[{"text":"The user is building a Telegram bot.","type":"project","importance":3},{"text":"The user prefers Python.","type":"preference","importance":3}]}
Message: من دانشجوی مکانیک هستم
{"facts":[{"text":"The user is a mechanical engineering student.","type":"fact","importance":4}]}
"""

SECRET_RE = re.compile(r"(password|passwd|api[_ -]?key|secret|token)\s*(is|:|=)|sk-[A-Za-z0-9]{10,}",
                       re.IGNORECASE)
MAX_FACT_LEN = 300


def parse_facts(raw):
    """Turn the model's reply into a clean list of facts. Never raises."""
    if not raw:
        return []
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        data = json.loads(raw[start:end + 1])
    except ValueError:
        return []
    items = data.get("facts") if isinstance(data, dict) else None
    facts = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            item = {"text": item}
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        if not text or len(text) > MAX_FACT_LEN or SECRET_RE.search(text):
            continue
        facts.append({"text": text,
                      "type": item.get("type") or "other",
                      "importance": item.get("importance") or 3})
    return facts


class AutoMemory:
    """Callable used as Agent(before_turn=...). Returns the facts it saved."""

    def __init__(self, client, model, memory_tools, max_facts=3, min_chars=4):
        self.client = client
        self.model = model
        self.memory = memory_tools
        self.max_facts = max_facts
        self.min_chars = min_chars

    def __call__(self, user_text):
        if len(user_text.strip()) < self.min_chars:
            return []
        response = self.client.chat.completions.create(
            model=self.model, temperature=0,
            messages=[{"role": "system", "content": EXTRACT_PROMPT},
                      {"role": "user", "content": f"Message: {user_text}"}])
        saved = []
        for fact in parse_facts(response.choices[0].message.content)[:self.max_facts]:
            result = self.memory.remember(fact["text"], fact["type"], fact["importance"])
            if result.get("ok"):
                saved.append(fact["text"])
        return saved
