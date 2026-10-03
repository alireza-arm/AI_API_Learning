"""Thin tool layer over long_term_memory.py for the agent.

The LLM sees only six small tools instead of the ~30 functions in
long_term_memory.py. The backend is imported lazily so tests can inject a fake.
"""

MEMORY_TYPES = ("preference", "fact", "goal", "project", "person", "other")
MAX_TEXT_LEN = 500


def _clamp(value, low, high, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _clean_text(value):
    return str(value or "").strip()[:MAX_TEXT_LEN]


def _clean_type(value):
    value = _clean_text(value).lower()
    return value if value in MEMORY_TYPES else "other"


class MemoryTools:
    def __init__(self, backend=None):
        self._backend = backend

    @property
    def backend(self):
        if self._backend is None:
            import long_term_memory
            self._backend = long_term_memory
        return self._backend

    # ---- handlers -------------------------------------------------------

    def remember(self, text, type="other", importance=3):
        text = _clean_text(text)
        if not text:
            return {"ok": False, "error": "text is empty"}
        saved = self.backend.add_memory(
            text,
            memory_type=_clean_type(type),
            importance=_clamp(importance, 1, 5, 3),
            source_text="agent_tool:remember",
        )
        return {"ok": bool(saved),
                "note": "saved" if saved else "not saved (possibly a duplicate)"}

    def recall(self, query, max_results=5):
        query = _clean_text(query)
        if not query:
            return {"ok": False, "error": "query is empty"}
        results = self.backend.search_memory(
            query, max_results=_clamp(max_results, 1, 10, 5))
        return {"ok": True, "results": [
            {"memory": r.get("memory"),
             "type": r.get("type"),
             "importance": r.get("importance"),
             "similarity": r.get("similarity"),
             "valid_from": r.get("valid_from")}
            for r in results]}

    def update(self, old_text, new_text, type="other", importance=3):
        old_text, new_text = _clean_text(old_text), _clean_text(new_text)
        if not old_text or not new_text:
            return {"ok": False, "error": "old_text and new_text are required"}
        done = self.backend.update_memory(
            old_text, new_text,
            memory_type=_clean_type(type),
            importance=_clamp(importance, 1, 5, 3),
            source_text="agent_tool:update",
        )
        return {"ok": bool(done)}

    def end(self, text, reason="no longer true"):
        text = _clean_text(text)
        if not text:
            return {"ok": False, "error": "text is empty"}
        done = self.backend.end_memory(
            text, reason=_clean_text(reason) or "no longer true",
            source_text="agent_tool:end")
        return {"ok": bool(done)}

    def forget(self, text):
        text = _clean_text(text)
        if not text:
            return {"ok": False, "error": "text is empty"}
        done = self.backend.delete_memory(text, source_text="agent_tool:forget")
        return {"ok": bool(done), "note": "archived, can be restored"}

    def list_recent(self, n=10):
        items = self.backend.get_memory()
        items = sorted(items, key=lambda i: i.get("updated_at") or "", reverse=True)
        return {"ok": True, "results": [
            {"memory": i.get("memory"), "type": i.get("type"),
             "importance": i.get("importance")}
            for i in items[:_clamp(n, 1, 30, 10)]]}

    # ---- registration ---------------------------------------------------

    def register_into(self, registry):
        def schema(name, description, properties, required):
            return {"type": "function", "function": {
                "name": name, "description": description,
                "parameters": {"type": "object",
                               "properties": properties, "required": required}}}

        t_text = {"type": "string"}
        t_type = {"type": "string", "enum": list(MEMORY_TYPES)}
        t_imp = {"type": "integer", "minimum": 1, "maximum": 5}

        registry.register(schema(
            "remember",
            "Save a durable fact about the user or their projects. "
            "Search first to avoid duplicates. Never store passwords or API keys.",
            {"text": t_text, "type": t_type, "importance": t_imp}, ["text"]),
            self.remember)
        registry.register(schema(
            "recall", "Search long-term memory by meaning.",
            {"query": t_text, "max_results": {"type": "integer"}}, ["query"]),
            self.recall)
        registry.register(schema(
            "update_memory",
            "Replace an existing memory with a corrected or newer version "
            "(history is preserved).",
            {"old_text": t_text, "new_text": t_text,
             "type": t_type, "importance": t_imp}, ["old_text", "new_text"]),
            self.update)
        registry.register(schema(
            "end_memory", "Mark a memory as no longer true without deleting it.",
            {"text": t_text, "reason": t_text}, ["text"]),
            self.end)
        registry.register(schema(
            "forget", "Archive a memory the user asked to forget.",
            {"text": t_text}, ["text"]),
            self.forget)
        registry.register(schema(
            "list_recent_memories", "List the most recently updated memories.",
            {"n": {"type": "integer"}}, []),
            self.list_recent)
