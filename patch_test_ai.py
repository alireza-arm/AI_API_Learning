"""One-time fix for test_ai.py: answer questions about stored memories even when the
question is not English (the embedding model is English-only).

Run it from the project folder:   py patch_test_ai.py
It keeps a backup copy: test_ai.py.bak
"""

from pathlib import Path

TARGET = Path("test_ai.py")

OLD = """    relevant_memories = search_memory(
        user_input,
        max_results=5,
        threshold=0.35
    )
"""

NEW = """    relevant_memories = search_memory(
        user_input,
        max_results=5,
        threshold=0.20
    )

    # Fallback: the embedding model only understands English, so a question in another
    # language (or a very short one) often matches nothing. Also include the most
    # recent memories so the assistant can still answer.
    seen_ids = {item.get("memory_id") for item in relevant_memories}
    recent_memories = sorted(
        get_memory(),
        key=lambda item: item.get("updated_at") or "",
        reverse=True
    )
    for item in recent_memories[:3]:
        if item.get("memory_id") not in seen_ids:
            relevant_memories.append({**item, "similarity": 0.0})
"""


def main():
    if not TARGET.exists():
        print("test_ai.py was not found. Run this from the project folder.")
        return 1
    source = TARGET.read_text(encoding="utf-8")
    if NEW in source:
        print("Already patched. Nothing to do.")
        return 0
    if source.count(OLD) != 1:
        print("Could not find the expected code in test_ai.py (it may have been edited).")
        print("Nothing was changed. Send me lines 2340-2360 of test_ai.py.")
        return 1
    Path("test_ai.py.bak").write_text(source, encoding="utf-8")
    TARGET.write_text(source.replace(OLD, NEW), encoding="utf-8")
    print("Patched test_ai.py (backup saved as test_ai.py.bak).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())