import json


# --------------------------------------------------
# Memory Consolidation
# --------------------------------------------------

MAX_MEMORY_COUNT_FOR_PROMPT = 50
MAX_MEMORY_LENGTH = 500


def _clean_memories(memories):
    """
    Clean and normalize memory list before sending it to the model.
    """

    if not isinstance(memories, list):
        return []

    cleaned = []

    for memory in memories:
        if not isinstance(memory, str):
            continue

        memory = memory.strip()

        if not memory:
            continue

        if len(memory) > MAX_MEMORY_LENGTH:
            memory = memory[:MAX_MEMORY_LENGTH].rstrip()

        if memory not in cleaned:
            cleaned.append(memory)

    return cleaned


def consolidate_memories(client, model_name, memories):
    """
    Consolidate related memories into fewer, cleaner memories.

    Rules:
    - Never invent facts.
    - Never add information not present in the input.
    - Merge only genuinely related memories.
    - Keep unrelated memories separate.
    - Preserve important information.
    - Output the same or fewer memories.
    """

    memories = _clean_memories(memories)

    # Nothing to consolidate
    if len(memories) < 2:
        return memories

    # Prevent huge prompts
    memories_for_model = memories[:MAX_MEMORY_COUNT_FOR_PROMPT]

    memory_text = "\n".join(
        f"{index + 1}. {memory}"
        for index, memory in enumerate(memories_for_model)
    )

    prompt = f"""
You are a memory consolidation system.

Your job is to clean and consolidate long-term memories.

IMPORTANT RULES:

1. Use ONLY information already present in the provided memories.
2. NEVER invent new facts.
3. NEVER assume anything that is not explicitly stated.
4. Merge memories only when they clearly describe the same person, fact,
   preference, project, skill, activity, or situation.
5. Keep unrelated memories separate.
6. Remove exact duplicates.
7. Rewrite merged memories into concise, clear statements.
8. Preserve important details.
9. Do not turn several unrelated facts into one sentence.
10. The final number of memories must be equal to or smaller than the
    original number.
11. Return ONLY valid JSON.
12. The JSON must contain exactly this structure:

{{
    "memories": [
        "memory 1",
        "memory 2"
    ]
}}

Current memories:

{memory_text}
"""

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a precise long-term memory "
                        "consolidation system."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )

        content = response.choices[0].message.content

        if not content:
            return memories

        result = json.loads(content)

        new_memories = result.get("memories")

        # Validate model output
        if not isinstance(new_memories, list):
            return memories

        cleaned_new_memories = _clean_memories(new_memories)

        # Never allow the model to create more memories
        if len(cleaned_new_memories) > len(memories):
            return memories

        # Never replace a valid memory set with an empty one
        if not cleaned_new_memories:
            return memories

        return cleaned_new_memories

    except Exception as error:
        print(f"[Consolidation Error] {error}")
        return memories