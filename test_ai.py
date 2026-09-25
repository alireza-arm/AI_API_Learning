import os
import json

from groq import Groq
from dotenv import load_dotenv

from long_term_memory import (
    get_memory,
    add_memory,
    update_memory,
    govern_memory_action,
    delete_memory,
    search_memory,
    save_memory,
    save_embeddings,
    find_similar_memories,
    consolidate_memories,
    get_archived_memory,
    archive_eligible_memories,
    restore_memory,
    search_archived_memory,
    get_memory_chain,
    get_memory_as_of,
    get_memory_provenance,
    end_memory,
    add_causal_relationship,
    get_memory_causality,
    get_memory_graph,
    get_graph_neighbors,
    sync_memory_graph,
    clear_memory_graph,
)


from memory_entities import (
    get_all_entities,
    get_entity,
    search_entities,
    get_entities_for_memory,
    get_entity_history,
    get_entity_as_of,
    evolve_entity,
    link_entities_to_memory,
    clear_entities,
)

from memory_entity_relations import (
    get_all_entity_relations,
    get_entity_relations,
    search_entity_relations,
    upsert_entity_relations,
    clear_entity_relations,
)

from memory_entity_resolution import (
    resolve_entity_identity,
    get_resolution_history,
    clear_resolution_history,
)

# ==================================================
# 1. Load API Key
# ==================================================

load_dotenv()

api_key = os.getenv(
    "GROQ_API_KEY"
)

if not api_key:
    raise ValueError(
        "GROQ_API_KEY was not found."
    )

client = Groq(
    api_key=api_key
)

MODEL_NAME = "openai/gpt-oss-20b"


# ==================================================
# 2. Short-Term Memory
# ==================================================

messages = []


# ==================================================
# 3. Memory Manager
# ==================================================

def analyze_memory(
    user_text,
    existing_memories,
    causal_candidate_memories=None,
):

    existing_text = "\n".join(
        f"- {item['memory']} "
        f"(similarity: {item.get('similarity', 0)})"
        for item in existing_memories
        if isinstance(item, dict)
        and item.get("memory")
    )

    if not existing_text:
        existing_text = (
            "No similar memories found."
        )

    # Causal reasoning needs a broader candidate set than ordinary
    # semantic retrieval. A causal source may be topically related
    # without being one of the closest search hits.
    if causal_candidate_memories is None:
        causal_candidate_memories = existing_memories

    causal_text = "\n".join(
        f"- {item['memory']} "
        f"(similarity: {item.get('similarity', 0)})"
        for item in causal_candidate_memories
        if isinstance(item, dict)
        and item.get("memory")
    )

    if not causal_text:
        causal_text = "No causal candidate memories found."

    prompt = f"""
You are an advanced long-term memory manager.

Your job is to analyze the user's message and
decide how the long-term memory should change.


==================================================
AVAILABLE ACTIONS
==================================================

ADD
UPDATE
END
IGNORE
DELETE


==================================================
ADD
==================================================

Use ADD when the user provides important,
stable information that should be remembered.

Examples:

- Learning something
- Using a software
- Working on a project
- Long-term goals
- Skills
- Stable preferences


==================================================
UPDATE
==================================================

Use UPDATE when a stored memory is no longer
the best representation of the user's current
information.

Example:

Existing:
User is learning Python.

New:
User has now started working professionally
with Python.

Update the old memory instead of creating
another duplicate memory.




==================================================
END
==================================================

Use END when the user explicitly indicates that an
existing fact is no longer true, has stopped, ended,
or ceased to apply.

Examples:

- "I stopped learning Python."
- "I no longer use SolidWorks."
- "My work on project X ended."

IMPORTANT:
END is different from DELETE.
END means the fact was true in the past but is no longer
valid. Preserve it as historical information.
DELETE means the user wants the memory forgotten.

==================================================
IGNORE
==================================================

Use IGNORE for:

- Questions
- Temporary requests
- Greetings
- Casual conversation
- Explanations
- Information already adequately stored


==================================================
DELETE
==================================================

Use DELETE only when the user clearly indicates
that an existing memory is no longer true or
should be forgotten.


==================================================
TEMPORAL INFORMATION
==================================================

When the user explicitly gives a date or time
when the new fact became true, return it as
YYYY-MM-DD in "effective_from".

Examples:

"Since January 2026 I have been learning Python."
=> "effective_from": "2026-01-01"

"I started using Abaqus on 2026-06-15."
=> "effective_from": "2026-06-15"

If no explicit effective date is provided,
return an empty string.

For END, use "effective_to" for the date when
the fact stopped being true.
If the user says it stopped but gives no date,
return an empty string and let the memory engine use
the current timestamp.

Do not invent dates.


==================================================
PROVENANCE
==================================================

Return a short "reason" explaining why the memory decision was made.
Do not invent evidence.

For temporal_event use:
- START for a newly established fact
- CHANGE for a changed version of an existing fact
- END for a fact that stopped being valid
- NONE when no temporal event applies


==================================================
CAUSAL RELATIONSHIPS
==================================================

Return causal_relations only when the user's message
provides explicit evidence of a causal relationship.
Do not infer causality merely because two facts are related
or because one happened after another.

Allowed relations:
- CAUSES
- RESULTS_IN
- REQUIRES
- PREVENTS

Use the exact existing memory text when referencing an
existing memory. Use "__NEW_MEMORY__" for the memory
being created or updated.

Every relation must include a confidence from 0 to 1.
Only return a relation when confidence is at least 0.70.

Example:
Existing memory:
"User started a mechanical engineering project."
New memory:
"User is learning Abaqus."
User says:
"I started learning Abaqus because of my mechanical
engineering project."

Then a valid relation is:
"source_memory": "User started a mechanical engineering project.",
"target_memory": "__NEW_MEMORY__",
"relation": "CAUSES",
"confidence": 0.95,
"evidence": "because of my mechanical engineering project"

If no explicit causal relationship exists, return:
"causal_relations": []



==================================================
IMPORTANT
==================================================

Never create memories that are questions.

Bad:
"What engineering software do I use?"

Good:
"User uses Abaqus for engineering analysis."


==================================================
SIMILAR EXISTING MEMORIES
==================================================

{existing_text}


==================================================
CAUSAL CANDIDATE MEMORIES
==================================================

These memories are provided specifically for causal reasoning.
They may be less semantically similar to the user message than
the normal retrieval results, but they may still be the cause or
effect of the newly stated fact. Use exact text when referencing them.

{causal_text}


==================================================
USER MESSAGE
==================================================

{user_text}


==================================================
RETURN ONLY JSON
==================================================

ADD:

{{
    "action": "ADD",
    "memory": "short factual memory",
    "type": "learning",
    "importance": 5,
    "old_memory": "",
    "effective_from": "",
    "effective_to": "",
    "temporal_event": "START",
    "reason": "brief reason",
    "causal_relations": []
}}

UPDATE:

{{
    "action": "UPDATE",
    "memory": "updated factual memory",
    "type": "learning",
    "importance": 5,
    "old_memory": "old memory",
    "effective_from": "",
    "effective_to": "",
    "temporal_event": "CHANGE",
    "reason": "brief reason",
    "causal_relations": []
}}

END:

{{
    "action": "END",
    "memory": "",
    "type": "",
    "importance": 0,
    "old_memory": "memory to end",
    "effective_from": "",
    "effective_to": "",
    "temporal_event": "END",
    "reason": "brief reason",
    "causal_relations": []
}}

IGNORE:

{{
    "action": "IGNORE",
    "memory": "",
    "type": "",
    "importance": 0,
    "old_memory": "",
    "effective_from": "",
    "effective_to": "",
    "temporal_event": "NONE",
    "reason": "brief reason",
    "causal_relations": []
}}

DELETE:

{{
    "action": "DELETE",
    "memory": "",
    "type": "",
    "importance": 0,
    "old_memory": "memory to delete",
    "effective_from": "",
    "effective_to": "",
    "temporal_event": "NONE",
    "reason": "brief reason"
}}
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": prompt
            }
        ],
        temperature=0
    )

    result = (
        response
        .choices[0]
        .message
        .content
        .strip()
    )

    if result.startswith("```"):
        result = result.replace(
            "```json",
            ""
        )
        result = result.replace(
            "```",
            ""
        )
        result = result.strip()

    try:
        return json.loads(
            result
        )

    except json.JSONDecodeError:
        return {
            "action": "IGNORE",
            "memory": "",
            "type": "",
            "importance": 0,
            "old_memory": "",
            "effective_from": "",
            "effective_to": "",
            "temporal_event": "NONE",
            "reason": "",
            "causal_relations": []
        }


# ==================================================
# 4. Entity / Concept Extraction
# ==================================================

def analyze_entities(user_text, memory_text):
    """Extract durable entities/concepts supported by the user's message."""
    if not isinstance(user_text, str) or not user_text.strip():
        return []

    if not isinstance(memory_text, str) or not memory_text.strip():
        return []

    prompt = f"""
You are a conservative entity extraction system for a long-term memory engine.

Extract only concrete entities or durable concepts that are explicitly supported
by the user's message and are useful for connecting long-term memories.

Good examples:
- Python -> SOFTWARE or TECHNOLOGY
- Abaqus -> SOFTWARE
- SolidWorks -> SOFTWARE
- Project Atlas -> PROJECT
- mechanical engineering -> DOMAIN

Do NOT extract:
- generic words such as 'project', 'software', 'thing', 'problem'
- dates, numbers, actions, temporary states
- facts that are only implied
- entities not supported by the user's message
- the user themselves as an entity

Use only information explicitly present in the user message.

USER MESSAGE:
{user_text}

PROPOSED MEMORY:
{memory_text}

RETURN ONLY JSON:
{{
    "entities": [
        {{
            "name": "canonical entity name",
            "type": "SOFTWARE",
            "aliases": [],
            "description": "short factual description supported by the message",
            "confidence": 0.90
        }}
    ]
}}

If there are no useful entities:
{{"entities": []}}
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": prompt
            }
        ],
        temperature=0
    )

    result = response.choices[0].message.content.strip()

    if result.startswith("```"):
        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        return []

    entities = data.get("entities", []) if isinstance(data, dict) else []
    if not isinstance(entities, list):
        return []

    normalized = []

    for item in entities:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name", "")).strip()
        if not name:
            continue

        entity_type = str(item.get("type", "OTHER")).strip().upper()
        aliases = item.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = []

        aliases = [
            str(alias).strip()
            for alias in aliases
            if str(alias).strip()
        ][:10]

        description = str(item.get("description", "") or "").strip()

        try:
            confidence = float(item.get("confidence", 0.70))
        except (ValueError, TypeError):
            confidence = 0.70

        confidence = max(0.0, min(1.0, confidence))

        if confidence < 0.60:
            continue

        normalized.append({
            "name": name,
            "type": entity_type,
            "aliases": aliases,
            "description": description,
            "confidence": confidence,
        })

    unique = {}
    for item in normalized:
        key = item["name"].casefold()
        existing = unique.get(key)
        if existing is None or item["confidence"] > existing["confidence"]:
            unique[key] = item

    return list(unique.values())


# ==================================================
# 4. Entity Temporal Evolution
# ==================================================

def analyze_entity_evolution(user_text, linked_entities):
    """Detect only explicit temporal changes to already-known entities."""
    if not isinstance(user_text, str) or not user_text.strip():
        return []

    if not isinstance(linked_entities, list) or not linked_entities:
        return []

    entity_lines = []
    for entity in linked_entities:
        if not isinstance(entity, dict):
            continue
        entity_lines.append(
            f"- entity_id={entity.get('entity_id', '')}; "
            f"name={entity.get('name', '')}; "
            f"type={entity.get('type', 'OTHER')}; "
            f"version={entity.get('version', 1)}; "
            f"valid_from={entity.get('valid_from', '')}; "
            f"temporal_status={entity.get('temporal_status', 'current')}; "
            f"description={entity.get('description', '')}"
        )

    if not entity_lines:
        return []

    prompt = f"""
You are a conservative temporal entity reasoning system.

Determine whether the user's message explicitly says that one of the known entities
has changed over time or has ended. Do NOT treat a normal mention as an evolution.
Do NOT infer change from context alone.

Allowed events:
- CHANGE: the identity/description/type/name/aliases of an existing entity explicitly changed.
- END: the entity or the user's involvement with that entity explicitly ended.
- NONE: no explicit temporal entity change.

A temporal change should be returned only when the message contains explicit evidence such as:
- "X is now called Y"
- "X was renamed to Y"
- "Since 2026-06-01, X is ..."
- "X changed from ... to ..."
- "I stopped working with X"

For CHANGE you may return only fields directly supported by the message.
For END, use effective_to when an explicit end date is stated.
Never invent a date.

KNOWN ENTITIES:
{chr(10).join(entity_lines)}

USER MESSAGE:
{user_text}

RETURN ONLY JSON:
{{
  "evolutions": [
    {{
      "entity_id": "exact known entity_id",
      "event": "CHANGE",
      "effective_from": "YYYY-MM-DD or ISO timestamp or empty",
      "effective_to": "YYYY-MM-DD or ISO timestamp or empty",
      "new_name": "only if explicitly renamed",
      "new_type": "only if explicitly changed",
      "new_description": "only if explicitly changed",
      "aliases_add": [],
      "reason": "brief evidence-based reason"
    }}
  ]
}}

If there is no explicit evolution:
{{"evolutions": []}}
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": prompt}],
            temperature=0,
        )
        result = response.choices[0].message.content.strip()
    except Exception:
        return []

    if result.startswith("```"):
        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        return []

    evolutions = data.get("evolutions", []) if isinstance(data, dict) else []
    if not isinstance(evolutions, list):
        return []

    known_ids = {
        str(entity.get("entity_id", "")).strip()
        for entity in linked_entities
        if isinstance(entity, dict) and entity.get("entity_id")
    }

    normalized = []
    for item in evolutions:
        if not isinstance(item, dict):
            continue

        entity_id = str(item.get("entity_id", "")).strip()
        event = str(item.get("event", "NONE")).strip().upper()
        if entity_id not in known_ids or event not in {"CHANGE", "END"}:
            continue

        normalized.append({
            "entity_id": entity_id,
            "event": event,
            "effective_from": str(item.get("effective_from", "") or "").strip(),
            "effective_to": str(item.get("effective_to", "") or "").strip(),
            "new_name": str(item.get("new_name", "") or "").strip(),
            "new_type": str(item.get("new_type", "") or "").strip(),
            "new_description": str(item.get("new_description", "") or "").strip(),
            "aliases_add": [
                str(alias).strip()
                for alias in (item.get("aliases_add", []) if isinstance(item.get("aliases_add", []), list) else [])
                if str(alias).strip()
            ][:10],
            "reason": str(item.get("reason", "") or "").strip()[:500],
        })

    return normalized


# ==================================================
# 4. Memory Conflict Decision
# ==================================================

def analyze_conflict(
    new_memory,
    candidate_memories
):

    candidate_text = "\n".join(
        f"- {item['memory']} "
        f"(similarity: {item.get('similarity', 0)})"
        for item in candidate_memories
        if isinstance(item, dict) and item.get("memory")
    )

    if not candidate_text:
        return {
            "conflict": False,
            "old_memory": ""
        }

    prompt = f"""
You are a memory conflict detection system.

Determine whether the new memory contradicts an
existing memory or makes it outdated.

A conflict means the same fact has changed, for example:
- User is learning Python.
- User stopped learning Python and is now learning C++.

Do NOT mark these as conflicts:
- Two different facts about the same topic.
- A more detailed version that remains compatible.
- Similar statements that can both be true.

Rules:
1. Only use the supplied information.
2. Do not invent facts.
3. If several candidates conflict, select the single
   old memory that is actually contradicted.
4. Be conservative: uncertainty means no conflict.

NEW MEMORY:
{new_memory}

EXISTING CANDIDATES:
{candidate_text}

RETURN ONLY JSON:
{{
    "conflict": true,
    "old_memory": "exact old memory"
}}

OR:
{{
    "conflict": false,
    "old_memory": ""
}}
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": prompt
            }
        ],
        temperature=0
    )

    result = response.choices[0].message.content.strip()

    if result.startswith("```"):
        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        return {
            "conflict": False,
            "old_memory": ""
        }

    return {
        "conflict": bool(data.get("conflict", False)),
        "old_memory": str(data.get("old_memory", "")).strip()
    }


# ==================================================
# 5. Memory Consolidation Decision
# ==================================================

def analyze_consolidation(
    proposed_memory,
    similar_memories
):

    existing_text = "\n".join(
        f"- {item['memory']} "
        f"(similarity: {item.get('similarity', 0)})"
        for item in similar_memories
        if isinstance(item, dict)
        and item.get("memory")
    )

    if not existing_text:
        existing_text = (
            "No similar memories found."
        )

    prompt = f"""
You are a long-term memory consolidation system.

A new memory has been proposed and some existing
memories are semantically similar.

Your job is to decide whether these memories
represent the same underlying fact or should
remain separate.


==================================================
RULES
==================================================

1. CONSOLIDATE only if the memories clearly
   represent the same underlying information.

2. Keep memories separate if they describe
   different facts.

3. Never invent information.

4. The consolidated memory must contain only
   information supported by the provided memories.

5. Prefer one concise factual memory over
   several repetitive memories.

6. Preserve important information.

7. Never turn uncertainty into certainty.


==================================================
PROPOSED MEMORY
==================================================

{proposed_memory}


==================================================
SIMILAR EXISTING MEMORIES
==================================================

{existing_text}


==================================================
RETURN ONLY JSON
==================================================

If they should be consolidated:

{{
    "consolidate": true,
    "memory": "one concise factual memory",
    "type": "learning",
    "importance": 5
}}

If they should remain separate:

{{
    "consolidate": false,
    "memory": "",
    "type": "",
    "importance": 0
}}
"""

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": prompt
            }
        ],
        temperature=0
    )

    result = (
        response
        .choices[0]
        .message
        .content
        .strip()
    )

    if result.startswith("```"):
        result = result.replace(
            "```json",
            ""
        )
        result = result.replace(
            "```",
            ""
        )
        result = result.strip()

    try:
        return json.loads(
            result
        )

    except json.JSONDecodeError:
        return {
            "consolidate": False,
            "memory": "",
            "type": "",
            "importance": 0
        }


# ==================================================
# 6. Show Archived Memory
# ==================================================

def show_archived_memory():

    archive = get_archived_memory()

    print("\n")
    print("=" * 65)
    print("ARCHIVED MEMORY")
    print("=" * 65)

    if not archive:
        print("\nArchive is empty.")
        print("=" * 65)
        return

    for index, item in enumerate(archive, start=1):
        if not isinstance(item, dict):
            continue

        print(f"\n[{index}]")
        print(f"Memory: {item.get('memory', '')}")
        print(f"Type: {item.get('type', 'other')}")
        print(f"Importance: {item.get('importance', 0)}/5")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Access count: {item.get('access_count', 0)}")
        print(f"Version: {item.get('version', 1)}")
        print(f"Temporal status: {item.get('temporal_status', 'historical')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Archived at: {item.get('archived_at', '')}")
        print(f"Reason: {item.get('archive_reason', '')}")

    print("\n" + "=" * 65)


# ==================================================
# 7. Show Memory
# ==================================================

def show_memory():

    memory = get_memory()

    print("\n")
    print("=" * 65)
    print("LONG-TERM MEMORY")
    print("=" * 65)

    if not memory:
        print("\nMemory is empty.")
        print("=" * 65)
        return

    for index, item in enumerate(
        memory,
        start=1
    ):

        if not isinstance(item, dict):
            continue

        print(f"\n[{index}]")
        print(f"Memory: {item.get('memory', '')}")
        print(f"Type: {item.get('type', 'other')}")
        print(f"Importance: {item.get('importance', 0)}/5")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Access count: {item.get('access_count', 0)}")
        print(f"Version: {item.get('version', 1)}")
        print(f"Temporal status: {item.get('temporal_status', 'current')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Lifecycle: {item.get('status', 'active')}")
        print(f"Causal links: {len(item.get('causal_links', []))}")

    print("\n" + "=" * 65)


# ==================================================
# 8. Show Memory History
# ==================================================

def show_memory_history(query):

    if not query.strip():
        print("\nUsage: /history <memory text>")
        return

    history = get_memory_chain(
        memory_text=query.strip()
    )

    print("\n")
    print("=" * 65)
    print("MEMORY HISTORY")
    print("=" * 65)

    if not history:
        print("\nNo temporal history found.")
        print("=" * 65)
        return

    for index, item in enumerate(history, start=1):
        print(f"\n[{index}]")
        print(f"Version: {item.get('version', 1)}")
        print(f"Memory: {item.get('memory', '')}")
        print(f"Type: {item.get('type', 'other')}")
        print(f"Importance: {item.get('importance', 0)}/5")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Temporal status: {item.get('temporal_status', 'current')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Lifecycle status: {item.get('status', '')}")
        print(f"Supersedes: {item.get('supersedes') or '-'}")
        print(f"Superseded by: {item.get('superseded_by') or '-'}")

    print("\n" + "=" * 65)


# ==================================================
# 9. Temporal Point-in-Time Query
# ==================================================

def show_memory_as_of(argument):

    parts = argument.strip().split(maxsplit=1)

    if len(parts) != 2:
        print("\nUsage: /at <YYYY-MM-DD> <exact memory text>")
        return

    date_text = parts[0].strip()
    query = parts[1].strip()

    if len(date_text) == 10:
        date_text = date_text + "T00:00:00+00:00"

    result = get_memory_as_of(
        query,
        date_text,
    )

    print("\n")
    print("=" * 65)
    print("MEMORY AS OF DATE")
    print("=" * 65)
    print(f"\nDate: {date_text}")
    print(f"Query: {query}")

    if not result:
        print("\nNo version of this memory was valid at that time.")
        print("=" * 65)
        return

    print("\nValid version:")
    print(f"Version: {result.get('version', 1)}")
    print(f"Memory: {result.get('memory', '')}")
    print(f"Type: {result.get('type', 'other')}")
    print(f"Importance: {result.get('importance', 0)}/5")
    print(f"Confidence: {result.get('confidence', 0.0):.2f}")
    print(f"Valid from: {result.get('valid_from', '')}")
    print(f"Valid to: {result.get('valid_to', '') or '-'}")
    print(f"Temporal status: {result.get('temporal_status', '')}")
    print(f"Chain ID: {result.get('chain_id', '')}")

    print("\n" + "=" * 65)


# ==================================================
# 9. Memory Provenance Command
# ==================================================

def show_memory_provenance(query):

    if not query.strip():
        print("\nUsage: /provenance <memory text>")
        return

    provenance = get_memory_provenance(
        memory_text=query.strip()
    )

    print("\n")
    print("=" * 65)
    print("MEMORY PROVENANCE")
    print("=" * 65)

    if not provenance:
        print("\nNo provenance information found.")
        print("=" * 65)
        return

    for index, entry in enumerate(provenance, start=1):
        print(f"\n[{index}]")
        print(f"Timestamp: {entry.get('timestamp', '')}")
        print(f"Action: {entry.get('action', 'UNKNOWN')}")
        print(f"Temporal event: {entry.get('event', 'NONE')}")
        print(f"Reason: {entry.get('reason', '') or '-'}")
        print(f"Source: {entry.get('source_text', '') or '-'}")

        related = entry.get("related_memory_ids") or []
        print(
            "Related memory IDs: "
            + (", ".join(related) if related else "-")
        )

    print("\n" + "=" * 65)


# ==================================================
# 10. Causal Memory Command
# ==================================================

def show_memory_causality(query):

    if not query.strip():
        print("\nUsage: /causal <memory text>")
        return

    results = get_memory_causality(
        memory_text=query.strip(),
        direction="both",
    )

    print("\n")
    print("=" * 65)
    print("MEMORY CAUSAL RELATIONSHIPS")
    print("=" * 65)

    if not results:
        print("\nNo explicit causal relationships found.")
        print("=" * 65)
        return

    for index, item in enumerate(results, start=1):
        print(f"\n[{index}]")
        print(f"Direction: {item.get('direction', '')}")
        print(f"Relation: {item.get('relation', '')}")
        print(f"Source: {item.get('source_memory', '')}")
        print(f"Target: {item.get('target_memory', '')}")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Evidence: {item.get('evidence', '') or '-'}")
        print(f"Timestamp: {item.get('timestamp', '')}")
        print(f"Source status: {item.get('target_status', '') or '-'}")

    print("\n" + "=" * 65)



# ==================================================
# 10. Memory Graph Command
# ==================================================

def show_memory_graph(query=""):

    query = query.strip()

    graph = get_memory_graph(
        memory_text=query if query else None,
        max_nodes=50,
    )

    print("\n")
    print("=" * 65)
    print("MEMORY GRAPH")
    print("=" * 65)

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not nodes:
        print("\nMemory graph is empty.")
        print("=" * 65)
        return

    print(f"\nNodes: {len(nodes)}")
    print(f"Edges: {len(edges)}")

    for index, node in enumerate(nodes, start=1):
        print(f"\n[{index}]")
        print(f"ID: {node.get('id', '')}")
        print(f"Kind: {node.get('kind', 'memory')}")

        if node.get('kind') == 'entity':
            print(f"Entity: {node.get('name', '')}")
            print(f"Type: {node.get('type', 'OTHER')}")
            print(f"Confidence: {node.get('confidence', 0.0):.2f}")
            print(f"Mentions: {node.get('mention_count', 0)}")
        else:
            print(f"Memory: {node.get('memory', '')}")
            print(f"Type: {node.get('type', 'other')}")
            print(f"Version: {node.get('version', 1)}")
            print(f"Status: {node.get('status', '')}")
            print(f"Temporal: {node.get('temporal_status', '')}")

    if edges:
        print("\nRELATIONSHIPS")
        for index, edge in enumerate(edges, start=1):
            print(f"\n[{index}]")
            print(f"Type: {edge.get('type', '')}")
            print(f"Relation: {edge.get('relation', '') or '-'}")
            print(f"Source: {edge.get('source', '')}")
            print(f"Target: {edge.get('target', '')}")
            print(f"Confidence: {edge.get('confidence', 0.0):.2f}")
            print(f"Evidence: {edge.get('evidence', '') or '-'}")

    print("\n" + "=" * 65)


def show_related_memories(query):

    if not query.strip():
        print("\nUsage: /related <memory text>")
        return

    results = get_graph_neighbors(
        memory_text=query.strip(),
        direction="both",
        max_results=20,
    )

    print("\n")
    print("=" * 65)
    print("RELATED MEMORIES")
    print("=" * 65)

    if not results:
        print("\nNo graph relationships found.")
        print("=" * 65)
        return

    for index, item in enumerate(results, start=1):
        print(f"\n[{index}]")
        print(f"Direction: {item.get('direction', '')}")
        print(f"Relation: {item.get('relation', '')}")
        print(f"Edge type: {item.get('edge_type', '')}")
        if item.get('kind') == 'entity':
            print(f"Entity: {item.get('name', '')}")
            print(f"Entity type: {item.get('entity_type', 'OTHER')}")
        else:
            print(f"Memory: {item.get('memory', '')}")
            print(f"Status: {item.get('status', '')}")
            print(f"Version: {item.get('version', 1)}")

        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Evidence: {item.get('evidence', '') or '-'}")

    print("\n" + "=" * 65)


# ==================================================
# 10. Entity Commands
# ==================================================

def show_entities():
    entities = get_all_entities()

    print("\n")
    print("=" * 65)
    print("MEMORY ENTITIES / CONCEPTS")
    print("=" * 65)

    if not entities:
        print("\nEntity store is empty.")
        print("=" * 65)
        return

    print(f"\nEntities: {len(entities)}")

    for index, entity in enumerate(entities, start=1):
        print(f"\n[{index}]")
        print(f"ID: {entity.get('entity_id', '')}")
        print(f"Name: {entity.get('name', '')}")
        print(f"Type: {entity.get('type', 'OTHER')}")
        print(f"Confidence: {entity.get('confidence', 0.0):.2f}")
        print(f"Version: {entity.get('version', 1)}")
        print(f"Temporal status: {entity.get('temporal_status', 'current')}")
        print(f"Valid from: {entity.get('valid_from', '')}")
        print(f"Valid to: {entity.get('valid_to', '') or '-'}")
        print(f"History versions: {len(entity.get('history', []))}")
        print(f"Mentions: {entity.get('mention_count', 0)}")
        print(f"Aliases: {', '.join(entity.get('aliases', [])) or '-'}")
        print(f"Identity links: {entity.get('identity_resolution_count', 0)}")
        print(f"Last resolution: {entity.get('identity_resolution_method', '') or '-'}")
        print(f"Resolution score: {entity.get('identity_resolution_score', 0.0):.2f}")
        print(f"Memories linked: {len(entity.get('memory_ids', []))}")
        print(f"Description: {entity.get('description', '') or '-'}")

    print("\n" + "=" * 65)


def show_entity_command(query):
    if not query.strip():
        print("\nUsage: /entity <name>")
        return

    entity = get_entity(query.strip())

    print("\n")
    print("=" * 65)
    print("ENTITY DETAILS")
    print("=" * 65)

    if entity is None:
        print("\nEntity not found or query was ambiguous.")
        print("=" * 65)
        return

    print(f"\nID: {entity.get('entity_id', '')}")
    print(f"Name: {entity.get('name', '')}")
    print(f"Type: {entity.get('type', 'OTHER')}")
    print(f"Confidence: {entity.get('confidence', 0.0):.2f}")
    print(f"Version: {entity.get('version', 1)}")
    print(f"Temporal status: {entity.get('temporal_status', 'current')}")
    print(f"Valid from: {entity.get('valid_from', '')}")
    print(f"Valid to: {entity.get('valid_to', '') or '-'}")
    print(f"History versions: {len(entity.get('history', []))}")
    print(f"Mentions: {entity.get('mention_count', 0)}")
    print(f"Aliases: {', '.join(entity.get('aliases', [])) or '-'}")
    print(f"Identity links: {entity.get('identity_resolution_count', 0)}")
    print(f"Last resolution: {entity.get('identity_resolution_method', '') or '-'}")
    print(f"Resolution score: {entity.get('identity_resolution_score', 0.0):.2f}")
    print(f"Description: {entity.get('description', '') or '-'}")

    memory_ids = entity.get("memory_ids", [])
    memories_by_id = {}
    for item in get_memory() + get_archived_memory():
        memory_id = item.get("memory_id")
        if memory_id:
            memories_by_id[memory_id] = item

    print("\nLinked memories:")

    if not memory_ids:
        print("- None")
    else:
        for memory_id in memory_ids:
            item = memories_by_id.get(memory_id)
            if item is None:
                continue
            print(
                f"- [{item.get('status', 'unknown')}] "
                f"v{item.get('version', 1)}: {item.get('memory', '')}"
            )

    print("\n" + "=" * 65)


def show_entity_history_command(query):
    if not query.strip():
        print("\nUsage: /entity_history <entity name>")
        return

    history = get_entity_history(query.strip(), include_current=True)

    print("\n")
    print("=" * 65)
    print("ENTITY TEMPORAL HISTORY")
    print("=" * 65)

    if not history:
        print("\nNo entity temporal history found.")
        print("=" * 65)
        return

    for index, item in enumerate(history, start=1):
        print(f"\n[{index}]")
        print(f"Version: {item.get('version', 1)}")
        print(f"Name: {item.get('name', '')}")
        print(f"Type: {item.get('type', 'OTHER')}")
        print(f"Temporal status: {item.get('temporal_status', '')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Event: {item.get('event', '')}")
        print(f"Reason: {item.get('reason', '') or '-'}")
        print(f"Source: {item.get('source_text', '') or '-'}")

    print("\n" + "=" * 65)


def show_entity_as_of_command(argument):
    parts = argument.strip().split(maxsplit=1)
    if len(parts) < 2:
        print("\nUsage: /entity_at <YYYY-MM-DD> <entity name>")
        return

    target_time, query = parts
    result = get_entity_as_of(query, target_time)

    print("\n")
    print("=" * 65)
    print(f"ENTITY STATE AT: {target_time}")
    print("=" * 65)

    if result is None:
        print("\nNo entity state found for that date.")
        print("=" * 65)
        return

    print(f"\nEntity: {result.get('name', '')}")
    print(f"Type: {result.get('type', 'OTHER')}")
    print(f"Version: {result.get('version', 1)}")
    print(f"Temporal status: {result.get('temporal_status', '')}")
    print(f"Valid from: {result.get('valid_from', '')}")
    print(f"Valid to: {result.get('valid_to', '') or '-'}")
    print(f"Description: {result.get('description', '') or '-'}")

    print("\n" + "=" * 65)


def show_entity_resolve_command(query):
    if not query.strip():
        print("\nUsage: /entity_resolve <name>")
        return

    entities = get_all_entities()
    result = resolve_entity_identity(query.strip(), entities, "OTHER")

    print("\n")
    print("=" * 65)
    print("ENTITY IDENTITY RESOLUTION")
    print("=" * 65)
    print(f"\nQuery: {query.strip()}")
    print(f"Matched: {result.get('matched', False)}")
    print(f"Needs review: {result.get('needs_review', False)}")
    print(f"Ambiguous: {result.get('ambiguity', False)}")
    print(f"Score: {result.get('score', 0.0):.2f}")
    print(f"Method: {result.get('method', '') or '-'}")
    print(f"Matched name: {result.get('matched_name', '') or '-'}")

    alternatives = result.get("alternatives", [])
    if alternatives:
        print("\nCandidates:")
        for index, item in enumerate(alternatives, start=1):
            print(
                f"{index}. {item.get('entity_name', '')} "
                f"[{item.get('score', 0.0):.2f}] "
                f"{item.get('method', '')}"
            )

    print("\n" + "=" * 65)


def show_identity_history_command(query):
    records = get_resolution_history(query.strip(), max_results=50)

    print("\n")
    print("=" * 65)
    print("ENTITY IDENTITY RESOLUTION HISTORY")
    print("=" * 65)

    if not records:
        print("\nNo identity resolution records found.")
        print("=" * 65)
        return

    for index, item in enumerate(records, start=1):
        print(f"\n[{index}]")
        print(f"Candidate: {item.get('candidate_name', '')}")
        print(f"Resolved entity: {item.get('entity_name', '')}")
        print(f"Entity ID: {item.get('entity_id', '')}")
        print(f"Score: {item.get('score', 0.0):.2f}")
        print(f"Method: {item.get('method', '')}")
        print(f"Action: {item.get('action', '')}")
        print(f"Memory ID: {item.get('memory_id', '') or '-'}")
        print(f"Timestamp: {item.get('timestamp', '')}")

    print("=" * 65)


def search_entity_command(query):
    if not query.strip():
        print("\nUsage: /entity_search <text>")
        return

    results = search_entities(query, max_results=10)

    print("\n")
    print("=" * 65)
    print("ENTITY SEARCH")
    print("=" * 65)

    if not results:
        print("\nNo matching entities found.")
        print("=" * 65)
        return

    for index, entity in enumerate(results, start=1):
        print(f"\n[{index}]")
        print(f"Name: {entity.get('name', '')}")
        print(f"Type: {entity.get('type', 'OTHER')}")
        print(f"Search score: {entity.get('search_score', 0.0):.2f}")
        print(f"Confidence: {entity.get('confidence', 0.0):.2f}")
        print(f"Memories linked: {len(entity.get('memory_ids', []))}")

    print("\n" + "=" * 65)


# ==================================================
# 5. Entity Relation Reasoning
# ==================================================

def analyze_entity_relations(user_text, linked_entities):
    """Extract only explicit, durable relationships between known entities."""
    if not isinstance(user_text, str) or not user_text.strip():
        return []

    if not isinstance(linked_entities, list) or len(linked_entities) < 2:
        return []

    names = []
    for entity in linked_entities:
        if not isinstance(entity, dict):
            continue
        name = str(entity.get("name", "")).strip()
        if name and name not in names:
            names.append(name)

    if len(names) < 2:
        return []

    entity_text = "\n".join(f"- {name}" for name in names)

    prompt = f"""
You are a conservative entity-relation reasoning system for a long-term memory engine.

Identify relationships between the known entities below ONLY when the user's message
provides explicit or strongly supported evidence for that relationship. Do not infer
relationships merely because two entities appear in the same sentence.

Allowed relations:
- RELATED_TO
- USED_FOR
- WORKS_WITH
- PART_OF
- REQUIRES
- DEPENDS_ON
- LEADS_TO
- SUPPORTS
- LEARNS
- BUILDS
- APPLIES_TO

For directional relations, source is the entity that performs/has the relation and
target is the entity it points to. RELATED_TO and WORKS_WITH may be treated as
undirected.

KNOWN ENTITIES:
{entity_text}

USER MESSAGE:
{user_text}

Return only JSON:
{{
    "relations": [
        {{
            "source": "entity name",
            "target": "entity name",
            "relation": "USED_FOR",
            "confidence": 0.90,
            "evidence": "short evidence from the user's message"
        }}
    ]
}}

If there is no explicit supported relationship:
{{"relations": []}}
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": prompt
                }
            ],
            temperature=0,
        )
        result = response.choices[0].message.content.strip()
    except Exception:
        return []

    if result.startswith("```"):
        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        return []

    relations = data.get("relations", []) if isinstance(data, dict) else []
    if not isinstance(relations, list):
        return []

    normalized = []
    allowed = {
        "RELATED_TO", "USED_FOR", "WORKS_WITH", "PART_OF",
        "REQUIRES", "DEPENDS_ON", "LEADS_TO", "SUPPORTS",
        "LEARNS", "BUILDS", "APPLIES_TO",
    }
    known_keys = {name.casefold(): name for name in names}

    for item in relations:
        if not isinstance(item, dict):
            continue

        source = str(item.get("source", "")).strip()
        target = str(item.get("target", "")).strip()
        relation = str(item.get("relation", "")).strip().upper().replace("-", "_").replace(" ", "_")

        source = known_keys.get(source.casefold(), "")
        target = known_keys.get(target.casefold(), "")
        if not source or not target or source == target or relation not in allowed:
            continue

        try:
            confidence = float(item.get("confidence", 0.70))
        except (ValueError, TypeError):
            confidence = 0.70

        confidence = max(0.0, min(1.0, confidence))
        if confidence < 0.65:
            continue

        evidence = str(item.get("evidence", "") or "").strip()[:500]
        normalized.append({
            "source": source,
            "target": target,
            "relation": relation,
            "confidence": confidence,
            "evidence": evidence or user_text[:500],
        })

    return normalized


# ==================================================
# 10. Entity Relation Commands
# ==================================================

def show_entity_relations():
    relations = get_all_entity_relations()

    print("\n")
    print("=" * 65)
    print("ENTITY RELATIONS")
    print("=" * 65)

    if not relations:
        print("\nNo entity relations found.")
        print("=" * 65)
        return

    entity_map = {
        item.get("entity_id"): item.get("name", item.get("entity_id", ""))
        for item in get_all_entities()
    }

    print(f"\nRelations: {len(relations)}")
    for index, item in enumerate(relations, start=1):
        print(f"\n[{index}]")
        print(f"Source: {entity_map.get(item.get('source_entity_id'), item.get('source_entity_id', ''))}")
        print(f"Relation: {item.get('relation', '')}")
        print(f"Target: {entity_map.get(item.get('target_entity_id'), item.get('target_entity_id', ''))}")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Evidence: {item.get('evidence', '') or '-'}")
        print(f"Memories: {len(item.get('memory_ids', []))}")

    print("\n" + "=" * 65)


def show_entity_relation_command(query):
    if not query.strip():
        print("\nUsage: /relation <entity>")
        return

    results = get_entity_relations(query)

    print("\n")
    print("=" * 65)
    print(f"RELATIONS FOR: {query}")
    print("=" * 65)

    if not results:
        print("\nNo relations found.")
        print("=" * 65)
        return

    for index, item in enumerate(results, start=1):
        direction = item.get("direction", "outgoing")
        print(f"\n[{index}] {direction}")
        print(f"Source: {item.get('source_name', '')}")
        print(f"Relation: {item.get('relation', '')}")
        print(f"Target: {item.get('target_name', '')}")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Evidence: {item.get('evidence', '') or '-'}")

    print("\n" + "=" * 65)


def search_entity_relation_command(query):
    if not query.strip():
        print("\nUsage: /relation_search <text>")
        return

    results = search_entity_relations(query, max_results=20)

    print("\n")
    print("=" * 65)
    print("ENTITY RELATION SEARCH")
    print("=" * 65)

    if not results:
        print("\nNo matching relations found.")
        print("=" * 65)
        return

    for index, item in enumerate(results, start=1):
        print(f"\n[{index}]")
        print(f"{item.get('source_name', '')} --{item.get('relation', '')}--> {item.get('target_name', '')}")
        print(f"Confidence: {item.get('confidence', 0.0):.2f}")
        print(f"Evidence: {item.get('evidence', '') or '-'}")

    print("\n" + "=" * 65)


# ==================================================
# 10. Search Archived Memory Command
# ==================================================

def search_archived_memory_command(query):

    if not query.strip():
        print("\nUsage: /search_archive <text>")
        return

    results = search_archived_memory(
        query,
        max_results=10,
        threshold=0.30
    )

    print("\n")
    print("=" * 65)
    print("ARCHIVED MEMORY SEARCH")
    print("=" * 65)

    if not results:
        print("\nNo relevant archived memories found.")
        print("=" * 65)
        return

    for index, item in enumerate(results, start=1):
        print(f"\n[{index}]")
        print(f"Memory: {item['memory']}")
        print(f"Type: {item['type']}")
        print(f"Importance: {item['importance']}/5")
        print(f"Confidence: {item.get('confidence', 0.0)}")
        print(f"Similarity: {item['similarity']}")
        print(f"Version: {item.get('version', 1)}")
        print(f"Temporal status: {item.get('temporal_status', 'historical')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Archived at: {item['archived_at']}")
        print(f"Reason: {item['archive_reason']}")

    print("\n" + "=" * 65)


# ==================================================
# 10. Restore Command
# ==================================================

def restore_memory_command(query):

    if not query.strip():
        print("\nUsage: /restore <exact memory text>")
        return

    if restore_memory(query.strip()):
        print("\n[Archive] Memory restored successfully.")
    else:
        print("\n[Archive] Memory not found in archive.")


# ==================================================
# 11. Search Memory Command
# ==================================================

def search_memory_command(query):

    if not query.strip():
        print("\nUsage: /search <text>")
        return

    results = search_memory(
        query,
        max_results=10,
        threshold=0.30
    )

    print("\n")
    print("=" * 65)
    print("MEMORY SEARCH")
    print("=" * 65)

    if not results:
        print("\nNo relevant memories found.")
        print("=" * 65)
        return

    for index, item in enumerate(
        results,
        start=1
    ):

        print(f"\n[{index}]")
        print(f"Memory: {item['memory']}")
        print(f"Type: {item['type']}")
        print(f"Importance: {item['importance']}/5")
        print(f"Similarity: {item['similarity']}")
        print(f"Final Score: {item['score']}")
        print(f"Confidence: {item.get('confidence', 0.0)}")
        print(f"Version: {item.get('version', 1)}")
        print(f"Temporal status: {item.get('temporal_status', 'current')}")
        print(f"Valid from: {item.get('valid_from', '')}")
        print(f"Valid to: {item.get('valid_to', '') or '-'}")
        print(f"Access count: {item.get('access_count', 0)}")

    print("\n" + "=" * 65)


# ==================================================
# 12. Clear Memory
# ==================================================

def clear_memory():

    memory = get_memory()
    archived = get_archived_memory()
    entities = get_all_entities()

    if not memory and not archived and not entities:
        print("\nMemory system is already empty.")
        return

    confirmation = input(
        "\nDelete ALL long-term memory? (yes/no): "
    )

    if confirmation.lower().strip() != "yes":
        print("\nMemory was not deleted.")
        return

    save_memory([])

    from long_term_memory import save_archived_memory

    save_archived_memory([])
    save_embeddings({})
    clear_memory_graph()
    clear_entities()
    clear_entity_relations()
    clear_resolution_history()

    print("\nAll long-term memory deleted.")


# ==================================================
# 13. Help
# ==================================================

def show_help():

    print("\n")
    print("=" * 65)
    print("AVAILABLE COMMANDS")
    print("=" * 65)

    print(
        "\n/memory"
        "\n  Show all active long-term memories."
    )

    print(
        "\n/entities"
        "\n  Show all known entities and concepts."
    )

    print(
        "\n/entity <name>"
        "\n  Show one entity and linked memories."
    )

    print(
        "\n/entity_search <text>"
        "\n  Search entities and concepts."
    )

    print(
        "\n/entity_resolve <name>"
        "\n  Resolve an entity variant to a stable identity."
    )

    print(
        "\n/identity_history [text]"
        "\n  Show identity-resolution audit records."
    )

    print(
        "\n/entity_history <entity>"
        "\n  Show the temporal history of an entity."
    )

    print(
        "\n/entity_at <YYYY-MM-DD> <entity>"
        "\n  Show the entity state that was valid at a date."
    )

    print(
        "\n/relations"
        "\n  Show all known entity-to-entity relations."
    )

    print(
        "\n/relation <entity>"
        "\n  Show relations for one entity."
    )

    print(
        "\n/relation_search <text>"
        "\n  Search entity relations."
    )

    print(
        "\n/history <memory text>"
        "\n  Show the temporal version history of a memory."
    )

    print(
        "\n/provenance <memory text>"
        "\n  Show why and from which message a memory changed."
    )

    print(
        "\n/causal <memory text>"
        "\n  Show explicit causal relationships for a memory."
    )

    print(
        "\n/graph [memory text]"
        "\n  Show the memory graph or a memory-centered subgraph."
    )

    print(
        "\n/related <memory text>"
        "\n  Show memories directly related in the graph."
    )

    print(
        "\n/at <YYYY-MM-DD> <memory text>"
        "\n  Show which version was valid at a specific date."
    )

    print(
        "\n/search <text>"
        "\n  Search memory semantically."
    )

    print(
        "\n/clear"
        "\n  Delete all long-term memory."
    )

    print(
        "\n/archived"
        "\n  Show archived memories."
    )

    print(
        "\n/search_archive <text>"
        "\n  Search archived memories."
    )

    print(
        "\n/restore <exact memory text>"
        "\n  Restore an archived memory."
    )

    print(
        "\n/help"
        "\n  Show commands."
    )

    print(
        "\n/exit"
        "\n  Exit."
    )

    print("\n" + "=" * 65)


# ==================================================
# 14. Handle Commands
# ==================================================

def handle_command(user_input):

    command = user_input.strip()
    command_lower = command.lower()

    if command_lower in [
        "exit",
        "/exit",
        "quit",
        "/quit"
    ]:

        print("\nChat ended.")
        return "EXIT"

    if command_lower == "/memory":
        show_memory()
        return "HANDLED"

    if command_lower == "/entities":
        show_entities()
        return "HANDLED"

    if command_lower == "/relations":
        show_entity_relations()
        return "HANDLED"

    if command_lower.startswith("/relation_search"):
        query = command[len("/relation_search"):].strip()
        search_entity_relation_command(query)
        return "HANDLED"

    if command_lower.startswith("/relation"):
        query = command[len("/relation"):].strip()
        show_entity_relation_command(query)
        return "HANDLED"

    if command_lower.startswith("/identity_history"):
        query = command[len("/identity_history"):].strip()
        show_identity_history_command(query)
        return "HANDLED"

    if command_lower.startswith("/entity_resolve"):
        query = command[len("/entity_resolve"):].strip()
        show_entity_resolve_command(query)
        return "HANDLED"

    if command_lower.startswith("/entity_history"):
        query = command[len("/entity_history"):].strip()
        show_entity_history_command(query)
        return "HANDLED"

    if command_lower.startswith("/entity_at"):
        argument = command[len("/entity_at"):].strip()
        show_entity_as_of_command(argument)
        return "HANDLED"

    if command_lower.startswith("/entity_search"):
        query = command[len("/entity_search"):].strip()
        search_entity_command(query)
        return "HANDLED"

    if command_lower.startswith("/entity"):
        query = command[len("/entity"):].strip()
        show_entity_command(query)
        return "HANDLED"

    if command_lower == "/help":
        show_help()
        return "HANDLED"

    if command_lower == "/archived":
        show_archived_memory()
        return "HANDLED"

    if command_lower.startswith("/causal"):
        query = command[len("/causal"):].strip()
        show_memory_causality(query)
        return "HANDLED"

    if command_lower.startswith("/graph"):
        query = command[len("/graph"):].strip()
        show_memory_graph(query)
        return "HANDLED"

    if command_lower.startswith("/related"):
        query = command[len("/related"):].strip()
        show_related_memories(query)
        return "HANDLED"

    if command_lower.startswith("/provenance"):
        query = command[len("/provenance"):].strip()
        show_memory_provenance(query)
        return "HANDLED"

    if command_lower.startswith("/at"):
        argument = command[len("/at"):].strip()
        show_memory_as_of(argument)
        return "HANDLED"

    if command_lower.startswith("/history"):
        query = command[len("/history"):].strip()
        show_memory_history(query)
        return "HANDLED"

    if command_lower.startswith("/search_archive"):
        query = command[len("/search_archive"):].strip()
        search_archived_memory_command(query)
        return "HANDLED"

    if command_lower.startswith("/restore"):
        query = command[len("/restore"):].strip()
        restore_memory_command(query)
        return "HANDLED"

    if command_lower == "/clear":
        clear_memory()
        return "HANDLED"

    if command_lower.startswith("/search"):
        query = command[len("/search"):].strip()
        search_memory_command(query)
        return "HANDLED"

    return "CHAT"


# ==================================================
# Causal Candidate Retrieval
# ==================================================

def find_causal_candidates(user_text, relevant_memories, max_results=12):
    """Build a wider candidate set for causal reasoning.

    Ordinary memory search is selective by design. Causal reasoning is
    different: an existing fact may be causal even when it is only
    moderately similar to the current message. This function therefore
    combines normal results, broader semantic results, and a bounded set
    of remaining active memories for small memory banks.
    """
    merged = {}

    for item in relevant_memories or []:
        if not isinstance(item, dict) or not item.get("memory"):
            continue
        merged[item["memory"]] = item

    try:
        broad_results = find_similar_memories(
            user_text,
            threshold=0.20,
            max_results=max_results,
        )
    except Exception:
        broad_results = []

    for item in broad_results:
        if not isinstance(item, dict) or not item.get("memory"):
            continue
        merged[item["memory"]] = item

    if len(merged) < max_results:
        for item in get_memory():
            if not isinstance(item, dict) or not item.get("memory"):
                continue
            text_value = item["memory"]
            if text_value in merged:
                continue
            merged[text_value] = {
                "memory": text_value,
                "similarity": 0.0,
            }
            if len(merged) >= max_results:
                break

    return list(merged.values())[:max_results]


# ==================================================
# 15. Main
# ==================================================

print("\n")
print("=" * 65)
print("AI ASSISTANT")
print("=" * 65)

print("\nLong-term memory: ACTIVE")
print("Semantic search: ACTIVE")
print("Smart deduplication: ACTIVE")
print("Memory consolidation: ACTIVE")
print("Memory confidence: ACTIVE")
print("Memory temporal reasoning: ACTIVE")
print("Memory provenance: ACTIVE")
print("Memory causal reasoning: ACTIVE")
print("Memory graph: ACTIVE")
print("Entity / concept layer: ACTIVE")
print("Entity identity linking: ACTIVE")
print("Entity temporal reasoning: ACTIVE")

sync_memory_graph()

print("\nType /help for commands.")
print("=" * 65)


while True:

    user_input = input(
        "\nتو: "
    )

    if not user_input.strip():
        continue

    # ==================================================
    # Handle Commands
    # ==================================================

    command_result = handle_command(
        user_input
    )

    if command_result == "EXIT":
        break

    if command_result == "HANDLED":
        continue

    # ==================================================
    # Intelligent Archive Maintenance
    # ==================================================

    archived_now = archive_eligible_memories()

    if archived_now:
        print(
            f"\n[Archive] Automatically archived "
            f"{len(archived_now)} old memory/memories."
        )

    # ==================================================
    # Find Similar Memories
    # ==================================================

    relevant_memories = search_memory(
        user_input,
        max_results=5,
        threshold=0.35
    )

    # ==================================================
    # Build Memory Context
    # ==================================================

    if relevant_memories:

        memory_lines = []

        for item in relevant_memories:
            memory_lines.append(
                f"- {item['memory']}"
            )

        memory_text = "\n".join(
            memory_lines
        )

    else:
        memory_text = (
            "No relevant long-term memory found."
        )

    graph_lines = []
    graph_seen = set()

    for item in relevant_memories[:3]:
        related = get_graph_neighbors(
            memory_id=item.get("memory_id"),
            direction="both",
            max_results=5,
        )

        for related_item in related:
            memory_value = related_item.get("memory", "").strip()
            if not memory_value or memory_value in graph_seen:
                continue

            graph_seen.add(memory_value)
            graph_lines.append(
                f"- {related_item.get('relation', 'RELATED')}: {memory_value}"
            )

    graph_context = "\n".join(graph_lines) if graph_lines else "No graph-related memories found."

    entity_lines = []
    entity_seen = set()

    for item in relevant_memories[:5]:
        memory_id = item.get("memory_id")
        for entity in get_entities_for_memory(memory_id):
            entity_id = entity.get("entity_id")
            if not entity_id or entity_id in entity_seen:
                continue

            entity_seen.add(entity_id)
            entity_lines.append(
                f"- {entity.get('name', '')} "
                f"({entity.get('type', 'OTHER')})"
            )

    entity_context = "\n".join(entity_lines) if entity_lines else "No known entities connected."

    # ==================================================
    # System Message
    # ==================================================

    system_message = f"""
You are a helpful AI assistant.

Use the relevant long-term memories below
when they help answer the user's question.

Do not mention the memory system unless
the user asks about it.

Relevant memories:

{memory_text}

Related graph context:

{graph_context}

Known entities / concepts:

{entity_context}
"""

    # ==================================================
    # Add User Message
    # ==================================================

    messages.append({
        "role": "user",
        "content": user_input
    })

    # ==================================================
    # Ask AI
    # ==================================================

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": system_message
            },
            *messages
        ]
    )

    ai_answer = (
        response
        .choices[0]
        .message
        .content
    )

    print(
        "\nAI:",
        ai_answer
    )

    # ==================================================
    # Analyze Memory
    # ==================================================

    causal_candidates = find_causal_candidates(
        user_input,
        relevant_memories,
        max_results=12,
    )

    memory_decision = analyze_memory(
        user_input,
        relevant_memories,
        causal_candidate_memories=causal_candidates,
    )

    action = memory_decision.get(
        "action",
        "IGNORE"
    )

    # ==================================================
    # Unified Memory Governance
    # ==================================================

    new_memory = memory_decision.get(
        "memory",
        ""
    ).strip()

    memory_type = memory_decision.get(
        "type",
        "other"
    )

    importance = memory_decision.get(
        "importance",
        1
    )

    old_memory = memory_decision.get(
        "old_memory",
        ""
    ).strip()

    effective_from = memory_decision.get(
        "effective_from",
        ""
    )

    if not isinstance(effective_from, str):
        effective_from = ""

    effective_from = effective_from.strip()

    effective_to = memory_decision.get(
        "effective_to",
        ""
    )

    if not isinstance(effective_to, str):
        effective_to = ""

    effective_to = effective_to.strip()

    temporal_event = memory_decision.get(
        "temporal_event",
        "NONE"
    )

    if not isinstance(temporal_event, str):
        temporal_event = "NONE"

    temporal_event = temporal_event.strip().upper()

    decision_reason = memory_decision.get(
        "reason",
        ""
    )

    if not isinstance(decision_reason, str):
        decision_reason = ""

    decision_reason = decision_reason.strip()

    causal_relations = memory_decision.get(
        "causal_relations",
        []
    )

    if not isinstance(causal_relations, list):
        causal_relations = []

    normalized_causal_relations = []

    for relation in causal_relations:
        if not isinstance(relation, dict):
            continue

        source_memory = str(
            relation.get("source_memory", "")
        ).strip()

        target_memory = str(
            relation.get("target_memory", "")
        ).strip()

        relation_type = str(
            relation.get("relation", "CAUSES")
        ).strip().upper()

        evidence = str(
            relation.get("evidence", "")
        ).strip()

        try:
            confidence = float(
                relation.get("confidence", 0.0)
            )
        except (ValueError, TypeError):
            confidence = 0.0

        confidence = max(0.0, min(1.0, confidence))

        if (
            source_memory
            and target_memory
            and relation_type in {
                "CAUSES",
                "RESULTS_IN",
                "REQUIRES",
                "PREVENTS",
            }
            and confidence >= 0.70
        ):
            normalized_causal_relations.append({
                "source_memory": source_memory,
                "target_memory": target_memory,
                "relation": relation_type,
                "confidence": confidence,
                "evidence": evidence,
            })

    # --------------------------------------------------
    # Conflict Detection
    # --------------------------------------------------

    conflict_old_memory = ""

    if new_memory and action in [
        "ADD",
        "UPDATE"
    ]:

        similar = find_similar_memories(
            new_memory,
            threshold=0.75,
            max_results=3
        )

        if similar:

            conflict_decision = analyze_conflict(
                new_memory,
                similar
            )

            if conflict_decision.get("conflict"):

                conflict_old_memory = (
                    conflict_decision
                    .get("old_memory", "")
                    .strip()
                )

                if conflict_old_memory:
                    old_memory = conflict_old_memory

    # --------------------------------------------------
    # Consolidation Analysis
    # --------------------------------------------------

    consolidation_memory = ""
    consolidation_type = memory_type
    consolidation_importance = importance
    consolidation_targets = []

    if (
        action == "ADD"
        and new_memory
        and not old_memory
    ):

        similar = find_similar_memories(
            new_memory,
            threshold=0.75,
            max_results=3
        )

        if similar:

            consolidation_decision = analyze_consolidation(
                new_memory,
                similar
            )

            if consolidation_decision.get(
                "consolidate",
                False
            ):

                consolidation_memory = (
                    consolidation_decision
                    .get("memory", "")
                    .strip()
                )

                consolidation_type = (
                    consolidation_decision
                    .get("type", memory_type)
                )

                consolidation_importance = (
                    consolidation_decision
                    .get("importance", importance)
                )

                consolidation_targets = similar

    governance_result = govern_memory_action(
        action=action,
        memory_text=new_memory,
        memory_type=memory_type,
        importance=importance,
        old_memory=old_memory,
        similar_memories=consolidation_targets,
        consolidation_memory=consolidation_memory,
        consolidation_type=consolidation_type,
        consolidation_importance=consolidation_importance,
        effective_from=effective_from,
        effective_to=effective_to,
        source_text=user_input,
        decision_reason=decision_reason,
        temporal_event=temporal_event,
        causal_relations=normalized_causal_relations,
    )

    # --------------------------------------------------
    # Apply Explicit Causal Relationships
    # --------------------------------------------------

    applied_causal = 0

    if governance_result.get("success") and normalized_causal_relations:
        resolved_relations = []

        for relation in normalized_causal_relations:
            source_memory = relation["source_memory"]
            target_memory = relation["target_memory"]

            if source_memory == "__NEW_MEMORY__":
                source_memory = new_memory

            if target_memory == "__NEW_MEMORY__":
                target_memory = new_memory

            if not source_memory or not target_memory:
                continue

            resolved_relations.append({
                **relation,
                "source_memory": source_memory,
                "target_memory": target_memory,
            })

        for relation in resolved_relations:
            if add_causal_relationship(
                relation["source_memory"],
                relation["target_memory"],
                relation["relation"],
                confidence=relation["confidence"],
                evidence=relation["evidence"] or user_input,
            ):
                applied_causal += 1

    if applied_causal:
        print(
            f"\n[Memory] CAUSAL LINKS: {applied_causal} relationship(s) recorded."
        )

    final_action = governance_result.get(
        "action",
        action
    )

    if governance_result.get("success"):

        if final_action == "ADD":
            print("\n[Memory] ADD")

        elif final_action == "UPDATE":
            print("\n[Memory] UPDATE / TEMPORAL VERSION")

            if old_memory:
                print(
                    f"[Memory] Historical version: "
                    f"{old_memory}"
                )

            if new_memory:
                print(
                    f"[Memory] Current version: "
                    f"{new_memory}"
                )

            if effective_from:
                print(
                    f"[Memory] Effective from: "
                    f"{effective_from}"
                )

        elif final_action == "CONSOLIDATE":
            print("\n[Memory] CONSOLIDATE")

            if consolidation_memory:
                print(
                    f"[Memory] New consolidated memory: "
                    f"{consolidation_memory}"
                )

        elif final_action == "END":
            print("\n[Memory] END / TEMPORAL EVENT")
            if old_memory:
                print(
                    f"[Memory] Fact ended: "
                    f"{old_memory}"
                )
            if effective_to:
                print(
                    f"[Memory] Valid to: "
                    f"{effective_to}"
                )
            else:
                print(
                    "[Memory] Valid to: current timestamp"
                )

        elif final_action == "DELETE":
            print("\n[Memory] ARCHIVE")
            print(
                "[Memory] The memory was moved to the archive "
                "instead of being permanently deleted."
            )

        else:
            print("\n[Memory] IGNORE")

    else:

        if action == "IGNORE":
            print("\n[Memory] IGNORE")

        else:
            print(
                "\n[Memory] "
                f"{action} failed: "
                f"{governance_result.get('reason', 'unknown')}"
            )

    # ==================================================
    # Entity / Concept Layer
    # ==================================================

    entity_target_memory = ""

    if governance_result.get("success"):
        if final_action == "ADD":
            entity_target_memory = new_memory
        elif final_action == "UPDATE":
            entity_target_memory = new_memory
        elif final_action == "CONSOLIDATE":
            entity_target_memory = consolidation_memory

    if entity_target_memory:
        entity_candidates = analyze_entities(
            user_input,
            entity_target_memory,
        )

        if entity_candidates:
            target_item = None
            for item in get_memory() + get_archived_memory():
                if item.get("memory") == entity_target_memory:
                    target_item = item
                    break

            if target_item and target_item.get("memory_id"):
                linked_entities = link_entities_to_memory(
                    target_item["memory_id"],
                    entity_candidates,
                    source_text=user_input,
                    valid_from=target_item.get("valid_from", ""),
                )

                if linked_entities:
                    print(
                        f"\n[Entity] Linked {len(linked_entities)} "
                        f"entity/concept(s)."
                    )
                    for entity in linked_entities:
                        print(
                            f"[Entity] {entity.get('name', '')} "
                            f"({entity.get('type', 'OTHER')})"
                        )

                    # --------------------------------------------------
                    # Entity Temporal Evolution
                    # --------------------------------------------------

                    evolution_candidates = analyze_entity_evolution(
                        user_input,
                        linked_entities,
                    )

                    applied_entity_evolutions = 0

                    for evolution in evolution_candidates:
                        evolved = evolve_entity(
                            evolution.get("entity_id"),
                            event=evolution.get("event", "CHANGE"),
                            effective_from=evolution.get("effective_from", ""),
                            effective_to=evolution.get("effective_to", ""),
                            new_name=evolution.get("new_name", ""),
                            new_type=evolution.get("new_type", ""),
                            new_description=evolution.get("new_description", ""),
                            aliases_add=evolution.get("aliases_add", []),
                            reason=evolution.get("reason", ""),
                            source_text=user_input,
                            memory_id=target_item.get("memory_id"),
                        )

                        if evolved:
                            applied_entity_evolutions += 1
                            print(
                                f"\n[Entity] Temporal evolution: "
                                f"{evolved.get('name', '')} "
                                f"v{evolved.get('version', 1)} "
                                f"({evolved.get('temporal_status', 'current')})"
                            )

                    if applied_entity_evolutions:
                        print(
                            f"[Entity] Applied {applied_entity_evolutions} "
                            f"temporal evolution event(s)."
                        )

                    relation_candidates = analyze_entity_relations(
                        user_input,
                        linked_entities,
                    )

                    if relation_candidates:
                        relation_records = upsert_entity_relations(
                            relation_candidates,
                            memory_id=target_item.get("memory_id"),
                            source_text=user_input,
                        )

                        if relation_records:
                            print(
                                f"\n[Entity Relation] Stored {len(relation_records)} "
                                f"relation(s)."
                            )
                            for relation in relation_records:
                                print(
                                    f"[Entity Relation] "
                                    f"{relation.get('source_entity_id', '')} "
                                    f"--{relation.get('relation', '')}--> "
                                    f"{relation.get('target_entity_id', '')}"
                                )

                    sync_memory_graph()

    # ==================================================
    # Save Assistant Message
    # ==================================================

    messages.append({
        "role": "assistant",
        "content": ai_answer
    })
