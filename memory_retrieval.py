import contextlib
import json
import math
import os
import tempfile
import time

from long_term_memory import (
    EMBEDDINGS_FILE,
    cosine_similarity as _engine_cosine,
    get_memory,
)


# --------------------------------------------------
# Load embeddings
# --------------------------------------------------

def load_embeddings():
    """
    Read-through to the engine's canonical embedding store.

    STAGE 21 fix: previously this module read a separate file
    ("embeddings.json") that nothing else in the project ever wrote,
    so retrieve_memories() silently returned [] forever.  The engine
    owns one embedding document (memory_embeddings.json); reading it
    here keeps a single source of truth and stays backward compatible
    for callers of load_embeddings().

    The file is parsed directly (no sentence-transformers import), so
    retrieval works even when the optional ML dependency is absent.
    Malformed or non-object documents fail closed to {}.
    """
    try:
        with open(EMBEDDINGS_FILE, "r", encoding="utf-8") as f:
            embeddings = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}

    if not isinstance(embeddings, dict):
        return {}

    return embeddings


@contextlib.contextmanager
def isolated_stores(tmp_dir=None):
    """
    Point every store path used by retrieval at a throwaway directory
    (or a TemporaryDirectory if none is given), then restore originals.

    This exists so tests — and library users running batch jobs — can
    exercise retrieval without touching production files.  It mutates
    only module-level path constants for the duration of the block.
    """
    import long_term_memory as ltm

    created = None
    if tmp_dir is None:
        created = tempfile.TemporaryDirectory(prefix="memory_retrieval_")
        root = created.name
    else:
        root = str(tmp_dir)
        os.makedirs(root, exist_ok=True)

    saved = {
        "MEMORY_FILE": ltm.MEMORY_FILE,
        "ARCHIVE_FILE": ltm.ARCHIVE_FILE,
        "EMBEDDINGS_FILE": ltm.EMBEDDINGS_FILE,
        "BACKUP_FILE": getattr(ltm, "BACKUP_FILE", None),
    }

    def relocate(name):
        return os.path.join(root, os.path.basename(name))

    try:
        ltm.MEMORY_FILE = relocate(ltm.MEMORY_FILE)
        ltm.ARCHIVE_FILE = relocate(ltm.ARCHIVE_FILE)
        ltm.EMBEDDINGS_FILE = relocate(ltm.EMBEDDINGS_FILE)
        if saved["BACKUP_FILE"] is not None:
            ltm.BACKUP_FILE = relocate(saved["BACKUP_FILE"])
        yield root
    finally:
        ltm.MEMORY_FILE = saved["MEMORY_FILE"]
        ltm.ARCHIVE_FILE = saved["ARCHIVE_FILE"]
        ltm.EMBEDDINGS_FILE = saved["EMBEDDINGS_FILE"]
        if saved["BACKUP_FILE"] is not None:
            ltm.BACKUP_FILE = saved["BACKUP_FILE"]
        if created is not None:
            with contextlib.suppress(OSError):
                created.cleanup()



# --------------------------------------------------
# Cosine Similarity (delegates to the engine implementation)
# --------------------------------------------------

def cosine_similarity(vec1, vec2):
    """
    Thin wrapper over long_term_memory.cosine_similarity so callers of
    this module keep a stable local name.  Engine behavior is reused
    verbatim: empty/zero vectors score 0.
    """
    return _engine_cosine(vec1, vec2)




# --------------------------------------------------
# Normalize values
# --------------------------------------------------

def normalize(value, max_value):

    if value is None:
        return 0

    return min(
        value/max_value,
        1
    )




# --------------------------------------------------
# Memory score
# --------------------------------------------------

def calculate_memory_score(
        memory,
        similarity
):


    importance = normalize(
        memory.get(
            "importance",
            1
        ),
        5
    )


    confidence = memory.get(
        "confidence",
        0.5
    )

    # STAGE 21 determinism fix: confidence must be numeric before it
    # enters the weighted sum; a malformed value fails closed to the
    # neutral default instead of raising TypeError mid-scoring.
    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 0.5

    confidence = max(0.0, min(1.0, confidence))


    lifecycle_map = {

        "active":1,
        "aging":0.7,
        "decaying":0.4,
        "archived":0.2

    }


    lifecycle = lifecycle_map.get(
        memory.get(
            "status",
            "active"
        ),
        0.5
    )


    access = normalize(
        memory.get(
            "access_count",
            0
        ),
        20
    )


    timestamp = memory.get(
        "created_at",
        time.time()
    )


    # STAGE 21 determinism fix: the engine stores created_at as an ISO
    # string (current_timestamp()), but this code treated it as a unix
    # float.  Subtracting str - float raised TypeError on every real
    # record, so retrieve_memories() crashed in practice.  We now parse
    # both representations; unparseable timestamps fail closed to age 0
    # (maximum recency weight), matching days_since()'s contract.
    if isinstance(timestamp, str):
        from datetime import datetime, timezone

        try:
            parsed = datetime.fromisoformat(timestamp)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            epoch = datetime.fromtimestamp(0, tz=timezone.utc)
            timestamp = (parsed - epoch).total_seconds()
        except (ValueError, TypeError):
            timestamp = time.time()

    age = max(0.0, time.time() - float(timestamp))


    recency = math.exp(
        -age / (60*60*24*30)
    )



    score = (

        similarity * 0.35

        +

        importance * 0.20

        +

        confidence * 0.15

        +

        lifecycle * 0.10

        +

        access * 0.10

        +

        recency * 0.10

    )


    return round(
        score,
        4
    )




# --------------------------------------------------
# Retrieve memories
# --------------------------------------------------

def retrieve_memories(
        query_embedding,
        top_k=5
):


    memories = get_memory()


    embeddings = load_embeddings()


    results = []



    for memory in memories:


        memory_id = memory.get(
            "memory_id"
        )


        if memory_id not in embeddings:
            continue


        # STAGE 21 fail-closed guard: a corrupted embedding entry
        # (non-numeric payload) must produce a violation-free skip,
        # never an exception — same contract as the integrity engine.
        try:
            similarity = cosine_similarity(
                query_embedding,
                embeddings[memory_id]
            )
        except (TypeError, ValueError):
            continue


        score = calculate_memory_score(
            memory,
            similarity
        )


        results.append({

            "memory":memory.get(
                "content"
            ),

            "memory_id":memory_id,

            "similarity":round(
                similarity,
                4
            ),

            "importance":memory.get(
                "importance",
                0
            ),

            "confidence":memory.get(
                "confidence",
                0
            ),

            "final_score":score

        })



    results.sort(
        key=lambda x:x["final_score"],
        reverse=True
    )


    return results[:top_k]



# --------------------------------------------------
# Debug
# --------------------------------------------------

if __name__ == "__main__":


    print(
        "Memory Retrieval Engine Ready"
    )