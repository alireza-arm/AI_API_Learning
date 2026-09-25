import json
import os
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document


# ==================================================
# Entity Archive Configuration
# ==================================================

ENTITY_ARCHIVE_FILE = "memory_entities_archive.json"
ENTITY_ARCHIVE_SCHEMA_VERSION = 1
ENTITY_ARCHIVE_MAX_COUNT = 5000

ARCHIVE_STATE_ACTIVE = "ACTIVE"
ARCHIVE_STATE_ARCHIVED = "ARCHIVED"

ARCHIVABLE_LIFECYCLE_STATES = {
    "DORMANT",
    "ENDED",
}


# ==================================================
# Time Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


# ==================================================
# Archive Store
# ==================================================

def _empty_archive_store():
    return {
        "schema_version": ENTITY_ARCHIVE_SCHEMA_VERSION,
        "updated_at": None,
        "entities": [],
    }


def load_entity_archive():
    data = load_json_document(
        ENTITY_ARCHIVE_FILE,
        _empty_archive_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_archive_store()

    entities = data.get("entities")
    if not isinstance(entities, list):
        entities = []

    normalized = []
    seen_ids = set()

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        entity_id = str(entity.get("entity_id", "") or "").strip()
        name = str(entity.get("name", "") or "").strip()

        if not entity_id or not name or entity_id in seen_ids:
            continue

        item = dict(entity)
        item["entity_id"] = entity_id
        item["name"] = name
        item["archive_state"] = ARCHIVE_STATE_ARCHIVED

        if not item.get("archived_at"):
            item["archived_at"] = item.get("updated_at") or current_timestamp()

        normalized.append(item)
        seen_ids.add(entity_id)

        if len(normalized) >= ENTITY_ARCHIVE_MAX_COUNT:
            break

    return {
        "schema_version": ENTITY_ARCHIVE_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "entities": normalized,
    }


def save_entity_archive(store):
    if not isinstance(store, dict):
        store = _empty_archive_store()

    entities = store.get("entities", [])
    if not isinstance(entities, list):
        entities = []

    store["schema_version"] = ENTITY_ARCHIVE_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()
    store["entities"] = entities[-ENTITY_ARCHIVE_MAX_COUNT:]

    save_json_document(ENTITY_ARCHIVE_FILE, store, indent=2)


# ==================================================
# Retrieval
# ==================================================

def get_archived_entities():
    return load_entity_archive().get("entities", [])


def get_archived_entity(entity_query):
    query = str(entity_query or "").strip()
    if not query:
        return None

    entities = get_archived_entities()
    query_lower = query.casefold()

    for entity in entities:
        if str(entity.get("entity_id", "")).strip() == query:
            return entity

    exact_matches = []
    for entity in entities:
        names = [entity.get("name", "")]
        aliases = entity.get("aliases", [])
        if isinstance(aliases, list):
            names.extend(aliases)

        for name in names:
            if str(name or "").strip().casefold() == query_lower:
                exact_matches.append(entity)
                break

    if len(exact_matches) == 1:
        return exact_matches[0]

    return None


def search_archived_entities(query="", max_results=20):
    query = str(query or "").strip().casefold()
    entities = get_archived_entities()

    if not query:
        return entities[:max_results]

    results = []

    for entity in entities:
        names = [entity.get("name", "")]
        aliases = entity.get("aliases", [])
        if isinstance(aliases, list):
            names.extend(aliases)

        haystack = " ".join(
            str(name or "")
            for name in names
        ).casefold()

        if query in haystack:
            results.append(dict(entity))

    results.sort(
        key=lambda item: (
            item.get("archived_at", ""),
            item.get("name", "").casefold(),
        ),
        reverse=True,
    )

    return results[:max_results]


# ==================================================
# Eligibility
# ==================================================

def is_entity_archivable(entity):
    if not isinstance(entity, dict):
        return False

    lifecycle_status = str(
        entity.get("lifecycle_status", "ACTIVE") or "ACTIVE"
    ).strip().upper()

    return lifecycle_status in ARCHIVABLE_LIFECYCLE_STATES


# ==================================================
# Archive One Entity
# ==================================================

def _archive_entity_impl(entity_query, reason="lifecycle", force=False):
    """Move one active entity to the archive without deleting its data.

    Archived entities retain their stable entity_id, history, aliases,
    memory references and lifecycle metadata. They are removed only from
    the active entity store. Recovery is intentionally handled by the next
    stage of the architecture.
    """
    from memory_entities import load_entity_store, save_entity_store

    query = str(entity_query or "").strip()
    if not query:
        return None

    store = load_entity_store()
    entities = store.get("entities", [])

    target = None
    for entity in entities:
        if entity.get("entity_id") == query:
            target = entity
            break

    if target is None:
        query_lower = query.casefold()
        matches = []

        for entity in entities:
            names = [entity.get("name", "")]
            aliases = entity.get("aliases", [])
            if isinstance(aliases, list):
                names.extend(aliases)

            if any(
                str(name or "").strip().casefold() == query_lower
                for name in names
            ):
                matches.append(entity)

        if len(matches) == 1:
            target = matches[0]

    if target is None:
        return None

    if not force and not is_entity_archivable(target):
        return None

    target_id = str(target.get("entity_id", "")).strip()
    if not target_id:
        return None

    archive_store = load_entity_archive()
    archived_entities = archive_store.get("entities", [])

    now = current_timestamp()
    archived_item = dict(target)
    archived_item["archive_state"] = ARCHIVE_STATE_ARCHIVED
    archived_item["archived_at"] = now
    archived_item["archive_reason"] = str(reason or "lifecycle").strip()[:300]
    archived_item["pre_archive_lifecycle_status"] = str(
        target.get("lifecycle_status", "ACTIVE") or "ACTIVE"
    ).strip().upper()
    archived_item["updated_at"] = now

    replaced = False
    for index, item in enumerate(archived_entities):
        if item.get("entity_id") == target_id:
            archived_entities[index] = archived_item
            replaced = True
            break

    if not replaced:
        archived_entities.append(archived_item)

    archive_store["entities"] = archived_entities
    save_entity_archive(archive_store)

    store["entities"] = [
        entity
        for entity in entities
        if entity.get("entity_id") != target_id
    ]
    save_entity_store(store)

    return dict(archived_item)


def archive_entity(entity_query, reason="lifecycle", force=False):
    """Idempotent active->archive transition."""
    from memory_integrity import run_idempotent

    payload = {
        "entity_query": str(entity_query or "").strip(),
        "reason": str(reason or "lifecycle").strip(),
        "force": bool(force),
    }
    result = run_idempotent(
        "ENTITY_ARCHIVE",
        payload,
        lambda: _archive_entity_impl(entity_query, reason=reason, force=force),
    )
    return result.get("result")



# ==================================================
# Restore Archived Entity
# ==================================================

def _restore_entity_impl(entity_id, reason="recovery"):
    """Restore an archived entity to the active entity store.

    The stable entity_id, history, aliases and linked memory references are
    preserved. The caller is responsible for deciding whether identity
    recovery is safe; this function only performs the storage transition.
    """
    entity_id = str(entity_id or "").strip()
    if not entity_id:
        return None

    from memory_entities import load_entity_store, save_entity_store

    archive_store = load_entity_archive()
    archived_entities = archive_store.get("entities", [])

    target = None
    remaining_archive = []

    for entity in archived_entities:
        if entity.get("entity_id") == entity_id and target is None:
            target = dict(entity)
        else:
            remaining_archive.append(entity)

    if target is None:
        return None

    active_store = load_entity_store()
    active_entities = active_store.get("entities", [])

    # Never create two active copies with the same stable identity.
    if any(item.get("entity_id") == entity_id for item in active_entities):
        return None

    now = current_timestamp()

    target["archive_state"] = ARCHIVE_STATE_ACTIVE
    target["recovered_at"] = now
    target["recovery_reason"] = str(reason or "recovery").strip()[:300]
    target["lifecycle_status"] = "ACTIVE"
    target["lifecycle_score"] = 1.0
    target["last_seen_at"] = now
    target["updated_at"] = now
    target["archived_at"] = None
    target["archive_reason"] = ""

    active_entities.append(target)
    active_store["entities"] = active_entities

    save_entity_store(active_store)

    archive_store["entities"] = remaining_archive
    save_entity_archive(archive_store)

    return dict(target)

def restore_entity(entity_id, reason="recovery"):
    """Idempotent archive->active recovery transition."""
    from memory_integrity import run_idempotent

    payload = {
        "entity_id": str(entity_id or "").strip(),
        "reason": str(reason or "recovery").strip(),
    }
    result = run_idempotent(
        "ENTITY_RESTORE",
        payload,
        lambda: _restore_entity_impl(entity_id, reason=reason),
    )
    return result.get("result")



# ==================================================
# Automatic Archive Maintenance
# ==================================================

def archive_eligible_entities(reason="lifecycle"):
    """Archive all active entities whose lifecycle permits archiving."""
    from memory_entity_lifecycle import update_entity_lifecycle
    from memory_entities import load_entity_store

    update_entity_lifecycle()

    store = load_entity_store()
    candidates = [
        entity.get("entity_id")
        for entity in store.get("entities", [])
        if isinstance(entity, dict) and is_entity_archivable(entity)
    ]

    archived = []
    for entity_id in candidates:
        result = archive_entity(entity_id, reason=reason)
        if result is not None:
            archived.append(result)

    return archived


# ==================================================
# Archive Statistics
# ==================================================

def get_entity_archive_stats():
    entities = get_archived_entities()

    by_lifecycle = {}
    for entity in entities:
        state = str(
            entity.get("pre_archive_lifecycle_status", "UNKNOWN") or "UNKNOWN"
        ).strip().upper()
        by_lifecycle[state] = by_lifecycle.get(state, 0) + 1

    return {
        "count": len(entities),
        "by_lifecycle": by_lifecycle,
        "updated_at": load_entity_archive().get("updated_at"),
    }


# ==================================================
# Clear Archive
# ==================================================

def clear_entity_archive():
    save_entity_archive(_empty_archive_store())
    return True
