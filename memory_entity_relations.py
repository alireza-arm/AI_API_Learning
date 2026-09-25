import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document

from memory_entities import get_all_entities, get_entity


# ==================================================
# Entity Relation Configuration
# ==================================================

RELATION_FILE = "memory_entity_relations.json"
RELATION_SCHEMA_VERSION = 1
RELATION_MAX_COUNT = 15000
RELATION_MAX_MEMORY_IDS = 100
RELATION_MAX_EVIDENCE_CHARS = 500
RELATION_MIN_CONFIDENCE = 0.65

VALID_RELATIONS = {
    "RELATED_TO",
    "USED_FOR",
    "WORKS_WITH",
    "PART_OF",
    "REQUIRES",
    "DEPENDS_ON",
    "LEADS_TO",
    "SUPPORTS",
    "LEARNS",
    "BUILDS",
    "APPLIES_TO",
}

UNDIRECTED_RELATIONS = {
    "RELATED_TO",
    "WORKS_WITH",
}


# ==================================================
# Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def generate_relation_id(source_entity_id, target_entity_id, relation):
    key = f"{source_entity_id}|{target_entity_id}|{relation}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"rel_{digest}"


def normalize_name(value):
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())


def canonical_relation(value):
    if not isinstance(value, str):
        return ""
    value = value.strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "RELATES_TO": "RELATED_TO",
        "RELATED": "RELATED_TO",
        "USE_FOR": "USED_FOR",
        "WORKS_WITH": "WORKS_WITH",
        "DEPENDENT_ON": "DEPENDS_ON",
        "RESULTS_IN": "LEADS_TO",
        "LEAD_TO": "LEADS_TO",
        "APPLY_TO": "APPLIES_TO",
    }
    return aliases.get(value, value)


def normalize_confidence(value, default=0.70):
    try:
        value = float(value)
    except (ValueError, TypeError):
        value = default
    return round(max(0.0, min(1.0, value)), 4)


def normalize_memory_ids(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []

    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            continue
        item = item.strip()
        if not item or item in seen:
            continue
        result.append(item)
        seen.add(item)
        if len(result) >= RELATION_MAX_MEMORY_IDS:
            break
    return result


# ==================================================
# Store
# ==================================================

def _empty_store():
    return {
        "schema_version": RELATION_SCHEMA_VERSION,
        "updated_at": None,
        "relations": [],
    }


def normalize_relation_item(item):
    if not isinstance(item, dict):
        return None

    source_entity_id = normalize_name(item.get("source_entity_id"))
    target_entity_id = normalize_name(item.get("target_entity_id"))
    relation = canonical_relation(item.get("relation"))

    if not source_entity_id or not target_entity_id:
        return None
    if source_entity_id == target_entity_id:
        return None
    if relation not in VALID_RELATIONS:
        return None

    source_entity = next(
        (entity for entity in get_all_entities() if entity.get("entity_id") == source_entity_id),
        None,
    )
    target_entity = next(
        (entity for entity in get_all_entities() if entity.get("entity_id") == target_entity_id),
        None,
    )
    if source_entity is None or target_entity is None:
        return None

    directed = bool(item.get("directed", relation not in UNDIRECTED_RELATIONS))
    evidence = str(item.get("evidence", "") or "").strip()[:RELATION_MAX_EVIDENCE_CHARS]
    confidence = normalize_confidence(item.get("confidence", 0.70))
    if confidence < RELATION_MIN_CONFIDENCE:
        return None

    memory_ids = normalize_memory_ids(item.get("memory_ids", []))

    relation_id = normalize_name(item.get("relation_id"))
    if not relation_id:
        relation_id = generate_relation_id(source_entity_id, target_entity_id, relation)

    created_at = item.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        created_at = current_timestamp()

    updated_at = item.get("updated_at")
    if not isinstance(updated_at, str) or not updated_at.strip():
        updated_at = created_at

    status = str(item.get("status", "active") or "active").strip().lower()
    if status not in {"active", "inactive"}:
        status = "active"

    return {
        "relation_id": relation_id,
        "source_entity_id": source_entity_id,
        "target_entity_id": target_entity_id,
        "relation": relation,
        "directed": directed,
        "confidence": confidence,
        "evidence": evidence,
        "memory_ids": memory_ids,
        "status": status,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def load_relation_store():
    data = load_json_document(
        RELATION_FILE,
        _empty_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_store()

    raw_relations = data.get("relations")
    if not isinstance(raw_relations, list):
        raw_relations = []

    relations = []
    seen_ids = set()
    for item in raw_relations:
        normalized = normalize_relation_item(item)
        if normalized is None:
            continue
        if normalized["relation_id"] in seen_ids:
            continue
        relations.append(normalized)
        seen_ids.add(normalized["relation_id"])

    return {
        "schema_version": RELATION_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "relations": relations[:RELATION_MAX_COUNT],
    }


def save_relation_store(store):
    if not isinstance(store, dict):
        store = _empty_store()

    store["schema_version"] = RELATION_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()

    save_json_document(RELATION_FILE, store, indent=2)


def get_all_entity_relations(include_inactive=False):
    relations = load_relation_store().get("relations", [])
    if include_inactive:
        return relations
    return [item for item in relations if item.get("status") == "active"]


# ==================================================
# Relation Upsert
# ==================================================

def _resolve_entity(value):
    if isinstance(value, dict):
        entity_id = value.get("entity_id")
        if entity_id:
            return next(
                (entity for entity in get_all_entities() if entity.get("entity_id") == entity_id),
                None,
            )
        value = value.get("name", "")

    if not isinstance(value, str):
        return None
    return get_entity(value)


def _upsert_entity_relation_impl(
    source_entity,
    target_entity,
    relation,
    confidence=0.70,
    evidence="",
    memory_id=None,
):
    source = _resolve_entity(source_entity)
    target = _resolve_entity(target_entity)

    if source is None or target is None:
        return None

    relation = canonical_relation(relation)
    if relation not in VALID_RELATIONS:
        return None
    if source.get("entity_id") == target.get("entity_id"):
        return None

    confidence = normalize_confidence(confidence)
    if confidence < RELATION_MIN_CONFIDENCE:
        return None

    store = load_relation_store()
    relations = store.get("relations", [])

    source_id = source["entity_id"]
    target_id = target["entity_id"]
    relation_id = generate_relation_id(source_id, target_id, relation)

    target_relation = None
    for item in relations:
        if item.get("relation_id") == relation_id:
            target_relation = item
            break

    if target_relation is None:
        now = current_timestamp()
        target_relation = {
            "relation_id": relation_id,
            "source_entity_id": source_id,
            "target_entity_id": target_id,
            "relation": relation,
            "directed": relation not in UNDIRECTED_RELATIONS,
            "confidence": confidence,
            "evidence": str(evidence or "").strip()[:RELATION_MAX_EVIDENCE_CHARS],
            "memory_ids": [],
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
        relations.append(target_relation)
    else:
        target_relation["confidence"] = max(
            normalize_confidence(target_relation.get("confidence", 0.0)),
            confidence,
        )
        if evidence:
            target_relation["evidence"] = str(evidence).strip()[:RELATION_MAX_EVIDENCE_CHARS]
        target_relation["status"] = "active"
        target_relation["updated_at"] = current_timestamp()

    if memory_id:
        memory_id = normalize_name(memory_id)
        if memory_id:
            memory_ids = normalize_memory_ids(target_relation.get("memory_ids", []))
            if memory_id not in memory_ids:
                memory_ids.append(memory_id)
            target_relation["memory_ids"] = memory_ids[-RELATION_MAX_MEMORY_IDS:]

    save_relation_store({
        "schema_version": RELATION_SCHEMA_VERSION,
        "updated_at": current_timestamp(),
        "relations": relations[-RELATION_MAX_COUNT:],
    })

    return dict(target_relation)


def upsert_entity_relation(
    source_entity,
    target_entity,
    relation,
    confidence=0.70,
    evidence="",
    memory_id=None,
):
    """Idempotent relation upsert preserving deterministic relation_id."""
    from memory_integrity import run_idempotent

    source = _resolve_entity(source_entity)
    target = _resolve_entity(target_entity)
    if source is None or target is None:
        return None

    canonical = canonical_relation(relation)
    payload = {
        "source_entity_id": source.get("entity_id", ""),
        "target_entity_id": target.get("entity_id", ""),
        "relation": canonical,
        "confidence": round(float(confidence or 0.0), 4),
        "evidence": str(evidence or "").strip(),
        "memory_id": normalize_name(memory_id),
    }

    result = run_idempotent(
        "RELATION_UPSERT",
        payload,
        lambda: _upsert_entity_relation_impl(
            source,
            target,
            relation,
            confidence=confidence,
            evidence=evidence,
            memory_id=memory_id,
        ),
    )
    return result.get("result")


def upsert_entity_relations(candidates, memory_id=None, source_text=""):
    if not isinstance(candidates, list):
        return []

    results = []
    seen = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        source = candidate.get("source") or candidate.get("from")
        target = candidate.get("target") or candidate.get("to")
        relation = candidate.get("relation")

        source_name = normalize_name(source)
        target_name = normalize_name(target)
        relation = canonical_relation(relation)
        if not source_name or not target_name or relation not in VALID_RELATIONS:
            continue

        source_entity = _resolve_entity(source_name)
        target_entity = _resolve_entity(target_name)
        if source_entity is None or target_entity is None:
            continue

        key = (
            source_entity.get("entity_id"),
            target_entity.get("entity_id"),
            relation,
        )
        if key in seen:
            continue
        seen.add(key)

        relation_item = upsert_entity_relation(
            source_entity,
            target_entity,
            relation,
            confidence=candidate.get("confidence", 0.70),
            evidence=candidate.get("evidence") or source_text,
            memory_id=memory_id,
        )
        if relation_item:
            results.append(relation_item)

    return results


# ==================================================
# Retrieval
# ==================================================

def _entity_name_map():
    return {
        entity.get("entity_id"): entity.get("name", "")
        for entity in get_all_entities()
        if entity.get("entity_id")
    }


def _format_relation(item, entity_names):
    source_id = item.get("source_entity_id")
    target_id = item.get("target_entity_id")
    return {
        **item,
        "source_name": entity_names.get(source_id, source_id),
        "target_name": entity_names.get(target_id, target_id),
    }


def get_entity_relations(entity_query, direction="both", include_inactive=False):
    entity = _resolve_entity(entity_query)
    if entity is None:
        return []

    entity_id = entity.get("entity_id")
    direction = str(direction or "both").strip().lower()
    if direction not in {"in", "out", "both"}:
        direction = "both"

    entity_names = _entity_name_map()
    results = []

    for item in get_all_entity_relations(include_inactive=include_inactive):
        source = item.get("source_entity_id")
        target = item.get("target_entity_id")

        if direction == "out" and source != entity_id:
            continue
        if direction == "in" and target != entity_id:
            continue
        if direction == "both" and source != entity_id and target != entity_id:
            continue

        results.append(_format_relation(item, entity_names))

    results.sort(key=lambda x: (x.get("confidence", 0.0), x.get("updated_at", "")), reverse=True)
    return results


def search_entity_relations(query, max_results=20):
    query = normalize_name(query)
    if not query:
        return []

    query_key = query.casefold()
    entity_names = _entity_name_map()
    results = []

    for item in get_all_entity_relations():
        source_name = entity_names.get(item.get("source_entity_id"), "")
        target_name = entity_names.get(item.get("target_entity_id"), "")
        relation = item.get("relation", "")
        haystack = f"{source_name} {target_name} {relation}".casefold()
        if query_key not in haystack:
            continue
        results.append(_format_relation(item, entity_names))

    results.sort(key=lambda x: x.get("confidence", 0.0), reverse=True)
    return results[:max_results]


def remove_memory_reference(memory_id):
    memory_id = normalize_name(memory_id)
    if not memory_id:
        return False

    store = load_relation_store()
    changed = False

    for item in store.get("relations", []):
        old_ids = normalize_memory_ids(item.get("memory_ids", []))
        new_ids = [value for value in old_ids if value != memory_id]
        if new_ids != old_ids:
            item["memory_ids"] = new_ids
            item["updated_at"] = current_timestamp()
            changed = True

    if changed:
        save_relation_store(store)

    return changed


def prune_memory_references(valid_memory_ids):
    valid = set(normalize_memory_ids(valid_memory_ids))
    store = load_relation_store()
    changed = False

    for item in store.get("relations", []):
        old_ids = normalize_memory_ids(item.get("memory_ids", []))
        new_ids = [value for value in old_ids if value in valid]
        if new_ids != old_ids:
            item["memory_ids"] = new_ids
            item["updated_at"] = current_timestamp()
            changed = True

    if changed:
        save_relation_store(store)

    return changed


def clear_entity_relations():
    save_relation_store(_empty_store())
