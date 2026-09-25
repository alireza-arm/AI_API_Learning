import math
from datetime import datetime, timezone


# ==================================================
# Entity Lifecycle Configuration
# ==================================================

ENTITY_LIFECYCLE_ACTIVE = "ACTIVE"
ENTITY_LIFECYCLE_AGING = "AGING"
ENTITY_LIFECYCLE_DORMANT = "DORMANT"
ENTITY_LIFECYCLE_ENDED = "ENDED"

ENTITY_AGING_DAYS = 30
ENTITY_DORMANT_DAYS = 90
ENTITY_LIFECYCLE_MIN_SCORE = 0.20
ENTITY_LIFECYCLE_MAX_SCORE = 1.00

VALID_ENTITY_LIFECYCLE_STATES = {
    ENTITY_LIFECYCLE_ACTIVE,
    ENTITY_LIFECYCLE_AGING,
    ENTITY_LIFECYCLE_DORMANT,
    ENTITY_LIFECYCLE_ENDED,
}


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def normalize_lifecycle_state(value, default=ENTITY_LIFECYCLE_ACTIVE):
    value = str(value or "").strip().upper()
    return value if value in VALID_ENTITY_LIFECYCLE_STATES else default


def days_since(value, now=None):
    timestamp = parse_timestamp(value)
    if timestamp is None:
        return float("inf")

    if now is None:
        now = datetime.now(timezone.utc)

    difference = now - timestamp
    return max(0.0, difference.total_seconds() / 86400.0)


def calculate_recency_score(last_seen_at, now=None):
    age_days = days_since(last_seen_at, now=now)

    if age_days == float("inf"):
        return 0.0

    if age_days <= 0:
        return 1.0

    return max(0.0, min(1.0, 1.0 / (1.0 + math.log1p(age_days))))


def calculate_mention_score(mention_count):
    try:
        mention_count = max(0, int(mention_count))
    except (ValueError, TypeError):
        mention_count = 0

    if mention_count <= 0:
        return 0.0

    return min(1.0, math.log1p(mention_count) / math.log1p(20))


def calculate_entity_lifecycle_score(entity, now=None):
    if not isinstance(entity, dict):
        return 0.0

    confidence = entity.get("confidence", 0.70)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (ValueError, TypeError):
        confidence = 0.70

    recency = calculate_recency_score(entity.get("last_seen_at"), now=now)
    mention_score = calculate_mention_score(entity.get("mention_count", 0))

    if normalize_lifecycle_state(entity.get("lifecycle_status")) == ENTITY_LIFECYCLE_ENDED:
        return ENTITY_LIFECYCLE_MIN_SCORE

    score = (
        recency * 0.55
        + mention_score * 0.30
        + confidence * 0.15
    )

    return round(
        max(ENTITY_LIFECYCLE_MIN_SCORE, min(ENTITY_LIFECYCLE_MAX_SCORE, score)),
        4,
    )


def determine_entity_lifecycle_state(entity, now=None):
    if not isinstance(entity, dict):
        return ENTITY_LIFECYCLE_DORMANT

    temporal_status = str(entity.get("temporal_status", "current") or "current").strip().lower()
    if temporal_status == "ended":
        return ENTITY_LIFECYCLE_ENDED

    last_seen_at = entity.get("last_seen_at") or entity.get("updated_at") or entity.get("created_at")
    age_days = days_since(last_seen_at, now=now)

    if age_days <= ENTITY_AGING_DAYS:
        return ENTITY_LIFECYCLE_ACTIVE

    if age_days <= ENTITY_DORMANT_DAYS:
        return ENTITY_LIFECYCLE_AGING

    return ENTITY_LIFECYCLE_DORMANT


def update_entity_lifecycle(save=True, now=None):
    """Recalculate lifecycle state and score for every entity.

    Entity storage remains the source of truth. This module only governs
    lifecycle metadata and does not archive or delete entities.
    """
    from memory_entities import load_entity_store, save_entity_store

    store = load_entity_store()
    entities = store.get("entities", [])
    changed = False

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        state = determine_entity_lifecycle_state(entity, now=now)
        score = calculate_entity_lifecycle_score(entity, now=now)

        if entity.get("lifecycle_status") != state:
            entity["lifecycle_status"] = state
            changed = True

        try:
            previous_score = float(entity.get("lifecycle_score", 0.0))
        except (ValueError, TypeError):
            previous_score = 0.0

        if round(previous_score, 4) != score:
            entity["lifecycle_score"] = score
            changed = True

    if changed and save:
        save_entity_store(store)

    return changed


def mark_entity_seen(entity_id, seen_at=None):
    """Update the observation timestamp and lifecycle state for one entity."""
    from memory_entities import load_entity_store, save_entity_store

    entity_id = str(entity_id or "").strip()
    if not entity_id:
        return None

    seen_at = seen_at or current_timestamp()
    store = load_entity_store()

    target = next(
        (entity for entity in store.get("entities", []) if entity.get("entity_id") == entity_id),
        None,
    )
    if target is None:
        return None

    if not isinstance(target.get("first_seen_at"), str) or not target.get("first_seen_at"):
        target["first_seen_at"] = seen_at

    target["last_seen_at"] = seen_at
    target["updated_at"] = seen_at
    target["lifecycle_status"] = determine_entity_lifecycle_state(target)
    target["lifecycle_score"] = calculate_entity_lifecycle_score(target)

    save_entity_store(store)
    return dict(target)


def get_entities_by_lifecycle(state=None):
    from memory_entities import get_all_entities

    state = normalize_lifecycle_state(state, default="") if state else ""
    entities = get_all_entities()
    if not state:
        return list(entities)

    return [
        entity
        for entity in entities
        if normalize_lifecycle_state(entity.get("lifecycle_status"), default="") == state
    ]


def get_entity_lifecycle(entity_query):
    from memory_entities import get_entity

    entity = get_entity(entity_query)
    if entity is None:
        return None

    return {
        "entity_id": entity.get("entity_id", ""),
        "name": entity.get("name", ""),
        "temporal_status": entity.get("temporal_status", "current"),
        "lifecycle_status": normalize_lifecycle_state(entity.get("lifecycle_status")),
        "lifecycle_score": float(entity.get("lifecycle_score", 0.0) or 0.0),
        "first_seen_at": entity.get("first_seen_at", ""),
        "last_seen_at": entity.get("last_seen_at", ""),
        "mention_count": entity.get("mention_count", 0),
        "confidence": entity.get("confidence", 0.0),
    }


def clear_entity_lifecycle():
    """Reset lifecycle metadata in every stored entity without deleting entities."""
    from memory_entities import load_entity_store, save_entity_store

    store = load_entity_store()
    changed = False

    for entity in store.get("entities", []):
        if not isinstance(entity, dict):
            continue

        first_seen = entity.get("first_seen_at") or entity.get("created_at") or current_timestamp()
        last_seen = entity.get("last_seen_at") or entity.get("updated_at") or first_seen

        if entity.get("first_seen_at") != first_seen:
            entity["first_seen_at"] = first_seen
            changed = True
        if entity.get("last_seen_at") != last_seen:
            entity["last_seen_at"] = last_seen
            changed = True
        if entity.get("lifecycle_status") not in VALID_ENTITY_LIFECYCLE_STATES:
            entity["lifecycle_status"] = determine_entity_lifecycle_state(entity)
            changed = True
        if "lifecycle_score" not in entity:
            entity["lifecycle_score"] = calculate_entity_lifecycle_score(entity)
            changed = True

    if changed:
        save_entity_store(store)

    return changed
