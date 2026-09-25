import json
import os
import uuid
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document


# ==================================================
# Entity Conflict Resolution Configuration
# ==================================================

CONFLICT_FILE = "memory_entity_conflicts.json"
CONFLICT_SCHEMA_VERSION = 1
CONFLICT_MAX_COUNT = 5000

DECISION_SAME = "SAME"
DECISION_POSSIBLE_CONFLICT = "POSSIBLE_CONFLICT"
DECISION_DIFFERENT = "DIFFERENT"
VALID_DECISIONS = {
    DECISION_SAME,
    DECISION_POSSIBLE_CONFLICT,
    DECISION_DIFFERENT,
}

STATUS_ACTIVE = "ACTIVE"
STATUS_RESOLVED = "RESOLVED"
STATUS_DISMISSED = "DISMISSED"
VALID_STATUSES = {
    STATUS_ACTIVE,
    STATUS_RESOLVED,
    STATUS_DISMISSED,
}

# Names that usually add a description to a known software/tool identity
# without creating a second identity by themselves.
GENERIC_IDENTITY_TERMS = {
    "software",
    "tool",
    "app",
    "application",
    "program",
    "platform",
    "system",
    "fea",
    "cae",
    "language",
    "programming",
    "programming_language",
}

# Same-name collisions are inherently risky for these entity types. Name
# similarity alone should not collapse two such entities into one identity.
NAME_COLLISION_TYPES = {
    "PERSON",
    "ORGANIZATION",
    "PLACE",
}


# ==================================================
# Time / Normalization Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value):
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().casefold().split())


def normalize_type(value):
    if not isinstance(value, str):
        return "OTHER"
    return value.strip().upper() or "OTHER"


def normalize_decision(value):
    decision = str(value or "").strip().upper()
    if decision not in VALID_DECISIONS:
        return DECISION_POSSIBLE_CONFLICT
    return decision


def normalize_status(value):
    status = str(value or "").strip().upper()
    if status not in VALID_STATUSES:
        return STATUS_ACTIVE
    return status


def _canonical_name(value):
    return normalize_text(value)


def _core_name(value):
    """Return a conservative core name for generic descriptive modifiers."""
    tokens = _canonical_name(value).replace("-", " ").split()
    tokens = [token for token in tokens if token not in GENERIC_IDENTITY_TERMS]
    return " ".join(tokens)


def _entity_name_candidates(entity):
    if not isinstance(entity, dict):
        return []

    values = [entity.get("name", "")]
    aliases = entity.get("aliases", [])
    if isinstance(aliases, list):
        values.extend(aliases)

    return [value for value in values if isinstance(value, str) and value.strip()]


def _same_name_or_alias(candidate_name, entity):
    query = _canonical_name(candidate_name)
    return bool(query) and any(
        _canonical_name(name) == query
        for name in _entity_name_candidates(entity)
    )


def _type_compatible(candidate_type, entity_type):
    candidate_type = normalize_type(candidate_type)
    entity_type = normalize_type(entity_type)
    if candidate_type == "OTHER" or entity_type == "OTHER":
        return True
    return candidate_type == entity_type


# ==================================================
# Conflict Store
# ==================================================

def _empty_store():
    return {
        "schema_version": CONFLICT_SCHEMA_VERSION,
        "updated_at": None,
        "conflicts": [],
    }


def _normalize_record(record):
    if not isinstance(record, dict):
        return None

    conflict_id = str(record.get("conflict_id", "") or "").strip()
    if not conflict_id:
        conflict_id = f"ecf_{uuid.uuid4().hex[:12]}"

    decision = normalize_decision(record.get("decision"))
    status = normalize_status(record.get("status"))

    created_at = record.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        created_at = current_timestamp()

    updated_at = record.get("updated_at")
    if not isinstance(updated_at, str) or not updated_at.strip():
        updated_at = created_at

    identity_resolution = record.get("identity_resolution", {})
    if not isinstance(identity_resolution, dict):
        identity_resolution = {}

    return {
        "conflict_id": conflict_id,
        "candidate_name": str(record.get("candidate_name", "") or "").strip(),
        "candidate_type": normalize_type(record.get("candidate_type", "OTHER")),
        "candidate": record.get("candidate") if isinstance(record.get("candidate"), dict) else {},
        "entity_id": str(record.get("entity_id", "") or "").strip(),
        "entity_name": str(record.get("entity_name", "") or "").strip(),
        "entity_type": normalize_type(record.get("entity_type", "OTHER")),
        "entity_snapshot": record.get("entity_snapshot") if isinstance(record.get("entity_snapshot"), dict) else {},
        "decision": decision,
        "status": status,
        "score": round(float(record.get("score", 0.0) or 0.0), 4),
        "method": str(record.get("method", "") or "").strip(),
        "reason": str(record.get("reason", "") or "").strip()[:1000],
        "source_text": str(record.get("source_text", "") or "").strip()[:1000],
        "memory_id": str(record.get("memory_id", "") or "").strip(),
        "identity_resolution": identity_resolution,
        "created_entity_id": str(record.get("created_entity_id", "") or "").strip(),
        "resolution_reason": str(record.get("resolution_reason", "") or "").strip()[:1000],
        "created_at": created_at,
        "updated_at": updated_at,
    }


def load_conflict_store():
    data = load_json_document(
        CONFLICT_FILE,
        _empty_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_store()

    raw_conflicts = data.get("conflicts", [])
    if not isinstance(raw_conflicts, list):
        raw_conflicts = []

    normalized = []
    seen = set()

    for item in raw_conflicts:
        normalized_item = _normalize_record(item)
        if normalized_item is None:
            continue
        conflict_id = normalized_item["conflict_id"]
        if conflict_id in seen:
            continue
        normalized.append(normalized_item)
        seen.add(conflict_id)

    return {
        "schema_version": CONFLICT_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "conflicts": normalized[-CONFLICT_MAX_COUNT:],
    }


def save_conflict_store(store):
    if not isinstance(store, dict):
        store = _empty_store()

    conflicts = store.get("conflicts", [])
    if not isinstance(conflicts, list):
        conflicts = []

    store["schema_version"] = CONFLICT_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()
    store["conflicts"] = conflicts[-CONFLICT_MAX_COUNT:]

    save_json_document(CONFLICT_FILE, store, indent=2)


def _same_pair(record, candidate_name, entity_id):
    return (
        _canonical_name(record.get("candidate_name")) == _canonical_name(candidate_name)
        and str(record.get("entity_id", "") or "") == str(entity_id or "")
    )


# ==================================================
# Conflict Analysis
# ==================================================

def analyze_entity_conflict(
    candidate,
    entity,
    identity_result=None,
):
    """Classify whether an identity match is safe to merge.

    The resolver supplies similarity evidence; this layer decides whether that
    evidence is strong enough to establish identity. Similarity by itself is
    never treated as proof.
    """
    if not isinstance(candidate, dict) or not isinstance(entity, dict):
        return {
            "decision": DECISION_DIFFERENT,
            "conflict": True,
            "score": 0.0,
            "method": "invalid_input",
            "reason": "Missing candidate or entity data.",
        }

    if not isinstance(identity_result, dict):
        identity_result = {}

    candidate_name = str(candidate.get("name", "") or "").strip()
    entity_name = str(entity.get("name", "") or "").strip()
    candidate_type = normalize_type(candidate.get("type", "OTHER"))
    entity_type = normalize_type(entity.get("type", "OTHER"))

    score = 0.0
    try:
        score = max(0.0, min(1.0, float(identity_result.get("score", 0.0) or 0.0)))
    except (TypeError, ValueError):
        score = 0.0

    method = str(identity_result.get("method", "") or "").strip() or "identity_evidence"
    ambiguous = bool(identity_result.get("ambiguity", False))
    exact_name = _same_name_or_alias(candidate_name, entity)
    core_equal = bool(candidate_name and _core_name(candidate_name) == _core_name(entity_name))
    type_compatible = _type_compatible(candidate_type, entity_type)

    # A known type mismatch is strong evidence that two similar names refer to
    # different entities. Do not let an embedding score override this.
    if not type_compatible:
        return {
            "decision": DECISION_DIFFERENT,
            "conflict": True,
            "score": round(score, 4),
            "method": "type_mismatch",
            "reason": f"Candidate type {candidate_type} is incompatible with entity type {entity_type}.",
            "exact_name": exact_name,
            "core_equal": core_equal,
            "ambiguous": ambiguous,
        }

    # Ambiguity is never permission to merge.
    if ambiguous:
        return {
            "decision": DECISION_POSSIBLE_CONFLICT,
            "conflict": True,
            "score": round(score, 4),
            "method": "ambiguous_identity",
            "reason": "Multiple identity candidates remain too close to establish a safe identity merge.",
            "exact_name": exact_name,
            "core_equal": core_equal,
            "ambiguous": True,
        }

    # Same-name collisions are particularly dangerous for people and other
    # real-world named entities where two distinct identities can share a name.
    if exact_name and candidate_type == entity_type in NAME_COLLISION_TYPES:
        return {
            "decision": DECISION_POSSIBLE_CONFLICT,
            "conflict": True,
            "score": round(score, 4),
            "method": "same_name_collision",
            "reason": "The names match exactly, but name equality alone is insufficient to establish identity for this entity type.",
            "exact_name": True,
            "core_equal": core_equal,
            "ambiguous": ambiguous,
        }

    # Explicitly descriptive software variants such as "Python programming
    # language" or "Abaqus FEA" can safely reuse the same core identity when
    # their type is compatible.
    if core_equal and type_compatible and score >= 0.68:
        return {
            "decision": DECISION_SAME,
            "conflict": False,
            "score": round(max(score, 0.90), 4),
            "method": "compatible_core_identity",
            "reason": "The candidate and entity share the same conservative identity core and compatible entity type.",
            "exact_name": exact_name,
            "core_equal": True,
            "ambiguous": ambiguous,
        }

    # Very strong identity evidence is enough when the types are compatible
    # and there is no collision signal.
    if score >= 0.92 and type_compatible:
        return {
            "decision": DECISION_SAME,
            "conflict": False,
            "score": round(score, 4),
            "method": "strong_identity_match",
            "reason": "High-confidence identity evidence with compatible entity type.",
            "exact_name": exact_name,
            "core_equal": core_equal,
            "ambiguous": ambiguous,
        }

    # Moderate similarity is useful evidence but not identity proof.
    if score >= 0.68:
        return {
            "decision": DECISION_POSSIBLE_CONFLICT,
            "conflict": True,
            "score": round(score, 4),
            "method": "similarity_without_identity_proof",
            "reason": "The names are similar enough to warrant a conflict record, but the evidence is insufficient for automatic merge.",
            "exact_name": exact_name,
            "core_equal": core_equal,
            "ambiguous": ambiguous,
        }

    return {
        "decision": DECISION_DIFFERENT,
        "conflict": True,
        "score": round(score, 4),
        "method": "insufficient_identity_evidence",
        "reason": "The available identity evidence is too weak to treat the candidate as the existing entity.",
        "exact_name": exact_name,
        "core_equal": core_equal,
        "ambiguous": ambiguous,
    }


# ==================================================
# Conflict Recording / Resolution
# ==================================================

def _record_conflict_impl(
    candidate,
    entity,
    analysis,
    identity_result=None,
    source_text="",
    memory_id="",
    created_entity_id="",
):
    if not isinstance(candidate, dict) or not isinstance(entity, dict):
        return None

    if not isinstance(analysis, dict):
        return None

    decision = normalize_decision(analysis.get("decision"))
    entity_id = str(entity.get("entity_id", "") or "").strip()
    candidate_name = str(candidate.get("name", "") or "").strip()

    store = load_conflict_store()
    now = current_timestamp()

    existing = None
    for item in store["conflicts"]:
        if _same_pair(item, candidate_name, entity_id):
            # A conflict is one durable record for one candidate/entity pair.
            # Re-analysis must be able to reopen a previously RESOLVED or
            # DISMISSED record instead of creating a second parallel record.
            existing = item
            break

    if existing is not None:
        existing.update({
            "candidate_name": candidate_name,
            "candidate_type": normalize_type(candidate.get("type", "OTHER")),
            "candidate": dict(candidate),
            "entity_id": entity_id,
            "entity_name": str(entity.get("name", "") or "").strip(),
            "entity_type": normalize_type(entity.get("type", "OTHER")),
            "entity_snapshot": dict(entity),
            "decision": decision,
            "status": STATUS_RESOLVED if decision == DECISION_SAME else STATUS_ACTIVE,
            "score": round(float(analysis.get("score", 0.0) or 0.0), 4),
            "method": str(analysis.get("method", "") or "").strip(),
            "reason": str(analysis.get("reason", "") or "").strip()[:1000],
            "source_text": str(source_text or "").strip()[:1000],
            "memory_id": str(memory_id or "").strip(),
            "identity_resolution": identity_result if isinstance(identity_result, dict) else {},
            "created_entity_id": str(created_entity_id or existing.get("created_entity_id", "") or "").strip(),
            "resolution_reason": "safe_identity_match" if decision == DECISION_SAME else "",
            "updated_at": now,
        })
        save_conflict_store(store)
        return dict(existing)

    record = {
        "conflict_id": f"ecf_{uuid.uuid4().hex[:12]}",
        "candidate_name": candidate_name,
        "candidate_type": normalize_type(candidate.get("type", "OTHER")),
        "candidate": dict(candidate),
        "entity_id": entity_id,
        "entity_name": str(entity.get("name", "") or "").strip(),
        "entity_type": normalize_type(entity.get("type", "OTHER")),
        "entity_snapshot": dict(entity),
        "decision": decision,
        "status": STATUS_RESOLVED if decision == DECISION_SAME else STATUS_ACTIVE,
        "score": round(float(analysis.get("score", 0.0) or 0.0), 4),
        "method": str(analysis.get("method", "") or "").strip(),
        "reason": str(analysis.get("reason", "") or "").strip()[:1000],
        "source_text": str(source_text or "").strip()[:1000],
        "memory_id": str(memory_id or "").strip(),
        "identity_resolution": identity_result if isinstance(identity_result, dict) else {},
        "created_entity_id": str(created_entity_id or "").strip(),
        "resolution_reason": "" if decision != DECISION_SAME else "safe_identity_match",
        "created_at": now,
        "updated_at": now,
    }

    store["conflicts"].append(record)
    save_conflict_store(store)
    return dict(record)


def record_conflict(
    candidate,
    entity,
    analysis,
    identity_result=None,
    source_text="",
    memory_id="",
    created_entity_id="",
):
    """Record one conflict analysis idempotently for the same evidence."""
    from memory_integrity import run_idempotent

    if not isinstance(candidate, dict) or not isinstance(entity, dict):
        return None
    if not isinstance(analysis, dict):
        return None

    payload = {
        "candidate_name": str(candidate.get("name", "") or "").strip(),
        "entity_id": str(entity.get("entity_id", "") or "").strip(),
        "memory_id": str(memory_id or "").strip(),
        "source_text": str(source_text or "").strip(),
        "decision": normalize_decision(analysis.get("decision")),
        "score": round(float(analysis.get("score", 0.0) or 0.0), 4),
        "method": str(analysis.get("method", "") or "").strip(),
        "created_entity_id": str(created_entity_id or "").strip(),
    }

    result = run_idempotent(
        "CONFLICT_RECORD",
        payload,
        lambda: _record_conflict_impl(
            candidate=candidate,
            entity=entity,
            analysis=analysis,
            identity_result=identity_result,
            source_text=source_text,
            memory_id=memory_id,
            created_entity_id=created_entity_id,
        ),
    )
    return result.get("result")


def get_conflict(conflict_id):
    conflict_id = str(conflict_id or "").strip()
    if not conflict_id:
        return None

    for item in load_conflict_store().get("conflicts", []):
        if item.get("conflict_id") == conflict_id:
            return item
    return None


def get_conflicts(query="", status=None, decisions=None, max_results=50):
    query = str(query or "").strip().casefold()
    status_filter = str(status or "").strip().upper()

    if status_filter and status_filter not in VALID_STATUSES:
        status_filter = ""

    if isinstance(decisions, str):
        decisions = [decisions]

    decision_filter = {
        normalize_decision(item)
        for item in decisions
        if str(item or "").strip()
    } if isinstance(decisions, list) else set()

    records = load_conflict_store().get("conflicts", [])
    results = []

    for item in records:
        if status_filter and item.get("status") != status_filter:
            continue
        if decision_filter and item.get("decision") not in decision_filter:
            continue

        if query:
            haystack = " ".join([
                str(item.get("conflict_id", "")),
                str(item.get("candidate_name", "")),
                str(item.get("entity_name", "")),
                str(item.get("reason", "")),
                str(item.get("source_text", "")),
            ]).casefold()
            if query not in haystack:
                continue

        results.append(item)

    return list(reversed(results[-max_results:]))


def update_conflict_status(
    conflict_id,
    status,
    reason="",
    decision=None,
):
    status = normalize_status(status)
    conflict_id = str(conflict_id or "").strip()
    if not conflict_id:
        return None

    store = load_conflict_store()
    for item in store.get("conflicts", []):
        if item.get("conflict_id") != conflict_id:
            continue

        item["status"] = status
        if decision is not None:
            item["decision"] = normalize_decision(decision)
        if reason:
            item["resolution_reason"] = str(reason).strip()[:1000]
        item["updated_at"] = current_timestamp()
        save_conflict_store(store)
        return dict(item)

    return None


def resolve_conflict(conflict_id, reason="manual_resolution"):
    """Mark an active conflict as resolved without changing the entities."""
    return update_conflict_status(
        conflict_id,
        STATUS_RESOLVED,
        reason=reason,
    )


def dismiss_conflict(conflict_id, reason="manual_dismissal"):
    return update_conflict_status(
        conflict_id,
        STATUS_DISMISSED,
        reason=reason,
    )


def _reanalyze_conflict_impl(
    conflict_id,
    identity_result=None,
    source_text=None,
    memory_id=None,
):
    """Re-run conflict analysis against the stored candidate/entity pair."""
    record = get_conflict(conflict_id)
    if record is None:
        return None

    candidate = record.get("candidate", {})
    entity = record.get("entity_snapshot", {})

    if not isinstance(candidate, dict) or not isinstance(entity, dict):
        return None

    if identity_result is None:
        stored_identity = record.get("identity_resolution", {})
        identity_result = stored_identity if isinstance(stored_identity, dict) else {}

    analysis = analyze_entity_conflict(
        candidate,
        entity,
        identity_result=identity_result,
    )

    updated = record_conflict(
        candidate=candidate,
        entity=entity,
        analysis=analysis,
        identity_result=identity_result,
        source_text=record.get("source_text", "") if source_text is None else source_text,
        memory_id=record.get("memory_id", "") if memory_id is None else memory_id,
        created_entity_id=record.get("created_entity_id", ""),
    )

    if updated is None:
        return None

    # Preserve the original conflict ID when an older record is being
    # re-analyzed and record_conflict had to create a replacement record.
    if updated.get("conflict_id") != conflict_id:
        store = load_conflict_store()
        replacement = next(
            (item for item in store["conflicts"] if item.get("conflict_id") == updated.get("conflict_id")),
            None,
        )
        if replacement is not None:
            replacement["conflict_id"] = conflict_id
            replacement["updated_at"] = current_timestamp()
            save_conflict_store(store)
            updated = dict(replacement)

    return updated


def reanalyze_conflict(
    conflict_id,
    identity_result=None,
    source_text=None,
    memory_id=None,
):
    """Idempotently re-run one conflict analysis for one evidence snapshot."""
    record = get_conflict(conflict_id)
    if record is None:
        return None

    stored_identity = record.get("identity_resolution", {})
    effective_identity = identity_result if identity_result is not None else stored_identity
    payload = {
        "conflict_id": str(conflict_id or "").strip(),
        "identity_result": effective_identity if isinstance(effective_identity, dict) else {},
        "source_text": record.get("source_text", "") if source_text is None else source_text,
        "memory_id": record.get("memory_id", "") if memory_id is None else memory_id,
    }

    result = run_idempotent(
        "CONFLICT_REANALYZE",
        payload,
        lambda: _reanalyze_conflict_impl(
            conflict_id,
            identity_result=identity_result,
            source_text=source_text,
            memory_id=memory_id,
        ),
    )
    return result.get("result")


def attach_created_entity(conflict_id, created_entity_id):
    conflict_id = str(conflict_id or "").strip()
    created_entity_id = str(created_entity_id or "").strip()
    if not conflict_id or not created_entity_id:
        return None

    store = load_conflict_store()
    for item in store.get("conflicts", []):
        if item.get("conflict_id") != conflict_id:
            continue
        item["created_entity_id"] = created_entity_id
        item["updated_at"] = current_timestamp()
        save_conflict_store(store)
        return dict(item)

    return None


def clear_conflicts():
    save_conflict_store(_empty_store())
    return True
