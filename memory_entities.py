import json
import os
import uuid
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document


# ==================================================
# Entity Store Configuration
# ==================================================

ENTITY_FILE = "memory_entities.json"
ENTITY_SCHEMA_VERSION = 4
ENTITY_MAX_COUNT = 5000
ENTITY_MAX_MEMORY_LINKS = 200
ENTITY_MAX_ALIASES = 20
ENTITY_MAX_DESCRIPTION_CHARS = 500
ENTITY_MIN_CONFIDENCE = 0.60
ENTITY_MAX_HISTORY = 20
ENTITY_HISTORY_SOURCE_MAX_CHARS = 500
ENTITY_TEMPORAL_CURRENT = "current"
ENTITY_TEMPORAL_HISTORICAL = "historical"
ENTITY_TEMPORAL_ENDED = "ended"

VALID_ENTITY_TYPES = {
    "PERSON",
    "SOFTWARE",
    "PROJECT",
    "SKILL",
    "TECHNOLOGY",
    "ORGANIZATION",
    "PLACE",
    "GOAL",
    "DOMAIN",
    "PRODUCT",
    "OTHER",
}


# ==================================================
# Time / ID Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def generate_entity_id():
    return f"ent_{uuid.uuid4().hex[:12]}"


def normalize_entity_name(value):
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())


def canonicalize_entity_name(value):
    return normalize_entity_name(value).casefold()


def normalize_entity_type(value):
    if not isinstance(value, str):
        return "OTHER"

    value = value.strip().upper().replace("-", "_")

    aliases = {
        "APP": "SOFTWARE",
        "APPLICATION": "SOFTWARE",
        "TOOL": "SOFTWARE",
        "PROGRAM": "SOFTWARE",
        "TECH": "TECHNOLOGY",
        "COMPANY": "ORGANIZATION",
        "ORG": "ORGANIZATION",
        "OBJECTIVE": "GOAL",
        "SPECIALIZATION": "DOMAIN",
    }

    value = aliases.get(value, value)
    return value if value in VALID_ENTITY_TYPES else "OTHER"


def normalize_confidence(value, default=0.70):
    try:
        value = float(value)
    except (ValueError, TypeError):
        value = default

    return round(max(0.0, min(1.0, value)), 4)


def normalize_aliases(value, canonical_name=""):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        values = []

    canonical = canonicalize_entity_name(canonical_name)
    result = []
    seen = set()

    for alias in values:
        alias = normalize_entity_name(alias)
        if not alias:
            continue

        alias_key = canonicalize_entity_name(alias)
        if alias_key == canonical or alias_key in seen:
            continue

        result.append(alias)
        seen.add(alias_key)

        if len(result) >= ENTITY_MAX_ALIASES:
            break

    return result


def normalize_memory_ids(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []

    result = []
    seen = set()

    for memory_id in value:
        if not isinstance(memory_id, str):
            continue

        memory_id = memory_id.strip()
        if not memory_id or memory_id in seen:
            continue

        result.append(memory_id)
        seen.add(memory_id)

        if len(result) >= ENTITY_MAX_MEMORY_LINKS:
            break

    return result


def normalize_version(value):
    try:
        value = int(value)
    except (ValueError, TypeError):
        value = 1
    return max(1, value)


def normalize_temporal_status(value, default=ENTITY_TEMPORAL_CURRENT):
    if value in {
        ENTITY_TEMPORAL_CURRENT,
        ENTITY_TEMPORAL_HISTORICAL,
        ENTITY_TEMPORAL_ENDED,
    }:
        return value
    return default


def normalize_iso_timestamp(value, fallback=None):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback or current_timestamp()


def parse_entity_time(value):
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text + "T00:00:00+00:00")
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def normalize_entity_history(value, current_name=""):
    if not isinstance(value, list):
        return []

    normalized = []

    for entry in value:
        if not isinstance(entry, dict):
            continue

        # Version 2 stores a wrapper containing the snapshot and event metadata.
        # Earlier intermediate builds could contain the snapshot directly, so
        # accept that shape as a compatibility migration too.
        if isinstance(entry.get("snapshot"), dict):
            snapshot = dict(entry["snapshot"])
            recorded_at = entry.get("recorded_at")
            event = entry.get("event", "CHANGE")
            reason = entry.get("reason", "")
            source_text = entry.get("source_text", "")
            memory_id = entry.get("memory_id", "")
        else:
            snapshot = dict(entry)
            recorded_at = entry.get("recorded_at")
            event = entry.get("event", "CHANGE")
            reason = entry.get("reason", "")
            source_text = entry.get("source_text", "")
            memory_id = entry.get("memory_id", "")

        name = normalize_entity_name(snapshot.get("name", current_name))
        if not name:
            continue

        snapshot_aliases = normalize_aliases(snapshot.get("aliases", []), name)
        snapshot_type = normalize_entity_type(snapshot.get("type", "OTHER"))
        description = str(snapshot.get("description", "") or "").strip()[:ENTITY_MAX_DESCRIPTION_CHARS]

        valid_from = normalize_iso_timestamp(
            snapshot.get("valid_from"),
            fallback=snapshot.get("created_at"),
        )
        valid_to = snapshot.get("valid_to")
        if not isinstance(valid_to, str) or not valid_to.strip():
            valid_to = None

        normalized.append({
            "snapshot": {
                "version": normalize_version(snapshot.get("version", 1)),
                "name": name,
                "canonical_name": canonicalize_entity_name(name),
                "type": snapshot_type,
                "aliases": snapshot_aliases,
                "description": description,
                "confidence": normalize_confidence(snapshot.get("confidence", 0.70)),
                "valid_from": valid_from,
                "valid_to": valid_to,
                "temporal_status": normalize_temporal_status(
                    snapshot.get("temporal_status"),
                    ENTITY_TEMPORAL_HISTORICAL,
                ),
            },
            "recorded_at": normalize_iso_timestamp(recorded_at),
            "event": str(event or "CHANGE").strip().upper(),
            "reason": str(reason or "").strip(),
            "source_text": str(source_text or "").strip()[:ENTITY_HISTORY_SOURCE_MAX_CHARS],
            "memory_id": str(memory_id or "").strip(),
        })

    return normalized[-ENTITY_MAX_HISTORY:]


# ==================================================
# JSON Store
# ==================================================

def _empty_store():
    return {
        "schema_version": ENTITY_SCHEMA_VERSION,
        "updated_at": None,
        "entities": [],
    }


def load_entity_store():
    data = load_json_document(
        ENTITY_FILE,
        _empty_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_store()

    entities = data.get("entities")
    if not isinstance(entities, list):
        entities = []

    normalized = []
    seen_ids = set()

    for entity in entities:
        item = normalize_entity_item(entity)
        if item is None:
            continue
        if item["entity_id"] in seen_ids:
            continue
        normalized.append(item)
        seen_ids.add(item["entity_id"])

    return {
        "schema_version": ENTITY_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "entities": normalized[:ENTITY_MAX_COUNT],
    }


def save_entity_store(store):
    if not isinstance(store, dict):
        store = _empty_store()

    store["schema_version"] = ENTITY_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()

    save_json_document(ENTITY_FILE, store, indent=2)


def normalize_entity_item(item):
    if not isinstance(item, dict):
        return None

    name = normalize_entity_name(item.get("name"))
    if not name:
        return None

    entity_id = normalize_entity_name(item.get("entity_id"))
    if not entity_id:
        entity_id = generate_entity_id()

    entity_type = normalize_entity_type(item.get("type", "OTHER"))
    aliases = normalize_aliases(item.get("aliases", []), name)
    memory_ids = normalize_memory_ids(item.get("memory_ids", []))
    confidence = normalize_confidence(item.get("confidence", 0.70))

    description = item.get("description", "")
    if not isinstance(description, str):
        description = ""
    description = description.strip()[:ENTITY_MAX_DESCRIPTION_CHARS]

    try:
        mention_count = max(0, int(item.get("mention_count", len(memory_ids))))
    except (ValueError, TypeError):
        mention_count = len(memory_ids)

    created_at = item.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        created_at = current_timestamp()

    updated_at = item.get("updated_at")
    if not isinstance(updated_at, str) or not updated_at.strip():
        updated_at = created_at

    entity_chain_id = normalize_entity_name(item.get("entity_chain_id"))
    if not entity_chain_id:
        entity_chain_id = entity_id

    version = normalize_version(item.get("version", 1))
    valid_from = normalize_iso_timestamp(item.get("valid_from"), fallback=created_at)

    valid_to = item.get("valid_to")
    if not isinstance(valid_to, str) or not valid_to.strip():
        valid_to = None

    temporal_status = normalize_temporal_status(
        item.get("temporal_status"),
        ENTITY_TEMPORAL_CURRENT,
    )

    history = normalize_entity_history(item.get("history", []), current_name=name)

    try:
        identity_resolution_count = max(0, int(item.get("identity_resolution_count", 0)))
    except (ValueError, TypeError):
        identity_resolution_count = 0

    identity_resolution_method = str(item.get("identity_resolution_method", "") or "").strip()

    try:
        identity_resolution_score = normalize_confidence(
            item.get("identity_resolution_score", 0.0),
            default=0.0,
        )
    except Exception:
        identity_resolution_score = 0.0

    first_seen_at = item.get("first_seen_at")
    if not isinstance(first_seen_at, str) or not first_seen_at.strip():
        first_seen_at = created_at

    last_seen_at = item.get("last_seen_at")
    if not isinstance(last_seen_at, str) or not last_seen_at.strip():
        last_seen_at = updated_at

    lifecycle_status = str(
        item.get("lifecycle_status", "ACTIVE") or "ACTIVE"
    ).strip().upper()
    if lifecycle_status not in {
        "ACTIVE",
        "AGING",
        "DORMANT",
        "ENDED",
    }:
        lifecycle_status = "ACTIVE"

    try:
        lifecycle_score = float(item.get("lifecycle_score", 0.0))
    except (ValueError, TypeError):
        lifecycle_score = 0.0
    lifecycle_score = round(max(0.0, min(1.0, lifecycle_score)), 4)

    archive_state = str(
        item.get("archive_state", "ACTIVE") or "ACTIVE"
    ).strip().upper()
    if archive_state not in {"ACTIVE", "ARCHIVED"}:
        archive_state = "ACTIVE"

    archived_at = item.get("archived_at")
    if not isinstance(archived_at, str) or not archived_at.strip():
        archived_at = None

    archive_reason = str(item.get("archive_reason", "") or "").strip()[:300]
    pre_archive_lifecycle_status = str(
        item.get("pre_archive_lifecycle_status", "") or ""
    ).strip().upper()

    return {
        "entity_id": entity_id,
        "entity_chain_id": entity_chain_id,
        "version": version,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "temporal_status": temporal_status,
        "history": history,
        "name": name,
        "canonical_name": canonicalize_entity_name(name),
        "type": entity_type,
        "aliases": aliases,
        "description": description,
        "confidence": confidence,
        "mention_count": mention_count,
        "memory_ids": memory_ids,
        "identity_resolution_count": identity_resolution_count,
        "identity_resolution_method": identity_resolution_method,
        "identity_resolution_score": identity_resolution_score,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "lifecycle_status": lifecycle_status,
        "lifecycle_score": lifecycle_score,
        "archive_state": archive_state,
        "archived_at": archived_at,
        "archive_reason": archive_reason,
        "pre_archive_lifecycle_status": pre_archive_lifecycle_status,
        "created_at": created_at,
        "updated_at": updated_at,
    }


# ==================================================
# Entity Retrieval
# ==================================================

def get_all_entities():
    return load_entity_store().get("entities", [])


def _find_entity_by_canonical(canonical_name, entities):
    for entity in entities:
        if entity.get("canonical_name") == canonical_name:
            return entity

        for alias in entity.get("aliases", []):
            if canonicalize_entity_name(alias) == canonical_name:
                return entity

    return None


def _resolve_entity_reference(query):
    if isinstance(query, dict):
        entity_id = normalize_entity_name(query.get("entity_id"))
        if entity_id:
            return next(
                (entity for entity in get_all_entities() if entity.get("entity_id") == entity_id),
                None,
            )
        query = query.get("name", "")

    query = normalize_entity_name(query)
    if not query:
        return None

    for entity in get_all_entities():
        if entity.get("entity_id") == query:
            return entity

    return get_entity(query)


def resolve_entity_identity_query(query):
    """Resolve a user-provided entity name to a stable entity identity."""
    query = normalize_entity_name(query)
    if not query:
        return None

    entities = get_all_entities()

    try:
        from memory_entity_resolution import resolve_entity_identity
        result = resolve_entity_identity(query, entities, "OTHER")
        if result.get("matched"):
            return next(
                (item for item in entities if item.get("entity_id") == result.get("entity_id")),
                None,
            )
    except Exception:
        pass

    return _find_entity_by_canonical(canonicalize_entity_name(query), entities)


def get_entity(query):
    query = normalize_entity_name(query)
    if not query:
        return None

    entities = get_all_entities()
    canonical = canonicalize_entity_name(query)
    exact = _find_entity_by_canonical(canonical, entities)
    if exact:
        return exact

    try:
        from memory_entity_resolution import resolve_entity_identity
        identity_result = resolve_entity_identity(query, entities, "OTHER")
        if identity_result.get("matched"):
            matched = next(
                (item for item in entities if item.get("entity_id") == identity_result.get("entity_id")),
                None,
            )
            if matched is not None:
                return matched
    except Exception:
        pass

    # Conservative fallback: unique substring match only.
    matches = []
    for entity in entities:
        candidates = [entity.get("name", "")] + entity.get("aliases", [])
        for candidate in candidates:
            if canonical in canonicalize_entity_name(candidate):
                matches.append(entity)
                break

    unique = {item.get("entity_id"): item for item in matches}
    return next(iter(unique.values())) if len(unique) == 1 else None


def search_entities(query, max_results=10):
    query = normalize_entity_name(query)
    if not query:
        return []

    query_canonical = canonicalize_entity_name(query)
    query_tokens = set(query_canonical.split())
    results = []

    for entity in get_all_entities():
        candidates = [entity.get("name", "")] + entity.get("aliases", [])
        best_score = 0.0

        for candidate in candidates:
            candidate_canonical = canonicalize_entity_name(candidate)
            candidate_tokens = set(candidate_canonical.split())

            if candidate_canonical == query_canonical:
                score = 1.0
            elif query_canonical in candidate_canonical or candidate_canonical in query_canonical:
                score = 0.85
            elif query_tokens and candidate_tokens:
                overlap = len(query_tokens & candidate_tokens)
                union = len(query_tokens | candidate_tokens)
                score = overlap / union if union else 0.0
            else:
                score = 0.0

            best_score = max(best_score, score)

        if best_score <= 0:
            continue

        results.append({
            **entity,
            "search_score": round(best_score, 4),
        })

    results.sort(
        key=lambda x: (
            x.get("search_score", 0.0),
            x.get("mention_count", 0),
            x.get("confidence", 0.0),
        ),
        reverse=True,
    )

    return results[:max_results]


# ==================================================
# Entity Upsert / Memory Linking
# ==================================================

def _normalize_candidate(candidate):
    if isinstance(candidate, str):
        candidate = {"name": candidate}

    if not isinstance(candidate, dict):
        return None

    name = normalize_entity_name(candidate.get("name"))
    if not name:
        return None

    confidence = normalize_confidence(candidate.get("confidence", 0.70))
    if confidence < ENTITY_MIN_CONFIDENCE:
        return None

    return {
        "name": name,
        "type": normalize_entity_type(candidate.get("type", "OTHER")),
        "aliases": normalize_aliases(candidate.get("aliases", []), name),
        "description": str(candidate.get("description", "") or "").strip()[:ENTITY_MAX_DESCRIPTION_CHARS],
        "confidence": confidence,
    }


def _upsert_entities_impl(candidates, memory_id=None, source_text="", valid_from=""):
    """Insert or link entities through Identity Resolution + Conflict Resolution.

    Identity Resolution finds plausible candidates. Conflict Resolution is the
    final merge gate: only SAME may reuse an existing entity identity.
    POSSIBLE_CONFLICT and DIFFERENT always keep the candidate as a separate
    entity while preserving the conflict record for later review/re-analysis.
    """
    if not isinstance(candidates, list):
        return []

    store = load_entity_store()
    entities = store.get("entities", [])
    linked = []

    for raw in candidates:
        candidate = _normalize_candidate(raw)
        if candidate is None:
            continue

        canonical = canonicalize_entity_name(candidate["name"])

        try:
            from memory_entity_resolution import resolve_entity_identity, record_resolution

            identity_result = resolve_entity_identity(
                candidate["name"],
                entities,
                candidate.get("type", "OTHER"),
            )
        except Exception:
            identity_result = {
                "matched": False,
                "entity_id": "",
                "score": 0.0,
                "method": "resolver_unavailable",
                "matched_name": "",
                "ambiguity": False,
                "best_candidate": {},
                "alternatives": [],
            }

        # --------------------------------------------------
        # Identity Candidate Selection
        # --------------------------------------------------
        # Prefer the resolver's matched entity. When it does not auto-match,
        # still inspect its best candidate so ambiguity/near matches cannot
        # silently fall through to a canonical-name merge.
        identity_entity = None

        if identity_result.get("matched"):
            matched_id = identity_result.get("entity_id")
            identity_entity = next(
                (item for item in entities if item.get("entity_id") == matched_id),
                None,
            )

        if identity_entity is None:
            best_candidate = identity_result.get("best_candidate")
            if isinstance(best_candidate, dict):
                best_id = best_candidate.get("entity_id")
                if best_id:
                    identity_entity = next(
                        (item for item in entities if item.get("entity_id") == best_id),
                        None,
                    )

        # Exact canonical matches are also conflict-checked rather than
        # bypassing the conflict layer. This protects same-name PERSON/ORG
        # entities from accidental merging when the identity resolver is not
        # decisive.
        if identity_entity is None:
            identity_entity = _find_entity_by_canonical(canonical, entities)

        # A best candidate that is below the resolver review threshold is not
        # a meaningful identity candidate at all. Do not create spurious
        # DIFFERENT conflicts against unrelated entities. Exact canonical
        # matches remain eligible for conflict analysis because they can be
        # high-risk same-name collisions.
        identity_score = 0.0
        try:
            identity_score = float(identity_result.get("score", 0.0) or 0.0)
        except (TypeError, ValueError):
            identity_score = 0.0

        is_exact_canonical = identity_entity is not None and (
            canonical == canonicalize_entity_name(identity_entity.get("name", ""))
            or any(
                canonical == canonicalize_entity_name(alias)
                for alias in identity_entity.get("aliases", [])
                if isinstance(alias, str)
            )
        )

        if identity_entity is not None and identity_score < 0.68 and not is_exact_canonical:
            identity_entity = None

        # --------------------------------------------------
        # Archived Entity Recovery
        # --------------------------------------------------
        # Active identity candidates always have priority. Only when no active
        # candidate exists do we inspect the archived identity store. Recovery
        # itself performs Entity Resolution + Conflict Resolution; only SAME
        # can bring the entity back.
        recovered_existing = False
        recovery_result = None

        if identity_entity is None:
            try:
                from memory_entity_recovery import recover_entity_candidate

                recovery_result = recover_entity_candidate(
                    candidate,
                    source_text=source_text,
                    memory_id=memory_id or "",
                    reason="new_evidence",
                )
            except Exception:
                recovery_result = None

            if recovery_result and recovery_result.get("recovered"):
                recovered_id = recovery_result.get("entity", {}).get("entity_id", "")

                refreshed_store = load_entity_store()
                entities = refreshed_store.get("entities", [])

                identity_entity = next(
                    (item for item in entities if item.get("entity_id") == recovered_id),
                    None,
                )
                recovered_existing = identity_entity is not None

        entity = None
        conflict_record = None
        conflict_analysis = None

        # A blocked archived recovery may already have a conflict record.
        # Preserve it so the newly created separate entity can be attached to
        # the same audit record after creation.
        if isinstance(recovery_result, dict):
            conflict_record = recovery_result.get("conflict_record")

        if identity_entity is not None and recovered_existing:
            # Recovery has already passed the conflict gate. Do not create a
            # second conflict record for the same recovery event.
            entity = identity_entity
            identity_resolution = recovery_result.get("identity_result", {}) if isinstance(recovery_result, dict) else {}

            try:
                entity["identity_resolution_count"] = max(
                    0, int(entity.get("identity_resolution_count", 0))
                ) + 1
            except (ValueError, TypeError):
                entity["identity_resolution_count"] = 1

            entity["identity_resolution_method"] = (
                recovery_result.get("analysis", {}).get("method")
                if isinstance(recovery_result, dict) and isinstance(recovery_result.get("analysis"), dict)
                else identity_resolution.get("method", "recovered_identity")
            )
            entity["identity_resolution_score"] = normalize_confidence(
                recovery_result.get("analysis", {}).get("score", identity_resolution.get("score", 0.0))
                if isinstance(recovery_result, dict) and isinstance(recovery_result.get("analysis"), dict)
                else identity_resolution.get("score", 0.0),
                default=0.0,
            )

            try:
                from memory_entity_resolution import record_resolution

                record_resolution(
                    candidate_name=candidate["name"],
                    entity_id=entity.get("entity_id", ""),
                    entity_name=entity.get("name", ""),
                    score=entity.get("identity_resolution_score", 0.0),
                    method=entity.get("identity_resolution_method", "recovered_identity"),
                    source_text=source_text,
                    memory_id=memory_id or "",
                    action="RECOVER",
                )
            except Exception:
                pass

        elif identity_entity is not None:
            try:
                from memory_entity_conflict import (
                    analyze_entity_conflict,
                    record_conflict,
                )

                conflict_analysis = analyze_entity_conflict(
                    candidate,
                    identity_entity,
                    identity_result=identity_result,
                )

                conflict_record = record_conflict(
                    candidate=candidate,
                    entity=identity_entity,
                    analysis=conflict_analysis,
                    identity_result=identity_result,
                    source_text=source_text,
                    memory_id=memory_id or "",
                )
            except Exception:
                # Conflict resolution is a safety gate. If the conflict layer
                # is unavailable, do not merge an existing identity. The safer
                # fallback is to create a separate entity.
                conflict_analysis = {
                    "decision": "POSSIBLE_CONFLICT",
                    "conflict": True,
                    "score": identity_result.get("score", 0.0),
                    "method": "conflict_resolver_unavailable",
                    "reason": "Conflict resolver unavailable; merge denied safely.",
                }

            if conflict_analysis.get("decision") == "SAME":
                entity = identity_entity

                # The resolver's evidence has now passed the conflict gate and
                # may update identity audit metadata.
                try:
                    entity["identity_resolution_count"] = max(
                        0, int(entity.get("identity_resolution_count", 0))
                    ) + 1
                except (ValueError, TypeError):
                    entity["identity_resolution_count"] = 1

                entity["identity_resolution_method"] = conflict_analysis.get(
                    "method",
                    identity_result.get("method", ""),
                )
                entity["identity_resolution_score"] = normalize_confidence(
                    conflict_analysis.get("score", identity_result.get("score", 0.0)),
                    default=0.0,
                )

                try:
                    record_resolution(
                        candidate_name=candidate["name"],
                        entity_id=entity.get("entity_id", ""),
                        entity_name=entity.get("name", ""),
                        score=conflict_analysis.get("score", identity_result.get("score", 0.0)),
                        method=conflict_analysis.get("method", identity_result.get("method", "")),
                        source_text=source_text,
                        memory_id=memory_id or "",
                        action="LINK",
                    )
                except Exception:
                    pass
            else:
                # POSSIBLE_CONFLICT and DIFFERENT are hard merge blockers.
                # Keep the candidate separate and retain the conflict record.
                entity = None

        if entity is None:
            entity = {
                "entity_id": generate_entity_id(),
                "entity_chain_id": "",
                "version": 1,
                "valid_from": normalize_iso_timestamp(valid_from, fallback=current_timestamp()),
                "valid_to": None,
                "temporal_status": ENTITY_TEMPORAL_CURRENT,
                "history": [],
                "name": candidate["name"],
                "canonical_name": canonical,
                "type": candidate["type"],
                "aliases": [],
                "description": candidate["description"],
                "confidence": candidate["confidence"],
                "mention_count": 0,
                "memory_ids": [],
                "identity_resolution_count": 0,
                "identity_resolution_method": "created",
                "identity_resolution_score": 1.0,
                "first_seen_at": current_timestamp(),
                "last_seen_at": current_timestamp(),
                "lifecycle_status": "ACTIVE",
                "lifecycle_score": 1.0,
                "created_at": current_timestamp(),
                "updated_at": current_timestamp(),
            }
            entity["entity_chain_id"] = entity["entity_id"]
            entities.append(entity)

            # Link the new entity to the blocking conflict so later manual or
            # automated review can understand which identity collision caused
            # the split.
            if conflict_record is not None:
                try:
                    from memory_entity_conflict import attach_created_entity
                    attach_created_entity(
                        conflict_record.get("conflict_id", ""),
                        entity.get("entity_id", ""),
                    )
                except Exception:
                    pass
        else:
            entity["confidence"] = max(
                normalize_confidence(entity.get("confidence", 0.0)),
                candidate["confidence"],
            )

            aliases = normalize_aliases(
                entity.get("aliases", []) + candidate["aliases"] + [candidate["name"]],
                entity.get("name", ""),
            )
            entity["aliases"] = aliases

            # Add useful candidate description without overwriting stronger
            # existing information with an empty string.
            if not entity.get("description") and candidate.get("description"):
                entity["description"] = candidate["description"]

        if memory_id and isinstance(memory_id, str):
            memory_id = memory_id.strip()
            memory_ids = normalize_memory_ids(entity.get("memory_ids", []))
            if memory_id not in memory_ids:
                memory_ids.append(memory_id)
                try:
                    current_mentions = int(entity.get("mention_count", 0))
                except (ValueError, TypeError):
                    current_mentions = 0
                entity["mention_count"] = max(0, current_mentions) + 1
            else:
                try:
                    entity["mention_count"] = max(1, int(entity.get("mention_count", 1)))
                except (ValueError, TypeError):
                    entity["mention_count"] = 1
            entity["memory_ids"] = memory_ids[-ENTITY_MAX_MEMORY_LINKS:]

        seen_now = current_timestamp()

        first_seen_at = entity.get("first_seen_at")
        if not isinstance(first_seen_at, str) or not first_seen_at.strip():
            entity["first_seen_at"] = entity.get("created_at") or seen_now

        entity["last_seen_at"] = seen_now
        entity["updated_at"] = seen_now

        linked.append(dict(entity))

    # Keep deterministic order and cap store size.
    entities.sort(
        key=lambda x: (
            -int(x.get("mention_count", 0)),
            -float(x.get("confidence", 0.0)),
            x.get("canonical_name", ""),
        )
    )
    store["entities"] = entities[:ENTITY_MAX_COUNT]
    save_entity_store(store)

    try:
        from memory_entity_lifecycle import update_entity_lifecycle
        update_entity_lifecycle()
        refreshed = load_entity_store().get("entities", [])
        refreshed_map = {
            item.get("entity_id"): item
            for item in refreshed
            if isinstance(item, dict) and item.get("entity_id")
        }
        linked = [
            dict(refreshed_map.get(item.get("entity_id"), item))
            for item in linked
        ]
    except Exception:
        pass

    return linked


def upsert_entities(candidates, memory_id=None, source_text="", valid_from=""):
    """Idempotent public Entity ingestion entry point."""
    from memory_integrity import run_idempotent

    payload = {
        "candidates": candidates if isinstance(candidates, list) else [],
        "memory_id": str(memory_id or "").strip(),
        "source_text": str(source_text or "").strip(),
        "valid_from": str(valid_from or "").strip(),
    }

    result = run_idempotent(
        "ENTITY_INGEST",
        payload,
        lambda: _upsert_entities_impl(
            candidates,
            memory_id=memory_id,
            source_text=source_text,
            valid_from=valid_from,
        ),
    )
    return result.get("result") or []


def link_entities_to_memory(memory_id, candidates, source_text="", valid_from=""):
    if not isinstance(memory_id, str) or not memory_id.strip():
        return []
    return upsert_entities(candidates, memory_id=memory_id.strip(), source_text=source_text, valid_from=valid_from)


def _entity_snapshot(entity, valid_to=None, temporal_status=ENTITY_TEMPORAL_HISTORICAL):
    return {
        "version": normalize_version(entity.get("version", 1)),
        "name": normalize_entity_name(entity.get("name", "")),
        "canonical_name": canonicalize_entity_name(entity.get("name", "")),
        "type": normalize_entity_type(entity.get("type", "OTHER")),
        "aliases": normalize_aliases(entity.get("aliases", []), entity.get("name", "")),
        "description": str(entity.get("description", "") or "").strip()[:ENTITY_MAX_DESCRIPTION_CHARS],
        "confidence": normalize_confidence(entity.get("confidence", 0.70)),
        "valid_from": normalize_iso_timestamp(entity.get("valid_from"), fallback=entity.get("created_at")),
        "valid_to": valid_to,
        "temporal_status": temporal_status,
    }


def evolve_entity(
    entity_query,
    event="CHANGE",
    effective_from="",
    effective_to="",
    new_name="",
    new_type="",
    new_description="",
    aliases_add=None,
    reason="",
    source_text="",
    memory_id=None,
):
    """Apply an explicit temporal change to an entity while preserving history."""
    entity = _resolve_entity_reference(entity_query)
    if entity is None:
        return None

    event = str(event or "CHANGE").strip().upper()
    if event not in {"CHANGE", "END"}:
        return None

    store = load_entity_store()
    stored = next(
        (item for item in store.get("entities", []) if item.get("entity_id") == entity.get("entity_id")),
        None,
    )
    if stored is None:
        return None

    now = current_timestamp()
    change_time = normalize_iso_timestamp(effective_from, fallback=now)
    end_time = normalize_iso_timestamp(effective_to, fallback=change_time) if effective_to else change_time

    history = normalize_entity_history(stored.get("history", []), current_name=stored.get("name", ""))

    previous_snapshot = _entity_snapshot(
        stored,
        valid_to=(end_time if event == "END" else change_time),
        temporal_status=ENTITY_TEMPORAL_HISTORICAL,
    )

    history.append({
        "snapshot": previous_snapshot,
        "recorded_at": now,
        "event": event,
        "reason": str(reason or "").strip(),
        "source_text": str(source_text or "").strip()[:ENTITY_HISTORY_SOURCE_MAX_CHARS],
        "memory_id": str(memory_id or "").strip(),
    })

    stored["history"] = history[-ENTITY_MAX_HISTORY:]
    stored["version"] = normalize_version(stored.get("version", 1)) + 1
    stored["updated_at"] = now

    if event == "END":
        stored["valid_from"] = end_time
        stored["valid_to"] = end_time
        stored["temporal_status"] = ENTITY_TEMPORAL_ENDED
    else:
        stored["valid_from"] = change_time
        stored["valid_to"] = None
        stored["temporal_status"] = ENTITY_TEMPORAL_CURRENT

        old_name = normalize_entity_name(stored.get("name", ""))
        if isinstance(new_name, str) and new_name.strip():
            canonical_new = canonicalize_entity_name(new_name)
            if canonical_new != canonicalize_entity_name(old_name):
                stored["aliases"] = normalize_aliases(
                    stored.get("aliases", []) + [old_name],
                    normalize_entity_name(new_name),
                )
                stored["name"] = normalize_entity_name(new_name)
                stored["canonical_name"] = canonical_new

        if isinstance(new_type, str) and new_type.strip():
            normalized_type = normalize_entity_type(new_type)
            if normalized_type != "OTHER":
                stored["type"] = normalized_type

        if isinstance(new_description, str) and new_description.strip():
            stored["description"] = new_description.strip()[:ENTITY_MAX_DESCRIPTION_CHARS]

        if isinstance(aliases_add, list):
            stored["aliases"] = normalize_aliases(
                stored.get("aliases", []) + aliases_add,
                stored.get("name", ""),
            )

    now = current_timestamp()
    stored["last_seen_at"] = now
    stored["updated_at"] = now

    if event == "END":
        stored["lifecycle_status"] = "ENDED"
        stored["lifecycle_score"] = 0.20
    else:
        stored["lifecycle_status"] = "ACTIVE"

    store["entities"] = [
        stored if item.get("entity_id") == stored.get("entity_id") else item
        for item in store.get("entities", [])
    ]
    save_entity_store(store)

    try:
        from memory_entity_lifecycle import update_entity_lifecycle
        update_entity_lifecycle()
        refreshed = load_entity_store().get("entities", [])
        stored = next(
            (item for item in refreshed if item.get("entity_id") == stored.get("entity_id")),
            stored,
        )
    except Exception:
        pass

    return dict(stored)


def get_entity_history(query, include_current=True):
    entity = _resolve_entity_reference(query)
    if entity is None:
        return []

    history = []
    for entry in normalize_entity_history(entity.get("history", []), current_name=entity.get("name", "")):
        snapshot = dict(entry.get("snapshot", {}))
        snapshot["recorded_at"] = entry.get("recorded_at")
        snapshot["event"] = entry.get("event", "CHANGE")
        snapshot["reason"] = entry.get("reason", "")
        snapshot["source_text"] = entry.get("source_text", "")
        snapshot["memory_id"] = entry.get("memory_id", "")
        snapshot["entity_id"] = entity.get("entity_id")
        snapshot["entity_chain_id"] = entity.get("entity_chain_id", entity.get("entity_id"))
        history.append(snapshot)

    if include_current:
        history.append({
            "version": normalize_version(entity.get("version", 1)),
            "name": entity.get("name", ""),
            "canonical_name": entity.get("canonical_name", ""),
            "type": entity.get("type", "OTHER"),
            "aliases": list(entity.get("aliases", [])),
            "description": entity.get("description", ""),
            "confidence": normalize_confidence(entity.get("confidence", 0.70)),
            "valid_from": entity.get("valid_from"),
            "valid_to": entity.get("valid_to"),
            "temporal_status": entity.get("temporal_status", ENTITY_TEMPORAL_CURRENT),
            "recorded_at": entity.get("updated_at"),
            "event": "CURRENT",
            "reason": "current entity state",
            "source_text": "",
            "memory_id": "",
            "entity_id": entity.get("entity_id"),
            "entity_chain_id": entity.get("entity_chain_id", entity.get("entity_id")),
        })

    history.sort(
        key=lambda item: (
            parse_entity_time(item.get("valid_from"))
            or datetime.min.replace(tzinfo=timezone.utc),
            item.get("version", 1),
        )
    )
    return history


def entity_temporal_interval_contains(snapshot, target_datetime):
    start = parse_entity_time(snapshot.get("valid_from"))
    if start is None:
        return False

    end = parse_entity_time(snapshot.get("valid_to"))
    if target_datetime < start:
        return False
    if end is not None and target_datetime > end:
        return False

    return True


def get_entity_as_of(query, target_time):
    parsed_target = parse_entity_time(target_time)
    if parsed_target is None:
        return None

    history = get_entity_history(query, include_current=True)
    candidates = [
        item for item in history
        if entity_temporal_interval_contains(item, parsed_target)
    ]

    if not candidates:
        return None

    candidates.sort(key=lambda item: item.get("version", 1), reverse=True)
    return candidates[0]


def remove_memory_reference(memory_id):
    if not isinstance(memory_id, str) or not memory_id.strip():
        return False

    memory_id = memory_id.strip()
    store = load_entity_store()
    changed = False

    for entity in store.get("entities", []):
        old_ids = entity.get("memory_ids", [])
        new_ids = [item for item in old_ids if item != memory_id]
        if new_ids != old_ids:
            entity["memory_ids"] = new_ids
            entity["updated_at"] = current_timestamp()
            changed = True

    if changed:
        save_entity_store(store)

    return changed


def prune_memory_references(valid_memory_ids):
    valid_memory_ids = set(
        item.strip()
        for item in valid_memory_ids
        if isinstance(item, str) and item.strip()
    )

    store = load_entity_store()
    changed = False

    for entity in store.get("entities", []):
        old_ids = normalize_memory_ids(entity.get("memory_ids", []))
        new_ids = [item for item in old_ids if item in valid_memory_ids]
        if new_ids != old_ids:
            entity["memory_ids"] = new_ids
            entity["updated_at"] = current_timestamp()
            changed = True

    if changed:
        save_entity_store(store)

    return changed


def get_entities_for_memory(memory_id):
    if not isinstance(memory_id, str) or not memory_id.strip():
        return []

    memory_id = memory_id.strip()
    return [
        entity
        for entity in get_all_entities()
        if memory_id in entity.get("memory_ids", [])
    ]


def mark_entities_seen_for_memory(memory_id, seen_at=None):
    """Reinforce active entities linked to a memory that became current again."""
    if not isinstance(memory_id, str) or not memory_id.strip():
        return 0

    linked_entities = get_entities_for_memory(memory_id.strip())
    if not linked_entities:
        return 0

    try:
        from memory_entity_lifecycle import mark_entity_seen
    except Exception:
        return 0

    changed = 0
    for entity in linked_entities:
        entity_id = entity.get("entity_id") if isinstance(entity, dict) else ""
        if not entity_id:
            continue
        if mark_entity_seen(entity_id, seen_at=seen_at) is not None:
            changed += 1

    return changed


def clear_entities():
    save_entity_store(_empty_store())

    return True
