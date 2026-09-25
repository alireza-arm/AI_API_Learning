import json
import os
import uuid
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document


# ==================================================
# Entity Recovery Configuration
# ==================================================

ENTITY_RECOVERY_FILE = "memory_entity_recovery.json"
ENTITY_RECOVERY_SCHEMA_VERSION = 1
ENTITY_RECOVERY_MAX_LOG = 5000

RECOVERY_SAME = "SAME"
RECOVERY_POSSIBLE_CONFLICT = "POSSIBLE_CONFLICT"
RECOVERY_DIFFERENT = "DIFFERENT"

RECOVERY_MAX_CANDIDATES = 5
RECOVERY_MIN_SCORE = 0.68

RECOVERY_STATUS_RECOVERED = "RECOVERED"
RECOVERY_STATUS_BLOCKED = "BLOCKED"
RECOVERY_STATUS_NOT_FOUND = "NOT_FOUND"


# ==================================================
# Time Helpers
# ==================================================


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


# ==================================================
# Recovery Audit Store
# ==================================================


def _empty_store():
    return {
        "schema_version": ENTITY_RECOVERY_SCHEMA_VERSION,
        "updated_at": None,
        "recoveries": [],
    }


def load_recovery_store():
    data = load_json_document(
        ENTITY_RECOVERY_FILE,
        _empty_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_store()

    recoveries = data.get("recoveries")
    if not isinstance(recoveries, list):
        recoveries = []

    normalized = []
    for item in recoveries[-ENTITY_RECOVERY_MAX_LOG:]:
        if not isinstance(item, dict):
            continue
        normalized.append(dict(item))

    return {
        "schema_version": ENTITY_RECOVERY_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "recoveries": normalized,
    }


def save_recovery_store(store):
    if not isinstance(store, dict):
        store = _empty_store()

    store["schema_version"] = ENTITY_RECOVERY_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()
    store["recoveries"] = list(store.get("recoveries", []))[-ENTITY_RECOVERY_MAX_LOG:]

    save_json_document(ENTITY_RECOVERY_FILE, store, indent=2)


def _record_recovery_attempt_impl(
    candidate,
    archived_entity,
    identity_result,
    decision,
    status,
    reason,
    source_text="",
    memory_id="",
):
    candidate = candidate if isinstance(candidate, dict) else {}
    archived_entity = archived_entity if isinstance(archived_entity, dict) else {}
    identity_result = identity_result if isinstance(identity_result, dict) else {}

    store = load_recovery_store()
    record = {
        "recovery_id": f"erc_{uuid.uuid4().hex[:12]}",
        "candidate_name": str(candidate.get("name", "") or "").strip(),
        "candidate_type": str(candidate.get("type", "OTHER") or "OTHER").strip().upper(),
        "entity_id": str(archived_entity.get("entity_id", "") or "").strip(),
        "entity_name": str(archived_entity.get("name", "") or "").strip(),
        "decision": str(decision or "").strip().upper(),
        "status": str(status or "").strip().upper(),
        "score": round(float(identity_result.get("score", 0.0) or 0.0), 4),
        "method": str(identity_result.get("method", "") or "").strip(),
        "reason": str(reason or "").strip()[:1000],
        "source_text": str(source_text or "").strip()[:1000],
        "memory_id": str(memory_id or "").strip(),
        "timestamp": current_timestamp(),
    }

    store["recoveries"].append(record)
    save_recovery_store(store)
    return record


def record_recovery_attempt(
    candidate,
    archived_entity,
    identity_result,
    decision,
    status,
    reason,
    source_text="",
    memory_id="",
):
    """Persist a recovery audit event once for one logical attempt."""
    from memory_integrity import run_idempotent

    payload = {
        "candidate_name": str((candidate or {}).get("name", "") if isinstance(candidate, dict) else "").strip(),
        "candidate_type": str((candidate or {}).get("type", "OTHER") if isinstance(candidate, dict) else "OTHER").strip().upper(),
        "entity_id": str((archived_entity or {}).get("entity_id", "") if isinstance(archived_entity, dict) else "").strip(),
        "decision": str(decision or "").strip().upper(),
        "status": str(status or "").strip().upper(),
        "source_text": str(source_text or "").strip(),
        "memory_id": str(memory_id or "").strip(),
        "reason": str(reason or "").strip(),
    }
    result = run_idempotent(
        "RECOVERY_AUDIT",
        payload,
        lambda: _record_recovery_attempt_impl(
            candidate=candidate,
            archived_entity=archived_entity,
            identity_result=identity_result,
            decision=decision,
            status=status,
            reason=reason,
            source_text=source_text,
            memory_id=memory_id,
        ),
    )
    return result.get("result")


def get_recovery_history(query="", max_results=50):
    query = str(query or "").strip().casefold()
    records = load_recovery_store().get("recoveries", [])

    if query:
        records = [
            item
            for item in records
            if query in str(item.get("candidate_name", "")).casefold()
            or query in str(item.get("entity_name", "")).casefold()
            or query in str(item.get("entity_id", "")).casefold()
            or query in str(item.get("source_text", "")).casefold()
        ]

    return list(reversed(records[-max_results:]))


def clear_recovery_history():
    save_recovery_store(_empty_store())
    return True


# ==================================================
# Candidate Retrieval
# ==================================================


def find_archived_recovery_candidate(candidate, max_results=RECOVERY_MAX_CANDIDATES):
    """Find the strongest archived entity candidate using existing Resolution."""
    if not isinstance(candidate, dict):
        return None, {
            "matched": False,
            "score": 0.0,
            "method": "invalid_candidate",
            "ambiguity": False,
        }

    name = str(candidate.get("name", "") or "").strip()
    candidate_type = str(candidate.get("type", "OTHER") or "OTHER").strip().upper()
    if not name:
        return None, {
            "matched": False,
            "score": 0.0,
            "method": "empty_candidate",
            "ambiguity": False,
        }

    from memory_entity_archive import get_archived_entities
    from memory_entity_resolution import resolve_entity_identity

    archived_entities = get_archived_entities()
    if not archived_entities:
        return None, {
            "matched": False,
            "score": 0.0,
            "method": "archive_empty",
            "ambiguity": False,
        }

    identity_result = resolve_entity_identity(
        name,
        archived_entities,
        candidate_type,
    )

    score = float(identity_result.get("score", 0.0) or 0.0)
    best = identity_result.get("best_candidate")

    if not isinstance(best, dict):
        return None, identity_result

    entity_id = str(best.get("entity_id", "") or "").strip()
    if not entity_id:
        return None, identity_result

    archived_entity = next(
        (item for item in archived_entities if item.get("entity_id") == entity_id),
        None,
    )

    if archived_entity is None:
        return None, identity_result

    # A weak candidate is not considered a recovery attempt. This prevents
    # unrelated archived entities from being treated as recovery targets.
    if score < RECOVERY_MIN_SCORE and not identity_result.get("matched"):
        return None, identity_result

    identity_result = dict(identity_result)
    identity_result["recovery_candidate"] = True
    identity_result["archived_candidates_checked"] = min(
        len(archived_entities),
        max(1, int(max_results)),
    )

    return archived_entity, identity_result


# ==================================================
# Recovery Gate
# ==================================================


def _recover_entity_candidate_impl(
    candidate,
    source_text="",
    memory_id="",
    reason="new_evidence",
    force=False,
):
    """Attempt to recover an archived entity using Resolution + Conflict gates.

    Only SAME permits recovery. POSSIBLE_CONFLICT and DIFFERENT leave the
    archived entity untouched so the caller may create a separate active entity.
    """
    candidate = candidate if isinstance(candidate, dict) else None
    if candidate is None or not str(candidate.get("name", "") or "").strip():
        return {
            "recovered": False,
            "decision": RECOVERY_DIFFERENT,
            "status": RECOVERY_STATUS_NOT_FOUND,
            "entity": None,
            "reason": "Invalid recovery candidate.",
        }

    archived_entity, identity_result = find_archived_recovery_candidate(candidate)

    if archived_entity is None:
        record_recovery_attempt(
            candidate,
            {},
            identity_result,
            RECOVERY_DIFFERENT,
            RECOVERY_STATUS_NOT_FOUND,
            "No sufficiently plausible archived identity was found.",
            source_text=source_text,
            memory_id=memory_id,
        )
        return {
            "recovered": False,
            "decision": RECOVERY_DIFFERENT,
            "status": RECOVERY_STATUS_NOT_FOUND,
            "entity": None,
            "identity_result": identity_result,
            "reason": "No sufficiently plausible archived identity was found.",
        }

    from memory_entity_conflict import analyze_entity_conflict

    if force:
        analysis = {
            "decision": RECOVERY_SAME,
            "conflict": False,
            "score": identity_result.get("score", 0.0),
            "method": "forced_recovery",
            "reason": "Recovery explicitly forced by caller.",
        }
    else:
        analysis = analyze_entity_conflict(
            candidate,
            archived_entity,
            identity_result=identity_result,
        )

    decision = str(analysis.get("decision", RECOVERY_POSSIBLE_CONFLICT)).strip().upper()
    if decision not in {
        RECOVERY_SAME,
        RECOVERY_POSSIBLE_CONFLICT,
        RECOVERY_DIFFERENT,
    }:
        decision = RECOVERY_POSSIBLE_CONFLICT

    if decision != RECOVERY_SAME:
        status = RECOVERY_STATUS_BLOCKED
        reason_text = str(
            analysis.get("reason", "Recovery blocked by identity conflict analysis.")
            or "Recovery blocked by identity conflict analysis."
        ).strip()

        conflict_record = None
        try:
            from memory_entity_conflict import record_conflict

            conflict_record = record_conflict(
                candidate=candidate,
                entity=archived_entity,
                analysis=analysis,
                identity_result=identity_result,
                source_text=source_text,
                memory_id=memory_id or "",
            )
        except Exception:
            conflict_record = None

        record_recovery_attempt(
            candidate,
            archived_entity,
            identity_result,
            decision,
            status,
            reason_text,
            source_text=source_text,
            memory_id=memory_id,
        )

        return {
            "recovered": False,
            "decision": decision,
            "status": status,
            "entity": None,
            "archived_entity": dict(archived_entity),
            "identity_result": identity_result,
            "analysis": analysis,
            "conflict_record": conflict_record,
            "reason": reason_text,
        }

    from memory_entity_archive import restore_entity

    recovered = restore_entity(
        archived_entity.get("entity_id"),
        reason=reason,
    )

    if recovered is None:
        reason_text = "Recovery passed identity checks but archive restoration failed."
        record_recovery_attempt(
            candidate,
            archived_entity,
            identity_result,
            decision,
            RECOVERY_STATUS_BLOCKED,
            reason_text,
            source_text=source_text,
            memory_id=memory_id,
        )
        return {
            "recovered": False,
            "decision": decision,
            "status": RECOVERY_STATUS_BLOCKED,
            "entity": None,
            "archived_entity": dict(archived_entity),
            "identity_result": identity_result,
            "analysis": analysis,
            "reason": reason_text,
        }

    record_recovery_attempt(
        candidate,
        recovered,
        identity_result,
        decision,
        RECOVERY_STATUS_RECOVERED,
        str(analysis.get("reason", "Archived entity recovered after identity confirmation.")),
        source_text=source_text,
        memory_id=memory_id,
    )

    return {
        "recovered": True,
        "decision": decision,
        "status": RECOVERY_STATUS_RECOVERED,
        "entity": recovered,
        "archived_entity": dict(archived_entity),
        "identity_result": identity_result,
        "analysis": analysis,
        "reason": str(analysis.get("reason", "Recovered archived entity.")),
    }

def recover_entity_candidate(
    candidate,
    source_text="",
    memory_id="",
    reason="new_evidence",
    force=False,
):
    """Idempotent Recovery Gate for one evidence event."""
    from memory_integrity import run_idempotent

    payload = {
        "candidate": candidate if isinstance(candidate, dict) else {},
        "source_text": str(source_text or "").strip(),
        "memory_id": str(memory_id or "").strip(),
        "reason": str(reason or "new_evidence").strip(),
        "force": bool(force),
    }

    result = run_idempotent(
        "ENTITY_RECOVERY",
        payload,
        lambda: _recover_entity_candidate_impl(
            candidate,
            source_text=source_text,
            memory_id=memory_id,
            reason=reason,
            force=force,
        ),
    )
    return result.get("result")

