import hashlib
import json
import os
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document


# ==================================================
# Integrity / Idempotency Configuration
# ==================================================

OPERATION_FILE = "memory_operations.json"
OPERATION_SCHEMA_VERSION = 2
OPERATION_MAX_COUNT = 10000
OPERATION_RECOVERY_STALE_SECONDS = 120.0
OPERATION_MAX_RECOVERY_ATTEMPTS = 3
OPERATION_LOCK_FILE = f"{OPERATION_FILE}.lock"
OPERATION_LOCK_TIMEOUT_SECONDS = 10.0
OPERATION_LOCK_STALE_SECONDS = 120.0

INTEGRITY_SCHEMA_VERSION = 1

VALID_OPERATION_STATUSES = {
    "COMPLETED",
    "FAILED",
    "STARTED",
}


# ==================================================
# Time / Normalization Helpers
# ==================================================


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _normalize_scalar(value):
    if isinstance(value, str):
        return " ".join(value.strip().split())
    if isinstance(value, float):
        return round(value, 8)
    return value


def _canonicalize(value):
    """Build a deterministic JSON-compatible representation."""
    if isinstance(value, dict):
        return {
            str(key): _canonicalize(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }

    if isinstance(value, list):
        return [_canonicalize(item) for item in value]

    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]

    if isinstance(value, set):
        normalized = [_canonicalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))

    return _normalize_scalar(value)


def build_operation_key(operation_type, payload):
    """Return a stable hash for one logical operation.

    The key intentionally excludes timestamps, generated IDs and other
    transient fields supplied by callers. Callers should pass only fields that
    define logical identity for the operation.
    """
    operation_type = str(operation_type or "").strip().upper()
    canonical_payload = _canonicalize(payload if payload is not None else {})
    document = {
        "operation_type": operation_type,
        "payload": canonical_payload,
    }

    serialized = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ==================================================
# Operation Store
# ==================================================


def _empty_operation_store():
    return {
        "schema_version": OPERATION_SCHEMA_VERSION,
        "updated_at": None,
        "operations": [],
    }


def _normalize_operation_record(record):
    if not isinstance(record, dict):
        return None

    operation_key = str(record.get("operation_key", "") or "").strip()
    if not operation_key:
        return None

    operation_type = str(record.get("operation_type", "") or "").strip().upper()
    if not operation_type:
        return None

    status = str(record.get("status", "COMPLETED") or "COMPLETED").strip().upper()
    if status not in VALID_OPERATION_STATUSES:
        status = "COMPLETED"

    created_at = str(record.get("created_at", "") or "").strip() or current_timestamp()
    updated_at = str(record.get("updated_at", "") or "").strip() or created_at
    started_at = str(record.get("started_at", "") or "").strip() or created_at
    lease_expires_at = record.get("lease_expires_at")
    if not isinstance(lease_expires_at, str) or not lease_expires_at.strip():
        lease_expires_at = None

    try:
        attempt_count = max(1, int(record.get("attempt_count", 1)))
    except (TypeError, ValueError):
        attempt_count = 1

    try:
        recovery_count = max(0, int(record.get("recovery_count", 0)))
    except (TypeError, ValueError):
        recovery_count = 0

    return {
        "operation_id": str(record.get("operation_id", "") or "").strip() or f"op_{uuid.uuid4().hex[:12]}",
        "operation_key": operation_key,
        "operation_type": operation_type,
        "status": status,
        "result_ref": str(record.get("result_ref", "") or "").strip(),
        "error": str(record.get("error", "") or "").strip()[:1000],
        "result_data": record.get("result_data"),
        "attempt_count": attempt_count,
        "recovery_count": recovery_count,
        "started_at": started_at,
        "lease_expires_at": lease_expires_at,
        "last_recovery_at": str(record.get("last_recovery_at", "") or "").strip() or None,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def load_operation_store():
    data = load_json_document(
        OPERATION_FILE,
        _empty_operation_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_operation_store()

    operations = data.get("operations")
    if not isinstance(operations, list):
        operations = []

    normalized = []
    seen_keys = set()

    for item in operations:
        normalized_item = _normalize_operation_record(item)
        if normalized_item is None:
            continue

        key = normalized_item["operation_key"]
        if key in seen_keys:
            # Keep the first durable record for one logical operation.
            continue

        normalized.append(normalized_item)
        seen_keys.add(key)

    return {
        "schema_version": OPERATION_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "operations": normalized[-OPERATION_MAX_COUNT:],
    }


@contextmanager
def _operation_store_lock():
    """Serialize operation-store claims/updates across processes."""
    lock_path = os.path.abspath(OPERATION_LOCK_FILE)
    deadline = time.monotonic() + OPERATION_LOCK_TIMEOUT_SECONDS
    fd = None

    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8"))
            os.close(fd)
            fd = None
            break
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lock_path)
                if age > OPERATION_LOCK_STALE_SECONDS:
                    os.remove(lock_path)
                    continue
            except OSError:
                pass

            if time.monotonic() >= deadline:
                raise TimeoutError("Could not acquire operation store lock.")
            time.sleep(0.02)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)

    try:
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.remove(lock_path)
        except OSError:
            pass


def _safe_result_data(result):
    """Return JSON-safe reusable result data for duplicate operations."""
    if result is None:
        return None

    try:
        json.dumps(result, ensure_ascii=False)
        return result
    except (TypeError, ValueError):
        return str(result)


def _result_ref(result):
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return str(
            result.get("entity_id")
            or result.get("memory_id")
            or result.get("conflict_id")
            or result.get("relation_id")
            or result.get("recovery_id")
            or ""
        )
    return str(result)


def save_operation_store(store):
    if not isinstance(store, dict):
        store = _empty_operation_store()

    operations = store.get("operations", [])
    if not isinstance(operations, list):
        operations = []

    store["schema_version"] = OPERATION_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()
    store["operations"] = operations[-OPERATION_MAX_COUNT:]

    save_json_document(OPERATION_FILE, store, indent=2)


# ==================================================
# Operation Recovery Helpers
# ==================================================


def _parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _lease_expiry(now=None):
    now = now or datetime.now(timezone.utc)
    return (now.timestamp() + OPERATION_RECOVERY_STALE_SECONDS)


def _lease_timestamp(now=None):
    now = now or datetime.now(timezone.utc)
    return datetime.fromtimestamp(
        _lease_expiry(now),
        tz=timezone.utc,
    ).isoformat()


def is_operation_stale(record, now=None):
    if not isinstance(record, dict):
        return False

    if str(record.get("status", "") or "").upper() != "STARTED":
        return False

    now = now or datetime.now(timezone.utc)
    lease = _parse_timestamp(record.get("lease_expires_at"))
    if lease is not None:
        return lease <= now

    updated = _parse_timestamp(record.get("updated_at"))
    if updated is None:
        return True

    return (now - updated).total_seconds() >= OPERATION_RECOVERY_STALE_SECONDS


def get_recoverable_operations(now=None, max_results=100):
    now = now or datetime.now(timezone.utc)
    records = [
        item
        for item in load_operation_store().get("operations", [])
        if is_operation_stale(item, now=now)
    ]
    return [dict(item) for item in records[-max_results:]]


# ==================================================
# Idempotency API
# ==================================================


def get_operation(operation_key):
    operation_key = str(operation_key or "").strip()
    if not operation_key:
        return None

    for item in load_operation_store().get("operations", []):
        if item.get("operation_key") == operation_key:
            return dict(item)

    return None


def get_operation_for(operation_type, payload):
    return get_operation(build_operation_key(operation_type, payload))


def begin_operation(operation_type, payload, result_ref=""):
    """Atomically claim a logical operation, or recover a stale claim."""
    operation_type = str(operation_type or "").strip().upper()
    operation_key = build_operation_key(operation_type, payload)

    with _operation_store_lock():
        store = load_operation_store()
        operations = store.get("operations", [])
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()

        for item in operations:
            if item.get("operation_key") != operation_key:
                continue

            status = str(item.get("status", "COMPLETED") or "COMPLETED").upper()
            if status == "COMPLETED":
                return dict(item), False

            if status == "FAILED":
                return dict(item), False

            if status == "STARTED" and not is_operation_stale(item, now=now_dt):
                return dict(item), False

            if status == "STARTED" and is_operation_stale(item, now=now_dt):
                try:
                    recovery_count = max(0, int(item.get("recovery_count", 0)))
                except (TypeError, ValueError):
                    recovery_count = 0

                if recovery_count >= OPERATION_MAX_RECOVERY_ATTEMPTS:
                    item["status"] = "FAILED"
                    item["error"] = "operation_recovery_attempt_limit_exceeded"
                    item["updated_at"] = now
                    item["lease_expires_at"] = None
                    save_operation_store(store)
                    return dict(item), False

                item["status"] = "STARTED"
                item["attempt_count"] = max(1, int(item.get("attempt_count", 1) or 1)) + 1
                item["recovery_count"] = recovery_count + 1
                item["started_at"] = now
                item["lease_expires_at"] = _lease_timestamp(now_dt)
                item["last_recovery_at"] = now
                item["error"] = ""
                item["updated_at"] = now
                save_operation_store(store)
                return dict(item), True

        record = {
            "operation_id": f"op_{uuid.uuid4().hex[:12]}",
            "operation_key": operation_key,
            "operation_type": operation_type,
            "status": "STARTED",
            "result_ref": str(result_ref or "").strip(),
            "error": "",
            "result_data": None,
            "attempt_count": 1,
            "recovery_count": 0,
            "started_at": now,
            "lease_expires_at": _lease_timestamp(now_dt),
            "last_recovery_at": None,
            "created_at": now,
            "updated_at": now,
        }

        operations.append(record)
        save_operation_store({
            "schema_version": OPERATION_SCHEMA_VERSION,
            "updated_at": now,
            "operations": operations,
        })
        return dict(record), True


def heartbeat_operation(operation_key):
    """Extend an active operation lease without changing its logical identity."""
    operation_key = str(operation_key or "").strip()
    if not operation_key:
        return None

    with _operation_store_lock():
        store = load_operation_store()
        for item in store.get("operations", []):
            if item.get("operation_key") != operation_key:
                continue
            if str(item.get("status", "") or "").upper() != "STARTED":
                return dict(item)

            now_dt = datetime.now(timezone.utc)
            item["started_at"] = item.get("started_at") or now_dt.isoformat()
            item["lease_expires_at"] = _lease_timestamp(now_dt)
            item["updated_at"] = now_dt.isoformat()
            save_operation_store(store)
            return dict(item)

    return None


def complete_operation(operation_key, result_ref="", result_data=None):
    operation_key = str(operation_key or "").strip()
    if not operation_key:
        return None

    with _operation_store_lock():
        store = load_operation_store()
        for item in store.get("operations", []):
            if item.get("operation_key") != operation_key:
                continue

            item["status"] = "COMPLETED"
            if result_ref:
                item["result_ref"] = str(result_ref).strip()
            item["error"] = ""
            item["result_data"] = _safe_result_data(result_data)
            item["lease_expires_at"] = None
            item["updated_at"] = current_timestamp()
            save_operation_store(store)
            return dict(item)

    return None


def fail_operation(operation_key, error):
    operation_key = str(operation_key or "").strip()
    if not operation_key:
        return None

    with _operation_store_lock():
        store = load_operation_store()
        for item in store.get("operations", []):
            if item.get("operation_key") != operation_key:
                continue

            item["status"] = "FAILED"
            item["error"] = str(error or "operation_failed").strip()[:1000]
            item["lease_expires_at"] = None
            item["updated_at"] = current_timestamp()
            save_operation_store(store)
            return dict(item)

    return None


def run_idempotent(operation_type, payload, callback):
    """Execute once, or safely replay a stale operation after a crash."""
    operation_record, should_execute = begin_operation(operation_type, payload)

    if not should_execute:
        if operation_record.get("status") == "COMPLETED":
            return {
                "executed": False,
                "status": "ALREADY_COMPLETED",
                "record": operation_record,
                "result": operation_record.get("result_data"),
            }

        return {
            "executed": False,
            "status": "ALREADY_RECORDED",
            "record": operation_record,
            "result": operation_record.get("result_data"),
        }

    operation_key = operation_record["operation_key"]

    try:
        result = callback()
    except BaseException as exc:
        # Exceptions such as KeyboardInterrupt/SystemExit intentionally leave
        # the operation STARTED so the lease-based recovery mechanism can
        # detect a crash-like interruption. Ordinary exceptions are marked
        # FAILED because the callback reported a normal application failure.
        if isinstance(exc, Exception):
            fail_operation(operation_key, repr(exc))
        raise

    completed = complete_operation(
        operation_key,
        result_ref=_result_ref(result),
        result_data=result,
    )

    return {
        "executed": True,
        "status": "RECOVERED" if operation_record.get("recovery_count", 0) else "COMPLETED",
        "record": completed or operation_record,
        "result": result,
    }



def clear_operation_store():
    save_operation_store(_empty_operation_store())
    return True


# ==================================================
# Generic JSON / Invariant Helpers
# ==================================================


def _load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default


def _append_violation(violations, code, message, context=None):
    violations.append({
        "code": str(code),
        "message": str(message),
        "context": context if isinstance(context, dict) else {},
    })


def _entity_maps(active_entities, archived_entities):
    active_by_id = {}
    archived_by_id = {}

    for entity in active_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if entity_id:
            active_by_id[entity_id] = entity

    for entity in archived_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if entity_id:
            archived_by_id[entity_id] = entity

    return active_by_id, archived_by_id


def _check_operation_invariants(operation_store, violations):
    if not isinstance(operation_store, dict):
        _append_violation(
            violations,
            "OPERATION_INVALID_STORE",
            "Operation store is not a dictionary.",
        )
        return

    operations = operation_store.get("operations", [])
    if not isinstance(operations, list):
        _append_violation(
            violations,
            "OPERATION_INVALID_COLLECTION",
            "Operation store operations is not a list.",
        )
        return

    seen_keys = set()
    seen_ids = set()
    for item in operations:
        if not isinstance(item, dict):
            _append_violation(
                violations,
                "OPERATION_INVALID_RECORD",
                "Operation store contains a non-dictionary record.",
            )
            continue

        operation_id = str(item.get("operation_id", "") or "").strip()
        operation_key = str(item.get("operation_key", "") or "").strip()
        if not operation_id:
            _append_violation(
                violations,
                "OPERATION_MISSING_ID",
                "Operation record is missing operation_id.",
            )
        elif operation_id in seen_ids:
            _append_violation(
                violations,
                "OPERATION_DUPLICATE_ID",
                "Duplicate operation_id exists.",
                {"operation_id": operation_id},
            )
        seen_ids.add(operation_id)

        if not operation_key:
            _append_violation(
                violations,
                "OPERATION_MISSING_KEY",
                "Operation record is missing operation_key.",
                {"operation_id": operation_id},
            )
        elif operation_key in seen_keys:
            _append_violation(
                violations,
                "OPERATION_DUPLICATE_KEY",
                "Duplicate operation_key exists.",
                {"operation_key": operation_key},
            )
        seen_keys.add(operation_key)

        status = str(item.get("status", "") or "").upper()
        try:
            attempt_count = int(item.get("attempt_count", 1))
        except (TypeError, ValueError):
            attempt_count = 0
        try:
            recovery_count = int(item.get("recovery_count", 0))
        except (TypeError, ValueError):
            recovery_count = -1

        if status not in VALID_OPERATION_STATUSES:
            _append_violation(
                violations,
                "OPERATION_INVALID_STATUS",
                "Operation record contains an invalid status.",
                {"operation_id": operation_id, "status": status},
            )

        if attempt_count < 1:
            _append_violation(
                violations,
                "OPERATION_INVALID_ATTEMPT_COUNT",
                "Operation attempt_count must be at least 1.",
                {"operation_id": operation_id, "attempt_count": attempt_count},
            )

        if recovery_count < 0 or recovery_count > OPERATION_MAX_RECOVERY_ATTEMPTS:
            _append_violation(
                violations,
                "OPERATION_INVALID_RECOVERY_COUNT",
                "Operation recovery_count is outside the allowed range.",
                {"operation_id": operation_id, "recovery_count": recovery_count},
            )

        if status == "COMPLETED" and item.get("lease_expires_at"):
            _append_violation(
                violations,
                "COMPLETED_OPERATION_HAS_LEASE",
                "Completed operation must not retain an active lease.",
                {"operation_id": operation_id},
            )


def _check_memory_invariants(memory_active, memory_archive, violations):
    active_by_id = {}
    archived_by_id = {}
    active_ids = set()
    archived_ids = set()

    for item in memory_active:
        if not isinstance(item, dict):
            _append_violation(violations, "MEMORY_INVALID_RECORD", "Active Memory contains a non-dictionary item.")
            continue

        memory_id = str(item.get("memory_id", "") or "").strip()
        if not memory_id:
            _append_violation(violations, "MEMORY_MISSING_ID", "Active Memory is missing memory_id.")
            continue
        if memory_id in active_ids:
            _append_violation(violations, "MEMORY_DUPLICATE_ID_ACTIVE", "Duplicate memory_id exists in active Memory store.", {"memory_id": memory_id})
        active_ids.add(memory_id)
        active_by_id[memory_id] = item

        if str(item.get("status", "active") or "active").strip().lower() == "archived":
            _append_violation(violations, "ACTIVE_MEMORY_MARKED_ARCHIVED", "Active Memory item is marked archived.", {"memory_id": memory_id})

    for item in memory_archive:
        if not isinstance(item, dict):
            _append_violation(violations, "MEMORY_INVALID_ARCHIVE_RECORD", "Memory archive contains a non-dictionary item.")
            continue

        memory_id = str(item.get("memory_id", "") or "").strip()
        if not memory_id:
            _append_violation(violations, "MEMORY_ARCHIVE_MISSING_ID", "Archived Memory is missing memory_id.")
            continue
        if memory_id in archived_ids:
            _append_violation(violations, "MEMORY_DUPLICATE_ID_ARCHIVE", "Duplicate memory_id exists in Memory archive.", {"memory_id": memory_id})
        archived_ids.add(memory_id)
        archived_by_id[memory_id] = item

        if str(item.get("status", "archived") or "archived").strip().lower() != "archived":
            _append_violation(violations, "MEMORY_ARCHIVE_STATUS_INVALID", "Archived Memory is not marked archived.", {"memory_id": memory_id})

    for memory_id in sorted(active_ids & archived_ids):
        _append_violation(
            violations,
            "MEMORY_ACTIVE_ARCHIVE_OVERLAP",
            "Memory exists simultaneously in active and archive stores.",
            {"memory_id": memory_id},
        )

    all_ids = active_ids | archived_ids
    for item in memory_active + memory_archive:
        if not isinstance(item, dict):
            continue
        memory_id = str(item.get("memory_id", "") or "").strip()
        for field, code in (("supersedes", "MEMORY_SUPERSEDES_REFERENCE_MISSING"), ("superseded_by", "MEMORY_SUPERSEDED_BY_REFERENCE_MISSING")):
            related = item.get(field)
            if isinstance(related, str) and related.strip() and related.strip() not in all_ids:
                _append_violation(
                    violations,
                    code,
                    f"Memory {field} references a missing Memory.",
                    {"memory_id": memory_id, "related_memory_id": related.strip()},
                )

        for link in item.get("causal_links", []) if isinstance(item.get("causal_links"), list) else []:
            if not isinstance(link, dict):
                continue
            target = str(link.get("target_memory_id", "") or "").strip()
            if target and target not in all_ids:
                _append_violation(
                    violations,
                    "MEMORY_CAUSAL_REFERENCE_MISSING",
                    "Causal link references a missing Memory.",
                    {"memory_id": memory_id, "target_memory_id": target},
                )


def _check_entity_lifecycle_temporal_invariants(active_entities, archived_entities, violations):
    for entity in active_entities + archived_entities:
        if not isinstance(entity, dict):
            continue
        entity_id = str(entity.get("entity_id", "") or "").strip()
        temporal = str(entity.get("temporal_status", "current") or "current").strip().lower()
        lifecycle = str(entity.get("lifecycle_status", "ACTIVE") or "ACTIVE").strip().upper()
        archive_state = str(entity.get("archive_state", "ACTIVE") or "ACTIVE").strip().upper()

        if temporal == "ended" and lifecycle != "ENDED":
            _append_violation(
                violations,
                "ENTITY_ENDED_LIFECYCLE_MISMATCH",
                "An ended Entity must have lifecycle_status ENDED.",
                {"entity_id": entity_id, "lifecycle_status": lifecycle},
            )

        if archive_state == "ARCHIVED" and lifecycle not in {"DORMANT", "ENDED"}:
            _append_violation(
                violations,
                "ENTITY_ARCHIVE_LIFECYCLE_MISMATCH",
                "Archived Entity has an invalid lifecycle state.",
                {"entity_id": entity_id, "lifecycle_status": lifecycle},
            )

        if archive_state == "ACTIVE" and entity in archived_entities:
            _append_violation(
                violations,
                "ARCHIVE_ENTITY_ACTIVE_STATE_MISMATCH",
                "Archived-store Entity is marked ACTIVE.",
                {"entity_id": entity_id},
            )


def _check_entity_invariants(active_entities, archived_entities, violations):
    seen_active = set()
    seen_archive = set()

    for entity in active_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if not entity_id:
            _append_violation(
                violations,
                "ENTITY_MISSING_ID",
                "Active Entity is missing entity_id.",
                {"name": entity.get("name", "")},
            )
            continue

        if entity_id in seen_active:
            _append_violation(
                violations,
                "ENTITY_DUPLICATE_ID_ACTIVE",
                "Duplicate entity_id exists in active Entity store.",
                {"entity_id": entity_id},
            )
        seen_active.add(entity_id)

        archive_state = str(entity.get("archive_state", "ACTIVE") or "ACTIVE").upper()
        if archive_state == "ARCHIVED":
            _append_violation(
                violations,
                "ACTIVE_ENTITY_MARKED_ARCHIVED",
                "Active Entity store contains an Entity marked ARCHIVED.",
                {"entity_id": entity_id},
            )

    for entity in archived_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if not entity_id:
            _append_violation(
                violations,
                "ARCHIVE_MISSING_ID",
                "Archived Entity is missing entity_id.",
                {"name": entity.get("name", "")},
            )
            continue

        if entity_id in seen_archive:
            _append_violation(
                violations,
                "ENTITY_DUPLICATE_ID_ARCHIVE",
                "Duplicate entity_id exists in Entity archive.",
                {"entity_id": entity_id},
            )
        seen_archive.add(entity_id)

        if str(entity.get("archive_state", "ARCHIVED") or "ARCHIVED").upper() != "ARCHIVED":
            _append_violation(
                violations,
                "ARCHIVE_ENTITY_NOT_ARCHIVED",
                "Entity in archive is not marked ARCHIVED.",
                {"entity_id": entity_id},
            )

    overlap = seen_active & seen_archive
    for entity_id in sorted(overlap):
        _append_violation(
            violations,
            "ENTITY_ACTIVE_ARCHIVE_OVERLAP",
            "Entity exists simultaneously in active and archive stores.",
            {"entity_id": entity_id},
        )

    for entity in active_entities + archived_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        lifecycle_status = str(entity.get("lifecycle_status", "ACTIVE") or "ACTIVE").upper()
        archive_state = str(entity.get("archive_state", "ACTIVE") or "ACTIVE").upper()

        if archive_state == "ARCHIVED" and lifecycle_status not in {"DORMANT", "ENDED"}:
            _append_violation(
                violations,
                "ARCHIVE_INVALID_LIFECYCLE",
                "Archived Entity does not have an archivable lifecycle state.",
                {"entity_id": entity_id, "lifecycle_status": lifecycle_status},
            )

        history = entity.get("history", [])
        if not isinstance(history, list):
            _append_violation(
                violations,
                "ENTITY_HISTORY_NOT_LIST",
                "Entity history is not a list.",
                {"entity_id": entity_id},
            )
            continue

        current_version = entity.get("version", 1)
        try:
            current_version = int(current_version)
        except (TypeError, ValueError):
            current_version = 0

        history_versions = []
        for entry in history:
            if not isinstance(entry, dict):
                _append_violation(
                    violations,
                    "ENTITY_HISTORY_INVALID_ENTRY",
                    "Entity history contains a non-dictionary entry.",
                    {"entity_id": entity_id},
                )
                continue

            snapshot = entry.get("snapshot", entry)
            if not isinstance(snapshot, dict):
                _append_violation(
                    violations,
                    "ENTITY_HISTORY_INVALID_SNAPSHOT",
                    "Entity history entry has no valid snapshot.",
                    {"entity_id": entity_id},
                )
                continue

            try:
                history_versions.append(int(snapshot.get("version", 0)))
            except (TypeError, ValueError):
                _append_violation(
                    violations,
                    "ENTITY_HISTORY_INVALID_VERSION",
                    "Entity history snapshot has an invalid version.",
                    {"entity_id": entity_id},
                )

        if history_versions and max(history_versions) >= current_version:
            _append_violation(
                violations,
                "ENTITY_HISTORY_CURRENT_VERSION_COLLISION",
                "Historical Entity snapshot has a version equal to or newer than the current Entity version.",
                {"entity_id": entity_id, "current_version": current_version, "history_versions": history_versions},
            )


def _check_conflict_invariants(conflicts, active_by_id, archived_by_id, violations):
    seen_ids = set()

    for record in conflicts:
        conflict_id = str(record.get("conflict_id", "") or "").strip()
        if not conflict_id:
            _append_violation(
                violations,
                "CONFLICT_MISSING_ID",
                "Conflict record is missing conflict_id.",
            )
            continue

        if conflict_id in seen_ids:
            _append_violation(
                violations,
                "CONFLICT_DUPLICATE_ID",
                "Duplicate conflict_id exists.",
                {"conflict_id": conflict_id},
            )
        seen_ids.add(conflict_id)

        decision = str(record.get("decision", "") or "").upper()
        entity_id = str(record.get("entity_id", "") or "").strip()
        created_entity_id = str(record.get("created_entity_id", "") or "").strip()

        if decision in {"POSSIBLE_CONFLICT", "DIFFERENT"} and created_entity_id and created_entity_id == entity_id:
            _append_violation(
                violations,
                "CONFLICT_MERGE_BLOCK_VIOLATED",
                "A POSSIBLE_CONFLICT/DIFFERENT record points its created_entity_id at the conflicting Entity itself.",
                {"conflict_id": conflict_id, "entity_id": entity_id},
            )

        if decision == "SAME" and created_entity_id and entity_id and created_entity_id != entity_id:
            _append_violation(
                violations,
                "CONFLICT_SAME_ID_MISMATCH",
                "A SAME conflict record points to a different created Entity identity.",
                {"conflict_id": conflict_id, "entity_id": entity_id, "created_entity_id": created_entity_id},
            )

        if entity_id and entity_id not in active_by_id and entity_id not in archived_by_id:
            # Historical conflicts may outlive an entity only if it was explicitly
            # deleted, which this architecture currently does not support.
            _append_violation(
                violations,
                "CONFLICT_ENTITY_REFERENCE_MISSING",
                "Conflict record references an Entity that does not exist in active or archive stores.",
                {"conflict_id": conflict_id, "entity_id": entity_id},
            )


def _check_recovery_invariants(recoveries, active_by_id, archived_by_id, violations):
    seen_ids = set()

    for record in recoveries:
        recovery_id = str(record.get("recovery_id", "") or "").strip()
        if not recovery_id:
            _append_violation(
                violations,
                "RECOVERY_MISSING_ID",
                "Recovery record is missing recovery_id.",
            )
            continue

        if recovery_id in seen_ids:
            _append_violation(
                violations,
                "RECOVERY_DUPLICATE_ID",
                "Duplicate recovery_id exists.",
                {"recovery_id": recovery_id},
            )
        seen_ids.add(recovery_id)

        status = str(record.get("status", "") or "").upper()
        decision = str(record.get("decision", "") or "").upper()
        entity_id = str(record.get("entity_id", "") or "").strip()

        if status == "RECOVERED" and decision != "SAME":
            _append_violation(
                violations,
                "RECOVERY_DECISION_MISMATCH",
                "A RECOVERED operation must have a SAME identity decision.",
                {"recovery_id": recovery_id, "decision": decision},
            )

        if status == "RECOVERED" and entity_id and entity_id in archived_by_id:
            _append_violation(
                violations,
                "RECOVERED_ENTITY_STILL_ARCHIVED",
                "Successfully recovered Entity still exists in the archive.",
                {"recovery_id": recovery_id, "entity_id": entity_id},
            )

        if status == "RECOVERED" and entity_id and entity_id not in active_by_id:
            _append_violation(
                violations,
                "RECOVERED_ENTITY_NOT_ACTIVE",
                "Successfully recovered Entity is not present in active Entity store.",
                {"recovery_id": recovery_id, "entity_id": entity_id},
            )


def _check_relation_invariants(relations, active_by_id, archived_by_id, memory_ids, violations):
    seen_relation_ids = set()

    all_entity_ids = set(active_by_id) | set(archived_by_id)

    for relation in relations:
        relation_id = str(relation.get("relation_id", "") or "").strip()
        if not relation_id:
            _append_violation(
                violations,
                "RELATION_MISSING_ID",
                "Relation is missing relation_id.",
            )
            continue

        if relation_id in seen_relation_ids:
            _append_violation(
                violations,
                "RELATION_DUPLICATE_ID",
                "Duplicate relation_id exists.",
                {"relation_id": relation_id},
            )
        seen_relation_ids.add(relation_id)

        source_id = str(relation.get("source_entity_id", "") or "").strip()
        target_id = str(relation.get("target_entity_id", "") or "").strip()

        if not source_id or not target_id:
            _append_violation(
                violations,
                "RELATION_MISSING_ENDPOINT",
                "Relation is missing one or both Entity endpoints.",
                {"relation_id": relation_id},
            )
            continue

        if source_id == target_id:
            _append_violation(
                violations,
                "RELATION_SELF_REFERENCE",
                "Relation source and target refer to the same Entity.",
                {"relation_id": relation_id, "entity_id": source_id},
            )

        if source_id not in all_entity_ids or target_id not in all_entity_ids:
            _append_violation(
                violations,
                "RELATION_ENTITY_REFERENCE_MISSING",
                "Relation references a missing Entity.",
                {"relation_id": relation_id, "source_entity_id": source_id, "target_entity_id": target_id},
            )

        relation_memory_ids = relation.get("memory_ids", [])
        if isinstance(relation_memory_ids, list):
            for memory_id in relation_memory_ids:
                memory_id = str(memory_id or "").strip()
                if memory_id and memory_id not in memory_ids:
                    _append_violation(
                        violations,
                        "RELATION_MEMORY_REFERENCE_MISSING",
                        "Relation references a missing Memory.",
                        {"relation_id": relation_id, "memory_id": memory_id},
                    )


def _check_memory_entity_links(active_entities, archived_entities, memory_ids, violations):
    for entity in active_entities + archived_entities:
        entity_id = str(entity.get("entity_id", "") or "").strip()
        linked_ids = entity.get("memory_ids", [])
        if not isinstance(linked_ids, list):
            _append_violation(
                violations,
                "ENTITY_MEMORY_LINKS_NOT_LIST",
                "Entity memory_ids is not a list.",
                {"entity_id": entity_id},
            )
            continue

        seen = set()
        for memory_id in linked_ids:
            memory_id = str(memory_id or "").strip()
            if not memory_id:
                _append_violation(
                    violations,
                    "ENTITY_EMPTY_MEMORY_LINK",
                    "Entity contains an empty memory link.",
                    {"entity_id": entity_id},
                )
                continue

            if memory_id in seen:
                _append_violation(
                    violations,
                    "ENTITY_DUPLICATE_MEMORY_LINK",
                    "Entity contains a duplicate memory link.",
                    {"entity_id": entity_id, "memory_id": memory_id},
                )

            if memory_id not in memory_ids:
                _append_violation(
                    violations,
                    "ENTITY_MEMORY_REFERENCE_MISSING",
                    "Entity memory_ids contains a Memory that does not exist in active or archive stores.",
                    {"entity_id": entity_id, "memory_id": memory_id},
                )

            seen.add(memory_id)


def _check_graph_invariants(graph, memory_ids, active_by_id, archived_by_id, violations):
    if not isinstance(graph, dict):
        _append_violation(
            violations,
            "GRAPH_INVALID_STORE",
            "Graph store is not a dictionary.",
        )
        return

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        _append_violation(
            violations,
            "GRAPH_INVALID_COLLECTIONS",
            "Graph nodes or edges is not a list.",
        )
        return

    node_by_id = {}
    for node in nodes:
        if not isinstance(node, dict):
            _append_violation(
                violations,
                "GRAPH_INVALID_NODE",
                "Graph contains a non-dictionary node.",
            )
            continue

        node_id = str(node.get("id", "") or "").strip()
        kind = str(node.get("kind", "") or "").strip().lower()
        if not node_id:
            _append_violation(
                violations,
                "GRAPH_NODE_MISSING_ID",
                "Graph node is missing id.",
            )
            continue

        if node_id in node_by_id:
            _append_violation(
                violations,
                "GRAPH_DUPLICATE_NODE_ID",
                "Graph contains duplicate node id.",
                {"node_id": node_id},
            )

        node_by_id[node_id] = node

        if kind == "memory" and node_id not in memory_ids:
            _append_violation(
                violations,
                "GRAPH_MEMORY_NODE_MISSING_SOURCE",
                "Graph contains a memory node that does not exist in Memory stores.",
                {"node_id": node_id},
            )
        elif kind == "entity" and node_id not in active_by_id and node_id not in archived_by_id:
            _append_violation(
                violations,
                "GRAPH_ENTITY_NODE_MISSING_SOURCE",
                "Graph contains an Entity node that does not exist in Entity stores.",
                {"node_id": node_id},
            )

    valid_entity_ids = set(active_by_id) | set(archived_by_id)

    for edge in edges:
        if not isinstance(edge, dict):
            _append_violation(
                violations,
                "GRAPH_INVALID_EDGE",
                "Graph contains a non-dictionary edge.",
            )
            continue

        source = str(edge.get("source", "") or "").strip()
        target = str(edge.get("target", "") or "").strip()
        edge_type = str(edge.get("type", "") or "").strip().upper()

        if source not in node_by_id or target not in node_by_id:
            _append_violation(
                violations,
                "GRAPH_EDGE_NODE_MISSING",
                "Graph edge points to a missing graph node.",
                {"source": source, "target": target, "type": edge_type},
            )

        if edge_type == "MEMORY_HAS_ENTITY":
            if source not in memory_ids:
                _append_violation(
                    violations,
                    "GRAPH_MEMORY_ENTITY_MEMORY_MISSING",
                    "MEMORY_HAS_ENTITY edge points to a missing Memory.",
                    {"source": source, "target": target},
                )
            if target not in valid_entity_ids:
                _append_violation(
                    violations,
                    "GRAPH_MEMORY_ENTITY_ENTITY_MISSING",
                    "MEMORY_HAS_ENTITY edge points to a missing Entity.",
                    {"source": source, "target": target},
                )

        if edge_type == "ENTITY_RELATION":
            if source not in valid_entity_ids or target not in valid_entity_ids:
                _append_violation(
                    violations,
                    "GRAPH_ENTITY_RELATION_ENTITY_MISSING",
                    "ENTITY_RELATION edge points to a missing Entity.",
                    {"source": source, "target": target},
                )


# ==================================================
# Public Validator
# ==================================================


def validate_invariants(base_path="."):
    """Validate all cross-layer invariants without mutating project data."""
    base_path = os.path.abspath(base_path)

    def path(name):
        return os.path.join(base_path, name)

    active_store = _load_json(path("memory_entities.json"), {"entities": []})
    archive_store = _load_json(path("memory_entities_archive.json"), {"entities": []})
    conflict_store = _load_json(path("memory_entity_conflicts.json"), {"conflicts": []})
    recovery_store = _load_json(path("memory_entity_recovery.json"), {"recoveries": []})
    relation_store = _load_json(path("memory_entity_relations.json"), {"relations": []})
    memory_active = _load_json(path("memory.json"), [])
    memory_archive = _load_json(path("memory_archive.json"), [])
    graph = _load_json(path("memory_graph.json"), {"nodes": [], "edges": []})
    operation_store = _load_json(path(OPERATION_FILE), _empty_operation_store())

    active_entities = active_store.get("entities", []) if isinstance(active_store, dict) else []
    archived_entities = archive_store.get("entities", []) if isinstance(archive_store, dict) else []
    conflicts = conflict_store.get("conflicts", []) if isinstance(conflict_store, dict) else []
    recoveries = recovery_store.get("recoveries", []) if isinstance(recovery_store, dict) else []
    relations = relation_store.get("relations", []) if isinstance(relation_store, dict) else []

    if not isinstance(active_entities, list):
        active_entities = []
    if not isinstance(archived_entities, list):
        archived_entities = []
    if not isinstance(conflicts, list):
        conflicts = []
    if not isinstance(recoveries, list):
        recoveries = []
    if not isinstance(relations, list):
        relations = []
    if not isinstance(memory_active, list):
        memory_active = []
    if not isinstance(memory_archive, list):
        memory_archive = []

    memory_ids = set()
    for item in memory_active + memory_archive:
        if not isinstance(item, dict):
            continue
        memory_id = str(item.get("memory_id", "") or "").strip()
        if memory_id:
            memory_ids.add(memory_id)

    active_by_id, archived_by_id = _entity_maps(active_entities, archived_entities)
    violations = []

    _check_operation_invariants(operation_store, violations)
    _check_memory_invariants(memory_active, memory_archive, violations)
    _check_entity_invariants(active_entities, archived_entities, violations)
    _check_entity_lifecycle_temporal_invariants(active_entities, archived_entities, violations)
    _check_conflict_invariants(conflicts, active_by_id, archived_by_id, violations)
    _check_recovery_invariants(recoveries, active_by_id, archived_by_id, violations)
    _check_relation_invariants(relations, active_by_id, archived_by_id, memory_ids, violations)
    _check_memory_entity_links(active_entities, archived_entities, memory_ids, violations)
    _check_graph_invariants(graph, memory_ids, active_by_id, archived_by_id, violations)

    return {
        "schema_version": INTEGRITY_SCHEMA_VERSION,
        "valid": not violations,
        "violations": violations,
        "counts": {
            "active_entities": len(active_entities),
            "archived_entities": len(archived_entities),
            "conflicts": len(conflicts),
            "recoveries": len(recoveries),
            "relations": len(relations),
            "memories": len(memory_ids),
            "graph_nodes": len(graph.get("nodes", [])) if isinstance(graph, dict) and isinstance(graph.get("nodes"), list) else 0,
            "graph_edges": len(graph.get("edges", [])) if isinstance(graph, dict) and isinstance(graph.get("edges"), list) else 0,
            "operations": len(operation_store.get("operations", [])) if isinstance(operation_store, dict) and isinstance(operation_store.get("operations"), list) else 0,
        },
    }


def assert_invariants(base_path="."):
    report = validate_invariants(base_path)
    if report["valid"]:
        return report

    first = report["violations"][0]
    raise AssertionError(
        f"Invariant violation: {first.get('code')}: {first.get('message')}"
    )


# ==================================================
# Safe Isolated Test Directory Helper
# ==================================================


def create_isolated_directory(prefix="memory_integrity_test_"):
    return tempfile.TemporaryDirectory(prefix=prefix)
