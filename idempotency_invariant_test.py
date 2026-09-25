import json
import os
import sys

from memory_integrity import (
    build_operation_key,
    clear_operation_store,
    get_operation_for,
    run_idempotent,
    validate_invariants,
)


BASE = os.path.dirname(os.path.abspath(__file__))


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def test_operation_key_is_stable():
    first = build_operation_key(
        "ENTITY_INGEST",
        {
            "candidate": {"type": "SOFTWARE", "name": "Abaqus"},
            "memory_id": "mem_1",
        },
    )
    second = build_operation_key(
        "ENTITY_INGEST",
        {
            "memory_id": "mem_1",
            "candidate": {"name": "Abaqus", "type": "SOFTWARE"},
        },
    )

    expect(first == second, "Operation key must be deterministic.")


def test_run_idempotent(tmp_dir):
    os.chdir(tmp_dir)
    clear_operation_store()

    calls = {"count": 0}

    def callback():
        calls["count"] += 1
        return {"entity_id": "ent_test_1"}

    payload = {
        "candidate_name": "Abaqus",
        "candidate_type": "SOFTWARE",
        "memory_id": "mem_001",
    }

    first = run_idempotent("ENTITY_INGEST", payload, callback)
    second = run_idempotent("ENTITY_INGEST", payload, callback)

    expect(first["executed"] is True, "First operation must execute.")
    expect(second["executed"] is False, "Second identical operation must be skipped.")
    expect(calls["count"] == 1, "Idempotent callback executed more than once.")

    record = get_operation_for("ENTITY_INGEST", payload)
    expect(record is not None, "Operation record was not persisted.")
    expect(record["status"] == "COMPLETED", "Operation did not reach COMPLETED state.")


def test_valid_fixture(tmp_dir):
    write_json(
        os.path.join(tmp_dir, "memory.json"),
        [{"memory_id": "mem_1", "memory": "Abaqus"}],
    )
    write_json(os.path.join(tmp_dir, "memory_archive.json"), [])
    write_json(
        os.path.join(tmp_dir, "memory_entities.json"),
        {
            "entities": [
                {
                    "entity_id": "ent_1",
                    "name": "Abaqus",
                    "archive_state": "ACTIVE",
                    "lifecycle_status": "ACTIVE",
                    "version": 2,
                    "history": [
                        {
                            "snapshot": {
                                "version": 1,
                                "name": "Abaqus",
                            }
                        }
                    ],
                    "memory_ids": ["mem_1"],
                }
            ]
        },
    )
    write_json(os.path.join(tmp_dir, "memory_entities_archive.json"), {"entities": []})
    write_json(os.path.join(tmp_dir, "memory_entity_conflicts.json"), {"conflicts": []})
    write_json(os.path.join(tmp_dir, "memory_entity_recovery.json"), {"recoveries": []})
    write_json(os.path.join(tmp_dir, "memory_entity_relations.json"), {"relations": []})
    write_json(
        os.path.join(tmp_dir, "memory_graph.json"),
        {
            "nodes": [
                {"id": "mem_1", "kind": "memory"},
                {"id": "ent_1", "kind": "entity"},
            ],
            "edges": [
                {
                    "source": "mem_1",
                    "target": "ent_1",
                    "type": "MEMORY_HAS_ENTITY",
                }
            ],
        },
    )

    report = validate_invariants(tmp_dir)
    expect(report["valid"], f"Valid fixture was rejected: {report['violations']}")


def test_duplicate_and_inconsistent_state_detection(tmp_dir):
    write_json(
        os.path.join(tmp_dir, "memory.json"),
        [{"memory_id": "mem_1", "memory": "Abaqus"}],
    )
    write_json(os.path.join(tmp_dir, "memory_archive.json"), [])

    # Deliberately corrupt: duplicate active entity ID, plus the same entity ID
    # in the archive.
    write_json(
        os.path.join(tmp_dir, "memory_entities.json"),
        {
            "entities": [
                {
                    "entity_id": "ent_1",
                    "name": "Abaqus",
                    "archive_state": "ACTIVE",
                    "lifecycle_status": "ACTIVE",
                    "version": 1,
                    "history": [],
                    "memory_ids": ["mem_1"],
                },
                {
                    "entity_id": "ent_1",
                    "name": "Abaqus duplicate",
                    "archive_state": "ACTIVE",
                    "lifecycle_status": "ACTIVE",
                    "version": 1,
                    "history": [],
                    "memory_ids": ["mem_1"],
                },
            ]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_entities_archive.json"),
        {
            "entities": [
                {
                    "entity_id": "ent_1",
                    "name": "Abaqus",
                    "archive_state": "ARCHIVED",
                    "lifecycle_status": "DORMANT",
                    "memory_ids": ["mem_1"],
                }
            ]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_entity_conflicts.json"),
        {
            "conflicts": [
                {
                    "conflict_id": "conf_1",
                    "candidate_name": "Abaqus",
                    "entity_id": "ent_1",
                    "decision": "DIFFERENT",
                    "created_entity_id": "ent_1",
                }
            ]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_entity_recovery.json"),
        {
            "recoveries": [
                {
                    "recovery_id": "rec_1",
                    "entity_id": "ent_1",
                    "decision": "SAME",
                    "status": "RECOVERED",
                }
            ]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_entity_relations.json"),
        {
            "relations": [
                {
                    "relation_id": "rel_1",
                    "source_entity_id": "ent_1",
                    "target_entity_id": "missing_entity",
                    "relation": "RELATED_TO",
                    "memory_ids": ["missing_memory"],
                }
            ]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_graph.json"),
        {
            "nodes": [
                {"id": "ent_1", "kind": "entity"},
            ],
            "edges": [
                {
                    "source": "mem_missing",
                    "target": "ent_1",
                    "type": "MEMORY_HAS_ENTITY",
                }
            ],
        },
    )

    report = validate_invariants(tmp_dir)
    codes = {item["code"] for item in report["violations"]}

    expected = {
        "ENTITY_DUPLICATE_ID_ACTIVE",
        "ENTITY_ACTIVE_ARCHIVE_OVERLAP",
        "CONFLICT_MERGE_BLOCK_VIOLATED",
        "RECOVERED_ENTITY_STILL_ARCHIVED",
        "RELATION_ENTITY_REFERENCE_MISSING",
        "RELATION_MEMORY_REFERENCE_MISSING",
        "GRAPH_MEMORY_ENTITY_MEMORY_MISSING",
    }

    missing = expected - codes
    expect(not missing, f"Expected invariant violations were not detected: {sorted(missing)}")


def main():
    original_cwd = os.getcwd()

    try:
        import tempfile

        test_operation_key_is_stable()

        with tempfile.TemporaryDirectory(prefix="idempotency_test_") as tmp_dir:
            test_run_idempotent(tmp_dir)

        with tempfile.TemporaryDirectory(prefix="invariant_valid_test_") as tmp_dir:
            test_valid_fixture(tmp_dir)

        with tempfile.TemporaryDirectory(prefix="invariant_invalid_test_") as tmp_dir:
            test_duplicate_and_inconsistent_state_detection(tmp_dir)

        print("PASS: deterministic operation key")
        print("PASS: idempotent callback executes once")
        print("PASS: valid fixture satisfies invariants")
        print("PASS: duplicate + inconsistent state detection")
        print("IDEMPOTENCY_INVARIANT_TEST_PASS")

    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    main()
