import importlib
import json
import os
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent


def write_embedding_stub(root: Path):
    package = root / "sentence_transformers"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text(
        "import hashlib\n"
        "class SentenceTransformer:\n"
        "    def __init__(self, *args, **kwargs):\n"
        "        pass\n\n"
        "    def encode(self, text, normalize_embeddings=True):\n"
        "        digest = hashlib.sha256(str(text).encode('utf-8')).digest()\n"
        "        index = digest[0] % 16\n"
        "        vector = [0.0] * 16\n"
        "        vector[index] = 1.0\n"
        "        class Vector:\n"
        "            def tolist(self):\n"
        "                return vector\n"
        "        return Vector()\n",
        encoding="utf-8",
    )


def fresh_import(name):
    sys.modules.pop(name, None)
    return importlib.import_module(name)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    original_cwd = Path.cwd()
    old_path = list(sys.path)
    complete_original = None

    with tempfile.TemporaryDirectory(prefix="memory_transaction_recovery_") as tmp:
        tmp = Path(tmp)
        write_embedding_stub(tmp)
        os.chdir(tmp)
        sys.path.insert(0, str(tmp))
        sys.path.insert(1, str(BASE))

        modules = [
            "memory_storage",
            "memory_integrity",
            "memory_entities",
            "memory_entity_resolution",
            "memory_entity_relations",
            "memory_entity_conflict",
            "memory_entity_archive",
            "memory_entity_recovery",
        ]
        imported = {name: fresh_import(name) for name in modules}
        integrity = imported["memory_integrity"]
        entities = imported["memory_entities"]
        archive = imported["memory_entity_archive"]

        Path("memory.json").write_text(
            json.dumps([
                {
                    "memory_id": "mem_crash_1",
                    "memory": "Crash recovery fixture",
                    "status": "active",
                }
            ], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        Path("memory_archive.json").write_text("[]", encoding="utf-8")
        Path("memory_graph.json").write_text(
            json.dumps({"nodes": [], "edges": []}, indent=2),
            encoding="utf-8",
        )

        # --------------------------------------------------
        # 1. Simulate a crash after the entity side-effect but
        #    before operation completion is committed.
        # --------------------------------------------------
        integrity.clear_operation_store()
        callback_triggered = {"value": False}
        complete_original = integrity.complete_operation
        outer_payload = {
            "candidates": [{"name": "CrashSafePython", "type": "SOFTWARE", "confidence": 0.95}],
            "memory_id": "mem_crash_1",
            "source_text": "crash test",
            "valid_from": "",
        }
        outer_key = integrity.build_operation_key("ENTITY_INGEST", outer_payload)

        def crash_after_callback(operation_key, *args, **kwargs):
            if operation_key == outer_key and not callback_triggered["value"]:
                callback_triggered["value"] = True
                raise KeyboardInterrupt("simulated_process_crash")
            return complete_original(operation_key, *args, **kwargs)

        integrity.complete_operation = crash_after_callback
        try:
            try:
                entities.upsert_entities(
                    [{"name": "CrashSafePython", "type": "SOFTWARE", "confidence": 0.95}],
                    memory_id="mem_crash_1",
                    source_text="crash test",
                )
            except KeyboardInterrupt:
                pass
        finally:
            integrity.complete_operation = complete_original

        expect(callback_triggered["value"], "Crash simulation did not reach completion boundary.")
        entity_records = entities.get_all_entities()
        expect(len(entity_records) == 1, "Initial side-effect was not persisted before simulated crash.")

        operation_store = integrity.load_operation_store()
        crashed_operation = next(
            (item for item in operation_store["operations"] if item.get("operation_key") == outer_key),
            None,
        )
        expect(crashed_operation is not None, "Crash simulation did not create the outer operation record.")
        expect(crashed_operation["status"] == "STARTED", "Crash boundary did not leave operation STARTED.")
        operation_id_before = crashed_operation["operation_id"]

        # Force lease expiry without waiting in real time.
        crashed_operation["lease_expires_at"] = "2000-01-01T00:00:00+00:00"
        integrity.save_operation_store(operation_store)

        # --------------------------------------------------
        # 2. Replay must recover the same logical operation,
        #    preserve operation_id, and avoid duplicate Entity creation.
        # --------------------------------------------------
        recovered = entities.upsert_entities(
            [{"name": "CrashSafePython", "type": "SOFTWARE", "confidence": 0.95}],
            memory_id="mem_crash_1",
            source_text="crash test",
        )

        expect(len(entities.get_all_entities()) == 1, "Crash recovery created a duplicate Entity.")
        recovered_store = integrity.load_operation_store()
        recovered_operation = next(
            (item for item in recovered_store["operations"] if item.get("operation_key") == outer_key),
            None,
        )
        expect(recovered_operation is not None, "Crash recovery lost the outer operation record.")
        expect(recovered_operation["status"] == "COMPLETED", "Recovered operation did not reach COMPLETED.")
        expect(recovered_operation["operation_id"] == operation_id_before, "Recovery changed operation_id.")
        expect(recovered_operation["recovery_count"] == 1, "Recovery count was not incremented exactly once.")
        expect(recovered_operation["attempt_count"] == 2, "Attempt count was not incremented exactly once.")
        expect(recovered_operation["lease_expires_at"] is None, "Completed operation retained a lease.")

        report = integrity.validate_invariants(tmp)
        expect(report["valid"], f"Recovered Entity state violates invariants: {report['violations']}")
        print("PASS: crash after side-effect leaves durable STARTED operation")
        print("PASS: stale STARTED operation is replayed safely")
        print("PASS: replay preserves operation_id")
        print("PASS: replay does not duplicate Entity side-effects")
        print("PASS: recovered operation clears its lease")
        print("PASS: recovered state satisfies invariants")

        # --------------------------------------------------
        # 3. Recovery-attempt limit prevents infinite replay.
        # --------------------------------------------------
        integrity.clear_operation_store()
        started, created = integrity.begin_operation(
            "TEST_RECOVERY_LIMIT",
            {"value": "limit"},
        )
        expect(created, "Recovery-limit operation was not created.")
        store = integrity.load_operation_store()
        record = store["operations"][0]
        record["lease_expires_at"] = "2000-01-01T00:00:00+00:00"
        record["recovery_count"] = integrity.OPERATION_MAX_RECOVERY_ATTEMPTS
        integrity.save_operation_store(store)

        limited, should_execute = integrity.begin_operation(
            "TEST_RECOVERY_LIMIT",
            {"value": "limit"},
        )
        expect(not should_execute, "Recovery-limit operation should not be replayed.")
        expect(limited["status"] == "FAILED", "Recovery-limit operation did not become FAILED.")
        expect(limited["error"] == "operation_recovery_attempt_limit_exceeded", "Recovery-limit reason is incorrect.")
        print("PASS: recovery attempt limit prevents endless replay")

        print("TRANSACTION_RECOVERY_TEST_PASS")

    os.chdir(original_cwd)
    sys.path[:] = old_path


if __name__ == "__main__":
    main()
