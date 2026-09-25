import json
import os
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent


def write_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def write_embedding_stub(tmp):
    package = Path(tmp) / "sentence_transformers"
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


def main():
    original_cwd = Path.cwd()
    sys.path.insert(0, str(BASE))

    try:
        with tempfile.TemporaryDirectory(prefix="memory_idempotency_real_") as tmp:
            os.chdir(tmp)
            write_embedding_stub(tmp)
            sys.path.insert(0, tmp)

            import memory_integrity
            import memory_entities
            import memory_entity_resolution
            import memory_entity_relations
            import memory_entity_conflict
            import memory_entity_archive
            import memory_entity_recovery
            import long_term_memory as ltm

            memory_integrity.clear_operation_store()
            write_json(tmp + "/memory.json", [
                {"memory_id": "mem_1", "memory": "Abaqus"},
                {"memory_id": "mem_2", "memory": "Python"},
            ])
            write_json(tmp + "/memory_archive.json", [])
            memory_entities.clear_entities()
            memory_entity_archive.clear_entity_archive()
            memory_entity_conflict.clear_conflicts()
            memory_entity_recovery.clear_recovery_history()
            memory_entity_resolution.clear_resolution_history()
            memory_entity_relations.clear_entity_relations()

            # --------------------------------------------------
            # Entity ingestion must execute once for same payload.
            # --------------------------------------------------
            candidate = [{
                "name": "Abaqus",
                "type": "SOFTWARE",
                "description": "FEA software",
                "confidence": 0.95,
            }]
            first = memory_entities.upsert_entities(candidate, memory_id="mem_1", source_text="Abaqus", valid_from="2026-09-24T00:00:00+00:00")
            second = memory_entities.upsert_entities(candidate, memory_id="mem_1", source_text="Abaqus", valid_from="2026-09-24T00:00:00+00:00")
            entities = memory_entities.get_all_entities()
            expect(len(first) == 1 and len(second) == 1, "Entity ingestion result missing.")
            expect(len(entities) == 1, "Repeated Entity ingestion created a duplicate Entity.")
            expect(entities[0]["entity_id"] == first[0]["entity_id"] == second[0]["entity_id"], "Entity identity changed across idempotent replay.")

            # --------------------------------------------------
            # Resolution audit must execute once for same evidence.
            # --------------------------------------------------
            r1 = memory_entity_resolution.record_resolution(
                "Abaqus", entities[0]["entity_id"], "Abaqus", 0.99, "exact",
                source_text="Abaqus", memory_id="mem_1", action="LINK",
            )
            r2 = memory_entity_resolution.record_resolution(
                "Abaqus", entities[0]["entity_id"], "Abaqus", 0.99, "exact",
                source_text="Abaqus", memory_id="mem_1", action="LINK",
            )
            resolution_records = memory_entity_resolution.load_resolution_store()["resolutions"]
            expect(r1["resolution_id"] == r2["resolution_id"], "Resolution replay created a different audit record.")
            expect(len(resolution_records) == 1, "Resolution audit duplicate created.")

            # --------------------------------------------------
            # Relation upsert already has deterministic relation_id;
            # Operation Idempotency must prevent duplicate side effects.
            # --------------------------------------------------
            second_entity = memory_entities.upsert_entities([
                {"name": "Python", "type": "SOFTWARE", "confidence": 0.95}
            ], memory_id="mem_2", source_text="Python")[0]
            rel1 = memory_entity_relations.upsert_entity_relation(
                entities[0], second_entity, "RELATED_TO", confidence=0.9,
                evidence="shared project", memory_id="mem_1",
            )
            rel2 = memory_entity_relations.upsert_entity_relation(
                entities[0], second_entity, "RELATED_TO", confidence=0.9,
                evidence="shared project", memory_id="mem_1",
            )
            relation_records = memory_entity_relations.load_relation_store()["relations"]
            expect(rel1["relation_id"] == rel2["relation_id"], "Relation identity changed across replay.")
            expect(len(relation_records) == 1, "Relation duplicate created.")

            # --------------------------------------------------
            # Conflict record must remain one logical audit record.
            # --------------------------------------------------
            conflict_analysis = {
                "decision": "POSSIBLE_CONFLICT",
                "conflict": True,
                "score": 0.75,
                "method": "test",
                "reason": "same evidence",
            }
            c1 = memory_entity_conflict.record_conflict(
                {"name": "Abaqus", "type": "SOFTWARE"},
                entities[0],
                conflict_analysis,
                identity_result={"score": 0.75},
                source_text="same evidence",
                memory_id="mem_1",
            )
            c2 = memory_entity_conflict.record_conflict(
                {"name": "Abaqus", "type": "SOFTWARE"},
                entities[0],
                conflict_analysis,
                identity_result={"score": 0.75},
                source_text="same evidence",
                memory_id="mem_1",
            )
            conflict_records = memory_entity_conflict.load_conflict_store()["conflicts"]
            expect(c1["conflict_id"] == c2["conflict_id"], "Conflict replay changed conflict_id.")
            expect(len(conflict_records) == 1, "Conflict duplicate created.")

            # --------------------------------------------------
            # Archive transition must execute once.
            # --------------------------------------------------
            store = memory_entities.load_entity_store()
            target = next(item for item in store["entities"] if item["entity_id"] == second_entity["entity_id"])
            target["lifecycle_status"] = "DORMANT"
            memory_entities.save_entity_store(store)

            a1 = memory_entity_archive.archive_entity(second_entity["entity_id"], reason="test")
            a2 = memory_entity_archive.archive_entity(second_entity["entity_id"], reason="test")
            expect(a1["entity_id"] == a2["entity_id"], "Archive replay changed result identity.")
            expect(len(memory_entity_archive.get_archived_entities()) == 1, "Archive replay created duplicate archived Entity.")
            expect(not any(item["entity_id"] == second_entity["entity_id"] for item in memory_entities.get_all_entities()), "Archived Entity remained active.")

            # --------------------------------------------------
            # Recovery transition must execute once and preserve entity_id.
            # --------------------------------------------------
            recovery_candidate = {"name": "Python", "type": "SOFTWARE", "confidence": 0.95}
            rec1 = memory_entity_recovery.recover_entity_candidate(
                recovery_candidate,
                source_text="Python recovery",
                memory_id="mem_2",
                reason="test_recovery",
            )
            rec2 = memory_entity_recovery.recover_entity_candidate(
                recovery_candidate,
                source_text="Python recovery",
                memory_id="mem_2",
                reason="test_recovery",
            )
            expect(rec1["recovered"] is True, "Initial recovery did not succeed.")
            expect(rec2["recovered"] is True, "Idempotent recovery replay did not return the successful result.")
            expect(rec1["entity"]["entity_id"] == rec2["entity"]["entity_id"] == second_entity["entity_id"], "Recovery did not preserve entity_id.")
            active_ids = {item["entity_id"] for item in memory_entities.get_all_entities()}
            archive_ids = {item["entity_id"] for item in memory_entity_archive.get_archived_entities()}
            expect(second_entity["entity_id"] in active_ids, "Recovered Entity is not active.")
            expect(second_entity["entity_id"] not in archive_ids, "Recovered Entity remains archived.")

            # Validate the completed Entity phase before switching stores.
            entity_report = memory_integrity.validate_invariants(tmp)
            expect(entity_report["valid"], f"Healthy Entity phase failed invariants: {entity_report['violations']}")

            # --------------------------------------------------
            # Isolated Memory mutation phase.
            # --------------------------------------------------
            memory_phase = Path(tmp) / "memory_phase"
            memory_phase.mkdir(parents=True, exist_ok=True)
            os.chdir(memory_phase)
            memory_integrity.clear_operation_store()

            expect(ltm.add_memory("IdemMemory1", importance=3) is True, "Initial Memory ADD failed.")
            expect(ltm.add_memory("IdemMemory1", importance=3) is True, "Idempotent Memory ADD replay did not return prior result.")
            expect(len(ltm.get_memory()) == 1, "Repeated Memory ADD created a duplicate.")

            expect(ltm.archive_memory("IdemMemory1", reason="test") is True, "Initial Memory archive failed.")
            expect(ltm.archive_memory("IdemMemory1", reason="test") is True, "Idempotent Memory archive replay failed.")
            expect(len(ltm.get_archived_memory()) == 1 and not ltm.get_memory(), "Memory archive transition is inconsistent.")

            expect(ltm.restore_memory("IdemMemory1") is True, "Initial Memory restore failed.")
            expect(ltm.restore_memory("IdemMemory1") is True, "Idempotent Memory restore replay failed.")
            expect(len(ltm.get_memory()) == 1 and not ltm.get_archived_memory(), "Memory restore transition is inconsistent.")

            expect(ltm.add_memory("IdemMemory3", importance=2) is True, "Old fact add failed.")
            expect(ltm.resolve_memory_conflict("IdemMemory3", "IdemMemory4", importance=2) is True, "Memory update failed.")
            expect(ltm.resolve_memory_conflict("IdemMemory3", "IdemMemory4", importance=2) is True, "Idempotent Memory update replay failed.")
            expect(sum(1 for item in ltm.get_memory() if item.get("memory") == "IdemMemory4") == 1, "Repeated Memory update created duplicate current facts.")
            expect(sum(1 for item in ltm.get_archived_memory() if item.get("memory") == "IdemMemory3") == 1, "Repeated Memory update created duplicate historical facts.")

            expect(ltm.add_memory("IdemMemory5", importance=2) is True, "Cause fact add failed.")
            expect(ltm.add_memory("IdemMemory6", importance=2) is True, "Effect fact add failed.")
            expect(ltm.add_causal_relationship("IdemMemory5", "IdemMemory6", "CAUSES", confidence=0.9, evidence="test") is True, "Initial causal relation failed.")
            expect(ltm.add_causal_relationship("IdemMemory5", "IdemMemory6", "CAUSES", confidence=0.9, evidence="test") is True, "Idempotent causal replay failed.")
            cause = next(item for item in ltm.get_memory() if item.get("memory") == "IdemMemory5")
            expect(len(cause.get("causal_links", [])) == 1, "Repeated causal relation created duplicate link.")

            expect(ltm.add_memory("IdemMemory7", importance=1) is True, "Consolidation source A add failed.")
            expect(ltm.add_memory("IdemMemory9", importance=1) is True, "Consolidation source B add failed.")
            expect(ltm.consolidate_memories(["IdemMemory7", "IdemMemory9"], "IdemMemory11", importance=2) is True, "Initial consolidation failed.")
            expect(ltm.consolidate_memories(["IdemMemory7", "IdemMemory9"], "IdemMemory11", importance=2) is True, "Idempotent consolidation replay failed.")
            expect(sum(1 for item in ltm.get_memory() if item.get("memory") == "IdemMemory11") == 1, "Repeated consolidation created duplicate result.")

            govern_payload = {"action": "ADD", "memory_text": "IdemMemory13", "memory_type": "other", "importance": 2}
            expect(ltm.govern_memory_action(**govern_payload)["success"] is True, "Initial governed Memory ADD failed.")
            expect(ltm.govern_memory_action(**govern_payload)["success"] is True, "Idempotent governed Memory replay failed.")
            expect(sum(1 for item in ltm.get_memory() if item.get("memory") == "IdemMemory13") == 1, "Governed replay created duplicate Memory.")

            memory_report = memory_integrity.validate_invariants(memory_phase)
            expect(memory_report["valid"], f"Healthy Memory phase failed invariants: {memory_report['violations']}")

            print("PASS: real Memory ADD is idempotent")
            print("PASS: real Memory archive/restore is idempotent")
            print("PASS: real Memory update is idempotent")
            print("PASS: real causal relation is idempotent")
            print("PASS: real Memory consolidation is idempotent")
            print("PASS: real Memory governance is idempotent")
            print("PASS: healthy Memory phase satisfies invariants")

            operation_store = memory_integrity.load_operation_store()
            operation_keys = [item["operation_key"] for item in operation_store["operations"]]
            expect(len(operation_keys) == len(set(operation_keys)), "Duplicate operation keys exist in operation store.")

            print("PASS: real Entity ingestion is idempotent")
            print("PASS: real Resolution audit is idempotent")
            print("PASS: real Relation upsert is idempotent")
            print("PASS: real Conflict recording is idempotent")
            print("PASS: real Entity archive is idempotent")
            print("PASS: real Entity recovery is idempotent")
            print("PASS: healthy cross-layer state satisfies invariants")
            print("REAL_IDEMPOTENCY_INTEGRATION_TEST_PASS")

    finally:
        os.chdir(original_cwd)
        if str(BASE) in sys.path:
            sys.path.remove(str(BASE))
        for item in list(sys.path):
            if item and "memory_idempotency_real_" in item:
                sys.path.remove(item)


if __name__ == "__main__":
    main()
