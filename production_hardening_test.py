import importlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

BASE = Path('/mnt/data')


def write_stub_sentence_transformers(root: Path):
    package = root / 'sentence_transformers'
    package.mkdir(parents=True, exist_ok=True)
    (package / '__init__.py').write_text(
        '''class SentenceTransformer:\n    def __init__(self, *args, **kwargs):\n        pass\n\n    def encode(self, text, normalize_embeddings=True):\n        class Vector:\n            def tolist(self):\n                return [0.1, 0.2, 0.3]\n        return Vector()\n''',
        encoding='utf-8',
    )


def fresh_import(name):
    sys.modules.pop(name, None)
    return importlib.import_module(name)


def corrupt(path):
    Path(path).write_text('{ invalid json', encoding='utf-8')


def assert_json_valid(path):
    with open(path, 'r', encoding='utf-8') as f:
        json.load(f)


def main():
    tmp = Path(tempfile.mkdtemp(prefix='memory_production_hardening_'))
    original_cwd = Path.cwd()
    old_path = list(sys.path)

    try:
        write_stub_sentence_transformers(tmp)
        os.chdir(tmp)
        sys.path.insert(0, str(tmp))
        sys.path.insert(1, str(BASE))

        modules = [
            'memory_storage',
            'memory_entities',
            'memory_entity_archive',
            'memory_entity_conflict',
            'memory_entity_recovery',
            'memory_entity_resolution',
            'memory_entity_relations',
            'long_term_memory',
            'memory_integrity',
        ]
        imported = {name: fresh_import(name) for name in modules}

        storage = imported['memory_storage']
        # Direct atomic/backup behavior.
        direct_path = tmp / 'direct.json'
        storage.save_json_document(str(direct_path), {'version': 1}, indent=2)
        storage.save_json_document(str(direct_path), {'version': 2}, indent=2)
        assert (tmp / 'direct.json.bak').exists()
        corrupt(direct_path)
        restored = storage.load_json_document(str(direct_path), dict, expected_type=dict)
        assert restored == {'version': 1}
        assert_json_valid(direct_path)
        print('PASS: atomic write + backup restore')

        # Entity store.
        entities = imported['memory_entities']
        first = entities._empty_store()
        first['entities'] = [{'entity_id': 'ent_test', 'name': 'Python', 'type': 'SOFTWARE'}]
        entities.save_entity_store(first)
        second = dict(first)
        second['entities'] = [{'entity_id': 'ent_test', 'name': 'Python 3', 'type': 'SOFTWARE'}]
        entities.save_entity_store(second)
        corrupt(tmp / entities.ENTITY_FILE)
        recovered = entities.load_entity_store()
        assert recovered['entities'][0]['name'] == 'Python'
        assert_json_valid(tmp / entities.ENTITY_FILE)
        print('PASS: entity store recovery')

        # Archive store.
        archive = imported['memory_entity_archive']
        archive.save_entity_archive({'entities': [{'entity_id': 'ent_a', 'name': 'Archived'}]})
        archive.save_entity_archive({'entities': [{'entity_id': 'ent_b', 'name': 'Newer'}]})
        corrupt(tmp / archive.ENTITY_ARCHIVE_FILE)
        recovered = archive.load_entity_archive()
        assert recovered['entities'][0]['entity_id'] == 'ent_a'
        print('PASS: archive store recovery')

        # Conflict store.
        conflict = imported['memory_entity_conflict']
        conflict.save_conflict_store({'conflicts': [{'conflict_id': 'c1', 'candidate_name': 'Python', 'entity_id': 'e1'}]})
        conflict.save_conflict_store({'conflicts': [{'conflict_id': 'c2', 'candidate_name': 'Abaqus', 'entity_id': 'e2'}]})
        corrupt(tmp / conflict.CONFLICT_FILE)
        recovered = conflict.load_conflict_store()
        assert recovered['conflicts'][0]['conflict_id'] == 'c1'
        print('PASS: conflict store recovery')

        # Recovery audit store.
        recovery = imported['memory_entity_recovery']
        recovery.save_recovery_store({'recoveries': [{'recovery_id': 'r1'}]})
        recovery.save_recovery_store({'recoveries': [{'recovery_id': 'r2'}]})
        corrupt(tmp / recovery.ENTITY_RECOVERY_FILE)
        recovered = recovery.load_recovery_store()
        assert recovered['recoveries'][0]['recovery_id'] == 'r1'
        print('PASS: recovery store recovery')

        # Resolution store.
        resolution = imported['memory_entity_resolution']
        resolution.save_resolution_store({'resolutions': [{'resolution_id': 'x1'}]})
        resolution.save_resolution_store({'resolutions': [{'resolution_id': 'x2'}]})
        corrupt(tmp / resolution.RESOLUTION_FILE)
        recovered = resolution.load_resolution_store()
        assert recovered['resolutions'][0]['resolution_id'] == 'x1'
        print('PASS: resolution store recovery')

        # Operation store / Idempotency metadata.
        integrity = imported['memory_integrity']
        integrity.save_operation_store({
            'operations': [{
                'operation_id': 'op_1',
                'operation_key': 'key_1',
                'operation_type': 'TEST',
                'status': 'COMPLETED',
                'result_data': {'entity_id': 'e1'},
            }]
        })
        integrity.save_operation_store({
            'operations': [{
                'operation_id': 'op_2',
                'operation_key': 'key_2',
                'operation_type': 'TEST',
                'status': 'COMPLETED',
                'result_data': {'entity_id': 'e2'},
            }]
        })
        corrupt(tmp / integrity.OPERATION_FILE)
        recovered = integrity.load_operation_store()
        assert recovered['operations'][0]['operation_key'] == 'key_1'
        assert_json_valid(tmp / integrity.OPERATION_FILE)
        print('PASS: operation store recovery')

        # Relation store.
        relations = imported['memory_entity_relations']
        entities.save_entity_store({
            'entities': [
                {'entity_id': 'e1', 'name': 'Entity One', 'type': 'OTHER'},
                {'entity_id': 'e2', 'name': 'Entity Two', 'type': 'OTHER'},
                {'entity_id': 'e3', 'name': 'Entity Three', 'type': 'OTHER'},
            ]
        })
        relations.save_relation_store({'relations': [{'relation_id': 'rel1', 'source_entity_id': 'e1', 'target_entity_id': 'e2', 'relation': 'USED_FOR'}]})
        relations.save_relation_store({'relations': [{'relation_id': 'rel2', 'source_entity_id': 'e2', 'target_entity_id': 'e3', 'relation': 'USED_FOR'}]})
        corrupt(tmp / relations.RELATION_FILE)
        recovered = relations.load_relation_store()
        assert recovered['relations'][0]['relation_id'] == 'rel1'
        print('PASS: relation store recovery')

        # Generic memory list and embeddings.
        ltm = imported['long_term_memory']
        ltm.save_json_list(ltm.MEMORY_FILE, [{'memory_id': 'm1', 'content': 'hello'}])
        ltm.save_json_list(ltm.MEMORY_FILE, [{'memory_id': 'm2', 'content': 'new'}])
        corrupt(tmp / ltm.MEMORY_FILE)
        recovered_memory = ltm.load_json_list(ltm.MEMORY_FILE)
        assert recovered_memory[0]['memory_id'] == 'm1'
        ltm.save_embeddings({'m1': [0.1]})
        ltm.save_embeddings({'m2': [0.2]})
        corrupt(tmp / ltm.EMBEDDINGS_FILE)
        recovered_embeddings = ltm.load_embeddings()
        assert recovered_embeddings == {'m1': [0.1]}
        print('PASS: memory + embeddings recovery')

        print('PRODUCTION_PERSISTENCE_TEST_PASS')

    finally:
        os.chdir(original_cwd)
        sys.path[:] = old_path
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
