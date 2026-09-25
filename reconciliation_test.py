import base64
import json
import hashlib
import os
import tempfile
import time
from pathlib import Path

from memory_integrity import validate_invariants
from memory_identity_provider import (
    IDENTITY_ATTESTATION_ALGORITHM_ED25519,
    IDENTITY_JWT_ALGORITHM_EDDSA,
    IDENTITY_KEY_STATUS_ACTIVE,
    IDENTITY_KEY_STATUS_GRACE,
    IDENTITY_KEY_STATUS_REVOKED,
    IDENTITY_KEY_STATUS_RETIRED,
    OIDCDiscoveryJWKSSource,
    OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED,
    OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE,
    OIDCTrustStateConflictError,
    OIDCJWTAttestationAdapter,
    TrustedAttestationKeyRegistry,
    _canonical_json,
    public_key_to_jwk,
    sign_identity_attestation_ed25519,
)
from memory_reconciliation import (
    REPAIRABLE_VIOLATION_CODES,
    REPAIR_POLICY_APPROVAL_REQUIRED_CODES,
    REPAIR_POLICY_APPROVAL_REQUIREMENTS,
    REPAIR_POLICY_AUTO,
    REPAIR_POLICY_BLOCKED,
    evaluate_repair_policy,
    get_reconciliation_history,
    inspect_reconciliation,
    prepare_repair_approval,
    prepare_repair_approvals,
    reconcile,
)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


class FakeAuthoritativeIdentityProvider:
    def __init__(self, records, provider_name="TEST-IDP"):
        self.records = dict(records)
        self.provider_name = provider_name
        self.calls = []

    def verify(self, actor, claimed_role="", reference=""):
        actor = str(actor or "").strip()
        claimed_role = str(claimed_role or "").strip()
        reference = str(reference or "").strip()
        self.calls.append({
            "actor": actor,
            "claimed_role": claimed_role,
            "reference": reference,
        })

        record = self.records.get(actor)
        if not isinstance(record, dict) or not record.get("active", True):
            return {
                "verified": False,
                "provider": self.provider_name,
                "actor": actor,
                "subject": record.get("subject") if isinstance(record, dict) else None,
                "roles": record.get("roles", []) if isinstance(record, dict) else [],
                "reference": reference,
                "status": "REVOKED" if isinstance(record, dict) and record.get("revoked") else "INACTIVE",
                "active": False,
                "revoked": bool(record.get("revoked", False)) if isinstance(record, dict) else False,
                "verified_at": record.get("verified_at") if isinstance(record, dict) else None,
                "valid_until": record.get("valid_until") if isinstance(record, dict) else None,
                "attestation_id": record.get("attestation_id") if isinstance(record, dict) else None,
                "error": "identity_not_active",
            }

        return {
            "verified": True,
            "provider": self.provider_name,
            "actor": actor,
            "subject": record.get("subject"),
            "roles": record.get("roles", []),
            "reference": reference,
            "status": "ACTIVE" if record.get("active", True) else "INACTIVE",
            "active": bool(record.get("active", True)),
            "revoked": bool(record.get("revoked", False)),
            "verified_at": record.get("verified_at"),
            "valid_until": record.get("valid_until"),
            "attestation_id": record.get("attestation_id"),
        }


class CryptographicFakeIdentityProvider(FakeAuthoritativeIdentityProvider):
    def __init__(self, records, private_key, key_id="test-key-1", provider_name="TEST-IDP"):
        super().__init__(records, provider_name=provider_name)
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id
        self.key_status = IDENTITY_KEY_STATUS_ACTIVE
        self.key_version = "1"
        self.key_not_before = ""
        self.key_not_after = "2099-01-01T00:00:00+00:00"
        self.key_registry = TrustedAttestationKeyRegistry()
        self._register_current_key()

    def _register_current_key(self):
        self.key_registry.register_key(
            self.key_id,
            self.public_key,
            algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            status=self.key_status,
            not_before=self.key_not_before,
            not_after=self.key_not_after,
            version=self.key_version,
        )

    def verify(
        self,
        actor,
        claimed_role="",
        reference="",
        attestation_nonce="",
        expected_issuer="",
        expected_audience="",
    ):
        raw = super().verify(actor, claimed_role, reference)
        record = self.records.get(str(actor or "").strip(), {})
        raw["signature_algorithm"] = IDENTITY_ATTESTATION_ALGORITHM_ED25519
        raw["signature_key_id"] = self.key_id
        raw["attestation_issuer"] = record.get("issuer", expected_issuer)
        raw["attestation_audience"] = record.get("audience", expected_audience)
        raw["attestation_nonce"] = attestation_nonce
        raw["cryptographic_attestation_verified"] = False

        raw_for_signing = dict(raw)
        raw_for_signing["attestation_signature"] = ""
        raw["attestation_signature"] = sign_identity_attestation_ed25519(
            self.private_key,
            raw_for_signing,
        )
        return raw

    def get_verification_key(self, key_id, algorithm):
        if key_id != self.key_id or algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return None
        return self.public_key

    def get_verification_key_metadata(self, key_id, algorithm):
        return self.key_registry.get_verification_key_metadata(key_id, algorithm)


def build_fixture(tmp_dir):
    write_json(
        os.path.join(tmp_dir, "memory.json"),
        [{
            "memory_id": "mem_1",
            "memory": "Abaqus",
            "status": "active",
            "importance": 3,
            "confidence": 0.8,
            "version": 1,
            "memory_type": "fact",
        }],
    )
    write_json(os.path.join(tmp_dir, "memory_archive.json"), [])

    write_json(
        os.path.join(tmp_dir, "memory_entities.json"),
        {
            "entities": [{
                "entity_id": "ent_1",
                "name": "Abaqus",
                "type": "SOFTWARE",
                "archive_state": "ACTIVE",
                "lifecycle_status": "ACTIVE",
                "version": 2,
                "history": [{
                    "snapshot": {
                        "version": 1,
                        "name": "Abaqus",
                    }
                }],
                "memory_ids": ["mem_1", "mem_1", "", "missing_memory"],
            }, {
                "entity_id": "ent_2",
                "name": "Python",
                "type": "SOFTWARE",
                "archive_state": "ACTIVE",
                "lifecycle_status": "ACTIVE",
                "version": 1,
                "history": [],
                "memory_ids": "mem_1",
            }],
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_entities_archive.json"),
        {"entities": []},
    )
    write_json(os.path.join(tmp_dir, "memory_entity_conflicts.json"), {"conflicts": []})
    write_json(os.path.join(tmp_dir, "memory_entity_recovery.json"), {"recoveries": []})
    write_json(
        os.path.join(tmp_dir, "memory_entity_relations.json"),
        {
            "relations": [{
                "relation_id": "rel_1",
                "source_entity_id": "ent_1",
                "target_entity_id": "ent_2",
                "relation": "RELATED_TO",
                "directed": True,
                "memory_ids": ["mem_1", "mem_1", "missing_memory", ""],
            }],
        },
    )

    # Intentionally corrupted graph: ghost node, no required Memory->Entity edge.
    write_json(
        os.path.join(tmp_dir, "memory_graph.json"),
        {
            "nodes": [
                {"id": "ghost", "kind": "memory"},
            ],
            "edges": [],
        },
    )

    # Intentionally corrupted canonical fields.
    write_json(
        os.path.join(tmp_dir, "memory_archive.json"),
        [{
            "memory_id": "mem_old",
            "memory": "Old memory",
            "status": "active",
        }],
    )

    write_json(
        os.path.join(tmp_dir, "memory_entities_archive.json"),
        {
            "entities": [{
                "entity_id": "ent_old",
                "name": "Old Entity",
                "archive_state": "ACTIVE",
                "lifecycle_status": "DORMANT",
                "memory_ids": ["mem_old"],
            }]
        },
    )

    write_json(
        os.path.join(tmp_dir, "memory_operations.json"),
        {
            "operations": [{
                "operation_id": "op_completed_1",
                "operation_key": "completed_key",
                "operation_type": "TEST",
                "status": "COMPLETED",
                "result_ref": "",
                "error": "",
                "result_data": {"ok": True},
                "attempt_count": 1,
                "recovery_count": 0,
                "started_at": "2026-01-01T00:00:00+00:00",
                "lease_expires_at": "2099-01-01T00:00:00+00:00",
                "last_recovery_at": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }],
        },
    )


def test_classification_is_conservative(tmp_dir):
    build_fixture(tmp_dir)
    inspection = inspect_reconciliation(tmp_dir)

    expect(not inspection["valid"], "Fixture must start invalid.")
    expect(inspection["repairable_codes"], "Fixture must contain repairable violations.")
    expect(
        set(inspection["repairable_codes"]).issubset(REPAIRABLE_VIOLATION_CODES),
        "Classification contains an unregistered repair code.",
    )


def test_repair_and_reaudit(tmp_dir):
    build_fixture(tmp_dir)

    before = validate_invariants(tmp_dir)
    expect(not before["valid"], "Corrupted fixture must fail before repair.")

    first = reconcile(tmp_dir)
    expect(first["status"] == "REPAIRED", f"Unexpected first reconciliation status: {first}")
    expect(first["executed"] is True, "First reconciliation must execute a repair operation.")
    expect(first["after"]["valid"], f"Repaired state is still invalid: {first['after']}")

    with open(os.path.join(tmp_dir, "memory_archive.json"), "r", encoding="utf-8") as file:
        memory_archive = json.load(file)
    expect(
        all(item.get("status") == "archived" for item in memory_archive),
        "Archived Memory status was not repaired.",
    )

    with open(os.path.join(tmp_dir, "memory_entities_archive.json"), "r", encoding="utf-8") as file:
        entity_archive = json.load(file)
    expect(
        all(item.get("archive_state") == "ARCHIVED" for item in entity_archive["entities"]),
        "Archived Entity state was not repaired.",
    )

    with open(os.path.join(tmp_dir, "memory_operations.json"), "r", encoding="utf-8") as file:
        operations = json.load(file)["operations"]
    completed = next(item for item in operations if item["operation_id"] == "op_completed_1")
    expect(completed["lease_expires_at"] is None, "Completed operation lease was not cleared.")

    with open(os.path.join(tmp_dir, "memory_graph.json"), "r", encoding="utf-8") as file:
        graph = json.load(file)
    node_ids = {item.get("id") for item in graph["nodes"]}
    edge_keys = {
        (item.get("source"), item.get("target"), item.get("type"))
        for item in graph["edges"]
    }
    expect("ghost" not in node_ids, "Ghost graph node survived reconciliation.")
    expect(
        ("mem_1", "ent_1", "MEMORY_HAS_ENTITY") in edge_keys,
        "Canonical Memory->Entity graph edge was not rebuilt.",
    )

    with open(os.path.join(tmp_dir, "memory_entities.json"), "r", encoding="utf-8") as file:
        entity_store = json.load(file)
    entity_by_id = {item["entity_id"]: item for item in entity_store["entities"]}
    expect(entity_by_id["ent_1"]["memory_ids"] == ["mem_1"], "Entity Memory references were not canonicalized.")
    expect(entity_by_id["ent_2"]["memory_ids"] == [], "Non-list Entity memory references were not repaired safely.")

    with open(os.path.join(tmp_dir, "memory_entity_relations.json"), "r", encoding="utf-8") as file:
        relation_store = json.load(file)
    expect(relation_store["relations"][0]["memory_ids"] == ["mem_1"], "Relation Memory references were not canonicalized.")

    repair_data = first["repair"]
    reference_repair = repair_data["authoritative_reference_repair"]
    expect(reference_repair["changed"] is True, "Authoritative reference repair did not report a change.")
    expect(reference_repair["entity_reference_count_removed"] >= 3, "Entity reference removals were not counted correctly.")
    expect(reference_repair["relation_reference_count_removed"] >= 3, "Relation reference removals were not counted correctly.")

    second = reconcile(tmp_dir)
    expect(second["status"] == "HEALTHY", f"Second reconciliation should be a no-op health check: {second}")
    expect(second["executed"] is False, "Healthy second reconciliation must not execute another repair.")


def test_reconciliation_audit_history(tmp_dir):
    build_fixture(tmp_dir)

    first = reconcile(tmp_dir)
    expect(first["status"] == "REPAIRED", f"Audit fixture did not repair: {first}")

    history = get_reconciliation_history(tmp_dir)
    expect(len(history) == 1, f"Expected exactly one reconciliation history record: {history}")

    record = history[0]
    expect(record["status"] == "COMPLETED", f"Reconciliation journal record is not completed: {record}")
    expect(record["reconciliation_status"] == "REPAIRED", f"Audit status is incorrect: {record}")
    expect(record["attempt_count"] == 1, f"Unexpected audit attempt count: {record}")
    expect(record["after"]["valid"] is True, f"Audit did not persist a healthy after-snapshot: {record}")
    expect(record["repair"]["changed"] is True, f"Audit did not persist repair details: {record}")

    second = reconcile(tmp_dir)
    expect(second["status"] == "HEALTHY", f"Second reconciliation changed healthy state: {second}")

    history_after = get_reconciliation_history(tmp_dir)
    expect(len(history_after) == 1, "A healthy no-op reconciliation must not create a new repair history record.")
    expect(history_after[0]["operation_id"] == record["operation_id"], "Repair history operation identity changed unexpectedly.")




def test_repair_reentry_after_new_corruption(tmp_dir):
    build_fixture(tmp_dir)

    first = reconcile(tmp_dir)
    expect(first["status"] == "REPAIRED", f"Initial repair failed: {first}")
    expect(first["executed"] is True, "Initial repair must execute.")

    # Reintroduce the same class of corruption after the first repair cycle.
    with open(os.path.join(tmp_dir, "memory_graph.json"), "w", encoding="utf-8") as file:
        json.dump(
            {
                "nodes": [{"id": "ghost_again", "kind": "memory"}],
                "edges": [],
            },
            file,
            ensure_ascii=False,
            indent=2,
        )

    second = reconcile(tmp_dir)
    expect(second["status"] == "REPAIRED", f"Reintroduced corruption was not repaired: {second}")
    expect(second["executed"] is True, "A new corruption cycle must execute a new repair.")
    expect(
        second["operation_id"] != first["operation_id"],
        "A later corruption cycle incorrectly reused the previous reconciliation operation.",
    )
    expect(second["after"]["valid"] is True, "Reintroduced corruption remained after the second repair.")

    history = get_reconciliation_history(tmp_dir)
    expect(len(history) == 2, f"Expected two completed reconciliation cycles: {history}")
    expect(
        history[0]["operation_id"] != history[1]["operation_id"],
        "Repair history did not record distinct reconciliation cycles.",
    )

    third = reconcile(tmp_dir)
    expect(third["status"] == "HEALTHY", f"Healthy state unexpectedly triggered another repair: {third}")
    expect(third["executed"] is False, "Healthy state must not execute another operation.")
    expect(len(get_reconciliation_history(tmp_dir)) == 2, "Healthy check created an unnecessary repair history record.")



def _project_digest(tmp_dir):
    digest = hashlib.sha256()
    for root, _, files in os.walk(tmp_dir):
        for filename in sorted(files):
            path = os.path.join(root, filename)
            relative = os.path.relpath(path, tmp_dir).replace(os.sep, "/")
            digest.update(relative.encode("utf-8"))
            with open(path, "rb") as file:
                digest.update(file.read())
    return digest.hexdigest()


def test_dry_run_is_non_destructive(tmp_dir):
    build_fixture(tmp_dir)

    before_digest = _project_digest(tmp_dir)
    before_history = get_reconciliation_history(tmp_dir)
    expect(not before_history, "Dry-run fixture must not have reconciliation history yet.")

    result = reconcile(tmp_dir, dry_run=True)

    expect(result["status"] == "DRY_RUN", f"Unexpected dry-run status: {result}")
    expect(result["dry_run"] is True, "Dry-run flag was not preserved.")
    expect(result["executed"] is False, "Dry-run must never execute a real repair operation.")
    expect(result["would_execute"] is True, "Dry-run must report that a repair would execute.")
    expect(result["operation_id"] is None, "Dry-run must not create an operation id.")
    expect(result["simulated_after"]["valid"] is True, "Dry-run simulation did not reach a healthy state.")
    expect(result["impact"]["files_would_change"], "Dry-run did not report expected file changes.")

    after_digest = _project_digest(tmp_dir)
    expect(before_digest == after_digest, "Dry-run modified project files.")
    expect(not get_reconciliation_history(tmp_dir), "Dry-run created an operation journal entry.")

    real = reconcile(tmp_dir)
    expect(real["status"] == "REPAIRED", f"Real repair failed after dry-run: {real}")
    expect(real["executed"] is True, "Real repair should execute after dry-run.")


def test_dry_run_on_healthy_state_is_noop(tmp_dir):
    build_fixture(tmp_dir)
    repaired = reconcile(tmp_dir)
    expect(repaired["status"] == "REPAIRED", f"Fixture setup repair failed: {repaired}")

    before_digest = _project_digest(tmp_dir)
    history_before = get_reconciliation_history(tmp_dir)

    result = reconcile(tmp_dir, dry_run=True)

    expect(result["status"] == "HEALTHY", f"Healthy dry-run should be HEALTHY: {result}")
    expect(result["would_execute"] is False, "Healthy dry-run must not plan a repair.")
    expect(result["impact"]["files_would_change"] == [], "Healthy dry-run reported file changes.")
    expect(_project_digest(tmp_dir) == before_digest, "Healthy dry-run changed project files.")
    expect(get_reconciliation_history(tmp_dir) == history_before, "Healthy dry-run changed repair history.")


def test_repair_plan_explainability(tmp_dir):
    build_fixture(tmp_dir)

    result = reconcile(tmp_dir, dry_run=True)
    expect(result["status"] == "DRY_RUN", f"Unexpected dry-run status: {result}")

    plan = result.get("repair_plan")
    expect(isinstance(plan, dict), "Dry-run did not return a repair_plan dictionary.")
    expect(plan["file_count"] > 0, "Repair plan did not identify changed files.")
    expect(plan["change_count"] > 0, "Repair plan did not identify field-level changes.")

    by_file = {item["file"]: item for item in plan["files"]}
    expect("memory_archive.json" in by_file, "Repair plan omitted Memory archive changes.")
    expect("memory_entities.json" in by_file, "Repair plan omitted Entity reference changes.")
    expect("memory_entity_relations.json" in by_file, "Repair plan omitted Relation reference changes.")
    expect("memory_entities_archive.json" in by_file, "Repair plan omitted Entity archive-state changes.")
    expect("memory_graph.json" in by_file, "Repair plan omitted derived Graph rebuild.")

    archive_changes = by_file["memory_archive.json"]["changes"]
    expect(
        any(
            item.get("path") == "$[0].status"
            and item.get("before") == "active"
            and item.get("after") == "archived"
            for item in archive_changes
        ),
        "Repair plan did not explain the Memory archive status change.",
    )

    entity_changes = by_file["memory_entities.json"]["changes"]
    expect(
        any(
            item.get("path") == "$.entities[0].memory_ids"
            and item.get("before") == ["mem_1", "mem_1", "", "missing_memory"]
            and item.get("after") == ["mem_1"]
            for item in entity_changes
        ),
        "Repair plan did not explain Entity memory_ids canonicalization.",
    )

    relation_changes = by_file["memory_entity_relations.json"]["changes"]
    expect(
        any(
            item.get("path") == "$.relations[0].memory_ids"
            and item.get("before") == ["mem_1", "mem_1", "missing_memory", ""]
            and item.get("after") == ["mem_1"]
            for item in relation_changes
        ),
        "Repair plan did not explain Relation memory_ids canonicalization.",
    )

    expect(
        by_file["memory_graph.json"]["changes"],
        "Graph rebuild was reported without an explainable change entry.",
    )

    real = reconcile(tmp_dir)
    expect(real["status"] == "REPAIRED", f"Real repair failed after explainability test: {real}")
    expect(real["repair_plan"]["change_count"] > 0, "Real repair did not retain the repair plan.")

def test_non_repairable_state_is_blocked(tmp_dir):
    build_fixture(tmp_dir)

    # Add an ambiguous Entity overlap that cannot safely be solved by a
    # deterministic canonical rewrite.
    with open(os.path.join(tmp_dir, "memory_entities.json"), "r", encoding="utf-8") as file:
        active = json.load(file)
    active["entities"].append({
        "entity_id": "ent_old",
        "name": "Conflicting active identity",
        "archive_state": "ACTIVE",
        "lifecycle_status": "ACTIVE",
        "version": 1,
        "history": [],
        "memory_ids": ["mem_1"],
    })
    write_json(os.path.join(tmp_dir, "memory_entities.json"), active)

    result = reconcile(tmp_dir)
    expect(result["status"] == "PARTIALLY_REPAIRED", f"Expected safe partial repair: {result}")
    blocked_codes = {item.get("code") for item in result["blocked"]}
    expect("ENTITY_ACTIVE_ARCHIVE_OVERLAP" in blocked_codes, "Ambiguous Entity overlap was not blocked.")


def test_repair_policy_gate_is_explicit(tmp_dir):
    build_fixture(tmp_dir)
    inspection = inspect_reconciliation(tmp_dir)
    policy = evaluate_repair_policy(inspection)

    expect(
        policy["effective_policy"] == REPAIR_POLICY_AUTO,
        f"Current deterministic repair set should be AUTO: {policy}",
    )
    expect(policy["policy_safe_to_auto_repair"] is True, "Current repair set is not marked safe for automatic repair.")
    expect(not policy["requires_approval"], "Current deterministic repairs unexpectedly require approval.")
    expect(not policy["requires_dry_run"], "Current deterministic repairs unexpectedly require dry-run.")
    expect(not policy["blocked_policy_codes"], "Current repairable codes must all have explicit policies.")


def test_repair_policy_fails_closed_for_unknown_code():
    synthetic = {
        "repairable_codes": ["UNKNOWN_FUTURE_REPAIR_CODE"],
    }

    policy = evaluate_repair_policy(synthetic)
    expect(policy["effective_policy"] == REPAIR_POLICY_BLOCKED, f"Unknown repair policy did not fail closed: {policy}")
    expect(
        policy["blocked_policy_codes"] == ["UNKNOWN_FUTURE_REPAIR_CODE"],
        f"Unknown repair code was not isolated as blocked: {policy}",
    )


def test_approval_gate_is_non_destructive(tmp_dir):
    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original = set(REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    try:
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        before_digest = _project_digest(tmp_dir)
        result = reconcile(tmp_dir)

        expect(result["status"] == "APPROVAL_REQUIRED", f"Expected approval gate: {result}")
        expect(result["executed"] is False, "Approval-gated repair must not execute without approval.")
        expect(result["approval_granted"] is False, "Approval flag is incorrect.")
        expect(result["policy"]["requires_approval"] is True, "Policy did not expose approval requirement.")
        expect(_project_digest(tmp_dir) == before_digest, "Approval gate changed project state.")
        expect(not get_reconciliation_history(tmp_dir), "Approval gate must not create a repair history record.")

        approved = reconcile(tmp_dir, approve=True)
        expect(approved["status"] == "REPAIRED", f"Approved repair did not execute successfully: {approved}")
        expect(approved["executed"] is True, "Approved repair must execute.")
        expect(approved["approval_granted"] is True, "Approved repair did not persist approval state in the result.")
    finally:
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original)


def test_dry_run_can_inspect_approval_gated_repair(tmp_dir):
    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original = set(REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    try:
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        before_digest = _project_digest(tmp_dir)
        result = reconcile(tmp_dir, dry_run=True)

        expect(result["status"] == "DRY_RUN", f"Approval-gated dry-run should remain inspectable: {result}")
        expect(result["policy"]["requires_approval"] is True, "Dry-run did not expose approval requirement.")
        expect(result["executed"] is False, "Dry-run must never execute repair.")
        expect(result["simulated_after"]["valid"] is True, "Approval-gated dry-run did not simulate a healthy result.")
        expect(_project_digest(tmp_dir) == before_digest, "Approval-gated dry-run changed project state.")
    finally:
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original)


def test_policy_version_and_approval_trace(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_version = reconciliation_module.REPAIR_POLICY_VERSION

    context = {
        "approval_id": "approval-test-001",
        "actor": "test_user",
        "reason": "approved deterministic reconciliation for integration test",
        "reference": "TEST-REPAIR-001",
    }

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        first = reconcile(
            tmp_dir,
            approve=True,
            approval_context=context,
        )
        expect(first["status"] == "REPAIRED", f"Approved reconciliation failed: {first}")
        expect(first["executed"] is True, "Approved reconciliation must execute.")
        expect(first["approval"]["approval_id"] == context["approval_id"], "Approval ID was not traced.")
        expect(first["approval"]["actor"] == context["actor"], "Approval actor was not traced.")
        expect(first["approval"]["reason"] == context["reason"], "Approval reason was not traced.")
        expect(first["approval"]["reference"] == context["reference"], "Approval reference was not traced.")
        expect(first["policy"]["policy_version"] == original_version, "Policy version was not exposed.")
        expect(len(first["policy"]["policy_fingerprint"]) == 64, "Policy fingerprint is not SHA256-sized.")
        expect(len(first["approval"]["approval_fingerprint"]) == 64, "Approval fingerprint is not SHA256-sized.")

        history = get_reconciliation_history(tmp_dir)
        expect(len(history) == 1, f"Expected one audited approval repair: {history}")
        record = history[0]
        expect(record["policy_version"] == original_version, "History lost policy version.")
        expect(record["policy_fingerprint"] == first["policy"]["policy_fingerprint"], "History lost policy fingerprint.")
        expect(record["approval"]["approval_id"] == context["approval_id"], "History lost approval context.")
        expect(record["approval_fingerprint"] == first["approval"]["approval_fingerprint"], "History lost approval fingerprint.")

        # Reintroduce the same corruption under a new policy version.
        with open(os.path.join(tmp_dir, "memory_graph.json"), "w", encoding="utf-8") as file:
            json.dump({"nodes": [{"id": "ghost_again", "kind": "memory"}], "edges": []}, file, ensure_ascii=False, indent=2)

        reconciliation_module.REPAIR_POLICY_VERSION = "2.0"

        second = reconcile(
            tmp_dir,
            approve=True,
            approval_context=context,
        )
        expect(second["status"] == "REPAIRED", f"Repair under new policy version failed: {second}")
        expect(second["executed"] is True, "New policy version must create a new repair operation.")
        expect(second["operation_id"] != first["operation_id"], "Policy version change reused the old operation identity.")
        expect(second["policy"]["policy_version"] == "2.0", "New policy version was not recorded.")
        expect(second["policy"]["policy_fingerprint"] != first["policy"]["policy_fingerprint"], "Policy fingerprint did not change with policy version.")

        history_after = get_reconciliation_history(tmp_dir)
        expect(len(history_after) == 2, f"Expected two distinct policy-versioned repair records: {history_after}")
        expect(history_after[0]["policy_version"] == original_version, "Historical policy version was rewritten.")
        expect(history_after[1]["policy_version"] == "2.0", "Second repair did not retain its policy version.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_VERSION = original_version


def test_approval_expiration_and_replay_protection(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="test_user",
            reason="approval expiration/replay test",
            reference="TEST-APPROVAL-REPLAY",
            ttl_seconds=1,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")
        approval = prepared["approval"]
        expect(approval["repair_plan_fingerprint"] == prepared["repair_plan_fingerprint"], "Prepared approval is not bound to the repair plan.")
        expect(approval["expires_at"], "Prepared approval has no expiration.")

        # Rebuild a deterministic expired token without sleeping.
        expired = dict(approval)
        expired["expires_at"] = "2000-01-01T00:00:00+00:00"
        expired["approval_fingerprint"] = None
        identity = dict(expired)
        identity["fingerprint"] = None
        expired["approval_fingerprint"] = None
        expired["approval_fingerprint"] = None

        base_context = {
            "schema_version": expired.get("schema_version"),
            "approved": True,
            "approval_id": expired.get("approval_id"),
            "actor": expired.get("actor"),
            "reason": expired.get("reason"),
            "reference": expired.get("reference"),
            "issued_at": expired.get("issued_at"),
            "expires_at": expired.get("expires_at"),
            "policy_version": expired.get("policy_version"),
            "policy_fingerprint": expired.get("policy_fingerprint"),
            "repair_plan_fingerprint": expired.get("repair_plan_fingerprint"),
            "previous_operation_id": expired.get("previous_operation_id"),
            "previous_operation_key": expired.get("previous_operation_key"),
        }
        base_context["fingerprint"] = reconciliation_module._approval_fingerprint(base_context)

        before_digest = _project_digest(tmp_dir)
        expired_result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=base_context,
        )
        expect(expired_result["status"] == "APPROVAL_EXPIRED", f"Expired approval was not rejected: {expired_result}")
        expect(expired_result["executed"] is False, "Expired approval executed a repair.")
        expect(_project_digest(tmp_dir) == before_digest, "Expired approval changed project state.")

        fresh = prepare_repair_approval(
            tmp_dir,
            actor="test_user",
            reason="valid approval",
            reference="TEST-APPROVAL-REPLAY-VALID",
            ttl_seconds=900,
        )
        expect(fresh["status"] == "APPROVAL_READY", f"Fresh approval preparation failed: {fresh}")
        approved = reconcile(
            tmp_dir,
            approve=True,
            approval_context=fresh["approval"],
        )
        expect(approved["status"] == "REPAIRED", f"Fresh bound approval did not execute: {approved}")
        expect(approved["executed"] is True, "Fresh bound approval did not execute.")

        # Reintroduce corruption. The same approval was issued for the prior
        # repair cycle and must not authorize this new cycle.
        with open(os.path.join(tmp_dir, "memory_graph.json"), "w", encoding="utf-8") as file:
            json.dump({"nodes": [{"id": "replayed_ghost", "kind": "memory"}], "edges": []}, file, ensure_ascii=False, indent=2)

        before_replay_digest = _project_digest(tmp_dir)
        replay = reconcile(
            tmp_dir,
            approve=True,
            approval_context=approved["approval"],
        )
        expect(replay["status"] == "APPROVAL_INVALID", f"Old approval was replayed: {replay}")
        expect(replay["executed"] is False, "Replayed approval executed a new repair cycle.")
        replay_codes = {item.get("code") for item in replay["blocked"]}
        expect(
            "APPROVAL_CYCLE_MISMATCH" in replay_codes or "APPROVAL_REPAIR_PLAN_MISMATCH" in replay_codes,
            f"Replay protection reported unexpected codes: {replay_codes}",
        )
        expect(_project_digest(tmp_dir) == before_replay_digest, "Rejected approval replay changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)


def test_approval_one_time_consumption(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_apply = reconciliation_module._apply_repairs

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="one_time_user",
            reason="one-time approval test",
            reference="TEST-ONE-TIME",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        # Force the first execution to fail after the idempotent operation is
        # claimed. A failed operation must still consume the approval.
        def failing_apply(base_path, repairable_codes):
            raise RuntimeError("forced approval consumption failure")

        reconciliation_module._apply_repairs = failing_apply
        try:
            reconcile(
                tmp_dir,
                approve=True,
                approval_context=prepared["approval"],
            )
            raise AssertionError("Forced failure did not propagate.")
        except RuntimeError:
            pass

        reconciliation_module._apply_repairs = original_apply

        before_replay_digest = _project_digest(tmp_dir)
        replay = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(replay["status"] == "APPROVAL_INVALID", f"Consumed approval was accepted again: {replay}")
        expect(replay["executed"] is False, "Consumed approval executed a second operation.")
        blocked_codes = {item.get("code") for item in replay["blocked"]}
        expect("APPROVAL_ALREADY_CONSUMED" in blocked_codes, f"Missing one-time consumption violation: {blocked_codes}")
        expect(_project_digest(tmp_dir) == before_replay_digest, "Consumed approval replay changed project state.")

        history = get_reconciliation_history(tmp_dir)
        expect(len(history) == 1, f"Failed consumed operation should remain the only reconciliation record: {history}")
        expect(history[0]["status"] == "FAILED", f"Forced approval consumption test did not persist FAILED operation: {history}")
    finally:
        reconciliation_module._apply_repairs = original_apply
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)


def test_approval_consumption_allows_crash_recovery(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_apply = reconciliation_module._apply_repairs

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="recovery_user",
            reason="approval recovery test",
            reference="TEST-ONE-TIME-RECOVERY",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        def crashing_apply(base_path, repairable_codes):
            raise KeyboardInterrupt("forced crash")

        reconciliation_module._apply_repairs = crashing_apply
        try:
            reconcile(
                tmp_dir,
                approve=True,
                approval_context=prepared["approval"],
            )
            raise AssertionError("Forced crash did not propagate.")
        except KeyboardInterrupt:
            pass

        reconciliation_module._apply_repairs = original_apply

        operations_path = os.path.join(tmp_dir, "memory_operations.json")
        with open(operations_path, "r", encoding="utf-8") as file:
            operation_store = json.load(file)

        reconciliation_operations = [
            item
            for item in operation_store["operations"]
            if item.get("operation_type") == "RECONCILIATION_REPAIR"
        ]
        expect(len(reconciliation_operations) == 1, "Crash test did not create one reconciliation operation.")
        expect(reconciliation_operations[0]["status"] == "STARTED", "Crash-like failure did not preserve STARTED state.")

        # Expire the lease so the existing transaction recovery mechanism can
        # legitimately reclaim the exact same operation.
        reconciliation_operations[0]["lease_expires_at"] = "2000-01-01T00:00:00+00:00"
        with open(operations_path, "w", encoding="utf-8") as file:
            json.dump(operation_store, file, ensure_ascii=False, indent=2)

        recovered = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(recovered["status"] == "REPAIRED", f"Crash recovery was blocked by one-time approval semantics: {recovered}")
        expect(recovered["executed"] is True, "Recovered operation did not execute.")
        expect(recovered["operation_id"] == reconciliation_operations[0]["operation_id"], "Recovery created a new operation instead of reclaiming the original.")
        expect(recovered["approval_consumed"] is True, "Recovered repair did not preserve approval consumption metadata.")
    finally:
        reconciliation_module._apply_repairs = original_apply
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)

def test_multi_approver_quorum_and_distinct_actor_policy(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[
                {"actor": "alice", "reason": "reviewed repair", "reference": "APP-A"},
                {"actor": "bob", "reason": "independent review", "reference": "APP-B"},
            ],
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Multi-approval preparation failed: {prepared}")
        expect(prepared["approval_requirement"]["required_count"] == 2, "Two approvals were not required.")
        expect(prepared["approval_requirement"]["distinct_actors"] is True, "Distinct actor requirement was lost.")
        expect(len(prepared["approvals"]) == 2, "Expected two prepared approvals.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval_context"],
        )
        expect(result["status"] == "REPAIRED", f"Two-approver repair failed: {result}")
        expect(result["executed"] is True, "Two-approver repair did not execute.")
        expect(result["approval_requirement"]["required_count"] == 2, "Result lost approval quorum requirement.")
        expect(len(result["approval_fingerprints"]) == 2, "Both approval fingerprints were not persisted.")
        expect(result["approval"]["approval_count"] == 2, "Approval trace did not retain both approvers.")
        expect(
            {item["actor"] for item in result["approval"]["approvals"]} == {"alice", "bob"},
            "Approval trace lost the distinct approver identities.",
        )

        history = get_reconciliation_history(tmp_dir)
        expect(len(history) == 1, f"Expected one multi-approval history record: {history}")
        expect(history[0]["approval_requirement"]["required_count"] == 2, "History lost quorum requirement.")
        expect(len(history[0]["approval_fingerprints"]) == 2, "History lost both approval fingerprints.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_multi_approver_insufficient_quorum(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[{"actor": "alice", "reason": "single review", "reference": "APP-A"}],
            ttl_seconds=900,
        )
        expect(
            prepared["status"] == "APPROVAL_COUNT_INSUFFICIENT",
            f"Insufficient quorum was not rejected at preparation: {prepared}",
        )
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_multi_approver_distinct_actor_requirement(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[
                {"actor": "alice", "reason": "review one", "reference": "APP-A"},
                {"actor": "alice", "reason": "review two", "reference": "APP-A2"},
            ],
            ttl_seconds=900,
        )
        expect(
            prepared["status"] == "APPROVAL_DISTINCT_ACTORS_REQUIRED",
            f"Repeated actor was accepted despite distinct-actor policy: {prepared}",
        )
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_multi_approver_replay_consumption(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)
    original_apply = reconciliation_module._apply_repairs

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[
                {"actor": "alice", "reason": "reviewed repair", "reference": "APP-A"},
                {"actor": "bob", "reason": "independent review", "reference": "APP-B"},
            ],
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Multi-approval preparation failed: {prepared}")

        def failing_apply(base_path, repairable_codes):
            raise RuntimeError("forced multi-approval consumption failure")

        reconciliation_module._apply_repairs = failing_apply
        try:
            reconcile(
                tmp_dir,
                approve=True,
                approval_context=prepared["approval_context"],
            )
            raise AssertionError("Forced multi-approval failure did not propagate.")
        except RuntimeError:
            pass

        reconciliation_module._apply_repairs = original_apply

        before = _project_digest(tmp_dir)
        replay = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval_context"],
        )
        expect(replay["status"] == "APPROVAL_INVALID", f"Consumed multi-approval was replayed: {replay}")
        expect(replay["executed"] is False, "Consumed multi-approval executed a second cycle.")
        blocked_codes = {item.get("code") for item in replay["blocked"]}
        expect("APPROVAL_ALREADY_CONSUMED" in blocked_codes, "Multi-approval consumption was not enforced.")
        expect(_project_digest(tmp_dir) == before, "Rejected multi-approval replay changed project state.")

        history = get_reconciliation_history(tmp_dir)
        expect(len(history) == 1, f"Expected one failed reconciliation record: {history}")
        expect(history[0]["status"] == "FAILED", "Failed multi-approval operation was not journaled as FAILED.")
    finally:
        reconciliation_module._apply_repairs = original_apply
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)



def test_role_based_approval_constraints(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
            "allowed_roles": ["reviewer", "security"],
            "required_roles": ["reviewer", "security"],
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[
                {
                    "actor": "alice",
                    "role": "reviewer",
                    "reason": "reviewed deterministic repair",
                    "reference": "ROLE-A",
                },
                {
                    "actor": "bob",
                    "role": "security",
                    "reason": "security review",
                    "reference": "ROLE-B",
                },
            ],
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Role-constrained preparation failed: {prepared}")
        expect(prepared["approval_requirement"]["required_roles"] == ["reviewer", "security"], "Required roles were lost during preparation.")
        expect({item["role"] for item in prepared["approvals"]} == {"reviewer", "security"}, "Prepared approvals lost role metadata.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval_context"],
        )
        expect(result["status"] == "REPAIRED", f"Role-constrained repair failed: {result}")
        expect(result["executed"] is True, "Role-constrained repair did not execute.")
        expect({item["role"] for item in result["approval"]["approvals"]} == {"reviewer", "security"}, "Role trace was not persisted.")
        expect(set(result["approval"]["approval_roles"]) == {"reviewer", "security"}, "Approval role summary was not persisted.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_role_based_approval_rejects_unauthorized_role(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="reviewer",
            reason="wrong role test",
            reference="ROLE-DENY",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Unauthorized role was accepted: {result}")
        expect(result["executed"] is False, "Unauthorized role executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_ROLE_NOT_ALLOWED" in blocked_codes, "Missing unauthorized-role violation.")
        expect(_project_digest(tmp_dir) == before, "Rejected role approval changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_approval_delegation_semantics(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["manager"],
            "allow_delegation": True,
            "require_delegation_reference": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="delegate",
            role="manager",
            reason="delegated approval",
            reference="DELEGATED-APPROVAL",
            delegated_by="director",
            delegation_reason="director delegated the repair review",
            delegation_reference="DEL-2026-001",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Delegated approval preparation failed: {prepared}")
        expect(prepared["approval"]["delegated_by"] == "director", "Delegator was not retained.")
        expect(prepared["approval"]["delegation_reference"] == "DEL-2026-001", "Delegation reference was not retained.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "REPAIRED", f"Allowed delegated approval failed: {result}")
        expect(result["approval"]["approvals"][0]["delegated_by"] == "director", "Delegation metadata was lost in trace.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)



def test_delegation_reference_requirement_is_enforced(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["manager"],
            "allow_delegation": True,
            "require_delegation_reference": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="delegate",
            role="manager",
            reason="missing delegation reference test",
            reference="DELEGATED-MISSING-REF",
            delegated_by="director",
            delegation_reason="reference deliberately omitted",
            delegation_reference="",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Missing delegation reference was accepted: {result}")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_DELEGATION_REFERENCE_REQUIRED" in blocked_codes, "Missing delegation-reference violation.")
        expect(result["executed"] is False, "Missing delegation reference executed a repair.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_approval_delegation_is_blocked_without_policy_permission(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["manager"],
            "allow_delegation": False,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="delegate",
            role="manager",
            reason="delegation denied test",
            reference="DELEGATED-DENY",
            delegated_by="director",
            delegation_reason="should be blocked",
            delegation_reference="DEL-DENY",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Disallowed delegation was accepted: {result}")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_DELEGATION_NOT_ALLOWED" in blocked_codes, "Missing delegation-policy violation.")
        expect(result["executed"] is False, "Disallowed delegation executed a repair.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)

def test_authoritative_identity_requires_active_status(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = FakeAuthoritativeIdentityProvider({
        "alice": {
            "subject": "sub-alice",
            "roles": ["security"],
            "active": False,
            "revoked": False,
            "attestation_id": "att-inactive-1",
        }
    })

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="active status test",
            reference="ACTIVE-1",
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_INVALID", f"Inactive identity was accepted: {prepared}")
        expect("APPROVAL_IDENTITY_INACTIVE" in prepared["identity_validation"]["codes"], "Inactive identity violation missing.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_authoritative_identity_revocation_blocks_execution(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = FakeAuthoritativeIdentityProvider({
        "alice": {
            "subject": "sub-alice",
            "roles": ["security"],
            "active": True,
            "revoked": False,
            "attestation_id": "att-revocation-1",
        }
    })

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="revocation re-check",
            reference="REVOCATION-1",
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Active identity preparation failed: {prepared}")
        expect(prepared["approval"]["identity_status"] == "ACTIVE", "Active identity status was not traced.")
        expect(prepared["approval"]["identity_active"] is True, "Active identity flag was not traced.")
        expect(prepared["approval"]["identity_attestation_id"] == "att-revocation-1", "Attestation ID was not traced.")

        provider.records["alice"]["revoked"] = True
        provider.records["alice"]["active"] = False

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=provider,
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Revoked identity was accepted: {result}")
        expect(result["executed"] is False, "Revoked identity executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_IDENTITY_REVOKED" in blocked_codes, "Missing revoked-identity violation.")
        expect(_project_digest(tmp_dir) == before, "Revoked identity rejection mutated project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_authoritative_identity_attestation_expiration_blocks(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = FakeAuthoritativeIdentityProvider({
        "alice": {
            "subject": "sub-alice",
            "roles": ["security"],
            "active": True,
            "revoked": False,
            "valid_until": "2000-01-01T00:00:00+00:00",
            "attestation_id": "att-expired-1",
        }
    })

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="expired attestation",
            reference="ATTEST-EXPIRED",
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_INVALID", f"Expired identity attestation was accepted: {prepared}")
        expect("APPROVAL_IDENTITY_ATTESTATION_EXPIRED" in prepared["identity_validation"]["codes"], "Missing expired-attestation violation.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_active_identity_policy_changes_fingerprint(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP",
        }
        first = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "identity_provider": "TEST-IDP",
        }
        second = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(first["approval_requirement"]["require_active_identity"] is False, "Active identity requirement unexpectedly enabled in baseline policy.")
        expect(second["approval_requirement"]["require_active_identity"] is True, "Active identity requirement was not reflected in policy.")
        expect(second["policy_fingerprint"] != first["policy_fingerprint"], "Active identity policy change did not alter policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)

def test_oidc_trust_state_recovery_journal(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from memory_storage import interprocess_lock

    issuer = "https://issuer.test/journal"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/journal/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_state.json")
    key_v1 = Ed25519PrivateKey.generate()
    key_v2 = Ed25519PrivateKey.generate()
    current_jwks = {
        "keys": [public_key_to_jwk(key_v1.public_key(), "journal-v1", version="1", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock = [4000.0]

    def fetch_json(url, timeout_seconds, request_headers=None):
        if url == discovery_url:
            return {"issuer": issuer, "jwks_uri": jwks_url}, {"status": 200, "cache-control": "max-age=10", "etag": '"j1"'}
        return json.loads(json.dumps(current_jwks)), {"status": 200, "cache-control": "max-age=10", "etag": '"jk1"'}

    first = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    expect(first.refresh()["success"] is True, "Initial journal fixture refresh failed.")

    second = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    stale_revision = second.get_discovery_metadata()["state_revision"]

    current_jwks = {
        "keys": [public_key_to_jwk(key_v2.public_key(), "journal-v2", version="2", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock[0] = 4011.0
    expect(first.refresh()["success"] is True, "Journal fixture rotation failed.")
    durable_revision = first.get_discovery_metadata()["state_revision"]

    second._jwks_uri = "https://keys.issuer.test/journal/divergent.json"
    second._discovery_document = {"issuer": issuer, "jwks_uri": second._jwks_uri}
    second.registry.refresh_from_jwks(
        {"keys": [public_key_to_jwk(key_v1.public_key(), "journal-divergent", version="3", status=IDENTITY_KEY_STATUS_ACTIVE)]},
        source=second._jwks_uri,
        retire_missing=True,
    )

    conflict = None
    with interprocess_lock(state_path + ".lock", timeout_seconds=5):
        try:
            second._persist_state()
        except OIDCTrustStateConflictError as exc:
            conflict = exc
    expect(conflict is not None, "Journal fixture did not produce a conflict.")

    recovery = second._recover_from_state_conflict(conflict)
    expect(recovery["recovered"] is True, "Journal recovery did not recover authoritative state.")

    journal = second.get_trust_state_journal(limit=20)
    event_types = [item.get("event_type") for item in journal]
    expect("CONFLICT_DETECTED" in event_types, "Conflict detection was not written to the trust-state journal.")
    expect("RECOVERY_DECISION" in event_types, "Recovery decision was not written to the trust-state journal.")

    conflict_record = next(item for item in journal if item.get("event_type") == "CONFLICT_DETECTED")
    expect(conflict_record["details"]["expected_revision"] == stale_revision, "Journal lost expected revision.")
    expect(conflict_record["details"]["actual_revision"] == durable_revision, "Journal lost actual durable revision.")

    recovery_record = next(item for item in journal if item.get("event_type") == "RECOVERY_DECISION")
    expect(recovery_record["details"]["recovered"] is True, "Journal recovery record is not marked recovered.")
    expect(recovery_record["details"]["decision"] == OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE, "Journal recorded the wrong recovery decision.")

    with open(state_path + ".journal", "r", encoding="utf-8") as file:
        persisted_journal = json.load(file)
    expect(persisted_journal["schema_version"] == 3, "Unexpected trust-state journal schema version.")
    expect(len(persisted_journal["records"]) >= 2, "Trust-state journal did not persist audit records.")

    restarted = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    restarted_journal = restarted.get_trust_state_journal(limit=20)
    expect(len(restarted_journal) == len(journal), "Trust-state journal did not survive restart.")
    expect(restarted.get_discovery_metadata()["journal_record_count"] >= 2, "Journal metadata did not expose persisted history.")

    print("PASS: trust-state conflict history is persisted")
    print("PASS: recovery decisions are auditable")
    print("PASS: trust-state journal survives process restart")
    print("PASS: journal preserves expected and authoritative revisions")



def test_oidc_trust_state_journal_integrity_and_replay(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/journal-integrity"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/journal-integrity/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_integrity_state.json")
    key = Ed25519PrivateKey.generate()

    def fetch_json(url, timeout_seconds, request_headers=None):
        if url == discovery_url:
            return {"issuer": issuer, "jwks_uri": jwks_url}, {"status": 200, "cache-control": "max-age=10", "etag": '"i1"'}
        return {"keys": [public_key_to_jwk(key.public_key(), "integrity-key", version="1", status=IDENTITY_KEY_STATUS_ACTIVE)]}, {"status": 200, "cache-control": "max-age=10", "etag": '"ik1"'}

    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: 5000.0,
    )
    expect(source.refresh()["success"] is True, "Journal integrity fixture refresh failed.")

    # Create a conflict/recovery pair so replay has meaningful events.
    second = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: 5001.0,
    )
    source._state_revision += 1
    source._state_fingerprint = "divergent-fixture"
    source._persisted_state_fingerprint = "divergent-fixture"
    try:
        source._persist_state()
    except OIDCTrustStateConflictError as exc:
        second._record_state_conflict(
            exc.expected_revision,
            exc.actual_revision,
            exc.expected_fingerprint,
            exc.actual_fingerprint,
        )
        second._recover_from_state_conflict(exc)

    verification = second.verify_trust_state_journal()
    expect(verification["valid"] is True, f"Fresh trust-state journal failed integrity verification: {verification}")
    replay = second.replay_trust_state_journal()
    expect(replay["success"] is True, "Trust-state journal replay failed.")
    expect(replay["summary"]["events"] >= 1, "Journal replay returned no events.")

    journal_path = state_path + ".journal"
    with open(journal_path, "r", encoding="utf-8") as file:
        tampered = json.load(file)
    tampered["records"][0]["event_type"] = "TAMPERED"
    with open(journal_path, "w", encoding="utf-8") as file:
        json.dump(tampered, file, ensure_ascii=False, indent=2)

    tampered_result = second.verify_trust_state_journal()
    expect(tampered_result["valid"] is False, "Journal tampering was not detected.")
    expect(tampered_result["reason"] in {"record_hash_mismatch", "previous_hash_mismatch"}, "Unexpected tamper failure reason.")

    # Restore the last known-good journal from the storage backup and verify again.
    backup_path = journal_path + ".bak"
    expect(os.path.exists(backup_path), "Journal backup was not created.")
    with open(backup_path, "r", encoding="utf-8") as source_file:
        backup = json.load(source_file)
    with open(journal_path, "w", encoding="utf-8") as file:
        json.dump(backup, file, ensure_ascii=False, indent=2)
    restored = second.verify_trust_state_journal()
    expect(restored["valid"] is True, f"Journal did not recover to a valid chain: {restored}")

    print("PASS: trust-state journal hash chain is valid")
    print("PASS: journal tampering is detected")
    print("PASS: journal replay is observational and deterministic")
    print("PASS: journal backup recovery restores integrity")



def _journal_concurrency_worker(state_path, worker_id):
    issuer = "https://issuer.test/journal-concurrency"
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 7000.0 + worker_id,
    )
    source._state_revision = worker_id
    source._state_fingerprint = f"worker-{worker_id}"
    source._append_trust_state_journal(
        "CONCURRENT_TEST_EVENT",
        {"worker_id": worker_id},
    )


def test_oidc_trust_state_journal_concurrency_and_atomicity(tmp_dir):
    import multiprocessing

    issuer = "https://issuer.test/journal-concurrency"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_concurrency_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 6999.0,
    )

    worker_count = 8
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_journal_concurrency_worker, args=(state_path, index))
        for index in range(1, worker_count + 1)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(15)
        expect(not process.is_alive(), "Journal concurrency worker did not terminate.")
        expect(process.exitcode == 0, f"Journal concurrency worker failed: exit={process.exitcode}")

    verification = source.verify_trust_state_journal()
    expect(verification["valid"] is True, f"Concurrent journal writes corrupted the hash chain: {verification}")

    records = source.get_trust_state_journal(limit=worker_count + 5)
    expect(len(records) == worker_count, f"Concurrent journal writes lost records: {records}")
    expect(
        [item.get("sequence") for item in records] == list(range(1, worker_count + 1)),
        "Concurrent journal writes produced duplicate or missing sequence numbers.",
    )
    worker_ids = sorted(item.get("details", {}).get("worker_id") for item in records)
    expect(worker_ids == list(range(1, worker_count + 1)), "Concurrent journal writes lost or duplicated event payloads.")
    expect(os.path.exists(state_path + ".journal.lock"), "Journal inter-process lock file was not created.")

    metadata = source.get_discovery_metadata()
    expect(metadata.get("journal_lock_path") == state_path + ".journal.lock", "Journal lock path was not exposed in metadata.")

    print("PASS: concurrent trust-state journal writers are serialized")
    print("PASS: concurrent journal writes preserve every audit event")
    print("PASS: concurrent journal writes preserve hash-chain integrity")
    print("PASS: journal lock state is traceable")


def test_oidc_trust_state_journal_checkpoint_and_compaction(tmp_dir):
    import memory_identity_provider as identity_module

    issuer = "https://issuer.test/journal-checkpoint"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_checkpoint_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8000.0,
    )
    source._state_revision = 42
    source._state_fingerprint = "authoritative-trust-fingerprint"
    source._persisted_state_fingerprint = "authoritative-trust-fingerprint"

    for index in range(1, 9):
        source._append_trust_state_journal(
            "CHECKPOINT_TEST_EVENT",
            {"index": index},
        )

    before_compact = source.verify_trust_state_journal()
    expect(before_compact["valid"] is True, f"Pre-compaction journal is invalid: {before_compact}")

    result = source.compact_trust_state_journal(retain_records=2)
    expect(result["success"] is True, f"Checkpoint compaction failed: {result}")
    expect(result["status"] == "COMPACTED", f"Unexpected compaction status: {result}")
    expect(result["checkpoint_sequence"] == 6, f"Checkpoint covered the wrong sequence: {result}")
    expect(result["retained_tail_records"] == 2, f"Compaction retained the wrong tail size: {result}")

    with open(state_path + ".journal", "r", encoding="utf-8") as file:
        journal = json.load(file)

    expect(journal["schema_version"] == identity_module.OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION, "Wrong checkpointed journal schema.")
    expect(isinstance(journal.get("checkpoint"), dict), "Compaction did not persist an immutable checkpoint object.")
    checkpoint = journal["checkpoint"]
    expect(checkpoint["sequence"] == 6, "Checkpoint sequence is incorrect.")
    expect(checkpoint["record_hash"] == journal["records"][0]["previous_record_hash"], "Checkpoint is not the hash-chain predecessor of the tail.")
    expect(checkpoint["state_revision"] == 42, "Checkpoint lost trust-state revision.")
    expect(checkpoint["state_fingerprint"] == "authoritative-trust-fingerprint", "Checkpoint lost trust-state fingerprint.")
    expect(checkpoint["checkpoint_hash"], "Checkpoint hash is missing.")
    expect(checkpoint["checkpoint_id"], "Checkpoint ID is missing.")
    expect([item["sequence"] for item in journal["records"]] == [7, 8], "Tail sequences are not preserved after compaction.")
    expect(journal["head_hash"] == journal["records"][-1]["record_hash"], "Journal head hash is incorrect after compaction.")

    verification = source.verify_trust_state_journal()
    expect(verification["valid"] is True, f"Checkpointed journal failed verification: {verification}")
    expect(verification["checkpoint_present"] is True, "Checkpoint was not recognized during verification.")
    expect(verification["coverage_end_sequence"] == 8, "Coverage end sequence is incorrect.")

    replay = source.replay_trust_state_journal()
    expect(replay["success"] is True, f"Checkpoint + tail replay failed: {replay}")
    expect(replay["summary"]["events"] == 8, "Replay lost checkpointed event coverage.")
    expect(replay["summary"]["events_replayed"] == 2, "Replay reported the wrong retained tail size.")
    expect(replay["summary"]["checkpointed_events"] == 6, "Replay lost checkpoint coverage count.")
    expect(replay["summary"]["coverage_end_sequence"] == 8, "Replay coverage end is incorrect.")
    expect(replay["checkpoint"]["sequence"] == 6, "Replay did not expose the checkpoint boundary.")

    with open(state_path + ".journal", "rb") as file:
        digest_before_idempotent_call = hashlib.sha256(file.read()).hexdigest()
    noop = source.compact_trust_state_journal(retain_records=2)
    expect(noop["success"] is True and noop["status"] == "NOOP", f"Repeated compaction was not idempotent: {noop}")
    with open(state_path + ".journal", "rb") as file:
        digest_after_idempotent_call = hashlib.sha256(file.read()).hexdigest()
    expect(digest_before_idempotent_call == digest_after_idempotent_call, "Idempotent compaction changed durable bytes.")

    checkpoint_before_append = source.get_trust_state_journal_checkpoint()
    source._append_trust_state_journal("POST_CHECKPOINT_APPEND", {"index": 9})
    checkpoint_after_append = source.get_trust_state_journal_checkpoint()
    expect(checkpoint_after_append == checkpoint_before_append, "Ordinary journal append mutated the immutable checkpoint.")
    expect(source.verify_trust_state_journal()["coverage_end_sequence"] == 9, "Post-checkpoint append broke sequence coverage.")

    print("PASS: trust-state journal checkpoint preserves sequence/hash/state binding")
    print("PASS: checkpoint remains immutable across ordinary append")
    print("PASS: checkpoint + journal tail replay verifies independently")
    print("PASS: journal compaction is idempotent")



def test_oidc_trust_state_journal_legacy_schema_upgrade(tmp_dir):
    issuer = "https://issuer.test/journal-legacy-upgrade"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_legacy_upgrade_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8050.0,
    )
    source._state_revision = 5
    source._state_fingerprint = "legacy-upgrade-fingerprint"
    source._persisted_state_fingerprint = "legacy-upgrade-fingerprint"

    for index in range(1, 4):
        source._append_trust_state_journal("LEGACY_UPGRADE_TEST", {"index": index})

    journal_path = state_path + ".journal"
    with open(journal_path, "r", encoding="utf-8") as file:
        modern = json.load(file)
    legacy = {
        "schema_version": 2,
        "records": modern["records"],
        "head_hash": modern["head_hash"],
    }
    with open(journal_path, "w", encoding="utf-8") as file:
        json.dump(legacy, file, ensure_ascii=False, indent=2)

    expect(source.verify_trust_state_journal()["valid"] is True, "Valid schema-2 journal was rejected before upgrade.")
    source._append_trust_state_journal("LEGACY_UPGRADE_APPEND", {"index": 4})

    with open(journal_path, "r", encoding="utf-8") as file:
        upgraded = json.load(file)
    expect(upgraded["schema_version"] == 3, "Legacy journal was not upgraded to the checkpoint-capable schema.")
    expect(upgraded.get("checkpoint") is None, "Legacy upgrade unexpectedly invented a checkpoint.")
    expect([item["sequence"] for item in upgraded["records"]] == [1, 2, 3, 4], "Legacy sequence continuity was not preserved.")
    expect(source.verify_trust_state_journal()["valid"] is True, "Upgraded legacy journal failed verification.")

    print("PASS: pre-checkpoint journal schema remains readable")
    print("PASS: pre-checkpoint journal upgrades without sequence loss")


def test_oidc_trust_state_journal_automatic_compaction_bounds_tail(tmp_dir):
    import memory_identity_provider as identity_module

    issuer = "https://issuer.test/journal-auto-compaction"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_auto_compaction_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8060.0,
    )
    source._state_revision = 6
    source._state_fingerprint = "automatic-compaction-fingerprint"
    source._persisted_state_fingerprint = "automatic-compaction-fingerprint"

    original_max = identity_module.OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS
    original_retain = identity_module.OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS
    identity_module.OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS = 6
    identity_module.OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS = 3
    try:
        for index in range(1, 8):
            source._append_trust_state_journal("AUTOMATIC_COMPACTION_TEST", {"index": index})
    finally:
        identity_module.OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS = original_max
        identity_module.OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS = original_retain

    verification = source.verify_trust_state_journal()
    expect(verification["valid"] is True, f"Automatically compacted journal failed verification: {verification}")
    expect(verification["coverage_end_sequence"] == 7, "Automatic compaction changed journal sequence coverage.")
    checkpoint = source.get_trust_state_journal_checkpoint()
    expect(checkpoint["sequence"] == 3, "Automatic compaction did not create the configured checkpoint boundary.")
    tail = source.get_trust_state_journal(limit=20)
    expect(len(tail) == 4, "Automatic compaction did not bound the tail to the configured retention window.")
    expect([item["sequence"] for item in tail] == [4, 5, 6, 7], "Automatic compaction produced the wrong retained tail.")

    print("PASS: automatic journal compaction bounds tail growth")

def test_oidc_trust_state_journal_checkpoint_corruption_and_backup_recovery(tmp_dir):
    issuer = "https://issuer.test/journal-checkpoint-corruption"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_checkpoint_corruption_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8100.0,
    )
    source._state_revision = 10
    source._state_fingerprint = "checkpoint-integrity-fingerprint"
    source._persisted_state_fingerprint = "checkpoint-integrity-fingerprint"

    for index in range(1, 7):
        source._append_trust_state_journal("CHECKPOINT_CORRUPTION_TEST", {"index": index})
    compact = source.compact_trust_state_journal(retain_records=2)
    expect(compact["status"] == "COMPACTED", "Corruption fixture did not compact.")

    journal_path = state_path + ".journal"
    with open(journal_path, "r", encoding="utf-8") as file:
        tampered = json.load(file)
    tampered["checkpoint"]["state_revision"] = 999999
    with open(journal_path, "w", encoding="utf-8") as file:
        json.dump(tampered, file, ensure_ascii=False, indent=2)

    tampered_verification = source.verify_trust_state_journal()
    expect(tampered_verification["valid"] is False, "Checkpoint corruption was not detected.")
    expect(tampered_verification["reason"] in {"checkpoint_hash_mismatch", "checkpoint_id_mismatch"}, "Unexpected checkpoint corruption reason.")

    replay = source.replay_trust_state_journal()
    expect(replay["success"] is False, "Replay continued after checkpoint corruption.")

    # Simulate a crash/corruption that makes the primary unreadable. The storage
    # layer must recover the last known-good journal from .bak instead of
    # silently accepting an empty or damaged journal.
    with open(journal_path, "w", encoding="utf-8") as file:
        file.write("{not-valid-json")

    recovered_verification = source.verify_trust_state_journal()
    expect(recovered_verification["valid"] is True, f"Journal backup recovery failed: {recovered_verification}")
    expect(recovered_verification["coverage_end_sequence"] == 6, "Backup recovery lost a valid audit event.")

    print("PASS: checkpoint corruption fails closed")
    print("PASS: corrupted primary journal recovers from backup")


def test_oidc_trust_state_journal_compaction_write_failure_preserves_primary(tmp_dir):
    import memory_storage

    issuer = "https://issuer.test/journal-compaction-write-failure"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_compaction_write_failure_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8200.0,
    )
    source._state_revision = 20
    source._state_fingerprint = "compaction-write-failure-fingerprint"
    source._persisted_state_fingerprint = "compaction-write-failure-fingerprint"

    for index in range(1, 7):
        source._append_trust_state_journal("COMPACTION_WRITE_FAILURE_TEST", {"index": index})

    journal_path = state_path + ".journal"
    with open(journal_path, "rb") as file:
        before = file.read()

    original_save = memory_storage.save_json_document

    def fail_save(*args, **kwargs):
        raise OSError("forced compaction persistence failure")

    memory_storage.save_json_document = fail_save
    try:
        try:
            source.compact_trust_state_journal(retain_records=2)
            raise AssertionError("Forced compaction write failure did not propagate.")
        except OSError:
            pass
    finally:
        memory_storage.save_json_document = original_save

    with open(journal_path, "rb") as file:
        after = file.read()
    expect(before == after, "Failed compaction changed the primary journal bytes.")
    expect(source.verify_trust_state_journal()["valid"] is True, "Failed compaction left the primary journal invalid.")

    print("PASS: failed compaction write leaves the last known-good journal intact")


def _journal_compaction_worker(state_path):
    source = OIDCDiscoveryJWKSSource(
        "https://issuer.test/journal-concurrency",
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8300.0,
    )
    time.sleep(0.05)
    for _ in range(5):
        source.compact_trust_state_journal(retain_records=3)
        time.sleep(0.02)


def test_oidc_trust_state_journal_historical_snapshot_reconstruction(tmp_dir):
    issuer = "https://issuer.test/journal-historical-reconstruction"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_historical_reconstruction_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8500.0,
    )

    for index in range(1, 9):
        source._state_revision = 100 + index
        source._state_fingerprint = f"historical-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal(
            "HISTORICAL_RECONSTRUCTION_TEST",
            {"index": index},
        )

    compact = source.compact_trust_state_journal(retain_records=3)
    expect(compact["status"] == "COMPACTED", "Historical reconstruction fixture did not compact.")
    expect(compact["checkpoint_sequence"] == 5, "Unexpected historical reconstruction checkpoint boundary.")

    checkpoint_snapshot = source.reconstruct_trust_state_snapshot(sequence=5)
    expect(checkpoint_snapshot["success"] is True, f"Checkpoint snapshot reconstruction failed: {checkpoint_snapshot}")
    expect(checkpoint_snapshot["status"] == "RECONSTRUCTED", "Checkpoint snapshot returned the wrong status.")
    expect(checkpoint_snapshot["snapshot"]["sequence"] == 5, "Checkpoint snapshot sequence is incorrect.")
    expect(checkpoint_snapshot["snapshot"]["state_revision"] == 105, "Checkpoint snapshot lost the checkpoint state revision.")
    expect(checkpoint_snapshot["snapshot"]["state_fingerprint"] == "historical-state-5", "Checkpoint snapshot lost the checkpoint fingerprint.")
    expect(checkpoint_snapshot["replayed_event_count"] == 0, "Checkpoint boundary should not replay tail events.")

    tail_snapshot = source.reconstruct_trust_state_snapshot(sequence=7, include_events=True)
    expect(tail_snapshot["success"] is True, f"Tail snapshot reconstruction failed: {tail_snapshot}")
    expect(tail_snapshot["snapshot"]["sequence"] == 7, "Tail snapshot sequence is incorrect.")
    expect(tail_snapshot["snapshot"]["state_revision"] == 107, "Tail snapshot lost the target revision.")
    expect(tail_snapshot["snapshot"]["state_fingerprint"] == "historical-state-7", "Tail snapshot lost the target fingerprint.")
    expect(tail_snapshot["replayed_event_count"] == 2, "Tail reconstruction replayed the wrong number of events.")
    expect([item["sequence"] for item in tail_snapshot["events"]] == [6, 7], "Tail reconstruction returned the wrong event range.")

    latest = source.reconstruct_trust_state_snapshot()
    expect(latest["success"] is True, f"Latest historical snapshot reconstruction failed: {latest}")
    expect(latest["snapshot"]["sequence"] == 8, "Latest reconstruction did not select the journal head.")
    expect(latest["snapshot"]["state_revision"] == 108, "Latest reconstruction lost the head revision.")
    expect(latest["snapshot"]["state_fingerprint"] == "historical-state-8", "Latest reconstruction lost the head fingerprint.")

    compacted_history = source.reconstruct_trust_state_snapshot(sequence=4)
    expect(compacted_history["success"] is False, "Compacted history was incorrectly reconstructed.")
    expect(compacted_history["status"] == "HISTORY_COMPACTED", "Compacted history returned the wrong failure status.")

    future_history = source.reconstruct_trust_state_snapshot(sequence=99)
    expect(future_history["success"] is False, "Unavailable future history was incorrectly reconstructed.")
    expect(future_history["status"] == "HISTORY_NOT_AVAILABLE", "Unavailable future history returned the wrong status.")

    print("PASS: checkpoint boundary can reconstruct an authenticated historical snapshot")
    print("PASS: retained journal tail reconstructs historical revisions")
    print("PASS: compacted history fails closed instead of being approximated")
    print("PASS: unavailable future history is rejected")


def test_oidc_trust_state_journal_snapshot_verification_and_authoritative_binding(tmp_dir):
    issuer = "https://issuer.test/journal-snapshot-verification"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_snapshot_verification_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8600.0,
    )

    for index in range(1, 6):
        source._state_revision = 200 + index
        source._state_fingerprint = f"verification-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal(
            "SNAPSHOT_VERIFICATION_TEST",
            {"index": index},
        )

    verified = source.verify_trust_state_snapshot(
        sequence=4,
        expected_state_revision=204,
        expected_state_fingerprint="verification-state-4",
    )
    expect(verified["success"] is True, f"Historical snapshot verification failed: {verified}")
    expect(verified["status"] == "SNAPSHOT_VERIFIED", "Verified snapshot returned the wrong status.")

    wrong_revision = source.verify_trust_state_snapshot(
        sequence=4,
        expected_state_revision=999,
    )
    expect(wrong_revision["success"] is False, "Wrong expected revision was accepted.")
    expect(wrong_revision["status"] == "SNAPSHOT_EXPECTATION_MISMATCH", "Wrong revision returned the wrong status.")

    wrong_fingerprint = source.verify_trust_state_snapshot(
        sequence=4,
        expected_state_fingerprint="tampered-fingerprint",
    )
    expect(wrong_fingerprint["success"] is False, "Wrong expected fingerprint was accepted.")
    expect(wrong_fingerprint["reason"] == "state_fingerprint_mismatch", "Wrong fingerprint returned the wrong reason.")

    strict_binding = source.reconstruct_trust_state_snapshot(
        sequence=5,
        require_current_authoritative_binding=True,
    )
    expect(strict_binding["success"] is False, "Strict authoritative binding accepted an unavailable durable state.")
    expect(strict_binding["status"] == "AUTHORITATIVE_STATE_UNAVAILABLE", "Strict authoritative binding returned the wrong status.")

    print("PASS: historical snapshot verification binds exact revision and fingerprint")
    print("PASS: mismatched snapshot expectations fail closed")
    print("PASS: strict authoritative binding fails closed when durable state is unavailable")


def test_oidc_trust_state_journal_historical_snapshot_real_authoritative_binding(tmp_dir):
    issuer = "https://issuer.test/journal-real-authoritative-binding"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_real_authoritative_binding_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8650.0,
    )

    source._persist_state()
    source._append_trust_state_journal(
        "AUTHORITATIVE_BINDING_TEST",
        {"stage": 1},
    )
    first_revision = source._state_revision
    first_fingerprint = source._state_fingerprint

    source._refresh_count = 1
    source._persist_state()
    source._append_trust_state_journal(
        "AUTHORITATIVE_BINDING_TEST",
        {"stage": 2},
    )

    latest = source.reconstruct_trust_state_snapshot(
        sequence=2,
        require_current_authoritative_binding=True,
    )
    expect(latest["success"] is True, f"Current authoritative snapshot binding failed: {latest}")
    expect(latest["snapshot"]["authoritative_current_state_match"] is True, "Current snapshot did not bind to authoritative state.")
    expect(latest["authoritative_state"]["state_revision"] == source._state_revision, "Authoritative revision was not loaded from durable state.")

    historical = source.reconstruct_trust_state_snapshot(
        sequence=1,
        require_current_authoritative_binding=True,
    )
    expect(historical["success"] is False, "Historical snapshot incorrectly matched the newer authoritative state.")
    expect(historical["status"] == "AUTHORITATIVE_STATE_MISMATCH", "Historical authoritative mismatch returned the wrong status.")
    expect(historical["snapshot"]["state_revision"] == first_revision, "Historical snapshot lost its original revision.")
    expect(historical["snapshot"]["state_fingerprint"] == first_fingerprint, "Historical snapshot lost its original fingerprint.")

    print("PASS: historical snapshot binds to the real durable authoritative state")
    print("PASS: older snapshot is rejected when current authoritative state has advanced")


def test_oidc_trust_state_journal_historical_snapshot_tamper_detection(tmp_dir):
    issuer = "https://issuer.test/journal-historical-tamper"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_historical_tamper_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8700.0,
    )
    source._state_revision = 1
    source._state_fingerprint = "tamper-state"
    source._persisted_state_fingerprint = source._state_fingerprint

    for index in range(1, 7):
        source._append_trust_state_journal(
            "HISTORICAL_TAMPER_TEST",
            {"index": index},
        )

    source.compact_trust_state_journal(retain_records=2)
    journal_path = state_path + ".journal"
    with open(journal_path, "r", encoding="utf-8") as file:
        journal = json.load(file)

    journal["records"][1]["state_fingerprint"] = "tampered-tail-fingerprint"
    with open(journal_path, "w", encoding="utf-8") as file:
        json.dump(journal, file, ensure_ascii=False, indent=2)

    result = source.reconstruct_trust_state_snapshot(sequence=6)
    expect(result["success"] is False, "Tampered historical tail was accepted.")
    expect(result["status"] == "JOURNAL_INVALID", "Tampered historical tail returned the wrong status.")
    expect(result["reason"] in {"record_hash_mismatch", "previous_hash_mismatch"}, "Unexpected historical tamper reason.")

    print("PASS: historical reconstruction fails closed on tail tampering")


def test_oidc_trust_state_journal_historical_query_and_audit_timeline(tmp_dir):
    issuer = "https://issuer.test/journal-query-timeline"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_query_timeline_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8800.0,
    )

    for index in range(1, 9):
        source._state_revision = 300 + index
        source._state_fingerprint = f"query-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal(
            "QUERY_EVENT_A" if index % 2 else "QUERY_EVENT_B",
            {"index": index},
        )

    compact = source.compact_trust_state_journal(retain_records=3)
    expect(compact["status"] == "COMPACTED", f"Query fixture did not compact: {compact}")
    expect(compact["checkpoint_sequence"] == 5, "Query fixture produced the wrong checkpoint boundary.")

    filtered = source.query_trust_state_journal(
        start_sequence=6,
        end_sequence=8,
        event_types=["QUERY_EVENT_B"],
        verify_integrity=True,
    )
    expect(filtered["success"] is True, f"Filtered journal query failed: {filtered}")
    expect([item["sequence"] for item in filtered["records"]] == [6, 8], "Event-type filtering returned the wrong sequence set.")
    expect(filtered["coverage_start_sequence"] == 6, "Query lost retained coverage start.")
    expect(filtered["coverage_end_sequence"] == 8, "Query lost retained coverage end.")
    expect(filtered["checkpoint_sequence"] == 5, "Query lost checkpoint boundary.")

    reverse = source.query_trust_state_journal(
        start_sequence=6,
        end_sequence=8,
        reverse=True,
        verify_integrity=True,
    )
    expect(reverse["success"] is True, f"Reverse journal query failed: {reverse}")
    expect([item["sequence"] for item in reverse["records"]] == [8, 7, 6], "Reverse query ordering is not deterministic.")

    timeline = source.get_trust_state_audit_timeline(
        start_sequence=6,
        end_sequence=8,
        limit=2,
        verify_integrity=True,
    )
    expect(timeline["success"] is True, f"Audit timeline query failed: {timeline}")
    expect(timeline["status"] == "AUDIT_TIMELINE", "Audit timeline returned the wrong status.")
    expect([item["sequence"] for item in timeline["timeline"]] == [6, 7], "Timeline limit was not enforced deterministically.")
    expect(timeline["checkpoint"]["sequence"] == 5, "Timeline lost checkpoint metadata.")

    compacted = source.query_trust_state_journal(start_sequence=4, end_sequence=5)
    expect(compacted["success"] is False, "Query incorrectly exposed compacted history.")
    expect(compacted["status"] == "HISTORY_COMPACTED", "Compacted query returned the wrong status.")

    future = source.query_trust_state_journal(start_sequence=9, end_sequence=9)
    expect(future["success"] is False, "Query incorrectly exposed unavailable future history.")
    expect(future["status"] == "HISTORY_UNAVAILABLE", "Unavailable query returned the wrong status.")

    invalid = source.query_trust_state_journal(start_sequence=8, end_sequence=6)
    expect(invalid["success"] is False, "Invalid sequence bounds were accepted.")
    expect(invalid["status"] == "INVALID_QUERY", "Invalid query returned the wrong status.")

    print("PASS: authenticated journal query filters and ordering are deterministic")
    print("PASS: audit timeline exposes checkpoint and retained coverage metadata")
    print("PASS: historical query fails closed before checkpoint and after journal head")


def test_oidc_trust_state_journal_audit_evidence_export_and_offline_verification(tmp_dir):
    issuer = "https://issuer.test/audit-evidence"
    state_path = os.path.join(tmp_dir, "memory_oidc_audit_evidence_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 9900.0,
    )

    for index in range(1, 7):
        source._state_revision = 500 + index
        source._state_fingerprint = f"evidence-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal(
            "EVIDENCE_EVENT_A" if index % 2 else "EVIDENCE_EVENT_B",
            {"index": index},
        )

    compact = source.compact_trust_state_journal(retain_records=3)
    expect(compact["status"] == "COMPACTED", f"Evidence fixture did not compact: {compact}")

    exported = source.export_trust_state_audit_evidence(
        start_sequence=4,
        end_sequence=6,
        event_types=["EVIDENCE_EVENT_A", "EVIDENCE_EVENT_B"],
        verify_integrity=True,
    ) if False else source.export_trust_state_audit_evidence(
        start_sequence=4,
        end_sequence=6,
        event_types=["EVIDENCE_EVENT_A", "EVIDENCE_EVENT_B"],
    )
    expect(exported["success"] is True, f"Audit evidence export failed: {exported}")
    expect(exported["status"] == "AUDIT_EVIDENCE_EXPORTED", "Evidence export returned the wrong status.")
    expect(exported["read_only"] is True, "Evidence export did not declare read-only behavior.")
    expect(exported["authoritative_state_mutated"] is False, "Evidence export reported authoritative mutation.")

    evidence = exported["evidence"]
    expect(evidence["coverage_start_sequence"] == 4, "Evidence lost retained coverage start.")
    expect(evidence["coverage_end_sequence"] == 6, "Evidence lost retained coverage end.")
    expect(evidence["checkpoint"]["sequence"] == 3, "Evidence lost checkpoint boundary.")
    expect([item["sequence"] for item in evidence["records"]] == [4, 5, 6], "Evidence contains the wrong record slice.")
    expect(len(evidence["evidence_fingerprint"]) == 64, "Evidence fingerprint is not SHA256-sized.")

    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence(
        evidence,
        expected_issuer=issuer,
    )
    expect(verified["success"] is True, f"Offline evidence verification failed: {verified}")
    expect(verified["status"] == "AUDIT_EVIDENCE_VERIFIED", "Offline evidence verification returned the wrong status.")

    tampered = json.loads(json.dumps(evidence))
    tampered["records"][0]["details"]["index"] = 999
    tampered_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence(
        tampered,
        expected_issuer=issuer,
    )
    expect(tampered_result["success"] is False, "Tampered evidence was accepted.")
    expect(tampered_result["status"] == "EVIDENCE_INVALID", "Tampered evidence returned the wrong status.")

    old = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=2)
    expect(old["success"] is False, "Evidence incorrectly exported compacted history.")
    expect(old["status"] == "AUDIT_EVIDENCE_UNAVAILABLE", "Compacted evidence returned the wrong status.")

    print("PASS: audit evidence export is deterministic and read-only")
    print("PASS: exported audit evidence verifies without storage access")
    print("PASS: audit evidence tampering fails closed")


def test_oidc_trust_state_audit_evidence_cryptographic_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/audit-attestation"
    state_path = os.path.join(tmp_dir, "memory_oidc_audit_attestation_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 12000.0,
    )

    for index in range(1, 5):
        source._state_revision = 700 + index
        source._state_fingerprint = f"attestation-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal("ATTESTATION_EVENT", {"index": index})

    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=4)
    expect(exported["success"] is True, f"Attestation fixture export failed: {exported}")
    evidence = exported["evidence"]

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence(
        evidence,
        private_key,
        key_id="audit-signing-key-1",
        issuer=issuer,
    )
    expect(attested["success"] is True, f"Audit evidence attestation failed: {attested}")
    expect(attested["status"] == "AUDIT_EVIDENCE_ATTESTED", "Attestation returned the wrong status.")
    expect(attested["read_only"] is True, "Attestation did not declare read-only behavior.")

    package = attested["evidence"]
    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation(
        package,
        public_key,
        expected_issuer=issuer,
        expected_key_id="audit-signing-key-1",
    )
    expect(verified["success"] is True, f"Cryptographic evidence attestation verification failed: {verified}")
    expect(verified["status"] == "AUDIT_EVIDENCE_ATTESTATION_VERIFIED", "Attestation verification returned the wrong status.")

    tampered = json.loads(json.dumps(package))
    tampered["records"][0]["details"]["index"] = 999
    tampered_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation(
        tampered,
        public_key,
        expected_issuer=issuer,
        expected_key_id="audit-signing-key-1",
    )
    expect(tampered_result["success"] is False, "Tampered attested evidence was accepted.")
    expect(tampered_result["status"] == "ATTESTATION_INVALID", "Tampered attestation returned the wrong status.")

    wrong_key = Ed25519PrivateKey.generate().public_key()
    wrong_key_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation(
        package,
        wrong_key,
        expected_issuer=issuer,
        expected_key_id="audit-signing-key-1",
    )
    expect(wrong_key_result["success"] is False, "Evidence verified with the wrong public key.")
    expect(wrong_key_result["reason"] == "signature_invalid", "Wrong-key verification returned the wrong reason.")

    invalid_evidence = dict(evidence)
    invalid_evidence["records"] = []
    invalid_attestation = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence(
        invalid_evidence,
        private_key,
        key_id="audit-signing-key-1",
        issuer=issuer,
    )
    expect(invalid_attestation["success"] is False, "Invalid evidence was attested.")

    print("PASS: audit evidence receives a cryptographic Ed25519 attestation")
    print("PASS: attested evidence verifies offline with the public key")
    print("PASS: evidence tampering and wrong-key verification fail closed")


def test_oidc_trust_state_audit_evidence_trusted_key_registry_and_rotation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/audit-trusted-key"
    state_path = os.path.join(tmp_dir, "memory_oidc_audit_trusted_key_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 13000.0,
    )

    for index in range(1, 4):
        source._state_revision = 800 + index
        source._state_fingerprint = f"trusted-key-state-{index}"
        source._persisted_state_fingerprint = source._state_fingerprint
        source._append_trust_state_journal("TRUSTED_KEY_EVENT", {"index": index})

    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    old_private.public_key(),
                    "audit-key-old",
                    version="1",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )

    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=3)
    expect(exported["success"] is True, f"Trusted-key evidence export failed: {exported}")
    evidence = exported["evidence"]

    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence(
        evidence,
        old_private,
        key_id="audit-key-old",
        issuer=issuer,
    )
    expect(attested["success"] is True, f"Trusted-key attestation failed: {attested}")

    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="audit-key-old",
    )
    expect(verified["success"] is True, f"Registry-backed evidence verification failed: {verified}")
    expect(verified["status"] == "AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION_VERIFIED", "Registry verification returned the wrong status.")
    expect(verified["key_status"] == IDENTITY_KEY_STATUS_ACTIVE, "Registry-backed verification lost key lifecycle status.")

    rotated = registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    old_private.public_key(),
                    "audit-key-old",
                    version="1",
                    status=IDENTITY_KEY_STATUS_GRACE,
                ),
                public_key_to_jwk(
                    new_private.public_key(),
                    "audit-key-new",
                    version="2",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                ),
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    expect(rotated["changed"] is True, "Evidence signing-key rotation did not change the registry.")

    grace_verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="audit-key-old",
    )
    expect(grace_verified["success"] is True, f"GRACE signing key was incorrectly rejected: {grace_verified}")
    expect(grace_verified["key_status"] == IDENTITY_KEY_STATUS_GRACE, "GRACE key status was not exposed.")

    retired = registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    new_private.public_key(),
                    "audit-key-new",
                    version="2",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
        retire_missing=True,
    )
    expect(retired["retired"] == [{"key_id": "audit-key-old", "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519}], "Old audit key was not retired.")

    retired_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="audit-key-old",
    )
    expect(retired_result["success"] is False, "Retired audit signing key was accepted.")
    expect(retired_result["reason"] == "trusted_key_retired", "Retired key returned the wrong rejection reason.")

    registry.set_status("audit-key-old", IDENTITY_KEY_STATUS_REVOKED)
    revoked_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="audit-key-old",
    )
    expect(revoked_result["success"] is False, "Revoked audit signing key was accepted.")
    expect(revoked_result["reason"] == "trusted_key_revoked", "Revoked key returned the wrong rejection reason.")

    print("PASS: audit evidence verification resolves signing keys through the trusted registry")
    print("PASS: ACTIVE and GRACE audit keys verify while lifecycle metadata remains visible")
    print("PASS: RETIRED and REVOKED audit signing keys fail closed after rotation")


def test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit_evidence_export_and_offline_verification(tmp_dir):
    issuer = "https://issuer.test/decision-consumption-audit-evidence"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_evidence_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 19500.0,
    )

    seed_records = [
        ("CONSUMED", "att-e1", "fp-e1", "nonce-e1", 19500.0, "one_time_consumption"),
        ("REPLAY_REJECTED", "att-e1", "fp-e1", "nonce-e1", 19510.0, "attestation_already_consumed"),
        ("CONSUMED", "att-e2", "fp-e2", "nonce-e2", 19520.0, "one_time_consumption"),
        ("REPLAY_REJECTED", "att-e2", "fp-e2", "nonce-e2", 19530.0, "attestation_already_consumed"),
        ("CONSUMED", "att-e3", "fp-e3", "nonce-e3", 19540.0, "one_time_consumption"),
    ]
    for event_type, attestation_id, fingerprint, nonce, event_at, reason in seed_records:
        appended = registry._append_decision_attestation_consumption_audit(
            event_type=event_type,
            attestation_id=attestation_id,
            decision_fingerprint=fingerprint,
            nonce=nonce,
            consumed_at=event_at,
            reason=reason,
        )
        expect(appended["success"] is True, f"Evidence audit fixture append failed: {appended}")

    source._persist_state()
    with open(state_path, "rb") as file:
        state_before = file.read()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=2,
        end_sequence=4,
    )
    expect(exported["success"] is True, f"Consumption audit evidence export failed: {exported}")
    expect(exported["status"] == "DECISION_ATTESTATION_AUDIT_EVIDENCE_EXPORTED", "Evidence export returned the wrong status.")
    expect(exported["read_only"] is True, "Evidence export was not read-only.")
    expect(exported["authoritative_state_mutated"] is False, "Evidence export reported authoritative mutation.")

    evidence = exported["evidence"]
    expect(evidence["chain_start_sequence"] == 1, "Evidence chain start is incorrect.")
    expect(evidence["chain_end_sequence"] == 4, "Evidence chain end is incorrect.")
    expect([item["sequence"] for item in evidence["records"]] == [1, 2, 3, 4], "Evidence did not retain an authenticated chain prefix.")
    expect([item["sequence"] for item in evidence["selected_records"]] == [2, 3, 4], "Evidence did not retain the requested audit slice.")
    expect(evidence["chain_head_hash"] == evidence["records"][-1]["record_hash"], "Chain head hash was not bound.")
    expect(evidence["selected_start_sequence"] == 2 and evidence["selected_end_sequence"] == 4, "Selected evidence range was not bound.")
    expect(len(evidence["evidence_fingerprint"]) == 64, "Evidence fingerprint is not SHA256-sized.")

    verified = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(evidence)
    expect(verified["success"] is True, f"Offline consumption-audit evidence verification failed: {verified}")
    expect(verified["status"] == "DECISION_ATTESTATION_AUDIT_EVIDENCE_VERIFIED", "Offline verification returned the wrong status.")
    expect(verified["record_count"] == 4, "Offline verification counted the wrong chain records.")
    expect(verified["selected_record_count"] == 3, "Offline verification counted the wrong selected records.")

    tampered_record = json.loads(json.dumps(evidence))
    tampered_record["records"][1]["reason"] = "tampered"
    tampered_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(tampered_record)
    expect(not tampered_result["success"], "Tampered evidence record was accepted.")
    expect(tampered_result["reason"] == "record_hash_mismatch", "Tampered evidence returned the wrong reason.")

    tampered_fingerprint = json.loads(json.dumps(evidence))
    tampered_fingerprint["records"][0]["reason"] = "changed"
    tampered_fingerprint["records"][0]["record_hash"] = evidence["records"][0]["record_hash"]
    fp_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(tampered_fingerprint)
    expect(not fp_result["success"], "Evidence with inconsistent fingerprint was accepted.")

    tampered_heads = json.loads(json.dumps(evidence))
    tampered_heads["audit_head_hash"] = "0" * 64
    head_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(tampered_heads)
    expect(not head_result["success"], "Evidence with inconsistent audit head binding was accepted.")
    expect(head_result["reason"] == "audit_head_hash_mismatch", "Audit-head tampering returned the wrong reason.")

    tampered_embedded = json.loads(json.dumps(evidence))
    tampered_embedded["audit_verification"]["head_hash"] = "1" * 64
    embedded_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(tampered_embedded)
    expect(not embedded_result["success"], "Evidence with inconsistent embedded audit verification was accepted.")
    expect(embedded_result["reason"] == "audit_head_hash_mismatch", "Embedded verification tampering returned the wrong reason.")

    empty_export = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=0)
    expect(not empty_export["success"], "Invalid empty sequence range was accepted.")
    expect(empty_export["status"] == "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID_QUERY", "Invalid evidence range returned the wrong status.")

    unavailable = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=6, end_sequence=6)
    expect(not unavailable["success"], "Evidence was exported beyond the audit head.")
    expect(unavailable["status"] == "DECISION_ATTESTATION_AUDIT_EVIDENCE_UNAVAILABLE", "Unavailable evidence returned the wrong status.")

    with open(state_path, "rb") as file:
        state_after = file.read()
    expect(state_after == state_before, "Evidence export mutated persisted trust state.")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer,
        restarted_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 19550.0,
    )
    restarted_export = restarted_registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=2,
        end_sequence=4,
    )
    expect(restarted_export["success"] is True, f"Restarted evidence export failed: {restarted_export}")
    restarted_verification = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(
        restarted_export["evidence"]
    )
    expect(restarted_verification["success"] is True, "Restarted audit evidence did not verify offline.")

    print("PASS: consumption audit evidence exports an authenticated chain prefix and selected slice")
    print("PASS: exported consumption audit evidence verifies without storage access")
    print("PASS: tampered consumption audit evidence fails closed")
    print("PASS: evidence export remains read-only and survives trust-state restart")

def test_decision_attestation_consumption_audit_evidence_cryptographic_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-audit-attestation"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_attestation_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 20000.0,
    )

    records = [
        ("CONSUMED", "att-ca-1", "fp-ca-1", "nonce-ca-1", 20000.0, "one_time_consumption"),
        ("REPLAY_REJECTED", "att-ca-1", "fp-ca-1", "nonce-ca-1", 20010.0, "attestation_already_consumed"),
        ("CONSUMED", "att-ca-2", "fp-ca-2", "nonce-ca-2", 20020.0, "one_time_consumption"),
    ]
    for event_type, attestation_id, fingerprint, nonce, event_at, reason in records:
        appended = registry._append_decision_attestation_consumption_audit(
            event_type=event_type,
            attestation_id=attestation_id,
            decision_fingerprint=fingerprint,
            nonce=nonce,
            consumed_at=event_at,
            reason=reason,
        )
        expect(appended["success"] is True, f"Cryptographic attestation fixture append failed: {appended}")

    source._persist_state()
    with open(state_path, "rb") as file:
        state_before = file.read()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=2,
        end_sequence=3,
    )
    expect(exported["success"] is True, f"Consumption-audit evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "consumption-audit-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    metadata = registry.get_verification_key_metadata(
        "consumption-audit-key",
        IDENTITY_ATTESTATION_ALGORITHM_ED25519,
    )

    direct = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence(
        exported["evidence"],
        private_key,
        key_id="consumption-audit-key",
        issuer=issuer,
    )
    expect(direct["success"] is True, f"Direct evidence attestation failed: {direct}")
    direct_verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation(
        direct["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(direct_verified["success"] is True, f"Offline direct attestation verification failed: {direct_verified}")

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-audit-key",
        issuer=issuer,
    )
    expect(attested["success"] is True, f"Trusted-key evidence attestation failed: {attested}")
    attestation = attested["evidence"]["attestation"]
    expect(
        attestation["evidence_fingerprint"] == exported["evidence"]["evidence_fingerprint"],
        "Evidence fingerprint was not bound to the attestation.",
    )
    expect(attestation["key_fingerprint"] == metadata["fingerprint"], "Key fingerprint provenance was not bound.")
    expect(attestation["registry_revision"] == metadata["registry_revision"], "Registry revision provenance was not bound.")
    expect(attestation["key_set_fingerprint"] == metadata["key_set_fingerprint"], "Key-set fingerprint provenance was not bound.")
    expect(attestation["key_source"] == metadata["source"], "Key source provenance was not bound.")
    expect(attestation["key_version"] == metadata["version"], "Key version provenance was not bound.")

    verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(verified["success"] is True, f"Trusted-key provenance verification failed: {verified}")
    expect(
        verified["status"] == "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_PROVENANCE_VERIFIED",
        "Trusted-key provenance verification returned the wrong status.",
    )
    expect(verified["current_registry_binding"] is True, "Current registry binding was not confirmed.")

    tampered_evidence = json.loads(json.dumps(attested["evidence"]))
    tampered_evidence["selected_records"][0]["reason"] = "tampered"
    tampered_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        tampered_evidence,
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not tampered_result["success"], "Tampered evidence was accepted after attestation.")

    tampered_evidence_fingerprint = json.loads(json.dumps(attested["evidence"]))
    tampered_evidence_fingerprint["attestation"]["evidence_fingerprint"] = "0" * 64
    tampered_evidence_fingerprint_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        tampered_evidence_fingerprint,
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(
        not tampered_evidence_fingerprint_result["success"],
        "Tampered attestation evidence fingerprint was accepted.",
    )
    expect(
        tampered_evidence_fingerprint_result["reason"] == "evidence_fingerprint_mismatch",
        "Tampered attestation evidence fingerprint returned the wrong reason.",
    )

    tampered_schema = json.loads(json.dumps(attested["evidence"]))
    tampered_schema["attestation"]["schema_version"] = 2
    tampered_schema_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        tampered_schema,
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not tampered_schema_result["success"], "Unsupported attestation schema was accepted.")
    expect(
        tampered_schema_result["reason"] == "unsupported_attestation_schema",
        "Unsupported attestation schema returned the wrong reason.",
    )

    tampered_provenance = json.loads(json.dumps(attested["evidence"]))
    tampered_provenance["attestation"]["key_source"] = "https://attacker.invalid/jwks"
    tampered_provenance_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        tampered_provenance,
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not tampered_provenance_result["success"], "Tampered key provenance was accepted.")
    expect(
        tampered_provenance_result["reason"] in {"registry_provenance_mismatch", "signature_verification_failed"},
        "Tampered provenance returned an unexpected failure reason.",
    )

    registry.set_status("consumption-audit-key", IDENTITY_KEY_STATUS_RETIRED)
    retired = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not retired["success"] and retired["reason"] == "trusted_key_retired", "Retired key was accepted.")

    registry.set_status("consumption-audit-key", IDENTITY_KEY_STATUS_REVOKED)
    revoked = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not revoked["success"] and revoked["reason"] == "trusted_key_revoked", "Revoked key was accepted.")

    registry.set_status("consumption-audit-key", IDENTITY_KEY_STATUS_ACTIVE)
    registry.register_key(
        "consumption-audit-key-2",
        Ed25519PrivateKey.generate().public_key(),
        status=IDENTITY_KEY_STATUS_ACTIVE,
        source=metadata["source"],
        version="2",
    )
    changed_binding = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
    )
    expect(not changed_binding["success"], "Registry mutation did not invalidate current provenance binding.")
    expect(changed_binding["reason"] == "registry_provenance_mismatch", "Registry mutation returned the wrong failure reason.")

    historical = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-audit-key",
        require_current_registry_binding=False,
    )
    expect(historical["success"] is True, f"Historical provenance verification failed: {historical}")
    expect(historical["current_registry_binding"] is False, "Historical verification incorrectly claimed current binding.")

    wrong_private = Ed25519PrivateKey.generate()
    wrong_key = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key(
        exported["evidence"],
        wrong_private,
        registry,
        key_id="consumption-audit-key",
        issuer=issuer,
    )
    expect(not wrong_key["success"], "A mismatched private key was accepted for trusted attestation.")

    with open(state_path, "rb") as file:
        state_after = file.read()
    expect(state_after == state_before, "Cryptographic evidence attestation mutated persisted trust state.")

    print("PASS: consumption-audit evidence can be cryptographically attested and verified offline")
    print("PASS: trusted-key provenance is bound to the attestation and current registry state")
    print("PASS: tampered evidence, provenance, retired keys, and revoked keys fail closed")
    print("PASS: evidence attestation remains read-only")


def test_decision_attestation_consumption_audit_evidence_replay_and_temporal_binding(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-audit-replay"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_replay_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 30000.0,
    )

    for sequence, event_type in enumerate(("CONSUMED", "REPLAY_REJECTED"), start=1):
        appended = registry._append_decision_attestation_consumption_audit(
            event_type=event_type,
            attestation_id="att-replay-001",
            decision_fingerprint="fp-replay-001",
            nonce="nonce-replay-001",
            consumed_at=30000.0 + sequence,
            reason="test",
        )
        expect(appended["success"] is True, f"Replay binding fixture append failed: {appended}")

    source._persist_state()
    with open(state_path, "rb") as file:
        state_before = file.read()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=2,
    )
    expect(exported["success"] is True, f"Replay evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "consumption-replay-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )

    legacy = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-replay-key",
        issuer=issuer,
    )
    expect(legacy["success"] is True, f"Legacy trusted attestation failed: {legacy}")
    legacy_verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        legacy["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
    )
    expect(legacy_verified["success"] is True, f"Legacy trusted attestation lost backward compatibility: {legacy_verified}")

    replay = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_replay_binding(
        exported["evidence"],
        private_key,
        key_id="consumption-replay-key",
        issuer=issuer,
        nonce="request-nonce-001",
        attestation_id="evidence-attestation-001",
        issued_at=30000.0,
        expires_at=30300.0,
    )
    expect(replay["success"] is True, f"Replay-bound direct attestation failed: {replay}")
    replay_attestation = replay["evidence"]["attestation"]
    expect(replay_attestation["schema_version"] == 2, "Replay-bound direct attestation did not use schema v2.")
    expect(replay_attestation["nonce"] == "request-nonce-001", "Replay nonce was not recorded.")
    expect(replay_attestation["attestation_id"] == "evidence-attestation-001", "Attestation ID was not recorded.")

    direct_verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        replay["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-001",
        expected_attestation_id="evidence-attestation-001",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(direct_verified["success"] is True, f"Replay-bound direct verification failed: {direct_verified}")
    expect(direct_verified["replay_binding"] is True, "Direct replay binding was not reported.")

    wrong_nonce = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        replay["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="wrong-nonce",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(not wrong_nonce["success"] and wrong_nonce["reason"] == "nonce_mismatch", "Mismatched replay nonce did not fail closed.")

    wrong_id = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        replay["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_attestation_id="wrong-attestation-id",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(not wrong_id["success"] and wrong_id["reason"] == "attestation_id_mismatch", "Mismatched attestation ID did not fail closed.")

    expired = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        replay["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-001",
        verification_time=30301.0,
        clock_skew_seconds=0,
    )
    expect(not expired["success"] and expired["reason"] == "attestation_expired", "Expired evidence attestation did not fail closed.")

    future = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        replay["evidence"],
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-001",
        verification_time=29999.0,
        clock_skew_seconds=0,
    )
    expect(not future["success"] and future["reason"] == "attestation_not_yet_valid", "Future evidence attestation did not fail closed.")

    tampered_nonce = json.loads(json.dumps(replay["evidence"]))
    tampered_nonce["attestation"]["nonce"] = "tampered-nonce"
    tampered_nonce_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        tampered_nonce,
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_nonce_result["success"] and tampered_nonce_result["reason"] == "signature_verification_failed", "Tampered signed nonce was not rejected cryptographically.")

    trusted_replay = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-replay-key",
        issuer=issuer,
        nonce="request-nonce-002",
        attestation_id="evidence-attestation-002",
        issued_at=30000.0,
        expires_at=30300.0,
    )
    expect(trusted_replay["success"] is True, f"Trusted replay-bound attestation failed: {trusted_replay}")

    trusted_verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
        trusted_replay["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-002",
        expected_attestation_id="evidence-attestation-002",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(trusted_verified["success"] is True, f"Trusted replay-bound verification failed: {trusted_verified}")
    expect(trusted_verified["replay_binding"] is True and trusted_verified["current_registry_binding"] is True, "Trusted replay binding/provenance state was not confirmed.")

    registry.register_key(
        "consumption-replay-key-2",
        Ed25519PrivateKey.generate().public_key(),
        status=IDENTITY_KEY_STATUS_ACTIVE,
        source=issuer + "/.well-known/jwks.json",
        version="2",
    )
    changed_registry = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
        trusted_replay["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-002",
        expected_attestation_id="evidence-attestation-002",
        verification_time=30100.0,
        clock_skew_seconds=0,
    )
    expect(not changed_registry["success"] and changed_registry["reason"] == "registry_provenance_mismatch", "Registry mutation did not invalidate current replay attestation provenance.")

    historical = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
        trusted_replay["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-replay-key",
        expected_nonce="request-nonce-002",
        expected_attestation_id="evidence-attestation-002",
        verification_time=30100.0,
        clock_skew_seconds=0,
        require_current_registry_binding=False,
    )
    expect(historical["success"] is True and historical["current_registry_binding"] is False, "Historical replay attestation verification did not preserve the provenance distinction.")

    with open(state_path, "rb") as file:
        state_after = file.read()
    expect(state_after == state_before, "Replay/temporal evidence attestation mutated persisted trust state.")

    print("PASS: consumption-audit evidence attestations support nonce and temporal replay binding")
    print("PASS: mismatched nonce, attestation ID, expiration, and not-before checks fail closed")
    print("PASS: replay context is cryptographically signed and tamper-evident")
    print("PASS: trusted-key replay attestations preserve current-vs-historical provenance semantics")
    print("PASS: schema-v1 consumption-audit attestations remain backward compatible")


def test_decision_attestation_consumption_audit_evidence_attestation_one_time_consumption(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-audit-one-time"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_one_time_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 31000.0,
    )

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="seed-attestation",
        decision_fingerprint="seed-fingerprint",
        nonce="seed-nonce",
        consumed_at=31000.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=1,
    )
    expect(exported["success"] is True, f"One-time evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "consumption-one-time-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )

    source._persist_state()

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-one-time-key",
        issuer=issuer,
        nonce="one-time-nonce-001",
        attestation_id="one-time-evidence-attestation-001",
        issued_at=31000.0,
        expires_at=31300.0,
    )
    expect(attested["success"] is True, f"Replay-bound one-time attestation creation failed: {attested}")

    first = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-one-time-key",
        expected_nonce="one-time-nonce-001",
        expected_attestation_id="one-time-evidence-attestation-001",
        verification_time=31100.0,
        clock_skew_seconds=0,
    )
    expect(
        first["success"] is True and first["status"] == "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
        f"First evidence-attestation consumption failed: {first}",
    )
    expect(first["authoritative_state_mutated"] is True and first["read_only"] is False, "First consumption did not report mutation semantics correctly.")

    second = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-one-time-key",
        expected_nonce="one-time-nonce-001",
        expected_attestation_id="one-time-evidence-attestation-001",
        verification_time=31100.0,
        clock_skew_seconds=0,
    )
    expect(
        not second["success"] and second["status"] == "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAYED",
        f"Second evidence-attestation consumption was accepted: {second}",
    )

    wrong_nonce = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-one-time-key",
        expected_nonce="wrong-nonce",
        expected_attestation_id="one-time-evidence-attestation-001",
        verification_time=31100.0,
        clock_skew_seconds=0,
    )
    expect(
        not wrong_nonce["success"] and wrong_nonce["reason"] == "nonce_mismatch",
        "Wrong nonce did not fail closed before authoritative consumption lookup.",
    )

    legacy = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-one-time-key",
        issuer=issuer,
    )
    expect(legacy["success"] is True, f"Legacy trusted evidence attestation creation failed: {legacy}")
    legacy_consume = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        legacy["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-one-time-key",
    )
    expect(
        not legacy_consume["success"] and legacy_consume["reason"] == "one_time_consumption_requires_schema_v2",
        "Schema-v1 consumption-audit evidence attestation was incorrectly eligible for one-time consumption.",
    )

    restored_registry = TrustedAttestationKeyRegistry()
    restored_source = OIDCDiscoveryJWKSSource(
        issuer,
        restored_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 31000.0,
    )
    restored_replay = restored_source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-one-time-key",
        expected_nonce="one-time-nonce-001",
        expected_attestation_id="one-time-evidence-attestation-001",
        verification_time=31100.0,
        clock_skew_seconds=0,
    )
    expect(
        not restored_replay["success"] and restored_replay["status"] == "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAYED",
        f"Persisted one-time evidence-attestation consumption was lost after restart: {restored_replay}",
    )

    audit = restored_registry.get_decision_attestation_consumption_audit(
        attestation_id="one-time-evidence-attestation-001"
    )
    expect(audit["success"] is True, f"One-time evidence-attestation audit query failed: {audit}")
    event_types = [record.get("event_type") for record in audit["records"]]
    expect(
        event_types == [
            "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED",
            "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED",
            "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
        ],
        f"Unexpected one-time evidence-attestation audit event ordering: {event_types}",
    )
    expect(
        audit["head_hash"] == restored_registry._consumption_audit_head_hash,
        "One-time evidence-attestation audit head hash was not preserved.",
    )

    print("PASS: consumption-audit evidence attestations are consumed exactly once")
    print("PASS: one-time evidence-attestation consumption survives persistent trust-state restart")
    print("PASS: mismatched replay context and schema-v1 evidence attestations fail closed")
    print("PASS: evidence-attestation consume/replay outcomes are recorded in the existing audit chain")



def _decision_attestation_evidence_concurrency_worker(state_path, attested_evidence, worker_id, result_queue):
    try:
        issuer = "https://issuer.test/decision-consumption-audit-concurrency"
        source = OIDCDiscoveryJWKSSource(
            issuer,
            TrustedAttestationKeyRegistry(),
            state_path=state_path,
            fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
            now_fn=lambda: 32000.0 + worker_id,
        )
        result = source.consume_decision_attestation_consumption_audit_evidence_attestation(
            attested_evidence,
            expected_issuer=issuer,
            expected_key_id="consumption-concurrency-key",
            expected_nonce="concurrency-nonce-001",
            expected_attestation_id="concurrency-attestation-001",
            verification_time=32100.0,
            clock_skew_seconds=0,
        )
        result_queue.put({
            "worker_id": worker_id,
            "success": bool(result.get("success")),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "audit_sequence": (result.get("audit_record") or {}).get("sequence"),
        })
    except Exception as exc:
        result_queue.put({
            "worker_id": worker_id,
            "success": False,
            "status": "WORKER_EXCEPTION",
            "reason": f"{type(exc).__name__}: {exc}",
            "audit_sequence": None,
        })




def _decision_attestation_consumption_proof_bundle_binding_concurrency_worker(state_path, proof, worker_id, result_queue):
    try:
        issuer = "https://issuer.test/decision-consumption-proof-bundle-binding-consumption"
        source = OIDCDiscoveryJWKSSource(
            issuer,
            TrustedAttestationKeyRegistry(),
            state_path=state_path,
            fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
            now_fn=lambda: 59000.0 + worker_id,
        )
        attestation = proof.get("attested_bundle", {}).get("bundle_attestation", {})
        binding = proof.get("binding", {})
        result = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
            proof,
            expected_bundle_id=str(binding.get("bundle_id", "") or ""),
            expected_issuer=issuer,
            expected_key_id=str(attestation.get("key_id", "") or ""),
            expected_nonce=str(attestation.get("nonce", "") or ""),
            expected_attestation_id=str(attestation.get("attestation_id", "") or ""),
            verification_time=59000.0,
            clock_skew_seconds=0,
        )
        result_queue.put({
            "worker_id": worker_id,
            "success": bool(result.get("success")),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "audit_sequence": (result.get("audit_record") or {}).get("sequence"),
        })
    except Exception as exc:
        result_queue.put({
            "worker_id": worker_id,
            "success": False,
            "status": "WORKER_EXCEPTION",
            "reason": f"{type(exc).__name__}: {exc}",
            "audit_sequence": None,
        })



def _decision_attestation_consumption_binding_consumption_binding_concurrency_worker(state_path, proof, worker_id, result_queue):
    try:
        issuer = "https://issuer.test/decision-consumption-proof-bundle-binding-consumption"
        source = OIDCDiscoveryJWKSSource(
            issuer,
            TrustedAttestationKeyRegistry(),
            state_path=state_path,
            fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
            now_fn=lambda: 60100.0 + worker_id,
        )
        attested_bundle = proof.get("source_proof", {}).get("attested_bundle", {})
        attestation = attested_bundle.get("bundle_attestation", {}) if isinstance(attested_bundle, dict) else {}
        binding = proof.get("binding", {})
        result = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
            proof,
            expected_bundle_id=str(binding.get("bundle_id", "") or ""),
            expected_issuer=issuer,
            expected_key_id=str(attestation.get("key_id", "") or ""),
            expected_nonce=str(attestation.get("nonce", "") or ""),
            expected_attestation_id=str(attestation.get("attestation_id", "") or ""),
            expected_key_fingerprint=str(binding.get("key_fingerprint", "") or ""),
            verification_time=60100.0,
            clock_skew_seconds=0,
        )
        result_queue.put({
            "worker_id": worker_id,
            "success": bool(result.get("success")),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "audit_sequence": (result.get("audit_record") or {}).get("sequence"),
        })
    except Exception as exc:
        result_queue.put({
            "worker_id": worker_id,
            "success": False,
            "status": "WORKER_EXCEPTION",
            "reason": f"{type(exc).__name__}: {exc}",
            "audit_sequence": None,
        })


def _decision_attestation_consumption_proof_bundle_concurrency_worker(state_path, attested_bundle, worker_id, result_queue):
    try:
        issuer = "https://issuer.test/decision-consumption-proof-bundle-consume"
        source = OIDCDiscoveryJWKSSource(
            issuer,
            TrustedAttestationKeyRegistry(),
            state_path=state_path,
            fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
            now_fn=lambda: 57100.0 + worker_id,
        )
        result = source.consume_decision_attestation_consumption_proof_bundle_attestation(
            attested_bundle,
            expected_bundle_id="bundle-concurrency-test-001",
            expected_issuer=issuer,
            expected_key_id="proof-bundle-consume-key",
            expected_nonce="bundle-concurrency-nonce",
            expected_attestation_id="bundle-concurrency-attestation",
            verification_time=57100.0,
            clock_skew_seconds=0,
        )
        result_queue.put({
            "worker_id": worker_id,
            "success": bool(result.get("success")),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "audit_sequence": (result.get("audit_record") or {}).get("sequence"),
        })
    except Exception as exc:
        result_queue.put({
            "worker_id": worker_id,
            "success": False,
            "status": "WORKER_EXCEPTION",
            "reason": f"{type(exc).__name__}: {exc}",
            "audit_sequence": None,
        })

def test_decision_attestation_consumption_status_and_read_only_proof(tmp_dir):
    issuer = "https://issuer.test/decision-consumption-status"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_status_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 20500.0,
    )

    unconsumed = registry.get_decision_attestation_consumption_status(
        "status-unconsumed",
    )
    expect(unconsumed["success"] is True, f"Unconsumed status lookup failed: {unconsumed}")
    expect(unconsumed["status"] == "DECISION_ATTESTATION_UNCONSUMED", "Unconsumed status returned the wrong state.")
    expect(unconsumed["consumed"] is False, "Unconsumed attestation was reported as consumed.")
    expect(unconsumed["read_only"] is True and unconsumed["authoritative_state_mutated"] is False, "Unconsumed status was not read-only.")

    consumed_at = 20510.0
    claim = registry.consume_decision_attestation(
        "status-consumed",
        "fp-status",
        nonce="nonce-status",
        consumed_at=consumed_at,
    )
    expect(claim["success"] is True, f"Status fixture claim failed: {claim}")
    appended = registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
        attestation_id="status-consumed",
        decision_fingerprint="fp-status",
        nonce="nonce-status",
        consumed_at=consumed_at,
        reason="one_time_consumption",
    )
    expect(appended["success"] is True, f"Status fixture audit append failed: {appended}")
    replay = registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED",
        attestation_id="status-consumed",
        decision_fingerprint="fp-status",
        nonce="nonce-status",
        consumed_at=20520.0,
        reason="attestation_already_consumed",
        previous_consumed_record=claim,
    )
    expect(replay["success"] is True, f"Status fixture replay append failed: {replay}")
    source._persist_state()

    with open(state_path, "rb") as file:
        before = file.read()

    status = registry.get_decision_attestation_consumption_status(
        "status-consumed",
        verify_integrity=True,
        include_replay_events=True,
    )
    expect(status["success"] is True, f"Consumed status lookup failed: {status}")
    expect(status["status"] == "DECISION_ATTESTATION_CONSUMED", "Consumed status returned the wrong state.")
    expect(status["consumed"] is True, "Consumed attestation was reported as unconsumed.")
    expect(status["consumed_record"]["decision_fingerprint"] == "fp-status", "Consumption proof lost the ledger fingerprint.")
    expect(status["consumption_audit_record"]["sequence"] == 1, "Consumption proof selected the wrong audit record.")
    expect(status["replay_count"] == 1 and len(status["replay_events"]) == 1, "Replay audit history was not exposed deterministically.")
    expect(status["read_only"] is True and status["authoritative_state_mutated"] is False, "Consumption status was not read-only.")

    with open(state_path, "rb") as file:
        after = file.read()
    expect(after == before, "Read-only consumption status mutated persisted trust state.")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer,
        restarted_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 20530.0,
    )
    restarted_status = restarted_registry.get_decision_attestation_consumption_status("status-consumed")
    expect(restarted_status["success"] is True, f"Restarted consumption status lookup failed: {restarted_status}")
    expect(restarted_status["consumed"] is True and restarted_status["replay_count"] == 1, "Consumption proof was not preserved across restart.")

    tampered_registry = TrustedAttestationKeyRegistry()
    tampered_registry._consumed_decision_attestations["status-consumed"] = {
        "decision_fingerprint": "fp-tampered",
        "nonce": "nonce-status",
        "consumed_at": consumed_at,
    }
    tampered_registry._consumption_audit_records = [dict(record) for record in registry._consumption_audit_records]
    tampered_registry._consumption_audit_head_hash = registry._consumption_audit_head_hash
    tampered = tampered_registry.get_decision_attestation_consumption_status("status-consumed")
    expect(not tampered["success"], "Tampered consumption ledger was accepted by the proof API.")
    expect(tampered["reason"] == "consumption_fingerprint_mismatch", "Tampered ledger returned the wrong proof failure reason.")

    print("PASS: one-time consumption status distinguishes consumed and unconsumed attestations")
    print("PASS: read-only consumption proof cross-checks ledger and audit record")
    print("PASS: consumption proof survives persistent trust-state restart")
    print("PASS: tampered consumption ledger fails closed")


def test_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-binding"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_binding_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 33000.0,
    )

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="seed-binding-attestation",
        decision_fingerprint="seed-binding-fingerprint",
        nonce="seed-binding-nonce",
        consumed_at=33000.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=1,
    )
    expect(exported["success"] is True, f"Binding evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "consumption-binding-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-binding-key",
        issuer=issuer,
        nonce="binding-nonce-001",
        attestation_id="binding-attestation-001",
        issued_at=33000.0,
        expires_at=33300.0,
    )
    expect(attested["success"] is True, f"Binding attestation creation failed: {attested}")

    before = Path(state_path).read_bytes()
    first = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
    )
    expect(first["success"] is True, f"Binding fixture consumption failed: {first}")

    bound = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
        require_current_registry_binding=True,
        verify_integrity=True,
    )
    expect(bound["success"] is True and bound["status"] == "DECISION_ATTESTATION_CONSUMPTION_BOUND", f"Cryptographic consumption binding failed: {bound}")
    expect(bound["read_only"] is True and bound["authoritative_state_mutated"] is False, "Binding verification was not read-only.")
    expect(len(bound["binding_fingerprint"]) == 64, "Binding fingerprint was not a SHA-256 digest.")
    expect(bound["evidence_fingerprint"] == bound["consumption_status"]["consumed_record"]["decision_fingerprint"], "Binding did not connect attestation evidence to the durable claim.")
    expect(bound["consumption_audit_sequence"] == bound["consumption_status"]["consumption_audit_record"]["sequence"], "Binding proof did not identify the authenticated consume event.")
    expect(bound["consumption_audit_record_hash"] == bound["consumption_status"]["consumption_audit_record"]["record_hash"], "Binding proof did not preserve the authenticated audit record hash.")

    with open(state_path, "rb") as file:
        after = file.read()
    expect(after != before, "Expected one-time consumption to persist before read-only binding checks.")
    before_binding = after

    repeated = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
    )
    expect(repeated["success"] is True and repeated["binding_fingerprint"] == bound["binding_fingerprint"], "Consumption binding was not deterministic.")
    expect(Path(state_path).read_bytes() == before_binding, "Read-only consumption binding verification mutated persisted trust state.")

    tampered_registry = TrustedAttestationKeyRegistry()
    tampered_registry._records = {
        key: dict(value) for key, value in registry._records.items()
    }
    tampered_registry._source = registry._source
    tampered_registry._revision = registry._revision
    tampered_registry._key_set_fingerprint = registry._key_set_fingerprint
    tampered_registry._consumed_decision_attestations = {
        key: dict(value) for key, value in registry._consumed_decision_attestations.items()
    }
    tampered_registry._consumption_audit_records = [dict(record) for record in registry._consumption_audit_records]
    tampered_registry._consumption_audit_head_hash = registry._consumption_audit_head_hash
    tampered_registry._consumed_decision_attestations["binding-attestation-001"]["decision_fingerprint"] = "deadbeef"
    tampered = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        tampered_registry,
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
    )
    expect(not tampered["success"] and tampered["reason"] == "consumption_status_consumption_fingerprint_mismatch", f"Tampered durable claim was accepted: {tampered}")

    unconsumed_registry = TrustedAttestationKeyRegistry()
    unconsumed_registry._records = {
        key: dict(value) for key, value in registry._records.items()
    }
    unconsumed_registry._source = registry._source
    unconsumed_registry._revision = registry._revision
    unconsumed_registry._key_set_fingerprint = registry._key_set_fingerprint
    unconsumed = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        unconsumed_registry,
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
    )
    expect(not unconsumed["success"] and unconsumed["reason"] == "attestation_not_consumed", f"Unconsumed attestation was incorrectly bound: {unconsumed}")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer,
        restarted_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 33000.0,
    )
    restarted = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        restarted_registry,
        expected_issuer=issuer,
        expected_key_id="consumption-binding-key",
        expected_nonce="binding-nonce-001",
        expected_attestation_id="binding-attestation-001",
        verification_time=33100.0,
        clock_skew_seconds=0,
        require_current_registry_binding=False,
    )
    expect(restarted["success"] is True and restarted["binding_fingerprint"] == bound["binding_fingerprint"], "Consumption binding was not preserved after restart.")

    print("PASS: evidence attestation cryptographically binds to the durable one-time consumption proof")
    print("PASS: binding fingerprint is deterministic and read-only")
    print("PASS: tampered durable consumption claims fail closed")
    print("PASS: unconsumed attestations cannot produce a consumption proof binding")
    print("PASS: consumption binding survives persistent trust-state restart")



def test_decision_attestation_consumption_binding_proof_offline_export_and_verification(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-offline-proof"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_offline_proof_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 44000.0,
    )

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="offline-proof-seed",
        decision_fingerprint="offline-proof-seed-fp",
        nonce="offline-proof-seed-nonce",
        consumed_at=44000.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Offline-proof evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "offline-proof-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="offline-proof-key",
        issuer=issuer,
        nonce="offline-proof-nonce-001",
        attestation_id="offline-proof-attestation-001",
        issued_at=44000.0,
        expires_at=44300.0,
    )
    expect(attested["success"] is True, f"Offline-proof attestation failed: {attested}")

    consumed = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(consumed["success"] is True, f"Offline-proof attestation consumption failed: {consumed}")

    bound = source.__class__.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        attested["evidence"],
        registry,
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(bound["success"] is True, f"Binding prerequisite failed: {bound}")

    proof_export = source.export_decision_attestation_consumption_binding_proof(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(proof_export["success"] is True, f"Binding proof export failed: {proof_export}")
    proof = proof_export["proof"]
    expect(proof_export["read_only"] is True and proof_export["authoritative_state_mutated"] is False, "Binding proof export was not read-only.")

    before = Path(state_path).read_bytes()
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_binding_proof(
        proof,
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(offline["success"] is True and offline["status"] == "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_VERIFIED", f"Offline binding proof verification failed: {offline}")
    expect(offline["binding_fingerprint"] == bound["binding_fingerprint"], "Offline proof produced a different binding fingerprint.")
    expect(offline["current_registry_binding"] is None and offline["offline"] is True, "Offline verification incorrectly claimed current registry membership.")
    expect(Path(state_path).read_bytes() == before, "Offline proof verification mutated persistent state.")

    tampered_proof = json.loads(json.dumps(proof))
    tampered_proof["binding"]["consumption_audit_record_hash"] = "0" * 64
    tampered = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_binding_proof(
        tampered_proof,
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(not tampered["success"] and tampered["reason"] == "proof_fingerprint_mismatch", f"Tampered proof was accepted: {tampered}")

    tampered_payload = json.loads(json.dumps(proof))
    tampered_payload["consumption_audit_evidence"]["records"][0]["decision_fingerprint"] = "tampered"
    payload = dict(tampered_payload)
    payload.pop("exported_at", None)
    payload.pop("proof_fingerprint", None)
    tampered_payload["proof_fingerprint"] = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    tampered_chain = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_binding_proof(
        tampered_payload,
        private_key.public_key(),
        expected_issuer=issuer,
        expected_key_id="offline-proof-key",
        expected_nonce="offline-proof-nonce-001",
        expected_attestation_id="offline-proof-attestation-001",
        verification_time=44100.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_chain["success"] and tampered_chain["reason"] == "consumption_audit_evidence_invalid", f"Tampered embedded chain was accepted: {tampered_chain}")

    print("PASS: consumption binding proof exports a self-contained cryptographic package")
    print("PASS: consumption binding proof verifies fully offline without authoritative state")
    print("PASS: offline verification never claims current registry membership")
    print("PASS: proof tampering and embedded audit-chain tampering fail closed")

def test_decision_attestation_consumption_proof_bundle_composition_and_offline_verification(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 44000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    def build_proof(index, verification_time):
        seed_attestation_id = f"proof-bundle-seed-{index}"
        registry._append_decision_attestation_consumption_audit(
            event_type="CONSUMED",
            attestation_id=seed_attestation_id,
            decision_fingerprint=f"proof-bundle-seed-fp-{index}",
            nonce=f"proof-bundle-seed-nonce-{index}",
            consumed_at=44000.0 + index,
            reason="fixture",
        )
        source._persist_state()

        exported = registry.export_decision_attestation_consumption_audit_evidence(
            start_sequence=len(registry._consumption_audit_records),
            end_sequence=len(registry._consumption_audit_records),
        )
        expect(exported["success"] is True, f"Proof-bundle evidence export failed for {index}: {exported}")

        nonce = f"proof-bundle-nonce-{index}"
        attestation_id = f"proof-bundle-attestation-{index}"
        attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
            exported["evidence"],
            private_key,
            registry,
            key_id="proof-bundle-key",
            issuer=issuer,
            nonce=nonce,
            attestation_id=attestation_id,
            issued_at=float(verification_time - 100),
            expires_at=float(verification_time + 200),
        )
        expect(attested["success"] is True, f"Proof-bundle attestation failed for {index}: {attested}")

        consumed = source.consume_decision_attestation_consumption_audit_evidence_attestation(
            attested["evidence"],
            expected_issuer=issuer,
            expected_key_id="proof-bundle-key",
            expected_nonce=nonce,
            expected_attestation_id=attestation_id,
            verification_time=float(verification_time),
            clock_skew_seconds=0,
        )
        expect(consumed["success"] is True, f"Proof-bundle consumption failed for {index}: {consumed}")

        proof_export = source.export_decision_attestation_consumption_binding_proof(
            attested["evidence"],
            expected_issuer=issuer,
            expected_key_id="proof-bundle-key",
            expected_nonce=nonce,
            expected_attestation_id=attestation_id,
            verification_time=float(verification_time),
            clock_skew_seconds=0,
        )
        expect(proof_export["success"] is True, f"Proof-bundle proof export failed for {index}: {proof_export}")
        return proof_export["proof"]

    proof_one = build_proof(1, 44100.0)
    proof_two = build_proof(2, 44200.0)

    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_one, proof_two],
        bundle_id="proof-bundle-test-001",
        created_at=44300.0,
    )
    expect(composed["success"] is True, f"Proof bundle composition failed: {composed}")
    bundle = composed["bundle"]
    expect(composed["proof_count"] == 2, "Proof bundle count mismatch.")
    expect(len(bundle["chain"]) == 2, "Proof bundle chain length mismatch.")
    expect(bundle["chain"][0]["previous_proof_fingerprint"] == "", "First proof should not have a previous link.")
    expect(
        bundle["chain"][1]["previous_proof_fingerprint"] == bundle["chain"][0]["proof_fingerprint"],
        "Second proof did not link to the previous proof fingerprint.",
    )

    before = Path(state_path).read_bytes()
    verified = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle(
        bundle,
        {bundle["proofs"][0]["binding"]["recorded_key_fingerprint"]: private_key.public_key()},
        expected_bundle_id="proof-bundle-test-001",
        expected_verification_time=44200.0,
        clock_skew_seconds=0,
    )
    expect(verified["success"] is True, f"Offline proof bundle verification failed: {verified}")
    expect(verified["proof_count"] == 2, "Offline verified proof count mismatch.")
    expect(verified["chain_fingerprint"] == bundle["chain_fingerprint"], "Chain fingerprint changed during verification.")
    expect(verified["bundle_fingerprint"] == bundle["bundle_fingerprint"], "Bundle fingerprint changed during verification.")
    expect(verified["current_registry_binding"] is None and verified["offline"] is True, "Offline bundle verification claimed current registry membership.")
    expect(Path(state_path).read_bytes() == before, "Offline bundle verification mutated persistent trust state.")

    tampered_link = json.loads(json.dumps(bundle))
    tampered_link["chain"][1]["previous_proof_fingerprint"] = "0" * 64
    tampered_link["bundle_fingerprint"] = hashlib.sha256(
        _canonical_json({key: value for key, value in tampered_link.items() if key not in {"created_at", "bundle_fingerprint"}}).encode("utf-8")
    ).hexdigest()
    failed_link = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle(
        tampered_link,
        {bundle["proofs"][0]["binding"]["recorded_key_fingerprint"]: private_key.public_key()},
        expected_bundle_id="proof-bundle-test-001",
        expected_verification_time=44200.0,
        clock_skew_seconds=0,
    )
    expect(not failed_link["success"] and failed_link["reason"] == "chain_fingerprint_mismatch", f"Tampered chain link was accepted: {failed_link}")

    missing_key = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle(
        bundle,
        {},
        expected_bundle_id="proof-bundle-test-001",
        expected_verification_time=44200.0,
        clock_skew_seconds=0,
    )
    expect(not missing_key["success"] and missing_key["reason"] == "entry_1_public_key_missing", f"Missing public key was not rejected: {missing_key}")

    duplicate = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_one, proof_one],
        bundle_id="proof-bundle-duplicate",
        created_at=44300.0,
    )
    expect(not duplicate["success"] and duplicate["reason"] == "duplicate_proof_fingerprint", f"Duplicate proof was accepted: {duplicate}")

    print("PASS: multiple consumption binding proofs compose into a cryptographic proof chain")
    print("PASS: proof-chain bundle verifies fully offline without authoritative registry state")
    print("PASS: previous-proof links, bundle fingerprints, and key resolution fail closed on tampering")
    print("PASS: proof-chain composition remains read-only and introduces no storage")


def test_decision_attestation_consumption_proof_bundle_cryptographic_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle-attestation"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_attestation_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 55000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-attestation-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="bundle-attestation-seed",
        decision_fingerprint="bundle-attestation-seed-fp",
        nonce="bundle-attestation-seed-nonce",
        consumed_at=55001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=len(registry._consumption_audit_records),
        end_sequence=len(registry._consumption_audit_records),
    )
    expect(exported["success"] is True, f"Bundle-attestation evidence export failed: {exported}")

    nonce = "bundle-attestation-nonce"
    attestation_id = "bundle-attestation-id"
    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="proof-bundle-attestation-key",
        issuer=issuer,
        nonce=nonce,
        attestation_id=attestation_id,
        issued_at=54900.0,
        expires_at=55200.0,
    )
    expect(attested["success"] is True, f"Evidence attestation failed: {attested}")

    consumed = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-attestation-key",
        expected_nonce=nonce,
        expected_attestation_id=attestation_id,
        verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(consumed["success"] is True, f"Evidence attestation consumption failed: {consumed}")

    proof_export = source.export_decision_attestation_consumption_binding_proof(
        attested["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-attestation-key",
        expected_nonce=nonce,
        expected_attestation_id=attestation_id,
        verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(proof_export["success"] is True, f"Binding proof export failed: {proof_export}")

    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_export["proof"]],
        bundle_id="bundle-attestation-test-001",
        created_at=55010.0,
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    bundle = composed["bundle"]
    original_bundle_fingerprint = bundle["bundle_fingerprint"]
    before = Path(state_path).read_bytes()

    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key(
        bundle,
        private_key,
        registry,
        key_id="proof-bundle-attestation-key",
        issuer=issuer,
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Proof bundle attestation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]
    expect(signed_bundle["bundle_fingerprint"] == original_bundle_fingerprint, "Bundle fingerprint changed after external attestation.")
    expect("bundle_attestation" in signed_bundle, "Bundle attestation was not embedded.")
    expect(Path(state_path).read_bytes() == before, "Bundle attestation mutated persistent trust state.")

    key_fingerprint = signed_bundle["bundle_attestation"]["key_fingerprint"]
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-attestation-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-attestation-key",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(offline["success"] is True, f"Offline bundle-attestation verification failed: {offline}")
    expect(offline["current_registry_binding"] is None and offline["offline"] is True, "Offline verifier claimed current registry binding.")
    expect(Path(state_path).read_bytes() == before, "Offline bundle-attestation verification mutated persistent state.")

    current = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
        signed_bundle,
        registry,
        expected_bundle_id="bundle-attestation-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-attestation-key",
        require_current_registry_binding=True,
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(current["success"] is True, f"Current registry bundle-attestation verification failed: {current}")
    expect(current["current_registry_binding"] is True, "Current registry binding was not established.")

    tampered = json.loads(json.dumps(signed_bundle))
    tampered["proofs"][0]["binding"]["binding_fingerprint"] = "0" * 64
    tampered["bundle_fingerprint"] = hashlib.sha256(
        _canonical_json({
            key: value
            for key, value in tampered.items()
            if key not in {"created_at", "bundle_fingerprint", "bundle_attestation"}
        }).encode("utf-8")
    ).hexdigest()
    failed_tamper = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        tampered,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-attestation-test-001",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(not failed_tamper["success"], f"Tampered bundle was accepted: {failed_tamper}")

    tampered_attestation = json.loads(json.dumps(signed_bundle))
    tampered_attestation["bundle_attestation"]["bundle_fingerprint"] = "f" * 64
    failed_signature = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        tampered_attestation,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-attestation-test-001",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(not failed_signature["success"] and failed_signature["reason"] == "bundle_fingerprint_mismatch", f"Tampered attestation metadata was accepted: {failed_signature}")

    print("PASS: proof bundle can be cryptographically attested with trusted-key provenance")
    print("PASS: bundle attestation verifies both offline and against the current trusted registry")
    print("PASS: bundle attestation is external to the bundle fingerprint and preserves prior bundle identity")
    print("PASS: bundle and attestation tampering fail closed without state mutation")

def test_decision_attestation_consumption_proof_bundle_attestation_replay_and_temporal_binding(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle-replay"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_replay_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 55000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-replay-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="bundle-replay-seed",
        decision_fingerprint="bundle-replay-seed-fp",
        nonce="bundle-replay-seed-nonce",
        consumed_at=55001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=len(registry._consumption_audit_records),
        end_sequence=len(registry._consumption_audit_records),
    )
    expect(exported["success"] is True, f"Bundle replay evidence export failed: {exported}")

    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="proof-bundle-replay-key",
        issuer=issuer,
        nonce="bundle-replay-evidence-nonce",
        attestation_id="bundle-replay-evidence-id",
        issued_at=54900.0,
        expires_at=55200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation failed: {evidence_attestation}")
    consumed = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-replay-key",
        expected_nonce="bundle-replay-evidence-nonce",
        expected_attestation_id="bundle-replay-evidence-id",
        verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(consumed["success"] is True, f"Evidence consumption failed: {consumed}")

    proof_export = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-replay-key",
        expected_nonce="bundle-replay-evidence-nonce",
        expected_attestation_id="bundle-replay-evidence-id",
        verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(proof_export["success"] is True, f"Binding proof export failed: {proof_export}")
    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_export["proof"]],
        bundle_id="bundle-replay-test-001",
        created_at=55010.0,
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    bundle = composed["bundle"]
    before = Path(state_path).read_bytes()

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        bundle,
        private_key,
        registry,
        key_id="proof-bundle-replay-key",
        issuer=issuer,
        nonce="bundle-replay-nonce",
        attestation_id="bundle-replay-attestation-id",
        issued_at=54990.0,
        expires_at=55100.0,
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(attested["success"] is True, f"Replay-bound bundle attestation failed: {attested}")
    signed_bundle = attested["bundle"]
    bundle_attestation = signed_bundle["bundle_attestation"]
    expect(bundle_attestation["schema_version"] == 2, "Replay-bound bundle attestation did not use schema v2.")
    expect(bundle_attestation["nonce"] == "bundle-replay-nonce", "Bundle nonce was not bound.")
    expect(bundle_attestation["attestation_id"] == "bundle-replay-attestation-id", "Bundle attestation ID was not bound.")
    expect(Path(state_path).read_bytes() == before, "Replay-bound bundle attestation mutated persistent trust state.")

    key_fingerprint = bundle_attestation["key_fingerprint"]
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-replay-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-replay-key",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(offline["success"] is True, f"Offline replay-bound bundle verification failed: {offline}")
    expect(offline["replay_binding"] is True, "Offline verifier did not report replay binding.")
    expect(offline["nonce"] == "bundle-replay-nonce", "Offline verifier lost the nonce.")

    current = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
        signed_bundle,
        registry,
        expected_bundle_id="bundle-replay-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-replay-key",
        require_current_registry_binding=True,
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(current["success"] is True, f"Current registry replay-bound verification failed: {current}")
    expect(current["current_registry_binding"] is True, "Replay-bound bundle attestation lost current registry binding.")

    wrong_nonce = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_nonce="wrong-nonce",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(not wrong_nonce["success"] and wrong_nonce["reason"] == "nonce_mismatch", f"Wrong bundle nonce was accepted: {wrong_nonce}")

    wrong_attestation_id = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_attestation_id="wrong-attestation-id",
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(not wrong_attestation_id["success"] and wrong_attestation_id["reason"] == "attestation_id_mismatch", f"Wrong bundle attestation ID was accepted: {wrong_attestation_id}")

    future_verification = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_verification_time=54950.0,
        clock_skew_seconds=0,
    )
    expect(not future_verification["success"] and future_verification["reason"] == "attestation_not_yet_valid", f"Not-yet-valid bundle attestation was accepted: {future_verification}")

    expired_verification = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        signed_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_verification_time=55150.0,
        clock_skew_seconds=0,
    )
    expect(not expired_verification["success"] and expired_verification["reason"] == "attestation_expired", f"Expired bundle attestation was accepted: {expired_verification}")

    tampered = json.loads(json.dumps(signed_bundle))
    tampered["bundle_attestation"]["nonce"] = "tampered-nonce"
    failed_tamper = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        tampered,
        {key_fingerprint: private_key.public_key()},
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(not failed_tamper["success"] and failed_tamper["reason"] == "signature_verification_failed", f"Tampered signed replay field was accepted: {failed_tamper}")

    legacy = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key(
        bundle,
        private_key,
        registry,
        key_id="proof-bundle-replay-key",
        issuer=issuer,
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(legacy["success"] is True, f"Legacy bundle attestation failed: {legacy}")
    legacy_bundle = legacy["bundle"]
    legacy_verification = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        legacy_bundle,
        {key_fingerprint: private_key.public_key()},
        expected_verification_time=55000.0,
        clock_skew_seconds=0,
    )
    expect(legacy_verification["success"] is True and legacy_verification["replay_binding"] is False, f"Schema-v1 compatibility broke: {legacy_verification}")

    print("PASS: proof-bundle attestations support nonce and temporal replay binding")
    print("PASS: wrong nonce, attestation ID, not-before, and expiration fail closed")
    print("PASS: tampered replay metadata fails signature verification")
    print("PASS: schema-v1 proof-bundle attestations remain backward compatible")


def test_decision_attestation_consumption_proof_bundle_attestation_one_time_consumption(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import multiprocessing

    issuer = "https://issuer.test/decision-consumption-proof-bundle-consume"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_consume_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 56000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-consume-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="proof-bundle-consume-seed",
        decision_fingerprint="proof-bundle-consume-seed-fp",
        nonce="proof-bundle-consume-seed-nonce",
        consumed_at=56001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=1,
    )
    expect(exported["success"] is True, f"Bundle-consumption evidence export failed: {exported}")

    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="proof-bundle-consume-key",
        issuer=issuer,
        nonce="bundle-consume-evidence-nonce",
        attestation_id="bundle-consume-evidence-id",
        issued_at=55900.0,
        expires_at=56200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation creation failed: {evidence_attestation}")

    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-consume-evidence-nonce",
        expected_attestation_id="bundle-consume-evidence-id",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence prerequisite consumption failed: {consumed_evidence}")

    proof_export = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-consume-evidence-nonce",
        expected_attestation_id="bundle-consume-evidence-id",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(proof_export["success"] is True, f"Bundle-consumption proof export failed: {proof_export}")

    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_export["proof"]],
        bundle_id="bundle-consume-test-001",
        created_at=56060.0,
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")

    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"],
        private_key,
        registry,
        key_id="proof-bundle-consume-key",
        issuer=issuer,
        nonce="bundle-consume-nonce",
        attestation_id="bundle-consume-attestation-id",
        issued_at=55990.0,
        expires_at=56200.0,
        expected_verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Replay-bound bundle attestation creation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]

    before_consume = Path(state_path).read_bytes()
    consumed = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-consume-nonce",
        expected_attestation_id="bundle-consume-attestation-id",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(consumed["success"] is True, f"Bundle attestation consumption failed: {consumed}")
    expect(consumed["status"] == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED", "Bundle consumption returned the wrong success status.")
    expect(consumed["consumption"]["decision_fingerprint"] == signed_bundle["bundle_fingerprint"], "Bundle fingerprint was not bound to the one-time claim.")
    expect(consumed["read_only"] is False and consumed["authoritative_state_mutated"] is True, "Successful bundle consumption did not report mutation semantics.")
    expect(Path(state_path).read_bytes() != before_consume, "Successful bundle consumption did not persist authoritative state.")

    replay = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-consume-nonce",
        expected_attestation_id="bundle-consume-attestation-id",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(not replay["success"] and replay["status"] == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAYED", f"Bundle replay was not rejected: {replay}")
    expect(replay["authoritative_state_mutated"] is True, "Bundle replay audit was not reported as persisted mutation.")

    status = registry.get_decision_attestation_consumption_status("bundle-consume-attestation-id")
    expect(status["success"] is True and status["consumed"] is True, f"Bundle consumption status was not readable: {status}")
    expect(status["consumption_audit_record"]["event_type"] == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED", "Generic consumption status did not recognize the bundle consume event.")
    expect(len(status["replay_events"]) == 1, "Generic consumption status did not expose the bundle replay event.")
    expect(status["read_only"] is True and status["authoritative_state_mutated"] is False, "Bundle consumption status was not read-only.")

    restored_registry = TrustedAttestationKeyRegistry()
    restored_source = OIDCDiscoveryJWKSSource(
        issuer,
        restored_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 56050.0,
    )
    restored_replay = restored_source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-consume-nonce",
        expected_attestation_id="bundle-consume-attestation-id",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(not restored_replay["success"] and restored_replay["status"] == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAYED", f"Bundle replay was not preserved across restart: {restored_replay}")

    tampered = json.loads(json.dumps(signed_bundle))
    tampered["bundle_attestation"]["nonce"] = "tampered-bundle-consume-nonce"
    before_tamper = Path(state_path).read_bytes()
    tampered_result = restored_source.consume_decision_attestation_consumption_proof_bundle_attestation(
        tampered,
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_result["success"] and tampered_result["reason"] == "signature_verification_failed", f"Tampered bundle attestation was accepted: {tampered_result}")
    expect(Path(state_path).read_bytes() == before_tamper, "Tampered bundle verification mutated persistent state.")

    legacy = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key(
        composed["bundle"],
        private_key,
        restored_registry,
        key_id="proof-bundle-consume-key",
        issuer=issuer,
        expected_verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(legacy["success"] is True, f"Legacy bundle attestation creation failed: {legacy}")
    legacy_result = restored_source.consume_decision_attestation_consumption_proof_bundle_attestation(
        legacy["bundle"],
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(not legacy_result["success"] and legacy_result["reason"] == "one_time_consumption_requires_schema_v2", f"Schema-v1 bundle attestation was consumed: {legacy_result}")

    short_lived = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"],
        private_key,
        restored_registry,
        key_id="proof-bundle-consume-key",
        issuer=issuer,
        nonce="bundle-consume-expired-nonce",
        attestation_id="bundle-consume-expired-id",
        issued_at=55990.0,
        expires_at=56100.0,
        expected_verification_time=56050.0,
        clock_skew_seconds=0,
    )
    expect(short_lived["success"] is True, f"Short-lived bundle attestation creation failed: {short_lived}")
    expired_before = Path(state_path).read_bytes()
    expired_result = restored_source.consume_decision_attestation_consumption_proof_bundle_attestation(
        short_lived["bundle"],
        expected_bundle_id="bundle-consume-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-consume-key",
        verification_time=56150.0,
        clock_skew_seconds=0,
    )
    expect(not expired_result["success"] and expired_result["reason"] == "attestation_expired", f"Expired bundle attestation was not rejected: {expired_result}")
    expect(Path(state_path).read_bytes() == expired_before, "Expired bundle verification mutated persistent state.")

    concurrency_issuer = issuer
    concurrency_source = OIDCDiscoveryJWKSSource(
        concurrency_issuer,
        restored_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 57050.0,
    )
    concurrency_evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        restored_registry,
        key_id="proof-bundle-consume-key",
        issuer=concurrency_issuer,
        nonce="bundle-concurrency-evidence-nonce",
        attestation_id="bundle-concurrency-evidence-id",
        issued_at=56900.0,
        expires_at=57300.0,
    )
    expect(concurrency_evidence_attestation["success"] is True, f"Concurrency evidence attestation creation failed: {concurrency_evidence_attestation}")
    concurrency_evidence_consumed = concurrency_source.consume_decision_attestation_consumption_audit_evidence_attestation(
        concurrency_evidence_attestation["evidence"],
        expected_issuer=concurrency_issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-concurrency-evidence-nonce",
        expected_attestation_id="bundle-concurrency-evidence-id",
        verification_time=57050.0,
        clock_skew_seconds=0,
    )
    expect(concurrency_evidence_consumed["success"] is True, f"Concurrency evidence consumption failed: {concurrency_evidence_consumed}")
    concurrency_proof_export = concurrency_source.export_decision_attestation_consumption_binding_proof(
        concurrency_evidence_attestation["evidence"],
        expected_issuer=concurrency_issuer,
        expected_key_id="proof-bundle-consume-key",
        expected_nonce="bundle-concurrency-evidence-nonce",
        expected_attestation_id="bundle-concurrency-evidence-id",
        verification_time=57050.0,
        clock_skew_seconds=0,
    )
    expect(concurrency_proof_export["success"] is True, f"Concurrency proof export failed: {concurrency_proof_export}")
    concurrency_composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [concurrency_proof_export["proof"]],
        bundle_id="bundle-concurrency-test-001",
        created_at=57070.0,
    )
    expect(concurrency_composed["success"] is True, f"Concurrency bundle composition failed: {concurrency_composed}")
    concurrency_attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        concurrency_composed["bundle"],
        private_key,
        restored_registry,
        key_id="proof-bundle-consume-key",
        issuer=concurrency_issuer,
        nonce="bundle-concurrency-nonce",
        attestation_id="bundle-concurrency-attestation",
        issued_at=57000.0,
        expires_at=57300.0,
        expected_verification_time=57100.0,
        clock_skew_seconds=0,
    )
    expect(concurrency_attested["success"] is True, f"Concurrency bundle attestation creation failed: {concurrency_attested}")

    worker_count = 8
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_decision_attestation_consumption_proof_bundle_concurrency_worker,
            args=(state_path, concurrency_attested["bundle"], index, result_queue),
        )
        for index in range(1, worker_count + 1)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
        expect(not process.is_alive(), "Concurrent bundle-consumption worker did not terminate.")
        expect(process.exitcode == 0, f"Concurrent bundle-consumption worker failed: exit={process.exitcode}")

    results = [result_queue.get(timeout=5) for _ in range(worker_count)]
    expect(all(result.get("status") != "WORKER_EXCEPTION" for result in results), f"Concurrent bundle-consumption worker raised an exception: {results}")
    consumed_results = [result for result in results if result.get("status") == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED"]
    replay_results = [result for result in results if result.get("status") == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAYED"]
    expect(len(consumed_results) == 1, f"Concurrent bundle one-time consumption accepted more than once: {results}")
    expect(len(replay_results) == worker_count - 1, f"Concurrent bundle replay protection did not reject every loser: {results}")
    expect(all(result.get("success") is False for result in replay_results), f"Bundle replay outcomes reported success: {replay_results}")

    final_registry = TrustedAttestationKeyRegistry()
    OIDCDiscoveryJWKSSource(
        concurrency_issuer,
        final_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 57100.0,
    )
    final_status = final_registry.get_decision_attestation_consumption_status("bundle-concurrency-attestation")
    expect(final_status["success"] is True and final_status["consumed"] is True, f"Concurrent bundle status was not durable: {final_status}")
    expect(len(final_status["replay_events"]) == worker_count - 1, f"Concurrent bundle replay audit count mismatch: {final_status}")

    print("PASS: proof-bundle attestations are consumed exactly once")
    print("PASS: bundle one-time consumption survives persistent trust-state restart")
    print("PASS: schema-v1, tampered, and expired bundle attestations fail closed without claiming consumption")
    print("PASS: generic read-only consumption status recognizes bundle consume/replay audit events")
    print("PASS: concurrent bundle consumption is serialized across processes")
    print("PASS: exactly one concurrent bundle consumer succeeds and every loser is rejected as replay")
    print("PASS: concurrent bundle consumption preserves durable audit history after restart")


def test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_one_time_consumption(tmp_dir):
    import multiprocessing
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle-binding-consumption"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_binding_consumption_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 59000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-binding-consumption-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="binding-consumption-seed",
        decision_fingerprint="binding-consumption-seed-fp",
        nonce="binding-consumption-seed-nonce",
        consumed_at=59001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Seed evidence export failed: {exported}")
    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"], private_key, registry,
        key_id="proof-bundle-binding-consumption-key", issuer=issuer,
        nonce="binding-consumption-evidence-nonce", attestation_id="binding-consumption-evidence-id",
        issued_at=58900.0, expires_at=59200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation failed: {evidence_attestation}")
    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"], expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="binding-consumption-evidence-nonce", expected_attestation_id="binding-consumption-evidence-id",
        verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence consumption failed: {consumed_evidence}")
    evidence_binding = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"], expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="binding-consumption-evidence-nonce", expected_attestation_id="binding-consumption-evidence-id",
        verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(evidence_binding["success"] is True, f"Evidence binding export failed: {evidence_binding}")
    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [evidence_binding["proof"]], bundle_id="bundle-binding-consumption-test-001", created_at=59030.0
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"], private_key, registry, key_id="proof-bundle-binding-consumption-key", issuer=issuer,
        nonce="proof-bundle-binding-consumption-nonce", attestation_id="proof-bundle-binding-consumption-attestation",
        issued_at=58990.0, expires_at=59200.0, expected_verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Bundle attestation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]
    consumed_bundle = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle, expected_bundle_id="bundle-binding-consumption-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="proof-bundle-binding-consumption-nonce",
        expected_attestation_id="proof-bundle-binding-consumption-attestation", verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(consumed_bundle["success"] is True, f"Bundle consumption failed: {consumed_bundle}")
    binding = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle, expected_bundle_id="bundle-binding-consumption-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="proof-bundle-binding-consumption-nonce",
        expected_attestation_id="proof-bundle-binding-consumption-attestation", verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(binding["success"] is True, f"Bundle binding proof export failed: {binding}")
    proof = binding["proof"]
    proof_fingerprint = proof["proof_fingerprint"]
    before = Path(state_path).read_bytes()
    proof_fingerprint = proof["proof_fingerprint"]
    consumption_id = f"proof-binding:{proof_fingerprint}"[:200]

    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    worker_count = 6
    processes = [
        context.Process(
            target=_decision_attestation_consumption_proof_bundle_binding_concurrency_worker,
            args=(state_path, proof, index, result_queue),
        )
        for index in range(worker_count)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
        expect(not process.is_alive(), "Binding-proof concurrent worker did not terminate.")
        expect(process.exitcode == 0, f"Binding-proof concurrent worker failed: exit={process.exitcode}")
    results = [result_queue.get(timeout=5) for _ in range(worker_count)]
    expect(not any(result.get("status") == "WORKER_EXCEPTION" for result in results), f"Binding-proof worker exception: {results}")
    successes = [result for result in results if result.get("status") == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED" and result.get("success") is True]
    replays = [result for result in results if result.get("status") == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAYED" and result.get("success") is False]
    expect(len(successes) == 1, f"Concurrent binding-proof consumption did not produce exactly one success: {results}")
    expect(len(replays) == worker_count - 1, f"Concurrent binding-proof replay protection did not reject every loser: {results}")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer, restarted_registry, state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")), now_fn=lambda: 59022.0,
    )
    status = restarted_registry.get_decision_attestation_consumption_status(consumption_id)
    expect(status["success"] is True and status["status"] == "DECISION_ATTESTATION_CONSUMED", f"Binding proof status invalid: {status}")
    expect(status["consumed_record"]["decision_fingerprint"] == proof_fingerprint, "Consumed binding proof fingerprint mismatch.")
    expect(Path(state_path).read_bytes() != before, "One-time consumption did not persist the authoritative claim.")

    replay = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        proof, expected_bundle_id="bundle-binding-consumption-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="proof-bundle-binding-consumption-nonce",
        expected_attestation_id="proof-bundle-binding-consumption-attestation", verification_time=59021.0, clock_skew_seconds=0,
    )
    expect(not replay["success"] and replay["status"] == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAYED", f"Binding proof replay accepted: {replay}")

    replay_after_restart = restarted_source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        proof, expected_bundle_id="bundle-binding-consumption-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="proof-bundle-binding-consumption-nonce",
        expected_attestation_id="proof-bundle-binding-consumption-attestation", verification_time=59022.0, clock_skew_seconds=0,
    )
    expect(not replay_after_restart["success"] and replay_after_restart["status"] == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAYED", f"Restart replay accepted: {replay_after_restart}")

    tampered = json.loads(json.dumps(proof))
    tampered["binding"]["bundle_fingerprint"] = "0" * 64
    tampered_result = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        tampered, expected_bundle_id="bundle-binding-consumption-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="proof-bundle-binding-consumption-nonce",
        expected_attestation_id="proof-bundle-binding-consumption-attestation", verification_time=59020.0, clock_skew_seconds=0,
    )
    expect(not tampered_result["success"] and tampered_result["reason"] == "proof_fingerprint_mismatch", f"Tampered binding proof was accepted: {tampered_result}")

    audit = restarted_registry.get_decision_attestation_consumption_audit(attestation_id=consumption_id)
    expect(audit["success"] is True, f"Binding-proof audit query failed: {audit}")
    event_types = [record.get("event_type") for record in audit["records"]]
    expect(event_types.count("DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED") == 1, f"Binding-proof consume audit count invalid: {event_types}")
    expect(event_types.count("DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAY_REJECTED") >= worker_count + 1, f"Binding-proof replay audit count invalid: {event_types}")

    print("PASS: bundle-attestation consumption binding proofs are one-time consumable")
    print("PASS: one-time binding-proof consumption survives restart and rejects tampering")
    print("PASS: concurrent binding-proof consumption remains serialized by the existing ledger and audit chain")


def test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle-binding-consumption-binding"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_binding_consumption_binding_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 60000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-consumption-binding-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="consumption-binding-seed",
        decision_fingerprint="consumption-binding-seed-fp",
        nonce="consumption-binding-seed-nonce",
        consumed_at=60001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Seed evidence export failed: {exported}")
    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"], private_key, registry,
        key_id="proof-bundle-consumption-binding-key", issuer=issuer,
        nonce="consumption-binding-evidence-nonce", attestation_id="consumption-binding-evidence-id",
        issued_at=59900.0, expires_at=60200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation failed: {evidence_attestation}")
    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"],
        expected_issuer=issuer, expected_key_id="proof-bundle-consumption-binding-key",
        expected_nonce="consumption-binding-evidence-nonce", expected_attestation_id="consumption-binding-evidence-id",
        verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence consumption failed: {consumed_evidence}")

    evidence_binding = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"],
        expected_issuer=issuer, expected_key_id="proof-bundle-consumption-binding-key",
        expected_nonce="consumption-binding-evidence-nonce", expected_attestation_id="consumption-binding-evidence-id",
        verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(evidence_binding["success"] is True, f"Evidence binding export failed: {evidence_binding}")
    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [evidence_binding["proof"]], bundle_id="bundle-consumption-binding-test-001", created_at=60030.0
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"], private_key, registry,
        key_id="proof-bundle-consumption-binding-key", issuer=issuer,
        nonce="bundle-consumption-binding-nonce", attestation_id="bundle-consumption-binding-attestation",
        issued_at=59990.0, expires_at=60200.0, expected_verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Bundle attestation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]
    consumed_bundle = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(consumed_bundle["success"] is True, f"Bundle consumption failed: {consumed_bundle}")

    bundle_binding = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(bundle_binding["success"] is True, f"Bundle binding proof export failed: {bundle_binding}")
    binding_proof = bundle_binding["proof"]
    consumed_binding_proof = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        binding_proof,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(consumed_binding_proof["success"] is True, f"Binding proof consumption failed: {consumed_binding_proof}")

    before_export = Path(state_path).read_bytes()
    exported_consumption_binding = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        binding_proof,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(exported_consumption_binding["success"] is True, f"Consumption-binding export failed: {exported_consumption_binding}")
    expect(exported_consumption_binding["read_only"] is True, "Consumption-binding export was not read-only.")
    expect(exported_consumption_binding["authoritative_state_mutated"] is False, "Consumption-binding export mutated authoritative state.")
    expect(Path(state_path).read_bytes() == before_export, "Consumption-binding export mutated persistent trust state.")

    proof = exported_consumption_binding["proof"]
    key_fingerprint = signed_bundle["bundle_attestation"]["key_fingerprint"]
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
        proof,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(offline["success"] is True, f"Offline consumption-binding verification failed: {offline}")
    expect(offline["offline"] is True and offline["read_only"] is True, "Offline verification mutation semantics were incorrect.")
    expect(offline["authoritative_state_mutated"] is False, "Offline verification claimed authoritative mutation.")
    expect(offline["source_proof_fingerprint"] == binding_proof["proof_fingerprint"], "Source proof fingerprint was not preserved.")
    expect(offline["consumption_audit_record_hash"] == proof["binding"]["consumption_audit_record_hash"], "Consumption audit record hash was not preserved.")

    before_repeat = Path(state_path).read_bytes()
    repeated = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        binding_proof,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(repeated["success"] is True, f"Repeated consumption-binding export failed: {repeated}")
    expect(repeated["proof"]["proof_fingerprint"] == proof["proof_fingerprint"], "Consumption-binding proof fingerprint was not deterministic.")
    expect(repeated["proof"]["binding"]["binding_fingerprint"] == proof["binding"]["binding_fingerprint"], "Consumption-binding fingerprint was not deterministic.")
    expect(Path(state_path).read_bytes() == before_repeat, "Repeated consumption-binding export mutated persistent trust state.")

    tampered = json.loads(json.dumps(proof))
    tampered["binding"]["consumption_audit_record_hash"] = "0" * 64
    tampered_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
        tampered,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(not tampered_result["success"] and tampered_result["reason"] in {"proof_fingerprint_mismatch", "binding_record_hash_mismatch"}, f"Tampered consumption-binding proof was accepted: {tampered_result}")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer, restarted_registry, state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")), now_fn=lambda: 60025.0,
    )
    restarted_export = restarted_source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        binding_proof,
        expected_bundle_id="bundle-consumption-binding-test-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-consumption-binding-key", expected_nonce="bundle-consumption-binding-nonce",
        expected_attestation_id="bundle-consumption-binding-attestation", verification_time=60020.0, clock_skew_seconds=0,
    )
    expect(restarted_export["success"] is True, f"Consumption-binding export after restart failed: {restarted_export}")
    expect(restarted_export["proof"]["proof_fingerprint"] == proof["proof_fingerprint"], "Restart changed consumption-binding proof identity.")

    print("PASS: binding-proof consumption is cryptographically bound to its authoritative one-time audit event")
    print("PASS: binding-proof consumption proof verifies fully offline without authoritative state")
    print("PASS: consumption-binding export is deterministic, read-only, restart-safe, and fail-closed on tampering")

def test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_one_time_consumption(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import multiprocessing

    issuer = "https://issuer.test/decision-consumption-proof-bundle-binding-consumption"
    state_path = os.path.join(tmp_dir, "memory_oidc_binding_consumption_binding_one_time_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 60100.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-binding-consumption-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="binding-consumption-seed",
        decision_fingerprint="binding-consumption-seed-fp",
        nonce="binding-consumption-seed-nonce",
        consumed_at=60101.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Seed evidence export failed: {exported}")
    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"], private_key, registry,
        key_id="proof-bundle-binding-consumption-key", issuer=issuer,
        nonce="binding-consumption-evidence-nonce", attestation_id="binding-consumption-evidence-id",
        issued_at=60000.0, expires_at=60300.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation failed: {evidence_attestation}")
    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"], expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="binding-consumption-evidence-nonce",
        expected_attestation_id="binding-consumption-evidence-id",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence consumption failed: {consumed_evidence}")

    evidence_binding = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"], expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="binding-consumption-evidence-nonce",
        expected_attestation_id="binding-consumption-evidence-id",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(evidence_binding["success"] is True, f"Evidence binding export failed: {evidence_binding}")
    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [evidence_binding["proof"]], bundle_id="bundle-binding-consumption-one-time-001", created_at=60130.0
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"], private_key, registry,
        key_id="proof-bundle-binding-consumption-key", issuer=issuer,
        nonce="bundle-binding-consumption-nonce", attestation_id="bundle-binding-consumption-attestation",
        issued_at=60090.0, expires_at=60300.0,
        expected_verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Bundle attestation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]
    consumed_bundle = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(consumed_bundle["success"] is True, f"Bundle consumption failed: {consumed_bundle}")

    binding_export = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(binding_export["success"] is True, f"Binding proof export failed: {binding_export}")
    binding_proof = binding_export["proof"]
    consumed_binding_proof = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        binding_proof,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(consumed_binding_proof["success"] is True, f"Binding proof consumption failed: {consumed_binding_proof}")

    consumption_binding_export = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        binding_proof,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(consumption_binding_export["success"] is True, f"Consumption binding export failed: {consumption_binding_export}")
    consumption_binding_proof = consumption_binding_export["proof"]
    state_before_tamper = Path(state_path).read_bytes()

    tampered = json.loads(json.dumps(consumption_binding_proof))
    tampered["binding"]["consumption_audit_record_hash"] = "0" * 64
    tampered_result = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        tampered,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(not tampered_result["success"], f"Tampered consumption-binding proof was accepted: {tampered_result}")
    expect(Path(state_path).read_bytes() == state_before_tamper, "Tampered proof changed authoritative state.")

    first = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        consumption_binding_proof,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(first["success"] is True, f"First consumption-binding proof consumption failed: {first}")
    expect(first["status"] == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMED", "First consumption returned wrong status.")

    replay = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        consumption_binding_proof,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(not replay["success"] and replay["status"] == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAYED", f"Replay was not rejected: {replay}")

    consumption_id = f"binding-consumption-binding:{consumption_binding_proof['proof_fingerprint']}"
    status = source.registry.get_decision_attestation_consumption_status(consumption_id, verify_integrity=True, include_replay_events=True)
    expect(status["success"] is True and status["status"] == "DECISION_ATTESTATION_CONSUMED", f"Consumption status invalid: {status}")
    expect(status["consumed_record"]["decision_fingerprint"] == consumption_binding_proof["proof_fingerprint"], "Consumed proof fingerprint mismatch.")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer, restarted_registry, state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")), now_fn=lambda: 60125.0,
    )
    restarted_replay = restarted_source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        consumption_binding_proof,
        expected_bundle_id="bundle-binding-consumption-one-time-001", expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-consumption-key",
        expected_nonce="bundle-binding-consumption-nonce",
        expected_attestation_id="bundle-binding-consumption-attestation",
        verification_time=60120.0, clock_skew_seconds=0,
    )
    expect(not restarted_replay["success"] and restarted_replay["status"] == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAYED", f"Restart replay was accepted: {restarted_replay}")

    # Fresh proof: same architecture, different source bundle/attestation identity.
    registry2 = TrustedAttestationKeyRegistry()
    source2 = OIDCDiscoveryJWKSSource(
        issuer, registry2,
        state_path=state_path + ".concurrent",
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 60100.0,
    )
    registry2.refresh_from_jwks(
        {"keys": [public_key_to_jwk(private_key.public_key(), "proof-bundle-binding-consumption-key", version="2026-09-25", status=IDENTITY_KEY_STATUS_ACTIVE)]},
        source=issuer + "/.well-known/jwks.json",
    )
    registry2._append_decision_attestation_consumption_audit(
        event_type="CONSUMED", attestation_id="concurrency-seed", decision_fingerprint="concurrency-seed-fp", nonce="concurrency-seed-nonce", consumed_at=60101.0, reason="fixture"
    )
    source2._persist_state()
    exported2 = registry2.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    evidence2 = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported2["evidence"], private_key, registry2, key_id="proof-bundle-binding-consumption-key", issuer=issuer,
        nonce="concurrency-evidence-nonce", attestation_id="concurrency-evidence-id", issued_at=60000.0, expires_at=60300.0,
    )
    source2.consume_decision_attestation_consumption_audit_evidence_attestation(evidence2["evidence"], expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="concurrency-evidence-nonce", expected_attestation_id="concurrency-evidence-id", verification_time=60120.0, clock_skew_seconds=0)
    proof2 = source2.export_decision_attestation_consumption_binding_proof(evidence2["evidence"], expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="concurrency-evidence-nonce", expected_attestation_id="concurrency-evidence-id", verification_time=60120.0, clock_skew_seconds=0)["proof"]
    bundle2 = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle([proof2], bundle_id="bundle-concurrency-binding-001", created_at=60130.0)["bundle"]
    signed2 = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(bundle2, private_key, registry2, key_id="proof-bundle-binding-consumption-key", issuer=issuer, nonce="bundle-concurrency-nonce", attestation_id="bundle-concurrency-attestation", issued_at=60090.0, expires_at=60300.0, expected_verification_time=60120.0, clock_skew_seconds=0)["bundle"]
    source2.consume_decision_attestation_consumption_proof_bundle_attestation(signed2, expected_bundle_id="bundle-concurrency-binding-001", expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="bundle-concurrency-nonce", expected_attestation_id="bundle-concurrency-attestation", verification_time=60120.0, clock_skew_seconds=0)
    binding2 = source2.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(signed2, expected_bundle_id="bundle-concurrency-binding-001", expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="bundle-concurrency-nonce", expected_attestation_id="bundle-concurrency-attestation", verification_time=60120.0, clock_skew_seconds=0)["proof"]
    source2.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(binding2, expected_bundle_id="bundle-concurrency-binding-001", expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="bundle-concurrency-nonce", expected_attestation_id="bundle-concurrency-attestation", verification_time=60120.0, clock_skew_seconds=0)
    concurrent_proof = source2.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(binding2, expected_bundle_id="bundle-concurrency-binding-001", expected_issuer=issuer, expected_key_id="proof-bundle-binding-consumption-key", expected_nonce="bundle-concurrency-nonce", expected_attestation_id="bundle-concurrency-attestation", verification_time=60120.0, clock_skew_seconds=0)["proof"]

    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    workers = [context.Process(target=_decision_attestation_consumption_binding_consumption_binding_concurrency_worker, args=(state_path + ".concurrent", concurrent_proof, index, result_queue)) for index in range(6)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(30)
        expect(not worker.is_alive(), "Consumption-binding concurrency worker did not terminate.")
        expect(worker.exitcode == 0, f"Consumption-binding concurrency worker failed: {worker.exitcode}")
    results = [result_queue.get(timeout=5) for _ in workers]
    expect(not any(item.get("status") == "WORKER_EXCEPTION" for item in results), f"Consumption-binding worker exception: {results}")
    successes = [item for item in results if item.get("success") is True and item.get("status") == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMED"]
    replays = [item for item in results if item.get("success") is False and item.get("status") == "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAYED"]
    expect(len(successes) == 1, f"Concurrent consumption did not produce exactly one success: {results}")
    expect(len(replays) == 5, f"Concurrent replay protection did not reject all losers: {results}")

    print("PASS: consumption-binding proofs are one-time consumable")
    print("PASS: replay is rejected after restart and tampering fails closed")
    print("PASS: concurrent consumption produces exactly one authoritative success")



def test_terminal_consumption_binding_proof_trusted_key_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/terminal-consumption-binding-attestation"
    state_path = os.path.join(tmp_dir, "memory_oidc_terminal_consumption_binding_attestation_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 61000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "terminal-consumption-binding-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="terminal-seed",
        decision_fingerprint="terminal-seed-fp",
        nonce="terminal-seed-nonce",
        consumed_at=61001.0,
        reason="fixture",
    )
    source._persist_state()

    seed = registry.export_decision_attestation_consumption_audit_evidence(start_sequence=1, end_sequence=1)
    expect(seed["success"] is True, f"Seed export failed: {seed}")
    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        seed["evidence"], private_key, registry,
        key_id="terminal-consumption-binding-key", issuer=issuer,
        nonce="terminal-evidence-nonce", attestation_id="terminal-evidence-id",
        issued_at=60900.0, expires_at=61200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation failed: {evidence_attestation}")
    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"], expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-evidence-nonce",
        expected_attestation_id="terminal-evidence-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence consumption failed: {consumed_evidence}")
    evidence_binding = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"], expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-evidence-nonce",
        expected_attestation_id="terminal-evidence-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(evidence_binding["success"] is True, f"Evidence binding export failed: {evidence_binding}")
    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [evidence_binding["proof"]], bundle_id="terminal-bundle-001", created_at=61030.0
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")
    signed_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"], private_key, registry,
        key_id="terminal-consumption-binding-key", issuer=issuer,
        nonce="terminal-bundle-nonce", attestation_id="terminal-bundle-id",
        issued_at=60990.0, expires_at=61200.0,
        expected_verification_time=61020.0, clock_skew_seconds=0,
    )["bundle"]
    consumed_bundle = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle, expected_bundle_id="terminal-bundle-001", expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-bundle-nonce",
        expected_attestation_id="terminal-bundle-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(consumed_bundle["success"] is True, f"Bundle consumption failed: {consumed_bundle}")
    terminal_binding = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle, expected_bundle_id="terminal-bundle-001", expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-bundle-nonce",
        expected_attestation_id="terminal-bundle-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(terminal_binding["success"] is True, f"Terminal binding export failed: {terminal_binding}")
    consumed_terminal_binding = source.consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        terminal_binding["proof"], expected_bundle_id="terminal-bundle-001", expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-bundle-nonce",
        expected_attestation_id="terminal-bundle-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(consumed_terminal_binding["success"] is True, f"Terminal binding proof consumption failed: {consumed_terminal_binding}")
    terminal_proof = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        terminal_binding["proof"], expected_bundle_id="terminal-bundle-001", expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-bundle-nonce",
        expected_attestation_id="terminal-bundle-id", verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(terminal_proof["success"] is True, f"Terminal proof export failed: {terminal_proof}")

    before = Path(state_path).read_bytes()
    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_with_trusted_key_replay_binding(
        terminal_proof["proof"], private_key, registry,
        key_id="terminal-consumption-binding-key", issuer=issuer,
        nonce="terminal-attestation-nonce", attestation_id="terminal-attestation-id",
        issued_at=60995.0, expires_at=61250.0,
        expected_bundle_id="terminal-bundle-001", expected_source_issuer=issuer,
        expected_source_key_id="terminal-consumption-binding-key", expected_source_nonce="terminal-bundle-nonce",
        expected_source_attestation_id="terminal-bundle-id", expected_verification_time=61020.0,
        clock_skew_seconds=0,
    )
    expect(attested["success"] is True, f"Terminal trusted-key attestation failed: {attested}")
    expect(Path(state_path).read_bytes() == before, "Terminal attestation mutated persistent trust state.")

    wrapper = attested["attestation"]
    key_fp = private_key.public_key()
    public_key_fingerprint = signed_bundle["bundle_attestation"]["key_fingerprint"]
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_offline(
        wrapper, {public_key_fingerprint: key_fp}, expected_bundle_id="terminal-bundle-001",
        expected_issuer=issuer, expected_key_id="terminal-consumption-binding-key",
        expected_nonce="terminal-attestation-nonce", expected_attestation_id="terminal-attestation-id",
        expected_source_key_id="terminal-consumption-binding-key", expected_source_nonce="terminal-bundle-nonce",
        expected_source_attestation_id="terminal-bundle-id", expected_verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(offline["success"] is True, f"Offline terminal attestation verification failed: {offline}")
    expect(offline["offline"] is True and offline["read_only"] is True and offline["authoritative_state_mutated"] is False, "Offline terminal attestation mutation semantics were incorrect.")

    current = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_with_registry(
        wrapper, registry, expected_bundle_id="terminal-bundle-001", expected_issuer=issuer,
        expected_key_id="terminal-consumption-binding-key", expected_nonce="terminal-attestation-nonce",
        expected_attestation_id="terminal-attestation-id", expected_source_key_id="terminal-consumption-binding-key",
        expected_source_nonce="terminal-bundle-nonce", expected_source_attestation_id="terminal-bundle-id",
        expected_verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(current["success"] is True and current["current_registry_binding"] is True, f"Current terminal attestation verification failed: {current}")

    tampered = json.loads(json.dumps(wrapper))
    tampered["terminal_proof_attestation"]["signature_fingerprint"] = "0" * 64
    tampered_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_offline(
        tampered, {public_key_fingerprint: key_fp}, expected_bundle_id="terminal-bundle-001",
        expected_issuer=issuer, expected_key_id="terminal-consumption-binding-key",
        expected_nonce="terminal-attestation-nonce", expected_attestation_id="terminal-attestation-id",
        expected_source_key_id="terminal-consumption-binding-key", expected_source_nonce="terminal-bundle-nonce",
        expected_source_attestation_id="terminal-bundle-id", expected_verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(not tampered_result["success"] and tampered_result["reason"] == "signature_fingerprint_mismatch", f"Tampered terminal attestation was accepted: {tampered_result}")

    expired = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_with_trusted_key_replay_binding(
        terminal_proof["proof"], private_key, registry,
        key_id="terminal-consumption-binding-key", issuer=issuer,
        nonce="terminal-expired-nonce", attestation_id="terminal-expired-id",
        issued_at=60900.0, expires_at=61010.0, expected_bundle_id="terminal-bundle-001",
        expected_source_issuer=issuer, expected_source_key_id="terminal-consumption-binding-key",
        expected_source_nonce="terminal-bundle-nonce", expected_source_attestation_id="terminal-bundle-id",
        expected_verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(expired["success"] is True, f"Expired fixture attestation creation failed: {expired}")
    expired_verify = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_offline(
        expired["attestation"], {public_key_fingerprint: key_fp}, expected_bundle_id="terminal-bundle-001",
        expected_issuer=issuer, expected_key_id="terminal-consumption-binding-key",
        expected_nonce="terminal-expired-nonce", expected_attestation_id="terminal-expired-id",
        expected_source_key_id="terminal-consumption-binding-key", expected_source_nonce="terminal-bundle-nonce",
        expected_source_attestation_id="terminal-bundle-id", expected_verification_time=61020.0, clock_skew_seconds=0,
    )
    expect(not expired_verify["success"] and expired_verify["reason"] == "attestation_expired", f"Expired terminal attestation was accepted: {expired_verify}")

    print("PASS: terminal consumption-binding proof can be trusted-key attested with replay binding")
    print("PASS: terminal attestation verifies offline and against current registry provenance")
    print("PASS: terminal attestation remains read-only and fails closed on tampering/expiration")

def test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-proof-bundle-binding"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_proof_bundle_binding_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 58000.0,
    )

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "proof-bundle-binding-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="proof-bundle-binding-seed",
        decision_fingerprint="proof-bundle-binding-seed-fp",
        nonce="proof-bundle-binding-seed-nonce",
        consumed_at=58001.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=1,
    )
    expect(exported["success"] is True, f"Binding evidence export failed: {exported}")

    evidence_attestation = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="proof-bundle-binding-key",
        issuer=issuer,
        nonce="bundle-binding-evidence-nonce",
        attestation_id="bundle-binding-evidence-id",
        issued_at=57900.0,
        expires_at=58200.0,
    )
    expect(evidence_attestation["success"] is True, f"Evidence attestation creation failed: {evidence_attestation}")

    consumed_evidence = source.consume_decision_attestation_consumption_audit_evidence_attestation(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-evidence-nonce",
        expected_attestation_id="bundle-binding-evidence-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(consumed_evidence["success"] is True, f"Evidence prerequisite consumption failed: {consumed_evidence}")

    proof_export = source.export_decision_attestation_consumption_binding_proof(
        evidence_attestation["evidence"],
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-evidence-nonce",
        expected_attestation_id="bundle-binding-evidence-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(proof_export["success"] is True, f"Evidence binding proof export failed: {proof_export}")

    composed = OIDCDiscoveryJWKSSource.compose_decision_attestation_consumption_proof_bundle(
        [proof_export["proof"]],
        bundle_id="bundle-binding-test-001",
        created_at=58060.0,
    )
    expect(composed["success"] is True, f"Bundle composition failed: {composed}")

    attested_bundle = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        composed["bundle"],
        private_key,
        registry,
        key_id="proof-bundle-binding-key",
        issuer=issuer,
        nonce="bundle-binding-nonce",
        attestation_id="bundle-binding-attestation-id",
        issued_at=57990.0,
        expires_at=58200.0,
        expected_verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(attested_bundle["success"] is True, f"Bundle attestation creation failed: {attested_bundle}")
    signed_bundle = attested_bundle["bundle"]

    consumed_bundle = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(consumed_bundle["success"] is True, f"Bundle attestation consumption failed: {consumed_bundle}")

    before_export = Path(state_path).read_bytes()
    exported_binding = source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle,
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(exported_binding["success"] is True, f"Bundle-attestation consumption binding export failed: {exported_binding}")
    expect(exported_binding["read_only"] is True and exported_binding["authoritative_state_mutated"] is False, "Binding proof export was not read-only.")
    expect(Path(state_path).read_bytes() == before_export, "Binding proof export mutated persistent trust state.")

    proof = exported_binding["proof"]
    key_fingerprint = signed_bundle["bundle_attestation"]["key_fingerprint"]
    offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        proof,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(offline["success"] is True, f"Offline consumption binding verification failed: {offline}")
    expect(offline["offline"] is True and offline["read_only"] is True and offline["authoritative_state_mutated"] is False, "Offline binding verification mutation semantics were incorrect.")
    expect(offline["bundle_fingerprint"] == signed_bundle["bundle_fingerprint"], "Offline binding proof lost the bundle fingerprint.")
    expect(offline["consumption_audit_record_hash"] == proof["binding"]["consumption_audit_record_hash"], "Offline binding proof lost the audit record hash.")

    proof_fingerprint_before_replay = proof["proof_fingerprint"]
    binding_fingerprint_before_replay = proof["binding"]["binding_fingerprint"]

    replay = source.consume_decision_attestation_consumption_proof_bundle_attestation(
        signed_bundle,
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(not replay["success"] and replay["status"] == "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAYED", f"Bundle replay was not rejected: {replay}")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted_source = OIDCDiscoveryJWKSSource(
        issuer,
        restarted_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 58060.0,
    )
    before_reexport = Path(state_path).read_bytes()
    reexported = restarted_source.export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        signed_bundle,
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(reexported["success"] is True, f"Binding proof re-export after restart failed: {reexported}")
    expect(reexported["proof"]["proof_fingerprint"] != proof_fingerprint_before_replay, "Replay did not create a distinct audit-evidence snapshot fingerprint.")
    expect(reexported["proof"]["binding"]["binding_fingerprint"] == binding_fingerprint_before_replay, "Binding fingerprint changed after replay/restart.")

    original_after_replay = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        proof,
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(original_after_replay["success"] is True, f"Original historical binding proof was invalidated by replay: {original_after_replay}")

    reexported_offline = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        reexported["proof"],
        {key_fingerprint: private_key.public_key()},
        expected_bundle_id="bundle-binding-test-001",
        expected_issuer=issuer,
        expected_key_id="proof-bundle-binding-key",
        expected_nonce="bundle-binding-nonce",
        expected_attestation_id="bundle-binding-attestation-id",
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(reexported_offline["success"] is True, f"Re-exported binding proof failed offline verification: {reexported_offline}")
    expect(Path(state_path).read_bytes() == before_reexport, "Binding proof re-export after restart mutated persistent trust state.")

    tampered_bundle = json.loads(json.dumps(proof))
    tampered_bundle["attested_bundle"]["bundle_attestation"]["nonce"] = "tampered-binding-nonce"
    tampered_bundle_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        tampered_bundle,
        {key_fingerprint: private_key.public_key()},
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_bundle_result["success"] and tampered_bundle_result["reason"] in {"proof_fingerprint_mismatch", "bundle_attestation_invalid"}, f"Tampered bundle-attestation binding proof was accepted: {tampered_bundle_result}")

    tampered_audit = json.loads(json.dumps(proof))
    tampered_audit["consumption_audit_evidence"]["records"][-1]["decision_fingerprint"] = "tampered-bundle-fingerprint"
    tampered_audit_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        tampered_audit,
        {key_fingerprint: private_key.public_key()},
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_audit_result["success"] and tampered_audit_result["reason"] == "proof_fingerprint_mismatch", f"Tampered audit evidence was accepted: {tampered_audit_result}")

    tampered_binding = json.loads(json.dumps(proof))
    tampered_binding["binding"]["bundle_fingerprint"] = "0" * 64
    tampered_binding_result = OIDCDiscoveryJWKSSource.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        tampered_binding,
        {key_fingerprint: private_key.public_key()},
        verification_time=58050.0,
        clock_skew_seconds=0,
    )
    expect(not tampered_binding_result["success"] and tampered_binding_result["reason"] == "proof_fingerprint_mismatch", f"Tampered binding section was accepted: {tampered_binding_result}")

    print("PASS: bundle-attestation consumption binding proof exports read-only without new storage")
    print("PASS: bundle-attestation consumption binding proof verifies fully offline")
    print("PASS: historical binding remains verifiable across replay and persistent trust-state restart")
    print("PASS: tampered bundle, audit evidence, and binding metadata fail closed")


def test_decision_attestation_consumption_audit_evidence_attestation_concurrent_one_time_consumption(tmp_dir):
    import multiprocessing
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/decision-consumption-audit-concurrency"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_concurrency_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 32000.0,
    )

    registry._append_decision_attestation_consumption_audit(
        event_type="CONSUMED",
        attestation_id="seed-concurrency-attestation",
        decision_fingerprint="seed-concurrency-fingerprint",
        nonce="seed-concurrency-nonce",
        consumed_at=32000.0,
        reason="fixture",
    )
    source._persist_state()

    exported = registry.export_decision_attestation_consumption_audit_evidence(
        start_sequence=1,
        end_sequence=1,
    )
    expect(exported["success"] is True, f"Concurrency evidence export failed: {exported}")

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "consumption-concurrency-key",
                    version="2026-09-25",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    source._persist_state()

    attested = OIDCDiscoveryJWKSSource.attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        exported["evidence"],
        private_key,
        registry,
        key_id="consumption-concurrency-key",
        issuer=issuer,
        nonce="concurrency-nonce-001",
        attestation_id="concurrency-attestation-001",
        issued_at=32000.0,
        expires_at=32300.0,
    )
    expect(attested["success"] is True, f"Concurrency replay-bound attestation creation failed: {attested}")

    worker_count = 8
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_decision_attestation_evidence_concurrency_worker,
            args=(state_path, attested["evidence"], index, result_queue),
        )
        for index in range(1, worker_count + 1)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
        expect(not process.is_alive(), "Concurrent evidence-attestation worker did not terminate.")
        expect(process.exitcode == 0, f"Concurrent evidence-attestation worker failed: exit={process.exitcode}")

    results = [result_queue.get(timeout=5) for _ in range(worker_count)]
    expect(len(results) == worker_count, f"Missing concurrent worker results: {results}")
    expect(
        all(result.get("status") != "WORKER_EXCEPTION" for result in results),
        f"Concurrent evidence-attestation worker raised an exception: {results}",
    )

    consumed = [result for result in results if result.get("status") == "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED"]
    replayed = [result for result in results if result.get("status") == "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAYED"]
    expect(len(consumed) == 1, f"Concurrent one-time consumption accepted more than once: {results}")
    expect(len(replayed) == worker_count - 1, f"Concurrent replay protection did not reject every loser: {results}")
    expect(all(result.get("success") is False for result in replayed), f"Replay outcomes reported success: {replayed}")

    restored_registry = TrustedAttestationKeyRegistry()
    restored_source = OIDCDiscoveryJWKSSource(
        issuer,
        restored_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 32000.0,
    )
    audit = restored_registry.get_decision_attestation_consumption_audit(
        attestation_id="concurrency-attestation-001"
    )
    expect(audit["success"] is True, f"Concurrent consumption audit query failed: {audit}")
    event_types = [record.get("event_type") for record in audit["records"]]
    expect(event_types.count("CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED") == 1, f"Concurrent audit recorded multiple consume events: {event_types}")
    expect(event_types.count("CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED") == worker_count - 1, f"Concurrent audit lost replay events: {event_types}")
    expect(
        len(restored_registry._consumed_decision_attestations) == 1
        and "concurrency-attestation-001" in restored_registry._consumed_decision_attestations,
        "Concurrent consumption created duplicate durable claims.",
    )

    timeline = restored_registry.get_decision_attestation_consumption_audit_timeline(
        limit=worker_count + 5,
        reverse=False,
        verify_integrity=True,
    )
    expect(timeline["success"] is True, f"Concurrent consumption timeline integrity failed: {timeline}")
    records = timeline.get("records", [])
    sequences = [record.get("sequence") for record in records]
    expect(sequences == list(range(1, len(records) + 1)), f"Concurrent consumption produced broken audit sequence: {records}")
    expect(
        timeline.get("head_hash") == restored_registry._consumption_audit_head_hash,
        "Concurrent consumption audit head hash was not preserved.",
    )

    print("PASS: concurrent evidence-attestation consumption is serialized across processes")
    print("PASS: exactly one concurrent consumer succeeds and every loser is rejected as replay")
    print("PASS: concurrent consumption preserves the existing audit hash chain")
    print("PASS: concurrent consumption leaves exactly one durable one-time claim after restart")

def test_oidc_trust_state_audit_evidence_key_provenance(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/audit-key-provenance"
    state_path = os.path.join(tmp_dir, "memory_oidc_audit_key_provenance_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 15000.0,
    )
    source._state_revision = 10
    source._state_fingerprint = "provenance-state"
    source._persisted_state_fingerprint = source._state_fingerprint
    source._append_trust_state_journal("PROVENANCE_EVENT", {"value": 1})

    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "audit-provenance-key",
                    version="7",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )
    metadata = registry.get_verification_key_metadata(
        "audit-provenance-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519
    )

    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Provenance evidence export failed: {exported}")

    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(
        exported["evidence"],
        private_key,
        registry,
        key_id="audit-provenance-key",
        issuer=issuer,
    )
    expect(attested["success"] is True, f"Trusted provenance attestation failed: {attested}")
    attestation = attested["evidence"]["attestation"]
    expect(attestation["key_fingerprint"] == metadata["fingerprint"], "Key fingerprint provenance was not recorded.")
    expect(attestation["registry_revision"] == metadata["registry_revision"], "Registry revision provenance was not recorded.")
    expect(attestation["key_set_fingerprint"] == metadata["key_set_fingerprint"], "Key-set fingerprint provenance was not recorded.")
    expect(attestation["key_source"] == metadata["source"], "Key source provenance was not recorded.")
    expect(attestation["key_version"] == metadata["version"], "Key version provenance was not recorded.")

    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_trusted_key_provenance(
        attested["evidence"], registry, expected_issuer=issuer, expected_key_id="audit-provenance-key"
    )
    expect(verified["success"] is True, f"Provenance verification failed: {verified}")
    expect(verified["status"] == "AUDIT_EVIDENCE_TRUSTED_KEY_PROVENANCE_VERIFIED", "Provenance verification returned the wrong status.")
    expect(verified["current_registry_binding"] is True, "Current registry binding was not confirmed.")

    tampered = json.loads(json.dumps(attested["evidence"]))
    tampered["attestation"]["key_source"] = "https://attacker.invalid/jwks"
    tampered_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_trusted_key_provenance(
        tampered, registry, expected_issuer=issuer, expected_key_id="audit-provenance-key"
    )
    expect(tampered_result["success"] is False, "Tampered key provenance was accepted.")
    expect(tampered_result["reason"] in {"registry_provenance_mismatch", "signature_verification_failed"}, "Tampered provenance returned an unexpected reason.")

    changed_registry = registry.register_key(
        "audit-provenance-key-2",
        Ed25519PrivateKey.generate().public_key(),
        status=IDENTITY_KEY_STATUS_ACTIVE,
        source=metadata["source"],
        version="8",
    )
    expect(changed_registry["registry_revision"] > metadata["registry_revision"], "Registry revision did not advance after trust-state change.")
    changed_result = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_trusted_key_provenance(
        attested["evidence"], registry, expected_issuer=issuer, expected_key_id="audit-provenance-key"
    )
    expect(changed_result["success"] is False, "Historical provenance unexpectedly remained current after registry mutation.")
    expect(changed_result["reason"] == "registry_provenance_mismatch", "Registry mutation returned the wrong provenance failure reason.")

    historical = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_trusted_key_provenance(
        attested["evidence"], registry, expected_issuer=issuer, expected_key_id="audit-provenance-key", require_current_registry_binding=False
    )
    expect(historical["success"] is True, f"Historical provenance verification failed: {historical}")
    expect(historical["current_registry_binding"] is False, "Historical verification incorrectly claimed current binding.")

    wrong_private = Ed25519PrivateKey.generate()
    wrong_key_result = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(
        exported["evidence"], wrong_private, registry, key_id="audit-provenance-key", issuer=issuer
    )
    expect(wrong_key_result["success"] is False, "A private key that does not match the registry key was accepted.")

    print("PASS: audit evidence records cryptographic trusted-key provenance")
    print("PASS: registry revision and key-set fingerprint are bound to the attestation")
    print("PASS: current registry mutation is detected while historical provenance remains verifiable")
    print("PASS: mismatched signing keys and tampered provenance fail closed")

def test_oidc_trust_state_journal_compaction_concurrency(tmp_dir):
    import multiprocessing

    issuer = "https://issuer.test/journal-concurrency"
    state_path = os.path.join(tmp_dir, "memory_oidc_journal_compaction_concurrency_state.json")
    source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 8400.0,
    )
    source._state_revision = 1
    source._state_fingerprint = "preloaded-concurrency-fingerprint"
    source._persisted_state_fingerprint = "preloaded-concurrency-fingerprint"

    for index in range(1, 7):
        source._append_trust_state_journal("COMPACTION_CONCURRENCY_SEED", {"index": index})

    worker_context = multiprocessing.get_context("spawn")
    compactor = worker_context.Process(target=_journal_compaction_worker, args=(state_path,))
    writers = []
    for worker_id in range(1, 9):
        writers.append(worker_context.Process(target=_journal_concurrency_worker, args=(state_path, worker_id)))

    compactor.start()
    for worker in writers:
        worker.start()

    compactor.join(20)
    expect(not compactor.is_alive(), "Compaction worker did not terminate.")
    expect(compactor.exitcode == 0, f"Compaction worker failed: exit={compactor.exitcode}")

    for worker in writers:
        worker.join(20)
        expect(not worker.is_alive(), "Concurrent journal writer did not terminate.")
        expect(worker.exitcode == 0, f"Concurrent journal writer failed: exit={worker.exitcode}")

    verification = source.verify_trust_state_journal()
    expect(verification["valid"] is True, f"Concurrent compaction corrupted journal integrity: {verification}")
    expect(verification["coverage_end_sequence"] == 14, "Concurrent compaction changed sequence coverage.")

    checkpoint = source.get_trust_state_journal_checkpoint()
    expect(isinstance(checkpoint, dict), "Concurrent compaction never produced a checkpoint.")
    expect(checkpoint["sequence"] < verification["coverage_end_sequence"], "Checkpoint does not precede the retained tail.")

    records = source.get_trust_state_journal(limit=20)
    expected_start = checkpoint["sequence"] + 1
    expect([item["sequence"] for item in records] == list(range(expected_start, 15)), "Concurrent compaction produced sequence gaps or overwrites.")

    print("PASS: compaction and concurrent journal writers serialize safely")
    print("PASS: compaction preserves complete sequence coverage")
    print("PASS: concurrent compaction preserves hash-chain integrity")

def test_approval_requirement_changes_policy_fingerprint(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        single_policy = evaluate_repair_policy(inspect_reconciliation(tmp_dir))
        single_fingerprint = single_policy["policy_fingerprint"]

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
        }
        multi_policy = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(multi_policy["approval_requirement"]["required_count"] == 2, "Multi-approval quorum was not reflected in policy evaluation.")
        expect(multi_policy["approval_requirement"]["distinct_actors"] is True, "Distinct-actor policy was not reflected in policy evaluation.")
        expect(multi_policy["policy_fingerprint"] != single_fingerprint, "Changing approval policy did not change policy fingerprint.")

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
            "allowed_roles": ["reviewer", "security"],
            "required_roles": ["reviewer", "security"],
            "allow_delegation": True,
            "require_delegation_reference": True,
        }
        role_policy = evaluate_repair_policy(inspect_reconciliation(tmp_dir))
        expect(role_policy["approval_requirement"]["allowed_roles"] == ["reviewer", "security"], "Allowed roles were not reflected in policy evaluation.")
        expect(role_policy["approval_requirement"]["required_roles"] == ["reviewer", "security"], "Required roles were not reflected in policy evaluation.")
        expect(role_policy["approval_requirement"]["allow_delegation"] is True, "Delegation permission was not reflected in policy evaluation.")
        expect(role_policy["approval_requirement"]["require_delegation_reference"] is True, "Delegation-reference requirement was not reflected in policy evaluation.")
        expect(role_policy["policy_fingerprint"] != multi_policy["policy_fingerprint"], "Role/delegation policy changes did not alter policy fingerprint.")

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
            "allowed_roles": ["reviewer", "security"],
            "required_roles": ["reviewer", "security"],
            "allow_delegation": True,
            "require_delegation_reference": True,
            "prohibit_requester_approval": True,
            "prohibit_requester_role_approval": True,
        }
        sod_policy = evaluate_repair_policy(inspect_reconciliation(tmp_dir))
        expect(sod_policy["approval_requirement"]["require_requester_context"] is True, "SoD policy did not imply requester-context enforcement.")
        expect(sod_policy["approval_requirement"]["prohibit_requester_approval"] is True, "Requester self-approval constraint was not reflected in policy.")
        expect(sod_policy["approval_requirement"]["prohibit_requester_role_approval"] is True, "Requester-role separation constraint was not reflected in policy.")
        expect(sod_policy["policy_fingerprint"] != role_policy["policy_fingerprint"], "Separation-of-duties policy changes did not alter policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)



def test_separation_of_duties_blocks_requester_self_approval(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "prohibit_requester_approval": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="requester self-approval test",
            reference="SOD-SELF",
            requester_actor="alice",
            requester_role="operator",
            requester_reference="REQ-001",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")
        expect(prepared["approval"]["requester_actor"] == "alice", "Requester actor was not bound to the approval.")
        expect(prepared["approval"]["requester_reference"] == "REQ-001", "Requester reference was not bound to the approval.")

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Requester self-approval was accepted: {result}")
        expect(result["executed"] is False, "Requester self-approval executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_REQUESTER_APPROVAL_FORBIDDEN" in blocked_codes, "Missing requester self-approval violation.")
        expect(_project_digest(tmp_dir) == before, "Rejected self-approval changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_separation_of_duties_blocks_requester_role_approval(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["operator", "security"],
            "prohibit_requester_role_approval": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="bob",
            role="operator",
            reason="requester role separation test",
            reference="SOD-ROLE",
            requester_actor="alice",
            requester_role="operator",
            requester_reference="REQ-002",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Requester role approval was accepted: {result}")
        expect(result["executed"] is False, "Requester-role approval executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_REQUESTER_ROLE_FORBIDDEN" in blocked_codes, "Missing requester-role separation violation.")
        expect(_project_digest(tmp_dir) == before, "Rejected requester-role approval changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_separation_of_duties_requires_requester_context(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_requester_context": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="bob",
            role="security",
            reason="missing requester context test",
            reference="SOD-CONTEXT",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Approval preparation failed: {prepared}")

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Missing requester context was accepted: {result}")
        expect(result["executed"] is False, "Missing requester context executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_REQUESTER_REQUIRED" in blocked_codes, "Missing requester-context violation.")
        expect(_project_digest(tmp_dir) == before, "Rejected approval without requester context changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_separation_of_duties_allows_independent_approvers(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 2,
            "distinct_actors": True,
            "allowed_roles": ["reviewer", "security"],
            "required_roles": ["reviewer", "security"],
            "prohibit_requester_approval": True,
            "prohibit_requester_role_approval": True,
        }

        prepared = prepare_repair_approvals(
            tmp_dir,
            approvers=[
                {
                    "actor": "bob",
                    "role": "reviewer",
                    "reason": "independent review",
                    "reference": "SOD-A",
                },
                {
                    "actor": "carol",
                    "role": "security",
                    "reason": "independent security review",
                    "reference": "SOD-B",
                },
            ],
            requester_actor="alice",
            requester_role="operator",
            requester_reference="REQ-003",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Independent SoD preparation failed: {prepared}")
        expect(
            {item["requester_actor"] for item in prepared["approvals"]} == {"alice"},
            "Requester context was not propagated to every approval.",
        )

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval_context"],
        )
        expect(result["status"] == "REPAIRED", f"Independent approvals were incorrectly blocked: {result}")
        expect(result["executed"] is True, "Independent approvals did not execute the repair.")
        expect(result["approval"]["requester_actor"] == "alice", "Requester actor was lost from the aggregate approval trace.")
        expect(
            {item["requester_role"] for item in result["approval"]["approvals"]} == {"operator"},
            "Requester role was not retained for all approval records.",
        )
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_requester_delegation_is_blocked_by_separation_of_duties(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["manager"],
            "allow_delegation": True,
            "require_delegation_reference": True,
            "prohibit_requester_approval": True,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="bob",
            role="manager",
            reason="delegation separation test",
            reference="SOD-DELEGATION",
            delegated_by="alice",
            delegation_reason="requester attempted to delegate approval",
            delegation_reference="DEL-SOD-001",
            requester_actor="alice",
            requester_role="operator",
            requester_reference="REQ-004",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Delegation test preparation failed: {prepared}")

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Requester delegation was accepted: {result}")
        expect(result["executed"] is False, "Requester delegation executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_REQUESTER_DELEGATION_FORBIDDEN" in blocked_codes, "Missing requester-delegation SoD violation.")
        expect(_project_digest(tmp_dir) == before, "Rejected requester delegation changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)




def test_authoritative_identity_requires_provider(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="identity provider required",
            reference="IDP-REQUIRED",
            ttl_seconds=900,
        )
        expect(prepared["status"] == "APPROVAL_INVALID", f"Missing identity provider was accepted during preparation: {prepared}")
        expect(
            "APPROVAL_IDENTITY_PROVIDER_REQUIRED" in prepared["identity_validation"]["codes"],
            "Missing identity-provider violation was not reported.",
        )
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_authoritative_identity_verification_and_trace(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = FakeAuthoritativeIdentityProvider({
        "alice": {"subject": "sub-alice", "roles": ["security", "reviewer"], "active": True},
    })

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="authoritative identity test",
            reference="IDP-VALID",
            ttl_seconds=900,
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Authoritative identity preparation failed: {prepared}")
        expect(prepared["approval"]["identity_provider"] == "TEST-IDP", "Provider name was not traced.")
        expect(prepared["approval"]["identity_subject"] == "sub-alice", "Identity subject was not traced.")
        expect(set(prepared["approval"]["identity_roles"]) == {"security", "reviewer"}, "Authoritative roles were not traced.")
        expect(len(prepared["approval"]["identity_fingerprint"]) == 64, "Identity fingerprint is not SHA256-sized.")
        expect(provider.calls, "Identity provider was not called during approval preparation.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=provider,
        )
        expect(result["status"] == "REPAIRED", f"Authoritatively verified approval did not execute: {result}")
        expect(result["executed"] is True, "Authoritatively verified approval did not execute.")
        expect(result["approval"]["identity_subject"] == "sub-alice", "Identity subject was lost in reconciliation trace.")
        expect(result["approval"]["identity_fingerprint"] == prepared["approval"]["identity_fingerprint"], "Identity fingerprint changed unexpectedly.")
        history = get_reconciliation_history(tmp_dir)
        expect(history[0]["approval"]["identity_provider"] == "TEST-IDP", "History lost authoritative identity provider metadata.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_authoritative_identity_rejects_forged_or_changed_role(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = FakeAuthoritativeIdentityProvider({
        "alice": {"subject": "sub-alice", "roles": ["security"], "active": True},
    })

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="identity role change test",
            reference="IDP-ROLE-CHANGE",
            ttl_seconds=900,
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Preparation failed: {prepared}")

        provider.records["alice"]["roles"] = ["reviewer"]
        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=provider,
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Changed authoritative role was accepted: {result}")
        expect(result["executed"] is False, "Changed authoritative role executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect(
            "APPROVAL_IDENTITY_NOT_VERIFIED" in blocked_codes
            or "APPROVAL_IDENTITY_ROLE_MISMATCH" in blocked_codes,
            f"Unexpected identity-role rejection codes: {blocked_codes}",
        )
        expect(_project_digest(tmp_dir) == before, "Rejected identity change mutated project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_authoritative_identity_provider_policy_is_traceable(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP-A",
        }
        first = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP-B",
        }
        second = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(first["approval_requirement"]["require_authoritative_identity"] is True, "Authoritative identity requirement was not exposed.")
        expect(first["approval_requirement"]["identity_provider"] == "TEST-IDP-A", "Identity-provider policy was not exposed.")
        expect(second["approval_requirement"]["identity_provider"] == "TEST-IDP-B", "Updated identity-provider policy was not exposed.")
        expect(second["policy_fingerprint"] != first["policy_fingerprint"], "Changing identity-provider policy did not change policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)



def test_attestation_nonce_issuer_audience_binding(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)
    provider = CryptographicFakeIdentityProvider(
        {
            "alice": {
                "subject": "sub-alice",
                "roles": ["security"],
                "active": True,
                "revoked": False,
                "issuer": "https://issuer.test",
                "audience": "reconciliation-service",
                "attestation_id": "att-binding-1",
            }
        },
        Ed25519PrivateKey.generate(),
        key_id="binding-key-1",
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "require_cryptographic_attestation": True,
            "require_attestation_nonce": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "binding-key-1",
            "attestation_issuer": "https://issuer.test",
            "attestation_audience": "reconciliation-service",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="nonce binding test",
            reference="BINDING-1",
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Bound attestation preparation failed: {prepared}")
        approval = prepared["approval"]
        expect(approval["identity_attestation_nonce"], "Attestation nonce was not generated.")
        expect(approval["identity_attestation_issuer"] == "https://issuer.test", "Issuer binding was not traced.")
        expect(approval["identity_attestation_audience"] == "reconciliation-service", "Audience binding was not traced.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=approval,
            identity_provider=provider,
        )
        expect(result["status"] == "REPAIRED", f"Bound attestation repair failed: {result}")
        expect(result["executed"] is True, "Bound attestation repair did not execute.")

    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_replayed_attestation_nonce_is_rejected(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)
    provider = CryptographicFakeIdentityProvider(
        {
            "alice": {
                "subject": "sub-alice",
                "roles": ["security"],
                "active": True,
                "issuer": "https://issuer.test",
                "audience": "reconciliation-service",
                "attestation_id": "att-replay-1",
            }
        },
        Ed25519PrivateKey.generate(),
        key_id="replay-key-1",
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_attestation_nonce": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "replay-key-1",
            "attestation_issuer": "https://issuer.test",
            "attestation_audience": "reconciliation-service",
        }

        first = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="first attestation",
            reference="REPLAY-1",
            identity_provider=provider,
        )
        expect(first["status"] == "APPROVAL_READY", f"Initial bound approval failed: {first}")
        old_approval = first["approval"]

        # Simulate a provider returning a previously captured signed attestation
        # regardless of the fresh nonce requested by the new approval.
        captured = dict(provider.records["alice"])
        captured_nonce = old_approval["identity_attestation_nonce"]

        class ReplayProvider(CryptographicFakeIdentityProvider):
            def verify(self, actor, claimed_role="", reference="", attestation_nonce="", expected_issuer="", expected_audience=""):
                raw = super().verify(actor, claimed_role, reference, attestation_nonce=captured_nonce, expected_issuer=expected_issuer, expected_audience=expected_audience)
                raw["attestation_nonce"] = captured_nonce
                raw_for_signing = dict(raw)
                raw_for_signing["attestation_signature"] = ""
                raw["attestation_signature"] = sign_identity_attestation_ed25519(self.private_key, raw_for_signing)
                return raw

        replay_provider = ReplayProvider(provider.records, provider.private_key, key_id="replay-key-1")
        second = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="second fresh approval",
            reference="REPLAY-2",
            identity_provider=replay_provider,
        )
        expect(second["status"] == "APPROVAL_INVALID", f"Replay provider unexpectedly produced a valid approval: {second}")
        expect(
            "APPROVAL_IDENTITY_ATTESTATION_NONCE_MISMATCH" in second["identity_validation"]["codes"],
            f"Missing nonce replay protection code: {second}",
        )

    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_attestation_scope_change_invalidates_policy(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_attestation_nonce": True,
            "identity_provider": "TEST-IDP",
            "attestation_issuer": "https://issuer.test",
            "attestation_audience": "reconciliation-service",
        }
        first = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_attestation_nonce": True,
            "identity_provider": "TEST-IDP",
            "attestation_issuer": "https://issuer.changed",
            "attestation_audience": "reconciliation-service",
        }
        second = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(first["approval_requirement"]["require_attestation_nonce"] is True, "Nonce requirement was not retained.")
        expect(second["approval_requirement"]["attestation_issuer"] == "https://issuer.changed", "Issuer change was not reflected in policy.")
        expect(second["policy_fingerprint"] != first["policy_fingerprint"], "Issuer change did not invalidate the policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)

def test_cryptographic_attestation_verification(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    private_key = Ed25519PrivateKey.generate()
    provider = CryptographicFakeIdentityProvider(
        {
            "alice": {
                "subject": "sub-alice",
                "roles": ["security"],
                "active": True,
                "verified_at": "2026-09-24T10:00:00+00:00",
                "valid_until": "2099-01-01T00:00:00+00:00",
                "attestation_id": "att-crypto-1",
            }
        },
        private_key,
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "test-key-1",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="cryptographic attestation test",
            reference="CRYPTO-VALID",
            ttl_seconds=900,
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Cryptographic preparation failed: {prepared}")
        approval = prepared["approval"]
        expect(approval["identity_signature_algorithm"] == IDENTITY_ATTESTATION_ALGORITHM_ED25519, "Signature algorithm was not traced.")
        expect(approval["identity_signature_key_id"] == "test-key-1", "Signature key id was not traced.")
        expect(approval["identity_cryptographic_attestation_verified"] is True, "Cryptographic verification flag was not traced.")
        expect(approval["identity_attestation_signature"], "Attestation signature was not retained.")
        expect(len(approval["identity_attestation_signature_fingerprint"]) == 64, "Signature fingerprint is not SHA256-sized.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=approval,
            identity_provider=provider,
        )
        expect(result["status"] == "REPAIRED", f"Cryptographically verified repair failed: {result}")
        expect(result["executed"] is True, "Cryptographically verified repair did not execute.")
        expect(result["approval"]["identity_cryptographic_attestation_verified"] is True, "Cryptographic verification was lost in audit trace.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_cryptographic_attestation_rejects_tampered_signature(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    private_key = Ed25519PrivateKey.generate()
    provider = CryptographicFakeIdentityProvider(
        {"alice": {"subject": "sub-alice", "roles": ["security"], "active": True}},
        private_key,
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "test-key-1",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="tampered signature test",
            reference="CRYPTO-TAMPER",
            ttl_seconds=900,
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Preparation failed: {prepared}")

        original_verify = provider.verify

        def tampered_verify(actor, claimed_role="", reference=""):
            response = original_verify(actor, claimed_role, reference)
            response["attestation_signature"] = response["attestation_signature"][:-2] + "AA"
            return response

        provider.verify = tampered_verify
        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=provider,
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Tampered signature was accepted: {result}")
        expect(result["executed"] is False, "Tampered signature executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect("APPROVAL_IDENTITY_SIGNATURE_INVALID" in blocked_codes, f"Missing cryptographic signature violation: {blocked_codes}")
        expect(_project_digest(tmp_dir) == before, "Rejected tampered attestation changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_cryptographic_attestation_key_rotation_invalidates_old_approval(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    first_private = Ed25519PrivateKey.generate()
    second_private = Ed25519PrivateKey.generate()
    provider = CryptographicFakeIdentityProvider(
        {"alice": {"subject": "sub-alice", "roles": ["security"], "active": True}},
        first_private,
        key_id="test-key-1",
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "test-key-1",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="key rotation test",
            reference="CRYPTO-ROTATION",
            ttl_seconds=900,
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Preparation failed: {prepared}")

        provider.private_key = second_private
        provider.public_key = second_private.public_key()
        provider.key_id = "test-key-2"

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=provider,
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Old approval survived key rotation: {result}")
        expect(result["executed"] is False, "Old cryptographic approval executed after key rotation.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect(
            "APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISMATCH" in blocked_codes
            or "APPROVAL_IDENTITY_SIGNATURE_MISMATCH" in blocked_codes,
            f"Unexpected key-rotation rejection: {blocked_codes}",
        )
        expect(_project_digest(tmp_dir) == before, "Rejected key rotation changed project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_trusted_attestation_key_lifecycle_and_revocation(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    provider = CryptographicFakeIdentityProvider(
        {"alice": {"subject": "sub-alice", "roles": ["security"], "active": True}},
        Ed25519PrivateKey.generate(),
        key_id="trusted-key-1",
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "allowed_roles": ["security"],
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_trusted_attestation_key": True,
            "attestation_key_statuses": [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "trusted-key-1",
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="trusted key lifecycle test",
            reference="TRUSTED-KEY-1",
            identity_provider=provider,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"Trusted-key approval preparation failed: {prepared}")
        approval = prepared["approval"]
        expect(approval["identity_signature_key_status"] == IDENTITY_KEY_STATUS_ACTIVE, "Key status was not traced.")
        expect(len(approval["identity_signature_key_fingerprint"]) == 64, "Key fingerprint was not traced.")

        provider.key_status = IDENTITY_KEY_STATUS_REVOKED
        provider.key_registry.set_status(provider.key_id, IDENTITY_KEY_STATUS_REVOKED)

        before = _project_digest(tmp_dir)
        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=approval,
            identity_provider=provider,
        )
        expect(result["status"] == "APPROVAL_INVALID", f"Revoked attestation key was accepted: {result}")
        expect(result["executed"] is False, "Revoked attestation key executed a repair.")
        blocked_codes = {item.get("code") for item in result["blocked"]}
        expect(
            "APPROVAL_IDENTITY_SIGNATURE_KEY_REVOKED" in blocked_codes
            or "APPROVAL_IDENTITY_SIGNATURE_KEY_STATUS_NOT_ALLOWED" in blocked_codes,
            f"Missing revoked-key violation: {blocked_codes}",
        )
        expect(_project_digest(tmp_dir) == before, "Revoked-key rejection mutated project state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_trusted_attestation_key_policy_changes_fingerprint(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_trusted_attestation_key": True,
            "attestation_key_statuses": [IDENTITY_KEY_STATUS_ACTIVE],
            "attestation_key_fingerprint": "a" * 64,
            "identity_provider": "TEST-IDP",
        }
        first = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "require_trusted_attestation_key": True,
            "attestation_key_statuses": [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
            "attestation_key_fingerprint": "b" * 64,
            "identity_provider": "TEST-IDP",
        }
        second = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(first["approval_requirement"]["require_trusted_attestation_key"] is True, "Trusted-key policy was not exposed.")
        expect(second["approval_requirement"]["attestation_key_statuses"] == [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE], "Key-status policy was not exposed.")
        expect(second["policy_fingerprint"] != first["policy_fingerprint"], "Trusted-key policy change did not alter policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)



def test_oidc_jwt_compatible_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    registry = TrustedAttestationKeyRegistry()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "oidc-key-1",
                    version="1",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source="https://issuer.test/.well-known/jwks.json",
    )

    issuer = "https://issuer.test"
    audience = "memory-api"
    now = int(time.time())

    def encode(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

    def make_token(header=None, claims=None, signing_key=None):
        current_header = {
            "alg": IDENTITY_JWT_ALGORITHM_EDDSA,
            "kid": "oidc-key-1",
            "typ": "JWT",
        }
        current_claims = {
            "iss": issuer,
            "sub": "sub-alice",
            "aud": audience,
            "actor": "alice",
            "roles": ["security", "operator"],
            "nonce": "nonce-001",
            "iat": now,
            "exp": now + 300,
            "jti": "jwt-001",
        }
        if header:
            current_header.update(header)
        if claims:
            current_claims.update(claims)

        encoded_header = encode(current_header)
        encoded_claims = encode(current_claims)
        signing_input = (encoded_header + "." + encoded_claims).encode("ascii")
        signer = signing_key or private_key
        signature = signer.sign(signing_input)
        encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return encoded_header + "." + encoded_claims + "." + encoded_signature

    adapter = OIDCJWTAttestationAdapter(
        registry,
        issuer=issuer,
        audience=audience,
        expected_key_statuses=[IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
        require_nonce=True,
    )

    valid = adapter.verify_token(
        make_token(),
        actor="alice",
        claimed_role="security",
        nonce="nonce-001",
    )
    expect(valid["verified"] is True, f"Valid OIDC JWT was rejected: {valid}")
    expect(valid["provider"] == issuer, "OIDC issuer was not mapped to provider.")
    expect(valid["subject"] == "sub-alice", "OIDC subject was not preserved.")
    expect(valid["actor"] == "alice", "JWT actor claim was not preserved.")
    expect(valid["roles"] == ["operator", "security"], "JWT roles were not normalized.")
    expect(valid["signature_algorithm"] == IDENTITY_ATTESTATION_ALGORITHM_ED25519, "EdDSA was not mapped to internal Ed25519.")
    expect(valid["signature_key_id"] == "oidc-key-1", "JWT kid was not traced.")
    expect(valid["signature_key_status"] == IDENTITY_KEY_STATUS_ACTIVE, "Trusted key status was not traced.")
    expect(len(valid["signature_key_fingerprint"]) == 64, "JWT key fingerprint was not traced.")
    expect(valid["cryptographic_attestation_verified"] is True, "JWT cryptographic verification was not marked complete.")
    expect(valid["attestation_id"] == "jwt-001", "JWT jti was not used as attestation id.")

    wrong_issuer = adapter.verify_token(
        make_token(claims={"iss": "https://evil.test"}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(wrong_issuer["codes"] == ["IDENTITY_JWT_ISSUER_MISMATCH"], f"Wrong issuer was not rejected precisely: {wrong_issuer}")

    wrong_audience = adapter.verify_token(
        make_token(claims={"aud": "other-api"}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(wrong_audience["codes"] == ["IDENTITY_JWT_AUDIENCE_MISMATCH"], f"Wrong audience was not rejected precisely: {wrong_audience}")

    expired = adapter.verify_token(
        make_token(claims={"exp": now - 120}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(expired["codes"] == ["IDENTITY_JWT_EXPIRED"], f"Expired JWT was not rejected: {expired}")

    not_yet_valid = adapter.verify_token(
        make_token(claims={"nbf": now + 120}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(not_yet_valid["codes"] == ["IDENTITY_JWT_NOT_YET_VALID"], f"Future nbf was not rejected: {not_yet_valid}")

    bad_nonce = adapter.verify_token(
        make_token(),
        actor="alice",
        nonce="wrong-nonce",
    )
    expect(bad_nonce["codes"] == ["IDENTITY_JWT_NONCE_MISMATCH"], f"Nonce mismatch was not rejected: {bad_nonce}")

    unknown_key = adapter.verify_token(
        make_token(header={"kid": "missing-key"}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(unknown_key["codes"] == ["IDENTITY_JWT_KEY_NOT_FOUND"], f"Unknown JWT kid was not rejected: {unknown_key}")

    revoked = adapter.verify_token(
        make_token(),
        actor="alice",
        nonce="nonce-001",
    )
    registry.set_status("oidc-key-1", IDENTITY_KEY_STATUS_REVOKED)
    revoked = adapter.verify_token(
        make_token(),
        actor="alice",
        nonce="nonce-001",
    )
    expect(revoked["codes"] == ["IDENTITY_JWT_KEY_REVOKED"], f"Revoked signing key was not rejected: {revoked}")
    registry.set_status("oidc-key-1", IDENTITY_KEY_STATUS_ACTIVE)

    bad_signature_key = Ed25519PrivateKey.generate()
    bad_signature = adapter.verify_token(
        make_token(signing_key=bad_signature_key),
        actor="alice",
        nonce="nonce-001",
    )
    expect(bad_signature["codes"] == ["IDENTITY_JWT_SIGNATURE_INVALID"], f"Invalid JWT signature was not rejected: {bad_signature}")

    unsupported_algorithm = adapter.verify_token(
        make_token(header={"alg": "none"}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(unsupported_algorithm["codes"] == ["IDENTITY_JWT_ALGORITHM_UNSUPPORTED"], f"Unsupported JWT algorithm was not rejected: {unsupported_algorithm}")

    multi_audience = adapter.verify_token(
        make_token(claims={"aud": [audience, "other-api"], "azp": audience}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(multi_audience["verified"] is True, f"Valid multi-audience OIDC JWT was rejected: {multi_audience}")

    missing_azp = adapter.verify_token(
        make_token(claims={"aud": [audience, "other-api"]}),
        actor="alice",
        nonce="nonce-001",
    )
    expect(missing_azp["codes"] == ["IDENTITY_JWT_AZP_MISMATCH"], f"Missing azp was not rejected: {missing_azp}")


def test_oidc_discovery_and_automatic_jwks_refresh(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/tenant1"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url_1 = "https://keys.issuer.test/tenant1/jwks.json"
    jwks_url_2 = "https://keys.issuer.test/tenant1/jwks-v2.json"

    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    calls = []
    clock = [1000.0]

    discovery_v1 = {
        "issuer": issuer,
        "jwks_uri": jwks_url_1,
    }
    discovery_v2 = {
        "issuer": issuer,
        "jwks_uri": jwks_url_2,
    }
    jwks_v1 = {
        "keys": [
            public_key_to_jwk(
                old_private.public_key(),
                "auto-old",
                version="1",
                status=IDENTITY_KEY_STATUS_ACTIVE,
            )
        ]
    }
    jwks_v2 = {
        "keys": [
            public_key_to_jwk(
                new_private.public_key(),
                "auto-new",
                version="2",
                status=IDENTITY_KEY_STATUS_ACTIVE,
            )
        ]
    }

    documents = {
        discovery_url: discovery_v1,
        jwks_url_1: jwks_v1,
        jwks_url_2: jwks_v2,
    }

    def fetch_json(url, timeout_seconds):
        calls.append((url, timeout_seconds))
        value = documents.get(url)
        if value is None:
            raise ValueError("unexpected URL")
        return json.loads(json.dumps(value))

    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        cache_ttl_seconds=10,
        timeout_seconds=2,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
        retire_missing=True,
    )

    first = source.refresh()
    expect(first["success"] is True, f"Initial OIDC discovery failed: {first}")
    expect(first["status"] == "REFRESHED", f"Initial refresh status was unexpected: {first}")
    expect(first["discovered"] == 1, f"Initial JWKS key was not discovered: {first}")
    expect(calls == [(discovery_url, 2.0), (jwks_url_1, 2.0)], f"Discovery/JWKS request sequence was wrong: {calls}")
    expect(source.discovery_url == discovery_url, "Issuer path was not used correctly for OIDC discovery URL.")
    expect(source.is_cache_valid() is True, "Fresh discovery cache was not marked valid.")

    cached_key = source.get_verification_key("auto-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519)
    expect(cached_key is not None, "Cached JWKS key was not retrievable.")
    expect(len(calls) == 2, "Valid discovery cache triggered an unnecessary network refresh.")

    cached = source.ensure_fresh()
    expect(cached["status"] == "CACHED", f"Fresh cache did not return CACHED status: {cached}")
    expect(len(calls) == 2, "Cached ensure_fresh performed an unnecessary request.")

    documents[discovery_url] = discovery_v2
    clock[0] = 1011.0

    rotated = source.ensure_fresh()
    expect(rotated["success"] is True, f"Automatic OIDC/JWKS rotation failed: {rotated}")
    expect(rotated["status"] == "REFRESHED", f"Expired cache did not refresh: {rotated}")
    expect(len(calls) == 4, f"Rotation did not perform discovery + new JWKS fetch: {calls}")
    expect(source.get_verification_key("auto-new", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "New rotated key was not trusted after refresh.")
    expect(
        source.get_verification_key_metadata("auto-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519)["status"] == IDENTITY_KEY_STATUS_RETIRED,
        "Old missing key was not safely retired after authoritative rotation.",
    )

    adapter = OIDCJWTAttestationAdapter(
        source,
        issuer=issuer,
        audience="memory-api",
        expected_key_statuses=[IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
        require_nonce=True,
    )
    now = int(time.time())

    def encode(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

    def make_token(signing_key, key_id, nonce="auto-nonce"):
        header = {
            "alg": IDENTITY_JWT_ALGORITHM_EDDSA,
            "kid": key_id,
            "typ": "JWT",
        }
        claims = {
            "iss": issuer,
            "sub": "sub-auto",
            "aud": "memory-api",
            "actor": "alice",
            "roles": ["security"],
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
            "jti": "auto-jwt-001",
        }
        encoded_header = encode(header)
        encoded_claims = encode(claims)
        signing_input = (encoded_header + "." + encoded_claims).encode("ascii")
        signature = signing_key.sign(signing_input)
        encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return encoded_header + "." + encoded_claims + "." + encoded_signature

    new_token = make_token(new_private, "auto-new")
    verified = adapter.verify_token(new_token, actor="alice", claimed_role="security", nonce="auto-nonce")
    expect(verified["verified"] is True, f"JWT signed by automatically discovered rotated key was rejected: {verified}")
    expect(verified["signature_key_id"] == "auto-new", "Automatically rotated key id was not traced.")

    bad_documents = {
        discovery_url: {"issuer": "https://attacker.test", "jwks_uri": jwks_url_1},
        jwks_url_1: jwks_v1,
    }

    def bad_fetch_json(url, timeout_seconds):
        value = bad_documents.get(url)
        if value is None:
            raise ValueError("unexpected URL")
        return json.loads(json.dumps(value))

    bad_source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        cache_ttl_seconds=10,
        fetch_json=bad_fetch_json,
        now_fn=lambda: 2000.0,
    )
    failed = bad_source.refresh()
    expect(failed["success"] is False, "Issuer-mismatched discovery document was accepted.")
    expect(failed["fail_closed"] is True, "Failed OIDC discovery did not fail closed.")
    expect("issuer" in failed["error"].lower(), f"Discovery issuer mismatch was not surfaced: {failed}")

    expired_source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        cache_ttl_seconds=1,
        fetch_json=lambda url, timeout_seconds: (_ for _ in ()).throw(RuntimeError("network unavailable")),
        now_fn=lambda: 5000.0,
    )
    expired_source._discovery_document = {"issuer": issuer, "jwks_uri": jwks_url_1}
    expired_source._jwks_uri = jwks_url_1
    expired_source._last_success_at = 4990.0
    expired_source._cache_expires_at = 4991.0

    fail_closed_adapter = OIDCJWTAttestationAdapter(
        expired_source,
        issuer=issuer,
        audience="memory-api",
        require_nonce=True,
    )
    fail_closed = fail_closed_adapter.verify_token(
        new_token,
        actor="alice",
        claimed_role="security",
        nonce="auto-nonce",
    )
    expect(
        fail_closed["codes"] == ["IDENTITY_JWKS_REFRESH_FAILED"],
        f"Expired automatic JWKS cache did not fail closed: {fail_closed}",
    )

def test_oidc_persisted_trust_state_restart_and_recovery(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/persistent"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/persistent/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_trust_state.json")
    private_key = Ed25519PrivateKey.generate()
    jwks = {
        "keys": [
            public_key_to_jwk(
                private_key.public_key(),
                "persistent-key",
                version="1",
                status=IDENTITY_KEY_STATUS_ACTIVE,
            )
        ]
    }
    documents = {
        discovery_url: {"issuer": issuer, "jwks_uri": jwks_url},
        jwks_url: jwks,
    }
    clock = [1000.0]
    calls = []

    def fetch_json(url, timeout_seconds, request_headers=None):
        calls.append((url, dict(request_headers or {})))
        return json.loads(json.dumps(documents[url])), {
            "status": 200,
            "cache-control": "max-age=30",
            "etag": '"v1"',
        }

    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        cache_ttl_seconds=30,
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    first = source.refresh()
    expect(first["success"] is True, f"Initial persistent OIDC refresh failed: {first}")
    expect(os.path.exists(state_path), "Persistent OIDC trust state was not written.")
    expect(registry.get_verification_key("persistent-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Initial trusted key missing.")

    restarted_registry = TrustedAttestationKeyRegistry()
    restarted = OIDCDiscoveryJWKSSource(
        issuer,
        restarted_registry,
        cache_ttl_seconds=30,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network should not be used while cache is valid")),
        now_fn=lambda: clock[0] + 5,
    )
    expect(restarted.is_cache_valid() is True, "Valid persisted OIDC cache was not restored after restart.")
    expect(restarted.get_verification_key("persistent-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Persisted trusted key was not restored after restart.")
    expect(restarted.ensure_fresh()["status"] == "CACHED", "Restarted source did not use the persisted valid cache.")

    clock[0] = 1035.0
    expired = restarted.ensure_fresh()
    expect(expired["success"] is False, "Expired persisted OIDC cache did not fail closed when network was unavailable.")
    expect(expired["fail_closed"] is True, "Expired persisted OIDC cache was not fail-closed.")
    expect(restarted.get_verification_key("persistent-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is None, "Expired persisted cache continued serving a trusted key.")

    # Corrupt primary state: memory_storage must restore the last known-good backup.
    backup_path = state_path + ".bak"
    expect(os.path.exists(backup_path), "Persistent OIDC backup was not created.")
    with open(state_path, "w", encoding="utf-8") as file:
        file.write("{corrupt")

    recovered_registry = TrustedAttestationKeyRegistry()
    recovered = OIDCDiscoveryJWKSSource(
        issuer,
        recovered_registry,
        cache_ttl_seconds=30,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network unavailable")),
        now_fn=lambda: 1005.0,
    )
    expect(recovered.is_cache_valid() is True, "Corrupted persisted state was not recovered from the backup.")
    expect(recovered.get_verification_key("persistent-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Backup recovery lost the trusted key.")

    print("PASS: OIDC trust state survives process restart")
    print("PASS: persisted trusted keys survive restart")
    print("PASS: expired persisted cache fails closed")
    print("PASS: corrupted primary trust state recovers from backup")


def test_oidc_distributed_trust_state_consistency(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/distributed"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/distributed/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_distributed_state.json")
    key_v1 = Ed25519PrivateKey.generate()
    key_v2 = Ed25519PrivateKey.generate()
    clock = [1000.0]
    current_jwks = {"keys": [public_key_to_jwk(key_v1.public_key(), "distributed-v1", version="1", status=IDENTITY_KEY_STATUS_ACTIVE)]}
    calls = []

    def fetch_json(url, timeout_seconds, request_headers=None):
        calls.append((url, dict(request_headers or {})))
        if url == discovery_url:
            return {"issuer": issuer, "jwks_uri": jwks_url}, {"status": 200, "cache-control": "max-age=10", "etag": '"d1"'}
        return json.loads(json.dumps(current_jwks)), {"status": 200, "cache-control": "max-age=10", "etag": '"j1"'}

    first = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    refreshed = first.refresh()
    expect(refreshed["success"] is True, f"Initial distributed trust refresh failed: {refreshed}")
    first_revision = first.get_discovery_metadata()["state_revision"]

    second = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    expect(second.is_cache_valid() is True, "Second instance did not load the shared valid trust cache.")
    expect(second.get_verification_key("distributed-v1", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Second instance lost the shared trusted key.")

    # Rotate through instance #1. Instance #2 is intentionally left with its
    # old in-memory state; its next normal refresh must reload durable state
    # while holding the inter-process lock before deciding whether to fetch.
    current_jwks = {"keys": [public_key_to_jwk(key_v2.public_key(), "distributed-v2", version="2", status=IDENTITY_KEY_STATUS_ACTIVE)]}
    clock[0] = 1011.0
    rotated = first.refresh()
    expect(rotated["success"] is True, f"First instance rotation failed: {rotated}")
    expect(first.get_verification_key("distributed-v2", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Rotated key was not trusted by first instance.")
    rotated_revision = first.get_discovery_metadata()["state_revision"]
    expect(rotated_revision > first_revision, "Distributed state revision did not advance after rotation.")

    before_second_calls = len(calls)
    second_result = second.ensure_fresh()
    expect(second_result["success"] is True, f"Second instance failed to converge to rotated state: {second_result}")
    expect(second_result["status"] == "CACHED", "Second instance unnecessarily refreshed after loading newer durable state.")
    expect(second.get_verification_key("distributed-v2", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Second instance did not converge to the rotated trusted key.")
    expect(second.get_discovery_metadata()["state_revision"] == rotated_revision, "Second instance loaded an inconsistent state revision.")
    expect(len(calls) == before_second_calls, "Second instance performed an unnecessary network refresh after convergence.")

    expect(os.path.exists(state_path + ".lock"), "Distributed trust lock file was not created.")
    print("PASS: multiple instances converge on persisted trust state")
    print("PASS: newer rotation state is not overwritten by a stale instance")
    print("PASS: shared state revision provides durable ordering")
    print("PASS: inter-process lock suppresses unnecessary concurrent refresh")

def test_oidc_trust_state_conflict_detection_and_recovery(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from memory_storage import interprocess_lock

    issuer = "https://issuer.test/conflict"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/conflict/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_conflict_state.json")
    key_v1 = Ed25519PrivateKey.generate()
    key_v2 = Ed25519PrivateKey.generate()
    key_v3 = Ed25519PrivateKey.generate()
    current_jwks = {
        "keys": [public_key_to_jwk(key_v1.public_key(), "conflict-v1", version="1", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock = [2000.0]

    def fetch_json(url, timeout_seconds, request_headers=None):
        if url == discovery_url:
            return {"issuer": issuer, "jwks_uri": jwks_url}, {"status": 200, "cache-control": "max-age=10", "etag": '"c1"'}
        return json.loads(json.dumps(current_jwks)), {"status": 200, "cache-control": "max-age=10", "etag": '"k1"'}

    first = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    expect(first.refresh()["success"] is True, "Initial conflict fixture refresh failed.")

    second = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    stale_revision = second.get_discovery_metadata()["state_revision"]

    current_jwks = {
        "keys": [public_key_to_jwk(key_v2.public_key(), "conflict-v2", version="2", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock[0] = 2011.0
    expect(first.refresh()["success"] is True, "First instance rotation failed.")
    durable_revision = first.get_discovery_metadata()["state_revision"]
    expect(durable_revision > stale_revision, "Durable revision did not advance before stale write test.")

    # Give the stale instance a divergent in-memory state. Its persistence
    # attempt must detect the newer durable revision rather than overwrite it.
    second._jwks_uri = "https://keys.issuer.test/conflict/divergent.json"
    second._discovery_document = {"issuer": issuer, "jwks_uri": second._jwks_uri}
    second.registry.refresh_from_jwks(
        {"keys": [public_key_to_jwk(key_v3.public_key(), "conflict-v3", version="3", status=IDENTITY_KEY_STATUS_ACTIVE)]},
        source=second._jwks_uri,
        retire_missing=True,
    )

    conflict = None
    with interprocess_lock(state_path + ".lock", timeout_seconds=5):
        try:
            second._persist_state()
        except OIDCTrustStateConflictError as exc:
            conflict = exc

    expect(conflict is not None, "Stale trust-state writer was not rejected.")
    expect(conflict.actual_revision == durable_revision, "Conflict reported the wrong durable revision.")
    expect(second.get_discovery_metadata()["state_revision"] == durable_revision, "Stale instance did not recover to durable revision.")
    expect(second.get_verification_key("conflict-v2", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Conflict recovery did not restore the authoritative rotated key.")
    expect(second.get_verification_key("conflict-v3", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is None, "Divergent stale key survived conflict recovery.")
    expect(second.get_discovery_metadata()["state_conflict_count"] >= 1, "Conflict counter did not record the detected conflict.")

    with open(state_path, "r", encoding="utf-8") as file:
        durable_state = json.load(file)
    expect(int(durable_state["state_revision"]) == durable_revision, "Stale writer overwrote newer durable state.")
    expect(durable_state.get("state_fingerprint"), "Durable trust state fingerprint was lost after conflict.")

    print("PASS: stale trust-state writer is detected")
    print("PASS: conflicting state does not overwrite newer durable trust")
    print("PASS: conflict recovery restores authoritative state")
    print("PASS: trust-state conflict is traceable")


def test_oidc_trust_state_conflict_policy(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/policy"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/policy/jwks.json"
    state_path = os.path.join(tmp_dir, "memory_oidc_policy_state.json")
    key_v1 = Ed25519PrivateKey.generate()
    key_v2 = Ed25519PrivateKey.generate()
    current_jwks = {
        "keys": [public_key_to_jwk(key_v1.public_key(), "policy-v1", version="1", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock = [3000.0]

    def fetch_json(url, timeout_seconds, request_headers=None):
        if url == discovery_url:
            return {"issuer": issuer, "jwks_uri": jwks_url}, {"status": 200, "cache-control": "max-age=10", "etag": '"p1"'}
        return json.loads(json.dumps(current_jwks)), {"status": 200, "cache-control": "max-age=10", "etag": '"pk1"'}

    authoritative = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )
    expect(authoritative.refresh()["success"] is True, "Initial policy fixture refresh failed.")
    durable_revision = authoritative.get_discovery_metadata()["state_revision"]

    stale = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
        conflict_policy=OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE,
    )
    expect(stale.get_discovery_metadata()["state_revision"] == durable_revision, "Stale policy fixture did not load durable revision.")

    current_jwks = {
        "keys": [public_key_to_jwk(key_v2.public_key(), "policy-v2", version="2", status=IDENTITY_KEY_STATUS_ACTIVE)]
    }
    clock[0] = 3011.0
    expect(authoritative.refresh()["success"] is True, "Authoritative policy rotation failed.")
    rotated_revision = authoritative.get_discovery_metadata()["state_revision"]
    expect(rotated_revision > durable_revision, "Authoritative revision did not advance.")

    # Construct the conflict explicitly: the stale writer still expects the
    # old revision, while durable storage contains the newer authoritative one.
    conflict = OIDCTrustStateConflictError(
        "simulated stale writer",
        expected_revision=durable_revision,
        actual_revision=rotated_revision,
        expected_fingerprint=stale.get_discovery_metadata()["state_fingerprint"],
        actual_fingerprint=authoritative.get_discovery_metadata()["state_fingerprint"],
    )
    recovery = stale._recover_from_state_conflict(conflict)
    expect(recovery["recovered"] is True, "Reload-authoritative policy did not recover newer durable state.")
    expect(recovery["decision"] == OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE, "Wrong conflict recovery decision.")
    expect(stale.get_discovery_metadata()["state_revision"] == rotated_revision, "Policy recovery did not adopt authoritative revision.")
    expect(stale.get_verification_key("policy-v2", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Policy recovery did not restore authoritative key.")

    # Same revision + different fingerprint is an unsafe state fork. The
    # fail-closed policy must record it but never choose one side silently.
    strict = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        state_path=state_path,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
        conflict_policy=OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED,
    )
    fork = OIDCTrustStateConflictError(
        "simulated same-revision fork",
        expected_revision=rotated_revision,
        actual_revision=rotated_revision,
        expected_fingerprint="expected-fork",
        actual_fingerprint="actual-fork",
    )
    strict_recovery = strict._recover_from_state_conflict(fork)
    expect(strict_recovery["recovered"] is False, "Fail-closed policy silently recovered a forked state.")
    expect(strict_recovery["decision"] == OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED, "Fail-closed policy returned the wrong decision.")
    expect(strict_recovery["conflict_type"] == "SAME_REVISION_DIFFERENT_STATE", "Same-revision fork was misclassified.")

    metadata = stale.get_discovery_metadata()
    expect(metadata["conflict_policy"] == OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE, "Conflict policy was not exposed in metadata.")
    expect(metadata["last_conflict_recovery"]["recovered"] is True, "Conflict recovery audit was not persisted in runtime metadata.")

    print("PASS: newer durable trust state is safely adopted by recovery policy")
    print("PASS: same-revision divergent trust state fails closed")
    print("PASS: conflict classification and recovery decision are traceable")



def test_oidc_jwt_adapter_integrates_with_reconciliation(tmp_dir):
    import memory_reconciliation as reconciliation_module
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    build_fixture(tmp_dir)

    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    private_key = Ed25519PrivateKey.generate()
    registry = TrustedAttestationKeyRegistry()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    private_key.public_key(),
                    "oidc-integration-key",
                    version="1",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source="https://issuer.test/.well-known/jwks.json",
    )

    issuer = "https://issuer.test"
    audience = "memory-api"
    token_cache = {}
    token_provider_calls = []

    def encode(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

    def token_provider(**kwargs):
        nonce = kwargs.get("attestation_nonce", "")
        token_provider_calls.append(dict(kwargs))
        if nonce in token_cache:
            return token_cache[nonce]

        now = int(time.time())
        header = {
            "alg": IDENTITY_JWT_ALGORITHM_EDDSA,
            "kid": "oidc-integration-key",
            "typ": "JWT",
        }
        claims = {
            "iss": issuer,
            "sub": "sub-alice",
            "aud": audience,
            "actor": kwargs.get("actor", "alice"),
            "roles": [kwargs.get("claimed_role", "security")],
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
            "jti": "jwt-integration-001",
        }
        encoded_header = encode(header)
        encoded_claims = encode(claims)
        signing_input = (encoded_header + "." + encoded_claims).encode("ascii")
        signature = private_key.sign(signing_input)
        token = (
            encoded_header
            + "."
            + encoded_claims
            + "."
            + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        )
        token_cache[nonce] = token
        return token

    adapter = OIDCJWTAttestationAdapter(
        registry,
        issuer=issuer,
        audience=audience,
        token_provider=token_provider,
        expected_key_statuses=[IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
        require_nonce=True,
    )

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_active_identity": True,
            "require_cryptographic_attestation": True,
            "require_trusted_attestation_key": True,
            "attestation_key_statuses": [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
            "attestation_key_id": "oidc-integration-key",
            "attestation_issuer": issuer,
            "attestation_audience": audience,
            "require_attestation_nonce": True,
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "identity_provider": issuer,
        }

        prepared = prepare_repair_approval(
            tmp_dir,
            actor="alice",
            role="security",
            reason="OIDC integration test",
            reference="OIDC-INTEGRATION-001",
            ttl_seconds=900,
            identity_provider=adapter,
        )
        expect(prepared["status"] == "APPROVAL_READY", f"OIDC-backed approval preparation failed: {prepared}")
        expect(prepared["identity_validation"]["valid"] is True, "OIDC adapter was not accepted as the authoritative identity provider.")
        expect(prepared["approval"]["identity_provider"] == issuer, "OIDC issuer was not persisted as identity provider.")
        expect(prepared["approval"]["identity_signature_key_id"] == "oidc-integration-key", "JWT signing key id was not persisted in the approval.")
        expect(prepared["approval"]["identity_cryptographic_attestation_verified"] is True, "JWT cryptographic attestation was not persisted as verified.")
        expect(prepared["approval"]["identity_attestation_nonce"], "Approval did not retain its nonce binding.")

        result = reconcile(
            tmp_dir,
            approve=True,
            approval_context=prepared["approval"],
            identity_provider=adapter,
        )
        expect(result["status"] == "REPAIRED", f"OIDC-backed reconciliation failed: {result}")
        expect(result["executed"] is True, "OIDC-backed reconciliation did not execute.")
        expect(result["approval"]["identity_signature_key_id"] == "oidc-integration-key", "Reconciliation lost the JWT key identity trace.")
        expect(result["approval"]["identity_attestation_issuer"] == issuer, "Reconciliation lost the JWT issuer trace.")
        expect(len(token_provider_calls) == 2, f"Expected exactly one JWT verification during preparation and one during execution, got {len(token_provider_calls)}")

        final_state = inspect_reconciliation(tmp_dir)
        expect(final_state["valid"] is True, "OIDC-backed reconciliation did not restore a valid memory state.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)

def test_jwks_key_discovery_and_rotation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    registry = TrustedAttestationKeyRegistry()

    first = registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    old_private.public_key(),
                    "jwks-old",
                    version="1",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source="https://issuer.test/.well-known/jwks.json",
    )
    expect(first["changed"] is True, "Initial JWKS discovery did not change the registry.")
    expect(first["rejected"] == [], f"Initial JWKS discovery rejected a valid key: {first}")
    expect(registry.get_verification_key("jwks-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "Discovered key was not retrievable.")
    first_metadata = registry.get_verification_key_metadata("jwks-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519)
    expect(first_metadata["status"] == IDENTITY_KEY_STATUS_ACTIVE, "Initial discovered key was not ACTIVE.")
    expect(len(first_metadata["fingerprint"]) == 64, "Discovered key fingerprint is not SHA256-sized.")
    first_registry_fingerprint = registry.get_registry_metadata()["key_set_fingerprint"]

    second = registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    old_private.public_key(),
                    "jwks-old",
                    version="1",
                    status=IDENTITY_KEY_STATUS_GRACE,
                ),
                public_key_to_jwk(
                    new_private.public_key(),
                    "jwks-new",
                    version="2",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                ),
            ]
        },
        source="https://issuer.test/.well-known/jwks.json",
    )
    expect(second["changed"] is True, "JWKS rotation did not change the registry fingerprint.")
    expect(registry.get_verification_key_metadata("jwks-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519)["status"] == IDENTITY_KEY_STATUS_GRACE, "Old key was not moved to GRACE during overlap rotation.")
    expect(registry.get_verification_key_metadata("jwks-new", IDENTITY_ATTESTATION_ALGORITHM_ED25519)["status"] == IDENTITY_KEY_STATUS_ACTIVE, "New key was not ACTIVE after rotation.")
    expect(registry.get_registry_metadata()["key_set_fingerprint"] != first_registry_fingerprint, "Key-set fingerprint did not change after rotation.")

    third = registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    new_private.public_key(),
                    "jwks-new",
                    version="2",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source="https://issuer.test/.well-known/jwks.json",
        retire_missing=True,
    )
    expect(third["retired"] == [{"key_id": "jwks-old", "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519}], "Missing old JWKS key was not safely retired.")
    expect(registry.get_verification_key_metadata("jwks-old", IDENTITY_ATTESTATION_ALGORITHM_ED25519)["status"] == IDENTITY_KEY_STATUS_RETIRED, "Old key was not RETIRED after final rotation.")
    expect(registry.get_verification_key_metadata("jwks-new", IDENTITY_ATTESTATION_ALGORITHM_ED25519)["status"] == IDENTITY_KEY_STATUS_ACTIVE, "New key lost ACTIVE status after final rotation.")

    malformed = registry.refresh_from_jwks(
        {"keys": [{"kty": "RSA", "kid": "bad-key", "n": "invalid"}]},
        source="https://issuer.test/.well-known/jwks.json",
    )
    expect(len(malformed["rejected"]) == 1, "Malformed non-Ed25519 JWK was unexpectedly accepted.")



def test_cryptographic_attestation_policy_is_traceable(tmp_dir):
    import memory_reconciliation as reconciliation_module

    build_fixture(tmp_dir)
    code = "GRAPH_MEMORY_NODE_MISSING_SOURCE"
    original_codes = set(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES)
    original_requirements = dict(reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS)

    try:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.add(code)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "identity_provider": "TEST-IDP",
        }
        first = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS[code] = {
            "required_count": 1,
            "require_authoritative_identity": True,
            "require_cryptographic_attestation": True,
            "identity_provider": "TEST-IDP",
            "attestation_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "attestation_key_id": "test-key-1",
        }
        second = evaluate_repair_policy(inspect_reconciliation(tmp_dir))

        expect(first["approval_requirement"]["require_cryptographic_attestation"] is False, "Baseline cryptographic requirement was unexpectedly enabled.")
        expect(second["approval_requirement"]["require_cryptographic_attestation"] is True, "Cryptographic attestation policy was not exposed.")
        expect(second["approval_requirement"]["attestation_algorithm"] == IDENTITY_ATTESTATION_ALGORITHM_ED25519, "Attestation algorithm policy was not exposed.")
        expect(second["approval_requirement"]["attestation_key_id"] == "test-key-1", "Attestation key policy was not exposed.")
        expect(second["policy_fingerprint"] != first["policy_fingerprint"], "Cryptographic attestation policy did not alter policy fingerprint.")
    finally:
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIRED_CODES.update(original_codes)
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.clear()
        reconciliation_module.REPAIR_POLICY_APPROVAL_REQUIREMENTS.update(original_requirements)


def test_oidc_http_cache_headers_etag_backoff(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/cache"
    discovery_url = issuer + "/.well-known/openid-configuration"
    jwks_url = "https://keys.issuer.test/cache/jwks.json"
    private = Ed25519PrivateKey.generate()
    jwks = {"keys": [public_key_to_jwk(private.public_key(), "cache-key", status=IDENTITY_KEY_STATUS_ACTIVE)]}
    discovery = {"issuer": issuer, "jwks_uri": jwks_url}
    clock = [1000.0]
    calls = []
    etags = {discovery_url: '"disc-v1"', jwks_url: '"jwks-v1"'}

    def fetch_json(url, timeout_seconds, request_headers=None):
        calls.append((url, timeout_seconds, dict(request_headers or {})))
        headers = {
            "status": 200,
            "etag": etags[url],
            "cache-control": "max-age=20",
        }
        if request_headers and request_headers.get("If-None-Match") == etags[url]:
            headers["status"] = 304
            return None, headers
        return (discovery if url == discovery_url else jwks), headers

    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        cache_ttl_seconds=5,
        refresh_backoff_seconds=5,
        max_refresh_backoff_seconds=20,
        fetch_json=fetch_json,
        now_fn=lambda: clock[0],
    )

    first = source.refresh()
    expect(first["success"] is True, f"Initial cache-header refresh failed: {first}")
    expect(source.get_discovery_metadata()["cache_expires_at"] == 1020.0, "Cache-Control max-age did not control cache expiry.")
    expect(len(calls) == 2, f"Initial refresh made unexpected requests: {calls}")

    clock[0] = 1021.0
    second = source.refresh()
    expect(second["success"] is True, f"ETag revalidation failed: {second}")
    expect(second["status"] == "NOT_MODIFIED", f"Expected NOT_MODIFIED status: {second}")
    expect(calls[2][2].get("If-None-Match") == '"disc-v1"', "Discovery ETag was not sent on revalidation.")
    expect(calls[3][2].get("If-None-Match") == '"jwks-v1"', "JWKS ETag was not sent on revalidation.")
    expect(source.get_verification_key("cache-key", IDENTITY_ATTESTATION_ALGORITHM_ED25519) is not None, "304 revalidation lost the trusted key.")

    failure_calls = []
    failure_clock = [2000.0]

    def failing_fetch(url, timeout_seconds):
        failure_calls.append(url)
        raise RuntimeError("network unavailable")

    failing_source = OIDCDiscoveryJWKSSource(
        issuer,
        TrustedAttestationKeyRegistry(),
        refresh_backoff_seconds=5,
        max_refresh_backoff_seconds=20,
        fetch_json=failing_fetch,
        now_fn=lambda: failure_clock[0],
    )
    failed = failing_source.refresh()
    expect(failed["success"] is False and failed["fail_closed"] is True, "Failed refresh did not fail closed.")
    expect(failed["retry_after_seconds"] == 5, f"Initial refresh backoff is incorrect: {failed}")

    blocked = failing_source.refresh()
    expect(blocked["status"] == "REFRESH_BACKOFF", f"Refresh backoff did not suppress a retry: {blocked}")
    expect(len(failure_calls) == 1, "Backoff did not prevent duplicate refresh requests.")

    failure_clock[0] = 2005.0
    failed_again = failing_source.refresh()
    expect(failed_again["retry_after_seconds"] == 10, f"Exponential refresh backoff did not increase: {failed_again}")
    expect(len(failure_calls) == 2, "Backoff window did not permit the next scheduled retry.")


def test_oidc_trust_state_audit_evidence_verification_policy_and_decision_recording(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer = "https://issuer.test/audit-policy"
    state_path = os.path.join(tmp_dir, "memory_oidc_audit_policy_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 16000.0,
    )
    source._state_revision = 11
    source._state_fingerprint = "policy-state"
    source._persisted_state_fingerprint = source._state_fingerprint
    source._append_trust_state_journal("POLICY_EVENT", {"value": 1})

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    registry.refresh_from_jwks(
        {
            "keys": [
                public_key_to_jwk(
                    public_key,
                    "audit-policy-key",
                    version="2026-09-24",
                    status=IDENTITY_KEY_STATUS_ACTIVE,
                )
            ]
        },
        source=issuer + "/.well-known/jwks.json",
    )

    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Policy evidence export failed: {exported}")
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(
        exported["evidence"],
        private_key,
        registry,
        key_id="audit-policy-key",
        issuer=issuer,
    )
    expect(attested["success"] is True, f"Policy attestation failed: {attested}")

    decision = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(
        attested["evidence"],
        registry,
        policy={
            "policy_id": "AUDIT_POLICY_V1",
            "expected_issuer": issuer,
            "expected_key_id": "audit-policy-key",
            "allowed_key_statuses": ["ACTIVE", "GRACE"],
            "require_current_registry_binding": True,
            "require_provenance": True,
        },
    )
    expect(decision["success"] and decision["decision"] == "VERIFIED", f"Policy verification failed: {decision}")
    expect(len(decision["decision_fingerprint"]) == 64, "Decision fingerprint was not deterministic SHA-256 length.")
    expect(decision["policy"]["policy_id"] == "AUDIT_POLICY_V1", "Policy ID was not recorded.")
    expect(decision["authoritative_state_mutated"] is False, "Verification mutated authoritative state.")

    rejected = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(
        attested["evidence"],
        registry,
        policy={
            "policy_id": "AUDIT_POLICY_WRONG_KEY",
            "expected_key_id": "different-key",
            "require_provenance": True,
        },
    )
    expect(not rejected["success"] and rejected["decision"] == "REJECTED", f"Rejected policy was not fail-closed: {rejected}")
    expect(rejected["decision_fingerprint"] != decision["decision_fingerprint"], "Rejected decision did not produce a distinct fingerprint.")

    invalid_policy = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(
        attested["evidence"],
        registry,
        policy={"allowed_key_statuses": []},
    )
    expect(not invalid_policy["success"] and invalid_policy["status"] == "AUDIT_EVIDENCE_POLICY_INVALID", f"Invalid policy was accepted: {invalid_policy}")

    print("PASS: audit evidence verification policy produces deterministic trust decision records")
    print("PASS: policy constraints and provenance are recorded without mutating authoritative state")
    print("PASS: rejected and invalid verification policies fail closed with distinct decision fingerprints")


def test_oidc_trust_state_audit_evidence_decision_attestation(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    issuer = "https://issuer.test/decision-attestation"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_attestation_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(issuer, registry, state_path=state_path, fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")), now_fn=lambda: 17000.0)
    source._state_revision = 17
    source._state_fingerprint = "decision-attestation-state"
    source._persisted_state_fingerprint = source._state_fingerprint
    source._append_trust_state_journal("DECISION_ATTESTATION_EVENT", {"value": 1})
    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks({"keys": [public_key_to_jwk(private_key.public_key(), "decision-attestation-key", version="2026-09-24", status=IDENTITY_KEY_STATUS_ACTIVE)]}, source=issuer + "/.well-known/jwks.json")
    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Decision evidence export failed: {exported}")
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(exported["evidence"], private_key, registry, key_id="decision-attestation-key", issuer=issuer)
    expect(attested["success"] is True, f"Decision source attestation failed: {attested}")
    decision = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(attested["evidence"], registry, policy={"policy_id": "DECISION_POLICY_V1", "expected_issuer": issuer, "expected_key_id": "decision-attestation-key", "allowed_key_statuses": ["ACTIVE", "GRACE"], "require_current_registry_binding": True, "require_provenance": True})
    expect(decision["success"] and decision["decision"] == "VERIFIED", f"Decision verification failed: {decision}")
    signed = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision(decision, private_key, registry, key_id="decision-attestation-key", issuer=issuer)
    expect(signed["success"] is True, f"Decision attestation failed: {signed}")
    signed_decision = signed["decision"]
    expect(signed_decision["decision_attestation"]["decision_fingerprint"] == decision["decision_fingerprint"], "Decision fingerprint was not bound.")
    expect(signed_decision["decision_attestation"]["policy_id"] == "DECISION_POLICY_V1", "Policy identity was not bound.")
    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-attestation-key")
    expect(verified["success"] is True and verified["current_registry_binding"] is True, f"Decision attestation verification failed: {verified}")
    tampered = json.loads(json.dumps(signed_decision))
    tampered["policy"]["policy_id"] = "TAMPERED_POLICY"
    tampered_check = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(tampered, registry, expected_issuer=issuer, expected_key_id="decision-attestation-key")
    expect(not tampered_check["success"] and tampered_check["reason"] == "decision_fingerprint_mismatch", "Tampered decision was not rejected.")
    registry.set_status("decision-attestation-key", IDENTITY_KEY_STATUS_RETIRED)
    retired = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-attestation-key", require_current_registry_binding=False)
    expect(not retired["success"] and retired["reason"] == "trusted_key_status_not_allowed", "Retired decision-signing key did not fail closed.")
    print("PASS: verification decisions can be cryptographically attested with trusted-key provenance")
    print("PASS: decision fingerprints and policy identity are cryptographically bound")
    print("PASS: tampered decisions and retired decision-signing keys fail closed")


def test_oidc_trust_state_audit_evidence_decision_attestation_replay_and_temporal_binding(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    issuer = "https://issuer.test/decision-replay"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_replay_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(issuer, registry, state_path=state_path, fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")), now_fn=lambda: 17000.0)
    source._state_revision = 19
    source._state_fingerprint = "decision-replay-state"
    source._persisted_state_fingerprint = source._state_fingerprint
    source._append_trust_state_journal("DECISION_REPLAY_EVENT", {"value": 1})
    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks({"keys": [public_key_to_jwk(private_key.public_key(), "decision-replay-key", version="2026-09-24", status=IDENTITY_KEY_STATUS_ACTIVE)]}, source=issuer + "/.well-known/jwks.json")
    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Replay evidence export failed: {exported}")
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(exported["evidence"], private_key, registry, key_id="decision-replay-key", issuer=issuer)
    expect(attested["success"] is True, f"Replay source attestation failed: {attested}")
    decision = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(attested["evidence"], registry, policy={"policy_id": "REPLAY_POLICY_V1", "expected_issuer": issuer, "expected_key_id": "decision-replay-key", "allowed_key_statuses": ["ACTIVE", "GRACE"], "require_current_registry_binding": True, "require_provenance": True})
    expect(decision["success"] is True, f"Replay decision failed: {decision}")
    signed = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision_with_replay_binding(decision, private_key, registry, key_id="decision-replay-key", issuer=issuer, nonce="request-nonce-001", attestation_id="decision-attestation-001", issued_at=17000.0, expires_at=17300.0)
    expect(signed["success"] is True, f"Replay-bound decision attestation failed: {signed}")
    signed_decision = signed["decision"]
    attestation = signed_decision["decision_attestation"]
    expect(attestation["schema_version"] == 2, "Replay-bound attestation did not use schema version 2.")
    expect(attestation["nonce"] == "request-nonce-001" and attestation["attestation_id"] == "decision-attestation-001", "Replay context was not recorded.")
    verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-replay-key", expected_nonce="request-nonce-001", expected_attestation_id="decision-attestation-001", verification_time=17100.0)
    expect(verified["success"] is True and verified["replay_binding"] is True, f"Replay-bound verification failed: {verified}")
    wrong_nonce = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-replay-key", expected_nonce="wrong-nonce", verification_time=17100.0)
    expect(not wrong_nonce["success"] and wrong_nonce["reason"] == "nonce_mismatch", "Mismatched nonce did not fail closed.")
    expired = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-replay-key", expected_nonce="request-nonce-001", verification_time=17361.0, clock_skew_seconds=0)
    expect(not expired["success"] and expired["reason"] == "attestation_expired", "Expired attestation did not fail closed.")
    future = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(signed_decision, registry, expected_issuer=issuer, expected_key_id="decision-replay-key", expected_nonce="request-nonce-001", verification_time=16900.0, clock_skew_seconds=0)
    expect(not future["success"] and future["reason"] == "attestation_not_yet_valid", "Future attestation did not fail closed.")
    tampered = json.loads(json.dumps(signed_decision))
    tampered["decision_attestation"]["nonce"] = "tampered-nonce"
    tampered_check = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(tampered, registry, expected_issuer=issuer, expected_key_id="decision-replay-key", verification_time=17100.0)
    expect(not tampered_check["success"] and tampered_check["reason"] == "signature_verification_failed", "Tampered replay binding was not rejected by signature verification.")
    legacy = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision(decision, private_key, registry, key_id="decision-replay-key", issuer=issuer)
    legacy_verified = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_verification_decision_attestation(legacy["decision"], registry, expected_issuer=issuer, expected_key_id="decision-replay-key")
    expect(legacy_verified["success"] is True and legacy_verified["replay_binding"] is False, "Legacy schema v1 decision attestation lost backward compatibility.")
    print("PASS: decision attestations support signed nonce and temporal replay binding")
    print("PASS: nonce, attestation ID, expiration, and not-before checks fail closed")
    print("PASS: tampered replay context is rejected cryptographically")
    print("PASS: legacy schema v1 decision attestations remain verifiable")

def test_oidc_trust_state_audit_evidence_decision_attestation_one_time_consumption(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    issuer = "https://issuer.test/decision-consume"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consume_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 17000.0,
    )
    source._append_trust_state_journal("DECISION_CONSUME_EVENT", {"value": 1})
    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks({"keys": [public_key_to_jwk(private_key.public_key(), "decision-consume-key", version="2026-09-24", status=IDENTITY_KEY_STATUS_ACTIVE)]}, source=issuer + "/.well-known/jwks.json")
    source._persist_state()
    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    expect(exported["success"] is True, f"Consumption evidence export failed: {exported}")
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(exported["evidence"], private_key, registry, key_id="decision-consume-key", issuer=issuer)
    expect(attested["success"] is True, f"Consumption source attestation failed: {attested}")
    decision = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(attested["evidence"], registry, policy={"policy_id": "CONSUME_POLICY_V1", "expected_issuer": issuer, "expected_key_id": "decision-consume-key", "allowed_key_statuses": ["ACTIVE", "GRACE"], "require_current_registry_binding": True, "require_provenance": True})
    expect(decision["success"] is True, f"Consumption decision failed: {decision}")
    signed = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision_with_replay_binding(
        decision, private_key, registry, key_id="decision-consume-key", issuer=issuer,
        nonce="consume-nonce-001", attestation_id="consume-attestation-001", issued_at=17000.0, expires_at=17300.0,
    )
    expect(signed["success"] is True, f"Consumption attestation failed: {signed}")
    signed_decision = signed["decision"]

    first = source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed_decision,
        expected_issuer=issuer,
        expected_key_id="decision-consume-key",
        expected_nonce="consume-nonce-001",
        expected_attestation_id="consume-attestation-001",
        verification_time=17100.0,
    )
    expect(first["success"] is True and first["status"] == "AUDIT_EVIDENCE_DECISION_ATTESTATION_CONSUMED", f"First consumption failed: {first}")

    second = source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed_decision,
        expected_issuer=issuer,
        expected_key_id="decision-consume-key",
        expected_nonce="consume-nonce-001",
        expected_attestation_id="consume-attestation-001",
        verification_time=17100.0,
    )
    expect(not second["success"] and second["status"] == "DECISION_ATTESTATION_REPLAYED", f"Second consumption was not rejected: {second}")

    restored_registry = TrustedAttestationKeyRegistry()
    restored_source = OIDCDiscoveryJWKSSource(
        issuer,
        restored_registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 17000.0,
    )
    restored_replay = restored_source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed_decision,
        expected_issuer=issuer,
        expected_key_id="decision-consume-key",
        expected_nonce="consume-nonce-001",
        expected_attestation_id="consume-attestation-001",
        verification_time=17100.0,
    )
    expect(not restored_replay["success"] and restored_replay["status"] == "DECISION_ATTESTATION_REPLAYED", f"Persisted one-time consumption was lost after restart: {restored_replay}")

    wrong_nonce = source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed_decision, expected_issuer=issuer, expected_key_id="decision-consume-key",
        expected_nonce="wrong-nonce", expected_attestation_id="consume-attestation-001", verification_time=17100.0,
    )
    expect(not wrong_nonce["success"] and wrong_nonce["reason"] == "nonce_mismatch", "Wrong nonce did not fail closed before consumption lookup.")

    legacy = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision(decision, private_key, registry, key_id="decision-consume-key", issuer=issuer)
    legacy_consume = source.consume_trust_state_audit_evidence_verification_decision_attestation(legacy["decision"], expected_issuer=issuer, expected_key_id="decision-consume-key")
    expect(not legacy_consume["success"] and legacy_consume["reason"] == "one_time_consumption_requires_schema_v2", "Schema v1 was incorrectly eligible for one-time consumption.")

    print("PASS: replay-bound decision attestations are consumed exactly once")
    print("PASS: one-time consumption survives persistent trust-state restart")
    print("PASS: mismatched replay context and legacy attestations fail closed")


def test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit(tmp_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    issuer = "https://issuer.test/decision-consumption-audit"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer, registry, state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 18000.0,
    )
    source._append_trust_state_journal("CONSUMPTION_AUDIT_EVENT", {"value": 1})
    private_key = Ed25519PrivateKey.generate()
    registry.refresh_from_jwks({"keys": [public_key_to_jwk(private_key.public_key(), "audit-consume-key", version="2026-09-24", status=IDENTITY_KEY_STATUS_ACTIVE)]}, source=issuer + "/jwks.json")
    source._persist_state()
    exported = source.export_trust_state_audit_evidence(start_sequence=1, end_sequence=1)
    attested = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_with_trusted_key(exported["evidence"], private_key, registry, key_id="audit-consume-key", issuer=issuer)
    decision = OIDCDiscoveryJWKSSource.verify_trust_state_audit_evidence_with_policy(attested["evidence"], registry, policy={"policy_id": "CONSUMPTION_AUDIT_POLICY_V1", "expected_issuer": issuer, "expected_key_id": "audit-consume-key", "allowed_key_statuses": ["ACTIVE", "GRACE"], "require_current_registry_binding": True, "require_provenance": True})
    signed = OIDCDiscoveryJWKSSource.attest_trust_state_audit_evidence_verification_decision_with_replay_binding(
        decision, private_key, registry, key_id="audit-consume-key", issuer=issuer,
        nonce="audit-nonce-001", attestation_id="audit-attestation-001", issued_at=18000.0, expires_at=18300.0,
    )
    first = source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed["decision"], expected_issuer=issuer, expected_key_id="audit-consume-key",
        expected_nonce="audit-nonce-001", expected_attestation_id="audit-attestation-001", verification_time=18100.0,
    )
    expect(first["success"] is True, f"First audited consumption failed: {first}")
    replay = source.consume_trust_state_audit_evidence_verification_decision_attestation(
        signed["decision"], expected_issuer=issuer, expected_key_id="audit-consume-key",
        expected_nonce="audit-nonce-001", expected_attestation_id="audit-attestation-001", verification_time=18100.0,
    )
    expect(not replay["success"] and replay["status"] == "DECISION_ATTESTATION_REPLAYED", f"Replay was not rejected: {replay}")

    audit = registry.get_decision_attestation_consumption_audit(attestation_id="audit-attestation-001")
    expect(audit["success"] and len(audit["records"]) == 2, f"Consumption audit did not record consume and replay: {audit}")
    expect(audit["records"][0]["event_type"] == "REPLAY_REJECTED" and audit["records"][1]["event_type"] == "CONSUMED", f"Unexpected audit ordering: {audit}")
    expect(audit["records"][0]["previous_hash"] == audit["records"][1]["record_hash"], "Consumption audit hash chain did not link correctly.")

    restored_registry = TrustedAttestationKeyRegistry()
    restored_source = OIDCDiscoveryJWKSSource(
        issuer, restored_registry, state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 18000.0,
    )
    restored_audit = restored_registry.get_decision_attestation_consumption_audit(attestation_id="audit-attestation-001")
    expect(restored_audit["success"] and len(restored_audit["records"]) == 2, f"Consumption audit was not persisted: {restored_audit}")
    expect(restored_audit["head_hash"] == audit["head_hash"], "Persisted consumption audit head hash changed after restart.")

    tampered = list(restored_registry._consumption_audit_records)
    tampered[0]["reason"] = "tampered"
    restored_registry._consumption_audit_records = tampered
    tamper_check = restored_registry.get_decision_attestation_consumption_audit()
    expect(not tamper_check["success"] and tamper_check["status"] == "DECISION_ATTESTATION_AUDIT_TAMPERED", f"Tampered consumption audit was accepted: {tamper_check}")

    print("PASS: decision attestation consumption records capture success and replay outcomes")
    print("PASS: consumption audit history persists and preserves a hash chain")
    print("PASS: tampered consumption audit history fails closed")



def test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit_query_and_timeline(tmp_dir):
    issuer = "https://issuer.test/decision-consumption-audit-query"
    state_path = os.path.join(tmp_dir, "memory_oidc_decision_consumption_audit_query_state.json")
    registry = TrustedAttestationKeyRegistry()
    source = OIDCDiscoveryJWKSSource(
        issuer,
        registry,
        state_path=state_path,
        fetch_json=lambda *args: (_ for _ in ()).throw(RuntimeError("network must not be used")),
        now_fn=lambda: 19000.0,
    )

    records = [
        ("CONSUMED", "att-1", "fp-1", "nonce-1", 19000.0, "one_time_consumption"),
        ("REPLAY_REJECTED", "att-1", "fp-1", "nonce-1", 19010.0, "attestation_already_consumed"),
        ("CONSUMED", "att-2", "fp-2", "nonce-2", 19020.0, "one_time_consumption"),
        ("REPLAY_REJECTED", "att-3", "fp-3", "nonce-3", 19030.0, "attestation_already_consumed"),
        ("CONSUMED", "att-2", "fp-2", "nonce-2", 19040.0, "one_time_consumption"),
    ]
    for event_type, attestation_id, fingerprint, nonce, event_at, reason in records:
        appended = registry._append_decision_attestation_consumption_audit(
            event_type=event_type,
            attestation_id=attestation_id,
            decision_fingerprint=fingerprint,
            nonce=nonce,
            consumed_at=event_at,
            reason=reason,
        )
        expect(appended["success"] is True, f"Audit fixture append failed: {appended}")

    source._persist_state()
    with open(state_path, "rb") as file:
        state_path_before = file.read()
    audit_state_before = {
        "head_hash": registry._consumption_audit_head_hash,
        "records": [dict(item) for item in registry._consumption_audit_records],
    }

    by_attestation = registry.get_decision_attestation_consumption_audit(
        attestation_id="att-2",
        reverse=False,
        verify_integrity=True,
    )
    expect(by_attestation["success"] is True, f"Attestation-id query failed: {by_attestation}")
    expect(by_attestation["status"] == "DECISION_ATTESTATION_AUDIT_OK", "Legacy query wrapper changed status unexpectedly.")
    expect([item["sequence"] for item in by_attestation["records"]] == [3, 5], "Attestation-id filtering returned the wrong records.")

    by_fingerprint = registry.query_decision_attestation_consumption_audit(
        decision_fingerprint="FP-2",
        reverse=False,
        verify_integrity=True,
    )
    expect(by_fingerprint["success"] is True, f"Decision-fingerprint query failed: {by_fingerprint}")
    expect([item["sequence"] for item in by_fingerprint["records"]] == [3, 5], "Decision-fingerprint filtering returned the wrong records.")

    by_event_type = registry.query_decision_attestation_consumption_audit(
        event_type="replay_rejected",
        reverse=True,
        verify_integrity=True,
    )
    expect(by_event_type["success"] is True, f"Event-type query failed: {by_event_type}")
    expect([item["sequence"] for item in by_event_type["records"]] == [4, 2], "Event-type reverse ordering is not deterministic.")

    by_sequence = registry.query_decision_attestation_consumption_audit(
        start_sequence=2,
        end_sequence=4,
        reverse=False,
        verify_integrity=True,
    )
    expect(by_sequence["success"] is True, f"Sequence-range query failed: {by_sequence}")
    expect([item["sequence"] for item in by_sequence["records"]] == [2, 3, 4], "Sequence range filtering returned the wrong records.")
    expect(by_sequence["coverage_start_sequence"] == 1, "Coverage start was not reported.")
    expect(by_sequence["coverage_end_sequence"] == 5, "Coverage end was not reported.")

    by_time = registry.query_decision_attestation_consumption_audit(
        start_time=19010.0,
        end_time="1970-01-01T05:17:10+00:00",
        reverse=False,
        verify_integrity=True,
    )
    expect(by_time["success"] is True, f"Time-range query failed: {by_time}")
    expect([item["sequence"] for item in by_time["records"]] == [2, 3, 4], "Time-range filtering returned the wrong records.")

    limited = registry.query_decision_attestation_consumption_audit(
        start_sequence=1,
        end_sequence=5,
        limit=2,
        reverse=True,
        verify_integrity=True,
    )
    expect(limited["success"] is True, f"Limited reverse query failed: {limited}")
    expect([item["sequence"] for item in limited["records"]] == [5, 4], "Limit/reverse query ordering is incorrect.")

    timeline = registry.get_decision_attestation_consumption_audit_timeline(
        start_sequence=2,
        end_sequence=4,
        reverse=False,
        verify_integrity=True,
    )
    expect(timeline["success"] is True, f"Consumption audit timeline failed: {timeline}")
    expect(timeline["status"] == "DECISION_ATTESTATION_AUDIT_TIMELINE", "Timeline returned the wrong status.")
    expect([item["sequence"] for item in timeline["timeline"]] == [2, 3, 4], "Timeline sequence ordering is incorrect.")
    expect(timeline["timeline"][0]["event_at_iso"] == "1970-01-01T05:16:50+00:00", "Timeline did not render event time deterministically.")
    expect(timeline["read_only"] is True and timeline["authoritative_state_mutated"] is False, "Timeline did not preserve read-only guarantees.")
    expect(timeline["integrity_verified"] is True, "Timeline did not report integrity verification.")

    invalid_sequence = registry.query_decision_attestation_consumption_audit(
        start_sequence=4,
        end_sequence=2,
    )
    expect(not invalid_sequence["success"], "Invalid sequence range was accepted.")
    expect(invalid_sequence["reason"] == "start_sequence_after_end_sequence", "Invalid sequence range returned the wrong reason.")

    invalid_time = registry.query_decision_attestation_consumption_audit(
        start_time=20000.0,
        end_time=19000.0,
    )
    expect(not invalid_time["success"], "Invalid time range was accepted.")
    expect(invalid_time["reason"] == "start_time_after_end_time", "Invalid time range returned the wrong reason.")

    with open(state_path, "rb") as file:
        state_path_after_queries = file.read()
    audit_state_after = {
        "head_hash": registry._consumption_audit_head_hash,
        "records": [dict(item) for item in registry._consumption_audit_records],
    }
    expect(state_path_after_queries == state_path_before, "Consumption audit query mutated persisted trust state.")
    expect(audit_state_after == audit_state_before, "Consumption audit query mutated in-memory audit history.")

    tampered = list(registry._consumption_audit_records)
    tampered[2] = dict(tampered[2])
    tampered[2]["reason"] = "tampered"
    registry._consumption_audit_records = tampered
    tamper_result = registry.query_decision_attestation_consumption_audit(
        verify_integrity=True,
    )
    expect(not tamper_result["success"], "Tampered consumption audit history was accepted by the query.")
    expect(tamper_result["status"] == "DECISION_ATTESTATION_AUDIT_TAMPERED", "Tampered query returned the wrong status.")
    expect(tamper_result["reason"] == "record_hash_mismatch", "Tampered query returned the wrong failure reason.")

    timeline_tamper = registry.get_decision_attestation_consumption_audit_timeline(
        verify_integrity=True,
    )
    expect(not timeline_tamper["success"], "Tampered timeline was accepted.")
    expect(timeline_tamper["status"] == "DECISION_ATTESTATION_AUDIT_TAMPERED", "Tampered timeline returned the wrong status.")

    print("PASS: consumption audit query filters by identity, fingerprint, event, sequence, and time")
    print("PASS: consumption audit query limit/reverse semantics are deterministic")
    print("PASS: consumption audit timeline is readable, authenticated, and read-only")
    print("PASS: consumption audit query and timeline detect hash-chain tampering")

def main():
    test_repair_policy_fails_closed_for_unknown_code()

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_repair_policy_gate_is_explicit(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_gate_is_non_destructive(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_dry_run_can_inspect_approval_gated_repair(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_classification_is_conservative(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_repair_and_reaudit(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_non_repairable_state_is_blocked(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_reconciliation_audit_history(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_repair_reentry_after_new_corruption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_dry_run_is_non_destructive(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_dry_run_on_healthy_state_is_noop(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_policy_version_and_approval_trace(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_expiration_and_replay_protection(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_consumption_allows_crash_recovery(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_multi_approver_quorum_and_distinct_actor_policy(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_multi_approver_insufficient_quorum(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_multi_approver_distinct_actor_requirement(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_multi_approver_replay_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_role_based_approval_constraints(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_role_based_approval_rejects_unauthorized_role(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_delegation_semantics(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_delegation_reference_requirement_is_enforced(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_delegation_is_blocked_without_policy_permission(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_separation_of_duties_blocks_requester_self_approval(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_separation_of_duties_blocks_requester_role_approval(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_separation_of_duties_requires_requester_context(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_separation_of_duties_allows_independent_approvers(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_requester_delegation_is_blocked_by_separation_of_duties(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_requires_provider(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_verification_and_trace(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_rejects_forged_or_changed_role(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_provider_policy_is_traceable(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_requires_active_status(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_revocation_blocks_execution(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_authoritative_identity_attestation_expiration_blocks(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_active_identity_policy_changes_fingerprint(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_attestation_nonce_issuer_audience_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_replayed_attestation_nonce_is_rejected(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_attestation_scope_change_invalidates_policy(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_cryptographic_attestation_verification(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_cryptographic_attestation_rejects_tampered_signature(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_cryptographic_attestation_key_rotation_invalidates_old_approval(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_trusted_attestation_key_lifecycle_and_revocation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_trusted_attestation_key_policy_changes_fingerprint(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_cryptographic_attestation_policy_is_traceable(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_jwks_key_discovery_and_rotation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_jwt_compatible_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_discovery_and_automatic_jwks_refresh(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_http_cache_headers_etag_backoff(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_persisted_trust_state_restart_and_recovery(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_distributed_trust_state_consistency(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_conflict_detection_and_recovery(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_conflict_policy(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_recovery_journal(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_integrity_and_replay(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_concurrency_and_atomicity(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_checkpoint_and_compaction(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_legacy_schema_upgrade(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_automatic_compaction_bounds_tail(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_checkpoint_corruption_and_backup_recovery(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_compaction_write_failure_preserves_primary(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_historical_snapshot_reconstruction(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_snapshot_verification_and_authoritative_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_historical_snapshot_real_authoritative_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_historical_snapshot_tamper_detection(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_historical_query_and_audit_timeline(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_audit_evidence_export_and_offline_verification(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_cryptographic_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_trusted_key_registry_and_rotation(tmp_dir)
    test_oidc_trust_state_audit_evidence_verification_policy_and_decision_recording(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation_replay_and_temporal_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit_query_and_timeline(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_decision_attestation_consumption_audit_evidence_export_and_offline_verification(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_audit_evidence_cryptographic_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_audit_evidence_replay_and_temporal_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_audit_evidence_attestation_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_binding_proof_offline_export_and_verification(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_composition_and_offline_verification(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_cryptographic_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_replay_and_temporal_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_terminal_consumption_binding_proof_trusted_key_attestation(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_audit_evidence_attestation_concurrent_one_time_consumption(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_status_and_read_only_proof(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_audit_evidence_key_provenance(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_oidc_trust_state_journal_compaction_concurrency(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="reconciliation_test_") as tmp_dir:
        test_approval_requirement_changes_policy_fingerprint(tmp_dir)

    print("RECONCILIATION_TEST_PASS")


if __name__ == "__main__":
    main()
