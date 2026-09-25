import hashlib
import json
import os
import secrets
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from memory_integrity import build_operation_key, load_operation_store, run_idempotent, validate_invariants
from memory_identity_provider import (
    normalize_identity_result,
    verify_identity_attestation,
)


# ==================================================
# Reconciliation Configuration
# ==================================================

RECONCILIATION_SCHEMA_VERSION = 8
RECONCILIATION_OPERATION_TYPE = "RECONCILIATION_REPAIR"
REPAIR_POLICY_VERSION = "1.7"
APPROVAL_SCHEMA_VERSION = 7
APPROVAL_DEFAULT_TTL_SECONDS = 900

REPAIR_POLICY_AUTO = "AUTO"
REPAIR_POLICY_DRY_RUN_ONLY = "DRY_RUN_ONLY"
REPAIR_POLICY_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
REPAIR_POLICY_BLOCKED = "BLOCKED"

# These violations have a deterministic repair source. No semantic identity
# decision, merge decision, deletion, or destructive move is required.
REPAIRABLE_VIOLATION_CODES = {
    # Derived graph is rebuilt from the authoritative Memory / Entity /
    # Relation stores, so every graph-local structural inconsistency is safe
    # to repair by a complete rebuild.
    "GRAPH_INVALID_STORE",
    "GRAPH_INVALID_COLLECTIONS",
    "GRAPH_INVALID_NODE",
    "GRAPH_NODE_MISSING_ID",
    "GRAPH_DUPLICATE_NODE_ID",
    "GRAPH_MEMORY_NODE_MISSING_SOURCE",
    "GRAPH_ENTITY_NODE_MISSING_SOURCE",
    "GRAPH_INVALID_EDGE",
    "GRAPH_EDGE_NODE_MISSING",
    "GRAPH_MEMORY_ENTITY_MEMORY_MISSING",
    "GRAPH_MEMORY_ENTITY_ENTITY_MISSING",
    "GRAPH_ENTITY_RELATION_ENTITY_MISSING",

    # Graph synchronization already contains the canonical pruning routines
    # for stale Memory IDs stored on Entities and Relations.
    "ENTITY_MEMORY_LINKS_NOT_LIST",
    "ENTITY_EMPTY_MEMORY_LINK",
    "ENTITY_DUPLICATE_MEMORY_LINK",
    "ENTITY_MEMORY_REFERENCE_MISSING",
    "RELATION_MEMORY_REFERENCE_MISSING",

    # These fields have a single canonical representation based on the store
    # in which the object is persisted.
    "MEMORY_ARCHIVE_STATUS_INVALID",
    "ARCHIVE_ENTITY_NOT_ARCHIVED",
    "COMPLETED_OPERATION_HAS_LEASE",
}

GRAPH_REPAIR_CODES = {
    code
    for code in REPAIRABLE_VIOLATION_CODES
    if code.startswith("GRAPH_")
}

LINK_REPAIR_CODES = {
    "ENTITY_MEMORY_LINKS_NOT_LIST",
    "ENTITY_EMPTY_MEMORY_LINK",
    "ENTITY_DUPLICATE_MEMORY_LINK",
    "ENTITY_MEMORY_REFERENCE_MISSING",
    "RELATION_MEMORY_REFERENCE_MISSING",
}

# Current deterministic repairs are safe for automatic execution. Keep the
# policy sets explicit so future repair types can be introduced conservatively
# without changing the reconciliation contract.
REPAIR_POLICY_AUTO_CODES = set(REPAIRABLE_VIOLATION_CODES)
REPAIR_POLICY_DRY_RUN_ONLY_CODES = set()
REPAIR_POLICY_APPROVAL_REQUIRED_CODES = set()
APPROVAL_DEFAULT_REQUIRED_COUNT = 1
APPROVAL_MAX_REQUIRED_COUNT = 10
APPROVAL_MAX_ROLE_COUNT = 20
APPROVAL_MAX_ROLE_LENGTH = 100
REPAIR_POLICY_APPROVAL_REQUIREMENTS = {}


# ==================================================
# Policy / Approval Helpers
# ==================================================


def _canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_role_list(value):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = []

    normalized = []
    for item in values[:APPROVAL_MAX_ROLE_COUNT]:
        role = str(item or "").strip()[:APPROVAL_MAX_ROLE_LENGTH]
        if role and role not in normalized:
            normalized.append(role)
    return sorted(normalized)


def _normalize_approval_requirement(value):
    if not isinstance(value, dict):
        value = {}

    try:
        required_count = int(value.get("required_count", APPROVAL_DEFAULT_REQUIRED_COUNT))
    except (TypeError, ValueError):
        required_count = APPROVAL_DEFAULT_REQUIRED_COUNT

    allowed_roles = _normalize_role_list(value.get("allowed_roles", []))
    required_roles = _normalize_role_list(value.get("required_roles", []))
    required_count = max(required_count, len(required_roles))
    required_count = max(1, min(required_count, APPROVAL_MAX_REQUIRED_COUNT))
    distinct_actors = bool(value.get("distinct_actors", False))
    allow_delegation = bool(value.get("allow_delegation", False))
    require_delegation_reference = bool(
        value.get("require_delegation_reference", False)
    ) and allow_delegation
    prohibit_requester_approval = bool(value.get("prohibit_requester_approval", False))
    prohibit_requester_role_approval = bool(value.get("prohibit_requester_role_approval", False))
    require_requester_context = bool(value.get("require_requester_context", False)) or prohibit_requester_approval or prohibit_requester_role_approval
    require_authoritative_identity = bool(value.get("require_authoritative_identity", False))
    require_cryptographic_attestation = bool(value.get("require_cryptographic_attestation", False))
    require_authoritative_identity = require_authoritative_identity or require_cryptographic_attestation
    require_active_identity = bool(value.get("require_active_identity", False)) and require_authoritative_identity
    identity_provider = str(value.get("identity_provider", "") or "").strip()[:100]
    attestation_algorithm = str(value.get("attestation_algorithm", "") or "").strip()[:100]
    attestation_key_id = str(value.get("attestation_key_id", "") or "").strip()[:200]
    require_attestation_nonce = bool(value.get("require_attestation_nonce", False))
    attestation_issuer = str(value.get("attestation_issuer", "") or "").strip()[:200]
    attestation_audience = str(value.get("attestation_audience", "") or "").strip()[:200]
    attestation_key_statuses = _normalize_role_list(value.get("attestation_key_statuses", []))
    attestation_key_fingerprint = str(value.get("attestation_key_fingerprint", "") or "").strip()[:128].lower()
    require_trusted_attestation_key = bool(value.get("require_trusted_attestation_key", False))

    return {
        "required_count": required_count,
        "distinct_actors": distinct_actors,
        "allowed_roles": allowed_roles,
        "required_roles": required_roles,
        "allow_delegation": allow_delegation,
        "require_delegation_reference": require_delegation_reference,
        "require_requester_context": require_requester_context,
        "prohibit_requester_approval": prohibit_requester_approval,
        "prohibit_requester_role_approval": prohibit_requester_role_approval,
        "require_authoritative_identity": require_authoritative_identity,
        "require_active_identity": require_active_identity,
        "require_cryptographic_attestation": require_cryptographic_attestation,
        "identity_provider": identity_provider,
        "attestation_algorithm": attestation_algorithm,
        "attestation_key_id": attestation_key_id,
        "require_attestation_nonce": require_attestation_nonce and require_cryptographic_attestation,
        "attestation_issuer": attestation_issuer,
        "attestation_audience": attestation_audience,
        "require_trusted_attestation_key": require_trusted_attestation_key,
        "attestation_key_statuses": attestation_key_statuses,
        "attestation_key_fingerprint": attestation_key_fingerprint,
    }


def _approval_requirement_for_codes(codes):
    codes = sorted({
        str(code or "").strip()
        for code in codes or []
        if str(code or "").strip()
    })

    if not codes:
        return {
            "required_count": 0,
            "distinct_actors": False,
            "allowed_roles": [],
            "required_roles": [],
            "allow_delegation": False,
            "require_delegation_reference": False,
            "require_requester_context": False,
            "prohibit_requester_approval": False,
            "prohibit_requester_role_approval": False,
            "require_authoritative_identity": False,
            "require_active_identity": False,
            "require_cryptographic_attestation": False,
            "identity_provider": "",
            "attestation_algorithm": "",
            "attestation_key_id": "",
            "require_attestation_nonce": False,
            "attestation_issuer": "",
            "attestation_audience": "",
            "require_trusted_attestation_key": False,
            "attestation_key_statuses": [],
            "attestation_key_fingerprint": "",
            "codes": [],
        }

    matched = []
    required_count = APPROVAL_DEFAULT_REQUIRED_COUNT
    distinct_actors = False
    required_roles = set()
    role_constraints = []
    allow_delegation = True
    require_delegation_reference = False
    require_requester_context = False
    prohibit_requester_approval = False
    prohibit_requester_role_approval = False
    require_authoritative_identity = False
    require_active_identity = False
    require_cryptographic_attestation = False
    identity_provider_names = []
    attestation_algorithms = []
    attestation_key_ids = []
    attestation_issuers = []
    attestation_audiences = []
    attestation_key_statuses = []
    attestation_key_fingerprints = []
    require_attestation_nonce = False
    require_trusted_attestation_key = False

    for code in codes:
        requirement = _normalize_approval_requirement(
            REPAIR_POLICY_APPROVAL_REQUIREMENTS.get(code)
        )
        matched.append({
            "code": code,
            **requirement,
        })
        required_count = max(required_count, requirement["required_count"])
        distinct_actors = distinct_actors or requirement["distinct_actors"]
        required_roles.update(requirement["required_roles"])
        if requirement["allowed_roles"]:
            role_constraints.append(set(requirement["allowed_roles"]))
        allow_delegation = allow_delegation and requirement["allow_delegation"]
        require_delegation_reference = (
            require_delegation_reference
            or requirement["require_delegation_reference"]
        )
        require_requester_context = require_requester_context or requirement["require_requester_context"]
        prohibit_requester_approval = prohibit_requester_approval or requirement["prohibit_requester_approval"]
        prohibit_requester_role_approval = prohibit_requester_role_approval or requirement["prohibit_requester_role_approval"]
        require_authoritative_identity = require_authoritative_identity or requirement["require_authoritative_identity"]
        require_active_identity = require_active_identity or requirement["require_active_identity"]
        require_cryptographic_attestation = require_cryptographic_attestation or requirement["require_cryptographic_attestation"]
        if requirement["identity_provider"]:
            identity_provider_names.append(requirement["identity_provider"])
        if requirement["attestation_algorithm"]:
            attestation_algorithms.append(requirement["attestation_algorithm"])
        if requirement["attestation_key_id"]:
            attestation_key_ids.append(requirement["attestation_key_id"])
        if requirement["attestation_issuer"]:
            attestation_issuers.append(requirement["attestation_issuer"])
        if requirement["attestation_audience"]:
            attestation_audiences.append(requirement["attestation_audience"])
        attestation_key_statuses.extend(requirement["attestation_key_statuses"])
        if requirement["attestation_key_fingerprint"]:
            attestation_key_fingerprints.append(requirement["attestation_key_fingerprint"])
        require_attestation_nonce = require_attestation_nonce or requirement["require_attestation_nonce"]
        require_trusted_attestation_key = require_trusted_attestation_key or requirement["require_trusted_attestation_key"]

    if role_constraints:
        allowed_roles = set.intersection(*role_constraints)
    else:
        allowed_roles = set()

    required_roles = sorted(required_roles)
    required_count = max(required_count, len(required_roles))
    required_count = min(required_count, APPROVAL_MAX_REQUIRED_COUNT)

    return {
        "required_count": required_count,
        "distinct_actors": distinct_actors,
        "allowed_roles": sorted(allowed_roles),
        "required_roles": required_roles,
        "allow_delegation": allow_delegation,
        "require_delegation_reference": require_delegation_reference and allow_delegation,
        "require_requester_context": require_requester_context,
        "prohibit_requester_approval": prohibit_requester_approval,
        "prohibit_requester_role_approval": prohibit_requester_role_approval,
        "require_authoritative_identity": require_authoritative_identity,
        "require_active_identity": require_active_identity and require_authoritative_identity,
        "require_cryptographic_attestation": require_cryptographic_attestation and require_authoritative_identity,
        "identity_provider": sorted(set(identity_provider_names))[0] if len(set(identity_provider_names)) == 1 else ("MULTIPLE" if identity_provider_names else ""),
        "attestation_algorithm": sorted(set(attestation_algorithms))[0] if len(set(attestation_algorithms)) == 1 else ("MULTIPLE" if attestation_algorithms else ""),
        "attestation_key_id": sorted(set(attestation_key_ids))[0] if len(set(attestation_key_ids)) == 1 else ("MULTIPLE" if attestation_key_ids else ""),
        "require_attestation_nonce": require_attestation_nonce and require_cryptographic_attestation,
        "attestation_issuer": sorted(set(attestation_issuers))[0] if len(set(attestation_issuers)) == 1 else ("MULTIPLE" if attestation_issuers else ""),
        "attestation_audience": sorted(set(attestation_audiences))[0] if len(set(attestation_audiences)) == 1 else ("MULTIPLE" if attestation_audiences else ""),
        "require_trusted_attestation_key": require_trusted_attestation_key,
        "attestation_key_statuses": sorted(set(attestation_key_statuses)),
        "attestation_key_fingerprint": sorted(set(attestation_key_fingerprints))[0] if len(set(attestation_key_fingerprints)) == 1 else ("MULTIPLE" if attestation_key_fingerprints else ""),
        "codes": matched,
    }


def _approval_set_fingerprint(approval_context, approval_requirement=None):
    context = approval_context if isinstance(approval_context, dict) else {}
    requirement = _normalize_approval_requirement(approval_requirement)
    fingerprints = []

    approvals = context.get("approvals")
    if isinstance(approvals, list):
        for item in approvals:
            if isinstance(item, dict):
                fingerprint = str(
                    item.get("fingerprint")
                    or item.get("approval_fingerprint")
                    or ""
                ).strip()
                if fingerprint:
                    fingerprints.append(fingerprint)

    single_fingerprint = str(
        context.get("fingerprint")
        or context.get("approval_fingerprint")
        or ""
    ).strip()
    if not fingerprints and single_fingerprint:
        fingerprints.append(single_fingerprint)

    identity = {
        "required_count": requirement["required_count"],
        "distinct_actors": requirement["distinct_actors"],
        "fingerprints": sorted(set(fingerprints)),
    }
    return hashlib.sha256(
        _canonical_json(identity).encode("utf-8")
    ).hexdigest()


def _policy_snapshot():
    snapshot = {
        "version": REPAIR_POLICY_VERSION,
        "auto_codes": sorted(REPAIR_POLICY_AUTO_CODES),
        "dry_run_only_codes": sorted(REPAIR_POLICY_DRY_RUN_ONLY_CODES),
        "approval_required_codes": sorted(REPAIR_POLICY_APPROVAL_REQUIRED_CODES),
        "approval_requirements": {
            code: _normalize_approval_requirement(
                REPAIR_POLICY_APPROVAL_REQUIREMENTS.get(code)
            )
            for code in sorted(REPAIR_POLICY_APPROVAL_REQUIREMENTS)
        },
        "blocked_codes": sorted(REPAIRABLE_VIOLATION_CODES - REPAIR_POLICY_AUTO_CODES - REPAIR_POLICY_DRY_RUN_ONLY_CODES - REPAIR_POLICY_APPROVAL_REQUIRED_CODES),
    }
    snapshot["fingerprint"] = __import__("hashlib").sha256(
        _canonical_json(snapshot).encode("utf-8")
    ).hexdigest()
    return snapshot


def _current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _approval_identity(context):
    return {
        "schema_version": context.get("schema_version", APPROVAL_SCHEMA_VERSION),
        "approval_id": context.get("approval_id"),
        "actor": context.get("actor"),
        "role": context.get("role"),
        "reason": context.get("reason"),
        "reference": context.get("reference"),
        "delegated_by": context.get("delegated_by"),
        "delegation_reason": context.get("delegation_reason"),
        "delegation_reference": context.get("delegation_reference"),
        "requester_actor": context.get("requester_actor"),
        "requester_role": context.get("requester_role"),
        "requester_reference": context.get("requester_reference"),
        "identity_provider": context.get("identity_provider"),
        "identity_subject": context.get("identity_subject"),
        "identity_roles": context.get("identity_roles"),
        "identity_reference": context.get("identity_reference"),
        "identity_fingerprint": context.get("identity_fingerprint"),
        "identity_status": context.get("identity_status"),
        "identity_active": context.get("identity_active"),
        "identity_revoked": context.get("identity_revoked"),
        "identity_verified_at": context.get("identity_verified_at"),
        "identity_valid_until": context.get("identity_valid_until"),
        "identity_attestation_id": context.get("identity_attestation_id"),
        "identity_attestation_fingerprint": context.get("identity_attestation_fingerprint"),
        "identity_signature_algorithm": context.get("identity_signature_algorithm"),
        "identity_signature_key_id": context.get("identity_signature_key_id"),
        "identity_signature_key_status": context.get("identity_signature_key_status"),
        "identity_signature_key_fingerprint": context.get("identity_signature_key_fingerprint"),
        "identity_attestation_signature": context.get("identity_attestation_signature"),
        "identity_cryptographic_attestation_verified": context.get("identity_cryptographic_attestation_verified"),
        "identity_attestation_signature_fingerprint": context.get("identity_attestation_signature_fingerprint"),
        "identity_attestation_issuer": context.get("identity_attestation_issuer"),
        "identity_attestation_audience": context.get("identity_attestation_audience"),
        "identity_attestation_nonce": context.get("identity_attestation_nonce"),
        "issued_at": context.get("issued_at"),
        "expires_at": context.get("expires_at"),
        "policy_version": context.get("policy_version"),
        "policy_fingerprint": context.get("policy_fingerprint"),
        "repair_plan_fingerprint": context.get("repair_plan_fingerprint"),
        "previous_operation_id": context.get("previous_operation_id"),
        "previous_operation_key": context.get("previous_operation_key"),
    }


def _approval_fingerprint(context):
    return hashlib.sha256(
        _canonical_json(_approval_identity(context)).encode("utf-8")
    ).hexdigest()


def _normalize_single_approval_context(
    approval_context,
    approve=False,
    policy_snapshot=None,
    repair_plan_fingerprint=None,
    repair_epoch=None,
):
    context = approval_context if isinstance(approval_context, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else _policy_snapshot()
    epoch = repair_epoch if isinstance(repair_epoch, dict) else {}

    actor = str(context.get("actor", "") or "").strip()[:200]
    role = str(context.get("role", "") or "").strip()[:APPROVAL_MAX_ROLE_LENGTH]
    reason = str(context.get("reason", "") or "").strip()[:500]
    reference = str(context.get("reference", "") or "").strip()[:200]
    delegated_by = str(context.get("delegated_by", "") or "").strip()[:200]
    delegation_reason = str(context.get("delegation_reason", "") or "").strip()[:500]
    delegation_reference = str(context.get("delegation_reference", "") or "").strip()[:200]
    requester_actor = str(context.get("requester_actor", "") or "").strip()[:200]
    requester_role = str(context.get("requester_role", "") or "").strip()[:APPROVAL_MAX_ROLE_LENGTH]
    requester_reference = str(context.get("requester_reference", "") or "").strip()[:200]
    identity_provider = str(context.get("identity_provider", "") or "").strip()[:100]
    identity_subject = str(context.get("identity_subject", "") or "").strip()[:200]
    identity_roles = context.get("identity_roles", []) if isinstance(context.get("identity_roles", []), list) else []
    identity_roles = sorted({str(item or "").strip()[:APPROVAL_MAX_ROLE_LENGTH] for item in identity_roles if str(item or "").strip()})
    identity_reference = str(context.get("identity_reference", "") or "").strip()[:200]
    identity_fingerprint = str(context.get("identity_fingerprint", "") or "").strip()
    identity_status = str(context.get("identity_status", "") or "").strip().upper()
    identity_active = bool(context.get("identity_active", False))
    identity_revoked = bool(context.get("identity_revoked", False))
    identity_verified_at = str(context.get("identity_verified_at", "") or "").strip()[:100]
    identity_valid_until = str(context.get("identity_valid_until", "") or "").strip()[:100]
    identity_attestation_id = str(context.get("identity_attestation_id", "") or "").strip()[:200]
    identity_attestation_fingerprint = str(context.get("identity_attestation_fingerprint", "") or "").strip()
    identity_signature_algorithm = str(context.get("identity_signature_algorithm", "") or "").strip()[:100]
    identity_signature_key_id = str(context.get("identity_signature_key_id", "") or "").strip()[:200]
    identity_signature_key_status = str(context.get("identity_signature_key_status", "") or "").strip().upper()[:50]
    identity_signature_key_fingerprint = str(context.get("identity_signature_key_fingerprint", "") or "").strip().lower()[:128]
    identity_attestation_signature = str(context.get("identity_attestation_signature", "") or "").strip()[:4096]
    identity_cryptographic_attestation_verified = bool(context.get("identity_cryptographic_attestation_verified", False))
    identity_attestation_signature_fingerprint = str(context.get("identity_attestation_signature_fingerprint", "") or "").strip()
    identity_attestation_issuer = str(context.get("identity_attestation_issuer", "") or "").strip()[:200]
    identity_attestation_audience = str(context.get("identity_attestation_audience", "") or "").strip()[:200]
    identity_attestation_nonce = str(context.get("identity_attestation_nonce", "") or "").strip()[:512]
    approval_id = str(context.get("approval_id", "") or "").strip()[:200]
    issued_at = str(context.get("issued_at", "") or "").strip()
    expires_at = str(context.get("expires_at", "") or "").strip()

    if approve and not approval_id:
        stable = {
            "actor": actor or "explicit_api_approval",
            "role": role,
            "reason": reason or "explicit approve=True",
            "reference": reference,
            "delegated_by": delegated_by,
            "delegation_reason": delegation_reason,
            "delegation_reference": delegation_reference,
            "requester_actor": requester_actor,
            "requester_role": requester_role,
            "requester_reference": requester_reference,
            "identity_provider": identity_provider,
            "identity_subject": identity_subject,
            "identity_roles": identity_roles,
            "identity_reference": identity_reference,
            "identity_fingerprint": identity_fingerprint,
            "identity_status": identity_status,
            "identity_active": identity_active,
            "identity_revoked": identity_revoked,
            "identity_verified_at": identity_verified_at,
            "identity_valid_until": identity_valid_until,
            "identity_attestation_id": identity_attestation_id,
            "identity_attestation_fingerprint": identity_attestation_fingerprint,
            "identity_signature_algorithm": identity_signature_algorithm,
            "identity_signature_key_id": identity_signature_key_id,
            "identity_attestation_signature": identity_attestation_signature,
            "identity_cryptographic_attestation_verified": identity_cryptographic_attestation_verified,
            "identity_attestation_signature_fingerprint": identity_attestation_signature_fingerprint,
            "policy_fingerprint": policy.get("fingerprint"),
            "repair_plan_fingerprint": repair_plan_fingerprint,
            "previous_operation_id": epoch.get("operation_id"),
            "previous_operation_key": epoch.get("operation_key"),
        }
        approval_id = "approval_" + hashlib.sha256(
            _canonical_json(stable).encode("utf-8")
        ).hexdigest()[:16]

    if approve and not issued_at:
        issued_at = _current_timestamp()

    if approve and not expires_at:
        issued = _parse_timestamp(issued_at)
        if issued is None:
            issued = datetime.now(timezone.utc)
            issued_at = issued.isoformat()
        expires_at = (issued + timedelta(seconds=APPROVAL_DEFAULT_TTL_SECONDS)).isoformat()

    normalized = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "approved": bool(approve),
        "approval_id": approval_id or None,
        "actor": actor or None,
        "role": role or None,
        "reason": reason or None,
        "reference": reference or None,
        "delegated_by": delegated_by or None,
        "delegation_reason": delegation_reason or None,
        "delegation_reference": delegation_reference or None,
        "requester_actor": requester_actor or None,
        "requester_role": requester_role or None,
        "requester_reference": requester_reference or None,
        "identity_provider": identity_provider or None,
        "identity_subject": identity_subject or None,
        "identity_roles": identity_roles,
        "identity_reference": identity_reference or None,
        "identity_fingerprint": identity_fingerprint or None,
        "identity_status": identity_status or None,
        "identity_active": identity_active,
        "identity_revoked": identity_revoked,
        "identity_verified_at": identity_verified_at or None,
        "identity_valid_until": identity_valid_until or None,
        "identity_attestation_id": identity_attestation_id or None,
        "identity_attestation_fingerprint": identity_attestation_fingerprint or None,
        "identity_signature_algorithm": identity_signature_algorithm or None,
        "identity_signature_key_id": identity_signature_key_id or None,
        "identity_signature_key_status": identity_signature_key_status or None,
        "identity_signature_key_fingerprint": identity_signature_key_fingerprint or None,
        "identity_attestation_signature": identity_attestation_signature or None,
        "identity_cryptographic_attestation_verified": identity_cryptographic_attestation_verified,
        "identity_attestation_signature_fingerprint": identity_attestation_signature_fingerprint or None,
        "identity_attestation_issuer": identity_attestation_issuer or None,
        "identity_attestation_audience": identity_attestation_audience or None,
        "identity_attestation_nonce": identity_attestation_nonce or None,
        "issued_at": issued_at or None,
        "expires_at": expires_at or None,
        "policy_version": context.get("policy_version") or policy.get("version"),
        "policy_fingerprint": context.get("policy_fingerprint") or policy.get("fingerprint"),
        "repair_plan_fingerprint": context.get("repair_plan_fingerprint") or repair_plan_fingerprint,
        "previous_operation_id": context.get("previous_operation_id") or epoch.get("operation_id"),
        "previous_operation_key": context.get("previous_operation_key") or epoch.get("operation_key"),
    }

    normalized["fingerprint"] = _approval_fingerprint(normalized)
    return normalized


def _normalize_approval_context(
    approval_context,
    approve=False,
    policy_snapshot=None,
    repair_plan_fingerprint=None,
    repair_epoch=None,
    approval_requirement=None,
):
    context = approval_context if isinstance(approval_context, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else _policy_snapshot()
    requirement = _normalize_approval_requirement(approval_requirement)

    raw_approvals = context.get("approvals")
    requester_defaults = {
        "requester_actor": context.get("requester_actor", ""),
        "requester_role": context.get("requester_role", ""),
        "requester_reference": context.get("requester_reference", ""),
    }
    if isinstance(raw_approvals, list):
        approvals = [
            _normalize_single_approval_context(
                {**requester_defaults, **item},
                approve=approve,
                policy_snapshot=policy,
                repair_plan_fingerprint=repair_plan_fingerprint,
                repair_epoch=repair_epoch,
            )
            for item in raw_approvals
            if isinstance(item, dict)
        ]
    elif context or approve:
        approvals = [
            _normalize_single_approval_context(
                context,
                approve=approve,
                policy_snapshot=policy,
                repair_plan_fingerprint=repair_plan_fingerprint,
                repair_epoch=repair_epoch,
            )
        ]
    else:
        approvals = []

    aggregate_fingerprint = _approval_set_fingerprint(
        {"approvals": approvals},
        requirement,
    )

    normalized = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "approved": bool(approve) and bool(approvals),
        "approvals": approvals,
        "approval_count": len(approvals),
        "required_approvals": requirement["required_count"],
        "distinct_actors_required": requirement["distinct_actors"],
        "fingerprint": aggregate_fingerprint,
    }

    if len(approvals) == 1:
        normalized.update({
            "approval_id": approvals[0].get("approval_id"),
            "actor": approvals[0].get("actor"),
            "role": approvals[0].get("role"),
            "reason": approvals[0].get("reason"),
            "reference": approvals[0].get("reference"),
            "delegated_by": approvals[0].get("delegated_by"),
            "delegation_reason": approvals[0].get("delegation_reason"),
            "delegation_reference": approvals[0].get("delegation_reference"),
            "requester_actor": approvals[0].get("requester_actor"),
            "requester_role": approvals[0].get("requester_role"),
            "requester_reference": approvals[0].get("requester_reference"),
            "identity_provider": approvals[0].get("identity_provider"),
            "identity_subject": approvals[0].get("identity_subject"),
            "identity_roles": approvals[0].get("identity_roles", []),
            "identity_reference": approvals[0].get("identity_reference"),
            "identity_fingerprint": approvals[0].get("identity_fingerprint"),
            "issued_at": approvals[0].get("issued_at"),
            "expires_at": approvals[0].get("expires_at"),
            "policy_version": approvals[0].get("policy_version"),
            "policy_fingerprint": approvals[0].get("policy_fingerprint"),
            "repair_plan_fingerprint": approvals[0].get("repair_plan_fingerprint"),
            "previous_operation_id": approvals[0].get("previous_operation_id"),
            "previous_operation_key": approvals[0].get("previous_operation_key"),
            "approval_fingerprint": approvals[0].get("fingerprint"),
        })
    else:
        normalized.update({
            "approval_id": None,
            "actor": None,
            "reason": None,
            "reference": None,
            "issued_at": None,
            "expires_at": None,
            "policy_version": policy.get("version"),
            "policy_fingerprint": policy.get("fingerprint"),
            "repair_plan_fingerprint": repair_plan_fingerprint,
            "previous_operation_id": (approvals[0].get("previous_operation_id") if approvals else None),
            "previous_operation_key": (approvals[0].get("previous_operation_key") if approvals else None),
            "approval_fingerprint": None,
            "requester_actor": (approvals[0].get("requester_actor") if approvals else None),
            "requester_role": (approvals[0].get("requester_role") if approvals else None),
            "requester_reference": (approvals[0].get("requester_reference") if approvals else None),
            "identity_provider": (approvals[0].get("identity_provider") if approvals else None),
            "identity_subject": (approvals[0].get("identity_subject") if approvals else None),
            "identity_roles": (approvals[0].get("identity_roles", []) if approvals else []),
            "identity_reference": (approvals[0].get("identity_reference") if approvals else None),
            "identity_fingerprint": (approvals[0].get("identity_fingerprint") if approvals else None),
            "identity_signature_algorithm": (approvals[0].get("identity_signature_algorithm") if approvals else None),
            "identity_signature_key_id": (approvals[0].get("identity_signature_key_id") if approvals else None),
            "identity_attestation_signature": (approvals[0].get("identity_attestation_signature") if approvals else None),
            "identity_cryptographic_attestation_verified": (approvals[0].get("identity_cryptographic_attestation_verified") if approvals else False),
            "identity_attestation_signature_fingerprint": (approvals[0].get("identity_attestation_signature_fingerprint") if approvals else None),
            "identity_attestation_issuer": (approvals[0].get("identity_attestation_issuer") if approvals else None),
            "identity_attestation_audience": (approvals[0].get("identity_attestation_audience") if approvals else None),
            "identity_attestation_nonce": (approvals[0].get("identity_attestation_nonce") if approvals else None),
            "approval_set_fingerprint": aggregate_fingerprint,
        })

    normalized["approval_set_fingerprint"] = aggregate_fingerprint
    return normalized


def _approval_trace(approval_context, policy_snapshot):
    context = approval_context if isinstance(approval_context, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else {}
    raw_approvals = context.get("approvals")

    if isinstance(raw_approvals, list):
        traces = []
        for item in raw_approvals:
            if not isinstance(item, dict):
                continue
            traces.append({
                "schema_version": item.get("schema_version", APPROVAL_SCHEMA_VERSION),
                "approved": bool(item.get("approved")),
                "approval_id": item.get("approval_id"),
                "actor": item.get("actor"),
                "role": item.get("role"),
                "reason": item.get("reason"),
                "reference": item.get("reference"),
                "delegated_by": item.get("delegated_by"),
                "delegation_reason": item.get("delegation_reason"),
                "delegation_reference": item.get("delegation_reference"),
                "requester_actor": item.get("requester_actor"),
                "requester_role": item.get("requester_role"),
                "requester_reference": item.get("requester_reference"),
                "identity_provider": item.get("identity_provider"),
                "identity_subject": item.get("identity_subject"),
                "identity_roles": item.get("identity_roles", []),
                "identity_reference": item.get("identity_reference"),
                "identity_fingerprint": item.get("identity_fingerprint"),
                "identity_status": item.get("identity_status"),
                "identity_active": item.get("identity_active"),
                "identity_revoked": item.get("identity_revoked"),
                "identity_verified_at": item.get("identity_verified_at"),
                "identity_valid_until": item.get("identity_valid_until"),
                "identity_attestation_id": item.get("identity_attestation_id"),
                "identity_attestation_fingerprint": item.get("identity_attestation_fingerprint"),
                "identity_signature_algorithm": item.get("identity_signature_algorithm"),
                "identity_signature_key_id": item.get("identity_signature_key_id"),
                "identity_signature_key_status": item.get("identity_signature_key_status"),
                "identity_signature_key_fingerprint": item.get("identity_signature_key_fingerprint"),
                "identity_attestation_signature": item.get("identity_attestation_signature"),
                "identity_cryptographic_attestation_verified": item.get("identity_cryptographic_attestation_verified"),
                "identity_attestation_signature_fingerprint": item.get("identity_attestation_signature_fingerprint"),
                "identity_attestation_issuer": item.get("identity_attestation_issuer"),
                "identity_attestation_audience": item.get("identity_attestation_audience"),
                "identity_attestation_nonce": item.get("identity_attestation_nonce"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
                "policy_version": item.get("policy_version") or policy.get("version"),
                "policy_fingerprint": item.get("policy_fingerprint") or policy.get("fingerprint"),
                "repair_plan_fingerprint": item.get("repair_plan_fingerprint"),
                "previous_operation_id": item.get("previous_operation_id"),
                "previous_operation_key": item.get("previous_operation_key"),
                "approval_fingerprint": item.get("fingerprint") or item.get("approval_fingerprint"),
            })

        trace = {
            "schema_version": context.get("schema_version", APPROVAL_SCHEMA_VERSION),
            "approved": bool(context.get("approved")),
            "approvals": traces,
            "approval_count": len(traces),
            "required_approvals": context.get("required_approvals", 0),
            "distinct_actors_required": bool(context.get("distinct_actors_required")),
            "approval_roles": sorted({
                str(item.get("role", "") or "").strip()
                for item in traces
                if str(item.get("role", "") or "").strip()
            }),
            "delegated_approvals": sorted({
                str(item.get("approval_id", "") or "").strip()
                for item in traces
                if str(item.get("delegated_by", "") or "").strip()
            }),
            "requester_actor": context.get("requester_actor") or (traces[0].get("requester_actor") if traces else None),
            "requester_role": context.get("requester_role") or (traces[0].get("requester_role") if traces else None),
            "requester_reference": context.get("requester_reference") or (traces[0].get("requester_reference") if traces else None),
            "approval_set_fingerprint": context.get("approval_set_fingerprint") or context.get("fingerprint"),
        }
        if len(traces) == 1:
            trace.update(traces[0])
        return trace

    return {
        "schema_version": context.get("schema_version", APPROVAL_SCHEMA_VERSION),
        "approved": bool(context.get("approved")),
        "approval_id": context.get("approval_id"),
        "actor": context.get("actor"),
        "role": context.get("role"),
        "reason": context.get("reason"),
        "reference": context.get("reference"),
        "delegated_by": context.get("delegated_by"),
        "delegation_reason": context.get("delegation_reason"),
        "delegation_reference": context.get("delegation_reference"),
        "requester_actor": context.get("requester_actor"),
        "requester_role": context.get("requester_role"),
        "requester_reference": context.get("requester_reference"),
        "identity_provider": context.get("identity_provider"),
        "identity_subject": context.get("identity_subject"),
        "identity_roles": context.get("identity_roles"),
        "identity_reference": context.get("identity_reference"),
        "identity_fingerprint": context.get("identity_fingerprint"),
        "identity_status": context.get("identity_status"),
        "identity_active": context.get("identity_active"),
        "identity_revoked": context.get("identity_revoked"),
        "identity_verified_at": context.get("identity_verified_at"),
        "identity_valid_until": context.get("identity_valid_until"),
        "identity_attestation_id": context.get("identity_attestation_id"),
        "identity_attestation_fingerprint": context.get("identity_attestation_fingerprint"),
        "identity_signature_algorithm": context.get("identity_signature_algorithm"),
        "identity_signature_key_id": context.get("identity_signature_key_id"),
        "identity_attestation_signature": context.get("identity_attestation_signature"),
        "identity_cryptographic_attestation_verified": context.get("identity_cryptographic_attestation_verified"),
        "identity_attestation_signature_fingerprint": context.get("identity_attestation_signature_fingerprint"),
        "issued_at": context.get("issued_at"),
        "expires_at": context.get("expires_at"),
        "policy_version": context.get("policy_version") or policy.get("version"),
        "policy_fingerprint": context.get("policy_fingerprint") or policy.get("fingerprint"),
        "repair_plan_fingerprint": context.get("repair_plan_fingerprint"),
        "previous_operation_id": context.get("previous_operation_id"),
        "previous_operation_key": context.get("previous_operation_key"),
        "approval_fingerprint": context.get("fingerprint") or context.get("approval_fingerprint"),
        "required_approvals": context.get("required_approvals", 1),
        "distinct_actors_required": bool(context.get("distinct_actors_required")),
        "approval_set_fingerprint": context.get("approval_set_fingerprint") or context.get("fingerprint"),
    }


# ==================================================
# General Helpers
# ==================================================


def _append_unique(items, value):
    if value not in items:
        items.append(value)


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default


def _save_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory or None,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass



def _snapshot_files(base_path):
    """Return deterministic content snapshots for files under one project path."""
    base_path = os.path.abspath(base_path)
    snapshot = {}

    for root, _, files in os.walk(base_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            relative_path = os.path.relpath(full_path, base_path)
            try:
                with open(full_path, "rb") as file:
                    content = file.read()
            except OSError:
                continue
            snapshot[relative_path] = content

    return snapshot


def _changed_snapshot_files(before_snapshot, after_snapshot):
    changed = []
    all_paths = sorted(set(before_snapshot) | set(after_snapshot))

    for relative_path in all_paths:
        if before_snapshot.get(relative_path) != after_snapshot.get(relative_path):
            changed.append(relative_path)

    return changed


def _json_value_change_plan(before, after, path="$", changes=None, max_changes=200):
    """Build a bounded, human-readable JSON field change plan."""
    if changes is None:
        changes = []

    if len(changes) >= max_changes:
        return changes

    if type(before) is not type(after):
        changes.append({
            "path": path,
            "change_type": "type_changed",
            "before": before,
            "after": after,
        })
        return changes

    if isinstance(before, dict):
        keys = sorted(set(before) | set(after), key=str)
        for key in keys:
            child_path = f"{path}.{key}"
            if key not in before:
                changes.append({
                    "path": child_path,
                    "change_type": "added",
                    "before": None,
                    "after": after[key],
                })
            elif key not in after:
                changes.append({
                    "path": child_path,
                    "change_type": "removed",
                    "before": before[key],
                    "after": None,
                })
            else:
                _json_value_change_plan(
                    before[key],
                    after[key],
                    child_path,
                    changes,
                    max_changes=max_changes,
                )

            if len(changes) >= max_changes:
                break
        return changes

    if isinstance(before, list):
        if len(before) > 50 or len(after) > 50:
            if before != after:
                changes.append({
                    "path": path,
                    "change_type": "collection_rebuilt",
                    "before_count": len(before),
                    "after_count": len(after),
                    "detail": "Large collection changed; individual elements omitted for bounded audit size.",
                })
            return changes

        max_length = max(len(before), len(after))
        for index in range(max_length):
            child_path = f"{path}[{index}]"
            if index >= len(before):
                changes.append({
                    "path": child_path,
                    "change_type": "added",
                    "before": None,
                    "after": after[index],
                })
            elif index >= len(after):
                changes.append({
                    "path": child_path,
                    "change_type": "removed",
                    "before": before[index],
                    "after": None,
                })
            else:
                _json_value_change_plan(
                    before[index],
                    after[index],
                    child_path,
                    changes,
                    max_changes=max_changes,
                )

            if len(changes) >= max_changes:
                break
        return changes

    if before != after:
        changes.append({
            "path": path,
        "change_type": "value_changed",
        "before": before,
        "after": after,
    })

    return changes


def _build_repair_plan(before_snapshot, after_snapshot, repairable_codes):
    """Explain exactly which persisted JSON fields a repair would change."""
    plan = []
    all_paths = sorted(set(before_snapshot) | set(after_snapshot))

    for relative_path in all_paths:
        before_bytes = before_snapshot.get(relative_path)
        after_bytes = after_snapshot.get(relative_path)

        if before_bytes == after_bytes:
            continue

        if relative_path == "memory_operations.json":
            # The operation journal is managed by the idempotency layer. Do not
            # attribute its own transaction bookkeeping to the repair plan.
            continue

        item = {
            "file": relative_path.replace(os.sep, "/"),
            "repair_codes": sorted(set(repairable_codes or [])),
        }

        if before_bytes is None:
            item["change_type"] = "file_added"
            item["changes"] = []
            plan.append(item)
            continue

        if after_bytes is None:
            item["change_type"] = "file_removed"
            item["changes"] = []
            plan.append(item)
            continue

        if relative_path.lower().endswith(".json"):
            try:
                before_data = json.loads(before_bytes.decode("utf-8"))
                after_data = json.loads(after_bytes.decode("utf-8"))
                changes = _json_value_change_plan(before_data, after_data)
                item["change_type"] = "json_fields_changed"
                item["changes"] = changes
                item["change_count"] = len(changes)
            except (UnicodeDecodeError, json.JSONDecodeError):
                item["change_type"] = "file_content_changed"
                item["changes"] = [{
                    "path": "$",
                    "change_type": "binary_or_non_json_content_changed",
                }]
        else:
            item["change_type"] = "file_content_changed"
            item["changes"] = [{
                "path": "$",
                "change_type": "content_changed",
            }]

        plan.append(item)

    return {
        "files": plan,
        "file_count": len(plan),
        "change_count": sum(
            int(item.get("change_count", len(item.get("changes", []))))
            for item in plan
        ),
    }


def _simulate_repair(base_path, repairable_codes):
    """Apply a repair plan to an isolated temporary copy and report its impact."""
    base_path = os.path.abspath(base_path)
    temporary_parent = tempfile.mkdtemp(prefix="reconciliation_dry_run_")
    simulation_path = os.path.join(temporary_parent, "project")

    try:
        shutil.copytree(base_path, simulation_path)

        before_snapshot = _snapshot_files(simulation_path)
        repair = _apply_repairs(simulation_path, repairable_codes)
        simulated_after = inspect_reconciliation(simulation_path)
        after_snapshot = _snapshot_files(simulation_path)

        return {
            "repair": repair,
            "simulated_after": simulated_after,
            "files_would_change": _changed_snapshot_files(
                before_snapshot,
                after_snapshot,
            ),
            "repair_plan": _build_repair_plan(
                before_snapshot,
                after_snapshot,
                repairable_codes,
            ),
        }
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)


@contextmanager
def _project_directory(base_path):
    """Run project-relative repair helpers against one isolated project path."""
    previous = os.getcwd()
    os.chdir(os.path.abspath(base_path))
    try:
        yield
    finally:
        os.chdir(previous)


# ==================================================
# Violation Classification
# ==================================================


def classify_violations(report):
    """Separate deterministic repair candidates from protected violations."""
    violations = report.get("violations", []) if isinstance(report, dict) else []
    repairable = []
    blocked = []

    for violation in violations:
        if not isinstance(violation, dict):
            blocked.append({
                "code": "INVALID_VIOLATION_RECORD",
                "message": "Invariant report contains an invalid violation record.",
                "context": {},
            })
            continue

        code = str(violation.get("code", "") or "").strip()
        target = repairable if code in REPAIRABLE_VIOLATION_CODES else blocked
        target.append(dict(violation))

    return {
        "repairable": repairable,
        "blocked": blocked,
        "repairable_codes": sorted({
            str(item.get("code", ""))
            for item in repairable
            if item.get("code")
        }),
        "blocked_codes": sorted({
            str(item.get("code", ""))
            for item in blocked
            if item.get("code")
        }),
    }


def inspect_reconciliation(base_path="."):
    """Return the invariant state plus a deterministic repair classification."""
    base_path = os.path.abspath(base_path)
    report = validate_invariants(base_path)
    classification = classify_violations(report)

    return {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "base_path": base_path,
        "valid": bool(report.get("valid")),
        "violations": list(report.get("violations", [])),
        "counts": dict(report.get("counts", {})),
        "repairable": classification["repairable"],
        "blocked": classification["blocked"],
        "repairable_codes": classification["repairable_codes"],
        "blocked_codes": classification["blocked_codes"],
    }


def evaluate_repair_policy(inspection):
    """Determine how each repairable violation may be executed safely.

    Unknown policy mappings fail closed. This keeps future/destructive repair
    types from becoming automatically executable merely because they were
    added to invariant classification.
    """
    inspection = inspection if isinstance(inspection, dict) else {}
    codes = sorted({
        str(code or "").strip()
        for code in inspection.get("repairable_codes", [])
        if str(code or "").strip()
    })

    decisions = []
    auto_codes = []
    dry_run_only_codes = []
    approval_required_codes = []
    blocked_policy_codes = []

    for code in codes:
        if code in REPAIR_POLICY_APPROVAL_REQUIRED_CODES:
            policy = REPAIR_POLICY_APPROVAL_REQUIRED
            approval_required_codes.append(code)
        elif code in REPAIR_POLICY_DRY_RUN_ONLY_CODES:
            policy = REPAIR_POLICY_DRY_RUN_ONLY
            dry_run_only_codes.append(code)
        elif code in REPAIR_POLICY_AUTO_CODES:
            policy = REPAIR_POLICY_AUTO
            auto_codes.append(code)
        else:
            policy = REPAIR_POLICY_BLOCKED
            blocked_policy_codes.append(code)

        decisions.append({
            "code": code,
            "policy": policy,
        })

    if blocked_policy_codes:
        effective_policy = REPAIR_POLICY_BLOCKED
    elif approval_required_codes:
        effective_policy = REPAIR_POLICY_APPROVAL_REQUIRED
    elif dry_run_only_codes:
        effective_policy = REPAIR_POLICY_DRY_RUN_ONLY
    elif auto_codes:
        effective_policy = REPAIR_POLICY_AUTO
    else:
        effective_policy = REPAIR_POLICY_BLOCKED

    policy_snapshot = _policy_snapshot()
    approval_requirement = _approval_requirement_for_codes(approval_required_codes)

    return {
        "effective_policy": effective_policy,
        "policy_version": policy_snapshot["version"],
        "policy_fingerprint": policy_snapshot["fingerprint"],
        "policy_snapshot": policy_snapshot,
        "decisions": decisions,
        "auto_codes": auto_codes,
        "dry_run_only_codes": dry_run_only_codes,
        "approval_required_codes": approval_required_codes,
        "blocked_policy_codes": blocked_policy_codes,
        "requires_approval": bool(approval_required_codes),
        "requires_dry_run": bool(dry_run_only_codes),
        "approval_requirement": approval_requirement,
        "policy_safe_to_auto_repair": effective_policy == REPAIR_POLICY_AUTO,
    }


# ==================================================
# Direct Canonical Repairs
# ==================================================


def _repair_memory_archive_status(base_path):
    path = os.path.join(base_path, "memory_archive.json")
    data = _load_json(path, [])

    if not isinstance(data, list):
        return 0

    changed = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "archived") or "archived").strip().lower()
        if status != "archived":
            item["status"] = "archived"
            changed += 1

    if changed:
        _save_json(path, data)

    return changed


def _repair_entity_archive_state(base_path):
    path = os.path.join(base_path, "memory_entities_archive.json")
    data = _load_json(path, {"entities": []})

    if not isinstance(data, dict):
        return 0

    entities = data.get("entities")
    if not isinstance(entities, list):
        return 0

    changed = 0
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        state = str(entity.get("archive_state", "ARCHIVED") or "ARCHIVED").strip().upper()
        if state != "ARCHIVED":
            entity["archive_state"] = "ARCHIVED"
            changed += 1

    if changed:
        _save_json(path, data)

    return changed


def _repair_authoritative_memory_references(base_path):
    """Canonicalize Entity/Relation memory_ids against real Memory IDs.

    Memory active/archive stores are authoritative for Memory identity. This
    repair only removes malformed, duplicate, empty or orphan references; it
    never creates Memory records or changes Entity identity.
    """
    memory_active = _load_json(os.path.join(base_path, "memory.json"), [])
    memory_archive = _load_json(os.path.join(base_path, "memory_archive.json"), [])
    entity_active_path = os.path.join(base_path, "memory_entities.json")
    entity_archive_path = os.path.join(base_path, "memory_entities_archive.json")
    relation_path = os.path.join(base_path, "memory_entity_relations.json")

    if not isinstance(memory_active, list):
        memory_active = []
    if not isinstance(memory_archive, list):
        memory_archive = []

    memory_ids = {
        str(item.get("memory_id", "") or "").strip()
        for item in memory_active + memory_archive
        if isinstance(item, dict) and str(item.get("memory_id", "") or "").strip()
    }

    entity_active = _load_json(entity_active_path, {"entities": []})
    entity_archive = _load_json(entity_archive_path, {"entities": []})
    relation_store = _load_json(relation_path, {"relations": []})

    if not isinstance(entity_active, dict):
        entity_active = {"entities": []}
    if not isinstance(entity_archive, dict):
        entity_archive = {"entities": []}
    if not isinstance(relation_store, dict):
        relation_store = {"relations": []}

    details = {
        "entity_reference_items_fixed": 0,
        "entity_reference_count_removed": 0,
        "relation_reference_items_fixed": 0,
        "relation_reference_count_removed": 0,
    }

    def canonicalize_references(value):
        if not isinstance(value, list):
            return [], True, max(0, len(value)) if isinstance(value, (tuple, set)) else 0

        normalized = []
        seen = set()
        removed = 0

        for item in value:
            memory_id = str(item or "").strip()
            if not memory_id or memory_id not in memory_ids or memory_id in seen:
                removed += 1
                continue
            normalized.append(memory_id)
            seen.add(memory_id)

        return normalized, normalized != value, removed

    for store in (entity_active, entity_archive):
        entities = store.get("entities")
        if not isinstance(entities, list):
            continue

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            normalized, changed, removed = canonicalize_references(entity.get("memory_ids"))
            if changed or not isinstance(entity.get("memory_ids"), list):
                entity["memory_ids"] = normalized
                details["entity_reference_items_fixed"] += 1
            details["entity_reference_count_removed"] += removed

    relations = relation_store.get("relations")
    if isinstance(relations, list):
        for relation in relations:
            if not isinstance(relation, dict):
                continue

            normalized, changed, removed = canonicalize_references(relation.get("memory_ids"))
            if changed or not isinstance(relation.get("memory_ids"), list):
                relation["memory_ids"] = normalized
                details["relation_reference_items_fixed"] += 1
            details["relation_reference_count_removed"] += removed

    if details["entity_reference_items_fixed"]:
        _save_json(entity_active_path, entity_active)
        _save_json(entity_archive_path, entity_archive)

    if details["relation_reference_items_fixed"]:
        _save_json(relation_path, relation_store)

    details["changed"] = any(
        details[key] > 0
        for key in (
            "entity_reference_items_fixed",
            "relation_reference_items_fixed",
        )
    )
    return details


def _repair_completed_operation_leases(base_path):
    path = os.path.join(base_path, "memory_operations.json")
    data = _load_json(path, {"operations": []})

    if not isinstance(data, dict):
        return 0

    operations = data.get("operations")
    if not isinstance(operations, list):
        return 0

    changed = 0
    for item in operations:
        if not isinstance(item, dict):
            continue

        status = str(item.get("status", "") or "").strip().upper()
        if status == "COMPLETED" and item.get("lease_expires_at"):
            item["lease_expires_at"] = None
            changed += 1

    if changed:
        _save_json(path, data)

    return changed


# ==================================================
# Deterministic Repair Engine
# ==================================================


def _normalize_id_list(value):
    if not isinstance(value, list):
        return []
    result = []
    seen = set()
    for item in value:
        item = str(item or "").strip()
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _graph_add_edge(edges, seen, source, target, edge_type, relation="", confidence=1.0, evidence=""):
    source = str(source or "").strip()
    target = str(target or "").strip()
    edge_type = str(edge_type or "").strip().upper()
    if not source or not target or source == target or not edge_type:
        return

    key = (source, target, edge_type, str(relation or "").strip().upper())
    if key in seen:
        return

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    edges.append({
        "source": source,
        "target": target,
        "type": edge_type,
        "relation": str(relation or "").strip().upper(),
        "confidence": round(confidence, 4),
        "evidence": str(evidence or "").strip()[:500],
    })
    seen.add(key)


def _repair_graph_and_derived_links(base_path):
    """Rebuild the derived graph directly from authoritative JSON stores.

    This deliberately does not import the embedding layer. Reconciliation is
    a recovery path and must remain usable when optional ML dependencies are
    unavailable.
    """
    memory_active = _load_json(os.path.join(base_path, "memory.json"), [])
    memory_archive = _load_json(os.path.join(base_path, "memory_archive.json"), [])
    entity_active = _load_json(os.path.join(base_path, "memory_entities.json"), {"entities": []})
    entity_archive = _load_json(os.path.join(base_path, "memory_entities_archive.json"), {"entities": []})
    relation_store = _load_json(os.path.join(base_path, "memory_entity_relations.json"), {"relations": []})

    if not isinstance(memory_active, list):
        memory_active = []
    if not isinstance(memory_archive, list):
        memory_archive = []

    if not isinstance(entity_active, dict):
        entity_active = {"entities": []}
    if not isinstance(entity_archive, dict):
        entity_archive = {"entities": []}
    if not isinstance(relation_store, dict):
        relation_store = {"relations": []}

    archived_memory_ids = {
        str(item.get("memory_id", "") or "").strip()
        for item in memory_archive
        if isinstance(item, dict) and str(item.get("memory_id", "") or "").strip()
    }
    all_memories = memory_active + memory_archive
    memory_ids = {
        str(item.get("memory_id", "") or "").strip()
        for item in all_memories
        if isinstance(item, dict) and str(item.get("memory_id", "") or "").strip()
    }

    entities = []
    entity_by_id = {}
    for source, default_archive_state in (
        (entity_active.get("entities", []), "ACTIVE"),
        (entity_archive.get("entities", []), "ARCHIVED"),
    ):
        if not isinstance(source, list):
            continue
        for entity in source:
            if not isinstance(entity, dict):
                continue
            entity_id = str(entity.get("entity_id", "") or "").strip()
            if not entity_id:
                continue
            entity_by_id[entity_id] = dict(entity)
            entity_by_id[entity_id].setdefault("archive_state", default_archive_state)

    nodes = []
    edges = []
    seen_edges = set()

    for item in all_memories:
        if not isinstance(item, dict):
            continue
        memory_id = str(item.get("memory_id", "") or "").strip()
        if not memory_id:
            continue
        try:
            importance = int(item.get("importance", 1) or 1)
        except (TypeError, ValueError):
            importance = 1
        try:
            confidence = float(item.get("confidence", 0.5) or 0.5)
        except (TypeError, ValueError):
            confidence = 0.5
        nodes.append({
            "id": memory_id,
            "kind": "memory",
            "memory": item.get("memory", ""),
            "type": item.get("type", item.get("memory_type", "other")),
            "importance": max(0, importance),
            "confidence": max(0.0, min(1.0, confidence)),
            "status": "archived" if memory_id in archived_memory_ids else item.get("status", "active"),
            "temporal_status": item.get("temporal_status", "current"),
            "chain_id": item.get("chain_id"),
            "version": int(item.get("version", 1) or 1) if str(item.get("version", 1) or 1).isdigit() else 1,
            "valid_from": item.get("valid_from"),
            "valid_to": item.get("valid_to"),
        })

    for entity_id, entity in entity_by_id.items():
        try:
            mention_count = max(0, int(entity.get("mention_count", 0) or 0))
        except (TypeError, ValueError):
            mention_count = 0
        try:
            confidence = float(entity.get("confidence", 0.7) or 0.7)
        except (TypeError, ValueError):
            confidence = 0.7

        memory_refs = [mid for mid in _normalize_id_list(entity.get("memory_ids")) if mid in memory_ids]
        nodes.append({
            "id": entity_id,
            "kind": "entity",
            "name": entity.get("name", ""),
            "canonical_name": entity.get("canonical_name", ""),
            "type": entity.get("type", "OTHER"),
            "confidence": max(0.0, min(1.0, confidence)),
            "mention_count": mention_count,
            "memory_ids": memory_refs,
            "entity_chain_id": entity.get("entity_chain_id", entity_id),
            "version": entity.get("version", 1),
            "valid_from": entity.get("valid_from"),
            "valid_to": entity.get("valid_to"),
            "temporal_status": entity.get("temporal_status", "current"),
            "history_versions": len(entity.get("history", [])) if isinstance(entity.get("history"), list) else 0,
            "lifecycle_status": entity.get("lifecycle_status", "ACTIVE"),
            "lifecycle_score": entity.get("lifecycle_score", 0.0),
            "archive_state": entity.get("archive_state", "ACTIVE"),
            "archived_at": entity.get("archived_at"),
            "archive_reason": entity.get("archive_reason", ""),
        })

        for memory_id in memory_refs:
            _graph_add_edge(
                edges,
                seen_edges,
                memory_id,
                entity_id,
                "MEMORY_HAS_ENTITY",
                relation="MENTIONS",
                confidence=confidence,
                evidence="entity memory reference",
            )

    valid_entity_ids = set(entity_by_id)

    relations = relation_store.get("relations", [])
    if isinstance(relations, list):
        for relation_item in relations:
            if not isinstance(relation_item, dict):
                continue
            source = str(relation_item.get("source_entity_id", "") or "").strip()
            target = str(relation_item.get("target_entity_id", "") or "").strip()
            if source not in valid_entity_ids or target not in valid_entity_ids or source == target:
                continue

            relation = relation_item.get("relation", "RELATED_TO")
            confidence = relation_item.get("confidence", 0.7)
            evidence = relation_item.get("evidence", "entity relation")
            _graph_add_edge(
                edges,
                seen_edges,
                source,
                target,
                "ENTITY_RELATION",
                relation=relation,
                confidence=confidence,
                evidence=evidence,
            )

            if not relation_item.get("directed", True):
                _graph_add_edge(
                    edges,
                    seen_edges,
                    target,
                    source,
                    "ENTITY_RELATION",
                    relation=relation,
                    confidence=confidence,
                    evidence=evidence,
                )

    for item in all_memories:
        if not isinstance(item, dict):
            continue
        source_id = str(item.get("memory_id", "") or "").strip()
        if not source_id or source_id not in memory_ids:
            continue

        supersedes = str(item.get("supersedes", "") or "").strip()
        if supersedes in memory_ids:
            _graph_add_edge(edges, seen_edges, source_id, supersedes, "TEMPORAL_SUPERSEDES", relation="SUPERSEDES", evidence="temporal metadata")

        superseded_by = str(item.get("superseded_by", "") or "").strip()
        if superseded_by in memory_ids:
            _graph_add_edge(edges, seen_edges, source_id, superseded_by, "TEMPORAL_SUPERSEDES", relation="SUPERSEDED_BY", evidence="temporal metadata")

        for related_id in _normalize_id_list(item.get("derived_from")):
            if related_id in memory_ids:
                _graph_add_edge(edges, seen_edges, source_id, related_id, "DERIVED_FROM", relation="DERIVED_FROM", evidence="memory metadata")

        causal_links = item.get("causal_links", [])
        if isinstance(causal_links, list):
            for link in causal_links:
                if not isinstance(link, dict):
                    continue
                target_id = str(link.get("target_memory_id", "") or "").strip()
                if target_id not in memory_ids:
                    continue
                _graph_add_edge(
                    edges,
                    seen_edges,
                    source_id,
                    target_id,
                    "CAUSAL",
                    relation=link.get("relation", "CAUSES"),
                    confidence=link.get("confidence", 0.0),
                    evidence=link.get("evidence", ""),
                )

        provenance = item.get("provenance", [])
        if isinstance(provenance, list):
            for entry in provenance:
                if not isinstance(entry, dict):
                    continue
                for related_id in _normalize_id_list(entry.get("related_memory_ids")):
                    if related_id in memory_ids:
                        _graph_add_edge(
                            edges,
                            seen_edges,
                            source_id,
                            related_id,
                            "DERIVED_FROM",
                            relation="PROVENANCE_RELATED",
                            confidence=1.0,
                            evidence=entry.get("reason", ""),
                        )

    chains = {}
    for node in nodes:
        chain_id = node.get("chain_id")
        if chain_id:
            chains.setdefault(chain_id, []).append(node)
    for chain_nodes in chains.values():
        chain_nodes.sort(key=lambda node: (node.get("version", 1), node.get("valid_from") or "", node.get("id", "")))
        for previous, current in zip(chain_nodes, chain_nodes[1:]):
            _graph_add_edge(edges, seen_edges, previous.get("id"), current.get("id"), "TEMPORAL_SAME_CHAIN", relation="NEXT_VERSION", evidence="shared temporal chain")

    nodes.sort(key=lambda node: (node.get("kind", ""), node.get("id", "")))
    graph = {
        "schema_version": 1,
        "updated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "nodes": nodes,
        "edges": edges,
    }

    _save_json(os.path.join(base_path, "memory_graph.json"), graph)

    return {
        "nodes": len(nodes),
        "edges": len(edges),
    }


def _apply_repairs(base_path, repairable_codes):
    repairable_codes = set(repairable_codes or [])
    details = {
        "memory_archive_status_fixed": 0,
        "entity_archive_state_fixed": 0,
        "completed_operation_leases_cleared": 0,
        "authoritative_reference_repair": {
            "changed": False,
            "entity_reference_items_fixed": 0,
            "entity_reference_count_removed": 0,
            "relation_reference_items_fixed": 0,
            "relation_reference_count_removed": 0,
        },
        "graph_rebuilt": False,
        "graph_nodes": 0,
        "graph_edges": 0,
    }

    if "MEMORY_ARCHIVE_STATUS_INVALID" in repairable_codes:
        details["memory_archive_status_fixed"] = _repair_memory_archive_status(base_path)

    if "ARCHIVE_ENTITY_NOT_ARCHIVED" in repairable_codes:
        details["entity_archive_state_fixed"] = _repair_entity_archive_state(base_path)

    if "COMPLETED_OPERATION_HAS_LEASE" in repairable_codes:
        details["completed_operation_leases_cleared"] = _repair_completed_operation_leases(base_path)

    if repairable_codes.intersection(LINK_REPAIR_CODES):
        details["authoritative_reference_repair"] = _repair_authoritative_memory_references(base_path)

    if repairable_codes.intersection(GRAPH_REPAIR_CODES | LINK_REPAIR_CODES):
        graph_result = _repair_graph_and_derived_links(base_path)
        details["graph_rebuilt"] = True
        details["graph_nodes"] = graph_result["nodes"]
        details["graph_edges"] = graph_result["edges"]

    details["changed"] = any([
        details["memory_archive_status_fixed"],
        details["entity_archive_state_fixed"],
        details["completed_operation_leases_cleared"],
        details["authoritative_reference_repair"]["changed"],
        details["graph_rebuilt"],
    ])
    return details


def _latest_completed_reconciliation_epoch(base_path):
    """Return the latest completed reconciliation operation identity.

    A completed Repair defines the boundary of one reconciliation cycle. If
    corruption is introduced again later, the previous completed operation
    becomes part of the new logical identity, allowing a new repair to run
    while preserving idempotency for retries within the same cycle.
    """
    with _project_directory(base_path):
        store = load_operation_store()

    operations = store.get("operations", []) if isinstance(store, dict) else []
    completed = [
        item
        for item in operations
        if isinstance(item, dict)
        and str(item.get("operation_type", "") or "").strip().upper()
        == RECONCILIATION_OPERATION_TYPE
        and str(item.get("status", "") or "").strip().upper() == "COMPLETED"
    ]

    if not completed:
        return None

    latest = completed[-1]
    return {
        "operation_id": latest.get("operation_id"),
        "operation_key": latest.get("operation_key"),
    }


def _repair_plan_identity(inspection, repair_epoch=None, policy_snapshot=None):
    inspection = inspection if isinstance(inspection, dict) else {}
    epoch = repair_epoch if isinstance(repair_epoch, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else _policy_snapshot()

    contexts = []
    for item in inspection.get("repairable", []):
        if not isinstance(item, dict):
            continue
        contexts.append({
            "code": str(item.get("code", "") or ""),
            "context": item.get("context", {}) if isinstance(item.get("context"), dict) else {},
        })

    contexts.sort(
        key=lambda item: _canonical_json(item)
    )

    identity = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "policy_version": policy.get("version"),
        "policy_fingerprint": policy.get("fingerprint"),
        "previous_operation_id": epoch.get("operation_id"),
        "previous_operation_key": epoch.get("operation_key"),
        "repairable_codes": sorted(set(inspection.get("repairable_codes", []))),
        "repair_targets": contexts,
    }
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


def _approval_consumption_check(base_path, approval, operation_payload):
    """Prevent reuse of consumed approvals while allowing exact crash recovery."""
    context = approval if isinstance(approval, dict) else {}
    approvals = context.get("approvals")
    if not isinstance(approvals, list):
        approvals = [context] if context.get("fingerprint") or context.get("approval_fingerprint") else []

    fingerprints = sorted({
        str(
            item.get("fingerprint")
            or item.get("approval_fingerprint")
            or ""
        ).strip()
        for item in approvals
        if isinstance(item, dict)
        and str(item.get("fingerprint") or item.get("approval_fingerprint") or "").strip()
    })

    if not fingerprints:
        return {"consumed": False, "same_operation": False, "approval_fingerprints": []}

    current_operation_key = build_operation_key(
        RECONCILIATION_OPERATION_TYPE,
        operation_payload,
    )

    with _project_directory(base_path):
        store = load_operation_store()

    operations = store.get("operations", []) if isinstance(store, dict) else []

    for item in operations:
        if not isinstance(item, dict):
            continue
        if str(item.get("operation_type", "") or "").strip().upper() != RECONCILIATION_OPERATION_TYPE:
            continue

        operation_key = str(item.get("operation_key", "") or "").strip()
        status = str(item.get("status", "") or "").strip().upper()

        result_data = item.get("result_data")
        recorded = []
        if isinstance(result_data, dict):
            recorded = result_data.get("approval_fingerprints") or []
            if not recorded:
                aggregate = result_data.get("approval_fingerprint")
                if aggregate:
                    recorded = [aggregate]
            if not recorded:
                approval_trace = result_data.get("approval")
                if isinstance(approval_trace, dict):
                    nested = approval_trace.get("approvals")
                    if isinstance(nested, list):
                        recorded = [
                            str(
                                nested_item.get("approval_fingerprint")
                                or nested_item.get("fingerprint")
                                or ""
                            ).strip()
                            for nested_item in nested
                            if isinstance(nested_item, dict)
                        ]
                    else:
                        single = approval_trace.get("approval_fingerprint")
                        if single:
                            recorded = [single]

        recorded_set = {
            str(value or "").strip()
            for value in recorded
            if str(value or "").strip()
        }
        matched = sorted(set(fingerprints) & recorded_set)

        if operation_key == current_operation_key:
            if status == "STARTED":
                return {
                    "consumed": False,
                    "same_operation": True,
                    "recoverable": True,
                    "operation_id": item.get("operation_id"),
                    "operation_key": operation_key,
                    "approval_fingerprints": fingerprints,
                }

            if status in {"COMPLETED", "FAILED"}:
                return {
                    "consumed": True,
                    "same_operation": True,
                    "recoverable": False,
                    "operation_id": item.get("operation_id"),
                    "operation_key": operation_key,
                    "status": status,
                    "approval_fingerprints": matched or fingerprints,
                }

        if matched and status in {"COMPLETED", "FAILED"}:
            return {
                "consumed": True,
                "same_operation": False,
                "recoverable": False,
                "operation_id": item.get("operation_id"),
                "operation_key": operation_key,
                "status": status,
                "approval_fingerprints": matched,
            }

    return {
        "consumed": False,
        "same_operation": False,
        "recoverable": False,
        "approval_fingerprints": fingerprints,
    }


def _provider_verify(identity_provider, actor, claimed_role, reference, requirement, attestation_nonce=""):
    kwargs = {
        "actor": str(actor or "").strip(),
        "claimed_role": str(claimed_role or "").strip(),
        "reference": str(reference or "").strip(),
    }
    binding_required = bool(
        requirement.get("require_attestation_nonce")
        or requirement.get("attestation_issuer")
        or requirement.get("attestation_audience")
    )
    if binding_required:
        kwargs.update({
            "attestation_nonce": str(attestation_nonce or "").strip(),
            "expected_issuer": str(requirement.get("attestation_issuer", "") or "").strip(),
            "expected_audience": str(requirement.get("attestation_audience", "") or "").strip(),
        })
        try:
            return identity_provider.verify(**kwargs), None
        except TypeError:
            return None, "APPROVAL_IDENTITY_PROVIDER_BINDING_UNSUPPORTED"

    try:
        return identity_provider.verify(**kwargs), None
    except TypeError:
        return None, "APPROVAL_IDENTITY_PROVIDER_UNAVAILABLE"


def _verify_authoritative_identity(identity_provider, actor, claimed_role, reference, requirement, attestation_nonce=""):
    """Verify an approver through the configured authoritative identity provider."""
    if not requirement.get("require_authoritative_identity"):
        return {"valid": True, "identity": None, "codes": []}

    if identity_provider is None or not hasattr(identity_provider, "verify"):
        return {"valid": False, "identity": None, "codes": ["APPROVAL_IDENTITY_PROVIDER_REQUIRED"]}

    if requirement.get("require_attestation_nonce") and not str(attestation_nonce or "").strip():
        return {"valid": False, "identity": None, "codes": ["APPROVAL_IDENTITY_ATTESTATION_NONCE_MISSING"]}

    expected_issuer = str(requirement.get("attestation_issuer", "") or "").strip()
    expected_audience = str(requirement.get("attestation_audience", "") or "").strip()
    if expected_issuer == "MULTIPLE" or expected_audience == "MULTIPLE":
        return {"valid": False, "identity": None, "codes": ["APPROVAL_IDENTITY_ATTESTATION_SCOPE_AMBIGUOUS"]}

    raw, provider_error = _provider_verify(
        identity_provider,
        actor,
        claimed_role,
        reference,
        requirement,
        attestation_nonce=attestation_nonce,
    )
    if provider_error:
        return {"valid": False, "identity": None, "codes": [provider_error]}
    if raw is None:
        return {"valid": False, "identity": None, "codes": ["APPROVAL_IDENTITY_PROVIDER_UNAVAILABLE"]}

    identity = normalize_identity_result(
        raw,
        requested_actor=str(actor or "").strip(),
        claimed_role=str(claimed_role or "").strip(),
    )

    if requirement.get("require_active_identity"):
        if identity.get("revoked") or identity.get("status") == "REVOKED":
            return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_REVOKED"]}
        if not identity.get("active") or identity.get("status") != "ACTIVE":
            return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_INACTIVE"]}

        valid_until = _parse_timestamp(identity.get("valid_until"))
        if valid_until is not None and valid_until <= datetime.now(timezone.utc):
            return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_ATTESTATION_EXPIRED"]}

    if not identity.get("verified"):
        return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_NOT_VERIFIED"]}

    expected_provider = str(requirement.get("identity_provider", "") or "").strip()
    if expected_provider and expected_provider != "MULTIPLE" and identity.get("provider") != expected_provider:
        return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_PROVIDER_MISMATCH"]}

    returned_issuer = str(identity.get("attestation_issuer") or "").strip()
    returned_audience = str(identity.get("attestation_audience") or "").strip()
    returned_nonce = str(identity.get("attestation_nonce") or "").strip()
    if expected_issuer and returned_issuer != expected_issuer:
        return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_ATTESTATION_ISSUER_MISMATCH"]}
    if expected_audience and returned_audience != expected_audience:
        return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_ATTESTATION_AUDIENCE_MISMATCH"]}
    if requirement.get("require_attestation_nonce") and returned_nonce != str(attestation_nonce or "").strip():
        return {"valid": False, "identity": identity, "codes": ["APPROVAL_IDENTITY_ATTESTATION_NONCE_MISMATCH"]}

    if requirement.get("require_cryptographic_attestation"):
        expected_algorithm = str(requirement.get("attestation_algorithm", "") or "").strip()
        expected_key_id = str(requirement.get("attestation_key_id", "") or "").strip()
        crypto = verify_identity_attestation(
            identity,
            identity_provider,
            expected_algorithm=expected_algorithm if expected_algorithm != "MULTIPLE" else "",
            expected_key_id=expected_key_id if expected_key_id != "MULTIPLE" else "",
            expected_issuer=expected_issuer if expected_issuer != "MULTIPLE" else "",
            expected_audience=expected_audience if expected_audience != "MULTIPLE" else "",
            expected_nonce=attestation_nonce if requirement.get("require_attestation_nonce") else "",
            expected_key_statuses=(
                requirement.get("attestation_key_statuses", [])
                if requirement.get("require_trusted_attestation_key")
                else []
            ),
            expected_key_fingerprint=(
                requirement.get("attestation_key_fingerprint", "")
                if requirement.get("require_trusted_attestation_key")
                and requirement.get("attestation_key_fingerprint") != "MULTIPLE"
                else ""
            ),
        )
        if not crypto.get("valid"):
            return {"valid": False, "identity": identity, "codes": crypto.get("codes", ["APPROVAL_IDENTITY_SIGNATURE_INVALID"])}
        identity["cryptographic_attestation_verified"] = True
        identity["attestation_signature_fingerprint"] = crypto.get("signature_fingerprint")
        identity["signature_key_status"] = crypto.get("key_status")
        identity["signature_key_fingerprint"] = crypto.get("key_fingerprint")

    return {"valid": True, "identity": identity, "codes": []}


def _validate_single_approval(
    approval,
    policy_snapshot,
    repair_plan_fingerprint,
    repair_epoch=None,
    approval_requirement=None,
    identity_provider=None,
):
    approval = approval if isinstance(approval, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else {}
    epoch = repair_epoch if isinstance(repair_epoch, dict) else {}
    requirement = _normalize_approval_requirement(approval_requirement)

    if not approval.get("approved"):
        return {"valid": False, "status": "APPROVAL_REQUIRED", "codes": ["APPROVAL_NOT_GRANTED"]}

    expected_fingerprint = _approval_fingerprint(approval)
    provided_fingerprint = approval.get("fingerprint") or approval.get("approval_fingerprint")
    if provided_fingerprint != expected_fingerprint:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_FINGERPRINT_MISMATCH"]}

    expires = _parse_timestamp(approval.get("expires_at"))
    if expires is None:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_EXPIRATION_INVALID"]}

    now = datetime.now(timezone.utc)
    if expires <= now:
        return {"valid": False, "status": "APPROVAL_EXPIRED", "codes": ["APPROVAL_EXPIRED"]}

    issued = _parse_timestamp(approval.get("issued_at"))
    if issued is None or issued > now:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_ISSUED_AT_INVALID"]}

    if approval.get("policy_version") != policy.get("version"):
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_POLICY_VERSION_MISMATCH"]}

    if approval.get("policy_fingerprint") != policy.get("fingerprint"):
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_POLICY_FINGERPRINT_MISMATCH"]}

    if approval.get("repair_plan_fingerprint") != repair_plan_fingerprint:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REPAIR_PLAN_MISMATCH"]}

    if approval.get("previous_operation_id") != epoch.get("operation_id"):
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_CYCLE_MISMATCH"]}

    if approval.get("previous_operation_key") != epoch.get("operation_key"):
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_CYCLE_KEY_MISMATCH"]}

    role = str(approval.get("role", "") or "").strip()
    identity_check = _verify_authoritative_identity(
        identity_provider,
        approval.get("actor", ""),
        role,
        approval.get("reference", ""),
        requirement,
        attestation_nonce=approval.get("identity_attestation_nonce", ""),
    )
    if not identity_check["valid"]:
        return {
            "valid": False,
            "status": "APPROVAL_INVALID",
            "codes": identity_check["codes"],
            "identity": identity_check.get("identity"),
        }

    if requirement.get("require_authoritative_identity"):
        identity = identity_check.get("identity") or {}
        if approval.get("identity_provider") != identity.get("provider"):
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_PROVIDER_MISMATCH"], "identity": identity}
        if approval.get("identity_subject") != identity.get("subject"):
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SUBJECT_MISMATCH"], "identity": identity}
        if approval.get("identity_fingerprint") != identity.get("identity_fingerprint"):
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_FINGERPRINT_MISMATCH"], "identity": identity}
        if requirement.get("require_cryptographic_attestation"):
            if approval.get("identity_signature_algorithm") != identity.get("signature_algorithm"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISMATCH"], "identity": identity}
            if approval.get("identity_signature_key_id") != identity.get("signature_key_id"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISMATCH"], "identity": identity}
            if requirement.get("require_trusted_attestation_key"):
                if approval.get("identity_signature_key_status") != identity.get("signature_key_status"):
                    return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_STATUS_MISMATCH"], "identity": identity}
                if approval.get("identity_signature_key_fingerprint") != identity.get("signature_key_fingerprint"):
                    return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_FINGERPRINT_MISMATCH"], "identity": identity}
            if approval.get("identity_attestation_signature") != identity.get("attestation_signature"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_SIGNATURE_MISMATCH"], "identity": identity}
            if approval.get("identity_attestation_fingerprint") != identity.get("attestation_fingerprint"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_ATTESTATION_FINGERPRINT_MISMATCH"], "identity": identity}
            if requirement.get("attestation_issuer") and approval.get("identity_attestation_issuer") != identity.get("attestation_issuer"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_ATTESTATION_ISSUER_MISMATCH"], "identity": identity}
            if requirement.get("attestation_audience") and approval.get("identity_attestation_audience") != identity.get("attestation_audience"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_ATTESTATION_AUDIENCE_MISMATCH"], "identity": identity}
            if requirement.get("require_attestation_nonce") and approval.get("identity_attestation_nonce") != identity.get("attestation_nonce"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_ATTESTATION_NONCE_MISMATCH"], "identity": identity}
            if not identity.get("cryptographic_attestation_verified"):
                return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_CRYPTOGRAPHIC_ATTESTATION_REQUIRED"], "identity": identity}
        verified_roles = set(identity.get("roles") or [])
        if role and role not in verified_roles:
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_IDENTITY_ROLE_MISMATCH"], "identity": identity}

    requester_actor = str(approval.get("requester_actor", "") or "").strip()
    requester_role = str(approval.get("requester_role", "") or "").strip()
    approver_actor = str(approval.get("actor", "") or "").strip()

    if requirement["require_requester_context"] and not requester_actor:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REQUESTER_REQUIRED"]}

    if requirement["prohibit_requester_approval"] and requester_actor and approver_actor == requester_actor:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REQUESTER_APPROVAL_FORBIDDEN"]}

    if requirement["prohibit_requester_role_approval"] and not requester_role:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REQUESTER_ROLE_REQUIRED"]}

    if requirement["prohibit_requester_role_approval"] and requester_role and role == requester_role:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REQUESTER_ROLE_FORBIDDEN"]}

    constrained_roles = bool(requirement["allowed_roles"] or requirement["required_roles"])
    if constrained_roles and not role:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_ROLE_REQUIRED"]}

    if requirement["allowed_roles"] and role not in set(requirement["allowed_roles"]):
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_ROLE_NOT_ALLOWED"]}

    delegated_by = str(approval.get("delegated_by", "") or "").strip()
    delegation_reference = str(approval.get("delegation_reference", "") or "").strip()
    if delegated_by:
        if requirement["prohibit_requester_approval"] and requester_actor and delegated_by == requester_actor:
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_REQUESTER_DELEGATION_FORBIDDEN"]}
        if not requirement["allow_delegation"]:
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_DELEGATION_NOT_ALLOWED"]}
        if delegated_by == str(approval.get("actor", "") or "").strip():
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_DELEGATOR_SELF_REFERENCE"]}
        if requirement["require_delegation_reference"] and not delegation_reference:
            return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_DELEGATION_REFERENCE_REQUIRED"]}
    elif requirement["require_delegation_reference"] and delegation_reference:
        return {"valid": False, "status": "APPROVAL_INVALID", "codes": ["APPROVAL_DELEGATION_REFERENCE_WITHOUT_DELEGATOR"]}

    return {"valid": True, "status": "APPROVED", "codes": []}


def _validate_approval(
    approval,
    policy_snapshot,
    repair_plan_fingerprint,
    repair_epoch=None,
    approval_requirement=None,
    identity_provider=None,
):
    context = approval if isinstance(approval, dict) else {}
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else {}
    requirement = _normalize_approval_requirement(approval_requirement)

    approvals = context.get("approvals")
    if not isinstance(approvals, list):
        approvals = [context] if context else []

    if not approvals:
        return {
            "valid": False,
            "status": "APPROVAL_REQUIRED",
            "codes": ["APPROVAL_NOT_GRANTED"],
            "required_approvals": requirement["required_count"],
            "provided_approvals": 0,
        }

    seen_ids = set()
    seen_fingerprints = set()
    validations = []
    valid_approvals = []

    for item in approvals:
        validation = _validate_single_approval(
            item,
            policy,
            repair_plan_fingerprint,
            repair_epoch=repair_epoch,
            approval_requirement=requirement,
            identity_provider=identity_provider,
        )
        validations.append(validation)

        approval_id = str(item.get("approval_id", "") or "").strip()
        fingerprint = str(
            item.get("fingerprint")
            or item.get("approval_fingerprint")
            or ""
        ).strip()

        if approval_id and approval_id in seen_ids:
            return {
                "valid": False,
                "status": "APPROVAL_INVALID",
                "codes": ["APPROVAL_DUPLICATE_ID"],
                "validations": validations,
                "required_approvals": requirement["required_count"],
                "provided_approvals": len(approvals),
            }
        if fingerprint and fingerprint in seen_fingerprints:
            return {
                "valid": False,
                "status": "APPROVAL_INVALID",
                "codes": ["APPROVAL_DUPLICATE_FINGERPRINT"],
                "validations": validations,
                "required_approvals": requirement["required_count"],
                "provided_approvals": len(approvals),
            }

        if approval_id:
            seen_ids.add(approval_id)
        if fingerprint:
            seen_fingerprints.add(fingerprint)

        if validation["valid"]:
            valid_approvals.append(item)
        else:
            return {
                "valid": False,
                "status": validation["status"],
                "codes": validation["codes"],
                "validations": validations,
                "required_approvals": requirement["required_count"],
                "provided_approvals": len(approvals),
            }

    if len(valid_approvals) < requirement["required_count"]:
        return {
            "valid": False,
            "status": "APPROVAL_REQUIRED",
            "codes": ["APPROVAL_QUORUM_NOT_MET"],
            "validations": validations,
            "required_approvals": requirement["required_count"],
            "provided_approvals": len(valid_approvals),
        }

    if requirement["distinct_actors"]:
        actors = {
            str(item.get("actor", "") or "").strip()
            for item in valid_approvals
        }
        if len(actors) < requirement["required_count"] or "" in actors:
            return {
                "valid": False,
                "status": "APPROVAL_INVALID",
                "codes": ["APPROVAL_DISTINCT_ACTORS_REQUIRED"],
                "validations": validations,
                "required_approvals": requirement["required_count"],
                "provided_approvals": len(valid_approvals),
            }

    roles = {
        str(item.get("role", "") or "").strip()
        for item in valid_approvals
        if str(item.get("role", "") or "").strip()
    }
    missing_roles = sorted(set(requirement["required_roles"]) - roles)
    if missing_roles:
        return {
            "valid": False,
            "status": "APPROVAL_REQUIRED",
            "codes": ["APPROVAL_REQUIRED_ROLE_MISSING"],
            "missing_roles": missing_roles,
            "validations": validations,
            "required_approvals": requirement["required_count"],
            "provided_approvals": len(valid_approvals),
        }

    return {
        "valid": True,
        "status": "APPROVED",
        "codes": [],
        "validations": validations,
        "required_approvals": requirement["required_count"],
        "provided_approvals": len(valid_approvals),
        "approval_fingerprints": sorted(seen_fingerprints),
        "distinct_actor_count": len({
            str(item.get("actor", "") or "").strip()
            for item in valid_approvals
        }),
    }


def prepare_repair_approval(
    base_path=".",
    actor="",
    reason="",
    reference="",
    ttl_seconds=APPROVAL_DEFAULT_TTL_SECONDS,
    role="",
    delegated_by="",
    delegation_reason="",
    delegation_reference="",
    requester_actor="",
    requester_role="",
    requester_reference="",
    identity_provider=None,
):
    """Create a traceable approval token bound to the current repair plan."""
    base_path = os.path.abspath(base_path)
    before = inspect_reconciliation(base_path)
    policy = evaluate_repair_policy(before)
    policy_snapshot = policy.get("policy_snapshot", _policy_snapshot())

    if not before.get("repairable_codes"):
        return {
            "status": "NO_REPAIR_REQUIRED",
            "approval": None,
            "policy": policy,
        }

    repair_epoch = _latest_completed_reconciliation_epoch(base_path)
    plan_fingerprint = _repair_plan_identity(before, repair_epoch, policy_snapshot)

    try:
        ttl_seconds = float(ttl_seconds)
    except (TypeError, ValueError):
        ttl_seconds = APPROVAL_DEFAULT_TTL_SECONDS
    ttl_seconds = max(1.0, min(ttl_seconds, 86400.0))

    issued_at = datetime.now(timezone.utc)
    requirement = policy.get(
        "approval_requirement",
        _approval_requirement_for_codes(policy.get("approval_required_codes", [])),
    )
    attestation_nonce = secrets.token_urlsafe(32) if requirement.get("require_attestation_nonce") else ""
    context = {
        "actor": str(actor or "").strip()[:200],
        "role": str(role or "").strip()[:APPROVAL_MAX_ROLE_LENGTH],
        "reason": str(reason or "").strip()[:500],
        "reference": str(reference or "").strip()[:200],
        "delegated_by": str(delegated_by or "").strip()[:200],
        "delegation_reason": str(delegation_reason or "").strip()[:500],
        "delegation_reference": str(delegation_reference or "").strip()[:200],
        "requester_actor": str(requester_actor or "").strip()[:200],
        "requester_role": str(requester_role or "").strip()[:APPROVAL_MAX_ROLE_LENGTH],
        "requester_reference": str(requester_reference or "").strip()[:200],
        "identity_attestation_nonce": attestation_nonce or None,
        "approval_id": "approval_" + hashlib.sha256(
            _canonical_json({
                "actor": str(actor or "").strip()[:200],
                "role": str(role or "").strip()[:APPROVAL_MAX_ROLE_LENGTH],
                "reason": str(reason or "").strip()[:500],
                "reference": str(reference or "").strip()[:200],
                "delegated_by": str(delegated_by or "").strip()[:200],
                "delegation_reason": str(delegation_reason or "").strip()[:500],
                "delegation_reference": str(delegation_reference or "").strip()[:200],
                "requester_actor": str(requester_actor or "").strip()[:200],
                "requester_role": str(requester_role or "").strip()[:APPROVAL_MAX_ROLE_LENGTH],
                "requester_reference": str(requester_reference or "").strip()[:200],
                "issued_at": issued_at.isoformat(),
                "plan_fingerprint": plan_fingerprint,
            }).encode("utf-8")
        ).hexdigest()[:16],
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(seconds=ttl_seconds)).isoformat(),
        "policy_version": policy_snapshot.get("version"),
        "policy_fingerprint": policy_snapshot.get("fingerprint"),
        "repair_plan_fingerprint": plan_fingerprint,
        "previous_operation_id": repair_epoch.get("operation_id") if isinstance(repair_epoch, dict) else None,
        "previous_operation_key": repair_epoch.get("operation_key") if isinstance(repair_epoch, dict) else None,
        "approved": True,
    }
    context["fingerprint"] = _approval_fingerprint(context)

    authoritative_identity = None
    if requirement.get("require_authoritative_identity"):
        identity_check = _verify_authoritative_identity(
            identity_provider,
            actor,
            role,
            reference,
            requirement,
            attestation_nonce=attestation_nonce,
        )
        if not identity_check["valid"]:
            return {
                "status": "APPROVAL_INVALID",
                "approval": None,
                "approval_context": None,
                "policy": policy,
                "approval_requirement": requirement,
                "identity_validation": identity_check,
            }
        authoritative_identity = identity_check["identity"]

    if authoritative_identity:
        context["identity_provider"] = authoritative_identity.get("provider")
        context["identity_subject"] = authoritative_identity.get("subject")
        context["identity_roles"] = authoritative_identity.get("roles", [])
        context["identity_reference"] = authoritative_identity.get("reference")
        context["identity_fingerprint"] = authoritative_identity.get("identity_fingerprint")
        context["identity_status"] = authoritative_identity.get("status")
        context["identity_active"] = authoritative_identity.get("active")
        context["identity_revoked"] = authoritative_identity.get("revoked")
        context["identity_verified_at"] = authoritative_identity.get("verified_at")
        context["identity_valid_until"] = authoritative_identity.get("valid_until")
        context["identity_attestation_id"] = authoritative_identity.get("attestation_id")
        context["identity_attestation_fingerprint"] = authoritative_identity.get("attestation_fingerprint")
        context["identity_signature_algorithm"] = authoritative_identity.get("signature_algorithm")
        context["identity_signature_key_id"] = authoritative_identity.get("signature_key_id")
        context["identity_signature_key_status"] = authoritative_identity.get("signature_key_status")
        context["identity_signature_key_fingerprint"] = authoritative_identity.get("signature_key_fingerprint")
        context["identity_attestation_signature"] = authoritative_identity.get("attestation_signature")
        context["identity_cryptographic_attestation_verified"] = authoritative_identity.get("cryptographic_attestation_verified", False)
        context["identity_attestation_signature_fingerprint"] = authoritative_identity.get("attestation_signature_fingerprint")
        context["identity_attestation_issuer"] = authoritative_identity.get("attestation_issuer")
        context["identity_attestation_audience"] = authoritative_identity.get("attestation_audience")
        context["identity_attestation_nonce"] = authoritative_identity.get("attestation_nonce") or attestation_nonce or None

    normalized = _normalize_approval_context(
        context,
        approve=True,
        policy_snapshot=policy_snapshot,
        repair_plan_fingerprint=plan_fingerprint,
        repair_epoch=repair_epoch,
        approval_requirement=requirement,
    )

    return {
        "status": "APPROVAL_READY",
        "approval": _approval_trace(normalized, policy_snapshot),
        "approval_context": _approval_trace(normalized, policy_snapshot),
        "policy": policy,
        "approval_requirement": requirement,
        "before": before,
        "repair_plan_fingerprint": plan_fingerprint,
        "identity_validation": {
            "valid": True,
            "identity": authoritative_identity,
            "codes": [],
        } if authoritative_identity else None,
    }


def prepare_repair_approvals(
    base_path=".",
    approvers=None,
    ttl_seconds=APPROVAL_DEFAULT_TTL_SECONDS,
    requester_actor="",
    requester_role="",
    requester_reference="",
    identity_provider=None,
):
    """Create a multi-approver context bound to the current repair plan."""
    base_path = os.path.abspath(base_path)
    before = inspect_reconciliation(base_path)
    policy = evaluate_repair_policy(before)
    policy_snapshot = policy.get("policy_snapshot", _policy_snapshot())
    requirement = policy.get(
        "approval_requirement",
        _approval_requirement_for_codes(policy.get("approval_required_codes", [])),
    )

    if not before.get("repairable_codes"):
        return {
            "status": "NO_REPAIR_REQUIRED",
            "approvals": [],
            "approval_context": None,
            "policy": policy,
        }

    raw_approvers = approvers if isinstance(approvers, list) else []
    if len(raw_approvers) < requirement["required_count"]:
        return {
            "status": "APPROVAL_COUNT_INSUFFICIENT",
            "approvals": [],
            "approval_context": None,
            "policy": policy,
            "approval_requirement": requirement,
            "provided_approvers": len(raw_approvers),
        }

    actor_values = []
    for item in raw_approvers:
        if isinstance(item, dict):
            actor_values.append(str(item.get("actor", "") or "").strip())
        else:
            actor_values.append(str(item or "").strip())

    if requirement["distinct_actors"]:
        meaningful = [actor for actor in actor_values if actor]
        if len(set(meaningful)) < requirement["required_count"]:
            return {
                "status": "APPROVAL_DISTINCT_ACTORS_REQUIRED",
                "approvals": [],
                "approval_context": None,
                "policy": policy,
                "approval_requirement": requirement,
                "provided_actors": actor_values,
            }

    approval_records = []
    for index, item in enumerate(raw_approvers[:APPROVAL_MAX_REQUIRED_COUNT]):
        if isinstance(item, dict):
            actor = item.get("actor", "")
            role = item.get("role", "")
            reason = item.get("reason", "")
            reference = item.get("reference", "")
            delegated_by = item.get("delegated_by", "")
            delegation_reason = item.get("delegation_reason", "")
            delegation_reference = item.get("delegation_reference", "")
        else:
            actor = str(item or "")
            role = ""
            reason = "multi-approver reconciliation approval"
            reference = f"MULTI-APPROVAL-{index + 1}"
            delegated_by = ""
            delegation_reason = ""
            delegation_reference = ""

        prepared = prepare_repair_approval(
            base_path,
            actor=actor,
            reason=reason,
            reference=reference,
            ttl_seconds=ttl_seconds,
            role=role,
            delegated_by=delegated_by,
            delegation_reason=delegation_reason,
            delegation_reference=delegation_reference,
            requester_actor=requester_actor,
            requester_role=requester_role,
            requester_reference=requester_reference,
            identity_provider=identity_provider,
        )
        if prepared.get("status") != "APPROVAL_READY":
            return {
                "status": prepared.get("status", "APPROVAL_INVALID"),
                "approvals": [],
                "approval_context": None,
                "policy": policy,
                "approval_requirement": requirement,
            }
        approval_records.append(prepared["approval"])

    repair_epoch = _latest_completed_reconciliation_epoch(base_path)
    plan_fingerprint = _repair_plan_identity(before, repair_epoch, policy_snapshot)
    context = {
        "approved": True,
        "approvals": approval_records,
        "requester_actor": str(requester_actor or "").strip()[:200],
        "requester_role": str(requester_role or "").strip()[:APPROVAL_MAX_ROLE_LENGTH],
        "requester_reference": str(requester_reference or "").strip()[:200],
    }
    normalized = _normalize_approval_context(
        context,
        approve=True,
        policy_snapshot=policy_snapshot,
        repair_plan_fingerprint=plan_fingerprint,
        repair_epoch=repair_epoch,
        approval_requirement=requirement,
    )

    return {
        "status": "APPROVAL_READY",
        "approvals": approval_records,
        "approval_context": _approval_trace(normalized, policy_snapshot),
        "policy": policy,
        "approval_requirement": requirement,
        "before": before,
        "repair_plan_fingerprint": plan_fingerprint,
        "approval_set_fingerprint": normalized.get("approval_set_fingerprint"),
    }


def _reconciliation_payload(
    inspection,
    repair_epoch=None,
    approval_context=None,
    policy_snapshot=None,
):
    """Build a stable logical identity for one repair cycle.

    Policy version/fingerprint and stable approval context are intentionally
    part of the operation identity so policy changes cannot collide with
    history created under an earlier policy.
    """
    contexts = []
    for item in inspection.get("repairable", []):
        if not isinstance(item, dict):
            continue
        contexts.append({
            "code": str(item.get("code", "") or ""),
            "context": item.get("context", {}) if isinstance(item.get("context"), dict) else {},
        })

    contexts.sort(
        key=lambda item: json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    epoch = repair_epoch if isinstance(repair_epoch, dict) else {}
    approval = approval_context if isinstance(approval_context, dict) else _normalize_approval_context({}, False)
    policy = policy_snapshot if isinstance(policy_snapshot, dict) else _policy_snapshot()

    return {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "policy": {
            "version": policy.get("version"),
            "fingerprint": policy.get("fingerprint"),
        },
        "repair_cycle": {
            "previous_operation_id": epoch.get("operation_id"),
            "previous_operation_key": epoch.get("operation_key"),
        },
        "repairable_codes": sorted(set(inspection.get("repairable_codes", []))),
        "repair_targets": contexts,
        "approval": {
            "approved": bool(approval.get("approved")),
            "approval_id": approval.get("approval_id"),
            "actor": approval.get("actor"),
            "reason": approval.get("reason"),
            "reference": approval.get("reference"),
            "requester_actor": approval.get("requester_actor"),
            "requester_role": approval.get("requester_role"),
            "requester_reference": approval.get("requester_reference"),
            "fingerprint": approval.get("fingerprint"),
            "approval_set_fingerprint": approval.get("approval_set_fingerprint") or approval.get("fingerprint"),
            "approval_fingerprints": sorted({
                str(
                    item.get("fingerprint")
                    or item.get("approval_fingerprint")
                    or ""
                ).strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict)
                and str(item.get("fingerprint") or item.get("approval_fingerprint") or "").strip()
            }),
            "approval_roles": sorted({
                str(item.get("role", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("role", "") or "").strip()
            }),
            "delegated_approvals": sorted({
                str(item.get("approval_id", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("delegated_by", "") or "").strip()
            }),
            "identity_signature_algorithms": sorted({
                str(item.get("identity_signature_algorithm", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_signature_algorithm", "") or "").strip()
            }),
            "identity_signature_key_ids": sorted({
                str(item.get("identity_signature_key_id", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_signature_key_id", "") or "").strip()
            }),
            "identity_attestation_fingerprints": sorted({
                str(item.get("identity_attestation_fingerprint", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_attestation_fingerprint", "") or "").strip()
            }),
            "identity_attestation_issuers": sorted({
                str(item.get("identity_attestation_issuer", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_attestation_issuer", "") or "").strip()
            }),
            "identity_attestation_audiences": sorted({
                str(item.get("identity_attestation_audience", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_attestation_audience", "") or "").strip()
            }),
            "identity_attestation_nonces": sorted({
                str(item.get("identity_attestation_nonce", "") or "").strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict) and str(item.get("identity_attestation_nonce", "") or "").strip()
            }),
        },
    }


def _audit_snapshot(inspection):
    """Return a compact, durable snapshot suitable for the operation journal."""
    if not isinstance(inspection, dict):
        return {
            "valid": False,
            "counts": {},
            "repairable_codes": [],
            "blocked_codes": [],
        }

    return {
        "valid": bool(inspection.get("valid")),
        "counts": dict(inspection.get("counts", {})),
        "repairable_codes": sorted(set(inspection.get("repairable_codes", []))),
        "blocked_codes": sorted(set(inspection.get("blocked_codes", []))),
    }


def _reconciliation_status(before, after, executed):
    """Classify the reconciliation outcome without hiding blocked violations."""
    if isinstance(after, dict) and after.get("valid"):
        return "REPAIRED" if executed else "HEALTHY"

    blocked = after.get("blocked", []) if isinstance(after, dict) else []
    if executed and blocked:
        return "PARTIALLY_REPAIRED"

    if before.get("repairable_codes") if isinstance(before, dict) else False:
        return "BLOCKED"

    return "BLOCKED"


def get_reconciliation_history(base_path=".", max_results=100):
    """Return reconciliation repair history stored in the existing operation journal.

    This function is read-only and does not create another audit database.
    """
    base_path = os.path.abspath(base_path)

    try:
        max_results = max(1, int(max_results))
    except (TypeError, ValueError):
        max_results = 100

    with _project_directory(base_path):
        store = load_operation_store()

    operations = store.get("operations", []) if isinstance(store, dict) else []
    history = []

    for item in operations:
        if not isinstance(item, dict):
            continue
        if str(item.get("operation_type", "") or "").strip().upper() != RECONCILIATION_OPERATION_TYPE:
            continue

        result_data = item.get("result_data")
        if not isinstance(result_data, dict):
            result_data = {}

        history.append({
            "operation_id": item.get("operation_id"),
            "operation_key": item.get("operation_key"),
            "status": item.get("status"),
            "reconciliation_status": result_data.get("reconciliation_status", "UNKNOWN"),
            "policy_version": result_data.get("policy_version"),
            "policy_fingerprint": result_data.get("policy_fingerprint"),
            "approval": result_data.get("approval"),
            "approval_fingerprint": result_data.get("approval_fingerprint"),
            "approval_fingerprints": result_data.get("approval_fingerprints", []),
            "approval_requirement": result_data.get("approval_requirement"),
            "approval_consumed": bool(result_data.get("approval_consumed", False)),
            "approval_consumed_at": result_data.get("approval_consumed_at"),
            "attempt_count": item.get("attempt_count", 1),
            "recovery_count": item.get("recovery_count", 0),
            "started_at": item.get("started_at"),
            "last_recovery_at": item.get("last_recovery_at"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "before": result_data.get("before"),
            "repair": result_data.get("repair"),
            "after": result_data.get("after"),
            "blocked": result_data.get("blocked", []),
        })

    return history[-max_results:]


def reconcile(base_path=".", dry_run=False, approve=False, approval_context=None, identity_provider=None):
    """Repair deterministic corruption and re-audit the resulting state.

    Set ``dry_run=True`` to simulate the repair against an isolated temporary
    copy. Dry-run mode never changes project files and never creates an
    operation-journal entry.

    The engine never guesses identity, merges Entities, deletes Memories,
    changes conflict decisions, or resolves ambiguous archive/recovery states.
    Such violations remain in the returned ``blocked`` collection.
    """
    base_path = os.path.abspath(base_path)
    before = inspect_reconciliation(base_path)

    dry_run = bool(dry_run)
    approve = bool(approve)
    policy = evaluate_repair_policy(before)
    policy_snapshot = policy.get("policy_snapshot", _policy_snapshot())
    approval_requirement = policy.get(
        "approval_requirement",
        _approval_requirement_for_codes(policy.get("approval_required_codes", [])),
    )
    repair_epoch = _latest_completed_reconciliation_epoch(base_path)
    repair_plan_fingerprint = _repair_plan_identity(before, repair_epoch, policy_snapshot)
    approval = _normalize_approval_context(
        approval_context,
        approve=approve,
        policy_snapshot=policy_snapshot,
        repair_plan_fingerprint=repair_plan_fingerprint,
        repair_epoch=repair_epoch,
        approval_requirement=approval_requirement,
    )

    if before["valid"]:
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "HEALTHY",
            "executed": False,
            "dry_run": dry_run,
            "would_execute": False,
            "approval_granted": approve,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "base_path": base_path,
            "before": before,
            "repair": {
                "changed": False,
            },
            "after": before,
            "simulated_after": before if dry_run else None,
            "impact": {
                "files_would_change": [],
            },
            "blocked": [],
        }

    repairable_codes = before.get("repairable_codes", [])
    if not repairable_codes:
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "DRY_RUN_BLOCKED" if dry_run else "BLOCKED",
            "executed": False,
            "dry_run": dry_run,
            "would_execute": False,
            "approval_granted": approve,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "base_path": base_path,
            "before": before,
            "repair": {
                "changed": False,
            },
            "after": before,
            "simulated_after": before if dry_run else None,
            "impact": {
                "files_would_change": [],
            },
            "blocked": before.get("blocked", []),
        }

    if dry_run:
        simulation = _simulate_repair(base_path, repairable_codes)
        simulated_after = simulation["simulated_after"]
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "DRY_RUN",
            "executed": False,
            "dry_run": True,
            "would_execute": True,
            "approval_granted": approve,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "operation_status": None,
            "operation_id": None,
            "base_path": base_path,
            "before": before,
            "repair": simulation["repair"],
            "repair_plan": simulation["repair_plan"],
            "after": before,
            "simulated_after": simulated_after,
            "impact": {
                "files_would_change": simulation["files_would_change"],
            },
            "blocked": simulated_after.get("blocked", []),
        }

    if policy["blocked_policy_codes"]:
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "BLOCKED",
            "executed": False,
            "dry_run": False,
            "would_execute": False,
            "approval_granted": approve,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "base_path": base_path,
            "before": before,
            "repair": {"changed": False},
            "after": before,
            "simulated_after": None,
            "impact": {"files_would_change": []},
            "blocked": before.get("blocked", []) + [
                {
                    "code": code,
                    "message": "Repair policy is fail-closed for this violation code.",
                    "context": {},
                }
                for code in policy["blocked_policy_codes"]
            ],
        }

    if policy["requires_dry_run"]:
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "DRY_RUN_REQUIRED",
            "executed": False,
            "dry_run": False,
            "would_execute": False,
            "approval_granted": approve,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "base_path": base_path,
            "before": before,
            "repair": {"changed": False},
            "after": before,
            "simulated_after": None,
            "impact": {"files_would_change": []},
            "blocked": before.get("blocked", []),
        }

    if policy["requires_approval"] and not approve:
        return {
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "status": "APPROVAL_REQUIRED",
            "executed": False,
            "dry_run": False,
            "would_execute": False,
            "approval_granted": False,
            "approval": _approval_trace(approval, policy_snapshot),
            "policy": policy,
            "base_path": base_path,
            "before": before,
            "repair_plan_fingerprint": repair_plan_fingerprint,
            "repair": {"changed": False},
            "after": before,
            "simulated_after": None,
            "impact": {"files_would_change": []},
            "blocked": before.get("blocked", []),
        }

    approval_validation = None
    if policy["requires_approval"]:
        approval_validation = _validate_approval(
            approval,
            policy_snapshot,
            repair_plan_fingerprint,
            repair_epoch=repair_epoch,
            approval_requirement=approval_requirement,
            identity_provider=identity_provider,
        )
        if not approval_validation["valid"]:
            return {
                "schema_version": RECONCILIATION_SCHEMA_VERSION,
                "status": approval_validation["status"],
                "executed": False,
                "dry_run": False,
                "would_execute": False,
                "approval_granted": approve,
                "approval": _approval_trace(approval, policy_snapshot),
                "policy": policy,
                "base_path": base_path,
                "before": before,
                "repair_plan_fingerprint": repair_plan_fingerprint,
                "repair": {"changed": False},
                "after": before,
                "simulated_after": None,
                "impact": {"files_would_change": []},
                "blocked": before.get("blocked", []) + [
                    {
                        "code": code,
                        "message": f"Approval validation failed: {approval_validation['status']}",
                        "context": {
                            "policy_version": policy_snapshot.get("version"),
                            "repair_plan_fingerprint": repair_plan_fingerprint,
                        },
                    }
                    for code in approval_validation["codes"]
                ],
            }

    payload = _reconciliation_payload(
        before,
        repair_epoch=repair_epoch,
        approval_context=approval,
        policy_snapshot=policy_snapshot,
    )

    approval_consumption = None
    if policy["requires_approval"]:
        approval_consumption = _approval_consumption_check(
            base_path,
            approval,
            payload,
        )
        if approval_consumption.get("consumed"):
            return {
                "schema_version": RECONCILIATION_SCHEMA_VERSION,
                "status": "APPROVAL_INVALID",
                "executed": False,
                "dry_run": False,
                "would_execute": False,
                "approval_granted": approve,
                "approval": _approval_trace(approval, policy_snapshot),
                "approval_validation": {
                    "valid": False,
                    "status": "APPROVAL_INVALID",
                    "codes": ["APPROVAL_ALREADY_CONSUMED"],
                },
                "approval_consumption": approval_consumption,
                "policy": policy,
                "repair_plan_fingerprint": repair_plan_fingerprint,
                "base_path": base_path,
                "before": before,
                "repair": {"changed": False},
                "after": before,
                "simulated_after": None,
                "impact": {"files_would_change": []},
                "blocked": before.get("blocked", []) + [{
                    "code": "APPROVAL_ALREADY_CONSUMED",
                    "message": "Approval has already been consumed by a completed or failed reconciliation operation.",
                    "context": {
                        "operation_id": approval_consumption.get("operation_id"),
                        "status": approval_consumption.get("status"),
                    },
                }],
            }

    def callback():
        consumed_at = _current_timestamp() if policy["requires_approval"] else None
        before_files = _snapshot_files(base_path)
        repair = _apply_repairs(base_path, repairable_codes)
        after_snapshot = inspect_reconciliation(base_path)
        after_files = _snapshot_files(base_path)
        return {
            "reconciliation_status": _reconciliation_status(before, after_snapshot, True),
            "policy_version": policy_snapshot.get("version"),
            "policy_fingerprint": policy_snapshot.get("fingerprint"),
            "approval": _approval_trace(approval, policy_snapshot),
            "approval_fingerprint": approval.get("fingerprint"),
            "approval_validation": approval_validation,
            "approval_consumed": bool(policy["requires_approval"]),
            "approval_consumed_at": consumed_at,
            "approval_fingerprint": approval.get("approval_fingerprint") or approval.get("fingerprint"),
            "approval_fingerprints": sorted({
                str(
                    item.get("fingerprint")
                    or item.get("approval_fingerprint")
                    or ""
                ).strip()
                for item in approval.get("approvals", [])
                if isinstance(item, dict)
                and str(item.get("fingerprint") or item.get("approval_fingerprint") or "").strip()
            }),
            "approval_requirement": approval_requirement,
            "approval_set_fingerprint": approval.get("approval_set_fingerprint") or approval.get("fingerprint"),
            "repair_plan_fingerprint": repair_plan_fingerprint,
            "before": _audit_snapshot(before),
            "repair": repair,
            "repair_plan": _build_repair_plan(
                before_files,
                after_files,
                repairable_codes,
            ),
            "after": _audit_snapshot(after_snapshot),
            "blocked": after_snapshot.get("blocked", []),
        }

    with _project_directory(base_path):
        operation = run_idempotent(
            RECONCILIATION_OPERATION_TYPE,
            payload,
            callback,
        )

    after = inspect_reconciliation(base_path)
    blocked = after.get("blocked", [])
    executed = bool(operation.get("executed"))
    status = _reconciliation_status(before, after, executed)

    operation_result = operation.get("result")
    if not isinstance(operation_result, dict):
        operation_result = {}

    return {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "status": status,
        "executed": bool(operation.get("executed")),
        "dry_run": False,
        "would_execute": bool(operation.get("executed")),
        "approval_granted": approve,
        "approval": operation_result.get("approval", _approval_trace(approval, policy_snapshot)),
        "approval_validation": operation_result.get("approval_validation", approval_validation),
        "approval_consumption": approval_consumption,
        "approval_consumed": operation_result.get("approval_consumed", False),
        "approval_consumed_at": operation_result.get("approval_consumed_at"),
        "approval_fingerprints": operation_result.get("approval_fingerprints", []),
        "approval_requirement": operation_result.get("approval_requirement", approval_requirement),
        "approval_set_fingerprint": operation_result.get("approval_set_fingerprint", approval.get("approval_set_fingerprint") or approval.get("fingerprint")),
        "policy": policy,
        "repair_plan_fingerprint": repair_plan_fingerprint,
        "operation_status": operation.get("status"),
        "operation_id": (operation.get("record") or {}).get("operation_id"),
        "base_path": base_path,
        "before": before,
        # Keep the established public shape: result["repair"] is the
        # actual repair-details dictionary, not the journal audit wrapper.
        "repair": operation_result.get("repair", operation_result),
        "repair_plan": operation_result.get("repair_plan", {
            "files": [],
            "file_count": 0,
            "change_count": 0,
        }),
        "audit": operation_result,
        "after": after,
        "simulated_after": None,
        "impact": {
            "files_would_change": [],
        },
        "blocked": blocked,
    }


# ==================================================
# Convenience Assertion
# ==================================================


def assert_reconciled(base_path="."):
    result = reconcile(base_path)
    if result.get("status") not in {"HEALTHY", "REPAIRED"}:
        blocked_codes = sorted({
            str(item.get("code", ""))
            for item in result.get("blocked", [])
            if isinstance(item, dict) and item.get("code")
        })
        raise AssertionError(
            f"Reconciliation did not produce a healthy state: {blocked_codes}"
        )
    return result
