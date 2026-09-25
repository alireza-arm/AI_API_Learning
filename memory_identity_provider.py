import base64
import hashlib
import json
import time
import threading
import uuid
from typing import Protocol, runtime_checkable


# ==================================================
# Authoritative Identity Provider Contract
# ==================================================

IDENTITY_PROVIDER_SCHEMA_VERSION = 7
IDENTITY_KEY_DISCOVERY_SCHEMA_VERSION = 1
IDENTITY_STATUS_ACTIVE = "ACTIVE"
IDENTITY_STATUS_INACTIVE = "INACTIVE"
IDENTITY_STATUS_REVOKED = "REVOKED"
IDENTITY_STATUS_SUSPENDED = "SUSPENDED"
IDENTITY_STATUS_UNKNOWN = "UNKNOWN"
IDENTITY_ATTESTATION_ALGORITHM_ED25519 = "Ed25519"
IDENTITY_JWT_SCHEMA_VERSION = 1
IDENTITY_JWT_ALGORITHM_EDDSA = "EdDSA"
IDENTITY_JWT_TYPE = "JWT"
MAX_PROVIDER_NAME_LENGTH = 100
MAX_SUBJECT_LENGTH = 200
MAX_REFERENCE_LENGTH = 200
MAX_ROLE_COUNT = 20
MAX_ROLE_LENGTH = 100
MAX_ATTESTATION_ID_LENGTH = 200
MAX_TIMESTAMP_LENGTH = 100
MAX_KEY_ID_LENGTH = 200
MAX_SIGNATURE_LENGTH = 4096
MAX_ISSUER_LENGTH = 200
MAX_AUDIENCE_LENGTH = 200
MAX_NONCE_LENGTH = 512
MAX_KEY_STATUS_LENGTH = 50
MAX_KEY_FINGERPRINT_LENGTH = 128
MAX_KEY_VERSION_LENGTH = 100
MAX_JWKS_KEYS = 100
MAX_KEY_SOURCE_LENGTH = 300
MAX_KEY_SET_FINGERPRINT_LENGTH = 128
MAX_CONSUMED_ATTESTATIONS = 10000
MAX_CONSUMED_ATTESTATION_ID_LENGTH = 200
MAX_CONSUMPTION_AUDIT_RECORDS = 20000
MAX_JWT_LENGTH = 16384
AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS = 300
AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS = 86400
MAX_JWT_CLAIM_VALUE_LENGTH = 4096
DEFAULT_JWT_CLOCK_SKEW_SECONDS = 60
DEFAULT_JWT_MAX_AGE_SECONDS = 300
OIDC_DISCOVERY_SCHEMA_VERSION = 2
PERSISTED_OIDC_STATE_SCHEMA_VERSION = 4
OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION = 3
OIDC_TRUST_STATE_JOURNAL_LEGACY_SCHEMA_VERSION = 1
OIDC_TRUST_STATE_JOURNAL_PRE_CHECKPOINT_SCHEMA_VERSION = 2
OIDC_TRUST_STATE_JOURNAL_CHECKPOINT_SCHEMA_VERSION = 1
OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS = 500
OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS = 250
OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM = "SHA-256"
OIDC_TRUST_CONFLICT_POLICY_SCHEMA_VERSION = 1
OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE = "RELOAD_AUTHORITATIVE"
OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED = "FAIL_CLOSED"
OIDC_TRUST_CONFLICT_POLICY_DEFAULT = OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE
OIDC_STATE_FILENAME = "memory_oidc_trust_state.json"
DEFAULT_OIDC_DISCOVERY_CACHE_TTL_SECONDS = 300
DEFAULT_OIDC_HTTP_TIMEOUT_SECONDS = 5
DEFAULT_OIDC_REFRESH_BACKOFF_SECONDS = 5
MAX_OIDC_REFRESH_BACKOFF_SECONDS = 300
MAX_OIDC_RESPONSE_BYTES = 1024 * 1024
MAX_OIDC_URL_LENGTH = 2048

IDENTITY_KEY_STATUS_ACTIVE = "ACTIVE"
IDENTITY_KEY_STATUS_GRACE = "GRACE"
IDENTITY_KEY_STATUS_RETIRED = "RETIRED"
IDENTITY_KEY_STATUS_REVOKED = "REVOKED"
IDENTITY_KEY_STATUS_UNKNOWN = "UNKNOWN"
IDENTITY_KEY_VALID_STATUSES = {
    IDENTITY_KEY_STATUS_ACTIVE,
    IDENTITY_KEY_STATUS_GRACE,
    IDENTITY_KEY_STATUS_RETIRED,
    IDENTITY_KEY_STATUS_REVOKED,
    IDENTITY_KEY_STATUS_UNKNOWN,
}


def _canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _b64url_decode(value):
    raw = str(value or "").strip()
    if not raw:
        return b""
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _b64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        from datetime import datetime, timezone

        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_attestation_key_status(value):
    status = str(value or IDENTITY_KEY_STATUS_UNKNOWN).strip().upper()
    return status if status in IDENTITY_KEY_VALID_STATUSES else IDENTITY_KEY_STATUS_UNKNOWN


def _public_key_fingerprint(public_key):
    """Return a SHA256 fingerprint for a trusted public verification key."""
    try:
        if isinstance(public_key, (bytes, bytearray)):
            raw = bytes(public_key)
            try:
                from cryptography.hazmat.primitives import serialization

                if b"BEGIN" in raw:
                    key = serialization.load_pem_public_key(raw)
                else:
                    key = serialization.load_der_public_key(raw)
                raw = key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            except Exception:
                raw = bytes(public_key)
            return hashlib.sha256(raw).hexdigest()

        from cryptography.hazmat.primitives import serialization

        raw = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        return None


class TrustedAttestationKeyRegistry:
    """Trusted verification-key registry with JWKS-style discovery.

    The registry remains an in-process trust boundary. It can be populated
    directly or from a JWKS-shaped dictionary containing ``keys`` entries.
    Discovery never grants trust based on an arbitrary key alone: every key is
    normalized, fingerprinted, associated with an explicit status, and folded
    into a deterministic key-set fingerprint.
    """

    def __init__(self, records=None):
        self._records = {}
        self._source = ""
        self._last_discovered_at = None
        self._key_set_fingerprint = hashlib.sha256(b"{}").hexdigest()
        self._revision = 0
        self._consumed_decision_attestations = {}
        self._consumption_audit_records = []
        self._consumption_audit_head_hash = hashlib.sha256(b"consumption-audit-genesis").hexdigest()
        self._consumption_lock = threading.RLock()

        for record in records or []:
            if not isinstance(record, dict):
                continue
            self.register_key(
                record.get("key_id", ""),
                record.get("public_key"),
                algorithm=record.get("algorithm", IDENTITY_ATTESTATION_ALGORITHM_ED25519),
                status=record.get("status", IDENTITY_KEY_STATUS_ACTIVE),
                not_before=record.get("not_before", ""),
                not_after=record.get("not_after", ""),
                version=record.get("version", ""),
                source=record.get("source", ""),
            )
        self._refresh_registry_fingerprint(force=True)

    def export_persisted_state(self):
        """Export trust state without serializing live cryptography objects."""
        keys = []
        for record in sorted(self._records.values(), key=lambda item: (item.get("algorithm", ""), item.get("key_id", ""))):
            public_key = record.get("public_key")
            jwk = public_key_to_jwk(
                public_key,
                key_id=record.get("key_id", ""),
                version=record.get("version", ""),
                status=record.get("status", IDENTITY_KEY_STATUS_UNKNOWN),
                not_before=record.get("not_before", ""),
                not_after=record.get("not_after", ""),
            )
            jwk.update({
                "status": record.get("status", IDENTITY_KEY_STATUS_UNKNOWN),
                "not_before": record.get("not_before", ""),
                "not_after": record.get("not_after", ""),
                "version": record.get("version", ""),
                "source": record.get("source", ""),
                "fingerprint": record.get("fingerprint", ""),
            })
            keys.append(jwk)
        return {
            "schema_version": IDENTITY_KEY_DISCOVERY_SCHEMA_VERSION,
            "source": self._source,
            "last_discovered_at": self._last_discovered_at,
            "revision": self._revision,
            "key_set_fingerprint": self._key_set_fingerprint,
            "consumed_decision_attestations": {
                key: dict(value) for key, value in sorted(self._consumed_decision_attestations.items())
            },
            "consumption_audit": {
                "schema_version": 1,
                "head_hash": self._consumption_audit_head_hash,
                "records": [dict(item) for item in self._consumption_audit_records],
            },
            "keys": keys,
        }

    def restore_persisted_state(self, state):
        """Restore a previously trusted registry state; reject malformed state."""
        if not isinstance(state, dict):
            raise ValueError("persisted registry state must be an object")
        keys = state.get("keys", [])
        if not isinstance(keys, list) or len(keys) > MAX_JWKS_KEYS:
            raise ValueError("persisted registry keys are invalid")

        restored = TrustedAttestationKeyRegistry()
        for item in keys:
            if not isinstance(item, dict):
                raise ValueError("persisted registry key entry is invalid")
            if str(item.get("source", "") or "").strip() and len(str(item.get("source", ""))) > MAX_KEY_SOURCE_LENGTH:
                raise ValueError("persisted key source is too long")
            normalized = restored._normalize_jwk_record(
                item,
                default_status=item.get("status", IDENTITY_KEY_STATUS_UNKNOWN),
                source=item.get("source", ""),
            )
            expected_fp = str(item.get("fingerprint", "") or "").strip().lower()
            if expected_fp and normalized.get("fingerprint", "").lower() != expected_fp:
                raise ValueError("persisted key fingerprint mismatch")
            restored._records[(normalized["key_id"], normalized["algorithm"])] = normalized

        restored._source = str(state.get("source", "") or "").strip()[:MAX_KEY_SOURCE_LENGTH]
        restored._last_discovered_at = state.get("last_discovered_at")
        restored._refresh_registry_fingerprint(force=True)
        persisted_revision = state.get("revision")
        try:
            persisted_revision = int(persisted_revision)
        except (TypeError, ValueError):
            persisted_revision = restored._revision
        restored._revision = max(restored._revision, persisted_revision)
        persisted_fingerprint = str(state.get("key_set_fingerprint", "") or "").strip()
        if persisted_fingerprint and persisted_fingerprint != restored._key_set_fingerprint:
            raise ValueError("persisted registry fingerprint mismatch")

        self._records = restored._records
        self._source = restored._source
        self._last_discovered_at = restored._last_discovered_at
        self._key_set_fingerprint = restored._key_set_fingerprint
        self._revision = restored._revision

        consumed = state.get("consumed_decision_attestations", {})
        if consumed is None:
            consumed = {}
        if not isinstance(consumed, dict) or len(consumed) > MAX_CONSUMED_ATTESTATIONS:
            raise ValueError("persisted consumed attestation state is invalid")
        normalized_consumed = {}
        for attestation_id, record in consumed.items():
            normalized_id = str(attestation_id or "").strip()[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
            if not normalized_id or not isinstance(record, dict):
                raise ValueError("persisted consumed attestation entry is invalid")
            decision_fingerprint = str(record.get("decision_fingerprint", "") or "").strip().lower()
            nonce = str(record.get("nonce", "") or "").strip()
            consumed_at = record.get("consumed_at")
            try:
                consumed_at = float(consumed_at)
            except (TypeError, ValueError):
                raise ValueError("persisted consumed attestation timestamp is invalid")
            if not decision_fingerprint:
                raise ValueError("persisted consumed attestation fingerprint is missing")
            normalized_consumed[normalized_id] = {
                "decision_fingerprint": decision_fingerprint,
                "nonce": nonce,
                "consumed_at": consumed_at,
            }
        self._consumed_decision_attestations = normalized_consumed

        audit = state.get("consumption_audit", {})
        if audit is None:
            audit = {}
        if not isinstance(audit, dict):
            raise ValueError("persisted consumption audit is invalid")
        records = audit.get("records", [])
        if not isinstance(records, list) or len(records) > MAX_CONSUMPTION_AUDIT_RECORDS:
            raise ValueError("persisted consumption audit records are invalid")
        previous_hash = hashlib.sha256(b"consumption-audit-genesis").hexdigest()
        normalized_audit = []
        for index, item in enumerate(records, start=1):
            if not isinstance(item, dict):
                raise ValueError("persisted consumption audit record is invalid")
            record = dict(item)
            if int(record.get("sequence", 0) or 0) != index:
                raise ValueError("persisted consumption audit sequence is invalid")
            record_previous = str(record.get("previous_hash", "") or "")
            record_hash = str(record.get("record_hash", "") or "")
            if record_previous != previous_hash or not record_hash:
                raise ValueError("persisted consumption audit hash chain is invalid")
            unsigned = dict(record)
            unsigned.pop("record_hash", None)
            expected_hash = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            if expected_hash != record_hash:
                raise ValueError("persisted consumption audit record hash mismatch")
            normalized_audit.append(record)
            previous_hash = record_hash
        persisted_head = str(audit.get("head_hash", "") or "")
        if persisted_head and persisted_head != previous_hash:
            raise ValueError("persisted consumption audit head hash mismatch")
        self._consumption_audit_records = normalized_audit
        self._consumption_audit_head_hash = previous_hash
        return self.get_registry_metadata()

    def _refresh_registry_fingerprint(self, force=False):
        canonical_records = []
        for record in self._records.values():
            canonical_records.append({
                "key_id": record.get("key_id"),
                "algorithm": record.get("algorithm"),
                "status": record.get("status"),
                "fingerprint": record.get("fingerprint"),
                "not_before": record.get("not_before"),
                "not_after": record.get("not_after"),
                "version": record.get("version"),
            })
        canonical_records.sort(key=lambda item: _canonical_json(item))
        fingerprint = hashlib.sha256(
            _canonical_json({
                "schema_version": IDENTITY_KEY_DISCOVERY_SCHEMA_VERSION,
                "records": canonical_records,
            }).encode("utf-8")
        ).hexdigest()
        if force or fingerprint != self._key_set_fingerprint:
            self._revision += 1
        self._key_set_fingerprint = fingerprint
        return fingerprint

    def register_key(
        self,
        key_id,
        public_key,
        algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        status=IDENTITY_KEY_STATUS_ACTIVE,
        not_before="",
        not_after="",
        version="",
        source="",
    ):
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        algorithm = str(algorithm or "").strip()[:100]
        status = normalize_attestation_key_status(status)
        version = str(version or "").strip()[:MAX_KEY_VERSION_LENGTH]
        not_before = str(not_before or "").strip()[:MAX_TIMESTAMP_LENGTH]
        not_after = str(not_after or "").strip()[:MAX_TIMESTAMP_LENGTH]
        source = str(source or "").strip()[:MAX_KEY_SOURCE_LENGTH]

        if not key_id or not public_key or not algorithm:
            raise ValueError("key_id, public_key and algorithm are required")
        fingerprint = _public_key_fingerprint(public_key)
        if fingerprint is None:
            raise ValueError("public_key fingerprint could not be calculated")

        before = self._records.get((key_id, algorithm))
        self._records[(key_id, algorithm)] = {
            "key_id": key_id,
            "algorithm": algorithm,
            "status": status,
            "public_key": public_key,
            "fingerprint": fingerprint,
            "not_before": not_before,
            "not_after": not_after,
            "version": version,
            "source": source,
        }
        self._refresh_registry_fingerprint(force=before is None or before != self._records[(key_id, algorithm)])
        return self.get_verification_key_metadata(key_id, algorithm)

    def set_status(self, key_id, status, algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519):
        record = self._records.get((str(key_id or "").strip(), str(algorithm or "").strip()))
        if record is None:
            return False
        normalized_status = normalize_attestation_key_status(status)
        if record["status"] != normalized_status:
            record["status"] = normalized_status
            self._refresh_registry_fingerprint()
        return True

    def get_verification_key(self, key_id, algorithm):
        record = self._records.get((str(key_id or "").strip(), str(algorithm or "").strip()))
        if record is None:
            return None
        return record["public_key"]

    def get_verification_key_metadata(self, key_id, algorithm):
        record = self._records.get((str(key_id or "").strip(), str(algorithm or "").strip()))
        if record is None:
            return None
        return {
            "key_id": record["key_id"],
            "algorithm": record["algorithm"],
            "status": record["status"],
            "fingerprint": record["fingerprint"],
            "not_before": record["not_before"],
            "not_after": record["not_after"],
            "version": record["version"],
            "source": record.get("source", ""),
            "registry_revision": self._revision,
            "key_set_fingerprint": self._key_set_fingerprint,
        }

    def list_key_metadata(self):
        return [
            self.get_verification_key_metadata(record["key_id"], record["algorithm"])
            for record in sorted(
                self._records.values(),
                key=lambda item: (item.get("algorithm", ""), item.get("key_id", "")),
            )
        ]

    def get_consumed_decision_attestation(self, attestation_id):
        attestation_id = str(attestation_id or "").strip()
        record = self._consumed_decision_attestations.get(attestation_id)
        return dict(record) if isinstance(record, dict) else None

    def get_decision_attestation_consumption_status(
        self,
        attestation_id,
        *,
        verify_integrity=True,
        include_replay_events=True,
    ):
        """Return a read-only, cross-checked proof of one-time consumption status.

        The status is derived from the existing one-time-consumption ledger and
        the immutable consumption-audit chain. No claim, audit append,
        persistence, or authoritative-state mutation is performed.
        """
        normalized_id = str(attestation_id or "").strip()[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
        if not normalized_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_INVALID",
                "reason": "attestation_id_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        with self._consumption_lock:
            consumed_record = self._consumed_decision_attestations.get(normalized_id)
            consumed_record = dict(consumed_record) if isinstance(consumed_record, dict) else None
            audit_records = [
                dict(record)
                for record in self._consumption_audit_records
                if str(record.get("attestation_id", "") or "") == normalized_id
            ]
            head_hash = str(self._consumption_audit_head_hash or "")

            verification = None
            if verify_integrity:
                verification = self._verify_consumption_audit_records(
                    [dict(record) for record in self._consumption_audit_records],
                    head_hash,
                )
                if not verification.get("valid"):
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                        "reason": verification.get("reason", "integrity_check_failed"),
                        "verification": verification,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }

            consumed_events = [
                record
                for record in audit_records
                if str(record.get("event_type", "") or "") in {
                    "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
                    "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED",
                    "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED",
                    "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMED",
                    "DECISION_ATTESTATION_CONSUMED",
                }
            ]
            replay_events = [
                record
                for record in audit_records
                if str(record.get("event_type", "") or "") in {
                    "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED",
                    "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAY_REJECTED",
                    "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAY_REJECTED",
                    "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAY_REJECTED",
                    "DECISION_ATTESTATION_REPLAY_REJECTED",
                }
            ]

            if consumed_record is None:
                if consumed_events or replay_events:
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                        "reason": "audit_events_exist_without_consumption_claim",
                        "audit_events": audit_records,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }
                return {
                    "success": True,
                    "status": "DECISION_ATTESTATION_UNCONSUMED",
                    "attestation_id": normalized_id,
                    "consumed": False,
                    "consumed_record": None,
                    "consumption_audit_record": None,
                    "replay_events": [],
                    "verification": verification if verify_integrity else None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            if len(consumed_events) != 1:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                    "reason": "invalid_consumption_event_count",
                    "consumed_event_count": len(consumed_events),
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            consumption_event = consumed_events[0]
            expected_fingerprint = str(consumed_record.get("decision_fingerprint", "") or "").lower()
            actual_fingerprint = str(consumption_event.get("decision_fingerprint", "") or "").lower()
            if expected_fingerprint != actual_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                    "reason": "consumption_fingerprint_mismatch",
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            if str(consumed_record.get("nonce", "") or "") != str(consumption_event.get("nonce", "") or ""):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                    "reason": "consumption_nonce_mismatch",
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            try:
                consumed_at = float(consumed_record.get("consumed_at"))
                event_at = float(consumption_event.get("event_at"))
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                    "reason": "consumption_timestamp_invalid",
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            if consumed_at != event_at:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_STATUS_TAMPERED",
                    "reason": "consumption_timestamp_mismatch",
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            return {
                "success": True,
                "status": "DECISION_ATTESTATION_CONSUMED",
                "attestation_id": normalized_id,
                "consumed": True,
                "consumed_record": consumed_record,
                "consumption_audit_record": dict(consumption_event),
                "replay_events": [dict(record) for record in replay_events] if include_replay_events else [],
                "replay_count": len(replay_events),
                "verification": verification if verify_integrity else None,
                "audit_head_hash": head_hash,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

    @staticmethod
    def _normalize_consumption_audit_time_bound(value, field_name):
        """Normalize an audit time bound to a finite Unix timestamp.

        Numeric Unix timestamps remain the canonical representation used by the
        persisted audit records. ISO-8601 strings are accepted as a convenience
        for human-facing audit queries without changing persisted data.
        """
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be a finite timestamp")
        try:
            numeric = float(value)
            if numeric == numeric and abs(numeric) != float("inf"):
                return numeric
        except (TypeError, ValueError):
            pass

        parsed = _parse_timestamp(str(value).strip())
        if parsed is None:
            raise ValueError(f"{field_name} must be a finite Unix timestamp or ISO-8601 timestamp")
        return parsed.timestamp()

    @classmethod
    def _verify_consumption_audit_records(cls, records, head_hash):
        """Verify the complete immutable decision-consumption audit hash chain."""
        if not isinstance(records, list):
            return {
                "valid": False,
                "reason": "records_not_list",
                "checked_records": 0,
            }

        previous_hash = hashlib.sha256(b"consumption-audit-genesis").hexdigest()
        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                return {
                    "valid": False,
                    "reason": "record_not_object",
                    "checked_records": index - 1,
                    "sequence": index,
                }

            try:
                sequence = int(record.get("sequence", 0) or 0)
            except (TypeError, ValueError):
                return {
                    "valid": False,
                    "reason": "invalid_sequence",
                    "checked_records": index - 1,
                    "sequence": index,
                }

            record_previous_hash = str(record.get("previous_hash", "") or "")
            record_hash = str(record.get("record_hash", "") or "")
            if sequence != index or record_previous_hash != previous_hash:
                return {
                    "valid": False,
                    "reason": "hash_chain_mismatch",
                    "checked_records": index - 1,
                    "sequence": index,
                }
            if not record_hash:
                return {
                    "valid": False,
                    "reason": "record_hash_missing",
                    "checked_records": index - 1,
                    "sequence": index,
                }

            unsigned = dict(record)
            unsigned.pop("record_hash", None)
            expected_hash = hashlib.sha256(
                _canonical_json(unsigned).encode("utf-8")
            ).hexdigest()
            if expected_hash != record_hash:
                return {
                    "valid": False,
                    "reason": "record_hash_mismatch",
                    "checked_records": index - 1,
                    "sequence": index,
                }
            previous_hash = record_hash

        expected_head = previous_hash
        actual_head = str(head_hash or "")
        if expected_head != actual_head:
            return {
                "valid": False,
                "reason": "head_hash_mismatch",
                "checked_records": len(records),
                "expected_head_hash": expected_head,
                "actual_head_hash": actual_head,
            }

        return {
            "valid": True,
            "reason": "ok",
            "checked_records": len(records),
            "head_hash": expected_head,
            "first_sequence": 1 if records else None,
            "last_sequence": len(records) if records else 0,
        }

    def query_decision_attestation_consumption_audit(
        self,
        *,
        attestation_id="",
        decision_fingerprint="",
        event_type="",
        start_sequence=None,
        end_sequence=None,
        start_time=None,
        end_time=None,
        limit=100,
        reverse=True,
        verify_integrity=True,
    ):
        """Safely query the immutable decision-attestation consumption audit.

        The query works only on a snapshot taken under the registry's existing
        in-process consumption lock. It never appends audit records, changes
        the one-time-consumption ledger, persists state, or mutates the
        authoritative trust state.
        """
        attestation_id = str(attestation_id or "").strip()[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
        decision_fingerprint = str(decision_fingerprint or "").strip().lower()
        event_type = str(event_type or "").strip().upper()

        try:
            start = None if start_sequence is None else int(start_sequence)
            end = None if end_sequence is None else int(end_sequence)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "invalid_sequence_range",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if start is not None and start < 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "start_sequence_must_be_positive",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if end is not None and end < 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "end_sequence_must_be_positive",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if start is not None and end is not None and start > end:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "start_sequence_after_end_sequence",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            start_at = self._normalize_consumption_audit_time_bound(
                start_time,
                "start_time",
            )
            end_at = self._normalize_consumption_audit_time_bound(
                end_time,
                "end_time",
            )
        except ValueError as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if start_at is not None and end_at is not None and start_at > end_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "start_time_after_end_time",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            limit_value = int(limit)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "invalid_limit",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if limit_value < 1 or limit_value > MAX_CONSUMPTION_AUDIT_RECORDS:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_INVALID",
                "reason": "invalid_limit",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        with self._consumption_lock:
            records_snapshot = [dict(record) for record in self._consumption_audit_records]
            head_hash = str(self._consumption_audit_head_hash or "")

            if verify_integrity:
                verification = self._verify_consumption_audit_records(
                    records_snapshot,
                    head_hash,
                )
                if not verification.get("valid"):
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_AUDIT_TAMPERED",
                        "reason": verification.get("reason", "integrity_check_failed"),
                        "sequence": verification.get("sequence"),
                        "checked_records": verification.get("checked_records", 0),
                        "expected_head_hash": verification.get("expected_head_hash"),
                        "actual_head_hash": verification.get("actual_head_hash", head_hash),
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }

            coverage_start = 1 if records_snapshot else 0
            coverage_end = len(records_snapshot)
            selected = []
            for record in records_snapshot:
                sequence = int(record.get("sequence", 0) or 0)
                if start is not None and sequence < start:
                    continue
                if end is not None and sequence > end:
                    continue
                if attestation_id and str(record.get("attestation_id", "")) != attestation_id:
                    continue
                if decision_fingerprint and str(record.get("decision_fingerprint", "")).lower() != decision_fingerprint:
                    continue
                if event_type and str(record.get("event_type", "")).upper() != event_type:
                    continue

                try:
                    event_at = float(record.get("event_at"))
                except (TypeError, ValueError):
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_AUDIT_TAMPERED",
                        "reason": "record_event_at_invalid",
                        "sequence": sequence,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }
                if start_at is not None and event_at < start_at:
                    continue
                if end_at is not None and event_at > end_at:
                    continue
                selected.append(record)

            selected.sort(
                key=lambda item: int(item.get("sequence", 0) or 0),
                reverse=bool(reverse),
            )
            selected = selected[:limit_value]

            return {
                "success": True,
                "status": "DECISION_ATTESTATION_AUDIT_QUERY_OK",
                "records": selected,
                "count": len(selected),
                "limit": limit_value,
                "reverse": bool(reverse),
                "filters": {
                    "attestation_id": attestation_id or None,
                    "decision_fingerprint": decision_fingerprint or None,
                    "event_type": event_type or None,
                    "start_sequence": start,
                    "end_sequence": end,
                    "start_time": start_at,
                    "end_time": end_at,
                },
                "coverage_start_sequence": coverage_start,
                "coverage_end_sequence": coverage_end,
                "head_hash": head_hash,
                "integrity_verified": bool(verify_integrity),
                "verification": verification if verify_integrity else None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

    def get_decision_attestation_consumption_audit(
        self,
        *,
        attestation_id="",
        decision_fingerprint="",
        event_type="",
        start_sequence=None,
        end_sequence=None,
        start_time=None,
        end_time=None,
        limit=100,
        reverse=True,
        verify_integrity=True,
    ):
        """Backward-compatible wrapper for the consumption-audit query API."""
        result = self.query_decision_attestation_consumption_audit(
            attestation_id=attestation_id,
            decision_fingerprint=decision_fingerprint,
            event_type=event_type,
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            reverse=reverse,
            verify_integrity=verify_integrity,
        )
        if result.get("success"):
            result = dict(result)
            result["status"] = "DECISION_ATTESTATION_AUDIT_OK"
        return result

    def get_decision_attestation_consumption_audit_timeline(
        self,
        *,
        attestation_id="",
        decision_fingerprint="",
        event_type="",
        start_sequence=None,
        end_sequence=None,
        start_time=None,
        end_time=None,
        limit=100,
        reverse=True,
        verify_integrity=True,
    ):
        """Return a readable, authenticated timeline of consumption events."""
        result = self.query_decision_attestation_consumption_audit(
            attestation_id=attestation_id,
            decision_fingerprint=decision_fingerprint,
            event_type=event_type,
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            reverse=reverse,
            verify_integrity=verify_integrity,
        )
        if not result.get("success"):
            return result

        from datetime import datetime, timezone

        timeline = []
        for record in result.get("records", []):
            try:
                event_at = float(record.get("event_at"))
                event_at_iso = datetime.fromtimestamp(
                    event_at,
                    tz=timezone.utc,
                ).isoformat()
            except (TypeError, ValueError, OverflowError, OSError):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_AUDIT_TAMPERED",
                    "reason": "record_event_at_invalid",
                    "sequence": record.get("sequence"),
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            timeline.append({
                "sequence": int(record.get("sequence", 0) or 0),
                "event_type": str(record.get("event_type", "") or ""),
                "attestation_id": str(record.get("attestation_id", "") or ""),
                "decision_fingerprint": str(record.get("decision_fingerprint", "") or "").lower(),
                "nonce": str(record.get("nonce", "") or ""),
                "event_at": event_at,
                "event_at_iso": event_at_iso,
                "reason": str(record.get("reason", "") or ""),
                "previous_hash": str(record.get("previous_hash", "") or ""),
                "record_hash": str(record.get("record_hash", "") or ""),
            })

        return {
            **result,
            "status": "DECISION_ATTESTATION_AUDIT_TIMELINE",
            "timeline": timeline,
            "timeline_count": len(timeline),
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _consumption_audit_genesis_hash():
        return hashlib.sha256(b"consumption-audit-genesis").hexdigest()

    @staticmethod
    def _normalize_consumption_audit_sequence_bound(value, field_name, *, default=None):
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be a positive integer")
        try:
            normalized = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field_name} must be an integer")
        if normalized < 1:
            raise ValueError(f"{field_name} must be positive")
        return normalized

    def export_decision_attestation_consumption_audit_evidence(
        self,
        *,
        start_sequence=None,
        end_sequence=None,
    ):
        """Export a self-verifying chain prefix plus a selected audit slice."""
        try:
            start = self._normalize_consumption_audit_sequence_bound(
                start_sequence, "start_sequence", default=1
            )
            end = self._normalize_consumption_audit_sequence_bound(
                end_sequence, "end_sequence", default=None
            )
        except ValueError as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID_QUERY",
                "reason": str(exc)[:300],
                "evidence": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if end is not None and start > end:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID_QUERY",
                "reason": "start_sequence_after_end_sequence",
                "evidence": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        def snapshot():
            with self._consumption_lock:
                records = [dict(item) for item in self._consumption_audit_records]
                head_hash = str(self._consumption_audit_head_hash or "")
                verification = self._verify_consumption_audit_records(records, head_hash)
                if not verification.get("valid"):
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_AUDIT_TAMPERED",
                        "reason": verification.get("reason", "integrity_check_failed"),
                        "verification": verification,
                        "evidence": None,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }

                coverage_end = len(records)
                resolved_end = coverage_end if end is None else end
                if resolved_end > coverage_end:
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_UNAVAILABLE",
                        "reason": "requested_sequence_after_audit_head",
                        "coverage_start_sequence": 1 if records else 0,
                        "coverage_end_sequence": coverage_end,
                        "evidence": None,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }
                if resolved_end == 0:
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_UNAVAILABLE",
                        "reason": "audit_history_empty",
                        "coverage_start_sequence": 0,
                        "coverage_end_sequence": 0,
                        "evidence": None,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }

                prefix = [dict(item) for item in records[:resolved_end]]
                selected = [dict(item) for item in prefix if start <= int(item.get("sequence", 0) or 0) <= resolved_end]
                return {
                    "success": True,
                    "prefix": prefix,
                    "selected": selected,
                    "head_hash": head_hash,
                    "verification": verification,
                    "coverage_end": coverage_end,
                    "resolved_end": resolved_end,
                }

        first = snapshot()
        if not first.get("success"):
            return first
        second = snapshot()
        if not second.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_CHANGED_DURING_EXPORT",
                "reason": "audit_changed_between_evidence_reads",
                "evidence": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        identity_fields = ("head_hash", "coverage_end", "resolved_end")
        before = {field: first.get(field) for field in identity_fields}
        before["record_hashes"] = [item.get("record_hash") for item in first["prefix"]]
        before["selected_sequences"] = [item.get("sequence") for item in first["selected"]]
        after = {field: second.get(field) for field in identity_fields}
        after["record_hashes"] = [item.get("record_hash") for item in second["prefix"]]
        after["selected_sequences"] = [item.get("sequence") for item in second["selected"]]
        if before != after:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_CHANGED_DURING_EXPORT",
                "reason": "audit_changed_between_evidence_reads",
                "audit_identity_before": before,
                "audit_identity_after": after,
                "evidence": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        prefix = [dict(item) for item in first["prefix"]]
        selected = [dict(item) for item in first["selected"]]
        evidence = {
            "schema_version": 1,
            "evidence_type": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE",
            "chain_start_sequence": 1,
            "chain_end_sequence": first["resolved_end"],
            "selected_start_sequence": start,
            "selected_end_sequence": first["resolved_end"],
            "audit_head_hash": first["head_hash"],
            "chain_head_hash": prefix[-1].get("record_hash", ""),
            "records": prefix,
            "selected_records": selected,
            "query": {"start_sequence": start, "end_sequence": end},
            "audit_verification": dict(first.get("verification") or {}),
            "exported_at": float(time.time()),
            "evidence_fingerprint": "",
        }
        payload = dict(evidence)
        payload.pop("exported_at", None)
        payload.pop("evidence_fingerprint", None)
        evidence["evidence_fingerprint"] = hashlib.sha256(
            _canonical_json(payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_EXPORTED",
            "evidence": evidence,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence(cls, evidence):
        """Verify a consumption-audit evidence package without storage access."""
        if not isinstance(evidence, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "evidence_must_be_object"}

        required = (
            "schema_version", "evidence_type", "chain_start_sequence",
            "chain_end_sequence", "selected_start_sequence",
            "selected_end_sequence", "audit_head_hash", "chain_head_hash",
            "records", "selected_records", "query", "audit_verification",
            "evidence_fingerprint",
        )
        missing = [field for field in required if field not in evidence]
        if missing:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "missing_evidence_fields", "fields": missing}
        if int(evidence.get("schema_version", 0) or 0) != 1:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "unsupported_evidence_schema"}
        if evidence.get("evidence_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE":
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "unsupported_evidence_type"}

        records = evidence.get("records")
        selected_records = evidence.get("selected_records")
        if not isinstance(records, list) or not isinstance(selected_records, list):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "records_not_list"}

        try:
            chain_start = int(evidence.get("chain_start_sequence", 0) or 0)
            chain_end = int(evidence.get("chain_end_sequence", 0) or 0)
            selected_start = int(evidence.get("selected_start_sequence", 0) or 0)
            selected_end = int(evidence.get("selected_end_sequence", 0) or 0)
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_sequence_metadata"}

        if chain_start != (1 if records else 0) or chain_end != len(records):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_chain_coverage"}
        if not records:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "empty_evidence_chain"}
        if selected_start < 1 or selected_start > chain_end or selected_end < selected_start or selected_end > chain_end:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_selected_range"}

        query = evidence.get("query")
        if not isinstance(query, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "query_not_object"}
        try:
            query_start = int(query.get("start_sequence", 0) or 0)
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_query_start_sequence"}
        query_end = query.get("end_sequence")
        if query_end is not None:
            try:
                query_end = int(query_end)
            except (TypeError, ValueError):
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_query_end_sequence"}
        if query_start != selected_start or (query_end is not None and query_end != selected_end):
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "query_selection_mismatch"}

        previous_hash = cls._consumption_audit_genesis_hash()
        for expected_sequence, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "record_not_object", "sequence": expected_sequence}
            try:
                sequence = int(record.get("sequence", 0) or 0)
            except (TypeError, ValueError):
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "invalid_sequence", "sequence": expected_sequence}
            if sequence != expected_sequence:
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "non_contiguous_record_chain", "sequence": expected_sequence}
            if str(record.get("previous_hash", "") or "") != previous_hash:
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "previous_hash_mismatch", "sequence": sequence}
            record_hash = str(record.get("record_hash", "") or "")
            if not record_hash:
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "record_hash_missing", "sequence": sequence}
            unsigned = dict(record)
            unsigned.pop("record_hash", None)
            expected_hash = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            if record_hash != expected_hash:
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "record_hash_mismatch", "sequence": sequence}
            previous_hash = record_hash

        chain_head_hash = str(evidence.get("chain_head_hash", "") or "")
        audit_head_hash = str(evidence.get("audit_head_hash", "") or "")
        if chain_head_hash != previous_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "chain_head_hash_mismatch",
            }
        audit_verification = evidence.get("audit_verification")
        if not isinstance(audit_verification, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "audit_verification_not_object",
            }
        if audit_verification.get("valid") is not True:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "embedded_audit_verification_invalid",
            }
        try:
            verified_checked_records = int(audit_verification.get("checked_records", -1))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "embedded_audit_verification_count_invalid",
            }
        if verified_checked_records < chain_end:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "embedded_audit_verification_count_mismatch",
            }
        if str(audit_verification.get("head_hash", "") or "") != audit_head_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "audit_head_hash_mismatch",
            }
        if int(audit_verification.get("first_sequence", 0) or 0) != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "embedded_audit_verification_first_sequence_mismatch",
            }
        if int(audit_verification.get("last_sequence", 0) or 0) != verified_checked_records:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID",
                "reason": "embedded_audit_verification_last_sequence_mismatch",
            }

        expected_selected = list(range(selected_start, selected_end + 1))
        actual_selected = [int(item.get("sequence", 0) or 0) for item in selected_records if isinstance(item, dict)]
        if actual_selected != expected_selected:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "selected_record_range_mismatch"}
        by_sequence = {int(item["sequence"]): item for item in records}
        for item in selected_records:
            if not isinstance(item, dict):
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "selected_record_not_object"}
            sequence = int(item.get("sequence", 0) or 0)
            if sequence not in by_sequence or _canonical_json(item) != _canonical_json(by_sequence[sequence]):
                return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "selected_record_mismatch", "sequence": sequence}

        payload = dict(evidence)
        payload.pop("exported_at", None)
        expected_fingerprint = str(payload.pop("evidence_fingerprint", "") or "")
        actual_fingerprint = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        if expected_fingerprint != actual_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_INVALID", "reason": "evidence_fingerprint_mismatch", "expected_fingerprint": expected_fingerprint, "actual_fingerprint": actual_fingerprint}

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_AUDIT_EVIDENCE_VERIFIED",
            "chain_start_sequence": chain_start,
            "chain_end_sequence": chain_end,
            "selected_start_sequence": selected_start,
            "selected_end_sequence": selected_end,
            "record_count": len(records),
            "selected_record_count": len(selected_records),
            "chain_head_hash": previous_hash,
            "audit_head_hash": str(evidence.get("audit_head_hash", "") or ""),
            "evidence_fingerprint": actual_fingerprint,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def _append_decision_attestation_consumption_audit(self, *, event_type, attestation_id, decision_fingerprint, nonce="", consumed_at=None, reason="", previous_consumed_record=None):
        if len(self._consumption_audit_records) >= MAX_CONSUMPTION_AUDIT_RECORDS:
            return {"success": False, "status": "DECISION_ATTESTATION_AUDIT_FULL", "reason": "consumption_audit_full"}
        sequence = len(self._consumption_audit_records) + 1
        record = {
            "sequence": sequence,
            "event_type": str(event_type),
            "attestation_id": str(attestation_id),
            "decision_fingerprint": str(decision_fingerprint or "").lower(),
            "nonce": str(nonce or ""),
            "event_at": float(time.time() if consumed_at is None else consumed_at),
            "reason": str(reason or ""),
        }
        if isinstance(previous_consumed_record, dict):
            record["previous_consumed_record"] = dict(previous_consumed_record)
        record["previous_hash"] = self._consumption_audit_head_hash
        record_hash = hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()
        record["record_hash"] = record_hash
        self._consumption_audit_records.append(record)
        self._consumption_audit_head_hash = record_hash
        return {"success": True, "status": "DECISION_ATTESTATION_AUDIT_RECORDED", "record": dict(record)}

    def consume_decision_attestation(self, attestation_id, decision_fingerprint, *, nonce="", consumed_at=None):
        """Atomically claim a decision attestation for one-time use.

        The consumption ledger is part of the existing trusted registry state,
        so no additional database/file is introduced. A previously consumed
        attestation is never silently overwritten, even when the fingerprint
        or nonce differs.
        """
        attestation_id = str(attestation_id or "").strip()[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
        decision_fingerprint = str(decision_fingerprint or "").strip().lower()
        nonce = str(nonce or "").strip()
        if not attestation_id or not decision_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "attestation_id_and_decision_fingerprint_required"}
        if len(self._consumed_decision_attestations) >= MAX_CONSUMED_ATTESTATIONS and attestation_id not in self._consumed_decision_attestations:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "consumption_ledger_full"}
        existing = self._consumed_decision_attestations.get(attestation_id)
        if existing is not None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_REPLAYED",
                "reason": "attestation_already_consumed",
                "attestation_id": attestation_id,
                "consumed_record": dict(existing),
            }
        if consumed_at is None:
            consumed_at = time.time()
        try:
            consumed_at = float(consumed_at)
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "invalid_consumed_at"}
        self._consumed_decision_attestations[attestation_id] = {
            "decision_fingerprint": decision_fingerprint,
            "nonce": nonce,
            "consumed_at": consumed_at,
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMED",
            "attestation_id": attestation_id,
            "decision_fingerprint": decision_fingerprint,
            "nonce": nonce,
            "consumed_at": consumed_at,
        }

    def retire_source_keys(self, source):
        """Move ACTIVE/GRACE keys from one retired JWKS source to RETIRED."""
        source = str(source or "").strip()[:MAX_KEY_SOURCE_LENGTH]
        if not source:
            return []

        retired = []
        changed = False
        for record in self._records.values():
            if record.get("source") != source:
                continue
            if record.get("status") in {
                IDENTITY_KEY_STATUS_ACTIVE,
                IDENTITY_KEY_STATUS_GRACE,
            }:
                record["status"] = IDENTITY_KEY_STATUS_RETIRED
                retired.append({
                    "key_id": record.get("key_id"),
                    "algorithm": record.get("algorithm"),
                })
                changed = True

        if changed:
            self._refresh_registry_fingerprint()
        return retired

    def get_registry_metadata(self):
        return {
            "schema_version": IDENTITY_KEY_DISCOVERY_SCHEMA_VERSION,
            "source": self._source,
            "last_discovered_at": self._last_discovered_at,
            "revision": self._revision,
            "key_set_fingerprint": self._key_set_fingerprint,
            "key_count": len(self._records),
        }

    def discover_key(self, key_id, algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519):
        """Return a trusted key plus metadata without changing registry state."""
        metadata = self.get_verification_key_metadata(key_id, algorithm)
        if metadata is None:
            return None
        return {
            "public_key": self.get_verification_key(key_id, algorithm),
            "metadata": metadata,
        }

    def refresh_from_jwks(
        self,
        jwks,
        *,
        source="jwks",
        retire_missing=False,
        default_status=IDENTITY_KEY_STATUS_ACTIVE,
    ):
        """Import a JWKS-shaped mapping and safely rotate trusted keys.

        Supported Ed25519 JWK shape:
        ``{"kty":"OKP","crv":"Ed25519","x":"...","kid":"..."}``.
        Optional status/version/time metadata is preserved when supplied.
        Missing existing keys are only moved to ``RETIRED`` when
        ``retire_missing=True``; they are never silently revoked.
        """
        if not isinstance(jwks, dict):
            raise ValueError("jwks must be a dictionary")

        raw_keys = jwks.get("keys")
        if not isinstance(raw_keys, list):
            raise ValueError("jwks must contain a keys list")
        if len(raw_keys) > MAX_JWKS_KEYS:
            raise ValueError(f"jwks exceeds MAX_JWKS_KEYS={MAX_JWKS_KEYS}")

        before_fingerprint = self._key_set_fingerprint
        discovered = []
        rejected = []
        incoming_pairs = set()

        for index, raw_key in enumerate(raw_keys):
            try:
                normalized = self._normalize_jwk_record(raw_key, default_status=default_status, source=source)
                pair = (normalized["key_id"], normalized["algorithm"])
                incoming_pairs.add(pair)
                existing = self._records.get(pair)
                if existing is not None and not raw_key.get("status"):
                    normalized["status"] = existing.get("status", normalized["status"])
                self._records[pair] = normalized
                discovered.append(self.get_verification_key_metadata(*pair))
            except Exception as exc:
                rejected.append({
                    "index": index,
                    "error": str(exc)[:300],
                })

        retired = []
        if retire_missing:
            for pair, record in self._records.items():
                if pair in incoming_pairs:
                    continue
                if record.get("source") != source:
                    continue
                if record.get("status") in {
                    IDENTITY_KEY_STATUS_ACTIVE,
                    IDENTITY_KEY_STATUS_GRACE,
                }:
                    record["status"] = IDENTITY_KEY_STATUS_RETIRED
                    retired.append({
                        "key_id": record.get("key_id"),
                        "algorithm": record.get("algorithm"),
                    })

        self._source = str(source or "").strip()[:MAX_KEY_SOURCE_LENGTH]
        from datetime import datetime, timezone

        self._last_discovered_at = datetime.now(timezone.utc).isoformat()
        after_fingerprint = self._refresh_registry_fingerprint(force=False)

        return {
            "schema_version": IDENTITY_KEY_DISCOVERY_SCHEMA_VERSION,
            "source": self._source,
            "discovered": discovered,
            "rejected": rejected,
            "retired": retired,
            "changed": after_fingerprint != before_fingerprint,
            "registry": self.get_registry_metadata(),
        }

    def _normalize_jwk_record(self, raw_key, default_status=IDENTITY_KEY_STATUS_ACTIVE, source=""):
        if not isinstance(raw_key, dict):
            raise ValueError("JWK entry must be an object")

        kty = str(raw_key.get("kty", "") or "").strip().upper()
        crv = str(raw_key.get("crv", "") or "").strip()
        kid = str(raw_key.get("kid", "") or "").strip()
        alg = str(raw_key.get("alg", "") or "").strip()
        use = str(raw_key.get("use", "") or "").strip().lower()
        x = str(raw_key.get("x", "") or "").strip()

        if kty != "OKP" or crv != "Ed25519":
            raise ValueError("unsupported JWK key type; expected OKP/Ed25519")
        if use and use != "sig":
            raise ValueError("JWK use must be sig when provided")
        if alg and alg != "EdDSA":
            raise ValueError("unsupported Ed25519 JWK algorithm")
        if not kid:
            raise ValueError("JWK kid is required")
        if not x:
            raise ValueError("JWK x is required")

        try:
            raw_public_key = _b64url_decode(x)
        except Exception as exc:
            raise ValueError("invalid JWK x encoding") from exc
        if len(raw_public_key) != 32:
            raise ValueError("Ed25519 JWK x must decode to 32 bytes")

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            public_key = Ed25519PublicKey.from_public_bytes(raw_public_key)
        except ImportError as exc:
            raise ValueError("cryptography is required for JWKS Ed25519 discovery") from exc

        status = normalize_attestation_key_status(raw_key.get("status", default_status))
        not_before = raw_key.get("not_before", raw_key.get("nbf", ""))
        not_after = raw_key.get("not_after", raw_key.get("exp", ""))
        not_before = _normalize_jwk_timestamp(not_before)
        not_after = _normalize_jwk_timestamp(not_after)
        version = str(raw_key.get("version", "") or "").strip()[:MAX_KEY_VERSION_LENGTH]
        fingerprint = _public_key_fingerprint(public_key)

        if fingerprint is None:
            raise ValueError("JWK public-key fingerprint could not be calculated")

        return {
            "key_id": kid[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "status": status,
            "public_key": public_key,
            "fingerprint": fingerprint,
            "not_before": not_before,
            "not_after": not_after,
            "version": version,
            "source": str(source or "").strip()[:MAX_KEY_SOURCE_LENGTH],
        }


def _normalize_jwk_timestamp(value):
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        from datetime import datetime, timezone

        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            raise ValueError("invalid JWK timestamp")
    text = str(value).strip()[:MAX_TIMESTAMP_LENGTH]
    if _parse_timestamp(text) is None:
        raise ValueError("invalid JWK timestamp")
    return text


def public_key_to_jwk(public_key, key_id, *, version="", status=IDENTITY_KEY_STATUS_ACTIVE, not_before="", not_after=""):
    """Serialize an Ed25519 public key into a deterministic JWK record."""
    try:
        from cryptography.hazmat.primitives import serialization

        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    except Exception as exc:
        raise ValueError("public_key must be an Ed25519 public-key object") from exc

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(raw),
        "kid": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
        "alg": "EdDSA",
        "use": "sig",
        "status": normalize_attestation_key_status(status),
        "version": str(version or "").strip()[:MAX_KEY_VERSION_LENGTH],
        "not_before": str(not_before or "").strip()[:MAX_TIMESTAMP_LENGTH],
        "not_after": str(not_after or "").strip()[:MAX_TIMESTAMP_LENGTH],
    }



def _jwt_numeric_date(value, claim_name):
    """Normalize a JWT NumericDate claim into a finite Unix timestamp."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{claim_name} must be a NumericDate")
    if value < 0:
        raise ValueError(f"{claim_name} must not be negative")
    return float(value)


def _jwt_timestamp_to_iso(timestamp):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _jwt_expected_audience_match(claim, expected_audience):
    expected = str(expected_audience or "").strip()
    if not expected:
        return False, ""

    if isinstance(claim, str):
        return claim == expected, claim

    if isinstance(claim, list):
        normalized = []
        for item in claim:
            if not isinstance(item, str) or not item.strip():
                return False, ""
            normalized.append(item.strip())
        return expected in normalized, expected

    return False, ""


def _jwt_resolve_key(key_resolver, key_id, jws_algorithm):
    """Resolve a JWS key while bridging EdDSA to the internal Ed25519 name."""
    registry_algorithm = (
        IDENTITY_ATTESTATION_ALGORITHM_ED25519
        if jws_algorithm == IDENTITY_JWT_ALGORITHM_EDDSA
        else jws_algorithm
    )

    try:
        if hasattr(key_resolver, "get_verification_key"):
            public_key = key_resolver.get_verification_key(key_id, registry_algorithm)
            metadata = None
            if hasattr(key_resolver, "get_verification_key_metadata"):
                metadata = key_resolver.get_verification_key_metadata(key_id, registry_algorithm)
            return public_key, metadata, registry_algorithm
        if callable(key_resolver):
            return key_resolver(key_id, registry_algorithm), None, registry_algorithm
    except Exception:
        return None, None, registry_algorithm

    return None, None, registry_algorithm


def _jwt_parse_compact(token):
    token = str(token or "").strip()
    if not token:
        return None, ["IDENTITY_JWT_MISSING"]
    if len(token) > MAX_JWT_LENGTH:
        return None, ["IDENTITY_JWT_TOO_LARGE"]

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None, ["IDENTITY_JWT_COMPACT_SERIALIZATION_INVALID"]

    header_segment, payload_segment, signature_segment = parts
    try:
        header_raw = _b64url_decode(header_segment)
        payload_raw = _b64url_decode(payload_segment)
        signature = _b64url_decode(signature_segment)
    except (ValueError, TypeError, UnicodeEncodeError, base64.binascii.Error):
        return None, ["IDENTITY_JWT_BASE64URL_INVALID"]

    if not signature:
        return None, ["IDENTITY_JWT_SIGNATURE_MISSING"]

    try:
        header = json.loads(header_raw.decode("utf-8"))
        claims = json.loads(payload_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, ["IDENTITY_JWT_JSON_INVALID"]

    if not isinstance(header, dict):
        return None, ["IDENTITY_JWT_HEADER_INVALID"]
    if not isinstance(claims, dict):
        return None, ["IDENTITY_JWT_CLAIMS_INVALID"]

    return {
        "token": token,
        "parts": parts,
        "header": header,
        "claims": claims,
        "signature": signature,
        "signing_input": (header_segment + "." + payload_segment).encode("ascii"),
    }, []


def verify_oidc_jwt_attestation(
    token,
    key_resolver,
    *,
    expected_issuer,
    expected_audience,
    expected_actor="",
    expected_nonce="",
    claimed_role="",
    expected_key_statuses=None,
    expected_key_fingerprint="",
    clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    max_token_age_seconds=DEFAULT_JWT_MAX_AGE_SECONDS,
    require_nonce=False,
):
    """Verify an OIDC/JWT-compatible EdDSA attestation.

    The adapter validates the JWS Compact Serialization, the EdDSA header,
    issuer/audience/subject, NumericDate claims, nonce binding, and the
    trusted-key lifecycle exposed by ``TrustedAttestationKeyRegistry``.
    Network discovery is intentionally handled by ``OIDCDiscoveryJWKSSource``;
    this verifier remains a pure token/key validation function.
    """
    parsed, codes = _jwt_parse_compact(token)
    if parsed is None:
        return {"verified": False, "codes": codes}

    expected_issuer = str(expected_issuer or "").strip()
    expected_audience = str(expected_audience or "").strip()
    expected_actor = str(expected_actor or "").strip()
    expected_nonce = str(expected_nonce or "").strip()
    claimed_role = str(claimed_role or "").strip()

    if not expected_issuer:
        return {"verified": False, "codes": ["IDENTITY_JWT_EXPECTED_ISSUER_MISSING"]}
    if not expected_audience:
        return {"verified": False, "codes": ["IDENTITY_JWT_EXPECTED_AUDIENCE_MISSING"]}

    try:
        clock_skew_seconds = float(clock_skew_seconds)
        if clock_skew_seconds < 0 or clock_skew_seconds > 900:
            raise ValueError
    except (TypeError, ValueError):
        return {"verified": False, "codes": ["IDENTITY_JWT_CLOCK_SKEW_INVALID"]}

    if max_token_age_seconds is not None:
        try:
            max_token_age_seconds = float(max_token_age_seconds)
            if max_token_age_seconds < 0 or max_token_age_seconds > 86400:
                raise ValueError
        except (TypeError, ValueError):
            return {"verified": False, "codes": ["IDENTITY_JWT_MAX_AGE_INVALID"]}

    header = parsed["header"]
    claims = parsed["claims"]
    algorithm = str(header.get("alg", "") or "").strip()
    key_id = str(header.get("kid", "") or "").strip()
    token_type = str(header.get("typ", "") or "").strip()

    if algorithm != IDENTITY_JWT_ALGORITHM_EDDSA:
        return {"verified": False, "codes": ["IDENTITY_JWT_ALGORITHM_UNSUPPORTED"]}
    if not key_id:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_ID_MISSING"]}
    if token_type and token_type.upper() not in {IDENTITY_JWT_TYPE}:
        return {"verified": False, "codes": ["IDENTITY_JWT_TYPE_UNSUPPORTED"]}

    issuer = claims.get("iss")
    subject = claims.get("sub")
    audience_claim = claims.get("aud")
    nonce = claims.get("nonce", "")

    if not isinstance(issuer, str) or not issuer.strip():
        return {"verified": False, "codes": ["IDENTITY_JWT_ISSUER_MISSING"]}
    if issuer.strip() != expected_issuer:
        return {"verified": False, "codes": ["IDENTITY_JWT_ISSUER_MISMATCH"]}
    if not isinstance(subject, str) or not subject.strip():
        return {"verified": False, "codes": ["IDENTITY_JWT_SUBJECT_MISSING"]}
    if len(subject.strip()) > MAX_SUBJECT_LENGTH:
        return {"verified": False, "codes": ["IDENTITY_JWT_SUBJECT_TOO_LONG"]}

    audience_ok, normalized_audience = _jwt_expected_audience_match(audience_claim, expected_audience)
    if not audience_ok:
        return {"verified": False, "codes": ["IDENTITY_JWT_AUDIENCE_MISMATCH"]}

    if isinstance(audience_claim, list) and len(audience_claim) > 1:
        azp = claims.get("azp")
        if not isinstance(azp, str) or azp.strip() != expected_audience:
            return {"verified": False, "codes": ["IDENTITY_JWT_AZP_MISMATCH"]}

    if require_nonce or expected_nonce:
        if not isinstance(nonce, str) or not nonce.strip():
            return {"verified": False, "codes": ["IDENTITY_JWT_NONCE_MISSING"]}
        if expected_nonce and nonce.strip() != expected_nonce:
            return {"verified": False, "codes": ["IDENTITY_JWT_NONCE_MISMATCH"]}
    elif nonce and not isinstance(nonce, str):
        return {"verified": False, "codes": ["IDENTITY_JWT_NONCE_INVALID"]}

    try:
        now_timestamp = __import__("time").time()
        expiration = _jwt_numeric_date(claims.get("exp"), "exp")
        issued_at = _jwt_numeric_date(claims.get("iat"), "iat")
        not_before = None
        if "nbf" in claims:
            not_before = _jwt_numeric_date(claims.get("nbf"), "nbf")
    except (TypeError, ValueError):
        return {"verified": False, "codes": ["IDENTITY_JWT_TIME_CLAIM_INVALID"]}

    if now_timestamp >= expiration + clock_skew_seconds:
        return {"verified": False, "codes": ["IDENTITY_JWT_EXPIRED"]}
    if not_before is not None and now_timestamp + clock_skew_seconds < not_before:
        return {"verified": False, "codes": ["IDENTITY_JWT_NOT_YET_VALID"]}
    if issued_at > now_timestamp + clock_skew_seconds:
        return {"verified": False, "codes": ["IDENTITY_JWT_ISSUED_IN_FUTURE"]}
    if max_token_age_seconds is not None and now_timestamp - issued_at > max_token_age_seconds + clock_skew_seconds:
        return {"verified": False, "codes": ["IDENTITY_JWT_TOO_OLD"]}

    public_key, key_metadata, registry_algorithm = _jwt_resolve_key(
        key_resolver,
        key_id,
        algorithm,
    )
    if public_key is None:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_NOT_FOUND"]}
    if registry_algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_ALGORITHM_UNSUPPORTED"]}
    if not isinstance(key_metadata, dict):
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_METADATA_REQUIRED"]}

    key_status = normalize_attestation_key_status(key_metadata.get("status"))
    key_fingerprint = str(key_metadata.get("fingerprint", "") or "").strip().lower()
    expected_key_fingerprint = str(expected_key_fingerprint or "").strip().lower()
    if isinstance(expected_key_statuses, str):
        expected_key_statuses = [expected_key_statuses]
    if not isinstance(expected_key_statuses, (list, tuple, set)) or not expected_key_statuses:
        expected_key_statuses = [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE]
    allowed_statuses = {
        normalize_attestation_key_status(item)
        for item in expected_key_statuses
        if str(item or "").strip()
    }
    if key_status not in allowed_statuses:
        if key_status == IDENTITY_KEY_STATUS_REVOKED:
            code = "IDENTITY_JWT_KEY_REVOKED"
        elif key_status == IDENTITY_KEY_STATUS_RETIRED:
            code = "IDENTITY_JWT_KEY_RETIRED"
        else:
            code = "IDENTITY_JWT_KEY_STATUS_NOT_ALLOWED"
        return {"verified": False, "codes": [code]}
    if expected_key_fingerprint and key_fingerprint != expected_key_fingerprint:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_FINGERPRINT_MISMATCH"]}

    not_before_text = str(key_metadata.get("not_before", "") or "").strip()
    not_after_text = str(key_metadata.get("not_after", "") or "").strip()
    key_not_before = _parse_timestamp(not_before_text)
    key_not_after = _parse_timestamp(not_after_text)
    if not_before_text and key_not_before is None:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_NOT_BEFORE_INVALID"]}
    if not_after_text and key_not_after is None:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_NOT_AFTER_INVALID"]}
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    if key_not_before is not None and now + __import__("datetime").timedelta(seconds=clock_skew_seconds) < key_not_before:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_NOT_YET_VALID"]}
    if key_not_after is not None and now - __import__("datetime").timedelta(seconds=clock_skew_seconds) >= key_not_after:
        return {"verified": False, "codes": ["IDENTITY_JWT_KEY_EXPIRED"]}

    try:
        if isinstance(public_key, (bytes, bytearray)):
            from cryptography.hazmat.primitives import serialization

            raw_key = bytes(public_key)
            if b"BEGIN" in raw_key:
                public_key = serialization.load_pem_public_key(raw_key)
            else:
                public_key = serialization.load_der_public_key(raw_key)
        public_key.verify(parsed["signature"], parsed["signing_input"])
    except ImportError:
        return {"verified": False, "codes": ["IDENTITY_JWT_CRYPTOGRAPHY_UNAVAILABLE"]}
    except Exception:
        return {"verified": False, "codes": ["IDENTITY_JWT_SIGNATURE_INVALID"]}

    roles_value = claims.get("roles", claims.get("role", []))
    roles = normalize_identity_roles(roles_value)
    actor = claims.get("actor", subject)
    if not isinstance(actor, str) or not actor.strip():
        actor = subject
    actor = actor.strip()[:MAX_SUBJECT_LENGTH]

    if expected_actor and actor != expected_actor:
        return {"verified": False, "codes": ["IDENTITY_JWT_ACTOR_MISMATCH"]}
    if claimed_role and claimed_role not in roles:
        return {"verified": False, "codes": ["IDENTITY_JWT_CLAIMED_ROLE_NOT_AUTHORIZED"]}

    attestation_id = claims.get("jti", "")
    if not isinstance(attestation_id, str) or not attestation_id.strip():
        attestation_id = hashlib.sha256(parsed["token"].encode("utf-8")).hexdigest()
    attestation_id = attestation_id.strip()[:MAX_ATTESTATION_ID_LENGTH]

    verified_at = _jwt_timestamp_to_iso(issued_at)
    valid_until = _jwt_timestamp_to_iso(expiration)
    signature = _b64url_encode(parsed["signature"])

    return {
        "schema_version": IDENTITY_JWT_SCHEMA_VERSION,
        "verified": True,
        "provider": issuer.strip()[:MAX_PROVIDER_NAME_LENGTH],
        "subject": subject.strip(),
        "actor": actor,
        "roles": roles,
        "status": IDENTITY_STATUS_ACTIVE,
        "active": True,
        "revoked": False,
        "verified_at": verified_at,
        "valid_until": valid_until,
        "attestation_id": attestation_id,
        "signature_algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        "signature_key_id": key_id[:MAX_KEY_ID_LENGTH],
        "signature_key_status": key_status,
        "signature_key_fingerprint": key_fingerprint or None,
        "attestation_issuer": issuer.strip()[:MAX_ISSUER_LENGTH],
        "attestation_audience": normalized_audience[:MAX_AUDIENCE_LENGTH],
        "attestation_nonce": nonce.strip()[:MAX_NONCE_LENGTH] if isinstance(nonce, str) else "",
        "attestation_signature": signature,
        "attestation_token": parsed["token"],
        "cryptographic_attestation_verified": True,
        "attestation_signature_fingerprint": hashlib.sha256(parsed["signature"]).hexdigest(),
        "attestation_fingerprint": hashlib.sha256(
            parsed["token"].encode("utf-8")
        ).hexdigest(),
        "identity_fingerprint": build_identity_fingerprint(
            issuer,
            subject,
            actor,
            roles,
        ),
        "jwt_claims": claims,
        "jwt_header": header,
        "error": None,
    }



class OIDCTrustStateConflictError(RuntimeError):
    """Raised when a stale writer would overwrite newer durable trust state."""

    def __init__(self, message, *, expected_revision=0, actual_revision=0, expected_fingerprint="", actual_fingerprint=""):
        super().__init__(message)
        self.expected_revision = int(expected_revision or 0)
        self.actual_revision = int(actual_revision or 0)
        self.expected_fingerprint = str(expected_fingerprint or "")
        self.actual_fingerprint = str(actual_fingerprint or "")

    @property
    def conflict_type(self):
        if self.actual_revision > self.expected_revision:
            return "NEWER_DURABLE_STATE"
        if self.actual_revision == self.expected_revision and self.actual_fingerprint != self.expected_fingerprint:
            return "SAME_REVISION_DIFFERENT_STATE"
        if self.actual_revision < self.expected_revision:
            return "DURABLE_STATE_REGRESSED"
        if not self.actual_fingerprint:
            return "DURABLE_STATE_DISAPPEARED"
        return "UNKNOWN"


class OIDCDiscoveryJWKSSource:
    """Automatic OIDC discovery + JWKS source with HTTP-aware cache controls.

    The source keeps ``TrustedAttestationKeyRegistry`` as the trust boundary.
    It supports Cache-Control/ETag metadata, bounded exponential backoff after
    failed refreshes, and a lock that coalesces concurrent refresh attempts.
    A failed refresh never replaces the last known-good registry and an expired
    cache fails closed until a fresh response succeeds.
    """

    def __init__(
        self,
        issuer,
        registry,
        *,
        cache_ttl_seconds=DEFAULT_OIDC_DISCOVERY_CACHE_TTL_SECONDS,
        timeout_seconds=DEFAULT_OIDC_HTTP_TIMEOUT_SECONDS,
        refresh_backoff_seconds=DEFAULT_OIDC_REFRESH_BACKOFF_SECONDS,
        max_refresh_backoff_seconds=MAX_OIDC_REFRESH_BACKOFF_SECONDS,
        require_https=True,
        retire_missing=True,
        fetch_json=None,
        now_fn=None,
        state_path="",
        auto_load_state=True,
        conflict_policy=OIDC_TRUST_CONFLICT_POLICY_DEFAULT,
    ):
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            raise TypeError("registry must be a TrustedAttestationKeyRegistry")

        self.issuer = str(issuer or "").strip().rstrip("/")
        self.registry = registry
        self.require_https = bool(require_https)
        self.retire_missing = bool(retire_missing)
        self.fetch_json = fetch_json or self._default_fetch_json
        self.now_fn = now_fn or time.time
        self.cache_ttl_seconds = self._normalize_positive_number(
            cache_ttl_seconds, "cache_ttl_seconds", maximum=86400
        )
        self.timeout_seconds = self._normalize_positive_number(
            timeout_seconds, "timeout_seconds", maximum=60
        )
        self.refresh_backoff_seconds = self._normalize_positive_number(
            refresh_backoff_seconds, "refresh_backoff_seconds", maximum=300
        )
        self.max_refresh_backoff_seconds = self._normalize_positive_number(
            max_refresh_backoff_seconds, "max_refresh_backoff_seconds", maximum=3600
        )
        if self.max_refresh_backoff_seconds < self.refresh_backoff_seconds:
            raise ValueError("max_refresh_backoff_seconds must be >= refresh_backoff_seconds")

        self._discovery_document = None
        self._jwks_uri = ""
        self._last_success_at = 0.0
        self._cache_expires_at = 0.0
        self._last_refresh_error = None
        self._refresh_count = 0
        self._consecutive_failures = 0
        self._next_refresh_allowed_at = 0.0
        self._etag_by_url = {}
        self._cache_control_by_url = {}
        self._last_http_status_by_url = {}
        self._refresh_lock = threading.Lock()
        self.state_path = str(state_path or "").strip()
        self.conflict_policy = str(conflict_policy or OIDC_TRUST_CONFLICT_POLICY_DEFAULT).strip().upper()
        if self.conflict_policy not in {OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE, OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED}:
            raise ValueError("unsupported conflict_policy")
        self.state_lock_path = f"{self.state_path}.lock" if self.state_path else ""
        self.journal_path = f"{self.state_path}.journal" if self.state_path else ""
        self.state_lock_timeout_seconds = 30.0
        self._state_revision = 0
        self._state_fingerprint = ""
        self._persisted_state_fingerprint = ""
        self._state_conflict_count = 0
        self._last_state_conflict = None
        self._last_conflict_recovery = None
        self._state_loaded = False

        self._validate_issuer(self.issuer)
        if self.state_path and auto_load_state:
            self.load_persisted_state()

    @staticmethod
    def _normalize_positive_number(value, field_name, maximum):
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field_name} must be numeric")
        if normalized <= 0 or normalized > maximum:
            raise ValueError(f"{field_name} must be > 0 and <= {maximum}")
        return normalized

    def _validate_issuer(self, issuer):
        from urllib.parse import urlsplit
        if not issuer or len(issuer) > MAX_OIDC_URL_LENGTH:
            raise ValueError("OIDC issuer is required and must be reasonably sized")
        parsed = urlsplit(issuer)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("OIDC issuer must be an absolute URL")
        if self.require_https and parsed.scheme.lower() != "https":
            raise ValueError("OIDC issuer must use HTTPS")
        if parsed.query or parsed.fragment:
            raise ValueError("OIDC issuer must not contain query or fragment")

    def _validate_endpoint_url(self, value, field_name):
        from urllib.parse import urlsplit
        value = str(value or "").strip()
        if not value or len(value) > MAX_OIDC_URL_LENGTH:
            raise ValueError(f"{field_name} must be a bounded absolute URL")
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"{field_name} must be an absolute URL")
        if self.require_https and parsed.scheme.lower() != "https":
            raise ValueError(f"{field_name} must use HTTPS")
        if parsed.username or parsed.password:
            raise ValueError(f"{field_name} must not contain userinfo")
        if parsed.query or parsed.fragment:
            raise ValueError(f"{field_name} must not contain query or fragment")
        return value

    def _build_discovery_url(self):
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(self.issuer)
        path = parsed.path.rstrip("/")
        discovery_path = (path + "/.well-known/openid-configuration") if path else "/.well-known/openid-configuration"
        return urlunsplit((parsed.scheme, parsed.netloc, discovery_path, "", ""))

    @staticmethod
    def _parse_cache_control(value):
        directives = {}
        for item in str(value or "").split(","):
            part = item.strip()
            if not part:
                continue
            if "=" in part:
                key, raw = part.split("=", 1)
                raw = raw.strip().strip('"')
                directives[key.strip().lower()] = raw
            else:
                directives[part.lower()] = True
        return directives

    def _cache_ttl_from_headers(self, headers):
        directives = self._parse_cache_control(headers.get("cache-control", "")) if isinstance(headers, dict) else {}
        if directives.get("no-store") or directives.get("no-cache"):
            return 0.0
        raw_max_age = directives.get("s-maxage", directives.get("max-age"))
        if raw_max_age is not None:
            try:
                return max(0.0, min(float(raw_max_age), 86400.0))
            except (TypeError, ValueError):
                pass
        return self.cache_ttl_seconds

    def _default_fetch_json(self, url, timeout_seconds, request_headers=None):
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError

        headers = {
            "Accept": "application/json",
            "User-Agent": "MemoryIdentityProvider/1.0",
        }
        if isinstance(request_headers, dict):
            headers.update(request_headers)
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                status = getattr(response, "status", 200)
                response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                if status == 304:
                    return None, {"status": 304, **response_headers}
                if status != 200:
                    raise ValueError(f"HTTP status {status}")
                raw = response.read(MAX_OIDC_RESPONSE_BYTES + 1)
                if len(raw) > MAX_OIDC_RESPONSE_BYTES:
                    raise ValueError("OIDC response exceeds MAX_OIDC_RESPONSE_BYTES")
                return json.loads(raw.decode("utf-8")), {"status": 200, **response_headers}
        except HTTPError as exc:
            if exc.code == 304:
                response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
                return None, {"status": 304, **response_headers}
            raise

    def _invoke_fetch(self, url):
        etag = self._etag_by_url.get(url, "")
        request_headers = {"If-None-Match": etag} if etag else {}
        if request_headers:
            try:
                result = self.fetch_json(url, self.timeout_seconds, request_headers)
            except TypeError:
                result = self.fetch_json(url, self.timeout_seconds)
        else:
            result = self.fetch_json(url, self.timeout_seconds)

        if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
            return result[0], {str(k).lower(): v for k, v in result[1].items()}
        return result, {"status": 200}

    def _apply_response_metadata(self, url, headers):
        if not isinstance(headers, dict):
            return self.cache_ttl_seconds
        etag = str(headers.get("etag", "") or "").strip()
        if etag:
            self._etag_by_url[url] = etag[:MAX_REFERENCE_LENGTH]
        cache_control = str(headers.get("cache-control", "") or "").strip()
        if cache_control:
            self._cache_control_by_url[url] = cache_control[:MAX_REFERENCE_LENGTH]
        status = headers.get("status")
        if status is not None:
            try:
                self._last_http_status_by_url[url] = int(status)
            except (TypeError, ValueError):
                pass
        return self._cache_ttl_from_headers(headers)

    @staticmethod
    def _compute_state_fingerprint(state):
        """Return a deterministic fingerprint for persisted trust state.

        Volatile bookkeeping such as ``saved_at`` is excluded so equivalent
        trust state produces the same fingerprint across processes.
        """
        if not isinstance(state, dict):
            return ""
        canonical = dict(state)
        canonical.pop("saved_at", None)
        canonical.pop("state_fingerprint", None)
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _journal_record_hash(record):
        payload = dict(record) if isinstance(record, dict) else {}
        payload.pop("record_hash", None)
        encoded = _canonical_json(payload).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _journal_genesis_hash():
        return hashlib.sha256(b"OIDC_TRUST_STATE_JOURNAL_GENESIS_V2").hexdigest()

    @staticmethod
    def _journal_checkpoint_hash(checkpoint):
        payload = dict(checkpoint) if isinstance(checkpoint, dict) else {}
        payload.pop("checkpoint_hash", None)
        encoded = _canonical_json(payload).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _journal_checkpoint_id(checkpoint):
        payload = {
            "issuer": str(checkpoint.get("issuer", "") or ""),
            "sequence": int(checkpoint.get("sequence", 0) or 0),
            "record_hash": str(checkpoint.get("record_hash", "") or ""),
            "state_revision": int(checkpoint.get("state_revision", 0) or 0),
            "state_fingerprint": str(checkpoint.get("state_fingerprint", "") or ""),
        }
        encoded = _canonical_json(payload).encode("utf-8")
        return "chk_" + hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _normalize_journal_records(cls, records, *, max_records=OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS):
        """Normalize legacy records into a deterministic hash chain."""
        normalized = []
        previous_hash = cls._journal_genesis_hash()
        for index, item in enumerate(records or [], start=1):
            if not isinstance(item, dict):
                continue
            record = dict(item)
            record.pop("record_hash", None)
            record.pop("previous_record_hash", None)
            record.pop("sequence", None)
            record["sequence"] = index
            record["previous_record_hash"] = previous_hash
            record["record_hash"] = cls._journal_record_hash(record)
            previous_hash = record["record_hash"]
            normalized.append(record)
        return normalized[-max(1, int(max_records)):]

    @classmethod
    def _verify_journal_records(
        cls,
        records,
        *,
        start_sequence=1,
        previous_hash=None,
    ):
        if not isinstance(records, list):
            return {"valid": False, "reason": "records_not_list", "checked_records": 0}

        try:
            expected_sequence = int(start_sequence)
        except (TypeError, ValueError):
            return {"valid": False, "reason": "invalid_start_sequence", "checked_records": 0}
        if expected_sequence < 1:
            return {"valid": False, "reason": "invalid_start_sequence", "checked_records": 0}

        if previous_hash is None:
            previous_hash = cls._journal_genesis_hash()
        previous_hash = str(previous_hash or "")
        if not previous_hash:
            return {"valid": False, "reason": "invalid_previous_hash", "checked_records": 0}

        first_sequence = expected_sequence
        for item in records:
            if not isinstance(item, dict):
                return {
                    "valid": False,
                    "reason": "record_not_object",
                    "checked_records": expected_sequence - first_sequence,
                }
            try:
                sequence = int(item.get("sequence"))
            except (TypeError, ValueError):
                return {
                    "valid": False,
                    "reason": "invalid_sequence",
                    "checked_records": expected_sequence - first_sequence,
                }
            if sequence != expected_sequence:
                return {
                    "valid": False,
                    "reason": "sequence_gap_or_reorder",
                    "checked_records": expected_sequence - first_sequence,
                    "expected_sequence": expected_sequence,
                    "actual_sequence": sequence,
                }
            if str(item.get("previous_record_hash", "")) != previous_hash:
                return {
                    "valid": False,
                    "reason": "previous_hash_mismatch",
                    "checked_records": expected_sequence - first_sequence,
                    "sequence": sequence,
                }
            actual_hash = cls._journal_record_hash(item)
            if str(item.get("record_hash", "")) != actual_hash:
                return {
                    "valid": False,
                    "reason": "record_hash_mismatch",
                    "checked_records": expected_sequence - first_sequence,
                    "sequence": sequence,
                }
            previous_hash = actual_hash
            expected_sequence += 1

        return {
            "valid": True,
            "reason": "ok",
            "checked_records": len(records),
            "first_sequence": first_sequence if records else None,
            "last_sequence": expected_sequence - 1 if records else first_sequence - 1,
            "head_hash": previous_hash,
        }

    @classmethod
    def _verify_journal_checkpoint(cls, checkpoint, *, expected_issuer=""):
        if not isinstance(checkpoint, dict):
            return {"valid": False, "reason": "checkpoint_missing"}

        required = (
            "schema_version",
            "checkpoint_id",
            "sequence",
            "record_hash",
            "state_revision",
            "state_fingerprint",
            "state_fingerprint_algorithm",
            "issuer",
            "created_at",
            "covered_event_count",
            "checkpoint_hash",
        )
        missing = [field for field in required if field not in checkpoint]
        if missing:
            return {"valid": False, "reason": "checkpoint_missing_field", "fields": missing}

        try:
            schema = int(checkpoint.get("schema_version", 0) or 0)
            sequence = int(checkpoint.get("sequence", 0) or 0)
            state_revision = int(checkpoint.get("state_revision", 0) or 0)
            covered_event_count = int(checkpoint.get("covered_event_count", 0) or 0)
        except (TypeError, ValueError):
            return {"valid": False, "reason": "checkpoint_invalid_numeric_field"}

        if schema != OIDC_TRUST_STATE_JOURNAL_CHECKPOINT_SCHEMA_VERSION:
            return {"valid": False, "reason": "unsupported_checkpoint_schema", "schema_version": schema}
        if sequence < 1 or covered_event_count != sequence:
            return {"valid": False, "reason": "checkpoint_sequence_mismatch"}
        if state_revision < 0:
            return {"valid": False, "reason": "checkpoint_invalid_state_revision"}
        if not str(checkpoint.get("record_hash", "") or ""):
            return {"valid": False, "reason": "checkpoint_missing_record_hash"}
        if not str(checkpoint.get("state_fingerprint", "") or ""):
            return {"valid": False, "reason": "checkpoint_missing_state_fingerprint"}
        if str(checkpoint.get("state_fingerprint_algorithm", "") or "") != OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM:
            return {"valid": False, "reason": "checkpoint_fingerprint_algorithm_mismatch"}
        if expected_issuer and str(checkpoint.get("issuer", "") or "") != expected_issuer:
            return {"valid": False, "reason": "checkpoint_issuer_mismatch"}
        if str(checkpoint.get("checkpoint_id", "") or "") != cls._journal_checkpoint_id(checkpoint):
            return {"valid": False, "reason": "checkpoint_id_mismatch"}
        if str(checkpoint.get("checkpoint_hash", "") or "") != cls._journal_checkpoint_hash(checkpoint):
            return {"valid": False, "reason": "checkpoint_hash_mismatch"}

        return {
            "valid": True,
            "reason": "ok",
            "sequence": sequence,
            "record_hash": str(checkpoint.get("record_hash", "")),
            "state_revision": state_revision,
            "state_fingerprint": str(checkpoint.get("state_fingerprint", "")),
            "checkpoint_id": str(checkpoint.get("checkpoint_id", "")),
        }

    @classmethod
    def _verify_journal_document(cls, journal, *, expected_issuer=""):
        if not isinstance(journal, dict):
            return {"valid": False, "reason": "journal_missing_or_invalid", "checked_records": 0}

        try:
            schema = int(journal.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema = 0

        records = journal.get("records", [])
        if not isinstance(records, list):
            return {"valid": False, "reason": "records_not_list", "checked_records": 0, "schema_version": schema}

        if schema == OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION:
            checkpoint = journal.get("checkpoint")
            if checkpoint is None:
                previous_hash = cls._journal_genesis_hash()
                start_sequence = 1
                checkpoint_result = {"valid": True, "reason": "not_present", "sequence": 0, "record_hash": previous_hash}
            else:
                checkpoint_result = cls._verify_journal_checkpoint(
                    checkpoint,
                    expected_issuer=expected_issuer,
                )
                if not checkpoint_result.get("valid"):
                    return {
                        **checkpoint_result,
                        "schema_version": schema,
                        "checked_records": 0,
                    }
                previous_hash = checkpoint_result["record_hash"]
                start_sequence = checkpoint_result["sequence"] + 1

            records_result = cls._verify_journal_records(
                records,
                start_sequence=start_sequence,
                previous_hash=previous_hash,
            )
            if not records_result.get("valid"):
                return {**records_result, "schema_version": schema, "checkpoint": checkpoint_result}

            expected_head = records_result.get("head_hash")
            persisted_head = str(journal.get("head_hash", "") or "")
            if persisted_head != expected_head:
                return {
                    "valid": False,
                    "reason": "head_hash_mismatch",
                    "schema_version": schema,
                    "checked_records": records_result.get("checked_records", 0),
                    "expected_head_hash": expected_head,
                    "actual_head_hash": persisted_head,
                }

            last_sequence = records_result.get("last_sequence")
            if last_sequence is None:
                last_sequence = checkpoint_result.get("sequence", 0)

            return {
                "valid": True,
                "reason": "ok",
                "schema_version": schema,
                "checked_records": records_result.get("checked_records", 0),
                "head_hash": expected_head,
                "head_hash_matches": True,
                "checkpoint_present": checkpoint is not None,
                "checkpoint": checkpoint_result,
                "coverage_start_sequence": start_sequence,
                "coverage_end_sequence": last_sequence,
            }

        if schema == OIDC_TRUST_STATE_JOURNAL_PRE_CHECKPOINT_SCHEMA_VERSION:
            result = cls._verify_journal_records(records)
            result["schema_version"] = schema
            result["checkpoint_present"] = False
            persisted_head = str(journal.get("head_hash", "") or "")
            if result.get("valid") and persisted_head != result.get("head_hash"):
                result["valid"] = False
                result["reason"] = "head_hash_mismatch"
                result["expected_head_hash"] = result.get("head_hash")
                result["actual_head_hash"] = persisted_head
            return result

        if schema == OIDC_TRUST_STATE_JOURNAL_LEGACY_SCHEMA_VERSION:
            normalized = cls._normalize_journal_records(records)
            result = cls._verify_journal_records(normalized)
            result["schema_version"] = schema
            result["legacy_validation"] = True
            result["checkpoint_present"] = False
            return result

        return {
            "valid": False,
            "reason": "unsupported_journal_schema",
            "checked_records": 0,
            "schema_version": schema,
        }

    @classmethod
    def _build_journal_checkpoint(cls, record, issuer, now):
        sequence = int(record.get("sequence", 0) or 0)
        checkpoint = {
            "schema_version": OIDC_TRUST_STATE_JOURNAL_CHECKPOINT_SCHEMA_VERSION,
            "checkpoint_id": "",
            "sequence": sequence,
            "record_hash": str(record.get("record_hash", "") or ""),
            "state_revision": int(record.get("state_revision", 0) or 0),
            "state_fingerprint": str(record.get("state_fingerprint", "") or ""),
            "state_fingerprint_algorithm": OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM,
            "issuer": str(issuer or ""),
            "created_at": float(now),
            "covered_event_count": sequence,
            "last_recorded_at": record.get("recorded_at"),
            "checkpoint_hash": "",
        }
        if sequence < 1 or not checkpoint["record_hash"] or not checkpoint["state_fingerprint"]:
            raise ValueError("cannot checkpoint an unbound trust-state journal record")
        checkpoint["checkpoint_id"] = cls._journal_checkpoint_id(checkpoint)
        checkpoint["checkpoint_hash"] = cls._journal_checkpoint_hash(checkpoint)
        return checkpoint

    @classmethod
    def _new_empty_journal(cls):
        return {
            "schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
            "checkpoint": None,
            "records": [],
            "head_hash": cls._journal_genesis_hash(),
        }

    def _load_trust_state_journal_document(self, load_json_document):
        journal = load_json_document(
            self.journal_path,
            self._new_empty_journal,
            expected_type=dict,
        )
        if not isinstance(journal, dict):
            raise ValueError("trust-state journal is not a JSON object")
        return journal

    def _migrate_journal_document_for_append(self, journal):
        try:
            schema = int(journal.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema = 0

        if schema == OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION:
            return journal

        verification = self._verify_journal_document(journal, expected_issuer=self.issuer)
        if not verification.get("valid"):
            raise ValueError(f"trust-state journal integrity failure: {verification.get('reason')}")

        if schema == OIDC_TRUST_STATE_JOURNAL_PRE_CHECKPOINT_SCHEMA_VERSION:
            records = [dict(item) for item in journal.get("records", []) if isinstance(item, dict)]
            return {
                "schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
                "checkpoint": None,
                "records": records,
                "head_hash": records[-1]["record_hash"] if records else self._journal_genesis_hash(),
            }

        if schema == OIDC_TRUST_STATE_JOURNAL_LEGACY_SCHEMA_VERSION:
            records = self._normalize_journal_records(journal.get("records", []))
            return {
                "schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
                "checkpoint": None,
                "records": records,
                "head_hash": records[-1]["record_hash"] if records else self._journal_genesis_hash(),
            }

        raise ValueError(f"unsupported trust-state journal schema: {schema}")

    def _append_trust_state_journal(self, event_type, details):
        if not self.journal_path:
            return False

        # Journal writes are independently serialized from trust-state writes.
        # This matters because conflict/recovery events can be emitted by
        # multiple instances, and a state lock alone does not protect the
        # journal when callers record an audit event outside that lock.
        from memory_storage import interprocess_lock, load_json_document, save_json_document

        journal_lock_path = self.journal_path + ".lock"
        with interprocess_lock(journal_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
            return self._append_trust_state_journal_locked(
                event_type,
                details,
                load_json_document,
                save_json_document,
            )

    def _append_trust_state_journal_locked(
        self,
        event_type,
        details,
        load_json_document,
        save_json_document,
    ):
        journal = self._load_trust_state_journal_document(load_json_document)
        journal = self._migrate_journal_document_for_append(journal)
        verification = self._verify_journal_document(journal, expected_issuer=self.issuer)
        if not verification.get("valid"):
            raise ValueError(f"trust-state journal integrity failure: {verification.get('reason')}")

        records = [dict(item) for item in journal.get("records", []) if isinstance(item, dict)]
        checkpoint = journal.get("checkpoint")

        if len(records) >= OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS:
            compacted = self._compact_trust_state_journal_document_locked(
                journal,
                retain_records=OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS,
                save_json_document=save_json_document,
            )
            journal = compacted["journal"]
            records = [dict(item) for item in journal.get("records", []) if isinstance(item, dict)]
            checkpoint = journal.get("checkpoint")

        previous_hash = records[-1].get("record_hash") if records else (
            checkpoint.get("record_hash") if isinstance(checkpoint, dict) else self._journal_genesis_hash()
        )
        next_sequence = int(records[-1].get("sequence", 0)) + 1 if records else (
            int(checkpoint.get("sequence", 0)) + 1 if isinstance(checkpoint, dict) else 1
        )

        record = {
            "sequence": next_sequence,
            "event_id": str(uuid.uuid4()),
            "event_type": str(event_type or "UNKNOWN"),
            "recorded_at": float(self.now_fn()),
            "issuer": self.issuer,
            "state_revision": int(self._state_revision or 0),
            "state_fingerprint": str(self._state_fingerprint or ""),
            "details": dict(details) if isinstance(details, dict) else {"value": str(details)},
            "previous_record_hash": previous_hash,
        }
        record["record_hash"] = self._journal_record_hash(record)
        records.append(record)

        journal = {
            "schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
            "checkpoint": dict(checkpoint) if isinstance(checkpoint, dict) else None,
            "records": records,
            "head_hash": record["record_hash"],
        }
        save_json_document(self.journal_path, journal)
        return True

    def _compact_trust_state_journal_document_locked(
        self,
        journal,
        *,
        retain_records,
        save_json_document,
    ):
        verification = self._verify_journal_document(journal, expected_issuer=self.issuer)
        if not verification.get("valid"):
            raise ValueError(f"trust-state journal integrity failure: {verification.get('reason')}")

        records = [dict(item) for item in journal.get("records", []) if isinstance(item, dict)]
        try:
            retain = int(retain_records)
        except (TypeError, ValueError):
            raise ValueError("retain_records must be an integer")
        if retain < 1 or retain > OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS:
            raise ValueError("retain_records must be between 1 and the journal record limit")

        if len(records) <= retain:
            return {
                "changed": False,
                "reason": "below_compaction_threshold",
                "journal": journal,
                "previous_tail_records": len(records),
                "retained_tail_records": len(records),
                "checkpoint_sequence": (
                    int(journal.get("checkpoint", {}).get("sequence", 0) or 0)
                    if isinstance(journal.get("checkpoint"), dict)
                    else 0
                ),
            }

        split_index = len(records) - retain
        checkpoint_record = records[split_index - 1]
        tail = records[split_index:]
        checkpoint = self._build_journal_checkpoint(
            checkpoint_record,
            self.issuer,
            float(self.now_fn()),
        )
        compacted = {
            "schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
            "checkpoint": checkpoint,
            "records": tail,
            "head_hash": tail[-1]["record_hash"],
        }

        verification_after_compaction = self._verify_journal_document(
            compacted,
            expected_issuer=self.issuer,
        )
        if not verification_after_compaction.get("valid"):
            raise ValueError(
                "trust-state journal compaction produced invalid checkpoint/tail: "
                f"{verification_after_compaction.get('reason')}"
            )

        save_json_document(self.journal_path, compacted)

        # Verify the durable result immediately. If persistence was interrupted
        # before os.replace(), the storage layer will leave the previous primary
        # intact. If the resulting document is unreadable later, its .bak
        # contains the last known-good journal and load_json_document can recover.
        from memory_storage import load_json_document
        persisted = load_json_document(
            self.journal_path,
            lambda: None,
            expected_type=dict,
        )
        persisted_verification = self._verify_journal_document(
            persisted,
            expected_issuer=self.issuer,
        )
        if not persisted_verification.get("valid"):
            raise ValueError(
                "durable trust-state journal compaction verification failed: "
                f"{persisted_verification.get('reason')}"
            )

        return {
            "changed": True,
            "reason": "compacted",
            "journal": compacted,
            "previous_tail_records": len(records),
            "retained_tail_records": len(tail),
            "checkpoint_sequence": checkpoint["sequence"],
            "checkpoint_record_hash": checkpoint["record_hash"],
            "checkpoint_hash": checkpoint["checkpoint_hash"],
            "checkpoint_id": checkpoint["checkpoint_id"],
            "head_hash": compacted["head_hash"],
        }

    def compact_trust_state_journal(self, retain_records=None):
        """Atomically checkpoint and compact old trust-state journal events.

        Only the journal tail remains in the primary journal after compaction.
        The checkpoint preserves the covered sequence, head record hash, trust
        state revision/fingerprint, and an authenticated checkpoint hash. The
        operation is serialized with ordinary journal appenders, making repeated
        calls safe and idempotent.
        """
        if not self.journal_path:
            return {
                "success": False,
                "status": "STATE_PATH_NOT_CONFIGURED",
                "changed": False,
            }

        from memory_storage import interprocess_lock, load_json_document, save_json_document

        retain = (
            OIDC_TRUST_STATE_JOURNAL_COMPACTION_RETAIN_RECORDS
            if retain_records is None
            else retain_records
        )
        journal_lock_path = self.journal_path + ".lock"
        with interprocess_lock(journal_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
            journal = self._load_trust_state_journal_document(load_json_document)
            journal = self._migrate_journal_document_for_append(journal)
            result = self._compact_trust_state_journal_document_locked(
                journal,
                retain_records=retain,
                save_json_document=save_json_document,
            )

        return {
            "success": True,
            "status": "COMPACTED" if result.get("changed") else "NOOP",
            **{key: value for key, value in result.items() if key != "journal"},
        }

    def verify_trust_state_journal(self):
        """Verify the journal chain and any checkpoint without modifying it."""
        if not self.journal_path:
            return {"valid": False, "reason": "state_path_not_configured", "checked_records": 0}
        from memory_storage import load_json_document
        journal = load_json_document(self.journal_path, lambda: None, expected_type=dict)
        return self._verify_journal_document(
            journal,
            expected_issuer=self.issuer,
        )

    def replay_trust_state_journal(self):
        """Replay the retained journal tail after validating checkpoint + tail.

        Replay is observational: it never mutates trust state. Compacted events
        are represented by the checkpoint coverage metadata rather than silently
        pretending that their individual records are still present.
        """
        verification = self.verify_trust_state_journal()
        if not verification.get("valid"):
            return {"success": False, "verification": verification, "events": [], "summary": {}}

        from memory_storage import load_json_document
        journal = load_json_document(self.journal_path, lambda: None, expected_type=dict)
        records = journal.get("records", []) if isinstance(journal, dict) else []
        if not isinstance(records, list):
            records = []

        checkpoint = journal.get("checkpoint") if isinstance(journal, dict) else None
        checkpoint_sequence = int(checkpoint.get("sequence", 0) or 0) if isinstance(checkpoint, dict) else 0
        summary = {
            "events": checkpoint_sequence + len(records),
            "events_replayed": len(records),
            "checkpointed_events": checkpoint_sequence,
            "conflicts_detected": 0,
            "recovery_decisions": 0,
            "recoveries_succeeded": 0,
            "fail_closed_decisions": 0,
            "last_revision": (
                int(checkpoint.get("state_revision", 0) or 0)
                if isinstance(checkpoint, dict)
                else 0
            ),
            "coverage_start_sequence": checkpoint_sequence + 1,
            "coverage_end_sequence": checkpoint_sequence + len(records),
        }
        events = []
        for record in records:
            event_type = str(record.get("event_type", "UNKNOWN"))
            details = record.get("details", {})
            if event_type == "CONFLICT_DETECTED":
                summary["conflicts_detected"] += 1
            elif event_type == "RECOVERY_DECISION":
                summary["recovery_decisions"] += 1
                if isinstance(details, dict) and details.get("recovered") is True:
                    summary["recoveries_succeeded"] += 1
                if isinstance(details, dict) and details.get("decision") == OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED:
                    summary["fail_closed_decisions"] += 1
            try:
                summary["last_revision"] = max(summary["last_revision"], int(record.get("state_revision", 0) or 0))
            except (TypeError, ValueError):
                pass
            events.append({
                "sequence": record.get("sequence"),
                "event_id": record.get("event_id"),
                "event_type": event_type,
                "recorded_at": record.get("recorded_at"),
                "state_revision": record.get("state_revision"),
            })

        return {
            "success": True,
            "verification": verification,
            "checkpoint": dict(checkpoint) if isinstance(checkpoint, dict) else None,
            "events": events,
            "summary": summary,
        }

    def _load_authoritative_trust_state_identity(self, load_json_document):
        """Read the durable trust-state revision/fingerprint without mutating self."""
        if not self.state_path:
            return {
                "available": False,
                "reason": "state_path_not_configured",
            }

        state = load_json_document(self.state_path, lambda: None, expected_type=dict)
        if not isinstance(state, dict):
            return {
                "available": False,
                "reason": "state_missing_or_invalid",
            }

        issuer = str(state.get("issuer", "") or "").strip().rstrip("/")
        if issuer != self.issuer:
            return {
                "available": False,
                "reason": "issuer_mismatch",
            }

        try:
            revision = max(0, int(state.get("state_revision", 0) or 0))
        except (TypeError, ValueError):
            return {
                "available": False,
                "reason": "invalid_state_revision",
            }

        computed_fingerprint = self._compute_state_fingerprint(state)
        persisted_fingerprint = str(state.get("state_fingerprint", "") or "").strip()
        if persisted_fingerprint and persisted_fingerprint != computed_fingerprint:
            return {
                "available": False,
                "reason": "state_fingerprint_mismatch",
                "state_revision": revision,
                "state_fingerprint": computed_fingerprint,
            }

        return {
            "available": True,
            "state_revision": revision,
            "state_fingerprint": computed_fingerprint,
            "state_fingerprint_algorithm": OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM,
        }

    def reconstruct_trust_state_snapshot(
        self,
        sequence=None,
        *,
        include_events=False,
        require_current_authoritative_binding=False,
    ):
        """Reconstruct an authenticated historical trust-state snapshot.

        The compacted journal does not retain the full pre-checkpoint event
        history. The checkpoint therefore acts as the immutable reconstruction
        boundary. A target before that boundary is intentionally unavailable
        rather than approximated. For targets at/after the checkpoint, the
        checkpoint identity plus retained journal tail provide an auditable
        historical revision/fingerprint and record-hash chain.

        This reconstructs the authenticated identity of a historical trust
        state, not a second copy of the complete trust-state database.
        """
        if not self.journal_path:
            return {
                "success": False,
                "status": "STATE_PATH_NOT_CONFIGURED",
                "reason": "state_path_not_configured",
                "snapshot": None,
                "events": [],
            }

        from memory_storage import interprocess_lock, load_json_document

        journal_lock_path = self.journal_path + ".lock"
        with interprocess_lock(
            journal_lock_path,
            timeout_seconds=self.state_lock_timeout_seconds,
        ):
            journal = load_json_document(
                self.journal_path,
                lambda: None,
                expected_type=dict,
            )
            verification = self._verify_journal_document(
                journal,
                expected_issuer=self.issuer,
            )
            if not verification.get("valid"):
                return {
                    "success": False,
                    "status": "JOURNAL_INVALID",
                    "reason": verification.get("reason"),
                    "verification": verification,
                    "snapshot": None,
                    "events": [],
                }

            checkpoint = journal.get("checkpoint") if isinstance(journal, dict) else None
            checkpoint_sequence = (
                int(checkpoint.get("sequence", 0) or 0)
                if isinstance(checkpoint, dict)
                else 0
            )
            checkpoint_result = verification.get("checkpoint") or {
                "valid": True,
                "sequence": 0,
                "record_hash": self._journal_genesis_hash(),
                "state_revision": 0,
                "state_fingerprint": "",
            }
            coverage_end = int(verification.get("coverage_end_sequence", 0) or 0)

            if coverage_end < checkpoint_sequence:
                return {
                    "success": False,
                    "status": "JOURNAL_COVERAGE_INVALID",
                    "reason": "checkpoint_ahead_of_journal_tail",
                    "verification": verification,
                    "snapshot": None,
                    "events": [],
                }

            if sequence is None:
                target_sequence = coverage_end
            else:
                try:
                    target_sequence = int(sequence)
                except (TypeError, ValueError):
                    return {
                        "success": False,
                        "status": "INVALID_SEQUENCE",
                        "reason": "sequence_must_be_integer",
                        "requested_sequence": sequence,
                        "snapshot": None,
                        "events": [],
                    }

            if target_sequence < 1:
                return {
                    "success": False,
                    "status": "INVALID_SEQUENCE",
                    "reason": "sequence_must_be_positive",
                    "requested_sequence": target_sequence,
                    "snapshot": None,
                    "events": [],
                }

            if target_sequence < checkpoint_sequence:
                return {
                    "success": False,
                    "status": "HISTORY_COMPACTED",
                    "reason": "requested_sequence_is_before_checkpoint_boundary",
                    "requested_sequence": target_sequence,
                    "checkpoint_sequence": checkpoint_sequence,
                    "coverage_end_sequence": coverage_end,
                    "verification": verification,
                    "snapshot": None,
                    "events": [],
                }

            if target_sequence > coverage_end:
                return {
                    "success": False,
                    "status": "HISTORY_NOT_AVAILABLE",
                    "reason": "requested_sequence_is_after_journal_coverage",
                    "requested_sequence": target_sequence,
                    "checkpoint_sequence": checkpoint_sequence,
                    "coverage_end_sequence": coverage_end,
                    "verification": verification,
                    "snapshot": None,
                    "events": [],
                }

            records = [
                dict(item)
                for item in (journal.get("records", []) if isinstance(journal, dict) else [])
                if isinstance(item, dict)
            ]

            if target_sequence == checkpoint_sequence and checkpoint_sequence > 0:
                snapshot = {
                    "sequence": checkpoint_sequence,
                    "record_hash": checkpoint_result.get("record_hash", ""),
                    "state_revision": int(checkpoint_result.get("state_revision", 0) or 0),
                    "state_fingerprint": str(checkpoint_result.get("state_fingerprint", "") or ""),
                    "state_fingerprint_algorithm": OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM,
                    "issuer": self.issuer,
                    "checkpoint_id": checkpoint_result.get("checkpoint_id"),
                    "source": "checkpoint",
                }
                replayed_events = []
            else:
                target_record = next(
                    (
                        record
                        for record in records
                        if int(record.get("sequence", 0) or 0) == target_sequence
                    ),
                    None,
                )
                if target_record is None:
                    return {
                        "success": False,
                        "status": "HISTORY_NOT_AVAILABLE",
                        "reason": "target_record_not_retained",
                        "requested_sequence": target_sequence,
                        "checkpoint_sequence": checkpoint_sequence,
                        "coverage_end_sequence": coverage_end,
                        "verification": verification,
                        "snapshot": None,
                        "events": [],
                    }

                try:
                    state_revision = int(target_record.get("state_revision", 0) or 0)
                except (TypeError, ValueError):
                    return {
                        "success": False,
                        "status": "SNAPSHOT_INVALID",
                        "reason": "target_record_state_revision_invalid",
                        "requested_sequence": target_sequence,
                        "snapshot": None,
                        "events": [],
                    }

                state_fingerprint = str(target_record.get("state_fingerprint", "") or "")
                if not state_fingerprint:
                    return {
                        "success": False,
                        "status": "SNAPSHOT_INVALID",
                        "reason": "target_record_state_fingerprint_missing",
                        "requested_sequence": target_sequence,
                        "snapshot": None,
                        "events": [],
                    }

                snapshot = {
                    "sequence": target_sequence,
                    "record_hash": str(target_record.get("record_hash", "") or ""),
                    "state_revision": state_revision,
                    "state_fingerprint": state_fingerprint,
                    "state_fingerprint_algorithm": OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM,
                    "issuer": str(target_record.get("issuer", "") or self.issuer),
                    "event_id": target_record.get("event_id"),
                    "event_type": target_record.get("event_type"),
                    "recorded_at": target_record.get("recorded_at"),
                    "source": "checkpoint_plus_tail",
                }
                replayed_events = [
                    record
                    for record in records
                    if checkpoint_sequence < int(record.get("sequence", 0) or 0) <= target_sequence
                ]

            authoritative = self._load_authoritative_trust_state_identity(load_json_document)
            current_state_match = None
            if authoritative.get("available"):
                current_state_match = (
                    int(authoritative.get("state_revision", 0) or 0) == snapshot["state_revision"]
                    and str(authoritative.get("state_fingerprint", "") or "") == snapshot["state_fingerprint"]
                )

            snapshot["authoritative_current_state_match"] = current_state_match
            snapshot["authoritative_state_available"] = bool(authoritative.get("available"))

            if require_current_authoritative_binding:
                if not authoritative.get("available"):
                    return {
                        "success": False,
                        "status": "AUTHORITATIVE_STATE_UNAVAILABLE",
                        "reason": authoritative.get("reason"),
                        "requested_sequence": target_sequence,
                        "verification": verification,
                        "snapshot": snapshot,
                        "events": list(replayed_events) if include_events else [],
                    }
                if not current_state_match:
                    return {
                        "success": False,
                        "status": "AUTHORITATIVE_STATE_MISMATCH",
                        "reason": "historical_snapshot_does_not_match_current_authoritative_state",
                        "requested_sequence": target_sequence,
                        "verification": verification,
                        "authoritative_state": authoritative,
                        "snapshot": snapshot,
                        "events": list(replayed_events) if include_events else [],
                    }

            result = {
                "success": True,
                "status": "RECONSTRUCTED",
                "requested_sequence": target_sequence,
                "checkpoint_sequence": checkpoint_sequence,
                "coverage_start_sequence": int(verification.get("coverage_start_sequence", 1) or 1),
                "coverage_end_sequence": coverage_end,
                "replayed_event_count": len(replayed_events),
                "authoritative_state": authoritative,
                "snapshot": snapshot,
                "verification": verification,
                "events": list(replayed_events) if include_events else [],
            }
            return result

    def verify_trust_state_snapshot(
        self,
        sequence=None,
        *,
        expected_state_revision=None,
        expected_state_fingerprint="",
        require_current_authoritative_binding=False,
    ):
        """Verify a historical snapshot identity against explicit expectations."""
        reconstruction = self.reconstruct_trust_state_snapshot(
            sequence=sequence,
            include_events=False,
            require_current_authoritative_binding=require_current_authoritative_binding,
        )
        if not reconstruction.get("success"):
            return reconstruction

        snapshot = reconstruction.get("snapshot") or {}
        if expected_state_revision is not None:
            try:
                expected_revision = int(expected_state_revision)
            except (TypeError, ValueError):
                return {
                    **reconstruction,
                    "success": False,
                    "status": "SNAPSHOT_EXPECTATION_INVALID",
                    "reason": "expected_state_revision_must_be_integer",
                }
            if int(snapshot.get("state_revision", 0) or 0) != expected_revision:
                return {
                    **reconstruction,
                    "success": False,
                    "status": "SNAPSHOT_EXPECTATION_MISMATCH",
                    "reason": "state_revision_mismatch",
                }

        expected_fingerprint = str(expected_state_fingerprint or "").strip()
        if expected_fingerprint and str(snapshot.get("state_fingerprint", "") or "") != expected_fingerprint:
            return {
                **reconstruction,
                "success": False,
                "status": "SNAPSHOT_EXPECTATION_MISMATCH",
                "reason": "state_fingerprint_mismatch",
            }

        return {
            **reconstruction,
            "status": "SNAPSHOT_VERIFIED",
        }


    def diff_trust_state_snapshots(
        self,
        from_sequence=None,
        to_sequence=None,
        *,
        require_current_authoritative_binding=False,
    ):
        """Compare two authenticated historical trust-state snapshots.

        The method is observational only. It never mutates authoritative trust
        state or the journal. The comparison is based on independently verified
        historical snapshot identities plus the authenticated journal events
        between the two sequence boundaries. It deliberately does not invent a
        field-level state diff from fingerprints: a fingerprint proves identity,
        while journal events provide the auditable transition details.
        """
        first = self.reconstruct_trust_state_snapshot(
            sequence=from_sequence,
            include_events=True,
            require_current_authoritative_binding=require_current_authoritative_binding,
        )
        if not first.get("success"):
            return {
                **first,
                "status": "HISTORICAL_DIFF_UNAVAILABLE",
                "reason": first.get("reason", "from_snapshot_unavailable"),
                "diff": None,
            }

        second = self.reconstruct_trust_state_snapshot(
            sequence=to_sequence,
            include_events=True,
            require_current_authoritative_binding=require_current_authoritative_binding,
        )
        if not second.get("success"):
            return {
                **second,
                "status": "HISTORICAL_DIFF_UNAVAILABLE",
                "reason": second.get("reason", "to_snapshot_unavailable"),
                "from_snapshot": first.get("snapshot"),
                "diff": None,
            }

        first_verification = first.get("verification") or {}
        second_verification = second.get("verification") or {}
        first_checkpoint = first_verification.get("checkpoint") or {}
        second_checkpoint = second_verification.get("checkpoint") or {}
        journal_identity_first = {
            "checkpoint_id": first_checkpoint.get("checkpoint_id"),
            "coverage_end_sequence": first_verification.get("coverage_end_sequence"),
            "head_hash": first_verification.get("head_hash"),
        }
        journal_identity_second = {
            "checkpoint_id": second_checkpoint.get("checkpoint_id"),
            "coverage_end_sequence": second_verification.get("coverage_end_sequence"),
            "head_hash": second_verification.get("head_hash"),
        }
        if journal_identity_first != journal_identity_second:
            return {
                "success": False,
                "status": "JOURNAL_CHANGED_DURING_DIFF",
                "reason": "journal_changed_between_historical_snapshot_reads",
                "from_snapshot": first.get("snapshot"),
                "to_snapshot": second.get("snapshot"),
                "diff": None,
                "journal_identity_before": journal_identity_first,
                "journal_identity_after": journal_identity_second,
            }

        from_snapshot = dict(first.get("snapshot") or {})
        to_snapshot = dict(second.get("snapshot") or {})
        from_sequence_value = int(from_snapshot.get("sequence", 0) or 0)
        to_sequence_value = int(to_snapshot.get("sequence", 0) or 0)

        if from_sequence_value < to_sequence_value:
            direction = "FORWARD"
            lower = from_sequence_value
            upper = to_sequence_value
            event_delta = [
                dict(item)
                for item in (second.get("events") or [])
                if lower < int(item.get("sequence", 0) or 0) <= upper
            ]
            delta_type = "ADDED"
        elif from_sequence_value > to_sequence_value:
            direction = "REVERSE"
            lower = to_sequence_value
            upper = from_sequence_value
            event_delta = [
                dict(item)
                for item in (first.get("events") or [])
                if lower < int(item.get("sequence", 0) or 0) <= upper
            ]
            delta_type = "REMOVED"
        else:
            direction = "UNCHANGED"
            event_delta = []
            delta_type = None

        if delta_type:
            event_delta = [
                {
                    "delta_type": delta_type,
                    "sequence": int(item.get("sequence", 0) or 0),
                    "event_id": item.get("event_id"),
                    "event_type": item.get("event_type"),
                    "recorded_at": item.get("recorded_at"),
                    "state_revision": int(item.get("state_revision", 0) or 0),
                    "state_fingerprint": str(item.get("state_fingerprint", "") or ""),
                    "details": dict(item.get("details", {})) if isinstance(item.get("details"), dict) else item.get("details"),
                    "record_hash": item.get("record_hash"),
                    "previous_record_hash": item.get("previous_record_hash"),
                }
                for item in event_delta
            ]

        from_revision = int(from_snapshot.get("state_revision", 0) or 0)
        to_revision = int(to_snapshot.get("state_revision", 0) or 0)
        from_fingerprint = str(from_snapshot.get("state_fingerprint", "") or "")
        to_fingerprint = str(to_snapshot.get("state_fingerprint", "") or "")
        transition = {
            "changed": (
                from_revision != to_revision
                or from_fingerprint != to_fingerprint
            ),
            "from_state_revision": from_revision,
            "to_state_revision": to_revision,
            "state_revision_delta": to_revision - from_revision,
            "from_state_fingerprint": from_fingerprint,
            "to_state_fingerprint": to_fingerprint,
        }

        return {
            "success": True,
            "status": "HISTORICAL_DIFF",
            "direction": direction,
            "from_snapshot": from_snapshot,
            "to_snapshot": to_snapshot,
            "journal_identity": journal_identity_first,
            "diff": {
                "sequence_delta": to_sequence_value - from_sequence_value,
                "event_count": len(event_delta),
                "events": event_delta,
                "state_transition": transition,
            },
        }

    def verify_trust_state_time_travel(
        self,
        sequence=None,
        *,
        expected_state_revision=None,
        expected_state_fingerprint="",
        require_current_authoritative_binding=False,
    ):
        """Verify a time-travel target without changing current trust state."""
        result = self.verify_trust_state_snapshot(
            sequence=sequence,
            expected_state_revision=expected_state_revision,
            expected_state_fingerprint=expected_state_fingerprint,
            require_current_authoritative_binding=require_current_authoritative_binding,
        )
        if not result.get("success"):
            return result
        return {
            **result,
            "status": "TIME_TRAVEL_VERIFIED",
            "time_travel": {
                "sequence": result.get("snapshot", {}).get("sequence"),
                "read_only": True,
                "authoritative_state_mutated": False,
            },
        }

    def get_trust_state_journal_checkpoint(self, verify_integrity=True):
        if not self.journal_path:
            return None
        from memory_storage import load_json_document
        journal = load_json_document(self.journal_path, lambda: None, expected_type=dict)
        if not isinstance(journal, dict):
            return None
        checkpoint = journal.get("checkpoint")
        if not isinstance(checkpoint, dict):
            return None
        if verify_integrity:
            verification = self.verify_trust_state_journal()
            if not verification.get("valid"):
                return None
            checkpoint_verification = verification.get("checkpoint", {})
            if not checkpoint_verification.get("valid"):
                return None
        return dict(checkpoint)

    def get_trust_state_journal(self, limit=50, verify_integrity=False):
        if not self.journal_path:
            return [] if not verify_integrity else {"valid": False, "reason": "state_path_not_configured", "records": []}
        from memory_storage import load_json_document
        journal = load_json_document(self.journal_path, lambda: None, expected_type=dict)
        if not isinstance(journal, dict):
            return [] if not verify_integrity else {"valid": False, "reason": "journal_missing_or_invalid", "records": []}

        try:
            schema = int(journal.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema = 0

        if schema not in {
            OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
            OIDC_TRUST_STATE_JOURNAL_PRE_CHECKPOINT_SCHEMA_VERSION,
            OIDC_TRUST_STATE_JOURNAL_LEGACY_SCHEMA_VERSION,
        }:
            return [] if not verify_integrity else {"valid": False, "reason": "unsupported_journal_schema", "records": []}

        records = journal.get("records", [])
        if not isinstance(records, list):
            return [] if not verify_integrity else {"valid": False, "reason": "records_not_list", "records": []}
        try:
            limit = max(1, min(int(limit), OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS))
        except (TypeError, ValueError):
            limit = 50
        selected = [dict(item) for item in records[-limit:] if isinstance(item, dict)]
        if verify_integrity:
            verification = self.verify_trust_state_journal()
            verification["records"] = selected
            return verification
        return selected


    def query_trust_state_journal(
        self,
        *,
        start_sequence=None,
        end_sequence=None,
        event_types=None,
        state_revision=None,
        limit=100,
        reverse=False,
        verify_integrity=True,
        include_checkpoint=True,
    ):
        """Query the authenticated trust-state timeline without mutating state.

        Queries are deliberately sequence-based.  The method never infers
        deleted pre-checkpoint history: when compaction has removed older
        records, the returned coverage explicitly identifies that boundary.
        With ``verify_integrity=True`` the complete retained chain is verified
        before records are returned, so a partial/tampered timeline fails
        closed instead of returning apparently trustworthy results.
        """
        if not self.journal_path:
            return {
                "success": False,
                "status": "JOURNAL_UNAVAILABLE",
                "reason": "state_path_not_configured",
                "records": [],
            }

        from memory_storage import load_json_document

        try:
            start = None if start_sequence is None else int(start_sequence)
            end = None if end_sequence is None else int(end_sequence)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "INVALID_QUERY",
                "reason": "sequence_bounds_must_be_integers",
                "records": [],
            }
        if start is not None and start < 1:
            return {"success": False, "status": "INVALID_QUERY", "reason": "start_sequence_must_be_positive", "records": []}
        if end is not None and end < 1:
            return {"success": False, "status": "INVALID_QUERY", "reason": "end_sequence_must_be_positive", "records": []}
        if start is not None and end is not None and start > end:
            return {"success": False, "status": "INVALID_QUERY", "reason": "start_sequence_after_end_sequence", "records": []}

        if event_types is None:
            normalized_types = None
        elif isinstance(event_types, str):
            normalized_types = {event_types.strip()}
        else:
            try:
                normalized_types = {str(item).strip() for item in event_types if str(item).strip()}
            except TypeError:
                return {"success": False, "status": "INVALID_QUERY", "reason": "event_types_must_be_iterable", "records": []}
        if normalized_types is not None and not normalized_types:
            normalized_types = None

        try:
            limit_value = max(1, min(int(limit), OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS))
        except (TypeError, ValueError):
            return {"success": False, "status": "INVALID_QUERY", "reason": "limit_must_be_integer", "records": []}

        journal_lock = getattr(self, "_journal_lock", None)
        if journal_lock is None:
            journal_lock = threading.RLock()

        with journal_lock:
            journal = load_json_document(self.journal_path, lambda: None, expected_type=dict)
            if not isinstance(journal, dict):
                return {"success": False, "status": "JOURNAL_INVALID", "reason": "journal_missing_or_invalid", "records": []}

            verification = self.verify_trust_state_journal() if verify_integrity else None
            if verify_integrity and not verification.get("valid"):
                return {
                    "success": False,
                    "status": "JOURNAL_INVALID",
                    "reason": verification.get("reason", "journal_integrity_check_failed"),
                    "records": [],
                    "verification": verification,
                }

            checkpoint = journal.get("checkpoint") if isinstance(journal.get("checkpoint"), dict) else None
            checkpoint_sequence = int(checkpoint.get("sequence", 0) or 0) if checkpoint else 0
            records = [dict(item) for item in journal.get("records", []) if isinstance(item, dict)]
            coverage_end = checkpoint_sequence + len(records)
            coverage_start = checkpoint_sequence + 1 if records else checkpoint_sequence

            if start is not None and start < coverage_start and checkpoint_sequence > 0:
                return {
                    "success": False,
                    "status": "HISTORY_COMPACTED",
                    "reason": "requested_sequence_is_before_retained_coverage",
                    "records": [],
                    "coverage_start_sequence": coverage_start,
                    "coverage_end_sequence": coverage_end,
                    "checkpoint_sequence": checkpoint_sequence,
                }
            if end is not None and end > coverage_end:
                return {
                    "success": False,
                    "status": "HISTORY_UNAVAILABLE",
                    "reason": "requested_sequence_is_after_retained_coverage",
                    "records": [],
                    "coverage_start_sequence": coverage_start,
                    "coverage_end_sequence": coverage_end,
                    "checkpoint_sequence": checkpoint_sequence,
                }

            selected = []
            for record in records:
                sequence = int(record.get("sequence", 0) or 0)
                if start is not None and sequence < start:
                    continue
                if end is not None and sequence > end:
                    continue
                if normalized_types is not None and str(record.get("event_type", "")) not in normalized_types:
                    continue
                if state_revision is not None:
                    try:
                        if int(record.get("state_revision", 0) or 0) != int(state_revision):
                            continue
                    except (TypeError, ValueError):
                        return {"success": False, "status": "INVALID_QUERY", "reason": "state_revision_must_be_integer", "records": []}
                selected.append(record)

            selected.sort(key=lambda item: int(item.get("sequence", 0) or 0), reverse=bool(reverse))
            selected = selected[:limit_value]
            return {
                "success": True,
                "status": "JOURNAL_QUERY",
                "records": selected,
                "count": len(selected),
                "limit": limit_value,
                "reverse": bool(reverse),
                "filters": {
                    "start_sequence": start,
                    "end_sequence": end,
                    "event_types": sorted(normalized_types) if normalized_types is not None else None,
                    "state_revision": state_revision,
                },
                "coverage_start_sequence": coverage_start,
                "coverage_end_sequence": coverage_end,
                "checkpoint_sequence": checkpoint_sequence,
                "checkpoint": dict(checkpoint) if checkpoint and include_checkpoint else None,
                "verification": verification if verify_integrity else None,
            }

    def get_trust_state_audit_timeline(
        self,
        *,
        start_sequence=None,
        end_sequence=None,
        event_types=None,
        limit=100,
        reverse=False,
        verify_integrity=True,
    ):
        """Return a compact audit timeline plus authenticated coverage metadata."""
        result = self.query_trust_state_journal(
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            event_types=event_types,
            limit=limit,
            reverse=reverse,
            verify_integrity=verify_integrity,
            include_checkpoint=True,
        )
        if not result.get("success"):
            return result

        timeline = []
        for record in result.get("records", []):
            timeline.append({
                "sequence": int(record.get("sequence", 0) or 0),
                "event_id": record.get("event_id"),
                "event_type": record.get("event_type"),
                "recorded_at": record.get("recorded_at"),
                "state_revision": int(record.get("state_revision", 0) or 0),
                "state_fingerprint": record.get("state_fingerprint", ""),
                "record_hash": record.get("record_hash", ""),
                "previous_record_hash": record.get("previous_record_hash", ""),
                "details": dict(record.get("details", {})) if isinstance(record.get("details"), dict) else record.get("details"),
            })
        return {
            **result,
            "status": "AUDIT_TIMELINE",
            "timeline": timeline,
        }

    def export_trust_state_audit_evidence(
        self,
        *,
        start_sequence=None,
        end_sequence=None,
        event_types=None,
        limit=100,
        reverse=False,
    ):
        """Export a self-contained, hash-bound audit evidence package.

        The export is observational and never mutates trust state or the
        journal.  The package contains the authenticated checkpoint/coverage,
        selected journal records, journal verification result, and a
        deterministic evidence fingerprint.  The fingerprint intentionally
        excludes the export timestamp so the same journal slice produces the
        same content identity.
        """
        first = self.query_trust_state_journal(
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            event_types=event_types,
            limit=limit,
            reverse=reverse,
            verify_integrity=True,
            include_checkpoint=True,
        )
        if not first.get("success"):
            return {
                **first,
                "status": "AUDIT_EVIDENCE_UNAVAILABLE",
                "evidence": None,
            }

        second = self.query_trust_state_journal(
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            event_types=event_types,
            limit=limit,
            reverse=reverse,
            verify_integrity=True,
            include_checkpoint=True,
        )
        if not second.get("success"):
            return {
                "success": False,
                "status": "JOURNAL_CHANGED_DURING_EXPORT",
                "reason": "journal_changed_between_evidence_reads",
                "evidence": None,
            }

        def identity(result):
            checkpoint = result.get("checkpoint") or {}
            verification = result.get("verification") or {}
            records = result.get("records") or []
            return {
                "checkpoint_id": checkpoint.get("checkpoint_id"),
                "checkpoint_sequence": checkpoint.get("sequence", 0),
                "coverage_start_sequence": result.get("coverage_start_sequence"),
                "coverage_end_sequence": result.get("coverage_end_sequence"),
                "head_hash": verification.get("head_hash"),
                "record_hashes": [item.get("record_hash") for item in records],
            }

        before = identity(first)
        after = identity(second)
        if before != after:
            return {
                "success": False,
                "status": "JOURNAL_CHANGED_DURING_EXPORT",
                "reason": "journal_changed_between_evidence_reads",
                "journal_identity_before": before,
                "journal_identity_after": after,
                "evidence": None,
            }

        verification = first.get("verification") or {}
        evidence = {
            "schema_version": 1,
            "evidence_type": "OIDC_TRUST_STATE_AUDIT_EVIDENCE",
            "issuer": self.issuer,
            "journal_schema_version": verification.get("schema_version"),
            "checkpoint": dict(first.get("checkpoint") or {}) if first.get("checkpoint") else None,
            "coverage_start_sequence": first.get("coverage_start_sequence"),
            "coverage_end_sequence": first.get("coverage_end_sequence"),
            "head_hash": verification.get("head_hash"),
            "query": dict(first.get("filters") or {}),
            "reverse": bool(reverse),
            "records": [dict(item) for item in first.get("records", [])],
            "journal_verification": dict(verification),
            "exported_at": float(self.now_fn()),
            "evidence_fingerprint": "",
        }
        fingerprint_payload = dict(evidence)
        fingerprint_payload.pop("exported_at", None)
        fingerprint_payload.pop("evidence_fingerprint", None)
        evidence["evidence_fingerprint"] = hashlib.sha256(
            _canonical_json(fingerprint_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_EXPORTED",
            "evidence": evidence,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _decision_attestation_consumption_audit_evidence_attestation_payload(
        evidence, *, issuer, key_id
    ):
        return {
            "schema_version": 1,
            "attestation_type": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION",
            "evidence_fingerprint": str(
                (evidence or {}).get("evidence_fingerprint", "") or ""
            ),
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        }

    @staticmethod
    def _normalize_decision_attestation_replay_binding(
        *,
        nonce="",
        attestation_id="",
        issued_at=None,
        expires_at=None,
        ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS,
    ):
        nonce = str(nonce or "").strip()[:MAX_NONCE_LENGTH]
        attestation_id = str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH]
        if not nonce or not attestation_id:
            return {
                "success": False,
                "reason": "nonce_and_attestation_id_required",
            }

        try:
            issued_at_value = time.time() if issued_at is None else float(issued_at)
        except (TypeError, ValueError):
            return {
                "success": False,
                "reason": "invalid_issued_at",
            }

        if expires_at is None:
            try:
                ttl = float(ttl_seconds)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "reason": "invalid_ttl",
                }
            if ttl <= 0 or ttl > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS:
                return {
                    "success": False,
                    "reason": "ttl_out_of_range",
                }
            expires_at_value = issued_at_value + ttl
        else:
            try:
                expires_at_value = float(expires_at)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "reason": "invalid_expires_at",
                }

        if (
            expires_at_value <= issued_at_value
            or expires_at_value - issued_at_value > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS
        ):
            return {
                "success": False,
                "reason": "invalid_temporal_window",
            }

        return {
            "success": True,
            "nonce": nonce,
            "attestation_id": attestation_id,
            "issued_at": issued_at_value,
            "expires_at": expires_at_value,
        }

    @staticmethod
    def _verify_decision_attestation_replay_binding(
        attestation,
        *,
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        if not isinstance(attestation, dict):
            return {"success": False, "reason": "attestation_missing"}

        nonce = str(attestation.get("nonce", "") or "").strip()
        attestation_id = str(attestation.get("attestation_id", "") or "").strip()
        if not nonce or not attestation_id:
            return {"success": False, "reason": "replay_binding_missing"}
        if expected_nonce and nonce != str(expected_nonce).strip():
            return {"success": False, "reason": "nonce_mismatch"}
        if expected_attestation_id and attestation_id != str(expected_attestation_id).strip():
            return {"success": False, "reason": "attestation_id_mismatch"}

        try:
            issued_at = float(attestation.get("issued_at"))
            expires_at = float(attestation.get("expires_at"))
            current_time = time.time() if verification_time is None else float(verification_time)
            skew = max(0.0, float(clock_skew_seconds))
        except (TypeError, ValueError):
            return {"success": False, "reason": "invalid_temporal_binding"}

        if (
            expires_at <= issued_at
            or expires_at - issued_at > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS
        ):
            return {"success": False, "reason": "invalid_temporal_window"}
        if issued_at > current_time + skew:
            return {"success": False, "reason": "attestation_not_yet_valid"}
        if expires_at < current_time - skew:
            return {"success": False, "reason": "attestation_expired"}

        return {
            "success": True,
            "nonce": nonce,
            "attestation_id": attestation_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    @staticmethod
    def _decision_attestation_consumption_audit_evidence_attestation_payload_v2(
        evidence,
        *,
        issuer,
        key_id,
        attestation_id,
        nonce,
        issued_at,
        expires_at,
    ):
        payload = OIDCDiscoveryJWKSSource._decision_attestation_consumption_audit_evidence_attestation_payload(
            evidence,
            issuer=issuer,
            key_id=key_id,
        )
        payload.update({
            "schema_version": 2,
            "attestation_id": str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH],
            "nonce": str(nonce or "").strip()[:MAX_NONCE_LENGTH],
            "issued_at": float(issued_at),
            "expires_at": float(expires_at),
        })
        return payload

    @staticmethod
    def _decision_attestation_consumption_audit_evidence_trusted_attestation_payload_v2(
        evidence,
        *,
        issuer,
        key_id,
        key_fingerprint,
        registry_revision,
        key_set_fingerprint,
        key_source,
        key_version,
        attestation_id,
        nonce,
        issued_at,
        expires_at,
    ):
        payload = OIDCDiscoveryJWKSSource._decision_attestation_consumption_audit_evidence_trusted_attestation_payload(
            evidence,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=key_fingerprint,
            registry_revision=registry_revision,
            key_set_fingerprint=key_set_fingerprint,
            key_source=key_source,
            key_version=key_version,
        )
        payload.update({
            "schema_version": 2,
            "attestation_id": str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH],
            "nonce": str(nonce or "").strip()[:MAX_NONCE_LENGTH],
            "issued_at": float(issued_at),
            "expires_at": float(expires_at),
        })
        return payload

    @classmethod
    def attest_decision_attestation_consumption_audit_evidence(
        cls,
        evidence,
        private_key,
        *,
        key_id,
        issuer,
    ):
        """Attach an Ed25519 signature to consumption-audit evidence.

        The signature binds the attestation metadata to the already-authenticated
        evidence fingerprint. The operation is strictly read-only.
        """
        if not isinstance(evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }

        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        if not private_key or not key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
            }

        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(
            evidence
        )
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_verify_before_attestation",
                "verification": evidence_result,
            }

        payload = cls._decision_attestation_consumption_audit_evidence_attestation_payload(
            evidence,
            issuer=resolved_issuer,
            key_id=key_id,
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
            }

        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            "schema_version": payload["schema_version"],
            "attestation_type": payload["attestation_type"],
            "algorithm": payload["algorithm"],
            "issuer": payload["issuer"],
            "key_id": payload["key_id"],
            "evidence_fingerprint": payload["evidence_fingerprint"],
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTED",
            "evidence": attested,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _decision_attestation_consumption_audit_evidence_trusted_attestation_payload(
        evidence,
        *,
        issuer,
        key_id,
        key_fingerprint,
        registry_revision,
        key_set_fingerprint,
        key_source,
        key_version,
    ):
        return {
            "schema_version": 1,
            "attestation_type": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION",
            "evidence_fingerprint": str(
                (evidence or {}).get("evidence_fingerprint", "") or ""
            ),
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_fingerprint": str(key_fingerprint or "").strip().lower(),
            "registry_revision": int(registry_revision),
            "key_set_fingerprint": str(key_set_fingerprint or "").strip().lower(),
            "key_source": str(key_source or "").strip()[:MAX_KEY_SOURCE_LENGTH],
            "key_version": str(key_version or "").strip()[:MAX_KEY_VERSION_LENGTH],
        }

    @classmethod
    def attest_decision_attestation_consumption_audit_evidence_with_trusted_key(
        cls,
        evidence,
        private_key,
        registry,
        *,
        key_id,
        issuer,
    ):
        """Attest consumption-audit evidence with trusted-key provenance bound."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
            }
        if not isinstance(evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_be_object",
            }

        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        if not private_key or not key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
            }

        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(
            evidence
        )
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_verify_before_attestation",
                "verification": evidence_result,
            }

        discovered = registry.discover_key(
            key_id,
            IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        )
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": key_id,
            }

        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": key_id,
                "key_status": key_status,
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "key_id": key_id,
            }

        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_public_key_unavailable",
                "error": str(exc)[:300],
            }

        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_does_not_match_trusted_key",
                "key_id": key_id,
            }

        payload = cls._decision_attestation_consumption_audit_evidence_trusted_attestation_payload(
            evidence,
            issuer=resolved_issuer,
            key_id=key_id,
            key_fingerprint=registry_fingerprint,
            registry_revision=metadata.get("registry_revision", 0),
            key_set_fingerprint=metadata.get("key_set_fingerprint", ""),
            key_source=metadata.get("source", ""),
            key_version=metadata.get("version", ""),
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
            }

        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            "schema_version": payload["schema_version"],
            "attestation_type": payload["attestation_type"],
            "algorithm": payload["algorithm"],
            "issuer": payload["issuer"],
            "key_id": payload["key_id"],
            "evidence_fingerprint": payload["evidence_fingerprint"],
            "key_fingerprint": payload["key_fingerprint"],
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "key_source": payload["key_source"],
            "key_version": payload["key_version"],
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTED",
            "evidence": attested,
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def attest_decision_attestation_consumption_audit_evidence_with_replay_binding(
        cls,
        evidence,
        private_key,
        *,
        key_id,
        issuer,
        nonce="",
        attestation_id="",
        issued_at=None,
        expires_at=None,
        ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS,
    ):
        """Create a schema-v2 consumption-audit evidence attestation with replay binding."""
        if not isinstance(evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        if not private_key or not key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
            }

        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(evidence)
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_verify_before_attestation",
                "verification": evidence_result,
            }

        replay = cls._normalize_decision_attestation_replay_binding(
            nonce=nonce,
            attestation_id=attestation_id,
            issued_at=issued_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": replay.get("reason", "invalid_replay_binding"),
            }

        payload = cls._decision_attestation_consumption_audit_evidence_attestation_payload_v2(
            evidence,
            issuer=resolved_issuer,
            key_id=key_id,
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
            }

        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            **payload,
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTED_WITH_REPLAY_BINDING",
            "evidence": attested,
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def attest_decision_attestation_consumption_audit_evidence_with_trusted_key_replay_binding(
        cls,
        evidence,
        private_key,
        registry,
        *,
        key_id,
        issuer,
        nonce="",
        attestation_id="",
        issued_at=None,
        expires_at=None,
        ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS,
    ):
        """Create a trusted-key schema-v2 attestation with replay binding."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
            }
        if not isinstance(evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_be_object",
            }
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        if not private_key or not key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
            }

        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(evidence)
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_INVALID",
                "reason": "evidence_must_verify_before_attestation",
                "verification": evidence_result,
            }

        replay = cls._normalize_decision_attestation_replay_binding(
            nonce=nonce,
            attestation_id=attestation_id,
            issued_at=issued_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": replay.get("reason", "invalid_replay_binding"),
            }

        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": key_id,
            }
        metadata = discovered.get("metadata") or {}
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": key_id,
                "key_status": key_status,
            }
        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_public_key_unavailable",
                "error": str(exc)[:300],
            }
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "private_key_does_not_match_trusted_key",
                "key_id": key_id,
            }

        payload = cls._decision_attestation_consumption_audit_evidence_trusted_attestation_payload_v2(
            evidence,
            issuer=resolved_issuer,
            key_id=key_id,
            key_fingerprint=registry_fingerprint,
            registry_revision=metadata.get("registry_revision", 0),
            key_set_fingerprint=metadata.get("key_set_fingerprint", ""),
            key_source=metadata.get("source", ""),
            key_version=metadata.get("version", ""),
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
            }

        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            **payload,
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTED_WITH_REPLAY_BINDING",
            "evidence": attested,
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_attestation(
        cls,
        attested_evidence,
        public_key,
        *,
        expected_issuer="",
        expected_key_id="",
    ):
        """Verify a consumption-audit evidence attestation without storage access."""
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "public_key_required",
            }

        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "attestation_missing",
            }

        required = (
            "schema_version",
            "attestation_type",
            "algorithm",
            "issuer",
            "key_id",
            "evidence_fingerprint",
            "signature",
        )
        missing = [field for field in required if field not in attestation]
        if missing:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "missing_attestation_fields",
                "fields": missing,
            }
        if int(attestation.get("schema_version", 0) or 0) != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_schema",
            }
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
            }
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_type",
            }

        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(attestation.get("key_id", "") or "").strip()
        if not issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "issuer_missing",
            }
        if not key_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_id_missing",
            }
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "issuer_mismatch",
            }
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_id_mismatch",
            }

        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(
            base_evidence
        )
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "embedded_evidence_invalid",
                "verification": evidence_result,
            }

        evidence_fingerprint = str(
            base_evidence.get("evidence_fingerprint", "") or ""
        ).strip().lower()
        if str(attestation.get("evidence_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_fingerprint_mismatch",
            }

        payload = cls._decision_attestation_consumption_audit_evidence_attestation_payload(
            base_evidence,
            issuer=issuer,
            key_id=key_id,
        )
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(
                signature,
                _canonical_json(payload).encode("utf-8"),
            )
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
            }

        expected_signature_fp = str(
            attestation.get("signature_fingerprint", "") or ""
        ).strip().lower()
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_attestation_with_registry(
        cls,
        attested_evidence,
        registry,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
        require_current_registry_binding=True,
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a trusted-key consumption-audit attestation fail-closed."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
            }
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }

        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "attestation_missing",
            }

        key_id = str(attestation.get("key_id", "") or "").strip()
        algorithm = str(attestation.get("algorithm", "") or "").strip()
        if not key_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_id_missing",
            }
        if int(attestation.get("schema_version", 0) or 0) != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_schema",
            }
        if algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
            }
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_id_mismatch",
            }
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_attestation_type_required",
            }

        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        if not issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "issuer_missing",
            }
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "issuer_mismatch",
            }

        discovered = registry.discover_key(
            key_id,
            IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        )
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
            }

        key_status = normalize_attestation_key_status(metadata.get("status"))
        if isinstance(expected_key_statuses, str):
            expected_key_statuses = [expected_key_statuses]
        if not isinstance(expected_key_statuses, (list, tuple, set)) or not expected_key_statuses:
            expected_key_statuses = [
                IDENTITY_KEY_STATUS_ACTIVE,
                IDENTITY_KEY_STATUS_GRACE,
            ]
        allowed_statuses = {
            normalize_attestation_key_status(item)
            for item in expected_key_statuses
            if str(item or "").strip()
        }
        if key_status not in allowed_statuses:
            if key_status == IDENTITY_KEY_STATUS_REVOKED:
                reason = "trusted_key_revoked"
            elif key_status == IDENTITY_KEY_STATUS_RETIRED:
                reason = "trusted_key_retired"
            else:
                reason = "trusted_key_status_not_allowed"
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": reason,
                "key_id": key_id,
                "key_status": key_status,
            }

        expected_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        current_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if expected_fingerprint and current_fingerprint != expected_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_fingerprint_mismatch",
                "key_id": key_id,
            }

        recorded = {
            "key_fingerprint": str(attestation.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": attestation.get("registry_revision"),
            "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(attestation.get("key_source", "") or "").strip(),
            "key_version": str(attestation.get("key_version", "") or "").strip(),
        }
        current = {
            "key_fingerprint": current_fingerprint,
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
        }
        if recorded["key_fingerprint"] != current["key_fingerprint"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_fingerprint_provenance_mismatch",
            }
        if require_current_registry_binding and recorded != current:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "registry_provenance_mismatch",
                "recorded_provenance": recorded,
                "current_registry_provenance": current,
            }

        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(
            base_evidence
        )
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "embedded_evidence_invalid",
                "verification": evidence_result,
            }

        evidence_fingerprint = str(
            base_evidence.get("evidence_fingerprint", "") or ""
        ).strip().lower()
        attested_evidence_fingerprint = str(
            attestation.get("evidence_fingerprint", "") or ""
        ).strip().lower()
        if attested_evidence_fingerprint != evidence_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_fingerprint_mismatch",
            }
        if recorded.get("key_source", "") != str(attestation.get("key_source", "") or "").strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "key_source_provenance_mismatch",
            }

        payload = cls._decision_attestation_consumption_audit_evidence_trusted_attestation_payload(
            base_evidence,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=recorded["key_fingerprint"],
            registry_revision=recorded["registry_revision"],
            key_set_fingerprint=recorded["key_set_fingerprint"],
            key_source=recorded["key_source"],
            key_version=recorded["key_version"],
        )
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(
                signature,
                _canonical_json(payload).encode("utf-8"),
            )
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
            }

        expected_signature_fp = str(
            attestation.get("signature_fingerprint", "") or ""
        ).strip().lower()
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_PROVENANCE_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "key_status": key_status,
            "key_fingerprint": current_fingerprint,
            "recorded_registry_revision": recorded["registry_revision"],
            "current_registry_revision": current["registry_revision"],
            "recorded_key_set_fingerprint": recorded["key_set_fingerprint"],
            "current_key_set_fingerprint": current["key_set_fingerprint"],
            "trusted_key_source": recorded["key_source"],
            "trusted_key_version": recorded["key_version"],
            "current_registry_binding": bool(recorded == current),
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_attestation_with_replay_binding(
        cls,
        attested_evidence,
        public_key,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a schema-v2 consumption-audit attestation offline with temporal binding."""
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "public_key_required",
            }
        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "attestation_missing",
            }
        if int(attestation.get("schema_version", 0) or 0) != 2:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "replay_binding_schema_required",
            }
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_type",
            }
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
            }

        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(attestation.get("key_id", "") or "").strip()
        if not issuer:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_missing"}
        if not key_id:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_id_missing"}
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_mismatch"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_id_mismatch"}

        replay = cls._verify_decision_attestation_replay_binding(
            attestation,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": replay.get("reason", "invalid_replay_binding"),
            }

        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(base_evidence)
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "embedded_evidence_invalid",
                "verification": evidence_result,
            }
        evidence_fingerprint = str(base_evidence.get("evidence_fingerprint", "") or "").strip().lower()
        if str(attestation.get("evidence_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_fingerprint_mismatch",
            }

        payload = cls._decision_attestation_consumption_audit_evidence_attestation_payload_v2(
            base_evidence,
            issuer=issuer,
            key_id=key_id,
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
            }

        expected_signature_fp = str(attestation.get("signature_fingerprint", "") or "").strip().lower()
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_REPLAY_BOUND_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "replay_binding": True,
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
        cls,
        attested_evidence,
        registry,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
    ):
        """Verify a trusted-key schema-v2 consumption-audit attestation fail-closed."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
            }
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }
        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "attestation_missing",
            }
        if int(attestation.get("schema_version", 0) or 0) != 2:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "replay_binding_schema_required",
            }
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "trusted_key_attestation_type_required",
            }
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
            }

        key_id = str(attestation.get("key_id", "") or "").strip()
        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        if not key_id:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_id_missing"}
        if not issuer:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_missing"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_id_mismatch"}
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_mismatch"}

        replay = cls._verify_decision_attestation_replay_binding(
            attestation,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": replay.get("reason", "invalid_replay_binding"),
            }

        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "trusted_key_not_found"}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key"}

        key_status = normalize_attestation_key_status(metadata.get("status"))
        if isinstance(expected_key_statuses, str):
            expected_key_statuses = [expected_key_statuses]
        if not isinstance(expected_key_statuses, (list, tuple, set)) or not expected_key_statuses:
            expected_key_statuses = [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE]
        allowed_statuses = {
            normalize_attestation_key_status(item)
            for item in expected_key_statuses
            if str(item or "").strip()
        }
        if key_status not in allowed_statuses:
            if key_status == IDENTITY_KEY_STATUS_REVOKED:
                reason = "trusted_key_revoked"
            elif key_status == IDENTITY_KEY_STATUS_RETIRED:
                reason = "trusted_key_retired"
            else:
                reason = "trusted_key_status_not_allowed"
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": reason,
                "key_id": key_id,
                "key_status": key_status,
            }

        expected_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        current_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if expected_fingerprint and current_fingerprint != expected_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "trusted_key_fingerprint_mismatch"}

        recorded = {
            "key_fingerprint": str(attestation.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": attestation.get("registry_revision"),
            "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(attestation.get("key_source", "") or "").strip(),
            "key_version": str(attestation.get("key_version", "") or "").strip(),
        }
        current = {
            "key_fingerprint": current_fingerprint,
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
        }
        if recorded["key_fingerprint"] != current["key_fingerprint"]:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_fingerprint_provenance_mismatch"}
        if require_current_registry_binding and recorded != current:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "registry_provenance_mismatch",
                "recorded_provenance": recorded,
                "current_registry_provenance": current,
            }

        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(base_evidence)
        if not evidence_result.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "embedded_evidence_invalid",
                "verification": evidence_result,
            }
        evidence_fingerprint = str(base_evidence.get("evidence_fingerprint", "") or "").strip().lower()
        if str(attestation.get("evidence_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "evidence_fingerprint_mismatch"}

        payload = cls._decision_attestation_consumption_audit_evidence_trusted_attestation_payload_v2(
            base_evidence,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=recorded["key_fingerprint"],
            registry_revision=recorded["registry_revision"],
            key_set_fingerprint=recorded["key_set_fingerprint"],
            key_source=recorded["key_source"],
            key_version=recorded["key_version"],
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
            }

        expected_signature_fp = str(attestation.get("signature_fingerprint", "") or "").strip().lower()
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_REPLAY_BOUND_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "key_status": key_status,
            "key_fingerprint": current_fingerprint,
            "recorded_registry_revision": recorded["registry_revision"],
            "current_registry_revision": current["registry_revision"],
            "recorded_key_set_fingerprint": recorded["key_set_fingerprint"],
            "current_key_set_fingerprint": current["key_set_fingerprint"],
            "trusted_key_source": recorded["key_source"],
            "trusted_key_version": recorded["key_version"],
            "current_registry_binding": bool(recorded == current),
            "replay_binding": True,
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _audit_evidence_attestation_payload(evidence, *, issuer, key_id):
        return {
            "schema_version": 1,
            "attestation_type": "OIDC_TRUST_STATE_AUDIT_EVIDENCE_ATTESTATION",
            "evidence_fingerprint": str((evidence or {}).get("evidence_fingerprint", "") or ""),
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        }

    @classmethod
    def attest_trust_state_audit_evidence(cls, evidence, private_key, *, key_id, issuer=None):
        """Attach an Ed25519 signature to exported audit evidence.

        The signature binds only to the immutable evidence fingerprint and
        attestation metadata. The operation is read-only with respect to the
        trust-state journal and authoritative state.
        """
        if not isinstance(evidence, dict):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "evidence_must_be_object"}
        if not private_key or not str(key_id or "").strip():
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "private_key_and_key_id_required"}
        evidence_result = cls.verify_trust_state_audit_evidence(
            evidence,
            expected_issuer=str(issuer or evidence.get("issuer", "") or "").strip().rstrip("/"),
        )
        if not evidence_result.get("success"):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "evidence_must_verify_before_attestation", "verification": evidence_result}
        resolved_issuer = str(issuer or evidence.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        payload = cls._audit_evidence_attestation_payload(evidence, issuer=resolved_issuer, key_id=key_id)
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "signing_failed", "error": str(exc)[:300]}
        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            "schema_version": 1,
            "attestation_type": payload["attestation_type"],
            "algorithm": payload["algorithm"],
            "issuer": resolved_issuer,
            "key_id": key_id,
            "evidence_fingerprint": payload["evidence_fingerprint"],
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_ATTESTED",
            "evidence": attested,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _audit_evidence_trusted_attestation_payload(evidence, *, issuer, key_id, key_fingerprint, registry_revision, key_set_fingerprint, key_source, key_version):
        return {
            "schema_version": 1,
            "attestation_type": "OIDC_TRUST_STATE_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION",
            "evidence_fingerprint": str((evidence or {}).get("evidence_fingerprint", "") or ""),
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_fingerprint": str(key_fingerprint or "").strip().lower(),
            "registry_revision": int(registry_revision),
            "key_set_fingerprint": str(key_set_fingerprint or "").strip().lower(),
            "key_source": str(key_source or "").strip()[:MAX_KEY_SOURCE_LENGTH],
            "key_version": str(key_version or "").strip()[:MAX_KEY_VERSION_LENGTH],
        }

    @classmethod
    def attest_trust_state_audit_evidence_with_trusted_key(cls, evidence, private_key, registry, *, key_id, issuer=None):
        """Attest audit evidence while binding the signature to trusted-key provenance.

        The registry supplies the exact key fingerprint, registry revision, key-set
        fingerprint, source and version. Those values are included in the signed
        payload so a verifier can distinguish the cryptographic key from the trust
        decision under which it was accepted.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_registry_required"}
        if not isinstance(evidence, dict):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "evidence_must_be_object"}
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        if not private_key or not key_id:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "private_key_and_key_id_required"}

        resolved_issuer = str(issuer or evidence.get("issuer", "") or "").strip().rstrip("/")
        evidence_result = cls.verify_trust_state_audit_evidence(evidence, expected_issuer=resolved_issuer)
        if not evidence_result.get("success"):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "evidence_must_verify_before_attestation", "verification": evidence_result}

        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_not_found", "key_id": key_id}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_status_not_allowed", "key_id": key_id, "key_status": key_status}
        if public_key is None:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key", "key_id": key_id}

        try:
            private_public = private_key.public_key()
            private_fingerprint = _public_key_fingerprint(private_public)
        except Exception as exc:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "private_key_public_key_unavailable", "error": str(exc)[:300]}
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "private_key_does_not_match_trusted_key", "key_id": key_id}

        payload = cls._audit_evidence_trusted_attestation_payload(
            evidence,
            issuer=resolved_issuer,
            key_id=key_id,
            key_fingerprint=registry_fingerprint,
            registry_revision=metadata.get("registry_revision", 0),
            key_set_fingerprint=metadata.get("key_set_fingerprint", ""),
            key_source=metadata.get("source", ""),
            key_version=metadata.get("version", ""),
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "signing_failed", "error": str(exc)[:300]}

        attested = json.loads(_canonical_json(evidence))
        attested["attestation"] = {
            "schema_version": payload["schema_version"],
            "attestation_type": payload["attestation_type"],
            "algorithm": payload["algorithm"],
            "issuer": payload["issuer"],
            "key_id": payload["key_id"],
            "evidence_fingerprint": payload["evidence_fingerprint"],
            "key_fingerprint": payload["key_fingerprint"],
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "key_source": payload["key_source"],
            "key_version": payload["key_version"],
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTED",
            "evidence": attested,
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_trust_state_audit_evidence_trusted_key_provenance(cls, attested_evidence, registry, *, expected_issuer="", expected_key_id="", require_current_registry_binding=True):
        """Verify a trusted-key audit attestation and its recorded registry provenance."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_registry_required"}
        if not isinstance(attested_evidence, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "evidence_must_be_object"}
        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "attestation_missing"}
        if attestation.get("attestation_type") != "OIDC_TRUST_STATE_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION":
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_attestation_type_required"}

        key_id = str(attestation.get("key_id", "") or "").strip()
        algorithm = str(attestation.get("algorithm", "") or "").strip()
        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        if algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519 or not key_id:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "invalid_trusted_key_attestation_metadata"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "key_id_mismatch"}
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "issuer_mismatch"}

        discovered = registry.discover_key(key_id, algorithm)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_not_found"}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        if public_key is None:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key"}
        status = normalize_attestation_key_status(metadata.get("status"))
        if status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "trusted_key_status_not_allowed", "key_status": status}

        expected = {
            "key_fingerprint": str(metadata.get("fingerprint", "") or "").strip().lower(),
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
        }
        actual = {
            "key_fingerprint": str(attestation.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": attestation.get("registry_revision"),
            "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(attestation.get("key_source", "") or "").strip(),
            "key_version": str(attestation.get("key_version", "") or "").strip(),
        }
        if actual["key_fingerprint"] != expected["key_fingerprint"]:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "key_fingerprint_provenance_mismatch"}
        if require_current_registry_binding and actual != expected:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "registry_provenance_mismatch", "recorded_provenance": actual, "current_registry_provenance": expected}

        payload = cls._audit_evidence_trusted_attestation_payload(
            attested_evidence,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=actual["key_fingerprint"],
            registry_revision=actual["registry_revision"],
            key_set_fingerprint=actual["key_set_fingerprint"],
            key_source=actual["key_source"],
            key_version=actual["key_version"],
        )
        try:
            signature = _b64url_decode(str(attestation.get("signature", "") or ""))
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "signature_verification_failed", "error": str(exc)[:300]}

        # The generic verifier is intentionally not reused for the signature payload;
        # verify the embedded evidence separately after the provenance signature.
        evidence_copy = json.loads(_canonical_json(attested_evidence))
        evidence_copy.pop("attestation", None)
        evidence_check = cls.verify_trust_state_audit_evidence(evidence_copy, expected_issuer=issuer)
        if not evidence_check.get("success"):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "embedded_evidence_invalid", "verification": evidence_check}
        if str(attestation.get("evidence_fingerprint", "") or "") != str(evidence_copy.get("evidence_fingerprint", "") or ""):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "evidence_fingerprint_mismatch"}

        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_TRUSTED_KEY_PROVENANCE_VERIFIED",
            "key_id": key_id,
            "key_status": status,
            "key_fingerprint": expected["key_fingerprint"],
            "recorded_registry_revision": actual["registry_revision"],
            "current_registry_revision": expected["registry_revision"],
            "recorded_key_set_fingerprint": actual["key_set_fingerprint"],
            "current_key_set_fingerprint": expected["key_set_fingerprint"],
            "trusted_key_source": actual["key_source"],
            "trusted_key_version": actual["key_version"],
            "current_registry_binding": bool(actual == expected),
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _normalize_audit_evidence_verification_policy(policy=None):
        """Normalize the explicit policy used for trusted audit-evidence verification."""
        source = policy if isinstance(policy, dict) else {}
        statuses = source.get("allowed_key_statuses", [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE])
        if isinstance(statuses, str):
            statuses = [statuses]
        if not isinstance(statuses, (list, tuple, set)):
            raise ValueError("allowed_key_statuses must be a sequence")
        normalized_statuses = sorted({
            normalize_attestation_key_status(item)
            for item in statuses
            if str(item or "").strip()
        })
        if not normalized_statuses:
            raise ValueError("allowed_key_statuses must not be empty")
        return {
            "schema_version": 1,
            "policy_id": str(source.get("policy_id", "AUDIT_EVIDENCE_DEFAULT") or "AUDIT_EVIDENCE_DEFAULT").strip()[:128],
            "expected_issuer": str(source.get("expected_issuer", "") or "").strip().rstrip("/"),
            "expected_key_id": str(source.get("expected_key_id", "") or "").strip()[:MAX_KEY_ID_LENGTH],
            "expected_key_fingerprint": str(source.get("expected_key_fingerprint", "") or "").strip().lower(),
            "allowed_key_statuses": normalized_statuses,
            "require_current_registry_binding": bool(source.get("require_current_registry_binding", True)),
            "require_provenance": bool(source.get("require_provenance", True)),
        }

    @classmethod
    def verify_trust_state_audit_evidence_with_policy(cls, attested_evidence, registry, *, policy=None):
        """Verify audit evidence under an explicit policy and return an immutable decision record.

        The returned record is a read-only audit artifact. It contains the exact normalized
        policy, verification result, trust provenance, and a deterministic decision fingerprint.
        No persistent state is mutated and no new storage is required.
        """
        try:
            normalized_policy = cls._normalize_audit_evidence_verification_policy(policy)
        except Exception as exc:
            return {
                "success": False,
                "status": "AUDIT_EVIDENCE_POLICY_INVALID",
                "reason": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if not normalized_policy["require_provenance"]:
            verification = cls.verify_trust_state_audit_evidence_attestation_with_registry(
                attested_evidence,
                registry,
                expected_issuer=normalized_policy["expected_issuer"],
                expected_key_id=normalized_policy["expected_key_id"],
                expected_key_statuses=normalized_policy["allowed_key_statuses"],
                expected_key_fingerprint=normalized_policy["expected_key_fingerprint"],
            )
        else:
            verification = cls.verify_trust_state_audit_evidence_trusted_key_provenance(
                attested_evidence,
                registry,
                expected_issuer=normalized_policy["expected_issuer"],
                expected_key_id=normalized_policy["expected_key_id"],
                require_current_registry_binding=normalized_policy["require_current_registry_binding"],
            )
            if verification.get("success") and normalized_policy["allowed_key_statuses"]:
                if verification.get("key_status") not in normalized_policy["allowed_key_statuses"]:
                    verification = {
                        "success": False,
                        "status": "ATTESTATION_INVALID",
                        "reason": "trusted_key_status_not_allowed",
                        "key_status": verification.get("key_status"),
                    }
            if verification.get("success") and normalized_policy["expected_key_fingerprint"]:
                if str(verification.get("key_fingerprint", "")).lower() != normalized_policy["expected_key_fingerprint"]:
                    verification = {
                        "success": False,
                        "status": "ATTESTATION_INVALID",
                        "reason": "trusted_key_fingerprint_mismatch",
                    }

        attestation = attested_evidence.get("attestation") if isinstance(attested_evidence, dict) else {}
        evidence_fingerprint = str((attested_evidence or {}).get("evidence_fingerprint", "") or "") if isinstance(attested_evidence, dict) else ""
        decision_core = {
            "schema_version": 1,
            "policy": normalized_policy,
            "evidence_fingerprint": evidence_fingerprint,
            "attestation_type": str((attestation or {}).get("attestation_type", "") or ""),
            "key_id": str((attestation or {}).get("key_id", "") or ""),
            "verification_status": str(verification.get("status", "") or ""),
            "verification_reason": str(verification.get("reason", "") or ""),
            "success": bool(verification.get("success")),
            "key_status": str(verification.get("key_status", "") or ""),
            "key_fingerprint": str(verification.get("key_fingerprint", "") or "").lower(),
            "recorded_registry_revision": verification.get("recorded_registry_revision", verification.get("registry_revision")),
            "current_registry_revision": verification.get("current_registry_revision", verification.get("registry_revision")),
            "recorded_key_set_fingerprint": str(verification.get("recorded_key_set_fingerprint", verification.get("key_set_fingerprint", "")) or "").lower(),
            "current_key_set_fingerprint": str(verification.get("current_key_set_fingerprint", verification.get("key_set_fingerprint", "")) or "").lower(),
            "trusted_key_source": str(verification.get("trusted_key_source", "") or ""),
            "trusted_key_version": str(verification.get("trusted_key_version", "") or ""),
            "current_registry_binding": verification.get("current_registry_binding"),
        }
        decision_fingerprint = hashlib.sha256(_canonical_json(decision_core).encode("utf-8")).hexdigest()
        decision = {
            **decision_core,
            "decision": "VERIFIED" if decision_core["success"] else "REJECTED",
            "decision_fingerprint": decision_fingerprint,
            "read_only": True,
            "authoritative_state_mutated": False,
        }
        return decision

    @staticmethod
    def _audit_evidence_decision_attestation_payload(decision, *, issuer, key_id, key_fingerprint, registry_revision, key_set_fingerprint, key_source, key_version):
        return {
            "schema_version": 1,
            "attestation_type": "OIDC_TRUST_STATE_AUDIT_EVIDENCE_DECISION_ATTESTATION",
            "decision_fingerprint": str((decision or {}).get("decision_fingerprint", "") or "").strip().lower(),
            "decision": str((decision or {}).get("decision", "") or "").strip().upper(),
            "evidence_fingerprint": str((decision or {}).get("evidence_fingerprint", "") or "").strip().lower(),
            "policy_id": str(((decision or {}).get("policy") or {}).get("policy_id", "") or "").strip()[:128],
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_fingerprint": str(key_fingerprint or "").strip().lower(),
            "registry_revision": int(registry_revision),
            "key_set_fingerprint": str(key_set_fingerprint or "").strip().lower(),
            "key_source": str(key_source or "").strip()[:MAX_KEY_SOURCE_LENGTH],
            "key_version": str(key_version or "").strip()[:MAX_KEY_VERSION_LENGTH],
        }

    @classmethod
    def _recompute_audit_evidence_decision_fingerprint(cls, decision):
        if not isinstance(decision, dict):
            return None
        core = dict(decision)
        for field in ("decision_fingerprint", "decision", "read_only", "authoritative_state_mutated", "decision_attestation"):
            core.pop(field, None)
        return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()

    @classmethod
    def attest_trust_state_audit_evidence_verification_decision(cls, decision, private_key, registry, *, key_id, issuer=None):
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_registry_required"}
        if not isinstance(decision, dict):
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_must_be_object"}
        if not private_key or not str(key_id or "").strip():
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_and_key_id_required"}
        if decision.get("read_only") is not True or decision.get("authoritative_state_mutated") is not False:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_mutability_flags_invalid"}
        if decision.get("decision") not in {"VERIFIED", "REJECTED"}:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_outcome_invalid"}
        recorded = str(decision.get("decision_fingerprint", "") or "").strip().lower()
        recomputed = cls._recompute_audit_evidence_decision_fingerprint(decision)
        if not recorded or recorded != recomputed:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_fingerprint_mismatch"}
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_not_found"}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        status = normalize_attestation_key_status(metadata.get("status"))
        if status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_status_not_allowed", "key_status": status}
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key"}
        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_public_key_unavailable", "error": str(exc)[:300]}
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_does_not_match_trusted_key"}
        payload = cls._audit_evidence_decision_attestation_payload(decision, issuer=resolved_issuer, key_id=key_id, key_fingerprint=registry_fingerprint, registry_revision=metadata.get("registry_revision", 0), key_set_fingerprint=metadata.get("key_set_fingerprint", ""), key_source=metadata.get("source", ""), key_version=metadata.get("version", ""))
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "signing_failed", "error": str(exc)[:300]}
        attested = json.loads(_canonical_json(decision))
        attested["decision_attestation"] = {**payload, "signature": _b64url_encode(signature), "signature_fingerprint": hashlib.sha256(signature).hexdigest()}
        return {"success": True, "status": "AUDIT_EVIDENCE_DECISION_ATTESTED", "decision": attested, "key_status": status, "key_fingerprint": registry_fingerprint, "registry_revision": payload["registry_revision"], "key_set_fingerprint": payload["key_set_fingerprint"], "trusted_key_source": payload["key_source"], "trusted_key_version": payload["key_version"], "read_only": True, "authoritative_state_mutated": False}

    @staticmethod
    def _audit_evidence_decision_attestation_payload_v2(decision, *, issuer, key_id, key_fingerprint, registry_revision, key_set_fingerprint, key_source, key_version, attestation_id, nonce, issued_at, expires_at):
        payload = OIDCDiscoveryJWKSSource._audit_evidence_decision_attestation_payload(decision, issuer=issuer, key_id=key_id, key_fingerprint=key_fingerprint, registry_revision=registry_revision, key_set_fingerprint=key_set_fingerprint, key_source=key_source, key_version=key_version)
        payload.update({"schema_version": 2, "attestation_id": str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH], "nonce": str(nonce or "").strip()[:MAX_NONCE_LENGTH], "issued_at": float(issued_at), "expires_at": float(expires_at)})
        return payload

    @classmethod
    def attest_trust_state_audit_evidence_verification_decision_with_replay_binding(cls, decision, private_key, registry, *, key_id, issuer=None, nonce="", attestation_id="", issued_at=None, expires_at=None, ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS):
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_registry_required"}
        if not isinstance(decision, dict):
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_must_be_object"}
        if not private_key or not str(key_id or "").strip():
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_and_key_id_required"}
        if decision.get("read_only") is not True or decision.get("authoritative_state_mutated") is not False:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_mutability_flags_invalid"}
        if decision.get("decision") not in {"VERIFIED", "REJECTED"}:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_outcome_invalid"}
        recorded = str(decision.get("decision_fingerprint", "") or "").strip().lower()
        recomputed = cls._recompute_audit_evidence_decision_fingerprint(decision)
        if not recorded or recorded != recomputed:
            return {"success": False, "status": "DECISION_INVALID", "reason": "decision_fingerprint_mismatch"}
        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        nonce = str(nonce or "").strip()[:MAX_NONCE_LENGTH]
        attestation_id = str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH]
        if not nonce or not attestation_id:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "nonce_and_attestation_id_required"}
        try:
            issued_at_value = time.time() if issued_at is None else float(issued_at)
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_issued_at"}
        if expires_at is None:
            try:
                ttl = float(ttl_seconds)
            except (TypeError, ValueError):
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_ttl"}
            if ttl <= 0 or ttl > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS:
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "ttl_out_of_range"}
            expires_at_value = issued_at_value + ttl
        else:
            try:
                expires_at_value = float(expires_at)
            except (TypeError, ValueError):
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_expires_at"}
        if expires_at_value <= issued_at_value or expires_at_value - issued_at_value > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_temporal_window"}
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_not_found"}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        status = normalize_attestation_key_status(metadata.get("status"))
        if status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_status_not_allowed", "key_status": status}
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key"}
        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_public_key_unavailable", "error": str(exc)[:300]}
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "private_key_does_not_match_trusted_key"}
        payload = cls._audit_evidence_decision_attestation_payload_v2(decision, issuer=resolved_issuer, key_id=key_id, key_fingerprint=registry_fingerprint, registry_revision=metadata.get("registry_revision", 0), key_set_fingerprint=metadata.get("key_set_fingerprint", ""), key_source=metadata.get("source", ""), key_version=metadata.get("version", ""), attestation_id=attestation_id, nonce=nonce, issued_at=issued_at_value, expires_at=expires_at_value)
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "signing_failed", "error": str(exc)[:300]}
        attested = json.loads(_canonical_json(decision))
        attested["decision_attestation"] = {**payload, "signature": _b64url_encode(signature), "signature_fingerprint": hashlib.sha256(signature).hexdigest()}
        return {"success": True, "status": "AUDIT_EVIDENCE_DECISION_ATTESTED_WITH_REPLAY_BINDING", "decision": attested, "key_status": status, "key_fingerprint": registry_fingerprint, "registry_revision": payload["registry_revision"], "key_set_fingerprint": payload["key_set_fingerprint"], "trusted_key_source": payload["key_source"], "trusted_key_version": payload["key_version"], "attestation_id": attestation_id, "nonce": nonce, "issued_at": issued_at_value, "expires_at": expires_at_value, "read_only": True, "authoritative_state_mutated": False}

    def consume_trust_state_audit_evidence_verification_decision_attestation(
        self,
        attested_decision,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=60,
        require_current_registry_binding=True,
    ):
        """Verify and atomically consume a replay-bound decision attestation once.

        The existing OIDC trust-state persistence is reused. With ``state_path``
        configured, the existing inter-process state lock serializes the claim
        and the consumption ledger is persisted inside the existing state file.
        Without persistence, one-time consumption is scoped to this source's
        in-process registry instance.
        """
        attestation = attested_decision.get("decision_attestation") if isinstance(attested_decision, dict) else None
        if not isinstance(attestation, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "decision_attestation_required"}
        schema_version = int(attestation.get("schema_version", 0) or 0)
        if schema_version != 2:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "one_time_consumption_requires_schema_v2"}
        attestation_id = str(attestation.get("attestation_id", "") or "").strip()
        nonce = str(attestation.get("nonce", "") or "").strip()
        if not attestation_id or not nonce:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "replay_binding_missing"}
        if expected_attestation_id and attestation_id != str(expected_attestation_id).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "attestation_id_mismatch"}
        if expected_nonce and nonce != str(expected_nonce).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID", "reason": "nonce_mismatch"}

        def _consume_current_state():
            verification = self.__class__.verify_trust_state_audit_evidence_verification_decision_attestation(
                attested_decision,
                self.registry,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
                require_current_registry_binding=require_current_registry_binding,
            )
            if not verification.get("success"):
                return verification
            decision_fingerprint = str(verification.get("decision_fingerprint", "") or "").strip().lower()
            with self.registry._consumption_lock:
                existing = self.registry.get_consumed_decision_attestation(attestation_id)
                if existing is not None:
                    audit = self.registry._append_decision_attestation_consumption_audit(
                        event_type="REPLAY_REJECTED",
                        attestation_id=attestation_id,
                        decision_fingerprint=decision_fingerprint,
                        nonce=nonce,
                        consumed_at=time.time() if verification_time is None else verification_time,
                        reason="attestation_already_consumed",
                        previous_consumed_record=existing,
                    )
                    if not audit.get("success"):
                        return {**audit, "read_only": False, "authoritative_state_mutated": False}
                    if self.state_path:
                        try:
                            self._persist_state()
                        except Exception as exc:
                            self._load_persisted_state_unlocked()
                            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_FAILED", "reason": "replay_audit_persistence_failed", "error": str(exc)[:300], "read_only": False, "authoritative_state_mutated": False}
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_REPLAYED",
                        "reason": "attestation_already_consumed",
                        "attestation_id": attestation_id,
                        "decision_fingerprint": decision_fingerprint,
                        "consumed_record": existing,
                        "audit_record": audit.get("record"),
                        "read_only": False,
                        "authoritative_state_mutated": True,
                    }
                event_time = time.time() if verification_time is None else verification_time
                claim = self.registry.consume_decision_attestation(
                    attestation_id,
                    decision_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                )
                if not claim.get("success"):
                    return {**claim, "read_only": False, "authoritative_state_mutated": False}
                audit = self.registry._append_decision_attestation_consumption_audit(
                    event_type="CONSUMED",
                    attestation_id=attestation_id,
                    decision_fingerprint=decision_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                    reason="one_time_consumption",
                )
                if not audit.get("success"):
                    self.registry._consumed_decision_attestations.pop(attestation_id, None)
                    return {**audit, "read_only": False, "authoritative_state_mutated": False}

                if self.state_path:
                    try:
                        self._persist_state()
                    except OIDCTrustStateConflictError:
                        # Never report a successful one-time claim when its
                        # durable commit did not succeed. Reloading restores
                        # the authoritative state and removes the local claim.
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_CONFLICT",
                            "reason": "durable_consumption_commit_conflict",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    except Exception as exc:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_FAILED",
                            "reason": "durable_consumption_commit_failed",
                            "error": str(exc)[:300],
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }

                return {
                    **verification,
                    "status": "AUDIT_EVIDENCE_DECISION_ATTESTATION_CONSUMED",
                    "consumption": claim,
                    "audit_record": audit.get("record"),
                    "read_only": False,
                    "authoritative_state_mutated": True,
                }

        if self.state_path:
            from memory_storage import interprocess_lock
            with self._refresh_lock:
                with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                    latest = self._load_persisted_state_unlocked()
                    if not latest.get("loaded"):
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_INVALID",
                            "reason": "authoritative_trust_state_unavailable",
                        }
                    return _consume_current_state()

        with self._refresh_lock:
            return _consume_current_state()

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
        cls,
        attested_evidence,
        registry,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Cryptographically bind a verified evidence attestation to its one-time consumption proof.

        The attestation signature authenticates the evidence fingerprint, issuer,
        key provenance and replay context. The authenticated consumption audit
        chain separately authenticates the durable consume event. This method
        cross-checks those two roots and derives a deterministic binding
        fingerprint without mutating state or creating additional storage.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        verification = cls.verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
            attested_evidence,
            registry,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_key_statuses=expected_key_statuses,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
            require_current_registry_binding=require_current_registry_binding,
        )
        if not verification.get("success"):
            return {
                **verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attestation = attested_evidence.get("attestation") or {}
        attestation_id = str(verification.get("attestation_id", "") or "").strip()
        nonce = str(verification.get("nonce", "") or "").strip()
        evidence_fingerprint = str(verification.get("evidence_fingerprint", "") or "").strip().lower()
        signature_fingerprint = str(verification.get("signature_fingerprint", "") or "").strip().lower()

        status = registry.get_decision_attestation_consumption_status(
            attestation_id,
            verify_integrity=verify_integrity,
            include_replay_events=True,
        )
        if not status.get("success"):
            return {
                **status,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": f"consumption_status_{status.get('reason', status.get('status', 'invalid'))}",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if status.get("status") != "DECISION_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "attestation_not_consumed",
                "consumption_status": status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        consumed = status.get("consumed_record") or {}
        audit_record = status.get("consumption_audit_record") or {}
        if str(consumed.get("decision_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "consumed_record_evidence_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(consumed.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "consumed_record_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("attestation_id", "") or "").strip() != attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_attestation_id_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_evidence_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("event_type", "") or "") != "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "unexpected_consumption_event_type",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        if not record_hash or not previous_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_hash_fields_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            consumed_at = float(consumed.get("consumed_at"))
            event_at = float(audit_record.get("event_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if consumed_at != event_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding_payload = {
            "binding_version": 1,
            "attestation_type": str(attestation.get("attestation_type", "") or ""),
            "issuer": str(verification.get("issuer", "") or "").strip().rstrip("/"),
            "key_id": str(verification.get("key_id", "") or "").strip(),
            "key_fingerprint": str(verification.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": verification.get("recorded_registry_revision", verification.get("registry_revision")),
            "key_set_fingerprint": str(verification.get("recorded_key_set_fingerprint", verification.get("key_set_fingerprint", "")) or "").strip().lower(),
            "attestation_id": attestation_id,
            "nonce": nonce,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": signature_fingerprint,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": audit_record.get("sequence"),
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        binding_fingerprint = hashlib.sha256(
            _canonical_json(binding_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_BOUND",
            "binding_version": 1,
            "binding_fingerprint": binding_fingerprint,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": signature_fingerprint,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": audit_record.get("sequence"),
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
            "consumption_audit_head_hash": status.get("audit_head_hash", ""),
            "current_registry_binding": verification.get("current_registry_binding"),
            "verification": verification,
            "consumption_status": status,
            "read_only": True,
            "authoritative_state_mutated": False,
        }


    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding(
        cls,
        attested_bundle,
        registry,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Cryptographically bind a proof-bundle attestation to its one-time consumption event.

        The bundle attestation authenticates the bundle fingerprint, trusted-key
        provenance, and replay context. The authoritative consumption audit chain
        separately authenticates the durable CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED
        event. This method cross-checks both roots and derives a deterministic
        binding fingerprint without mutating state or introducing storage.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
            attested_bundle,
            registry,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            require_current_registry_binding=require_current_registry_binding,
            expected_verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not verification.get("success"):
            return {
                **verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attestation = attested_bundle.get("bundle_attestation") or {}
        attestation_id = str(verification.get("attestation_id", "") or "").strip()
        nonce = str(verification.get("nonce", "") or "").strip()
        bundle_fingerprint = str(verification.get("bundle_fingerprint", "") or "").strip().lower()
        chain_fingerprint = str(verification.get("chain_fingerprint", "") or "").strip().lower()
        try:
            proof_count = int(verification.get("proof_count", 0) or 0)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "proof_count_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        signature_fingerprint = str(verification.get("signature_fingerprint", "") or "").strip().lower()
        key_fingerprint = str(verification.get("key_fingerprint", "") or "").strip().lower()
        registry_revision = verification.get("recorded_registry_revision", attestation.get("registry_revision"))
        key_set_fingerprint = str(
            verification.get("recorded_key_set_fingerprint", attestation.get("key_set_fingerprint", "")) or ""
        ).strip().lower()
        trusted_key_source = str(
            verification.get("trusted_key_source", attestation.get("key_source", "")) or ""
        ).strip()
        trusted_key_version = str(
            verification.get("trusted_key_version", attestation.get("key_version", "")) or ""
        ).strip()

        status = registry.get_decision_attestation_consumption_status(
            attestation_id,
            verify_integrity=verify_integrity,
            include_replay_events=True,
        )
        if not status.get("success"):
            return {
                **status,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": f"consumption_status_{status.get('reason', status.get('status', 'invalid'))}",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if status.get("status") != "DECISION_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "attestation_not_consumed",
                "consumption_status": status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        consumed = status.get("consumed_record") or {}
        audit_record = status.get("consumption_audit_record") or {}
        if str(consumed.get("decision_fingerprint", "") or "").strip().lower() != bundle_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumed_record_bundle_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(consumed.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumed_record_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("event_type", "") or "") != "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "unexpected_consumption_event_type",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("attestation_id", "") or "").strip() != attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "audit_attestation_id_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != bundle_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "audit_bundle_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "audit_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        if not record_hash or not previous_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumption_audit_hash_fields_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            consumed_at = float(consumed.get("consumed_at"))
            event_at = float(audit_record.get("event_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumption_time_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if consumed_at != event_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumption_time_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        sequence = audit_record.get("sequence")
        try:
            sequence = int(sequence)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_INVALID",
                "reason": "consumption_audit_sequence_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding_payload = {
            "binding_version": 1,
            "attestation_type": str(attestation.get("attestation_type", "") or ""),
            "issuer": str(verification.get("issuer", "") or "").strip().rstrip("/"),
            "key_id": str(verification.get("key_id", "") or "").strip(),
            "key_fingerprint": key_fingerprint,
            "registry_revision": registry_revision,
            "key_set_fingerprint": key_set_fingerprint,
            "trusted_key_source": trusted_key_source,
            "trusted_key_version": trusted_key_version,
            "bundle_id": str(verification.get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": bundle_fingerprint,
            "chain_fingerprint": chain_fingerprint,
            "proof_count": proof_count,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "signature_fingerprint": signature_fingerprint,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        binding_fingerprint = hashlib.sha256(
            _canonical_json(binding_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BOUND",
            "binding_version": 1,
            "binding_fingerprint": binding_fingerprint,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "bundle_id": binding_payload["bundle_id"],
            "bundle_fingerprint": bundle_fingerprint,
            "chain_fingerprint": chain_fingerprint,
            "proof_count": proof_count,
            "signature_fingerprint": signature_fingerprint,
            "key_fingerprint": key_fingerprint,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
            "consumption_audit_head_hash": record_hash,
            "current_registry_binding": verification.get("current_registry_binding"),
            "verification": verification,
            "consumption_status": status,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        self,
        attested_bundle,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Export a self-contained cryptographic proof of proof-bundle-attestation consumption."""
        if not isinstance(attested_bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "bundle_must_be_object",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding(
            attested_bundle,
            self.registry,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
            require_current_registry_binding=require_current_registry_binding,
            verify_integrity=verify_integrity,
        )
        if not binding.get("success"):
            return {
                **binding,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        sequence = binding.get("consumption_audit_sequence")
        exported = self.registry.export_decision_attestation_consumption_audit_evidence(
            start_sequence=sequence,
            end_sequence=sequence,
        )
        if not exported.get("success"):
            return {
                **exported,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_evidence_export_failed",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        proof = {
            "schema_version": 1,
            "proof_type": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_BINDING_PROOF",
            "attested_bundle": json.loads(_canonical_json(attested_bundle)),
            "consumption_audit_evidence": exported.get("evidence"),
            "binding": {
                "binding_version": binding.get("binding_version"),
                "binding_fingerprint": binding.get("binding_fingerprint"),
                "attestation_id": binding.get("attestation_id"),
                "nonce": binding.get("nonce"),
                "bundle_id": binding.get("bundle_id"),
                "bundle_fingerprint": binding.get("bundle_fingerprint"),
                "chain_fingerprint": binding.get("chain_fingerprint"),
                "proof_count": binding.get("proof_count"),
                "signature_fingerprint": binding.get("signature_fingerprint"),
                "key_fingerprint": binding.get("key_fingerprint"),
                "consumed_at": binding.get("consumed_at"),
                "consumption_audit_sequence": binding.get("consumption_audit_sequence"),
                "consumption_audit_previous_hash": binding.get("consumption_audit_previous_hash"),
                "consumption_audit_record_hash": binding.get("consumption_audit_record_hash"),
                "consumption_audit_head_hash": binding.get("consumption_audit_head_hash"),
                "recorded_registry_revision": (binding.get("verification") or {}).get("recorded_registry_revision"),
                "recorded_key_set_fingerprint": (binding.get("verification") or {}).get("recorded_key_set_fingerprint"),
                "trusted_key_source": (binding.get("verification") or {}).get("trusted_key_source"),
                "trusted_key_version": (binding.get("verification") or {}).get("trusted_key_version"),
            },
            "exported_at": float(time.time()),
            "proof_fingerprint": "",
        }
        fingerprint_payload = dict(proof)
        fingerprint_payload.pop("exported_at", None)
        fingerprint_payload.pop("proof_fingerprint", None)
        proof["proof_fingerprint"] = hashlib.sha256(
            _canonical_json(fingerprint_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_EXPORTED",
            "proof": proof,
            "binding": binding,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        self,
        proof,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
    ):
        """Verify and consume a bundle-attestation consumption binding proof exactly once.

        The proof fingerprint is the immutable artifact identity.  The existing
        trusted-registry one-time-consumption ledger, consumption audit hash chain,
        persistent trust state, and inter-process lock are reused; no new storage
        or parallel replay ledger is introduced.  The embedded bundle attestation
        must already represent a valid historical consumption, and the proof itself
        is then consumed exactly once using its deterministic fingerprint-derived ID.
        """
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                "reason": "proof_must_be_object",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        proof_fingerprint = str(proof.get("proof_fingerprint", "") or "").strip().lower()
        if len(proof_fingerprint) != 64 or any(char not in "0123456789abcdef" for char in proof_fingerprint):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                "reason": "proof_fingerprint_missing_or_invalid",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        attested_bundle = proof.get("attested_bundle")
        if not isinstance(attested_bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                "reason": "attested_bundle_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        def _verify_current_state():
            binding = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding(
                attested_bundle,
                self.registry,
                expected_bundle_id=expected_bundle_id,
                expected_issuer=expected_issuer,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
                require_current_registry_binding=require_current_registry_binding,
                verify_integrity=True,
            )
            if not binding.get("success"):
                return {
                    **binding,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            attestation = attested_bundle.get("bundle_attestation") or {}
            key_id = str(attestation.get("key_id", "") or "").strip()
            discovered = self.registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
            if not isinstance(discovered, dict) or discovered.get("public_key") is None:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                    "reason": "trusted_key_not_found",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }
            public_key = discovered.get("public_key")
            metadata = discovered.get("metadata") or {}
            key_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
            if not key_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                    "reason": "trusted_key_fingerprint_missing",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            proof_verification = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
                proof,
                {key_fingerprint: public_key},
                expected_bundle_id=expected_bundle_id,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                expected_key_fingerprint=expected_key_fingerprint or key_fingerprint,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
            )
            if not proof_verification.get("success"):
                return {
                    **proof_verification,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            consumption_attestation_id = f"proof-binding:{proof_fingerprint}"[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
            consumption_nonce = f"proof-binding:{proof_fingerprint}"
            event_time = time.time() if verification_time is None else verification_time

            with self.registry._consumption_lock:
                existing = self.registry.get_consumed_decision_attestation(consumption_attestation_id)
                if existing is not None:
                    replay_audit = self.registry._append_decision_attestation_consumption_audit(
                        event_type="DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAY_REJECTED",
                        attestation_id=consumption_attestation_id,
                        decision_fingerprint=proof_fingerprint,
                        nonce=consumption_nonce,
                        consumed_at=event_time,
                        reason="proof_already_consumed",
                        previous_consumed_record=existing,
                    )
                    if not replay_audit.get("success"):
                        return {
                            **replay_audit,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAY_FAILED",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    if self.state_path:
                        try:
                            self._persist_state()
                        except Exception:
                            self._load_persisted_state_unlocked()
                            return {
                                "success": False,
                                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAY_FAILED",
                                "reason": "durable_replay_audit_commit_failed",
                                "read_only": False,
                                "authoritative_state_mutated": False,
                            }
                    return {
                        **proof_verification,
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_REPLAYED",
                        "reason": "proof_already_consumed",
                        "consumption_attestation_id": consumption_attestation_id,
                        "consumption_nonce": consumption_nonce,
                        "consumed_record": existing,
                        "audit_record": replay_audit.get("record"),
                        "read_only": False,
                        "authoritative_state_mutated": True,
                    }

                claim = self.registry.consume_decision_attestation(
                    consumption_attestation_id,
                    proof_fingerprint,
                    nonce=consumption_nonce,
                    consumed_at=event_time,
                )
                if not claim.get("success"):
                    return {
                        **claim,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                audit = self.registry._append_decision_attestation_consumption_audit(
                    event_type="DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED",
                    attestation_id=consumption_attestation_id,
                    decision_fingerprint=proof_fingerprint,
                    nonce=consumption_nonce,
                    consumed_at=event_time,
                    reason="one_time_consumption",
                )
                if not audit.get("success"):
                    self.registry._consumed_decision_attestations.pop(consumption_attestation_id, None)
                    return {
                        **audit,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_FAILED",
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                if self.state_path:
                    try:
                        self._persist_state()
                    except OIDCTrustStateConflictError:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_CONFLICT",
                            "reason": "durable_consumption_commit_conflict",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    except Exception as exc:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_FAILED",
                            "reason": "durable_consumption_commit_failed",
                            "error": str(exc)[:300],
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }

                return {
                    **proof_verification,
                    "success": True,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED",
                    "consumption": claim,
                    "consumption_attestation_id": consumption_attestation_id,
                    "consumption_nonce": consumption_nonce,
                    "audit_record": audit.get("record"),
                    "read_only": False,
                    "authoritative_state_mutated": True,
                }

        if self.state_path:
            from memory_storage import interprocess_lock
            with self._refresh_lock:
                with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                    latest = self._load_persisted_state_unlocked()
                    if not latest.get("loaded"):
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                            "reason": "authoritative_trust_state_unavailable",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    return _verify_current_state()

        with self._refresh_lock:
            return _verify_current_state()


    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
        cls,
        proof,
        public_keys_by_fingerprint,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a proof-bundle-attestation consumption binding proof offline."""
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "proof_must_be_object",
            }
        if not isinstance(public_keys_by_fingerprint, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "public_keys_by_fingerprint_must_be_object",
            }
        required = (
            "schema_version",
            "proof_type",
            "attested_bundle",
            "consumption_audit_evidence",
            "binding",
            "proof_fingerprint",
        )
        missing = [field for field in required if field not in proof]
        if missing:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "missing_proof_fields",
                "fields": missing,
            }
        try:
            schema_version = int(proof.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "unsupported_proof_schema",
            }
        if proof.get("proof_type") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_BINDING_PROOF":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "unsupported_proof_type",
            }

        fingerprint_payload = dict(proof)
        fingerprint_payload.pop("exported_at", None)
        expected_proof_fingerprint = str(fingerprint_payload.pop("proof_fingerprint", "") or "").strip().lower()
        actual_proof_fingerprint = hashlib.sha256(_canonical_json(fingerprint_payload).encode("utf-8")).hexdigest()
        if not expected_proof_fingerprint or expected_proof_fingerprint != actual_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "proof_fingerprint_mismatch",
                "expected_fingerprint": expected_proof_fingerprint,
                "actual_fingerprint": actual_proof_fingerprint,
            }

        attested_bundle = proof.get("attested_bundle")
        attestation = attested_bundle.get("bundle_attestation") if isinstance(attested_bundle, dict) else None
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "bundle_attestation_missing",
            }
        key_fingerprint = str(attestation.get("key_fingerprint", "") or "").strip().lower()
        if not key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "attestation_key_fingerprint_missing",
            }
        public_key = public_keys_by_fingerprint.get(key_fingerprint)
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "attestation_public_key_missing",
            }

        bundle_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
            attested_bundle,
            public_keys_by_fingerprint,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not bundle_verification.get("success"):
            return {
                **bundle_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "bundle_attestation_invalid",
            }

        expected_key_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        if expected_key_fingerprint and key_fingerprint != expected_key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "attested_key_fingerprint_mismatch",
            }
        try:
            actual_public_key_fingerprint = _public_key_fingerprint(public_key).strip().lower()
        except Exception:
            actual_public_key_fingerprint = ""
        if not actual_public_key_fingerprint or actual_public_key_fingerprint != key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "public_key_fingerprint_mismatch",
            }

        consumption_evidence = proof.get("consumption_audit_evidence")
        evidence_verification = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(consumption_evidence)
        if not evidence_verification.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_evidence_invalid",
                "verification": evidence_verification,
            }

        binding = proof.get("binding")
        if not isinstance(binding, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_not_object",
            }

        try:
            sequence = int(binding.get("consumption_audit_sequence"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_sequence_invalid",
            }
        records = consumption_evidence.get("records") if isinstance(consumption_evidence, dict) else None
        if not isinstance(records, list):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_records_not_list",
            }
        matching = [
            record for record in records
            if isinstance(record, dict) and int(record.get("sequence", 0) or 0) == sequence
        ]
        if len(matching) != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_record_not_found",
            }
        audit_record = matching[0]
        attestation_id = str(bundle_verification.get("attestation_id", "") or "").strip()
        nonce = str(bundle_verification.get("nonce", "") or "").strip()
        bundle_fingerprint = str(bundle_verification.get("bundle_fingerprint", "") or "").strip().lower()
        chain_fingerprint = str(bundle_verification.get("chain_fingerprint", "") or "").strip().lower()
        try:
            proof_count = int(bundle_verification.get("proof_count", 0) or 0)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "proof_count_invalid",
            }
        signature_fingerprint = str(bundle_verification.get("signature_fingerprint", "") or "").strip().lower()
        if str(audit_record.get("event_type", "") or "") != "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "unexpected_consumption_event_type",
            }
        if str(audit_record.get("attestation_id", "") or "").strip() != attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "audit_attestation_id_mismatch",
            }
        if str(audit_record.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "audit_nonce_mismatch",
            }
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != bundle_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "audit_bundle_fingerprint_mismatch",
            }

        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        if record_hash != str(binding.get("consumption_audit_record_hash", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_record_hash_mismatch",
            }
        if previous_hash != str(binding.get("consumption_audit_previous_hash", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_previous_hash_mismatch",
            }

        try:
            consumed_at = float(audit_record.get("event_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "consumption_time_invalid",
            }
        try:
            binding_consumed_at = float(binding.get("consumed_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_consumption_time_invalid",
            }
        if binding_consumed_at != consumed_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_consumption_time_mismatch",
            }

        if str(binding.get("bundle_id", "") or "").strip() != str(bundle_verification.get("bundle_id", "") or "").strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_bundle_id_mismatch",
            }
        if str(binding.get("bundle_fingerprint", "") or "").strip().lower() != bundle_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_bundle_fingerprint_mismatch",
            }
        if str(binding.get("chain_fingerprint", "") or "").strip().lower() != chain_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_chain_fingerprint_mismatch",
            }
        if int(binding.get("proof_count", 0) or 0) != proof_count:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_proof_count_mismatch",
            }
        if str(binding.get("signature_fingerprint", "") or "").strip().lower() != signature_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_signature_fingerprint_mismatch",
            }
        if str(binding.get("key_fingerprint", "") or "").strip().lower() != key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_key_fingerprint_mismatch",
            }
        if str(binding.get("attestation_id", "") or "").strip() != attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_attestation_id_mismatch",
            }
        if str(binding.get("nonce", "") or "").strip() != nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_nonce_mismatch",
            }

        binding_payload = {
            "binding_version": int(binding.get("binding_version", 0) or 0),
            "attestation_type": str(attestation.get("attestation_type", "") or ""),
            "issuer": str(bundle_verification.get("issuer", "") or "").strip().rstrip("/"),
            "key_id": str(bundle_verification.get("key_id", "") or "").strip(),
            "key_fingerprint": key_fingerprint,
            "registry_revision": binding.get("recorded_registry_revision", attestation.get("registry_revision")),
            "key_set_fingerprint": str(
                binding.get("recorded_key_set_fingerprint", attestation.get("key_set_fingerprint", "")) or ""
            ).strip().lower(),
            "trusted_key_source": str(
                binding.get("trusted_key_source", attestation.get("key_source", "")) or ""
            ).strip(),
            "trusted_key_version": str(
                binding.get("trusted_key_version", attestation.get("key_version", "")) or ""
            ).strip(),
            "bundle_id": str(bundle_verification.get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": bundle_fingerprint,
            "chain_fingerprint": chain_fingerprint,
            "proof_count": proof_count,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "signature_fingerprint": signature_fingerprint,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        if binding_payload["binding_version"] != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "unsupported_binding_version",
            }
        actual_binding_fingerprint = hashlib.sha256(_canonical_json(binding_payload).encode("utf-8")).hexdigest()
        expected_binding_fingerprint = str(binding.get("binding_fingerprint", "") or "").strip().lower()
        if actual_binding_fingerprint != expected_binding_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_INVALID",
                "reason": "binding_fingerprint_mismatch",
                "expected_fingerprint": expected_binding_fingerprint,
                "actual_fingerprint": actual_binding_fingerprint,
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_VERIFIED",
            "proof_fingerprint": actual_proof_fingerprint,
            "binding_fingerprint": actual_binding_fingerprint,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "bundle_id": bundle_verification.get("bundle_id", ""),
            "bundle_fingerprint": bundle_fingerprint,
            "chain_fingerprint": chain_fingerprint,
            "proof_count": proof_count,
            "signature_fingerprint": signature_fingerprint,
            "consumption_audit_sequence": sequence,
            "consumption_audit_record_hash": record_hash,
            "recorded_key_fingerprint": key_fingerprint,
            "recorded_registry_revision": binding_payload["registry_revision"],
            "recorded_key_set_fingerprint": binding_payload["key_set_fingerprint"],
            "trusted_key_source": binding_payload["trusted_key_source"],
            "trusted_key_version": binding_payload["trusted_key_version"],
            "current_registry_binding": None,
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        cls,
        proof,
        registry,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Cryptographically bind consumption of a bundle-attestation binding proof.

        The source binding proof is already cryptographically tied to the signed
        bundle attestation and its historical consume event. This additional
        binding cross-checks that proof against the authoritative one-time
        consumption event for the binding proof itself. No new storage is used.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_must_be_object",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        source_proof_fingerprint = str(proof.get("proof_fingerprint", "") or "").strip().lower()
        if len(source_proof_fingerprint) != 64 or any(
            char not in "0123456789abcdef" for char in source_proof_fingerprint
        ):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_fingerprint_missing_or_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attested_bundle = proof.get("attested_bundle")
        if not isinstance(attested_bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "attested_bundle_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attestation = attested_bundle.get("bundle_attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "bundle_attestation_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        key_id = str(attestation.get("key_id", "") or "").strip()
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict) or discovered.get("public_key") is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "trusted_key_not_found",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        public_key = discovered.get("public_key")
        metadata = discovered.get("metadata") or {}
        discovered_key_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not discovered_key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                "reason": "trusted_key_fingerprint_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        registry_bundle_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
            attested_bundle,
            registry,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            require_current_registry_binding=require_current_registry_binding,
            expected_verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not registry_bundle_verification.get("success"):
            return {
                **registry_bundle_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "bundle_attestation_registry_verification_failed",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        source_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
            proof,
            {discovered_key_fingerprint: public_key},
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_key_fingerprint=expected_key_fingerprint or discovered_key_fingerprint,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not source_verification.get("success"):
            return {
                **source_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        consumption_attestation_id = f"proof-binding:{source_proof_fingerprint}"[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
        consumption_nonce = f"proof-binding:{source_proof_fingerprint}"
        status = registry.get_decision_attestation_consumption_status(
            consumption_attestation_id,
            verify_integrity=verify_integrity,
            include_replay_events=True,
        )
        if not status.get("success"):
            return {
                **status,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": f"consumption_status_{status.get('reason', status.get('status', 'invalid'))}",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if status.get("status") != "DECISION_ATTESTATION_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_not_consumed",
                "consumption_status": status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        consumed = status.get("consumed_record") or {}
        audit_record = status.get("consumption_audit_record") or {}
        if str(consumed.get("decision_fingerprint", "") or "").strip().lower() != source_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumed_record_proof_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(consumed.get("nonce", "") or "") != consumption_nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumed_record_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("event_type", "") or "") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unexpected_consumption_event_type",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("attestation_id", "") or "").strip() != consumption_attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_attestation_id_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != source_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_proof_fingerprint_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("nonce", "") or "") != consumption_nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_nonce_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        if not record_hash or not previous_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_hash_fields_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            consumed_at = float(consumed.get("consumed_at"))
            event_at = float(audit_record.get("event_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if consumed_at != event_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            sequence = int(audit_record.get("sequence"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_sequence_invalid",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        source_binding_fingerprint = str(source_verification.get("binding_fingerprint", "") or "").strip().lower()
        source_bundle_id = str(source_verification.get("bundle_id", "") or "").strip()
        source_bundle_fingerprint = str(source_verification.get("bundle_fingerprint", "") or "").strip().lower()
        source_chain_fingerprint = str(source_verification.get("chain_fingerprint", "") or "").strip().lower()
        try:
            source_proof_count = int(source_verification.get("proof_count", 0) or 0)
        except (TypeError, ValueError):
            source_proof_count = 0

        binding_payload = {
            "binding_version": 1,
            "source_proof_type": str(proof.get("proof_type", "") or ""),
            "source_proof_fingerprint": source_proof_fingerprint,
            "source_binding_fingerprint": source_binding_fingerprint,
            "bundle_id": source_bundle_id,
            "bundle_fingerprint": source_bundle_fingerprint,
            "chain_fingerprint": source_chain_fingerprint,
            "proof_count": source_proof_count,
            "attestation_id": str(source_verification.get("attestation_id", "") or "").strip(),
            "nonce": str(source_verification.get("nonce", "") or ""),
            "key_fingerprint": discovered_key_fingerprint,
            "registry_revision": source_verification.get("recorded_registry_revision"),
            "key_set_fingerprint": str(source_verification.get("recorded_key_set_fingerprint", "") or "").strip().lower(),
            "trusted_key_source": str(source_verification.get("trusted_key_source", "") or "").strip(),
            "trusted_key_version": str(source_verification.get("trusted_key_version", "") or "").strip(),
            "consumption_attestation_id": consumption_attestation_id,
            "consumption_nonce": consumption_nonce,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        if binding_payload["binding_version"] != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unsupported_binding_version",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        binding_fingerprint = hashlib.sha256(_canonical_json(binding_payload).encode("utf-8")).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BOUND",
            "source_proof_fingerprint": source_proof_fingerprint,
            "source_binding_fingerprint": source_binding_fingerprint,
            "binding_fingerprint": binding_fingerprint,
            "bundle_id": source_bundle_id,
            "bundle_fingerprint": source_bundle_fingerprint,
            "chain_fingerprint": source_chain_fingerprint,
            "proof_count": source_proof_count,
            "attestation_id": binding_payload["attestation_id"],
            "nonce": binding_payload["nonce"],
            "key_fingerprint": discovered_key_fingerprint,
            "consumption_attestation_id": consumption_attestation_id,
            "consumption_nonce": consumption_nonce,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
            "recorded_registry_revision": binding_payload["registry_revision"],
            "recorded_key_set_fingerprint": binding_payload["key_set_fingerprint"],
            "trusted_key_source": binding_payload["trusted_key_source"],
            "trusted_key_version": binding_payload["trusted_key_version"],
            "current_registry_binding": source_verification.get("current_registry_binding"),
            "verification": source_verification,
            "consumption_status": status,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def export_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        self,
        proof,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Export a self-contained proof that a binding proof was consumed once."""
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_must_be_object",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
            proof,
            self.registry,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_key_fingerprint=expected_key_fingerprint,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
            require_current_registry_binding=require_current_registry_binding,
            verify_integrity=verify_integrity,
        )
        if not binding.get("success"):
            return {
                **binding,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        sequence = binding.get("consumption_audit_sequence")
        exported = self.registry.export_decision_attestation_consumption_audit_evidence(
            start_sequence=sequence,
            end_sequence=sequence,
        )
        if not exported.get("success"):
            return {
                **exported,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_evidence_export_failed",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        proof_export = {
            "schema_version": 1,
            "proof_type": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_PROOF",
            "source_proof": json.loads(_canonical_json(proof)),
            "consumption_audit_evidence": exported.get("evidence"),
            "binding": {
                "binding_version": binding.get("binding_version", 1),
                "source_proof_fingerprint": binding.get("source_proof_fingerprint"),
                "source_binding_fingerprint": binding.get("source_binding_fingerprint"),
                "bundle_id": binding.get("bundle_id"),
                "bundle_fingerprint": binding.get("bundle_fingerprint"),
                "chain_fingerprint": binding.get("chain_fingerprint"),
                "proof_count": binding.get("proof_count"),
                "attestation_id": binding.get("attestation_id"),
                "nonce": binding.get("nonce"),
                "key_fingerprint": binding.get("key_fingerprint"),
                "consumption_attestation_id": binding.get("consumption_attestation_id"),
                "consumption_nonce": binding.get("consumption_nonce"),
                "consumed_at": binding.get("consumed_at"),
                "consumption_audit_sequence": binding.get("consumption_audit_sequence"),
                "consumption_audit_previous_hash": binding.get("consumption_audit_previous_hash"),
                "consumption_audit_record_hash": binding.get("consumption_audit_record_hash"),
                "recorded_registry_revision": binding.get("recorded_registry_revision"),
                "recorded_key_set_fingerprint": binding.get("recorded_key_set_fingerprint"),
                "trusted_key_source": binding.get("trusted_key_source"),
                "trusted_key_version": binding.get("trusted_key_version"),
                "binding_fingerprint": binding.get("binding_fingerprint"),
            },
            "exported_at": float(time.time()),
            "proof_fingerprint": "",
        }
        fingerprint_payload = dict(proof_export)
        fingerprint_payload.pop("exported_at", None)
        fingerprint_payload.pop("proof_fingerprint", None)
        embedded_audit = fingerprint_payload.get("consumption_audit_evidence")
        if isinstance(embedded_audit, dict):
            embedded_audit = dict(embedded_audit)
            embedded_audit.pop("exported_at", None)
            fingerprint_payload["consumption_audit_evidence"] = embedded_audit
        proof_export["proof_fingerprint"] = hashlib.sha256(
            _canonical_json(fingerprint_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_EXPORTED",
            "proof": proof_export,
            "binding": binding,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def consume_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
        self,
        proof,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
    ):
        """Verify and consume a consumption-binding proof exactly once.

        The proof fingerprint is the immutable artifact identity.  The existing
        trusted-registry one-time-consumption ledger, immutable consumption audit
        chain, persistent trust state, and inter-process lock are reused.  No new
        storage or replay ledger is introduced.
        """
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                "reason": "proof_must_be_object",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        proof_fingerprint = str(proof.get("proof_fingerprint", "") or "").strip().lower()
        if len(proof_fingerprint) != 64 or any(char not in "0123456789abcdef" for char in proof_fingerprint):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                "reason": "proof_fingerprint_missing_or_invalid",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        source_proof = proof.get("source_proof")
        if not isinstance(source_proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                "reason": "source_proof_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }
        attested_bundle = source_proof.get("attested_bundle")
        attestation = attested_bundle.get("bundle_attestation") if isinstance(attested_bundle, dict) else None
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                "reason": "bundle_attestation_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        def _verify_current_state():
            key_id = str(attestation.get("key_id", "") or "").strip()
            discovered = self.registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
            if not isinstance(discovered, dict) or discovered.get("public_key") is None:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                    "reason": "trusted_key_not_found",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }
            public_key = discovered.get("public_key")
            metadata = discovered.get("metadata") or {}
            key_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
            if not key_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_INVALID",
                    "reason": "trusted_key_fingerprint_missing",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            authoritative_binding = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding(
                source_proof,
                self.registry,
                expected_bundle_id=expected_bundle_id,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                expected_key_fingerprint=expected_key_fingerprint or key_fingerprint,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
                require_current_registry_binding=require_current_registry_binding,
                verify_integrity=True,
            )
            if not authoritative_binding.get("success"):
                return {
                    **authoritative_binding,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            offline_binding = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
                proof,
                {key_fingerprint: public_key},
                expected_bundle_id=expected_bundle_id,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                expected_key_fingerprint=expected_key_fingerprint or key_fingerprint,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
            )
            if not offline_binding.get("success"):
                return {
                    **offline_binding,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            consumption_attestation_id = f"binding-consumption-binding:{proof_fingerprint}"[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]
            consumption_nonce = f"binding-consumption-binding:{proof_fingerprint}"
            event_time = time.time() if verification_time is None else verification_time

            with self.registry._consumption_lock:
                existing = self.registry.get_consumed_decision_attestation(consumption_attestation_id)
                if existing is not None:
                    replay_audit = self.registry._append_decision_attestation_consumption_audit(
                        event_type="DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAY_REJECTED",
                        attestation_id=consumption_attestation_id,
                        decision_fingerprint=proof_fingerprint,
                        nonce=consumption_nonce,
                        consumed_at=event_time,
                        reason="proof_already_consumed",
                        previous_consumed_record=existing,
                    )
                    if not replay_audit.get("success"):
                        return {
                            **replay_audit,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAY_FAILED",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    if self.state_path:
                        try:
                            self._persist_state()
                        except Exception:
                            self._load_persisted_state_unlocked()
                            return {
                                "success": False,
                                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAY_FAILED",
                                "reason": "durable_replay_audit_commit_failed",
                                "read_only": False,
                                "authoritative_state_mutated": False,
                            }
                    return {
                        **authoritative_binding,
                        **offline_binding,
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_REPLAYED",
                        "reason": "proof_already_consumed",
                        "consumption_attestation_id": consumption_attestation_id,
                        "consumption_nonce": consumption_nonce,
                        "consumed_record": existing,
                        "audit_record": replay_audit.get("record"),
                        "read_only": False,
                        "authoritative_state_mutated": True,
                    }

                claim = self.registry.consume_decision_attestation(
                    consumption_attestation_id,
                    proof_fingerprint,
                    nonce=consumption_nonce,
                    consumed_at=event_time,
                )
                if not claim.get("success"):
                    return {
                        **claim,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                audit = self.registry._append_decision_attestation_consumption_audit(
                    event_type="DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMED",
                    attestation_id=consumption_attestation_id,
                    decision_fingerprint=proof_fingerprint,
                    nonce=consumption_nonce,
                    consumed_at=event_time,
                    reason="one_time_consumption",
                )
                if not audit.get("success"):
                    self.registry._consumed_decision_attestations.pop(consumption_attestation_id, None)
                    return {
                        **audit,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_FAILED",
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                if self.state_path:
                    try:
                        self._persist_state()
                    except OIDCTrustStateConflictError:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONFLICT",
                            "reason": "durable_consumption_commit_conflict",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    except Exception as exc:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_FAILED",
                            "reason": "durable_consumption_commit_failed",
                            "error": str(exc)[:300],
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }

                return {
                    **authoritative_binding,
                    **offline_binding,
                    "success": True,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMED",
                    "consumption": claim,
                    "consumption_attestation_id": consumption_attestation_id,
                    "consumption_nonce": consumption_nonce,
                    "audit_record": audit.get("record"),
                    "read_only": False,
                    "authoritative_state_mutated": True,
                }

        if self.state_path:
            from memory_storage import interprocess_lock
            with self._refresh_lock:
                with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                    latest = self._load_persisted_state_unlocked()
                    if not latest.get("loaded"):
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_CONSUMPTION_INVALID",
                            "reason": "authoritative_trust_state_unavailable",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    return _verify_current_state()

        with self._refresh_lock:
            return _verify_current_state()

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
        cls,
        proof,
        public_keys_by_fingerprint,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a binding proof's consumption proof without authoritative state."""
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(public_keys_by_fingerprint, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "public_keys_by_fingerprint_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        required = (
            "schema_version",
            "proof_type",
            "source_proof",
            "consumption_audit_evidence",
            "binding",
            "proof_fingerprint",
        )
        missing = [field for field in required if field not in proof]
        if missing:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "missing_proof_fields",
                "fields": missing,
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            schema_version = int(proof.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unsupported_proof_schema",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if proof.get("proof_type") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_PROOF":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unsupported_proof_type",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        fingerprint_payload = dict(proof)
        fingerprint_payload.pop("exported_at", None)
        expected_proof_fingerprint = str(fingerprint_payload.pop("proof_fingerprint", "") or "").strip().lower()
        embedded_audit = fingerprint_payload.get("consumption_audit_evidence")
        if isinstance(embedded_audit, dict):
            embedded_audit = dict(embedded_audit)
            embedded_audit.pop("exported_at", None)
            fingerprint_payload["consumption_audit_evidence"] = embedded_audit
        actual_proof_fingerprint = hashlib.sha256(_canonical_json(fingerprint_payload).encode("utf-8")).hexdigest()
        if not expected_proof_fingerprint or expected_proof_fingerprint != actual_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "proof_fingerprint_mismatch",
                "expected_fingerprint": expected_proof_fingerprint,
                "actual_fingerprint": actual_proof_fingerprint,
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        source_proof = proof.get("source_proof")
        if not isinstance(source_proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "source_proof_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        source_proof_fingerprint = str(source_proof.get("proof_fingerprint", "") or "").strip().lower()
        source_binding = source_proof.get("binding") if isinstance(source_proof, dict) else None
        source_attested_bundle = source_proof.get("attested_bundle") if isinstance(source_proof, dict) else None
        source_attestation = source_attested_bundle.get("bundle_attestation") if isinstance(source_attested_bundle, dict) else None
        if not isinstance(source_binding, dict) or not isinstance(source_attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "source_proof_structure_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        source_key_fingerprint = str(source_attestation.get("key_fingerprint", "") or "").strip().lower()
        source_key = public_keys_by_fingerprint.get(source_key_fingerprint)
        if source_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "attestation_public_key_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        source_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof(
            source_proof,
            public_keys_by_fingerprint,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_key_fingerprint=expected_key_fingerprint or source_key_fingerprint,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not source_verification.get("success"):
            return {
                **source_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "source_proof_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        consumption_evidence = proof.get("consumption_audit_evidence")
        evidence_verification = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(consumption_evidence)
        if not evidence_verification.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_evidence_invalid",
                "verification": evidence_verification,
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding = proof.get("binding")
        if not isinstance(binding, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_not_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            sequence = int(binding.get("consumption_audit_sequence"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_sequence_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        records = consumption_evidence.get("records") if isinstance(consumption_evidence, dict) else None
        if not isinstance(records, list):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_records_not_list",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        matching = [record for record in records if isinstance(record, dict) and int(record.get("sequence", 0) or 0) == sequence]
        if len(matching) != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_audit_record_not_found",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        audit_record = matching[0]
        consumption_attestation_id = str(binding.get("consumption_attestation_id", "") or "").strip()
        consumption_nonce = str(binding.get("consumption_nonce", "") or "")
        if consumption_attestation_id != f"proof-binding:{source_proof_fingerprint}"[:MAX_CONSUMED_ATTESTATION_ID_LENGTH]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_attestation_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if consumption_nonce != f"proof-binding:{source_proof_fingerprint}":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_nonce_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("event_type", "") or "") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMED":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unexpected_consumption_event_type",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("attestation_id", "") or "").strip() != consumption_attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_attestation_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != source_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "audit_proof_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        try:
            consumed_at = float(audit_record.get("event_at"))
            binding_consumed_at = float(binding.get("consumed_at"))
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if binding_consumed_at != consumed_at:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "consumption_time_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("source_proof_fingerprint", "") or "").strip().lower() != source_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_source_proof_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("source_binding_fingerprint", "") or "").strip().lower() != str(source_verification.get("binding_fingerprint", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_source_binding_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("bundle_id", "") or "").strip() != str(source_verification.get("bundle_id", "") or "").strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_bundle_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("bundle_fingerprint", "") or "").strip().lower() != str(source_verification.get("bundle_fingerprint", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_bundle_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("chain_fingerprint", "") or "").strip().lower() != str(source_verification.get("chain_fingerprint", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_chain_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("key_fingerprint", "") or "").strip().lower() != source_key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_key_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("consumption_audit_record_hash", "") or "").strip().lower() != record_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_record_hash_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if str(binding.get("consumption_audit_previous_hash", "") or "").strip().lower() != previous_hash:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_previous_hash_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding_payload = {
            "binding_version": int(binding.get("binding_version", 0) or 0),
            "source_proof_type": str(source_proof.get("proof_type", "") or ""),
            "source_proof_fingerprint": source_proof_fingerprint,
            "source_binding_fingerprint": str(source_verification.get("binding_fingerprint", "") or "").strip().lower(),
            "bundle_id": str(source_verification.get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": str(source_verification.get("bundle_fingerprint", "") or "").strip().lower(),
            "chain_fingerprint": str(source_verification.get("chain_fingerprint", "") or "").strip().lower(),
            "proof_count": int(source_verification.get("proof_count", 0) or 0),
            "attestation_id": str(source_verification.get("attestation_id", "") or "").strip(),
            "nonce": str(source_verification.get("nonce", "") or ""),
            "key_fingerprint": source_key_fingerprint,
            "registry_revision": binding.get("recorded_registry_revision", source_verification.get("recorded_registry_revision")),
            "key_set_fingerprint": str(binding.get("recorded_key_set_fingerprint", source_verification.get("recorded_key_set_fingerprint", "")) or "").strip().lower(),
            "trusted_key_source": str(binding.get("trusted_key_source", source_verification.get("trusted_key_source", "")) or "").strip(),
            "trusted_key_version": str(binding.get("trusted_key_version", source_verification.get("trusted_key_version", "")) or "").strip(),
            "consumption_attestation_id": consumption_attestation_id,
            "consumption_nonce": consumption_nonce,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        if binding_payload["binding_version"] != 1:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "unsupported_binding_version",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        actual_binding_fingerprint = hashlib.sha256(_canonical_json(binding_payload).encode("utf-8")).hexdigest()
        expected_binding_fingerprint = str(binding.get("binding_fingerprint", "") or "").strip().lower()
        if actual_binding_fingerprint != expected_binding_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                "reason": "binding_fingerprint_mismatch",
                "expected_fingerprint": expected_binding_fingerprint,
                "actual_fingerprint": actual_binding_fingerprint,
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_OFFLINE_VERIFIED",
            "proof_fingerprint": actual_proof_fingerprint,
            "source_proof_fingerprint": source_proof_fingerprint,
            "source_binding_fingerprint": str(source_verification.get("binding_fingerprint", "") or "").strip().lower(),
            "binding_fingerprint": actual_binding_fingerprint,
            "bundle_id": binding_payload["bundle_id"],
            "bundle_fingerprint": binding_payload["bundle_fingerprint"],
            "chain_fingerprint": binding_payload["chain_fingerprint"],
            "proof_count": binding_payload["proof_count"],
            "attestation_id": binding_payload["attestation_id"],
            "nonce": binding_payload["nonce"],
            "key_fingerprint": source_key_fingerprint,
            "consumption_attestation_id": consumption_attestation_id,
            "consumption_nonce": consumption_nonce,
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
            "recorded_registry_revision": binding_payload["registry_revision"],
            "recorded_key_set_fingerprint": binding_payload["key_set_fingerprint"],
            "trusted_key_source": binding_payload["trusted_key_source"],
            "trusted_key_version": binding_payload["trusted_key_version"],
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_audit_evidence_trusted_key_replay_binding_offline(
        cls,
        attested_evidence,
        public_key,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a trusted-key schema-v2 attestation without registry access."""
        if not isinstance(attested_evidence, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "evidence_must_be_object"}
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "public_key_required"}
        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "attestation_missing"}
        try:
            schema_version = int(attestation.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 2:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "replay_binding_schema_required"}
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION":
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "unsupported_attestation_type"}
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "unsupported_attestation_algorithm"}
        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(attestation.get("key_id", "") or "").strip()
        if not issuer or not key_id:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_or_key_id_missing"}
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "issuer_mismatch"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_id_mismatch"}
        replay = cls._verify_decision_attestation_replay_binding(
            attestation,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not replay.get("success"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": replay.get("reason", "invalid_replay_binding")}
        recorded_key_fingerprint = str(attestation.get("key_fingerprint", "") or "").strip().lower()
        expected_key_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        if not recorded_key_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "key_fingerprint_missing"}
        if expected_key_fingerprint and recorded_key_fingerprint != expected_key_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "trusted_key_fingerprint_mismatch"}
        try:
            actual_public_key_fingerprint = _public_key_fingerprint(public_key).strip().lower()
        except Exception:
            actual_public_key_fingerprint = ""
        if not actual_public_key_fingerprint or actual_public_key_fingerprint != recorded_key_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "public_key_fingerprint_mismatch"}
        recorded_provenance = {
            "key_fingerprint": recorded_key_fingerprint,
            "registry_revision": attestation.get("registry_revision"),
            "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(attestation.get("key_source", "") or "").strip(),
            "key_version": str(attestation.get("key_version", "") or "").strip(),
        }
        if not recorded_provenance["key_set_fingerprint"] or not recorded_provenance["key_source"] or not recorded_provenance["key_version"]:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "trusted_key_provenance_missing"}
        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(base_evidence)
        if not evidence_result.get("success"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "embedded_evidence_invalid", "verification": evidence_result}
        evidence_fingerprint = str(base_evidence.get("evidence_fingerprint", "") or "").strip().lower()
        if str(attestation.get("evidence_fingerprint", "") or "").strip().lower() != evidence_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "evidence_fingerprint_mismatch"}
        payload = cls._decision_attestation_consumption_audit_evidence_trusted_attestation_payload_v2(
            base_evidence,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=recorded_provenance["key_fingerprint"],
            registry_revision=recorded_provenance["registry_revision"],
            key_set_fingerprint=recorded_provenance["key_set_fingerprint"],
            key_source=recorded_provenance["key_source"],
            key_version=recorded_provenance["key_version"],
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "signature_verification_failed"}
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        expected_signature_fp = str(attestation.get("signature_fingerprint", "") or "").strip().lower()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_INVALID", "reason": "signature_fingerprint_mismatch"}
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_TRUSTED_KEY_REPLAY_BOUND_OFFLINE_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "recorded_registry_revision": recorded_provenance["registry_revision"],
            "recorded_key_fingerprint": recorded_key_fingerprint,
            "recorded_key_set_fingerprint": recorded_provenance["key_set_fingerprint"],
            "trusted_key_source": recorded_provenance["key_source"],
            "trusted_key_version": recorded_provenance["key_version"],
            "current_registry_binding": None,
            "replay_binding": True,
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def export_decision_attestation_consumption_binding_proof(
        self,
        attested_evidence,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
        verify_integrity=True,
    ):
        """Export a self-contained cryptographic proof of one-time consumption binding.

        The package contains the signed evidence attestation, the authenticated
        consumption-audit evidence prefix containing the durable CONSUMED event,
        and the deterministic binding fingerprint.  The package is read-only and
        can later be verified without access to the originating registry state.
        """
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "reason": "evidence_must_be_object",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        binding = self.__class__.verify_decision_attestation_consumption_audit_evidence_attestation_consumption_binding(
            attested_evidence,
            self.registry,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_key_statuses=expected_key_statuses,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
            require_current_registry_binding=require_current_registry_binding,
            verify_integrity=verify_integrity,
        )
        if not binding.get("success"):
            return {
                **binding,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        sequence = binding.get("consumption_audit_sequence")
        try:
            sequence = int(sequence)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_sequence_invalid",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        exported = self.registry.export_decision_attestation_consumption_audit_evidence(
            start_sequence=sequence,
            end_sequence=sequence,
        )
        if not exported.get("success"):
            return {
                **exported,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "reason": "consumption_audit_evidence_export_failed",
                "proof": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        proof = {
            "schema_version": 1,
            "proof_type": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF",
            "attested_evidence": json.loads(_canonical_json(attested_evidence)),
            "consumption_audit_evidence": exported.get("evidence"),
            "binding": {
                "binding_version": binding.get("binding_version"),
                "binding_fingerprint": binding.get("binding_fingerprint"),
                "attestation_id": binding.get("attestation_id"),
                "nonce": binding.get("nonce"),
                "evidence_fingerprint": binding.get("evidence_fingerprint"),
                "signature_fingerprint": binding.get("signature_fingerprint"),
                "consumed_at": binding.get("consumed_at"),
                "consumption_audit_sequence": binding.get("consumption_audit_sequence"),
                "consumption_audit_previous_hash": binding.get("consumption_audit_previous_hash"),
                "consumption_audit_record_hash": binding.get("consumption_audit_record_hash"),
                "consumption_audit_head_hash": binding.get("consumption_audit_head_hash"),
                "recorded_registry_revision": (binding.get("verification") or {}).get("recorded_registry_revision"),
                "recorded_key_fingerprint": (binding.get("verification") or {}).get("key_fingerprint"),
                "recorded_key_set_fingerprint": (binding.get("verification") or {}).get("recorded_key_set_fingerprint"),
                "trusted_key_source": (binding.get("verification") or {}).get("trusted_key_source"),
                "trusted_key_version": (binding.get("verification") or {}).get("trusted_key_version"),
            },
            "exported_at": float(time.time()),
            "proof_fingerprint": "",
        }
        fingerprint_payload = dict(proof)
        fingerprint_payload.pop("exported_at", None)
        fingerprint_payload.pop("proof_fingerprint", None)
        proof["proof_fingerprint"] = hashlib.sha256(
            _canonical_json(fingerprint_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_EXPORTED",
            "proof": proof,
            "binding": binding,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_binding_proof(
        cls,
        proof,
        public_key,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_key_fingerprint="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a consumption binding proof entirely offline.

        This verifies the exported audit chain, the Ed25519 replay-bound
        attestation, the supplied public-key fingerprint, and the deterministic
        binding fingerprint.  It deliberately does not claim current trust-state
        membership because no authoritative registry is consulted offline.
        """
        if not isinstance(proof, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "proof_must_be_object"}
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "public_key_required"}
        required = ("schema_version", "proof_type", "attested_evidence", "consumption_audit_evidence", "binding", "proof_fingerprint")
        missing = [field for field in required if field not in proof]
        if missing:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "missing_proof_fields", "fields": missing}
        try:
            schema_version = int(proof.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 1:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "unsupported_proof_schema"}
        if proof.get("proof_type") != "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF":
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "unsupported_proof_type"}

        fingerprint_payload = dict(proof)
        fingerprint_payload.pop("exported_at", None)
        expected_proof_fingerprint = str(fingerprint_payload.pop("proof_fingerprint", "") or "").strip().lower()
        actual_proof_fingerprint = hashlib.sha256(_canonical_json(fingerprint_payload).encode("utf-8")).hexdigest()
        if not expected_proof_fingerprint or expected_proof_fingerprint != actual_proof_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "reason": "proof_fingerprint_mismatch",
                "expected_fingerprint": expected_proof_fingerprint,
                "actual_fingerprint": actual_proof_fingerprint,
            }

        consumption_evidence = proof.get("consumption_audit_evidence")
        evidence_verification = TrustedAttestationKeyRegistry.verify_decision_attestation_consumption_audit_evidence(consumption_evidence)
        if not evidence_verification.get("success"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "consumption_audit_evidence_invalid", "verification": evidence_verification}

        attested_evidence = proof.get("attested_evidence")
        attestation_verification = cls.verify_decision_attestation_consumption_audit_evidence_trusted_key_replay_binding_offline(
            attested_evidence,
            public_key,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not attestation_verification.get("success"):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "attestation_invalid", "verification": attestation_verification}

        try:
            actual_public_key_fingerprint = _public_key_fingerprint(public_key)
        except Exception:
            actual_public_key_fingerprint = ""
        recorded_key_fingerprint = str(attestation_verification.get("recorded_key_fingerprint", attestation_verification.get("key_fingerprint", "")) or "").strip().lower()
        expected_key_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        if expected_key_fingerprint and recorded_key_fingerprint != expected_key_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "public_key_fingerprint_mismatch"}
        if actual_public_key_fingerprint and recorded_key_fingerprint and actual_public_key_fingerprint.lower() != recorded_key_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "attested_key_fingerprint_mismatch"}

        binding = proof.get("binding")
        if not isinstance(binding, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "binding_not_object"}
        binding_evidence_fingerprint = str(binding.get("evidence_fingerprint", "") or "").strip().lower()
        attestation_evidence_fingerprint = str(attestation_verification.get("evidence_fingerprint", "") or "").strip().lower()
        if binding_evidence_fingerprint != attestation_evidence_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "binding_evidence_fingerprint_mismatch"}

        records = consumption_evidence.get("records") if isinstance(consumption_evidence, dict) else None
        if not isinstance(records, list):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "consumption_records_not_list"}
        sequence = binding.get("consumption_audit_sequence")
        try:
            sequence = int(sequence)
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "consumption_audit_sequence_invalid"}
        matching = [record for record in records if isinstance(record, dict) and int(record.get("sequence", 0) or 0) == sequence]
        if len(matching) != 1:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "consumption_audit_record_not_found"}
        audit_record = matching[0]
        attestation_id = str(attestation_verification.get("attestation_id", "") or "").strip()
        nonce = str(attestation_verification.get("nonce", "") or "").strip()
        if str(audit_record.get("event_type", "") or "") != "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED":
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "unexpected_consumption_event_type"}
        if str(audit_record.get("attestation_id", "") or "").strip() != attestation_id:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "audit_attestation_id_mismatch"}
        if str(audit_record.get("nonce", "") or "").strip() != nonce:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "audit_nonce_mismatch"}
        if str(audit_record.get("decision_fingerprint", "") or "").strip().lower() != attestation_evidence_fingerprint:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "audit_evidence_fingerprint_mismatch"}
        record_hash = str(audit_record.get("record_hash", "") or "").strip().lower()
        previous_hash = str(audit_record.get("previous_hash", "") or "").strip().lower()
        if record_hash != str(binding.get("consumption_audit_record_hash", "") or "").strip().lower():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "binding_record_hash_mismatch"}
        if previous_hash != str(binding.get("consumption_audit_previous_hash", "") or "").strip().lower():
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "binding_previous_hash_mismatch"}

        try:
            consumed_at = float(audit_record.get("event_at"))
        except (TypeError, ValueError):
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "consumption_time_invalid"}
        if float(binding.get("consumed_at")) != consumed_at:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "binding_consumption_time_mismatch"}

        recorded_registry_revision = binding.get("recorded_registry_revision")
        recorded_key_set_fingerprint = str(binding.get("recorded_key_set_fingerprint", "") or "").strip().lower()
        binding_payload = {
            "binding_version": int(binding.get("binding_version", 0) or 0),
            "attestation_type": str((attested_evidence.get("attestation") or {}).get("attestation_type", "") or ""),
            "issuer": str(attestation_verification.get("issuer", "") or "").strip().rstrip("/"),
            "key_id": str(attestation_verification.get("key_id", "") or "").strip(),
            "key_fingerprint": recorded_key_fingerprint,
            "registry_revision": recorded_registry_revision,
            "key_set_fingerprint": recorded_key_set_fingerprint,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "evidence_fingerprint": attestation_evidence_fingerprint,
            "signature_fingerprint": str(attestation_verification.get("signature_fingerprint", "") or "").strip().lower(),
            "consumed_at": consumed_at,
            "consumption_audit_sequence": sequence,
            "consumption_audit_previous_hash": previous_hash,
            "consumption_audit_record_hash": record_hash,
        }
        if binding_payload["binding_version"] != 1:
            return {"success": False, "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID", "reason": "unsupported_binding_version"}
        actual_binding_fingerprint = hashlib.sha256(_canonical_json(binding_payload).encode("utf-8")).hexdigest()
        expected_binding_fingerprint = str(binding.get("binding_fingerprint", "") or "").strip().lower()
        if actual_binding_fingerprint != expected_binding_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_INVALID",
                "reason": "binding_fingerprint_mismatch",
                "expected_fingerprint": expected_binding_fingerprint,
                "actual_fingerprint": actual_binding_fingerprint,
            }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF_VERIFIED",
            "proof_fingerprint": actual_proof_fingerprint,
            "binding_fingerprint": actual_binding_fingerprint,
            "attestation_id": attestation_id,
            "nonce": nonce,
            "evidence_fingerprint": attestation_evidence_fingerprint,
            "consumption_audit_sequence": sequence,
            "consumption_audit_record_hash": record_hash,
            "recorded_key_fingerprint": recorded_key_fingerprint,
            "recorded_registry_revision": recorded_registry_revision,
            "recorded_key_set_fingerprint": recorded_key_set_fingerprint,
            "current_registry_binding": None,
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def compose_decision_attestation_consumption_proof_bundle(
        cls,
        proofs,
        *,
        bundle_id="",
        created_at=None,
    ):
        """Compose multiple verified binding proofs into a deterministic offline proof chain.

        The bundle is read-only and introduces no persistence. Each proof is
        embedded in full and linked by the previous proof fingerprint. The
        resulting chain has independent chain and bundle fingerprints.
        """
        if not isinstance(proofs, list) or not proofs:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "proofs_must_be_non_empty_list",
                "bundle": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        normalized_proofs = []
        chain = []
        seen_fingerprints = set()
        previous_proof_fingerprint = ""

        for index, proof in enumerate(proofs, start=1):
            if not isinstance(proof, dict):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_not_object",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            try:
                schema_version = int(proof.get("schema_version", 0) or 0)
            except (TypeError, ValueError):
                schema_version = 0
            if schema_version != 1:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_schema_unsupported",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            if proof.get("proof_type") != "DECISION_ATTESTATION_CONSUMPTION_BINDING_PROOF":
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_type_unsupported",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            supplied_proof_fingerprint = str(proof.get("proof_fingerprint", "") or "").strip().lower()
            if not supplied_proof_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_fingerprint_missing",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            fingerprint_payload = dict(proof)
            fingerprint_payload.pop("exported_at", None)
            fingerprint_payload.pop("proof_fingerprint", None)
            actual_proof_fingerprint = hashlib.sha256(
                _canonical_json(fingerprint_payload).encode("utf-8")
            ).hexdigest()
            if actual_proof_fingerprint != supplied_proof_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_fingerprint_mismatch",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            if supplied_proof_fingerprint in seen_fingerprints:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": "duplicate_proof_fingerprint",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            binding = proof.get("binding")
            if not isinstance(binding, dict):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_binding_missing",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            attestation = proof.get("attested_evidence", {}).get("attestation")
            if not isinstance(attestation, dict):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"proof_{index}_attestation_missing",
                    "bundle": None,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            seen_fingerprints.add(supplied_proof_fingerprint)
            chain.append(
                {
                    "sequence": index,
                    "proof_fingerprint": supplied_proof_fingerprint,
                    "previous_proof_fingerprint": previous_proof_fingerprint,
                    "attestation_id": str(binding.get("attestation_id", "") or "").strip(),
                    "evidence_fingerprint": str(binding.get("evidence_fingerprint", "") or "").strip().lower(),
                    "binding_fingerprint": str(binding.get("binding_fingerprint", "") or "").strip().lower(),
                }
            )
            normalized_proofs.append(json.loads(_canonical_json(proof)))
            previous_proof_fingerprint = supplied_proof_fingerprint

        chain_fingerprint = hashlib.sha256(
            _canonical_json(chain).encode("utf-8")
        ).hexdigest()
        normalized_bundle_id = str(bundle_id or "").strip()
        if not normalized_bundle_id:
            normalized_bundle_id = "bundle_" + chain_fingerprint[:32]
        try:
            created_at_value = float(time.time() if created_at is None else created_at)
        except (TypeError, ValueError):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "created_at_invalid",
                "bundle": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if created_at_value < 0:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "created_at_invalid",
                "bundle": None,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        bundle = {
            "schema_version": 1,
            "bundle_type": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE",
            "bundle_id": normalized_bundle_id,
            "proof_count": len(normalized_proofs),
            "chain": chain,
            "chain_fingerprint": chain_fingerprint,
            "proofs": normalized_proofs,
            "created_at": created_at_value,
            "bundle_fingerprint": "",
        }
        bundle_fingerprint_payload = dict(bundle)
        bundle_fingerprint_payload.pop("created_at", None)
        bundle_fingerprint_payload.pop("bundle_fingerprint", None)
        bundle_fingerprint_payload.pop("bundle_attestation", None)
        bundle["bundle_fingerprint"] = hashlib.sha256(
            _canonical_json(bundle_fingerprint_payload).encode("utf-8")
        ).hexdigest()

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_COMPOSED",
            "bundle": bundle,
            "bundle_fingerprint": bundle["bundle_fingerprint"],
            "chain_fingerprint": chain_fingerprint,
            "proof_count": len(normalized_proofs),
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle(
        cls,
        bundle,
        public_keys_by_fingerprint,
        *,
        expected_bundle_id="",
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a composed proof chain fully offline.

        ``public_keys_by_fingerprint`` maps recorded trusted-key fingerprints to
        Ed25519 public-key objects. No registry or persistent state is consulted.
        """
        if not isinstance(bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(public_keys_by_fingerprint, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "public_keys_by_fingerprint_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            schema_version = int(bundle.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 1 or bundle.get("bundle_type") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_schema_or_type_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        bundle_id = str(bundle.get("bundle_id", "") or "").strip()
        if expected_bundle_id and bundle_id != str(expected_bundle_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        proofs = bundle.get("proofs")
        chain = bundle.get("chain")
        if not isinstance(proofs, list) or not proofs:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "proofs_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(chain, list) or len(chain) != len(proofs):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "chain_length_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            proof_count = int(bundle.get("proof_count", 0) or 0)
        except (TypeError, ValueError):
            proof_count = 0
        if proof_count != len(proofs):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "proof_count_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        supplied_chain_fingerprint = str(bundle.get("chain_fingerprint", "") or "").strip().lower()
        actual_chain_fingerprint = hashlib.sha256(
            _canonical_json(chain).encode("utf-8")
        ).hexdigest()
        if supplied_chain_fingerprint != actual_chain_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "chain_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        supplied_bundle_fingerprint = str(bundle.get("bundle_fingerprint", "") or "").strip().lower()
        bundle_fingerprint_payload = dict(bundle)
        bundle_fingerprint_payload.pop("created_at", None)
        bundle_fingerprint_payload.pop("bundle_fingerprint", None)
        bundle_fingerprint_payload.pop("bundle_attestation", None)
        actual_bundle_fingerprint = hashlib.sha256(
            _canonical_json(bundle_fingerprint_payload).encode("utf-8")
        ).hexdigest()
        if supplied_bundle_fingerprint != actual_bundle_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_fingerprint_mismatch",
                "expected_fingerprint": supplied_bundle_fingerprint,
                "actual_fingerprint": actual_bundle_fingerprint,
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        seen_fingerprints = set()
        verification_results = []
        issuers = set()
        for index, (proof, chain_item) in enumerate(zip(proofs, chain), start=1):
            if not isinstance(proof, dict) or not isinstance(chain_item, dict):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_not_object",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            expected_sequence = index
            try:
                actual_sequence = int(chain_item.get("sequence", 0) or 0)
            except (TypeError, ValueError):
                actual_sequence = 0
            if actual_sequence != expected_sequence:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_sequence_invalid",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            proof_fingerprint = str(proof.get("proof_fingerprint", "") or "").strip().lower()
            chain_proof_fingerprint = str(chain_item.get("proof_fingerprint", "") or "").strip().lower()
            if not proof_fingerprint or proof_fingerprint != chain_proof_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_proof_fingerprint_mismatch",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            if proof_fingerprint in seen_fingerprints:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": "duplicate_proof_fingerprint",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            previous = "" if index == 1 else str(chain[index - 2].get("proof_fingerprint", "") or "").strip().lower()
            if str(chain_item.get("previous_proof_fingerprint", "") or "").strip().lower() != previous:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_previous_link_mismatch",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            binding = proof.get("binding")
            recorded_key_fingerprint = str((binding or {}).get("recorded_key_fingerprint", "") or "").strip().lower()
            public_key = public_keys_by_fingerprint.get(recorded_key_fingerprint)
            if public_key is None:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_public_key_missing",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            verified = cls.verify_decision_attestation_consumption_binding_proof(
                proof,
                public_key,
                verification_time=expected_verification_time,
                clock_skew_seconds=clock_skew_seconds,
                expected_key_fingerprint=recorded_key_fingerprint,
            )
            if not verified.get("success"):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_proof_invalid",
                    "verification": verified,
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }

            if str(verified.get("proof_fingerprint", "") or "").strip().lower() != proof_fingerprint:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                    "reason": f"entry_{index}_verified_proof_fingerprint_mismatch",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
            for field in ("attestation_id", "evidence_fingerprint", "binding_fingerprint"):
                expected_value = str(chain_item.get(field, "") or "").strip().lower()
                actual_value = str(verified.get(field, "") or "").strip().lower()
                if expected_value != actual_value:
                    return {
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                        "reason": f"entry_{index}_{field}_mismatch",
                        "offline": True,
                        "read_only": True,
                        "authoritative_state_mutated": False,
                    }
            issuers.add(str(verified.get("issuer", "") or "").strip().rstrip("/"))
            verification_results.append(verified)
            seen_fingerprints.add(proof_fingerprint)

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_VERIFIED",
            "bundle_id": bundle_id,
            "bundle_fingerprint": actual_bundle_fingerprint,
            "chain_fingerprint": actual_chain_fingerprint,
            "proof_count": len(proofs),
            "proof_fingerprints": [str(item.get("proof_fingerprint", "") or "").strip().lower() for item in chain],
            "issuers": sorted(value for value in issuers if value),
            "current_registry_binding": None,
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
            "verification": verification_results,
        }

    @staticmethod
    def _decision_attestation_consumption_proof_bundle_attestation_payload(
        bundle,
        *,
        issuer,
        key_id,
        key_fingerprint,
        registry_revision,
        key_set_fingerprint,
        key_source,
        key_version,
    ):
        return {
            "schema_version": 1,
            "attestation_type": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_TRUSTED_KEY_ATTESTATION",
            "bundle_id": str((bundle or {}).get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": str((bundle or {}).get("bundle_fingerprint", "") or "").strip().lower(),
            "chain_fingerprint": str((bundle or {}).get("chain_fingerprint", "") or "").strip().lower(),
            "proof_count": int((bundle or {}).get("proof_count", 0) or 0),
            "issuer": str(issuer or "").strip().rstrip("/"),
            "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_fingerprint": str(key_fingerprint or "").strip().lower(),
            "registry_revision": int(registry_revision),
            "key_set_fingerprint": str(key_set_fingerprint or "").strip().lower(),
            "key_source": str(key_source or "").strip()[:MAX_KEY_SOURCE_LENGTH],
            "key_version": str(key_version or "").strip()[:MAX_KEY_VERSION_LENGTH],
        }

    @classmethod
    def attest_decision_attestation_consumption_proof_bundle_with_trusted_key(
        cls,
        bundle,
        private_key,
        registry,
        *,
        key_id,
        issuer,
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Cryptographically attest an already-verified proof bundle with trusted-key provenance.

        The bundle fingerprint is left unchanged; the attestation is an
        externally bound field so existing bundle hashes remain stable.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_must_be_object",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not private_key or not str(key_id or "").strip() or not str(issuer or "").strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": key_id,
                "key_status": key_status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        registry_keys = {}
        for key_meta in registry.list_key_metadata():
            candidate_key_id = str(key_meta.get("key_id", "") or "").strip()
            candidate_algorithm = str(key_meta.get("algorithm", "") or "").strip()
            candidate_fp = str(key_meta.get("fingerprint", "") or "").strip().lower()
            if candidate_key_id and candidate_algorithm == IDENTITY_ATTESTATION_ALGORITHM_ED25519 and candidate_fp:
                candidate_public_key = registry.get_verification_key(candidate_key_id, candidate_algorithm)
                if candidate_public_key is not None:
                    registry_keys[candidate_fp] = candidate_public_key

        base_verification = cls.verify_decision_attestation_consumption_proof_bundle(
            bundle,
            registry_keys,
            expected_verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not base_verification.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_must_verify_before_attestation",
                "verification": base_verification,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_public_key_unavailable",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_does_not_match_trusted_key",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        payload = cls._decision_attestation_consumption_proof_bundle_attestation_payload(
            bundle,
            issuer=resolved_issuer,
            key_id=key_id,
            key_fingerprint=registry_fingerprint,
            registry_revision=metadata.get("registry_revision", 0),
            key_set_fingerprint=metadata.get("key_set_fingerprint", ""),
            key_source=metadata.get("source", ""),
            key_version=metadata.get("version", ""),
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attested_bundle = json.loads(_canonical_json(bundle))
        attested_bundle["bundle_attestation"] = {
            **payload,
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTED",
            "bundle": attested_bundle,
            "bundle_fingerprint": payload["bundle_fingerprint"],
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @staticmethod
    def _decision_attestation_consumption_proof_bundle_attestation_payload_v2(
        bundle,
        *,
        issuer,
        key_id,
        key_fingerprint,
        registry_revision,
        key_set_fingerprint,
        key_source,
        key_version,
        attestation_id,
        nonce,
        issued_at,
        expires_at,
    ):
        payload = OIDCDiscoveryJWKSSource._decision_attestation_consumption_proof_bundle_attestation_payload(
            bundle,
            issuer=issuer,
            key_id=key_id,
            key_fingerprint=key_fingerprint,
            registry_revision=registry_revision,
            key_set_fingerprint=key_set_fingerprint,
            key_source=key_source,
            key_version=key_version,
        )
        payload.update({
            "schema_version": 2,
            "attestation_id": str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH],
            "nonce": str(nonce or "").strip()[:MAX_NONCE_LENGTH],
            "issued_at": float(issued_at),
            "expires_at": float(expires_at),
        })
        return payload

    @classmethod
    def attest_decision_attestation_consumption_proof_bundle_with_trusted_key_replay_binding(
        cls,
        bundle,
        private_key,
        registry,
        *,
        key_id,
        issuer,
        nonce="",
        attestation_id="",
        issued_at=None,
        expires_at=None,
        ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS,
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Cryptographically attest a proof bundle with nonce/temporal replay binding.

        Schema v2 is additive; schema-v1 bundle attestations remain valid through
        the existing attestation APIs. No persistent state is modified.
        """
        replay = cls._normalize_decision_attestation_replay_binding(
            nonce=nonce,
            attestation_id=attestation_id,
            issued_at=issued_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": replay.get("reason"),
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_INVALID",
                "reason": "bundle_must_be_object",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        base_verification = cls.verify_decision_attestation_consumption_proof_bundle(
            bundle,
            {
                str(meta.get("fingerprint", "") or "").strip().lower(): registry.get_verification_key(
                    str(meta.get("key_id", "") or "").strip(),
                    IDENTITY_ATTESTATION_ALGORITHM_ED25519,
                )
                for meta in registry.list_key_metadata()
                if str(meta.get("algorithm", "") or "").strip() == IDENTITY_ATTESTATION_ALGORITHM_ED25519
                and str(meta.get("fingerprint", "") or "").strip()
                and registry.get_verification_key(
                    str(meta.get("key_id", "") or "").strip(),
                    IDENTITY_ATTESTATION_ALGORITHM_ED25519,
                ) is not None
            },
            expected_verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not base_verification.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_must_verify_before_attestation",
                "verification": base_verification,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        resolved_issuer = str(issuer or "").strip().rstrip("/")
        if not private_key or not key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": key_id,
                "key_status": key_status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_public_key_unavailable",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not private_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "private_key_does_not_match_trusted_key",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        payload = cls._decision_attestation_consumption_proof_bundle_attestation_payload_v2(
            bundle,
            issuer=resolved_issuer,
            key_id=key_id,
            key_fingerprint=registry_fingerprint,
            registry_revision=metadata.get("registry_revision", 0),
            key_set_fingerprint=metadata.get("key_set_fingerprint", ""),
            key_source=metadata.get("source", ""),
            key_version=metadata.get("version", ""),
            attestation_id=replay["attestation_id"],
            nonce=replay["nonce"],
            issued_at=replay["issued_at"],
            expires_at=replay["expires_at"],
        )
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attested_bundle = json.loads(_canonical_json(bundle))
        attested_bundle["bundle_attestation"] = {
            **payload,
            "signature": _b64url_encode(signature),
            "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTED_WITH_REPLAY_BINDING",
            "bundle": attested_bundle,
            "bundle_fingerprint": payload["bundle_fingerprint"],
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }


    @classmethod
    def attest_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_with_trusted_key_replay_binding(
        cls,
        proof,
        private_key,
        registry,
        *,
        key_id,
        issuer,
        nonce="",
        attestation_id="",
        issued_at=None,
        expires_at=None,
        ttl_seconds=AUDIT_DECISION_ATTESTATION_DEFAULT_TTL_SECONDS,
        expected_bundle_id="",
        expected_source_issuer="",
        expected_source_key_id="",
        expected_source_nonce="",
        expected_source_attestation_id="",
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Attest the terminal consumption-binding proof with trusted-key replay binding.

        This signs the already self-contained terminal proof. It does not create
        or mutate authoritative state; the proof remains the source of truth for
        the underlying one-time consumption event.
        """
        replay = cls._normalize_decision_attestation_replay_binding(
            nonce=nonce,
            attestation_id=attestation_id,
            issued_at=issued_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": replay.get("reason"),
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(proof, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "proof_must_be_object",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        resolved_issuer = str(issuer or "").strip().rstrip("/")
        normalized_key_id = str(key_id or "").strip()[:MAX_KEY_ID_LENGTH]
        if not private_key or not normalized_key_id or not resolved_issuer:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "private_key_key_id_and_issuer_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        discovered = registry.discover_key(normalized_key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": normalized_key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": normalized_key_id,
                "key_status": key_status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "key_id": normalized_key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            private_fingerprint = _public_key_fingerprint(private_key.public_key())
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "private_key_public_key_unavailable",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        registry_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not registry_fingerprint or private_fingerprint.lower() != registry_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "private_key_does_not_match_trusted_key",
                "key_id": normalized_key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        proof_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
            proof,
            {registry_fingerprint: public_key},
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_source_issuer,
            expected_key_id=expected_source_key_id,
            expected_nonce=expected_source_nonce,
            expected_attestation_id=expected_source_attestation_id,
            verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if proof_verification.get("success"):
            terminal_binding = proof.get("binding") if isinstance(proof, dict) else None
            if not isinstance(terminal_binding, dict):
                proof_verification = {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                    "reason": "binding_not_object",
                }
            else:
                recorded_provenance = {
                    "registry_revision": terminal_binding.get("recorded_registry_revision"),
                    "key_set_fingerprint": str(terminal_binding.get("recorded_key_set_fingerprint", "") or "").strip().lower(),
                    "key_source": str(terminal_binding.get("trusted_key_source", "") or "").strip(),
                    "key_version": str(terminal_binding.get("trusted_key_version", "") or "").strip(),
                }
                current_provenance = {
                    "registry_revision": metadata.get("registry_revision"),
                    "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
                    "key_source": str(metadata.get("source", "") or "").strip(),
                    "key_version": str(metadata.get("version", "") or "").strip(),
                }
                if str(terminal_binding.get("key_fingerprint", "") or "").strip().lower() != registry_fingerprint:
                    proof_verification = {
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                        "reason": "terminal_key_fingerprint_mismatch",
                    }
                elif recorded_provenance != current_provenance:
                    proof_verification = {
                        "success": False,
                        "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_INVALID",
                        "reason": "registry_provenance_mismatch",
                    }
        if not proof_verification.get("success"):
            return {
                **proof_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        payload = {
            "schema_version": 2,
            "attestation_type": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_TRUSTED_KEY_ATTESTATION",
            "issuer": resolved_issuer,
            "key_id": normalized_key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": metadata.get("registry_revision", 0),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
            "proof_type": str(proof.get("proof_type", "") or ""),
            "terminal_proof_fingerprint": str(proof_verification.get("proof_fingerprint", "") or "").strip().lower(),
            "terminal_binding_fingerprint": str(proof_verification.get("binding_fingerprint", "") or "").strip().lower(),
            "source_proof_fingerprint": str(proof_verification.get("source_proof_fingerprint", "") or "").strip().lower(),
            "source_binding_fingerprint": str(proof_verification.get("source_binding_fingerprint", "") or "").strip().lower(),
            "bundle_id": str(proof_verification.get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": str(proof_verification.get("bundle_fingerprint", "") or "").strip().lower(),
            "chain_fingerprint": str(proof_verification.get("chain_fingerprint", "") or "").strip().lower(),
            "proof_count": int(proof_verification.get("proof_count", 0) or 0),
            "source_attestation_id": str(proof_verification.get("attestation_id", "") or "").strip(),
            "source_nonce": str(proof_verification.get("nonce", "") or ""),
            "consumption_attestation_id": str(proof_verification.get("consumption_attestation_id", "") or "").strip(),
            "consumption_nonce": str(proof_verification.get("consumption_nonce", "") or ""),
            "consumed_at": proof_verification.get("consumed_at"),
            "consumption_audit_sequence": proof_verification.get("consumption_audit_sequence"),
            "consumption_audit_previous_hash": str(proof_verification.get("consumption_audit_previous_hash", "") or "").strip().lower(),
            "consumption_audit_record_hash": str(proof_verification.get("consumption_audit_record_hash", "") or "").strip().lower(),
            "nonce": replay["nonce"],
            "attestation_id": replay["attestation_id"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
        }
        try:
            signature = private_key.sign(_canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "signing_failed",
                "error": str(exc)[:300],
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        attested = {
            "terminal_proof": json.loads(_canonical_json(proof)),
            "terminal_proof_attestation": {
                **payload,
                "signature": _b64url_encode(signature),
                "signature_fingerprint": hashlib.sha256(signature).hexdigest(),
            },
        }
        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTED",
            "attestation": attested,
            "proof_fingerprint": payload["terminal_proof_fingerprint"],
            "binding_fingerprint": payload["terminal_binding_fingerprint"],
            "key_status": key_status,
            "key_fingerprint": registry_fingerprint,
            "registry_revision": payload["registry_revision"],
            "key_set_fingerprint": payload["key_set_fingerprint"],
            "trusted_key_source": payload["key_source"],
            "trusted_key_version": payload["key_version"],
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_offline(
        cls,
        attestation,
        public_keys_by_fingerprint,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_source_key_id="",
        expected_source_nonce="",
        expected_source_attestation_id="",
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify the terminal consumption-binding attestation fully offline."""
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "attestation_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(public_keys_by_fingerprint, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "public_keys_by_fingerprint_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        required = {"terminal_proof", "terminal_proof_attestation"}
        if not required.issubset(attestation):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "attestation_structure_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        terminal_proof = attestation.get("terminal_proof")
        terminal_attestation = attestation.get("terminal_proof_attestation")
        if not isinstance(terminal_proof, dict) or not isinstance(terminal_attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "attestation_structure_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        schema_version = int(terminal_attestation.get("schema_version", 0) or 0)
        if schema_version != 2:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_schema",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if terminal_attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_TRUSTED_KEY_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "attestation_type_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if terminal_attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        key_fingerprint = str(terminal_attestation.get("key_fingerprint", "") or "").strip().lower()
        public_key = public_keys_by_fingerprint.get(key_fingerprint)
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "attestation_public_key_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        replay = cls._verify_decision_attestation_replay_binding(
            terminal_attestation,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not replay.get("success"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": replay.get("reason", "replay_binding_invalid"),
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        terminal_verification = cls.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_offline(
            terminal_proof,
            public_keys_by_fingerprint,
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_source_key_id,
            expected_nonce=expected_source_nonce,
            expected_attestation_id=expected_source_attestation_id,
            verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not terminal_verification.get("success"):
            return {
                **terminal_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "terminal_proof_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        expected_proof_fingerprint = str(terminal_attestation.get("terminal_proof_fingerprint", "") or "").strip().lower()
        if expected_proof_fingerprint != str(terminal_verification.get("proof_fingerprint", "") or "").strip().lower():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "terminal_proof_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        payload = dict(terminal_attestation)
        signature_b64 = payload.pop("signature", "")
        signature_fingerprint = str(payload.pop("signature_fingerprint", "") or "").strip().lower()
        actual_proof_fp = str(terminal_verification.get("proof_fingerprint", "") or "").strip().lower()
        actual_binding_fp = str(terminal_verification.get("binding_fingerprint", "") or "").strip().lower()
        checks = {
            "terminal_binding_fingerprint": actual_binding_fp,
            "source_proof_fingerprint": str(terminal_verification.get("source_proof_fingerprint", "") or "").strip().lower(),
            "source_binding_fingerprint": str(terminal_verification.get("source_binding_fingerprint", "") or "").strip().lower(),
            "bundle_id": str(terminal_verification.get("bundle_id", "") or "").strip(),
            "bundle_fingerprint": str(terminal_verification.get("bundle_fingerprint", "") or "").strip().lower(),
            "chain_fingerprint": str(terminal_verification.get("chain_fingerprint", "") or "").strip().lower(),
            "proof_count": int(terminal_verification.get("proof_count", 0) or 0),
            "source_attestation_id": str(terminal_verification.get("attestation_id", "") or "").strip(),
            "source_nonce": str(terminal_verification.get("nonce", "") or ""),
            "consumption_attestation_id": str(terminal_verification.get("consumption_attestation_id", "") or "").strip(),
            "consumption_nonce": str(terminal_verification.get("consumption_nonce", "") or ""),
            "consumed_at": terminal_verification.get("consumed_at"),
            "consumption_audit_sequence": terminal_verification.get("consumption_audit_sequence"),
            "consumption_audit_previous_hash": str(terminal_verification.get("consumption_audit_previous_hash", "") or "").strip().lower(),
            "consumption_audit_record_hash": str(terminal_verification.get("consumption_audit_record_hash", "") or "").strip().lower(),
        }
        for field, expected_value in checks.items():
            if terminal_attestation.get(field) != expected_value:
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                    "reason": f"{field}_mismatch",
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
        if terminal_attestation.get("issuer", "").strip().rstrip("/") != str(expected_issuer or terminal_attestation.get("issuer", "")).strip().rstrip("/"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "issuer_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if expected_key_id and str(terminal_attestation.get("key_id", "") or "").strip() != str(expected_key_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "key_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        try:
            signature = _b64url_decode(signature_b64)
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if signature_fingerprint and signature_fingerprint != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_OFFLINE_VERIFIED",
            "issuer": terminal_attestation.get("issuer", ""),
            "key_id": terminal_attestation.get("key_id", ""),
            "key_fingerprint": key_fingerprint,
            "proof_fingerprint": actual_proof_fp,
            "binding_fingerprint": actual_binding_fp,
            "signature_fingerprint": actual_signature_fp,
            "attestation_id": replay["attestation_id"],
            "nonce": replay["nonce"],
            "issued_at": replay["issued_at"],
            "expires_at": replay["expires_at"],
            "terminal_proof": terminal_verification,
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_with_registry(
        cls,
        attestation,
        registry,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_source_key_id="",
        expected_source_nonce="",
        expected_source_attestation_id="",
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify terminal proof attestation and current trusted-key provenance."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        wrapper = attestation if isinstance(attestation, dict) else {}
        terminal_attestation = wrapper.get("terminal_proof_attestation") if isinstance(wrapper, dict) else None
        if not isinstance(terminal_attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "terminal_proof_attestation_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        key_id = str(terminal_attestation.get("key_id", "") or "").strip()
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if public_key is None or not fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        verified = cls.verify_decision_attestation_consumption_proof_bundle_attestation_consumption_binding_proof_consumption_binding_attestation_offline(
            wrapper,
            {fingerprint: public_key},
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_source_key_id=expected_source_key_id,
            expected_source_nonce=expected_source_nonce,
            expected_source_attestation_id=expected_source_attestation_id,
            expected_verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not verified.get("success"):
            return verified
        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_status": key_status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        recorded = {
            "key_fingerprint": str(terminal_attestation.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": terminal_attestation.get("registry_revision"),
            "key_set_fingerprint": str(terminal_attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(terminal_attestation.get("key_source", "") or "").strip(),
            "key_version": str(terminal_attestation.get("key_version", "") or "").strip(),
        }
        current = {
            "key_fingerprint": fingerprint,
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
        }
        if recorded != current:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_BINDING_PROOF_CONSUMPTION_BINDING_ATTESTATION_INVALID",
                "reason": "registry_provenance_mismatch",
                "recorded_provenance": recorded,
                "current_registry_provenance": current,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        return {
            **verified,
            "key_status": key_status,
            "current_registry_binding": True,
            "offline": False,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_offline(
        cls,
        bundle,
        public_keys_by_fingerprint,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a proof-bundle trusted-key attestation without registry access."""
        if not isinstance(bundle, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if not isinstance(public_keys_by_fingerprint, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "public_keys_by_fingerprint_must_be_object",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        base_verification = cls.verify_decision_attestation_consumption_proof_bundle(
            bundle,
            public_keys_by_fingerprint,
            expected_bundle_id=expected_bundle_id,
            expected_verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not base_verification.get("success"):
            return {
                **base_verification,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "embedded_bundle_invalid",
            }

        attestation = bundle.get("bundle_attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_attestation_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            schema_version = int(attestation.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version not in {1, 2}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_attestation_schema_unsupported",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if attestation.get("attestation_type") != "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_TRUSTED_KEY_ATTESTATION":
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_attestation_type_invalid",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(attestation.get("key_id", "") or "").strip()
        key_fingerprint = str(attestation.get("key_fingerprint", "") or "").strip().lower()
        if not issuer or not key_id or not key_fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_attestation_provenance_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "issuer_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "key_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        replay = {"success": True, "nonce": "", "attestation_id": "", "issued_at": None, "expires_at": None}
        if schema_version == 2:
            replay = cls._verify_decision_attestation_replay_binding(
                attestation,
                expected_nonce=str(expected_nonce or "").strip(),
                expected_attestation_id=str(expected_attestation_id or "").strip(),
                verification_time=expected_verification_time,
                clock_skew_seconds=clock_skew_seconds,
            )
            if not replay.get("success"):
                return {
                    "success": False,
                    "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                    "reason": replay.get("reason"),
                    "offline": True,
                    "read_only": True,
                    "authoritative_state_mutated": False,
                }
        elif expected_nonce or expected_attestation_id:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "replay_binding_required",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        public_key = public_keys_by_fingerprint.get(key_fingerprint)
        if public_key is None:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "attestation_public_key_missing",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        declared_bundle_id = str(attestation.get("bundle_id", "") or "").strip()
        declared_bundle_fingerprint = str(attestation.get("bundle_fingerprint", "") or "").strip().lower()
        declared_chain_fingerprint = str(attestation.get("chain_fingerprint", "") or "").strip().lower()
        try:
            declared_proof_count = int(attestation.get("proof_count", 0) or 0)
        except (TypeError, ValueError):
            declared_proof_count = 0
        if declared_bundle_id != base_verification["bundle_id"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_id_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if declared_bundle_fingerprint != base_verification["bundle_fingerprint"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if declared_chain_fingerprint != base_verification["chain_fingerprint"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "chain_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if declared_proof_count != base_verification["proof_count"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "proof_count_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        if schema_version == 2:
            payload = cls._decision_attestation_consumption_proof_bundle_attestation_payload_v2(
                bundle,
                issuer=issuer,
                key_id=key_id,
                key_fingerprint=attestation.get("key_fingerprint", ""),
                registry_revision=attestation.get("registry_revision", 0),
                key_set_fingerprint=attestation.get("key_set_fingerprint", ""),
                key_source=attestation.get("key_source", ""),
                key_version=attestation.get("key_version", ""),
                attestation_id=attestation.get("attestation_id", ""),
                nonce=attestation.get("nonce", ""),
                issued_at=attestation.get("issued_at"),
                expires_at=attestation.get("expires_at"),
            )
        else:
            payload = cls._decision_attestation_consumption_proof_bundle_attestation_payload(
                bundle,
                issuer=issuer,
                key_id=key_id,
                key_fingerprint=attestation.get("key_fingerprint", ""),
                registry_revision=attestation.get("registry_revision", 0),
                key_set_fingerprint=attestation.get("key_set_fingerprint", ""),
                key_source=attestation.get("key_source", ""),
                key_version=attestation.get("key_version", ""),
            )
        if payload["bundle_fingerprint"] != base_verification["bundle_fingerprint"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "signature_verification_failed",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        expected_signature_fp = str(attestation.get("signature_fingerprint", "") or "").strip().lower()
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "signature_fingerprint_mismatch",
                "offline": True,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        return {
            "success": True,
            "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_TRUSTED_KEY_ATTESTATION_VERIFIED",
            "bundle_id": base_verification["bundle_id"],
            "bundle_fingerprint": base_verification["bundle_fingerprint"],
            "chain_fingerprint": base_verification["chain_fingerprint"],
            "proof_count": base_verification["proof_count"],
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": attestation["algorithm"],
            "key_fingerprint": key_fingerprint,
            "recorded_registry_revision": attestation.get("registry_revision"),
            "recorded_key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "trusted_key_source": str(attestation.get("key_source", "") or "").strip(),
            "trusted_key_version": str(attestation.get("key_version", "") or "").strip(),
            "signature_fingerprint": actual_signature_fp,
            "replay_binding": bool(schema_version == 2),
            "attestation_id": replay.get("attestation_id", "") if schema_version == 2 else "",
            "nonce": replay.get("nonce", "") if schema_version == 2 else "",
            "issued_at": replay.get("issued_at") if schema_version == 2 else None,
            "expires_at": replay.get("expires_at") if schema_version == 2 else None,
            "current_registry_binding": None,
            "offline": True,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
        cls,
        bundle,
        registry,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        require_current_registry_binding=True,
        expected_verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
    ):
        """Verify a proof-bundle attestation and optionally enforce current registry provenance."""
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        attestation = bundle.get("bundle_attestation") if isinstance(bundle, dict) else None
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "bundle_attestation_missing",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        key_id = str(attestation.get("key_id", "") or "").strip()
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        if not public_key or not fingerprint:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_missing_public_key",
                "key_id": key_id,
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        verified = cls.verify_decision_attestation_consumption_proof_bundle_attestation_offline(
            bundle,
            {fingerprint: public_key},
            expected_bundle_id=expected_bundle_id,
            expected_issuer=expected_issuer,
            expected_key_id=expected_key_id,
            expected_nonce=expected_nonce,
            expected_attestation_id=expected_attestation_id,
            expected_verification_time=expected_verification_time,
            clock_skew_seconds=clock_skew_seconds,
        )
        if not verified.get("success"):
            return verified

        key_status = normalize_attestation_key_status(metadata.get("status"))
        if key_status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "trusted_key_status_not_allowed",
                "key_id": key_id,
                "key_status": key_status,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        recorded = {
            "key_fingerprint": str(attestation.get("key_fingerprint", "") or "").strip().lower(),
            "registry_revision": attestation.get("registry_revision"),
            "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(attestation.get("key_source", "") or "").strip(),
            "key_version": str(attestation.get("key_version", "") or "").strip(),
        }
        current = {
            "key_fingerprint": fingerprint,
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(),
            "key_source": str(metadata.get("source", "") or "").strip(),
            "key_version": str(metadata.get("version", "") or "").strip(),
        }
        if recorded["key_fingerprint"] != current["key_fingerprint"]:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "key_fingerprint_provenance_mismatch",
                "read_only": True,
                "authoritative_state_mutated": False,
            }
        if require_current_registry_binding and recorded != current:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_PROOF_BUNDLE_ATTESTATION_INVALID",
                "reason": "registry_provenance_mismatch",
                "recorded_provenance": recorded,
                "current_registry_provenance": current,
                "read_only": True,
                "authoritative_state_mutated": False,
            }

        return {
            **verified,
            "key_status": key_status,
            "current_registry_binding": bool(recorded == current),
            "offline": False,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    def consume_decision_attestation_consumption_audit_evidence_attestation(
        self,
        attested_evidence,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
    ):
        """Verify and consume a replay-bound consumption-audit evidence attestation exactly once.

        This reuses the existing trusted registry consumption ledger and the
        existing persistent trust-state transaction boundary. No new storage is
        introduced. A failed durable commit never reports a successful claim.
        """
        attestation = attested_evidence.get("attestation") if isinstance(attested_evidence, dict) else None
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "attestation_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        try:
            schema_version = int(attestation.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 2:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "one_time_consumption_requires_schema_v2",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        attestation_id = str(attestation.get("attestation_id", "") or "").strip()
        nonce = str(attestation.get("nonce", "") or "").strip()
        if not attestation_id or not nonce:
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "replay_binding_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }
        if expected_attestation_id and attestation_id != str(expected_attestation_id).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "attestation_id_mismatch",
                "read_only": False,
                "authoritative_state_mutated": False,
            }
        if expected_nonce and nonce != str(expected_nonce).strip():
            return {
                "success": False,
                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "nonce_mismatch",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        def _consume_current_state():
            verification = self.__class__.verify_decision_attestation_consumption_audit_evidence_attestation_with_trusted_key_replay_binding(
                attested_evidence,
                self.registry,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_key_statuses=expected_key_statuses,
                expected_key_fingerprint=expected_key_fingerprint,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
                require_current_registry_binding=require_current_registry_binding,
            )
            if not verification.get("success"):
                return {**verification, "read_only": False, "authoritative_state_mutated": False}

            evidence_fingerprint = str(verification.get("evidence_fingerprint", "") or "").strip().lower()
            event_time = time.time() if verification_time is None else verification_time
            with self.registry._consumption_lock:
                existing = self.registry.get_consumed_decision_attestation(attestation_id)
                if existing is not None:
                    audit = self.registry._append_decision_attestation_consumption_audit(
                        event_type="CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAY_REJECTED",
                        attestation_id=attestation_id,
                        decision_fingerprint=evidence_fingerprint,
                        nonce=nonce,
                        consumed_at=event_time,
                        reason="consumption_audit_evidence_attestation_already_consumed",
                        previous_consumed_record=existing,
                    )
                    if not audit.get("success"):
                        return {
                            **audit,
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    if self.state_path:
                        try:
                            self._persist_state()
                        except Exception as exc:
                            self._load_persisted_state_unlocked()
                            return {
                                "success": False,
                                "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_FAILED",
                                "reason": "replay_audit_persistence_failed",
                                "error": str(exc)[:300],
                                "read_only": False,
                                "authoritative_state_mutated": False,
                            }
                    return {
                        "success": False,
                        "status": "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_REPLAYED",
                        "reason": "attestation_already_consumed",
                        "attestation_id": attestation_id,
                        "evidence_fingerprint": evidence_fingerprint,
                        "consumed_record": existing,
                        "audit_record": audit.get("record"),
                        "read_only": False,
                        "authoritative_state_mutated": True,
                    }

                claim = self.registry.consume_decision_attestation(
                    attestation_id,
                    evidence_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                )
                if not claim.get("success"):
                    return {**claim, "read_only": False, "authoritative_state_mutated": False}

                audit = self.registry._append_decision_attestation_consumption_audit(
                    event_type="CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
                    attestation_id=attestation_id,
                    decision_fingerprint=evidence_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                    reason="one_time_consumption",
                )
                if not audit.get("success"):
                    self.registry._consumed_decision_attestations.pop(attestation_id, None)
                    return {
                        **audit,
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                if self.state_path:
                    try:
                        self._persist_state()
                    except OIDCTrustStateConflictError:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONFLICT",
                            "reason": "durable_consumption_commit_conflict",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    except Exception as exc:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_FAILED",
                            "reason": "durable_consumption_commit_failed",
                            "error": str(exc)[:300],
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }

                return {
                    **verification,
                    "status": "CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMED",
                    "consumption": claim,
                    "audit_record": audit.get("record"),
                    "read_only": False,
                    "authoritative_state_mutated": True,
                }

        if self.state_path:
            from memory_storage import interprocess_lock
            with self._refresh_lock:
                with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                    latest = self._load_persisted_state_unlocked()
                    if not latest.get("loaded"):
                        return {
                            "success": False,
                            "status": "DECISION_ATTESTATION_CONSUMPTION_AUDIT_EVIDENCE_ATTESTATION_CONSUMPTION_INVALID",
                            "reason": "authoritative_trust_state_unavailable",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    return _consume_current_state()

        with self._refresh_lock:
            return _consume_current_state()


    def consume_decision_attestation_consumption_proof_bundle_attestation(
        self,
        attested_bundle,
        *,
        expected_bundle_id="",
        expected_issuer="",
        expected_key_id="",
        expected_nonce="",
        expected_attestation_id="",
        verification_time=None,
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        require_current_registry_binding=True,
    ):
        """Verify and consume a replay-bound proof-bundle attestation exactly once.

        The existing trusted-registry consumption ledger, immutable consumption
        audit chain, persistent trust-state file, and inter-process lock are
        reused. No new storage is introduced. Only schema-v2 bundle attestations
        participate in one-time consumption so schema-v1 remains verification-only
        and backward compatible.
        """
        bundle_attestation = attested_bundle.get("bundle_attestation") if isinstance(attested_bundle, dict) else None
        if not isinstance(bundle_attestation, dict):
            return {
                "success": False,
                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "bundle_attestation_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        try:
            schema_version = int(bundle_attestation.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version != 2:
            return {
                "success": False,
                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "one_time_consumption_requires_schema_v2",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        attestation_id = str(bundle_attestation.get("attestation_id", "") or "").strip()
        nonce = str(bundle_attestation.get("nonce", "") or "").strip()
        if not attestation_id or not nonce:
            return {
                "success": False,
                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "replay_binding_missing",
                "read_only": False,
                "authoritative_state_mutated": False,
            }
        if expected_attestation_id and attestation_id != str(expected_attestation_id).strip():
            return {
                "success": False,
                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "attestation_id_mismatch",
                "read_only": False,
                "authoritative_state_mutated": False,
            }
        if expected_nonce and nonce != str(expected_nonce).strip():
            return {
                "success": False,
                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                "reason": "nonce_mismatch",
                "read_only": False,
                "authoritative_state_mutated": False,
            }

        def _consume_current_state():
            verification = self.__class__.verify_decision_attestation_consumption_proof_bundle_attestation_with_registry(
                attested_bundle,
                self.registry,
                expected_bundle_id=expected_bundle_id,
                expected_issuer=expected_issuer,
                expected_key_id=expected_key_id,
                expected_nonce=expected_nonce,
                expected_attestation_id=expected_attestation_id,
                require_current_registry_binding=require_current_registry_binding,
                expected_verification_time=verification_time,
                clock_skew_seconds=clock_skew_seconds,
            )
            if not verification.get("success"):
                return {
                    **verification,
                    "read_only": False,
                    "authoritative_state_mutated": False,
                }

            bundle_fingerprint = str(verification.get("bundle_fingerprint", "") or "").strip().lower()
            event_time = time.time() if verification_time is None else verification_time
            with self.registry._consumption_lock:
                existing = self.registry.get_consumed_decision_attestation(attestation_id)
                if existing is not None:
                    audit = self.registry._append_decision_attestation_consumption_audit(
                        event_type="CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAY_REJECTED",
                        attestation_id=attestation_id,
                        decision_fingerprint=bundle_fingerprint,
                        nonce=nonce,
                        consumed_at=event_time,
                        reason="proof_bundle_attestation_already_consumed",
                        previous_consumed_record=existing,
                    )
                    if not audit.get("success"):
                        return {
                            **audit,
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    if self.state_path:
                        try:
                            self._persist_state()
                        except Exception as exc:
                            self._load_persisted_state_unlocked()
                            return {
                                "success": False,
                                "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_FAILED",
                                "reason": "replay_audit_persistence_failed",
                                "error": str(exc)[:300],
                                "read_only": False,
                                "authoritative_state_mutated": False,
                            }
                    return {
                        "success": False,
                        "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_REPLAYED",
                        "reason": "attestation_already_consumed",
                        "attestation_id": attestation_id,
                        "bundle_id": verification.get("bundle_id", ""),
                        "bundle_fingerprint": bundle_fingerprint,
                        "consumed_record": existing,
                        "audit_record": audit.get("record"),
                        "read_only": False,
                        "authoritative_state_mutated": True,
                    }

                claim = self.registry.consume_decision_attestation(
                    attestation_id,
                    bundle_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                )
                if not claim.get("success"):
                    return {
                        **claim,
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                audit = self.registry._append_decision_attestation_consumption_audit(
                    event_type="CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED",
                    attestation_id=attestation_id,
                    decision_fingerprint=bundle_fingerprint,
                    nonce=nonce,
                    consumed_at=event_time,
                    reason="one_time_consumption",
                )
                if not audit.get("success"):
                    self.registry._consumed_decision_attestations.pop(attestation_id, None)
                    return {
                        **audit,
                        "read_only": False,
                        "authoritative_state_mutated": False,
                    }

                if self.state_path:
                    try:
                        self._persist_state()
                    except OIDCTrustStateConflictError:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONFLICT",
                            "reason": "durable_consumption_commit_conflict",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    except Exception as exc:
                        self._load_persisted_state_unlocked()
                        return {
                            "success": False,
                            "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_FAILED",
                            "reason": "durable_consumption_commit_failed",
                            "error": str(exc)[:300],
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }

                return {
                    **verification,
                    "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMED",
                    "consumption": claim,
                    "audit_record": audit.get("record"),
                    "read_only": False,
                    "authoritative_state_mutated": True,
                }

        if self.state_path:
            from memory_storage import interprocess_lock
            with self._refresh_lock:
                with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                    latest = self._load_persisted_state_unlocked()
                    if not latest.get("loaded"):
                        return {
                            "success": False,
                            "status": "CONSUMPTION_PROOF_BUNDLE_ATTESTATION_CONSUMPTION_INVALID",
                            "reason": "authoritative_trust_state_unavailable",
                            "read_only": False,
                            "authoritative_state_mutated": False,
                        }
                    return _consume_current_state()

        with self._refresh_lock:
            return _consume_current_state()


    @classmethod
    def verify_trust_state_audit_evidence_verification_decision_attestation(cls, attested_decision, registry, *, expected_issuer="", expected_key_id="", expected_nonce="", expected_attestation_id="", verification_time=None, clock_skew_seconds=60, require_current_registry_binding=True):
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_registry_required"}
        if not isinstance(attested_decision, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "decision_must_be_object"}
        attestation = attested_decision.get("decision_attestation")
        if not isinstance(attestation, dict) or attestation.get("attestation_type") != "OIDC_TRUST_STATE_AUDIT_EVIDENCE_DECISION_ATTESTATION":
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "decision_attestation_type_required"}
        schema_version = int(attestation.get("schema_version", 0) or 0)
        if schema_version not in {1, 2} or attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "unsupported_decision_attestation_schema"}
        if schema_version == 2:
            nonce = str(attestation.get("nonce", "") or "").strip()
            attestation_id = str(attestation.get("attestation_id", "") or "").strip()
            if not nonce or not attestation_id:
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "replay_binding_missing"}
            if expected_nonce and nonce != str(expected_nonce).strip():
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "nonce_mismatch"}
            if expected_attestation_id and attestation_id != str(expected_attestation_id).strip():
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "attestation_id_mismatch"}
            try:
                issued_at = float(attestation.get("issued_at"))
                expires_at = float(attestation.get("expires_at"))
                current_time = time.time() if verification_time is None else float(verification_time)
                skew = max(0.0, float(clock_skew_seconds))
            except (TypeError, ValueError):
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_temporal_binding"}
            if expires_at <= issued_at or expires_at - issued_at > AUDIT_DECISION_ATTESTATION_MAX_TTL_SECONDS:
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "invalid_temporal_window"}
            if issued_at > current_time + skew:
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "attestation_not_yet_valid"}
            if expires_at < current_time - skew:
                return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "attestation_expired"}
        key_id = str(attestation.get("key_id", "") or "").strip()
        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        if not key_id:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "key_id_missing"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "key_id_mismatch"}
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "issuer_mismatch"}
        recomputed = cls._recompute_audit_evidence_decision_fingerprint(attested_decision)
        if not recomputed or recomputed != str(attestation.get("decision_fingerprint", "") or "").strip().lower() or recomputed != str(attested_decision.get("decision_fingerprint", "") or "").strip().lower():
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "decision_fingerprint_mismatch"}
        discovered = registry.discover_key(key_id, IDENTITY_ATTESTATION_ALGORITHM_ED25519)
        if not isinstance(discovered, dict):
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_not_found"}
        metadata = discovered.get("metadata") or {}
        public_key = discovered.get("public_key")
        status = normalize_attestation_key_status(metadata.get("status"))
        if status not in {IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE}:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_status_not_allowed", "key_status": status}
        if public_key is None:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "trusted_key_missing_public_key"}
        actual = {"key_fingerprint": str(attestation.get("key_fingerprint", "") or "").strip().lower(), "registry_revision": attestation.get("registry_revision"), "key_set_fingerprint": str(attestation.get("key_set_fingerprint", "") or "").strip().lower(), "key_source": str(attestation.get("key_source", "") or "").strip(), "key_version": str(attestation.get("key_version", "") or "").strip()}
        expected = {"key_fingerprint": str(metadata.get("fingerprint", "") or "").strip().lower(), "registry_revision": metadata.get("registry_revision"), "key_set_fingerprint": str(metadata.get("key_set_fingerprint", "") or "").strip().lower(), "key_source": str(metadata.get("source", "") or "").strip(), "key_version": str(metadata.get("version", "") or "").strip()}
        if actual["key_fingerprint"] != expected["key_fingerprint"]:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "key_fingerprint_provenance_mismatch"}
        if require_current_registry_binding and actual != expected:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "registry_provenance_mismatch", "recorded_provenance": actual, "current_registry_provenance": expected}
        if schema_version == 2:
            payload = cls._audit_evidence_decision_attestation_payload_v2(attested_decision, issuer=issuer, key_id=key_id, key_fingerprint=actual["key_fingerprint"], registry_revision=actual["registry_revision"], key_set_fingerprint=actual["key_set_fingerprint"], key_source=actual["key_source"], key_version=actual["key_version"], attestation_id=str(attestation.get("attestation_id", "") or ""), nonce=str(attestation.get("nonce", "") or ""), issued_at=float(attestation.get("issued_at")), expires_at=float(attestation.get("expires_at")))
        else:
            payload = cls._audit_evidence_decision_attestation_payload(attested_decision, issuer=issuer, key_id=key_id, key_fingerprint=actual["key_fingerprint"], registry_revision=actual["registry_revision"], key_set_fingerprint=actual["key_set_fingerprint"], key_source=actual["key_source"], key_version=actual["key_version"])
        try:
            signature = _b64url_decode(str(attestation.get("signature", "") or ""))
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception as exc:
            return {"success": False, "status": "DECISION_ATTESTATION_INVALID", "reason": "signature_verification_failed", "error": str(exc)[:300]}
        return {"success": True, "status": "AUDIT_EVIDENCE_DECISION_ATTESTATION_VERIFIED", "decision": str(attested_decision.get("decision", "") or ""), "decision_fingerprint": recomputed, "evidence_fingerprint": str(attested_decision.get("evidence_fingerprint", "") or ""), "policy_id": str(((attested_decision.get("policy") or {}).get("policy_id", "")) or ""), "key_id": key_id, "key_status": status, "recorded_registry_revision": actual["registry_revision"], "current_registry_revision": expected["registry_revision"], "recorded_key_set_fingerprint": actual["key_set_fingerprint"], "current_key_set_fingerprint": expected["key_set_fingerprint"], "trusted_key_source": actual["key_source"], "trusted_key_version": actual["key_version"], "current_registry_binding": bool(actual == expected), "replay_binding": bool(schema_version == 2), "attestation_id": str(attestation.get("attestation_id", "") or "") if schema_version == 2 else "", "nonce": str(attestation.get("nonce", "") or "") if schema_version == 2 else "", "issued_at": float(attestation.get("issued_at")) if schema_version == 2 else None, "expires_at": float(attestation.get("expires_at")) if schema_version == 2 else None, "read_only": True, "authoritative_state_mutated": False}

    @classmethod
    def verify_trust_state_audit_evidence_attestation_with_registry(
        cls,
        attested_evidence,
        registry,
        *,
        expected_issuer="",
        expected_key_id="",
        expected_key_statuses=None,
        expected_key_fingerprint="",
    ):
        """Verify an audit-evidence attestation through the trusted key registry.

        The registry is the trust boundary: the attestation key must exist in
        the registry and its lifecycle status must be explicitly allowed.
        ACTIVE and GRACE are allowed by default; RETIRED, REVOKED and UNKNOWN
        are rejected fail-closed. No network discovery or state mutation occurs.
        """
        if not isinstance(registry, TrustedAttestationKeyRegistry):
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "trusted_key_registry_required",
            }
        if not isinstance(attested_evidence, dict):
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "evidence_must_be_object",
            }

        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "attestation_missing",
            }

        key_id = str(attestation.get("key_id", "") or "").strip()
        algorithm = str(attestation.get("algorithm", "") or "").strip()
        if not key_id:
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "key_id_missing",
            }
        if algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "unsupported_attestation_algorithm",
            }
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "key_id_mismatch",
            }

        discovered = registry.discover_key(key_id, algorithm)
        if not isinstance(discovered, dict):
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "trusted_key_not_found",
            }
        metadata = discovered.get("metadata")
        public_key = discovered.get("public_key")
        if not isinstance(metadata, dict) or public_key is None:
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "trusted_key_metadata_missing",
            }

        key_status = normalize_attestation_key_status(metadata.get("status"))
        if isinstance(expected_key_statuses, str):
            expected_key_statuses = [expected_key_statuses]
        if not isinstance(expected_key_statuses, (list, tuple, set)) or not expected_key_statuses:
            expected_key_statuses = [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE]
        allowed_statuses = {
            normalize_attestation_key_status(item)
            for item in expected_key_statuses
            if str(item or "").strip()
        }
        if key_status not in allowed_statuses:
            if key_status == IDENTITY_KEY_STATUS_REVOKED:
                reason = "trusted_key_revoked"
            elif key_status == IDENTITY_KEY_STATUS_RETIRED:
                reason = "trusted_key_retired"
            else:
                reason = "trusted_key_status_not_allowed"
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": reason,
                "key_id": key_id,
                "key_status": key_status,
            }

        key_fingerprint = str(metadata.get("fingerprint", "") or "").strip().lower()
        expected_fingerprint = str(expected_key_fingerprint or "").strip().lower()
        if expected_fingerprint and key_fingerprint != expected_fingerprint:
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "trusted_key_fingerprint_mismatch",
                "key_id": key_id,
            }

        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {
                "success": False,
                "status": "ATTESTATION_INVALID",
                "reason": "issuer_mismatch",
            }

        verified = cls.verify_trust_state_audit_evidence_attestation(
            attested_evidence,
            public_key,
            expected_issuer=issuer,
            expected_key_id=key_id,
        )
        if not verified.get("success"):
            return verified

        return {
            **verified,
            "status": "AUDIT_EVIDENCE_TRUSTED_KEY_ATTESTATION_VERIFIED",
            "key_status": key_status,
            "key_fingerprint": key_fingerprint,
            "registry_revision": metadata.get("registry_revision"),
            "key_set_fingerprint": metadata.get("key_set_fingerprint"),
            "trusted_key_source": metadata.get("source", ""),
        }

    @classmethod
    def verify_trust_state_audit_evidence_attestation(cls, attested_evidence, public_key, *, expected_issuer="", expected_key_id=""):
        """Verify an audit-evidence Ed25519 attestation without storage access."""
        if not isinstance(attested_evidence, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "evidence_must_be_object"}
        attestation = attested_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "attestation_missing"}
        required = ("schema_version", "attestation_type", "algorithm", "issuer", "key_id", "evidence_fingerprint", "signature")
        missing = [field for field in required if field not in attestation]
        if missing:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "missing_attestation_fields", "fields": missing}
        if int(attestation.get("schema_version", 0) or 0) != 1 or attestation.get("attestation_type") != "OIDC_TRUST_STATE_AUDIT_EVIDENCE_ATTESTATION":
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "unsupported_attestation_schema"}
        if attestation.get("algorithm") != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "unsupported_attestation_algorithm"}
        issuer = str(attestation.get("issuer", "") or "").strip().rstrip("/")
        key_id = str(attestation.get("key_id", "") or "").strip()
        if expected_issuer and issuer != str(expected_issuer).strip().rstrip("/"):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "issuer_mismatch"}
        if expected_key_id and key_id != str(expected_key_id).strip():
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "key_id_mismatch"}
        base_evidence = dict(attested_evidence)
        base_evidence.pop("attestation", None)
        evidence_result = cls.verify_trust_state_audit_evidence(base_evidence, expected_issuer=issuer)
        if not evidence_result.get("success"):
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "embedded_evidence_invalid", "verification": evidence_result}
        evidence_fingerprint = str(base_evidence.get("evidence_fingerprint", "") or "")
        if str(attestation.get("evidence_fingerprint", "") or "") != evidence_fingerprint:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "evidence_fingerprint_mismatch"}
        payload = cls._audit_evidence_attestation_payload(base_evidence, issuer=issuer, key_id=key_id)
        try:
            signature = _b64url_decode(attestation.get("signature", ""))
            if not signature:
                raise ValueError("empty signature")
            public_key.verify(signature, _canonical_json(payload).encode("utf-8"))
        except Exception:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "signature_invalid"}
        expected_signature_fp = str(attestation.get("signature_fingerprint", "") or "")
        actual_signature_fp = hashlib.sha256(signature).hexdigest()
        if expected_signature_fp and expected_signature_fp != actual_signature_fp:
            return {"success": False, "status": "ATTESTATION_INVALID", "reason": "signature_fingerprint_mismatch"}
        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_ATTESTATION_VERIFIED",
            "issuer": issuer,
            "key_id": key_id,
            "algorithm": IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "evidence_fingerprint": evidence_fingerprint,
            "signature_fingerprint": actual_signature_fp,
            "read_only": True,
            "authoritative_state_mutated": False,
        }

    @classmethod
    def verify_trust_state_audit_evidence(cls, evidence, *, expected_issuer=""):
        """Verify an exported audit-evidence package without reading storage."""
        if not isinstance(evidence, dict):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "evidence_must_be_object"}

        required = (
            "schema_version",
            "evidence_type",
            "issuer",
            "coverage_start_sequence",
            "coverage_end_sequence",
            "head_hash",
            "records",
            "journal_verification",
            "evidence_fingerprint",
        )
        missing = [field for field in required if field not in evidence]
        if missing:
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "missing_evidence_fields", "fields": missing}
        if int(evidence.get("schema_version", 0) or 0) != 1:
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "unsupported_evidence_schema"}
        if evidence.get("evidence_type") != "OIDC_TRUST_STATE_AUDIT_EVIDENCE":
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "unsupported_evidence_type"}
        issuer = str(evidence.get("issuer", "") or "")
        if expected_issuer and issuer != expected_issuer:
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "issuer_mismatch"}
        records = evidence.get("records")
        if not isinstance(records, list):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "records_not_list"}

        checkpoint = evidence.get("checkpoint")
        if checkpoint is not None:
            checkpoint_result = cls._verify_journal_checkpoint(checkpoint, expected_issuer=issuer)
            if not checkpoint_result.get("valid"):
                return {"success": False, "status": "EVIDENCE_INVALID", "reason": checkpoint_result.get("reason"), "checkpoint_verification": checkpoint_result}
            previous_hash = checkpoint_result["record_hash"]
            start_sequence = checkpoint_result["sequence"] + 1
        else:
            checkpoint_result = {"valid": True, "reason": "not_present", "sequence": 0, "record_hash": cls._journal_genesis_hash()}
            previous_hash = checkpoint_result["record_hash"]
            start_sequence = 1

        record_result = cls._verify_journal_records(
            records,
            start_sequence=start_sequence,
            previous_hash=previous_hash,
        )
        if not record_result.get("valid"):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": record_result.get("reason"), "record_verification": record_result}

        if str(evidence.get("head_hash", "") or "") != str(record_result.get("head_hash", "") or ""):
            return {"success": False, "status": "EVIDENCE_INVALID", "reason": "head_hash_mismatch", "record_verification": record_result}

        fingerprint_payload = dict(evidence)
        fingerprint_payload.pop("exported_at", None)
        expected_fingerprint = str(fingerprint_payload.pop("evidence_fingerprint", "") or "")
        actual_fingerprint = hashlib.sha256(
            _canonical_json(fingerprint_payload).encode("utf-8")
        ).hexdigest()
        if expected_fingerprint != actual_fingerprint:
            return {
                "success": False,
                "status": "EVIDENCE_INVALID",
                "reason": "evidence_fingerprint_mismatch",
                "expected_fingerprint": expected_fingerprint,
                "actual_fingerprint": actual_fingerprint,
            }

        return {
            "success": True,
            "status": "AUDIT_EVIDENCE_VERIFIED",
            "issuer": issuer,
            "checkpoint_verification": checkpoint_result,
            "record_verification": record_result,
            "evidence_fingerprint": actual_fingerprint,
            "read_only": True,
        }

    def _record_state_conflict(self, expected_revision, actual_revision, expected_fingerprint, actual_fingerprint):
        self._state_conflict_count += 1
        self._last_state_conflict = {
            "detected_at": float(self.now_fn()),
            "expected_revision": int(expected_revision or 0),
            "actual_revision": int(actual_revision or 0),
            "expected_fingerprint": str(expected_fingerprint or ""),
            "actual_fingerprint": str(actual_fingerprint or ""),
        }
        self._append_trust_state_journal("CONFLICT_DETECTED", self._last_state_conflict)

    def _load_persisted_state_unlocked(self):
        """Reload the latest durable state while the interprocess lock is held."""
        if not self.state_path:
            return {"loaded": False, "reason": "state_path_not_configured"}
        from memory_storage import load_json_document
        state = load_json_document(self.state_path, lambda: None, expected_type=dict)
        if not isinstance(state, dict):
            return {"loaded": False, "reason": "state_missing_or_invalid"}
        if str(state.get("issuer", "") or "").strip().rstrip("/") != self.issuer:
            return {"loaded": False, "reason": "issuer_mismatch"}
        try:
            schema = int(state.get("schema_version", 0))
        except (TypeError, ValueError):
            schema = 0
        if schema not in {1, 2, 3, PERSISTED_OIDC_STATE_SCHEMA_VERSION}:
            return {"loaded": False, "reason": "unsupported_state_schema"}
        try:
            registry_state = state.get("registry")
            if not isinstance(registry_state, dict):
                raise ValueError("registry_state_missing")
            self.registry.restore_persisted_state(registry_state)
            document = state.get("discovery_document")
            if document is not None and not isinstance(document, dict):
                raise ValueError("discovery_document must be an object")
            self._discovery_document = document
            self._jwks_uri = self._validate_endpoint_url(state.get("jwks_uri", ""), "jwks_uri") if state.get("jwks_uri") else ""
            self._state_revision = max(0, int(state.get("state_revision", 0) or 0))
            computed_fingerprint = self._compute_state_fingerprint(state)
            persisted_fingerprint = str(state.get("state_fingerprint", "") or "").strip()
            if persisted_fingerprint and persisted_fingerprint != computed_fingerprint:
                raise ValueError("persisted trust state fingerprint mismatch")
            self._state_fingerprint = computed_fingerprint
            self._persisted_state_fingerprint = computed_fingerprint
            self._last_success_at = float(state.get("last_success_at", 0.0) or 0.0)
            self._cache_expires_at = float(state.get("cache_expires_at", 0.0) or 0.0)
            self._last_refresh_error = state.get("last_refresh_error")
            self._refresh_count = max(0, int(state.get("refresh_count", 0) or 0))
            self._consecutive_failures = max(0, int(state.get("consecutive_failures", 0) or 0))
            self._next_refresh_allowed_at = float(state.get("next_refresh_allowed_at", 0.0) or 0.0)
            for attr in ("_etag_by_url", "_cache_control_by_url", "_last_http_status_by_url"):
                value = state.get(attr[1:], {})
                if not isinstance(value, dict):
                    raise ValueError(f"{attr} persisted value is invalid")
                setattr(self, attr, {str(k): v for k, v in value.items()})
            self._state_loaded = True
            return {"loaded": True, "cache_valid": self.is_cache_valid(), "metadata": self.get_discovery_metadata()}
        except Exception as exc:
            return {"loaded": False, "reason": str(exc)[:300]}

    def _persist_state(self):
        if not self.state_path:
            return False

        from memory_storage import load_json_document, save_json_document

        expected_revision = max(0, int(self._state_revision))
        expected_fingerprint = str(self._persisted_state_fingerprint or self._state_fingerprint or "")
        durable = load_json_document(self.state_path, lambda: None, expected_type=dict)

        if isinstance(durable, dict):
            try:
                durable_revision = max(0, int(durable.get("state_revision", 0) or 0))
            except (TypeError, ValueError):
                durable_revision = 0
            durable_fingerprint = self._compute_state_fingerprint(durable)
            if durable_revision != expected_revision or (expected_fingerprint and durable_fingerprint != expected_fingerprint):
                self._record_state_conflict(
                    expected_revision,
                    durable_revision,
                    expected_fingerprint,
                    durable_fingerprint,
                )
                self._load_persisted_state_unlocked()
                raise OIDCTrustStateConflictError(
                    "persistent trust state changed since this instance loaded it",
                    expected_revision=expected_revision,
                    actual_revision=durable_revision,
                    expected_fingerprint=expected_fingerprint,
                    actual_fingerprint=durable_fingerprint,
                )
        elif expected_revision != 0 or expected_fingerprint:
            self._record_state_conflict(expected_revision, 0, expected_fingerprint, "")
            raise OIDCTrustStateConflictError(
                "persistent trust state disappeared since this instance loaded it",
                expected_revision=expected_revision,
                actual_revision=0,
                expected_fingerprint=expected_fingerprint,
                actual_fingerprint="",
            )

        next_revision = expected_revision + 1
        state = {
            "schema_version": PERSISTED_OIDC_STATE_SCHEMA_VERSION,
            "state_revision": next_revision,
            "issuer": self.issuer,
            "saved_at": float(self.now_fn()),
            "discovery_document": self._discovery_document,
            "jwks_uri": self._jwks_uri,
            "last_success_at": self._last_success_at,
            "cache_expires_at": self._cache_expires_at,
            "last_refresh_error": self._last_refresh_error,
            "refresh_count": self._refresh_count,
            "consecutive_failures": self._consecutive_failures,
            "next_refresh_allowed_at": self._next_refresh_allowed_at,
            "etag_by_url": dict(self._etag_by_url),
            "cache_control_by_url": dict(self._cache_control_by_url),
            "last_http_status_by_url": dict(self._last_http_status_by_url),
            "registry": self.registry.export_persisted_state(),
            "state_conflict_count": self._state_conflict_count,
            "last_state_conflict": self._last_state_conflict,
            "conflict_policy_schema_version": OIDC_TRUST_CONFLICT_POLICY_SCHEMA_VERSION,
            "conflict_policy": self.conflict_policy,
            "last_conflict_recovery": self._last_conflict_recovery,
        }
        state["state_fingerprint"] = self._compute_state_fingerprint(state)
        save_json_document(self.state_path, state)
        self._state_revision = next_revision
        self._state_fingerprint = state["state_fingerprint"]
        self._persisted_state_fingerprint = state["state_fingerprint"]
        self._state_loaded = True
        return True

    def load_persisted_state(self):
        if not self.state_path:
            return {"loaded": False, "reason": "state_path_not_configured"}
        from memory_storage import load_json_document
        state = load_json_document(self.state_path, lambda: None, expected_type=dict)
        if not isinstance(state, dict):
            return {"loaded": False, "reason": "state_missing_or_invalid"}
        if str(state.get("issuer", "") or "").strip().rstrip("/") != self.issuer:
            return {"loaded": False, "reason": "issuer_mismatch"}
        try:
            schema = int(state.get("schema_version", 0))
        except (TypeError, ValueError):
            schema = 0
        if schema not in {1, 2, 3, PERSISTED_OIDC_STATE_SCHEMA_VERSION}:
            return {"loaded": False, "reason": "unsupported_state_schema"}
        registry_state = state.get("registry")
        if not isinstance(registry_state, dict):
            return {"loaded": False, "reason": "registry_state_missing"}
        try:
            self.registry.restore_persisted_state(registry_state)
            document = state.get("discovery_document")
            if document is not None and not isinstance(document, dict):
                raise ValueError("discovery_document must be an object")
            self._discovery_document = document
            self._jwks_uri = self._validate_endpoint_url(state.get("jwks_uri", ""), "jwks_uri") if state.get("jwks_uri") else ""
            self._state_revision = max(0, int(state.get("state_revision", 0) or 0))
            computed_fingerprint = self._compute_state_fingerprint(state)
            persisted_fingerprint = str(state.get("state_fingerprint", "") or "").strip()
            if persisted_fingerprint and persisted_fingerprint != computed_fingerprint:
                raise ValueError("persisted trust state fingerprint mismatch")
            self._state_fingerprint = computed_fingerprint
            self._persisted_state_fingerprint = computed_fingerprint
            self._state_conflict_count = max(0, int(state.get("state_conflict_count", 0) or 0))
            self._last_state_conflict = state.get("last_state_conflict")
            self._last_conflict_recovery = state.get("last_conflict_recovery")
            self._last_success_at = float(state.get("last_success_at", 0.0) or 0.0)
            self._cache_expires_at = float(state.get("cache_expires_at", 0.0) or 0.0)
            self._last_refresh_error = state.get("last_refresh_error")
            self._refresh_count = max(0, int(state.get("refresh_count", 0) or 0))
            self._consecutive_failures = max(0, int(state.get("consecutive_failures", 0) or 0))
            self._next_refresh_allowed_at = float(state.get("next_refresh_allowed_at", 0.0) or 0.0)
            for attr in ("_etag_by_url", "_cache_control_by_url", "_last_http_status_by_url"):
                value = state.get(attr[1:], {})
                if not isinstance(value, dict):
                    raise ValueError(f"{attr} persisted value is invalid")
                setattr(self, attr, {str(k): v for k, v in value.items()})
            self._state_loaded = True
            return {"loaded": True, "cache_valid": self.is_cache_valid(), "metadata": self.get_discovery_metadata()}
        except Exception as exc:
            self._discovery_document = None
            self._jwks_uri = ""
            self._cache_expires_at = 0.0
            self._state_loaded = False
            return {"loaded": False, "reason": str(exc)[:300]}

    def _recover_from_state_conflict(self, conflict):
        """Apply the configured conflict policy without overwriting durable state."""
        conflict_type = conflict.conflict_type
        decision = OIDC_TRUST_CONFLICT_POLICY_FAIL_CLOSED
        recovered = False
        reason = conflict_type

        if (
            self.conflict_policy == OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE
            and conflict_type == "NEWER_DURABLE_STATE"
        ):
            loaded = self._load_persisted_state_unlocked()
            if loaded.get("loaded"):
                decision = OIDC_TRUST_CONFLICT_POLICY_RELOAD_AUTHORITATIVE
                recovered = True
                reason = "newer_durable_state_adopted"
            else:
                reason = "authoritative_reload_failed"

        self._last_conflict_recovery = {
            "detected_at": float(self.now_fn()),
            "policy_schema_version": OIDC_TRUST_CONFLICT_POLICY_SCHEMA_VERSION,
            "policy": self.conflict_policy,
            "conflict_type": conflict_type,
            "decision": decision,
            "recovered": recovered,
            "reason": reason,
            "expected_revision": conflict.expected_revision,
            "actual_revision": conflict.actual_revision,
            "expected_fingerprint": conflict.expected_fingerprint,
            "actual_fingerprint": conflict.actual_fingerprint,
        }
        self._append_trust_state_journal("RECOVERY_DECISION", self._last_conflict_recovery)
        return dict(self._last_conflict_recovery)

    def clear_persisted_state(self):
        if self.state_path:
            try:
                import os
                os.remove(self.state_path)
            except FileNotFoundError:
                pass
            for path in (self.state_path + ".journal", self.state_path + ".journal.bak"):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
        self._discovery_document = None
        self._jwks_uri = ""
        self._cache_expires_at = 0.0
        self._state_revision = 0
        self._state_fingerprint = ""
        self._persisted_state_fingerprint = ""
        self._state_conflict_count = 0
        self._last_state_conflict = None
        self._last_conflict_recovery = None
        self._state_loaded = False

    @property
    def discovery_url(self):
        return self._build_discovery_url()

    def get_discovery_metadata(self):
        registry_metadata = self.registry.get_registry_metadata()
        now = float(self.now_fn())
        journal_records = self.get_trust_state_journal(limit=OIDC_TRUST_STATE_JOURNAL_MAX_RECORDS)
        journal_checkpoint = self.get_trust_state_journal_checkpoint(verify_integrity=True)
        journal_verification = self.verify_trust_state_journal()
        journal_checkpoint_sequence = (
            int(journal_checkpoint.get("sequence", 0) or 0)
            if isinstance(journal_checkpoint, dict)
            else 0
        )
        journal_coverage_end = int(journal_verification.get("coverage_end_sequence", 0) or 0)
        return {
            "schema_version": OIDC_DISCOVERY_SCHEMA_VERSION,
            "issuer": self.issuer,
            "state_revision": self._state_revision,
            "state_fingerprint": self._state_fingerprint,
            "state_fingerprint_algorithm": OIDC_TRUST_STATE_FINGERPRINT_ALGORITHM,
            "state_conflict_count": self._state_conflict_count,
            "last_state_conflict": self._last_state_conflict,
            "conflict_policy_schema_version": OIDC_TRUST_CONFLICT_POLICY_SCHEMA_VERSION,
            "conflict_policy": self.conflict_policy,
            "last_conflict_recovery": self._last_conflict_recovery,
            "state_lock_path": self.state_lock_path or None,
            "journal_path": self.journal_path or None,
            "journal_lock_path": (self.journal_path + ".lock") if self.journal_path else None,
            "journal_schema_version": OIDC_TRUST_STATE_JOURNAL_SCHEMA_VERSION,
            "journal_record_count": len(journal_records),
            "journal_tail_record_count": len(journal_records),
            "journal_checkpoint": journal_checkpoint,
            "journal_checkpoint_sequence": journal_checkpoint_sequence,
            "journal_coverage_end_sequence": journal_coverage_end,
            "discovery_url": self.discovery_url,
            "jwks_uri": self._jwks_uri,
            "last_success_at": self._last_success_at,
            "cache_expires_at": self._cache_expires_at,
            "cache_valid": self.is_cache_valid(),
            "last_refresh_error": self._last_refresh_error,
            "refresh_count": self._refresh_count,
            "consecutive_failures": self._consecutive_failures,
            "next_refresh_allowed_at": self._next_refresh_allowed_at,
            "backoff_active": now < self._next_refresh_allowed_at,
            "etag_by_url": dict(self._etag_by_url),
            "cache_control_by_url": dict(self._cache_control_by_url),
            "last_http_status_by_url": dict(self._last_http_status_by_url),
            "registry": registry_metadata,
        }

    def is_cache_valid(self):
        try:
            now = float(self.now_fn())
        except Exception:
            return False
        return bool(self._discovery_document and now < self._cache_expires_at)

    def ensure_fresh(self, force=False):
        if not force and self.is_cache_valid():
            return {"success": True, "status": "CACHED", "metadata": self.get_discovery_metadata()}
        return self.refresh(force=force)

    def refresh(self, force=False):
        """Refresh trust state with both thread and inter-process coordination."""
        if not self.state_path:
            with self._refresh_lock:
                return self._refresh_locked(force=force)
        from memory_storage import interprocess_lock
        with self._refresh_lock:
            with interprocess_lock(self.state_lock_path, timeout_seconds=self.state_lock_timeout_seconds):
                latest = self._load_persisted_state_unlocked()
                if latest.get("loaded"):
                    self._state_loaded = True
                return self._refresh_locked(force=force)

    def _refresh_locked(self, force=False):
        # The caller holds the process and, when configured, inter-process lock.
            if not force and self.is_cache_valid():
                return {"success": True, "status": "CACHED", "metadata": self.get_discovery_metadata()}

            now = float(self.now_fn())
            if not force and now < self._next_refresh_allowed_at:
                return {
                    "success": False,
                    "status": "REFRESH_BACKOFF",
                    "error": self._last_refresh_error or "refresh_backoff_active",
                    "fail_closed": True,
                    "metadata": self.get_discovery_metadata(),
                }

            previous_registry_fingerprint = self.registry.get_registry_metadata().get("key_set_fingerprint")
            previous_jwks_uri = self._jwks_uri
            discovery_url = self.discovery_url
            try:
                document, discovery_headers = self._invoke_fetch(discovery_url)
                discovery_ttl = self._apply_response_metadata(discovery_url, discovery_headers)

                if discovery_headers.get("status") == 304:
                    if not self._discovery_document:
                        raise ValueError("Discovery returned 304 without a cached document")
                    document = dict(self._discovery_document)
                else:
                    if not isinstance(document, dict):
                        raise ValueError("OIDC discovery response must be a JSON object")

                discovered_issuer = str(document.get("issuer", "") or "").strip().rstrip("/")
                if discovered_issuer != self.issuer:
                    raise ValueError("OIDC discovery issuer does not exactly match configured issuer")

                jwks_uri = self._validate_endpoint_url(document.get("jwks_uri", ""), "jwks_uri")
                jwks, jwks_headers = self._invoke_fetch(jwks_uri)
                jwks_ttl = self._apply_response_metadata(jwks_uri, jwks_headers)

                if jwks_headers.get("status") == 304:
                    if not self.registry.list_key_metadata():
                        raise ValueError("JWKS returned 304 without cached keys")
                    result = {
                        "changed": False,
                        "discovered": [],
                        "rejected": [],
                        "retired": [],
                        "registry": self.registry.get_registry_metadata(),
                    }
                else:
                    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                        raise ValueError("JWKS response must contain a keys list")
                    result = self.registry.refresh_from_jwks(
                        jwks,
                        source=jwks_uri,
                        retire_missing=self.retire_missing,
                    )

                    retired_previous_source = []
                    if previous_jwks_uri and previous_jwks_uri != jwks_uri:
                        retired_previous_source = self.registry.retire_source_keys(previous_jwks_uri)
                    if retired_previous_source:
                        result["retired"] = list(result.get("retired", [])) + retired_previous_source

                    if len(result.get("discovered", [])) == 0 and not self.registry.list_key_metadata():
                        raise ValueError("JWKS refresh did not discover any accepted keys")

                self._discovery_document = dict(document)
                self._jwks_uri = jwks_uri
                self._last_success_at = now
                self._cache_expires_at = now + min(discovery_ttl, jwks_ttl) if min(discovery_ttl, jwks_ttl) > 0 else now
                self._last_refresh_error = None
                self._consecutive_failures = 0
                self._next_refresh_allowed_at = 0.0
                self._refresh_count += 1
                self._persist_state()

                return {
                    "success": True,
                    "status": "NOT_MODIFIED" if discovery_headers.get("status") == 304 and jwks_headers.get("status") == 304 else "REFRESHED",
                    "changed": previous_registry_fingerprint != result["registry"].get("key_set_fingerprint"),
                    "discovered": len(result.get("discovered", [])),
                    "rejected": result.get("rejected", []),
                    "retired": result.get("retired", []),
                    "metadata": self.get_discovery_metadata(),
                }
            except OIDCTrustStateConflictError as exc:
                self._last_refresh_error = str(exc)[:500]
                recovery = self._recover_from_state_conflict(exc)
                if recovery.get("recovered") and self.is_cache_valid():
                    return {
                        "success": True,
                        "status": "CONFLICT_RECOVERED",
                        "changed": False,
                        "fail_closed": False,
                        "conflict": {
                            "type": exc.conflict_type,
                            "expected_revision": exc.expected_revision,
                            "actual_revision": exc.actual_revision,
                            "expected_fingerprint": exc.expected_fingerprint,
                            "actual_fingerprint": exc.actual_fingerprint,
                        },
                        "recovery": recovery,
                        "metadata": self.get_discovery_metadata(),
                    }
                return {
                    "success": False,
                    "status": "TRUST_STATE_CONFLICT",
                    "error": self._last_refresh_error,
                    "fail_closed": True,
                    "conflict": {
                        "type": exc.conflict_type,
                        "expected_revision": exc.expected_revision,
                        "actual_revision": exc.actual_revision,
                        "expected_fingerprint": exc.expected_fingerprint,
                        "actual_fingerprint": exc.actual_fingerprint,
                    },
                    "recovery": recovery,
                    "metadata": self.get_discovery_metadata(),
                }
            except Exception as exc:
                self._last_refresh_error = str(exc)[:500]
                self._consecutive_failures += 1
                delay = min(
                    self.refresh_backoff_seconds * (2 ** max(0, self._consecutive_failures - 1)),
                    self.max_refresh_backoff_seconds,
                )
                self._next_refresh_allowed_at = now + delay
                self._persist_state()
                return {
                    "success": False,
                    "status": "REFRESH_FAILED",
                    "error": self._last_refresh_error,
                    "fail_closed": True,
                    "retry_after_seconds": delay,
                    "metadata": self.get_discovery_metadata(),
                }

    def get_verification_key(self, key_id, algorithm):
        refresh = self.ensure_fresh()
        if not refresh.get("success"):
            return None
        return self.registry.get_verification_key(key_id, algorithm)

    def get_verification_key_metadata(self, key_id, algorithm):
        refresh = self.ensure_fresh()
        if not refresh.get("success"):
            return None
        return self.registry.get_verification_key_metadata(key_id, algorithm)

    def list_key_metadata(self):
        refresh = self.ensure_fresh()
        if not refresh.get("success"):
            return []
        return self.registry.list_key_metadata()

class OIDCJWTAttestationAdapter:
    """Configurable adapter for OIDC/JWT-compatible EdDSA attestations.

    The adapter implements the same provider-facing ``verify`` contract used
    by reconciliation. A token may be supplied directly or through a callable
    token provider. The latter allows the approval flow to bind a freshly
    generated nonce to a previously issued short-lived token without changing
    the reconciliation API.
    """

    def __init__(
        self,
        key_resolver,
        *,
        issuer,
        audience,
        token="",
        token_provider=None,
        expected_key_statuses=None,
        expected_key_fingerprint="",
        clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
        max_token_age_seconds=DEFAULT_JWT_MAX_AGE_SECONDS,
        require_nonce=False,
    ):
        if token and token_provider is not None:
            raise ValueError("token and token_provider are mutually exclusive")
        if token_provider is not None and not callable(token_provider):
            raise ValueError("token_provider must be callable")

        self.key_resolver = key_resolver
        self.issuer = str(issuer or "").strip()
        self.audience = str(audience or "").strip()
        self.token = str(token or "").strip()[:MAX_JWT_LENGTH]
        self.token_provider = token_provider
        self.expected_key_statuses = expected_key_statuses
        self.expected_key_fingerprint = str(expected_key_fingerprint or "").strip()
        self.clock_skew_seconds = clock_skew_seconds
        self.max_token_age_seconds = max_token_age_seconds
        self.require_nonce = bool(require_nonce)

    def _resolve_token(self, actor="", claimed_role="", reference="", attestation_nonce=""):
        if self.token_provider is not None:
            try:
                token = self.token_provider(
                    actor=str(actor or "").strip(),
                    claimed_role=str(claimed_role or "").strip(),
                    reference=str(reference or "").strip(),
                    attestation_nonce=str(attestation_nonce or "").strip(),
                )
            except TypeError:
                try:
                    token = self.token_provider(str(actor or "").strip(), str(attestation_nonce or "").strip())
                except Exception:
                    return ""
            except Exception:
                return ""
            return str(token or "").strip()[:MAX_JWT_LENGTH]
        return self.token

    def verify(
        self,
        actor,
        claimed_role="",
        reference="",
        attestation_nonce="",
        expected_issuer="",
        expected_audience="",
    ):
        """Verify the configured JWT as an authoritative identity response."""
        expected_issuer = str(expected_issuer or "").strip()
        expected_audience = str(expected_audience or "").strip()

        if expected_issuer and self.issuer and expected_issuer != self.issuer:
            return {
                "verified": False,
                "reference": str(reference or "").strip(),
                "error": "identity_jwt_adapter_issuer_configuration_mismatch",
                "codes": ["IDENTITY_JWT_ADAPTER_ISSUER_CONFIGURATION_MISMATCH"],
            }
        if expected_audience and self.audience and expected_audience != self.audience:
            return {
                "verified": False,
                "reference": str(reference or "").strip(),
                "error": "identity_jwt_adapter_audience_configuration_mismatch",
                "codes": ["IDENTITY_JWT_ADAPTER_AUDIENCE_CONFIGURATION_MISMATCH"],
            }

        token = self._resolve_token(
            actor=actor,
            claimed_role=claimed_role,
            reference=reference,
            attestation_nonce=attestation_nonce,
        )
        if not token:
            return {
                "verified": False,
                "reference": str(reference or "").strip(),
                "error": "identity_jwt_token_not_configured",
                "codes": ["IDENTITY_JWT_TOKEN_NOT_CONFIGURED"],
            }

        result = self.verify_token(
            token,
            actor=actor,
            claimed_role=claimed_role,
            nonce=attestation_nonce,
        )
        if isinstance(result, dict):
            result["reference"] = str(reference or "").strip()[:MAX_REFERENCE_LENGTH]
        return result

    def verify_token(
        self,
        token,
        *,
        actor="",
        claimed_role="",
        nonce="",
    ):
        if hasattr(self.key_resolver, "ensure_fresh"):
            try:
                refresh_result = self.key_resolver.ensure_fresh()
            except Exception as exc:
                return {
                    "verified": False,
                    "codes": ["IDENTITY_JWKS_REFRESH_FAILED"],
                    "error": str(exc)[:300],
                }
            if not isinstance(refresh_result, dict) or not refresh_result.get("success"):
                return {
                    "verified": False,
                    "codes": ["IDENTITY_JWKS_REFRESH_FAILED"],
                    "error": (refresh_result or {}).get("error", "jwks_refresh_failed") if isinstance(refresh_result, dict) else "jwks_refresh_failed",
                }

        return verify_oidc_jwt_attestation(
            token,
            self.key_resolver,
            expected_issuer=self.issuer,
            expected_audience=self.audience,
            expected_actor=actor,
            expected_nonce=nonce,
            claimed_role=claimed_role,
            expected_key_statuses=self.expected_key_statuses,
            expected_key_fingerprint=self.expected_key_fingerprint,
            clock_skew_seconds=self.clock_skew_seconds,
            max_token_age_seconds=self.max_token_age_seconds,
            require_nonce=self.require_nonce,
        )

    def get_verification_key(self, key_id, algorithm):
        """Expose the trusted verification key to the reconciliation layer."""
        if hasattr(self.key_resolver, "get_verification_key"):
            return self.key_resolver.get_verification_key(key_id, algorithm)
        if callable(self.key_resolver):
            return self.key_resolver(key_id, algorithm)
        return None

    def get_verification_key_metadata(self, key_id, algorithm):
        """Expose trusted-key lifecycle metadata to the reconciliation layer."""
        if hasattr(self.key_resolver, "get_verification_key_metadata"):
            return self.key_resolver.get_verification_key_metadata(key_id, algorithm)
        return None

def normalize_identity_roles(value):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = []

    roles = []
    for item in values[:MAX_ROLE_COUNT]:
        role = str(item or "").strip()[:MAX_ROLE_LENGTH]
        if role and role not in roles:
            roles.append(role)
    return sorted(roles)


def build_identity_fingerprint(provider, subject, actor, roles):
    identity = {
        "schema_version": IDENTITY_PROVIDER_SCHEMA_VERSION,
        "provider": str(provider or "").strip()[:MAX_PROVIDER_NAME_LENGTH],
        "subject": str(subject or "").strip()[:MAX_SUBJECT_LENGTH],
        "actor": str(actor or "").strip()[:MAX_SUBJECT_LENGTH],
        "roles": normalize_identity_roles(roles),
    }
    return hashlib.sha256(
        _canonical_json(identity).encode("utf-8")
    ).hexdigest()


def build_identity_attestation_document(
    provider,
    subject,
    actor,
    roles,
    status,
    verified_at,
    valid_until,
    attestation_id,
    algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519,
    key_id="",
    issuer="",
    audience="",
    nonce="",
):
    document = {
        "schema_version": IDENTITY_PROVIDER_SCHEMA_VERSION,
        "algorithm": str(algorithm or "").strip()[:100],
        "key_id": str(key_id or "").strip()[:MAX_KEY_ID_LENGTH],
        "provider": str(provider or "").strip()[:MAX_PROVIDER_NAME_LENGTH],
        "subject": str(subject or "").strip()[:MAX_SUBJECT_LENGTH],
        "actor": str(actor or "").strip()[:MAX_SUBJECT_LENGTH],
        "roles": normalize_identity_roles(roles),
        "status": str(status or IDENTITY_STATUS_UNKNOWN).strip().upper(),
        "verified_at": str(verified_at or "").strip()[:MAX_TIMESTAMP_LENGTH],
        "valid_until": str(valid_until or "").strip()[:MAX_TIMESTAMP_LENGTH],
        "attestation_id": str(attestation_id or "").strip()[:MAX_ATTESTATION_ID_LENGTH],
    }

    # Keep legacy signatures verifiable when the new binding claims are not
    # used. New issuer/audience/nonce-aware attestations explicitly sign them.
    issuer = str(issuer or "").strip()[:MAX_ISSUER_LENGTH]
    audience = str(audience or "").strip()[:MAX_AUDIENCE_LENGTH]
    nonce = str(nonce or "").strip()[:MAX_NONCE_LENGTH]
    if issuer or audience or nonce:
        document.update({
            "issuer": issuer,
            "audience": audience,
            "nonce": nonce,
        })

    return document


def build_identity_attestation_fingerprint(
    provider,
    subject,
    actor,
    roles,
    status,
    verified_at,
    valid_until,
    attestation_id,
    algorithm=IDENTITY_ATTESTATION_ALGORITHM_ED25519,
    key_id="",
    signature="",
    issuer="",
    audience="",
    nonce="",
):
    attestation = build_identity_attestation_document(
        provider,
        subject,
        actor,
        roles,
        status,
        verified_at,
        valid_until,
        attestation_id,
        algorithm=algorithm,
        key_id=key_id,
        issuer=issuer,
        audience=audience,
        nonce=nonce,
    )
    attestation["signature"] = str(signature or "").strip()[:MAX_SIGNATURE_LENGTH]
    return hashlib.sha256(
        _canonical_json(attestation).encode("utf-8")
    ).hexdigest()


def verify_identity_attestation(identity, key_resolver, expected_algorithm="", expected_key_id="", expected_issuer="", expected_audience="", expected_nonce="", expected_key_statuses=None, expected_key_fingerprint=""):
    """Verify an Ed25519 attestation over canonical identity claims.

    ``key_resolver`` may be a callable ``(key_id, algorithm) -> public_key`` or
    an object exposing ``get_verification_key(key_id, algorithm)``. Public keys
    may be cryptography key objects or PEM/DER encoded bytes.
    """
    identity = identity if isinstance(identity, dict) else {}
    algorithm = str(identity.get("signature_algorithm", "") or "").strip()
    key_id = str(identity.get("signature_key_id", "") or "").strip()
    signature = str(identity.get("attestation_signature", "") or "").strip()

    expected_algorithm = str(expected_algorithm or "").strip()
    expected_key_id = str(expected_key_id or "").strip()
    expected_issuer = str(expected_issuer or "").strip()
    expected_audience = str(expected_audience or "").strip()
    expected_nonce = str(expected_nonce or "").strip()
    expected_key_fingerprint = str(expected_key_fingerprint or "").strip()[:MAX_KEY_FINGERPRINT_LENGTH]
    if isinstance(expected_key_statuses, str):
        expected_key_statuses = [expected_key_statuses]
    if not isinstance(expected_key_statuses, (list, tuple, set)):
        expected_key_statuses = []
    expected_key_statuses = {
        normalize_attestation_key_status(item)
        for item in expected_key_statuses
        if str(item or "").strip()
    }

    issuer = str(identity.get("attestation_issuer", identity.get("issuer", "")) or "").strip()
    audience = str(identity.get("attestation_audience", identity.get("audience", "")) or "").strip()
    nonce = str(identity.get("attestation_nonce", identity.get("nonce", "")) or "").strip()

    # JWT attestations use JWS Compact Serialization, so their signature is
    # over ``base64url(header).base64url(payload)`` rather than the legacy
    # canonical identity document used by older attestations. Keep the legacy
    # path intact and bridge JWT tokens explicitly when the transient token is
    # present in the normalized provider response.
    attestation_token = str(identity.get("attestation_token", "") or "").strip()
    if attestation_token:
        if expected_algorithm and expected_algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISMATCH"]}
        jwt_result = verify_oidc_jwt_attestation(
            attestation_token,
            key_resolver,
            expected_issuer=expected_issuer or issuer,
            expected_audience=expected_audience or audience,
            expected_actor=str(identity.get("actor", "") or "").strip(),
            expected_nonce=expected_nonce or nonce,
            expected_key_statuses=expected_key_statuses or [IDENTITY_KEY_STATUS_ACTIVE, IDENTITY_KEY_STATUS_GRACE],
            expected_key_fingerprint=expected_key_fingerprint,
            clock_skew_seconds=DEFAULT_JWT_CLOCK_SKEW_SECONDS,
            max_token_age_seconds=DEFAULT_JWT_MAX_AGE_SECONDS,
            require_nonce=bool(expected_nonce or nonce),
        )
        if not jwt_result.get("verified"):
            return {
                "valid": False,
                "codes": jwt_result.get("codes", ["APPROVAL_IDENTITY_SIGNATURE_INVALID"]),
            }

        if expected_key_id and jwt_result.get("signature_key_id") != expected_key_id:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISMATCH"]}
        if algorithm and jwt_result.get("signature_algorithm") != algorithm:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISMATCH"]}
        if jwt_result.get("provider") != identity.get("provider"):
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_PROVIDER_MISMATCH"]}
        if jwt_result.get("subject") != identity.get("subject"):
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SUBJECT_MISMATCH"]}
        if jwt_result.get("actor") != identity.get("actor"):
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_ACTOR_MISMATCH"]}
        if normalize_identity_roles(jwt_result.get("roles", [])) != normalize_identity_roles(identity.get("roles", [])):
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_ROLE_MISMATCH"]}

        signature_bytes = _b64url_decode(jwt_result.get("attestation_signature", ""))
        return {
            "valid": True,
            "codes": [],
            "algorithm": jwt_result.get("signature_algorithm") or IDENTITY_ATTESTATION_ALGORITHM_ED25519,
            "key_id": jwt_result.get("signature_key_id") or key_id,
            "signature_fingerprint": hashlib.sha256(signature_bytes).hexdigest(),
            "key_status": jwt_result.get("signature_key_status"),
            "key_fingerprint": jwt_result.get("signature_key_fingerprint"),
        }

    if not algorithm:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISSING"]}
    if algorithm != IDENTITY_ATTESTATION_ALGORITHM_ED25519:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_UNSUPPORTED"]}
    if expected_algorithm and algorithm != expected_algorithm:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISMATCH"]}
    if not key_id:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISSING"]}
    if expected_key_id and key_id != expected_key_id:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISMATCH"]}
    if not signature:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_MISSING"]}
    if expected_issuer and issuer != expected_issuer:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_ISSUER_MISMATCH"]}
    if expected_audience and audience != expected_audience:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_AUDIENCE_MISMATCH"]}
    if expected_nonce and nonce != expected_nonce:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_NONCE_MISMATCH"]}
    if expected_issuer and not issuer:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_ISSUER_MISSING"]}
    if expected_audience and not audience:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_AUDIENCE_MISSING"]}
    if expected_nonce and not nonce:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_ATTESTATION_NONCE_MISSING"]}

    try:
        signature_bytes = _b64url_decode(signature)
    except (ValueError, TypeError, base64.binascii.Error):
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ENCODING_INVALID"]}

    try:
        if hasattr(key_resolver, "get_verification_key"):
            public_key = key_resolver.get_verification_key(key_id, algorithm)
        elif callable(key_resolver):
            public_key = key_resolver(key_id, algorithm)
        else:
            public_key = None
    except Exception:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_RESOLUTION_FAILED"]}

    if public_key is None:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_NOT_FOUND"]}

    key_metadata = None
    if hasattr(key_resolver, "get_verification_key_metadata"):
        try:
            key_metadata = key_resolver.get_verification_key_metadata(key_id, algorithm)
        except Exception:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_METADATA_RESOLUTION_FAILED"]}

    trust_controls_requested = bool(expected_key_statuses or expected_key_fingerprint)
    if trust_controls_requested and not isinstance(key_metadata, dict):
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_METADATA_REQUIRED"]}

    if isinstance(key_metadata, dict):
        metadata_key_id = str(key_metadata.get("key_id", "") or "").strip()
        metadata_algorithm = str(key_metadata.get("algorithm", "") or "").strip()
        key_status = normalize_attestation_key_status(key_metadata.get("status"))
        key_fingerprint = str(key_metadata.get("fingerprint", "") or "").strip().lower()
        not_before = _parse_timestamp(key_metadata.get("not_before"))
        not_after = _parse_timestamp(key_metadata.get("not_after"))
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)

        if metadata_key_id and metadata_key_id != key_id:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_ID_MISMATCH"]}
        if metadata_algorithm and metadata_algorithm != algorithm:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_ALGORITHM_MISMATCH"]}
        if expected_key_fingerprint and key_fingerprint != expected_key_fingerprint.lower():
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_FINGERPRINT_MISMATCH"]}
        if expected_key_statuses and key_status not in expected_key_statuses:
            return {
                "valid": False,
                "codes": [
                    "APPROVAL_IDENTITY_SIGNATURE_KEY_STATUS_NOT_ALLOWED"
                    if key_status != IDENTITY_KEY_STATUS_REVOKED
                    else "APPROVAL_IDENTITY_SIGNATURE_KEY_REVOKED"
                ],
            }
        if key_status == IDENTITY_KEY_STATUS_REVOKED:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_REVOKED"]}
        if not_before is not None and now < not_before:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_NOT_YET_VALID"]}
        if not_after is not None and now >= not_after:
            return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_KEY_EXPIRED"]}
    else:
        key_status = None
        key_fingerprint = None

    try:
        if isinstance(public_key, (bytes, bytearray)):
            from cryptography.hazmat.primitives import serialization

            raw_key = bytes(public_key)
            if b"BEGIN" in raw_key:
                public_key = serialization.load_pem_public_key(raw_key)
            else:
                public_key = serialization.load_der_public_key(raw_key)

        document = build_identity_attestation_document(
            identity.get("provider"),
            identity.get("subject"),
            identity.get("actor"),
            identity.get("roles", []),
            identity.get("status"),
            identity.get("verified_at"),
            identity.get("valid_until"),
            identity.get("attestation_id"),
            algorithm=algorithm,
            key_id=key_id,
            issuer=issuer,
            audience=audience,
            nonce=nonce,
        )
        public_key.verify(
            signature_bytes,
            _canonical_json(document).encode("utf-8"),
        )
    except ImportError:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_CRYPTOGRAPHY_UNAVAILABLE"]}
    except Exception:
        return {"valid": False, "codes": ["APPROVAL_IDENTITY_SIGNATURE_INVALID"]}

    signature_fingerprint = hashlib.sha256(signature_bytes).hexdigest()
    return {
        "valid": True,
        "codes": [],
        "algorithm": algorithm,
        "key_id": key_id,
        "signature_fingerprint": signature_fingerprint,
        "key_status": key_status,
        "key_fingerprint": key_fingerprint,
    }


def sign_identity_attestation_ed25519(private_key, identity):
    """Create a compact base64url Ed25519 signature for adapters/tests."""
    identity = identity if isinstance(identity, dict) else {}
    document = build_identity_attestation_document(
        identity.get("provider"),
        identity.get("subject"),
        identity.get("actor"),
        identity.get("roles", []),
        identity.get("status"),
        identity.get("verified_at"),
        identity.get("valid_until"),
        identity.get("attestation_id"),
        algorithm=identity.get("signature_algorithm") or IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        key_id=identity.get("signature_key_id", ""),
        issuer=identity.get("attestation_issuer", identity.get("issuer", "")),
        audience=identity.get("attestation_audience", identity.get("audience", "")),
        nonce=identity.get("attestation_nonce", identity.get("nonce", "")),
    )
    signature = private_key.sign(_canonical_json(document).encode("utf-8"))
    return _b64url_encode(signature)


def normalize_identity_result(result, requested_actor="", claimed_role=""):
    """Normalize a provider response into a safe, auditable identity attestation."""
    if not isinstance(result, dict):
        return {
            "schema_version": IDENTITY_PROVIDER_SCHEMA_VERSION,
            "verified": False,
            "provider": None,
            "subject": None,
            "actor": str(requested_actor or "").strip() or None,
            "roles": [],
            "reference": None,
            "status": IDENTITY_STATUS_UNKNOWN,
            "active": False,
            "revoked": False,
            "verified_at": None,
            "valid_until": None,
            "attestation_id": None,
            "signature_algorithm": None,
            "signature_key_id": None,
            "signature_key_status": None,
            "signature_key_fingerprint": None,
            "attestation_signature": None,
            "cryptographic_attestation_verified": False,
            "attestation_signature_fingerprint": None,
            "attestation_fingerprint": None,
            "identity_fingerprint": None,
            "error": "invalid_identity_provider_response",
        }

    verified = bool(result.get("verified", False))
    provider = str(result.get("provider", "") or "").strip()[:MAX_PROVIDER_NAME_LENGTH]
    subject = str(result.get("subject", "") or "").strip()[:MAX_SUBJECT_LENGTH]
    actor = str(result.get("actor", requested_actor) or "").strip()[:MAX_SUBJECT_LENGTH]
    roles = normalize_identity_roles(result.get("roles", []))
    reference = str(result.get("reference", "") or "").strip()[:MAX_REFERENCE_LENGTH]
    identity_fingerprint = str(result.get("identity_fingerprint", "") or "").strip()
    verified_at = str(result.get("verified_at", "") or "").strip()[:MAX_TIMESTAMP_LENGTH]
    valid_until = str(result.get("valid_until", "") or "").strip()[:MAX_TIMESTAMP_LENGTH]
    attestation_id = str(result.get("attestation_id", "") or "").strip()[:MAX_ATTESTATION_ID_LENGTH]
    signature_algorithm = str(result.get("signature_algorithm", "") or "").strip()[:100]
    signature_key_id = str(result.get("signature_key_id", "") or "").strip()[:MAX_KEY_ID_LENGTH]
    signature_key_status = normalize_attestation_key_status(result.get("signature_key_status")) if result.get("signature_key_status") is not None else None
    signature_key_fingerprint = str(result.get("signature_key_fingerprint", "") or "").strip().lower()[:MAX_KEY_FINGERPRINT_LENGTH]
    attestation_signature = str(result.get("attestation_signature", "") or "").strip()[:MAX_SIGNATURE_LENGTH]
    attestation_issuer = str(result.get("attestation_issuer", result.get("issuer", "")) or "").strip()[:MAX_ISSUER_LENGTH]
    attestation_audience = str(result.get("attestation_audience", result.get("audience", "")) or "").strip()[:MAX_AUDIENCE_LENGTH]
    attestation_nonce = str(result.get("attestation_nonce", result.get("nonce", "")) or "").strip()[:MAX_NONCE_LENGTH]
    attestation_token = str(result.get("attestation_token", "") or "").strip()[:MAX_JWT_LENGTH]
    cryptographic_verified = bool(result.get("cryptographic_attestation_verified", False))
    attestation_signature_fingerprint = str(result.get("attestation_signature_fingerprint", "") or "").strip().lower()[:MAX_KEY_FINGERPRINT_LENGTH]
    error = str(result.get("error", "") or "").strip()[:200]

    raw_status = str(result.get("status", "") or "").strip().upper()
    revoked = bool(result.get("revoked", False))

    if revoked:
        status = IDENTITY_STATUS_REVOKED
    elif raw_status in {
        IDENTITY_STATUS_ACTIVE,
        IDENTITY_STATUS_INACTIVE,
        IDENTITY_STATUS_REVOKED,
        IDENTITY_STATUS_SUSPENDED,
    }:
        status = raw_status
    elif "active" in result:
        status = IDENTITY_STATUS_ACTIVE if bool(result.get("active")) else IDENTITY_STATUS_INACTIVE
    elif verified:
        status = IDENTITY_STATUS_UNKNOWN
    else:
        status = IDENTITY_STATUS_UNKNOWN

    active = status == IDENTITY_STATUS_ACTIVE
    if status == IDENTITY_STATUS_REVOKED:
        active = False

    if not actor or actor != str(requested_actor or "").strip():
        verified = False
        error = "identity_actor_mismatch"

    if not provider:
        verified = False
        error = error or "identity_provider_missing"

    if not subject:
        verified = False
        error = error or "identity_subject_missing"

    if claimed_role and claimed_role not in roles:
        verified = False
        error = "identity_claimed_role_not_authorized"

    calculated = build_identity_fingerprint(provider, subject, actor, roles)

    if identity_fingerprint and identity_fingerprint != calculated:
        verified = False
        error = "identity_fingerprint_mismatch"

    identity_fingerprint = calculated if verified or not identity_fingerprint else identity_fingerprint

    attestation_fingerprint = build_identity_attestation_fingerprint(
        provider,
        subject,
        actor,
        roles,
        status,
        verified_at,
        valid_until,
        attestation_id,
        algorithm=signature_algorithm or IDENTITY_ATTESTATION_ALGORITHM_ED25519,
        key_id=signature_key_id,
        signature=attestation_signature,
        issuer=attestation_issuer,
        audience=attestation_audience,
        nonce=attestation_nonce,
    )

    if signature_algorithm and signature_key_id and attestation_signature and not cryptographic_verified:
        cryptographic_verified = False

    return {
        "schema_version": IDENTITY_PROVIDER_SCHEMA_VERSION,
        "verified": verified,
        "provider": provider or None,
        "subject": subject or None,
        "actor": actor or None,
        "roles": roles,
        "reference": reference or None,
        "status": status,
        "active": active,
        "revoked": revoked,
        "verified_at": verified_at or None,
        "valid_until": valid_until or None,
        "attestation_id": attestation_id or None,
        "signature_algorithm": signature_algorithm or None,
        "signature_key_id": signature_key_id or None,
        "signature_key_status": signature_key_status,
        "signature_key_fingerprint": signature_key_fingerprint or None,
        "attestation_issuer": attestation_issuer or None,
        "attestation_audience": attestation_audience or None,
        "attestation_nonce": attestation_nonce or None,
        "attestation_signature": attestation_signature or None,
        "attestation_token": attestation_token or None,
        "cryptographic_attestation_verified": cryptographic_verified,
        "attestation_signature_fingerprint": attestation_signature_fingerprint or None,
        "attestation_fingerprint": attestation_fingerprint,
        "identity_fingerprint": identity_fingerprint or None,
        "error": error or None,
    }


@runtime_checkable
class AuthoritativeIdentityProvider(Protocol):
    """Minimal provider contract used by reconciliation."""

    def verify(
        self,
        actor,
        claimed_role="",
        reference="",
        attestation_nonce="",
        expected_issuer="",
        expected_audience="",
    ):
        """Return a provider response suitable for normalize_identity_result."""
        raise NotImplementedError

    def get_verification_key(self, key_id, algorithm):
        """Return a public verification key for a cryptographic attestation."""
        raise NotImplementedError

    # Optional capability: providers may also expose
    # ``get_verification_key_metadata(key_id, algorithm)`` returning key
    # status/fingerprint/validity metadata. Reconciliation requires this
    # capability only when trusted-key lifecycle policy is enabled.
