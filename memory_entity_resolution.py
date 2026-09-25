import json
import os
import re
import uuid
from datetime import datetime, timezone

from memory_storage import load_json_document, save_json_document
from difflib import SequenceMatcher


# ==================================================
# Entity Identity Resolution Configuration
# ==================================================

RESOLUTION_FILE = "memory_entity_resolution.json"
RESOLUTION_SCHEMA_VERSION = 1
RESOLUTION_MAX_LOG = 5000
AUTO_LINK_THRESHOLD = 0.82
REVIEW_THRESHOLD = 0.68
AMBIGUITY_MARGIN = 0.08

# Generic modifiers that should not create a new identity when the
# remaining core entity name is the same.
GENERIC_TERMS = {
    "software", "tool", "app", "application", "program",
    "fea", "cae", "platform", "system",
    "نرم", "افزار", "نرم_افزار",
    "آباکوس", "آباکوس"  # kept only for safe replacement handling below
}

# Common Persian/Arabic spellings and transliterations. The resolver stays
# conservative: these are normalization hints, not proof by themselves.
TEXT_REPLACEMENTS = {
    # Common software names / Persian renderings first, before generic Arabic
    # character normalization can alter them.
    "آباکوس": "abaqus",
    "آباكوس": "abaqus",
    "سالیدورکس": "solidworks",
    "سالیدورك": "solidworks",
    "پایتون": "python",
    "نرم افزار": "نرم_افزار",
    "نرم‌افزار": "نرم_افزار",
    # Arabic/Persian character normalization.
    "ي": "ی",
    "ى": "ی",
    "ك": "ک",
    "ۀ": "ه",
    "ة": "ه",
    "أ": "ا",
    "إ": "ا",
    "آ": "ا",
}


# ==================================================
# Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value):
    if not isinstance(value, str):
        return ""

    text = value.strip().casefold()
    for old, new in TEXT_REPLACEMENTS.items():
        text = text.replace(old.casefold(), new.casefold())

    text = re.sub(r"[()\[\]{}<>:;,.!?/'\\\"`~@#$%^&*+=|_-]+", " ", text)
    text = " ".join(text.split())
    return text


def core_tokens(value):
    normalized = normalize_text(value)
    tokens = normalized.split()
    result = []

    for token in tokens:
        if token in GENERIC_TERMS:
            continue
        # Common generic phrase after normalization.
        if token in {"software", "tool", "application", "program", "app"}:
            continue
        if token in {"finite", "element", "analysis"} and len(tokens) > 1:
            continue
        result.append(token)

    return result


def canonical_identity_key(value):
    return " ".join(core_tokens(value))


def token_similarity(a, b):
    a_tokens = set(core_tokens(a))
    b_tokens = set(core_tokens(b))

    if not a_tokens or not b_tokens:
        return 0.0

    if a_tokens == b_tokens:
        return 1.0

    intersection = len(a_tokens & b_tokens)
    union = len(a_tokens | b_tokens)
    jaccard = intersection / union if union else 0.0

    containment = intersection / min(len(a_tokens), len(b_tokens))
    return max(jaccard, containment * 0.90)


def lexical_similarity(a, b):
    na = normalize_text(a)
    nb = normalize_text(b)

    if not na or not nb:
        return 0.0

    if na == nb:
        return 1.0

    return SequenceMatcher(None, na, nb).ratio()


def best_name_match(query, candidates):
    best = None
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            continue

        lexical = lexical_similarity(query, candidate)
        token_score = token_similarity(query, candidate)
        core_a = canonical_identity_key(query)
        core_b = canonical_identity_key(candidate)

        if core_a and core_b and core_a == core_b:
            score = 0.98
            method = "normalized_core_match"
        else:
            score = lexical * 0.45 + token_score * 0.55
            method = "lexical_token_match"

        if best is None or score > best["score"]:
            best = {
                "score": score,
                "method": method,
                "matched_name": candidate,
            }

    return best or {
        "score": 0.0,
        "method": "none",
        "matched_name": "",
    }


def _try_embedding_similarity(query, candidate):
    """Optional semantic similarity. Never makes the module unusable if the
    local embedding dependency/model is unavailable.
    """
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None

    try:
        model = _get_embedding_model()
        vectors = model.encode(
            [query, candidate],
            normalize_embeddings=True,
        )
        return float(sum(a * b for a, b in zip(vectors[0], vectors[1])))
    except Exception:
        return None


_EMBEDDING_MODEL = None


def _get_embedding_model():
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        from sentence_transformers import SentenceTransformer
        _EMBEDDING_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _EMBEDDING_MODEL


def resolve_entity_identity(candidate_name, entities, candidate_type="OTHER"):
    """Return the best existing entity identity match.

    Resolution is deliberately conservative. Exact/core/alias matches can be
    linked automatically. Semantic similarity is only used as supporting
    evidence, and ambiguous matches are rejected.
    """
    if not isinstance(candidate_name, str) or not candidate_name.strip():
        return {
            "matched": False,
            "entity_id": "",
            "score": 0.0,
            "method": "none",
            "matched_name": "",
            "ambiguity": False,
        }

    if not isinstance(entities, list) or not entities:
        return {
            "matched": False,
            "entity_id": "",
            "score": 0.0,
            "method": "none",
            "matched_name": "",
            "ambiguity": False,
        }

    candidates = []

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        names = [entity.get("name", "")]
        aliases = entity.get("aliases", [])
        if isinstance(aliases, list):
            names.extend(aliases)

        best = best_name_match(candidate_name, names)

        entity_type = str(entity.get("type", "OTHER") or "OTHER").strip().upper()
        candidate_type_norm = str(candidate_type or "OTHER").strip().upper()
        type_bonus = 0.04 if (
            entity_type == candidate_type_norm
            and entity_type != "OTHER"
            and candidate_type_norm != "OTHER"
        ) else 0.0

        embedding_score = None
        # Only call an embedding model when lexical evidence is already
        # plausible; this prevents unnecessary model work for unrelated names.
        if best["score"] >= 0.45:
            embedding_score = _try_embedding_similarity(
                candidate_name,
                best["matched_name"],
            )

        combined = best["score"]
        method = best["method"]

        if embedding_score is not None:
            combined = max(combined, embedding_score * 0.75 + best["score"] * 0.25)
            if embedding_score >= 0.86 and best["score"] >= 0.55:
                method = "semantic_identity_match"

        combined = min(1.0, combined + type_bonus)

        candidates.append({
            "entity_id": entity.get("entity_id", ""),
            "entity_name": entity.get("name", ""),
            "entity_type": entity_type,
            "score": round(combined, 4),
            "method": method,
            "matched_name": best["matched_name"],
            "embedding_score": round(embedding_score, 4) if embedding_score is not None else None,
        })

    candidates.sort(key=lambda item: item["score"], reverse=True)
    if not candidates:
        return {
            "matched": False,
            "entity_id": "",
            "score": 0.0,
            "method": "none",
            "matched_name": "",
            "ambiguity": False,
        }

    best = candidates[0]
    second_score = candidates[1]["score"] if len(candidates) > 1 else 0.0
    margin = best["score"] - second_score
    ambiguous = len(candidates) > 1 and best["score"] < 0.92 and margin < AMBIGUITY_MARGIN

    matched = best["score"] >= AUTO_LINK_THRESHOLD and not ambiguous

    return {
        "matched": matched,
        "needs_review": (
            not matched
            and best["score"] >= REVIEW_THRESHOLD
            and not ambiguous
        ),
        "entity_id": best["entity_id"] if matched else "",
        "score": best["score"],
        "method": best["method"],
        "matched_name": best["matched_name"],
        "ambiguity": ambiguous,
        "best_candidate": best,
        "alternatives": candidates[:5],
    }


def resolve_entity_candidates(candidates, entities):
    """Annotate extracted candidates with identity-resolution information."""
    if not isinstance(candidates, list):
        return []

    resolved = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        name = str(candidate.get("name", "") or "").strip()
        if not name:
            continue

        result = resolve_entity_identity(
            name,
            entities,
            candidate.get("type", "OTHER"),
        )

        item = dict(candidate)
        item["identity_resolution"] = result
        resolved.append(item)

    return resolved


# ==================================================
# Resolution Audit Log
# ==================================================

def _empty_store():
    return {
        "schema_version": RESOLUTION_SCHEMA_VERSION,
        "updated_at": None,
        "resolutions": [],
    }


def load_resolution_store():
    data = load_json_document(
        RESOLUTION_FILE,
        _empty_store,
        expected_type=dict,
    )

    if not isinstance(data, dict):
        return _empty_store()

    resolutions = data.get("resolutions")
    if not isinstance(resolutions, list):
        resolutions = []

    return {
        "schema_version": RESOLUTION_SCHEMA_VERSION,
        "updated_at": data.get("updated_at"),
        "resolutions": resolutions[-RESOLUTION_MAX_LOG:],
    }


def save_resolution_store(store):
    if not isinstance(store, dict):
        store = _empty_store()

    store["schema_version"] = RESOLUTION_SCHEMA_VERSION
    store["updated_at"] = current_timestamp()
    store["resolutions"] = store.get("resolutions", [])[-RESOLUTION_MAX_LOG:]

    save_json_document(RESOLUTION_FILE, store, indent=2)


def _record_resolution_impl(
    candidate_name,
    entity_id,
    entity_name,
    score,
    method,
    source_text="",
    memory_id="",
    action="LINK",
):
    store = load_resolution_store()
    record = {
        "resolution_id": f"ers_{uuid.uuid4().hex[:12]}",
        "candidate_name": str(candidate_name or "").strip(),
        "entity_id": str(entity_id or "").strip(),
        "entity_name": str(entity_name or "").strip(),
        "score": round(float(score or 0.0), 4),
        "method": str(method or "unknown").strip(),
        "action": str(action or "LINK").strip().upper(),
        "source_text": str(source_text or "").strip()[:500],
        "memory_id": str(memory_id or "").strip(),
        "timestamp": current_timestamp(),
    }
    store["resolutions"].append(record)
    save_resolution_store(store)
    return record


def record_resolution(
    candidate_name,
    entity_id,
    entity_name,
    score,
    method,
    source_text="",
    memory_id="",
    action="LINK",
):
    """Persist a resolution event once for one logical evidence event."""
    from memory_integrity import run_idempotent

    payload = {
        "candidate_name": str(candidate_name or "").strip(),
        "entity_id": str(entity_id or "").strip(),
        "memory_id": str(memory_id or "").strip(),
        "source_text": str(source_text or "").strip(),
        "action": str(action or "LINK").strip().upper(),
        "method": str(method or "unknown").strip(),
        "score": round(float(score or 0.0), 4),
    }

    result = run_idempotent(
        "RESOLUTION_RECORD",
        payload,
        lambda: _record_resolution_impl(
            candidate_name=candidate_name,
            entity_id=entity_id,
            entity_name=entity_name,
            score=score,
            method=method,
            source_text=source_text,
            memory_id=memory_id,
            action=action,
        ),
    )
    return result.get("result")


def get_resolution_history(query="", max_results=50):
    query = str(query or "").strip().casefold()
    records = load_resolution_store().get("resolutions", [])

    if query:
        records = [
            item for item in records
            if query in str(item.get("candidate_name", "")).casefold()
            or query in str(item.get("entity_name", "")).casefold()
            or query in str(item.get("source_text", "")).casefold()
        ]

    return list(reversed(records[-max_results:]))


def clear_resolution_history():
    save_resolution_store(_empty_store())
    return True
