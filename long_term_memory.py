import json
import os
import math
import uuid

from datetime import datetime, timezone

from sentence_transformers import SentenceTransformer

from memory_storage import load_json_document, save_json_document

from memory_entities import (
    get_all_entities,
    get_entities_for_memory,
    prune_memory_references,
)

from memory_entity_relations import (
    get_all_entity_relations,
    prune_memory_references as prune_relation_memory_references,
)


# ==================================================
# Configuration
# ==================================================

MEMORY_FILE = "memory.json"
ARCHIVE_FILE = "memory_archive.json"
EMBEDDINGS_FILE = "memory_embeddings.json"
GRAPH_FILE = "memory_graph.json"

MODEL_NAME = "all-MiniLM-L6-v2"

DEFAULT_SIMILARITY_THRESHOLD = 0.35
DUPLICATE_THRESHOLD = 0.85


# ==================================================
# Memory Lifecycle Configuration
# ==================================================

AGING_DAYS = 30
DECAYING_DAYS = 90
ARCHIVE_DAYS = 180

HIGH_IMPORTANCE_THRESHOLD = 4
ARCHIVE_IMPORTANCE_THRESHOLD = 3
ARCHIVE_MAX_ACCESS_COUNT = 3


# ==================================================
# Memory Temporal Configuration
# ==================================================

TEMPORAL_CURRENT = "current"
TEMPORAL_HISTORICAL = "historical"
TEMPORAL_ENDED = "ended"

TEMPORAL_EVENTS = {
    "START",
    "CHANGE",
    "END",
    "NONE",
}


# ==================================================
# Memory Provenance Configuration
# ==================================================

PROVENANCE_MAX_ENTRIES = 20
PROVENANCE_SOURCE_MAX_CHARS = 500

# ==================================================
# Memory Causal Reasoning Configuration
# ==================================================

CAUSAL_MAX_LINKS = 30
CAUSAL_MIN_CONFIDENCE = 0.70
CAUSAL_RELATIONS = {
    "CAUSES",
    "RESULTS_IN",
    "REQUIRES",
    "PREVENTS",
}



# ==================================================
# Memory Graph Configuration
# ==================================================

GRAPH_SCHEMA_VERSION = 2
GRAPH_MAX_NODES = 5000
GRAPH_MAX_EDGES = 15000

GRAPH_EDGE_TYPES = {
    "TEMPORAL_SUPERSEDES",
    "TEMPORAL_SAME_CHAIN",
    "DERIVED_FROM",
    "CAUSAL",
    "MEMORY_HAS_ENTITY",
    "ENTITY_RELATION",
}


# ==================================================
# Memory Graph JSON Helpers
# ==================================================

def load_memory_graph():
    if not os.path.exists(GRAPH_FILE):
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "updated_at": None,
            "nodes": [],
            "edges": [],
        }

    try:
        with open(GRAPH_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "updated_at": None,
            "nodes": [],
            "edges": [],
        }

    if not isinstance(data, dict):
        data = {}

    nodes = data.get("nodes")
    edges = data.get("edges")

    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []

    return {
        "schema_version": int(data.get("schema_version", GRAPH_SCHEMA_VERSION)),
        "updated_at": data.get("updated_at"),
        "nodes": nodes,
        "edges": edges,
    }


def save_memory_graph(graph):
    if not isinstance(graph, dict):
        graph = {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "updated_at": current_timestamp(),
            "nodes": [],
            "edges": [],
        }

    graph["schema_version"] = GRAPH_SCHEMA_VERSION
    graph["updated_at"] = current_timestamp()

    save_json_document(GRAPH_FILE, graph, indent=2)


def _graph_add_edge(edges, seen, source, target, edge_type, relation=None, confidence=1.0, evidence=""):
    if not source or not target or source == target:
        return

    edge_type = str(edge_type or "").strip().upper()
    if edge_type not in GRAPH_EDGE_TYPES:
        return

    key = (
        source,
        target,
        edge_type,
        str(relation or "").strip().upper(),
    )

    if key in seen:
        return

    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 0.0

    confidence = max(0.0, min(1.0, confidence))

    edges.append({
        "source": source,
        "target": target,
        "type": edge_type,
        "relation": str(relation or "").strip().upper(),
        "confidence": round(confidence, 4),
        "evidence": str(evidence or "").strip()[:PROVENANCE_SOURCE_MAX_CHARS],
    })
    seen.add(key)


def rebuild_memory_graph():
    """Rebuild the memory graph from active/archive memory metadata.

    The graph is a derived index. Memory JSON files remain the source of truth.
    """
    memory = get_memory()
    archive = get_archived_memory()
    all_items = memory + archive

    nodes = []
    edges = []
    seen_edges = set()
    ids = set()

    for item in all_items:
        if not isinstance(item, dict):
            continue

        memory_id = item.get("memory_id")
        if not isinstance(memory_id, str) or not memory_id.strip():
            continue

        memory_id = memory_id.strip()
        ids.add(memory_id)

        nodes.append({
            "id": memory_id,
            "kind": "memory",
            "memory": item.get("memory", ""),
            "type": item.get("type", "other"),
            "importance": normalize_importance(item.get("importance", 1)),
            "confidence": normalize_confidence(
                item.get(
                    "confidence",
                    initial_memory_confidence(item.get("importance", 1)),
                )
            ),
            "status": item.get("status", "active"),
            "temporal_status": item.get("temporal_status", TEMPORAL_CURRENT),
            "chain_id": item.get("chain_id"),
            "version": normalize_version(item.get("version", 1)),
            "valid_from": item.get("valid_from"),
            "valid_to": item.get("valid_to"),
        })

    # Entities are a separate knowledge layer.
    # Entity memory references are pruned so stale IDs do not survive.
    prune_memory_references(ids)
    active_entities = get_all_entities()

    # Archived entities remain visible in the derived graph as historical
    # nodes. They are not returned by get_all_entities(), because the active
    # store remains the operational source of truth, but the graph should
    # preserve the complete historical topology.
    try:
        from memory_entity_archive import get_archived_entities
        archived_entities = get_archived_entities()
    except Exception:
        archived_entities = []

    entity_map = {}
    for entity in active_entities + archived_entities:
        if not isinstance(entity, dict):
            continue
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if not entity_id:
            continue
        entity_map[entity_id] = entity

    for entity in entity_map.values():
        entity_id = str(entity.get("entity_id", "") or "").strip()
        if not entity_id:
            continue

        mention_count = entity.get("mention_count", 0)
        try:
            mention_count = max(0, int(mention_count))
        except (TypeError, ValueError):
            mention_count = 0

        nodes.append({
            "id": entity_id,
            "kind": "entity",
            "name": entity.get("name", ""),
            "canonical_name": entity.get("canonical_name", ""),
            "type": entity.get("type", "OTHER"),
            "confidence": normalize_confidence(entity.get("confidence", 0.70)),
            "mention_count": mention_count,
            "memory_ids": normalize_derived_from(entity.get("memory_ids")),
            "entity_chain_id": entity.get("entity_chain_id", entity_id),
            "version": normalize_version(entity.get("version", 1)),
            "valid_from": entity.get("valid_from"),
            "valid_to": entity.get("valid_to"),
            "temporal_status": entity.get("temporal_status", "current"),
            "history_versions": len(entity.get("history", [])),
            "lifecycle_status": entity.get("lifecycle_status", "ACTIVE"),
            "lifecycle_score": round(float(entity.get("lifecycle_score", 0.0) or 0.0), 4),
            "archive_state": entity.get("archive_state", "ACTIVE"),
            "archived_at": entity.get("archived_at"),
            "archive_reason": entity.get("archive_reason", ""),
        })

        for memory_id in normalize_derived_from(entity.get("memory_ids")):
            if memory_id not in ids:
                continue

            _graph_add_edge(
                edges,
                seen_edges,
                memory_id,
                entity_id,
                "MEMORY_HAS_ENTITY",
                relation="MENTIONS",
                confidence=entity.get("confidence", 0.70),
                evidence="entity extraction",
            )

    # Entity-to-entity relations are a separate derived edge layer.
    # Stale memory references inside relations are pruned before graph build.
    prune_relation_memory_references(ids)
    for relation_item in get_all_entity_relations():
        source_entity_id = relation_item.get("source_entity_id")
        target_entity_id = relation_item.get("target_entity_id")
        if source_entity_id not in {node.get("id") for node in nodes if node.get("kind") == "entity"}:
            continue
        if target_entity_id not in {node.get("id") for node in nodes if node.get("kind") == "entity"}:
            continue

        evidence = relation_item.get("evidence", "")
        relation = relation_item.get("relation", "RELATED_TO")
        linked_memory_ids = normalize_derived_from(relation_item.get("memory_ids"))
        evidence = evidence or (f"supported by {len(linked_memory_ids)} memory(s)" if linked_memory_ids else "entity relation")

        _graph_add_edge(
            edges,
            seen_edges,
            source_entity_id,
            target_entity_id,
            "ENTITY_RELATION",
            relation=relation,
            confidence=relation_item.get("confidence", 0.70),
            evidence=evidence,
        )

        # Undirected relations are represented in graph traversal by a reverse edge.
        if not relation_item.get("directed", True):
            _graph_add_edge(
                edges,
                seen_edges,
                target_entity_id,
                source_entity_id,
                "ENTITY_RELATION",
                relation=relation,
                confidence=relation_item.get("confidence", 0.70),
                evidence=evidence,
            )

    # Rebuild temporal and provenance/derivation edges.
    for item in all_items:
        if not isinstance(item, dict):
            continue

        source_id = item.get("memory_id")
        if source_id not in ids:
            continue

        supersedes = item.get("supersedes")
        if supersedes in ids:
            _graph_add_edge(
                edges,
                seen_edges,
                source_id,
                supersedes,
                "TEMPORAL_SUPERSEDES",
                relation="SUPERSEDES",
                evidence="temporal version metadata",
            )

        superseded_by = item.get("superseded_by")
        if superseded_by in ids:
            _graph_add_edge(
                edges,
                seen_edges,
                source_id,
                superseded_by,
                "TEMPORAL_SUPERSEDES",
                relation="SUPERSEDED_BY",
                evidence="temporal version metadata",
            )

        for related_id in normalize_derived_from(item.get("derived_from")):
            if related_id in ids:
                _graph_add_edge(
                    edges,
                    seen_edges,
                    source_id,
                    related_id,
                    "DERIVED_FROM",
                    relation="DERIVED_FROM",
                    evidence="memory derivation metadata",
                )

        for link in normalize_causal_links(item.get("causal_links")):
            target_id = link.get("target_memory_id")
            if target_id not in ids:
                continue

            _graph_add_edge(
                edges,
                seen_edges,
                source_id,
                target_id,
                "CAUSAL",
                relation=link.get("relation"),
                confidence=link.get("confidence", 0.0),
                evidence=link.get("evidence", ""),
            )

        for entry in normalize_provenance(item.get("provenance")):
            for related_id in entry.get("related_memory_ids", []):
                if related_id in ids:
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

    # Add explicit same-chain links between adjacent versions.
    chains = {}
    for node in nodes:
        chain_id = node.get("chain_id")
        if not chain_id:
            continue
        chains.setdefault(chain_id, []).append(node)

    for chain_nodes in chains.values():
        chain_nodes.sort(key=lambda n: (n.get("version", 1), n.get("valid_from") or ""))
        for previous, current in zip(chain_nodes, chain_nodes[1:]):
            _graph_add_edge(
                edges,
                seen_edges,
                previous["id"],
                current["id"],
                "TEMPORAL_SAME_CHAIN",
                relation="NEXT_VERSION",
                evidence="shared temporal chain",
            )

    nodes.sort(key=lambda n: (n.get("chain_id") or "", n.get("version", 1), n["id"]))
    edges = edges[:GRAPH_MAX_EDGES]
    nodes = nodes[:GRAPH_MAX_NODES]

    graph = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "updated_at": current_timestamp(),
        "nodes": nodes,
        "edges": edges,
    }

    save_memory_graph(graph)
    return graph


def sync_memory_graph():
    return rebuild_memory_graph()


def clear_memory_graph():
    save_memory_graph({
        "schema_version": GRAPH_SCHEMA_VERSION,
        "updated_at": current_timestamp(),
        "nodes": [],
        "edges": [],
    })


def get_memory_graph(memory_text=None, memory_id=None, include_archived=True, max_nodes=50):
    graph = rebuild_memory_graph()
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not memory_text and not memory_id:
        return {
            "schema_version": graph.get("schema_version", GRAPH_SCHEMA_VERSION),
            "updated_at": graph.get("updated_at"),
            "nodes": nodes[:max_nodes],
            "edges": edges,
        }

    target_id = memory_id
    if not target_id and memory_text:
        for node in nodes:
            if node.get("memory") == memory_text:
                target_id = node.get("id")
                break

    if not target_id:
        return {
            "schema_version": graph.get("schema_version", GRAPH_SCHEMA_VERSION),
            "updated_at": graph.get("updated_at"),
            "nodes": [],
            "edges": [],
        }

    neighbor_ids = {target_id}
    for edge in edges:
        if edge.get("source") == target_id:
            neighbor_ids.add(edge.get("target"))
        if edge.get("target") == target_id:
            neighbor_ids.add(edge.get("source"))

    selected_nodes = [node for node in nodes if node.get("id") in neighbor_ids]

    if not include_archived:
        selected_nodes = [
            node for node in selected_nodes
            if node.get("status") != "archived"
        ]

    selected_ids = {node.get("id") for node in selected_nodes}
    selected_edges = [
        edge for edge in edges
        if edge.get("source") in selected_ids
        and edge.get("target") in selected_ids
    ]

    return {
        "schema_version": graph.get("schema_version", GRAPH_SCHEMA_VERSION),
        "updated_at": graph.get("updated_at"),
        "nodes": selected_nodes[:max_nodes],
        "edges": selected_edges,
    }


def get_graph_neighbors(memory_text=None, memory_id=None, direction="both", max_results=20):
    graph = rebuild_memory_graph()
    nodes = {node.get("id"): node for node in graph.get("nodes", [])}

    target_id = memory_id
    if not target_id and memory_text:
        for node in graph.get("nodes", []):
            if node.get("memory") == memory_text:
                target_id = node.get("id")
                break

    if not target_id or target_id not in nodes:
        return []

    direction = str(direction or "both").strip().lower()
    if direction not in {"in", "out", "both"}:
        direction = "both"

    results = []
    seen = set()

    for edge in graph.get("edges", []):
        source = edge.get("source")
        target = edge.get("target")

        if direction == "out" and source != target_id:
            continue
        if direction == "in" and target != target_id:
            continue
        if direction == "both" and source != target_id and target != target_id:
            continue

        neighbor_id = target if source == target_id else source
        if neighbor_id in seen or neighbor_id not in nodes:
            continue

        seen.add(neighbor_id)
        neighbor = nodes[neighbor_id]

        neighbor_kind = neighbor.get("kind", "memory")
        results.append({
            "direction": "outgoing" if source == target_id else "incoming",
            "relation": edge.get("relation") or edge.get("type"),
            "edge_type": edge.get("type"),
            "confidence": edge.get("confidence", 0.0),
            "evidence": edge.get("evidence", ""),
            "memory_id": neighbor_id if neighbor_kind == "memory" else None,
            "memory": neighbor.get("memory", ""),
            "kind": neighbor_kind,
            "name": neighbor.get("name", ""),
            "entity_id": neighbor_id if neighbor_kind == "entity" else None,
            "entity_type": neighbor.get("type", "") if neighbor_kind == "entity" else "",
            "status": neighbor.get("status", ""),
            "temporal_status": neighbor.get("temporal_status", ""),
            "version": neighbor.get("version", 1),
        })

    return results[:max_results]


def get_memory_entities(memory_text=None, memory_id=None):
    """Return entities linked to one memory."""
    target_id = memory_id

    if not target_id and memory_text:
        target = _find_memory_by_text(str(memory_text).strip())
        if target:
            target_id = target.get("memory_id")

    if not target_id:
        return []

    return get_entities_for_memory(target_id)


# ==================================================
# Load Embedding Model
# ==================================================

embedding_model = SentenceTransformer(MODEL_NAME)


# ==================================================
# Time Helpers
# ==================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(timestamp):
    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(timestamp)
    except (ValueError, TypeError):
        return None


def days_since(timestamp):
    parsed = parse_timestamp(timestamp)

    if parsed is None:
        return 0

    now = datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    difference = now - parsed

    return max(0, difference.total_seconds() / 86400)


# ==================================================
# ID Helpers
# ==================================================

def generate_memory_id():
    return str(uuid.uuid4())


def generate_chain_id():
    return str(uuid.uuid4())


# ==================================================
# Normalize Importance
# ==================================================

def normalize_importance(importance):
    try:
        importance = int(importance)
    except (ValueError, TypeError):
        importance = 1

    return max(1, min(5, importance))


# ==================================================
# Memory Confidence
# ==================================================

INITIAL_CONFIDENCE_HIGH = 0.90
INITIAL_CONFIDENCE_MEDIUM = 0.80
INITIAL_CONFIDENCE_LOW = 0.70
CONFIDENCE_REINFORCEMENT_STEP = 0.03
CONFIDENCE_UPDATE_STEP = 0.05
CONFIDENCE_MIN = 0.20
CONFIDENCE_MAX = 0.99


def normalize_confidence(value, default=INITIAL_CONFIDENCE_MEDIUM):
    try:
        confidence = float(value)
    except (ValueError, TypeError):
        confidence = default
    return round(max(CONFIDENCE_MIN, min(CONFIDENCE_MAX, confidence)), 4)


def initial_memory_confidence(importance):
    importance = normalize_importance(importance)
    if importance >= 4:
        return INITIAL_CONFIDENCE_HIGH
    if importance >= 3:
        return INITIAL_CONFIDENCE_MEDIUM
    return INITIAL_CONFIDENCE_LOW


def calculate_confidence_score(item):
    if not isinstance(item, dict):
        return INITIAL_CONFIDENCE_LOW

    confidence = normalize_confidence(
        item.get(
            "confidence",
            initial_memory_confidence(item.get("importance", 1)),
        )
    )

    try:
        access_count = max(0, int(item.get("access_count", 0)))
    except (ValueError, TypeError):
        access_count = 0

    reinforcement = min(0.06, access_count * 0.01)

    return normalize_confidence(
        confidence + reinforcement,
        default=confidence,
    )


def reinforce_confidence(item, amount=CONFIDENCE_REINFORCEMENT_STEP):
    if not isinstance(item, dict):
        return False

    current = normalize_confidence(
        item.get(
            "confidence",
            initial_memory_confidence(item.get("importance", 1)),
        )
    )

    item["confidence"] = normalize_confidence(
        current + amount,
        default=current,
    )

    return True


# ==================================================
# Temporal Helpers
# ==================================================

def normalize_version(value):
    try:
        value = int(value)
    except (ValueError, TypeError):
        value = 1

    return max(1, value)


def normalize_temporal_status(value, default=TEMPORAL_CURRENT):
    if value in [
        TEMPORAL_CURRENT,
        TEMPORAL_HISTORICAL,
        TEMPORAL_ENDED,
    ]:
        return value
    return default


def normalize_temporal_event(value, default="NONE"):
    if not isinstance(value, str):
        return default

    value = value.strip().upper()

    if value in TEMPORAL_EVENTS:
        return value

    return default


def normalize_id(value, fallback_factory):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback_factory()


def normalize_derived_from(value):
    if not isinstance(value, list):
        return []

    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def normalize_provenance(value):
    if not isinstance(value, list):
        return []

    normalized = []

    for entry in value:
        if not isinstance(entry, dict):
            continue

        timestamp = entry.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp.strip():
            timestamp = current_timestamp()

        action = entry.get("action", "UNKNOWN")
        if not isinstance(action, str) or not action.strip():
            action = "UNKNOWN"
        action = action.strip().upper()

        event = normalize_temporal_event(
            entry.get("event", "NONE"),
            default="NONE",
        )

        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            reason = ""

        source_text = entry.get("source_text", "")
        if not isinstance(source_text, str):
            source_text = ""
        source_text = source_text.strip()[:PROVENANCE_SOURCE_MAX_CHARS]

        related_memory_ids = normalize_derived_from(
            entry.get("related_memory_ids")
        )

        normalized.append({
            "timestamp": timestamp,
            "action": action,
            "event": event,
            "reason": reason.strip(),
            "source_text": source_text,
            "related_memory_ids": related_memory_ids,
        })

    return normalized[-PROVENANCE_MAX_ENTRIES:]


def append_provenance(
    item,
    action,
    reason="",
    source_text="",
    event="NONE",
    related_memory_ids=None,
):
    if not isinstance(item, dict):
        return False

    provenance = normalize_provenance(item.get("provenance"))

    if not isinstance(source_text, str):
        source_text = ""

    entry = {
        "timestamp": current_timestamp(),
        "action": str(action or "UNKNOWN").strip().upper(),
        "event": normalize_temporal_event(event, default="NONE"),
        "reason": str(reason or "").strip(),
        "source_text": source_text.strip()[:PROVENANCE_SOURCE_MAX_CHARS],
        "related_memory_ids": normalize_derived_from(related_memory_ids),
    }

    provenance.append(entry)
    item["provenance"] = provenance[-PROVENANCE_MAX_ENTRIES:]
    return True


# ==================================================
# Causal Reasoning Helpers
# ==================================================

def normalize_causal_relation(value):
    if not isinstance(value, str):
        return None

    relation = value.strip().upper()

    if relation == "RESULTS IN":
        relation = "RESULTS_IN"

    if relation not in CAUSAL_RELATIONS:
        return None

    return relation


def normalize_causal_links(value):
    if not isinstance(value, list):
        return []

    normalized = []

    for entry in value:
        if not isinstance(entry, dict):
            continue

        target_memory_id = entry.get("target_memory_id")
        if not isinstance(target_memory_id, str) or not target_memory_id.strip():
            continue

        relation = normalize_causal_relation(entry.get("relation"))
        if relation is None:
            continue

        try:
            confidence = float(entry.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0

        confidence = round(
            max(0.0, min(1.0, confidence)),
            4,
        )

        if confidence < CAUSAL_MIN_CONFIDENCE:
            continue

        evidence = entry.get("evidence", "")
        if not isinstance(evidence, str):
            evidence = ""

        timestamp = entry.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp.strip():
            timestamp = current_timestamp()

        normalized.append({
            "target_memory_id": target_memory_id.strip(),
            "relation": relation,
            "confidence": confidence,
            "evidence": evidence.strip()[:PROVENANCE_SOURCE_MAX_CHARS],
            "timestamp": timestamp,
        })

    return normalized[-CAUSAL_MAX_LINKS:]


def append_causal_link(
    source_memory,
    target_memory_id,
    relation,
    confidence=1.0,
    evidence="",
):
    if not isinstance(source_memory, dict):
        return False

    if not isinstance(target_memory_id, str) or not target_memory_id.strip():
        return False

    relation = normalize_causal_relation(relation)
    if relation is None:
        return False

    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        return False

    confidence = round(max(0.0, min(1.0, confidence)), 4)

    if confidence < CAUSAL_MIN_CONFIDENCE:
        return False

    links = normalize_causal_links(source_memory.get("causal_links"))

    target_memory_id = target_memory_id.strip()
    updated = False

    for link in links:
        if (
            link.get("target_memory_id") == target_memory_id
            and link.get("relation") == relation
        ):
            link["confidence"] = max(
                float(link.get("confidence", 0.0)),
                confidence,
            )
            if evidence:
                link["evidence"] = str(evidence).strip()[:PROVENANCE_SOURCE_MAX_CHARS]
            link["timestamp"] = current_timestamp()
            updated = True
            break

    if not updated:
        links.append({
            "target_memory_id": target_memory_id,
            "relation": relation,
            "confidence": confidence,
            "evidence": str(evidence or "").strip()[:PROVENANCE_SOURCE_MAX_CHARS],
            "timestamp": current_timestamp(),
        })

    source_memory["causal_links"] = links[-CAUSAL_MAX_LINKS:]
    return True


def _find_memory_by_id(memory_id):
    if not memory_id:
        return None

    for item in get_memory() + get_archived_memory():
        if item.get("memory_id") == memory_id:
            return item

    return None


def _find_memory_by_text(memory_text):
    if not memory_text:
        return None

    for item in get_memory() + get_archived_memory():
        if item.get("memory") == memory_text:
            return item

    return None


def _find_memory_by_text_or_semantic(memory_text, threshold=0.55):
    """Resolve a memory by exact text first, then by semantic similarity."""
    if not isinstance(memory_text, str) or not memory_text.strip():
        return None

    query = memory_text.strip()

    exact = _find_memory_by_text(query)
    if exact is not None:
        return exact

    try:
        similar = find_similar_memories(
            query,
            threshold=threshold,
            max_results=1,
        )
    except Exception:
        similar = []

    if similar:
        matched_text = similar[0].get("memory")
        if matched_text:
            return _find_memory_by_text(matched_text)

    try:
        archived_matches = search_archived_memory(
            query,
            max_results=1,
            threshold=threshold,
        )
    except Exception:
        archived_matches = []

    if archived_matches:
        matched_text = archived_matches[0].get("memory")
        if matched_text:
            return _find_memory_by_text(matched_text)

    return None


def _add_causal_relationship_impl(
    source_memory_text,
    target_memory_text,
    relation="CAUSES",
    confidence=1.0,
    evidence="",
):
    """Create a directed causal relationship between two known memories."""
    source = _find_memory_by_text_or_semantic(
        source_memory_text.strip() if isinstance(source_memory_text, str) else "",
        threshold=0.55,
    )
    target = _find_memory_by_text_or_semantic(
        target_memory_text.strip() if isinstance(target_memory_text, str) else "",
        threshold=0.55,
    )

    if source is None or target is None:
        return False

    if source.get("memory_id") == target.get("memory_id"):
        return False

    if normalize_causal_relation(relation) is None:
        return False

    if not append_causal_link(
        source,
        target.get("memory_id"),
        relation,
        confidence=confidence,
        evidence=evidence,
    ):
        return False

    now = current_timestamp()

    # Persist the relationship on whichever side currently owns the source item.
    source_id = source.get("memory_id")
    active = get_memory()
    archive = get_archived_memory()

    for item in active:
        if item.get("memory_id") == source_id:
            item["causal_links"] = normalize_causal_links(source.get("causal_links"))
            item["updated_at"] = now
            break

    for item in archive:
        if item.get("memory_id") == source_id:
            item["causal_links"] = normalize_causal_links(source.get("causal_links"))
            item["updated_at"] = now
            break

    save_memory(active)
    save_archived_memory(archive)

    append_provenance(
        source,
        "CAUSAL_LINK",
        reason=f"causal_relation:{normalize_causal_relation(relation)}",
        source_text=evidence,
        event="NONE",
        related_memory_ids=[target.get("memory_id")],
    )

    # Re-save provenance without changing historical IDs.
    active = get_memory()
    archive = get_archived_memory()
    for item in active:
        if item.get("memory_id") == source_id:
            item["provenance"] = normalize_provenance(source.get("provenance"))
            item["causal_links"] = normalize_causal_links(source.get("causal_links"))
            break
    for item in archive:
        if item.get("memory_id") == source_id:
            item["provenance"] = normalize_provenance(source.get("provenance"))
            item["causal_links"] = normalize_causal_links(source.get("causal_links"))
            break

    save_memory(active)
    save_archived_memory(archive)
    sync_memory_graph()
    return True


def add_causal_relationship(
    source_memory_text,
    target_memory_text,
    relation="CAUSES",
    confidence=1.0,
    evidence="",
):
    """Idempotent public causal-relation mutation."""
    from memory_integrity import run_idempotent

    payload = {
        "source_memory": str(source_memory_text or "").strip(),
        "target_memory": str(target_memory_text or "").strip(),
        "relation": str(relation or "CAUSES").strip().upper(),
        "confidence": round(float(confidence or 0.0), 4),
        "evidence": str(evidence or "").strip(),
    }
    result = run_idempotent(
        "MEMORY_CAUSAL_UPSERT",
        payload,
        lambda: _add_causal_relationship_impl(
            source_memory_text,
            target_memory_text,
            relation=relation,
            confidence=confidence,
            evidence=evidence,
        ),
    )
    return bool(result.get("result"))


def get_memory_causality(memory_text=None, memory_id=None, direction="both"):
    """Return explicit causal links using exact or semantic memory lookup."""
    if not memory_text and not memory_id:
        return []

    direction = str(direction or "both").strip().lower()
    if direction not in {"in", "out", "both"}:
        direction = "both"

    active = get_memory()
    archive = get_archived_memory()
    all_items = active + archive

    target = _find_memory_by_id(memory_id) if memory_id else None

    # Exact match first.
    query_text = str(memory_text or "").strip()
    if target is None and query_text:
        target = _find_memory_by_text(query_text)

    # Semantic fallback so commands such as /causal Abaqus can resolve
    # the stored memory even when the memory text is a longer sentence.
    if target is None and query_text:
        similar = find_similar_memories(
            query_text,
            threshold=0.60,
            max_results=1,
        )

        if similar:
            matched_text = similar[0].get("memory")
            target = next(
                (item for item in all_items if item.get("memory") == matched_text),
                None,
            )

        if target is None:
            archived_matches = search_archived_memory(
                query_text,
                max_results=1,
                threshold=0.60,
            )

            if archived_matches:
                matched_text = archived_matches[0].get("memory")
                target = next(
                    (item for item in all_items if item.get("memory") == matched_text),
                    None,
                )

    if target is None:
        return []
    target_id = target.get("memory_id")
    results = []

    if direction in {"out", "both"}:
        for link in normalize_causal_links(target.get("causal_links")):
            linked = _find_memory_by_id(link.get("target_memory_id"))
            results.append({
                "direction": "outgoing",
                "source_memory_id": target_id,
                "source_memory": target.get("memory", ""),
                "target_memory_id": link.get("target_memory_id"),
                "target_memory": linked.get("memory", "") if linked else "[missing]",
                "target_status": linked.get("status", "") if linked else "missing",
                "relation": link.get("relation"),
                "confidence": link.get("confidence", 0.0),
                "evidence": link.get("evidence", ""),
                "timestamp": link.get("timestamp", ""),
            })

    if direction in {"in", "both"}:
        for item in all_items:
            if item.get("memory_id") == target_id:
                continue

            for link in normalize_causal_links(item.get("causal_links")):
                if link.get("target_memory_id") != target_id:
                    continue

                results.append({
                    "direction": "incoming",
                    "source_memory_id": item.get("memory_id"),
                    "source_memory": item.get("memory", ""),
                    "target_memory_id": target_id,
                    "target_memory": target.get("memory", ""),
                    "target_status": target.get("status", ""),
                    "relation": link.get("relation"),
                    "confidence": link.get("confidence", 0.0),
                    "evidence": link.get("evidence", ""),
                    "timestamp": link.get("timestamp", ""),
                })

    results.sort(key=lambda x: x.get("timestamp", ""))
    return results


def get_memory_provenance(memory_text=None, memory_id=None):
    """Return provenance for a memory using exact or semantic lookup.

    The memory text shown to the user is not always identical to the text
    stored by the memory manager, so human-friendly queries must have the
    same semantic fallback behavior as /history.
    """
    if not memory_text and not memory_id:
        return []

    active = get_memory()
    archive = get_archived_memory()
    all_items = active + archive

    target = None
    query_text = str(memory_text or "").strip()

    # 1. Exact lookup by memory ID / memory text.
    for item in all_items:
        if memory_id and item.get("memory_id") == memory_id:
            target = item
            break
        if query_text and item.get("memory") == query_text:
            target = item
            break

    # 2. Semantic fallback for natural-language /provenance queries.
    if target is None and query_text:
        similar = find_similar_memories(
            query_text,
            threshold=0.60,
            max_results=1,
        )

        if similar:
            matched_text = similar[0].get("memory")
            target = next(
                (
                    item
                    for item in all_items
                    if item.get("memory") == matched_text
                ),
                None,
            )

        # The matching version may be archived.
        if target is None:
            archived_matches = search_archived_memory(
                query_text,
                max_results=1,
                threshold=0.60,
            )

            if archived_matches:
                matched_text = archived_matches[0].get("memory")
                target = next(
                    (
                        item
                        for item in all_items
                        if item.get("memory") == matched_text
                    ),
                    None,
                )

    if target is None:
        return []

    return normalize_provenance(target.get("provenance"))


def get_memory_chain(memory_text=None, memory_id=None):
    """Return every version in the same temporal chain.

    Exact memory text is preferred. If the caller provides a natural-language
    query instead of the exact stored memory, fall back to semantic search so
    commands such as ``/history Project Atlas`` or the original user sentence
    can still resolve to the correct memory chain.
    """
    if not memory_text and not memory_id:
        return []

    active = get_memory()
    archive = get_archived_memory()
    all_items = active + archive

    target = None
    query_text = str(memory_text or "").strip()

    # 1. Exact lookup by memory ID / memory text.
    for item in all_items:
        if memory_id and item.get("memory_id") == memory_id:
            target = item
            break
        if query_text and item.get("memory") == query_text:
            target = item
            break

    # 2. Semantic fallback for human-friendly /history queries.
    if target is None and query_text:
        similar = find_similar_memories(
            query_text,
            threshold=0.60,
            max_results=1,
        )

        if similar:
            matched_text = similar[0].get("memory")
            target = next(
                (
                    item
                    for item in all_items
                    if item.get("memory") == matched_text
                ),
                None,
            )

        # The relevant version may be archived, so check the archive too.
        if target is None:
            archived_matches = search_archived_memory(
                query_text,
                max_results=1,
                threshold=0.60,
            )

            if archived_matches:
                matched_text = archived_matches[0].get("memory")
                target = next(
                    (
                        item
                        for item in all_items
                        if item.get("memory") == matched_text
                    ),
                    None,
                )

    if target is None:
        return []

    chain_id = target.get("chain_id")
    if not chain_id:
        return [target]

    chain = [
        item
        for item in all_items
        if item.get("chain_id") == chain_id
    ]

    chain.sort(
        key=lambda item: (
            normalize_version(item.get("version", 1)),
            item.get("valid_from", ""),
        )
    )

    return chain


def normalize_temporal_date(value):
    """Normalize a temporal date/timestamp without inventing one."""
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    parsed = parse_timestamp(value)
    if parsed is None:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc).isoformat()

    return parsed.isoformat()


def temporal_interval_contains(item, target_datetime):
    """Return True when target_datetime falls inside the item's validity interval."""
    if not isinstance(item, dict) or target_datetime is None:
        return False

    valid_from = parse_timestamp(item.get("valid_from"))
    valid_to = parse_timestamp(item.get("valid_to")) if item.get("valid_to") else None

    if valid_from is None:
        return False

    if valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=timezone.utc)

    if target_datetime.tzinfo is None:
        target_datetime = target_datetime.replace(tzinfo=timezone.utc)

    if target_datetime < valid_from:
        return False

    if valid_to is not None:
        if valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)
        return target_datetime < valid_to

    return True


def get_memory_as_of(memory_text, when):
    """Return the temporal version of a memory that was valid at a given time."""
    if not memory_text or not when:
        return None

    history = get_memory_chain(memory_text=memory_text.strip())
    if not history:
        return None

    target = parse_timestamp(when)
    if target is None:
        return None

    candidates = [
        item
        for item in history
        if temporal_interval_contains(item, target)
    ]

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            normalize_version(item.get("version", 1)),
            item.get("valid_from", ""),
        ),
        reverse=True,
    )

    return candidates[0]


def consolidate_memories(
    memory_texts,
    new_memory,
    memory_type="other",
    importance=1,
    source_text="",
    provenance_reason="semantic_consolidation",
):
    """Idempotent semantic-memory consolidation."""
    from memory_integrity import run_idempotent

    payload = {
        "memory_texts": list(memory_texts or []),
        "new_memory": str(new_memory or "").strip(),
        "memory_type": str(memory_type or "other").strip(),
        "importance": importance,
        "source_text": str(source_text or "").strip(),
        "provenance_reason": str(provenance_reason or "semantic_consolidation").strip(),
    }
    result = run_idempotent(
        "MEMORY_CONSOLIDATE",
        payload,
        lambda: _consolidate_memories_impl(
            memory_texts,
            new_memory,
            memory_type=memory_type,
            importance=importance,
            source_text=source_text,
            provenance_reason=provenance_reason,
        ),
    )
    return bool(result.get("result"))



# ==================================================
# Determine Lifecycle State
# ==================================================

def determine_lifecycle_state(item):
    if not isinstance(item, dict):
        return "active"

    importance = normalize_importance(item.get("importance", 1))

    if importance >= HIGH_IMPORTANCE_THRESHOLD:
        return "active"

    last_accessed = item.get("last_accessed")
    age_days = days_since(last_accessed)

    if age_days < AGING_DAYS:
        return "active"

    if age_days < DECAYING_DAYS:
        return "aging"

    return "decaying"


# ==================================================
# Normalize Memory Item
# ==================================================

def normalize_memory_item(item, archived=False):
    if not isinstance(item, dict):
        return None

    memory_text = item.get("memory", "")

    if not isinstance(memory_text, str):
        return None

    memory_text = memory_text.strip()

    if not memory_text:
        return None

    memory_type = item.get("type", "other")

    if not isinstance(memory_type, str):
        memory_type = "other"

    importance = normalize_importance(item.get("importance", 1))

    created_at = item.get("created_at")
    if not isinstance(created_at, str):
        created_at = current_timestamp()

    updated_at = item.get("updated_at")
    if not isinstance(updated_at, str):
        updated_at = created_at

    last_accessed = item.get("last_accessed")
    if not isinstance(last_accessed, str):
        last_accessed = created_at

    access_count = item.get("access_count", 0)

    try:
        access_count = int(access_count)
    except (ValueError, TypeError):
        access_count = 0

    access_count = max(0, access_count)

    confidence = normalize_confidence(
        item.get(
            "confidence",
            initial_memory_confidence(importance),
        ),
        default=initial_memory_confidence(importance),
    )

    memory_id = normalize_id(
        item.get("memory_id"),
        generate_memory_id,
    )

    chain_id = normalize_id(
        item.get("chain_id"),
        lambda: memory_id,
    )

    version = normalize_version(item.get("version", 1))

    valid_from = item.get("valid_from")
    if not isinstance(valid_from, str):
        valid_from = created_at

    valid_to = item.get("valid_to")
    if not isinstance(valid_to, str):
        valid_to = None

    supersedes = item.get("supersedes")
    if not isinstance(supersedes, str) or not supersedes.strip():
        supersedes = None
    else:
        supersedes = supersedes.strip()

    superseded_by = item.get("superseded_by")
    if not isinstance(superseded_by, str) or not superseded_by.strip():
        superseded_by = None
    else:
        superseded_by = superseded_by.strip()

    temporal_status = normalize_temporal_status(
        item.get("temporal_status"),
        TEMPORAL_CURRENT,
    )

    derived_from = normalize_derived_from(item.get("derived_from"))
    provenance = normalize_provenance(item.get("provenance"))
    causal_links = normalize_causal_links(item.get("causal_links"))

    normalized = {
        "memory": memory_text,
        "type": memory_type,
        "importance": importance,
        "confidence": confidence,
        "created_at": created_at,
        "updated_at": updated_at,
        "last_accessed": last_accessed,
        "access_count": access_count,
        "status": "archived" if archived else None,
        "memory_id": memory_id,
        "chain_id": chain_id,
        "version": version,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "supersedes": supersedes,
        "superseded_by": superseded_by,
        "temporal_status": temporal_status,
        "derived_from": derived_from,
        "provenance": provenance,
        "causal_links": causal_links,
    }

    if archived:
        archived_at = item.get("archived_at")
        if not isinstance(archived_at, str):
            archived_at = current_timestamp()

        normalized["archived_at"] = archived_at

        archive_reason = item.get("archive_reason", "")
        if not isinstance(archive_reason, str):
            archive_reason = ""

        normalized["archive_reason"] = archive_reason
    else:
        existing_status = item.get("status")

        if existing_status in ["active", "aging", "decaying"]:
            normalized["status"] = existing_status
        else:
            normalized["status"] = determine_lifecycle_state(normalized)

    return normalized


# ==================================================
# Generic JSON Helpers
# ==================================================

def load_json_list(filename):
    data = load_json_document(
        filename,
        list,
        expected_type=list,
    )
    return data if isinstance(data, list) else []


def save_json_list(filename, data):
    if not isinstance(data, list):
        data = []
    save_json_document(filename, data, indent=4)


# ==================================================
# Load Active Memory
# ==================================================

def get_memory():
    raw_memory = load_json_list(MEMORY_FILE)

    normalized_memory = []
    changed = False

    for item in raw_memory:
        normalized_item = normalize_memory_item(item, archived=False)

        if normalized_item is None:
            changed = True
            continue

        normalized_memory.append(normalized_item)

        if normalized_item != item:
            changed = True

    if changed:
        save_memory(normalized_memory)

    return normalized_memory


# ==================================================
# Save Active Memory
# ==================================================

def save_memory(memory):
    save_json_list(MEMORY_FILE, memory)


# ==================================================
# Load Archive
# ==================================================

def get_archived_memory():
    raw_archive = load_json_list(ARCHIVE_FILE)

    normalized_archive = []
    changed = False

    for item in raw_archive:
        normalized_item = normalize_memory_item(item, archived=True)

        if normalized_item is None:
            changed = True
            continue

        normalized_archive.append(normalized_item)

        if normalized_item != item:
            changed = True

    if changed:
        save_archived_memory(normalized_archive)

    return normalized_archive


# ==================================================
# Save Archive
# ==================================================

def save_archived_memory(memory):
    save_json_list(ARCHIVE_FILE, memory)


# ==================================================
# Load Embeddings
# ==================================================

def load_embeddings():
    embeddings = load_json_document(
        EMBEDDINGS_FILE,
        dict,
        expected_type=dict,
    )
    return embeddings if isinstance(embeddings, dict) else {}


# ==================================================
# Save Embeddings
# ==================================================

def save_embeddings(embeddings):
    if not isinstance(embeddings, dict):
        embeddings = {}
    save_json_document(EMBEDDINGS_FILE, embeddings, indent=2)


# ==================================================
# Create Embedding
# ==================================================

def create_embedding(text):
    vector = embedding_model.encode(text, normalize_embeddings=True)
    return vector.tolist()


# ==================================================
# Cosine Similarity
# ==================================================

def cosine_similarity(vector_a, vector_b):
    dot_product = sum(a * b for a, b in zip(vector_a, vector_b))

    magnitude_a = sum(a * a for a in vector_a) ** 0.5
    magnitude_b = sum(b * b for b in vector_b) ** 0.5

    if magnitude_a == 0 or magnitude_b == 0:
        return 0

    return dot_product / (magnitude_a * magnitude_b)


# ==================================================
# Reinforcement Score
# ==================================================

def calculate_reinforcement_score(access_count):
    try:
        access_count = int(access_count)
    except (ValueError, TypeError):
        access_count = 0

    if access_count <= 0:
        return 0.0

    score = math.log1p(access_count) / math.log1p(20)
    return min(1.0, score)


# ==================================================
# Lifecycle Score
# ==================================================

def calculate_lifecycle_score(item):
    if not isinstance(item, dict):
        return 0

    importance = normalize_importance(item.get("importance", 1))
    access_count = item.get("access_count", 0)
    reinforcement = calculate_reinforcement_score(access_count)
    status = determine_lifecycle_state(item)

    if status == "active":
        lifecycle_value = 1.0
    elif status == "aging":
        lifecycle_value = 0.65
    else:
        lifecycle_value = 0.30

    importance_value = importance / 5

    return (
        lifecycle_value * 0.50
        + importance_value * 0.30
        + reinforcement * 0.20
    )


# ==================================================
# Update Memory Lifecycle
# ==================================================

def update_memory_lifecycle():
    memory = get_memory()

    if not memory:
        return False

    changed = False

    for item in memory:
        old_status = item.get("status")
        new_status = determine_lifecycle_state(item)

        if old_status != new_status:
            item["status"] = new_status
            item["updated_at"] = current_timestamp()
            changed = True

    if changed:
        save_memory(memory)

    return changed


# ==================================================
# Archive Eligibility
# ==================================================

def calculate_archive_score(item):
    """Higher score means stronger reason to archive."""
    if not isinstance(item, dict):
        return 0.0

    importance = normalize_importance(item.get("importance", 1))
    access_count = max(0, int(item.get("access_count", 0)))
    inactivity_days = days_since(item.get("last_accessed"))

    age_score = min(1.0, inactivity_days / ARCHIVE_DAYS)
    importance_pressure = (5 - importance) / 4
    access_protection = min(1.0, access_count / 10)
    unused_score = 1.0 - access_protection

    lifecycle = item.get("status") or determine_lifecycle_state(item)

    lifecycle_pressure = {
        "active": 0.0,
        "aging": 0.45,
        "decaying": 1.0,
    }.get(lifecycle, 0.0)

    return (
        age_score * 0.35
        + importance_pressure * 0.30
        + unused_score * 0.15
        + lifecycle_pressure * 0.20
    )


def should_archive_memory(item):
    if not isinstance(item, dict):
        return False

    importance = normalize_importance(item.get("importance", 1))
    access_count = max(0, int(item.get("access_count", 0)))
    status = determine_lifecycle_state(item)
    inactivity_days = days_since(item.get("last_accessed"))

    if importance >= HIGH_IMPORTANCE_THRESHOLD:
        return False

    if access_count > ARCHIVE_MAX_ACCESS_COUNT:
        return False

    if status != "decaying":
        return False

    if inactivity_days < ARCHIVE_DAYS:
        return False

    return importance <= ARCHIVE_IMPORTANCE_THRESHOLD


# ==================================================
# Archive One Memory
# ==================================================

def _archive_memory_impl(
    memory_text,
    reason="automatic",
    provenance_action="ARCHIVE",
    source_text="",
    temporal_event="NONE",
    related_memory_ids=None,
):
    if not memory_text:
        return False

    memory = get_memory()
    archive = get_archived_memory()

    target = None
    remaining = []

    for item in memory:
        if item.get("memory") == memory_text and target is None:
            target = item
        else:
            remaining.append(item)

    if target is None:
        return False

    now = current_timestamp()

    target = dict(target)
    target["status"] = "archived"
    target["archived_at"] = now
    target["archive_reason"] = reason
    target["updated_at"] = now
    append_provenance(
        target,
        provenance_action,
        reason=reason,
        source_text=source_text,
        event=temporal_event,
        related_memory_ids=related_memory_ids,
    )

    archive = [
        item for item in archive
        if item.get("memory") != memory_text
    ]
    archive.append(target)

    save_memory(remaining)
    save_archived_memory(archive)
    sync_memory_graph()

    return True


def archive_memory(
    memory_text,
    reason="automatic",
    provenance_action="ARCHIVE",
    source_text="",
    temporal_event="NONE",
    related_memory_ids=None,
):
    """Idempotent Memory archive transition."""
    from memory_integrity import run_idempotent

    payload = {
        "memory": str(memory_text or "").strip(),
        "reason": str(reason or "automatic").strip(),
        "provenance_action": str(provenance_action or "ARCHIVE").strip().upper(),
        "source_text": str(source_text or "").strip(),
        "temporal_event": str(temporal_event or "NONE").strip().upper(),
        "related_memory_ids": list(related_memory_ids or []),
    }
    result = run_idempotent(
        "MEMORY_ARCHIVE",
        payload,
        lambda: _archive_memory_impl(
            memory_text,
            reason=reason,
            provenance_action=provenance_action,
            source_text=source_text,
            temporal_event=temporal_event,
            related_memory_ids=related_memory_ids,
        ),
    )
    return bool(result.get("result"))



# ==================================================
# Intelligent Archive
# ==================================================

def archive_eligible_memories():
    """Move old, low-value, unused decaying memories to the archive."""
    update_memory_lifecycle()

    memory = get_memory()
    archive = get_archived_memory()

    if not memory:
        return []

    remaining = []
    archived_items = []
    now = current_timestamp()

    existing_archive_texts = {
        item.get("memory")
        for item in archive
        if isinstance(item, dict)
    }

    for item in memory:
        if not should_archive_memory(item):
            remaining.append(item)
            continue

        item = dict(item)
        item["status"] = "archived"
        item["archived_at"] = now
        item["archive_reason"] = "automatic_lifecycle"
        item["updated_at"] = now

        if item.get("memory") in existing_archive_texts:
            archive = [
                old_item
                for old_item in archive
                if old_item.get("memory") != item.get("memory")
            ]

        archive.append(item)
        existing_archive_texts.add(item.get("memory"))
        archived_items.append(item)

    if archived_items:
        save_memory(remaining)
        save_archived_memory(archive)
        sync_memory_graph()

    return archived_items


# ==================================================
# Restore Archived Memory
# ==================================================

def _restore_memory_impl(memory_text):
    if not memory_text:
        return False

    archive = get_archived_memory()
    memory = get_memory()

    target = None
    remaining_archive = []

    for item in archive:
        if item.get("memory") == memory_text and target is None:
            target = item
        else:
            remaining_archive.append(item)

    if target is None:
        return False

    for item in memory:
        if item.get("memory") == memory_text:
            return False

    now = current_timestamp()

    target = dict(target)
    target.pop("archived_at", None)
    target.pop("archive_reason", None)
    target["status"] = "active"
    target["confidence"] = normalize_confidence(
        target.get(
            "confidence",
            initial_memory_confidence(target.get("importance", 1)),
        )
    )
    target["last_accessed"] = now
    target["updated_at"] = now
    append_provenance(
        target,
        "RESTORE",
        reason="archive_restore",
    )

    if not target.get("temporal_status"):
        target["temporal_status"] = TEMPORAL_CURRENT

    memory.append(target)

    save_memory(memory)
    save_archived_memory(remaining_archive)

    # Restoring a memory is new evidence that its currently-active entities
    # are relevant again. Reinforce only entities that are already active;
    # archived entities still require the explicit Entity Recovery gate.
    try:
        from memory_entities import mark_entities_seen_for_memory
        mark_entities_seen_for_memory(target.get("memory_id"))
    except Exception:
        pass

    sync_memory_graph()

    embeddings = load_embeddings()
    if memory_text not in embeddings:
        embeddings[memory_text] = create_embedding(memory_text)
        save_embeddings(embeddings)

    return True


def restore_memory(memory_text):
    """Idempotent Memory archive->active transition."""
    from memory_integrity import run_idempotent

    payload = {"memory": str(memory_text or "").strip()}
    result = run_idempotent(
        "MEMORY_RESTORE",
        payload,
        lambda: _restore_memory_impl(memory_text),
    )
    return bool(result.get("result"))



# ==================================================
# Reinforce Memory
# ==================================================

def reinforce_memory(memory_text):
    if not memory_text:
        return False

    memory = get_memory()
    changed = False
    now = current_timestamp()

    for item in memory:
        if item.get("memory") == memory_text:
            try:
                current_count = int(item.get("access_count", 0))
            except (ValueError, TypeError):
                current_count = 0

            item["access_count"] = max(0, current_count) + 1
            reinforce_confidence(item)
            item["last_accessed"] = now
            item["status"] = "active"
            item["updated_at"] = now
            changed = True
            break

    if changed:
        save_memory(memory)

    return changed


# ==================================================
# Find Similar Memories
# ==================================================

def find_similar_memories(query, threshold=DEFAULT_SIMILARITY_THRESHOLD, max_results=10):
    if not query or not query.strip():
        return []

    build_missing_embeddings()
    embeddings = load_embeddings()

    if not embeddings:
        return []

    query_embedding = create_embedding(query)
    all_memory = get_memory()

    memory_lookup = {
        item.get("memory"): item
        for item in all_memory
        if isinstance(item, dict) and item.get("memory")
    }

    results = []

    for memory_text, memory_embedding in embeddings.items():
        item = memory_lookup.get(memory_text)

        if not item:
            continue

        similarity = cosine_similarity(query_embedding, memory_embedding)

        if similarity < threshold:
            continue

        results.append({
            "memory": memory_text,
            "type": item.get("type", "other"),
            "importance": normalize_importance(item.get("importance", 1)),
            "similarity": round(similarity, 4),
            "status": item.get("status", "active"),
            "access_count": item.get("access_count", 0),
            "confidence": calculate_confidence_score(item),
            "memory_id": item.get("memory_id"),
            "chain_id": item.get("chain_id"),
            "version": item.get("version", 1),
            "temporal_status": item.get("temporal_status", TEMPORAL_CURRENT),
        })

    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:max_results]


# ==================================================
# Find Duplicate
# ==================================================

def find_duplicate_memory(memory_text, threshold=DUPLICATE_THRESHOLD):
    results = find_similar_memories(
        memory_text,
        threshold=threshold,
        max_results=1,
    )

    if not results:
        return None

    return results[0]


# ==================================================
# Add Memory
# ==================================================

def _add_memory_impl(
    memory_text,
    memory_type="other",
    importance=1,
    chain_id=None,
    version=1,
    supersedes=None,
    valid_from=None,
    derived_from=None,
    source_text="",
    provenance_action="ADD",
    provenance_reason="new_memory",
    temporal_event="START",
    causal_links=None,
):
    if not memory_text:
        return False

    memory_text = memory_text.strip()
    if not memory_text:
        return False

    importance = normalize_importance(importance)
    memory = get_memory()

    for item in memory:
        if item.get("memory") == memory_text:
            return False

    for item in get_archived_memory():
        if item.get("memory") == memory_text:
            return restore_memory(memory_text)

    duplicate = find_duplicate_memory(memory_text)
    if duplicate:
        return False

    now = current_timestamp()
    normalized_valid_from = normalize_temporal_date(valid_from)
    valid_from = normalized_valid_from or now

    new_memory = {
        "memory": memory_text,
        "type": memory_type,
        "importance": importance,
        "confidence": initial_memory_confidence(importance),
        "created_at": now,
        "updated_at": now,
        "last_accessed": now,
        "access_count": 0,
        "status": "active",
        "memory_id": generate_memory_id(),
        "chain_id": chain_id or generate_chain_id(),
        "version": normalize_version(version),
        "valid_from": valid_from,
        "valid_to": None,
        "supersedes": supersedes,
        "superseded_by": None,
        "temporal_status": TEMPORAL_CURRENT,
        "derived_from": normalize_derived_from(derived_from),
        "provenance": [],
        "causal_links": normalize_causal_links(causal_links),
    }

    append_provenance(
        new_memory,
        provenance_action,
        reason=provenance_reason,
        source_text=source_text,
        event=temporal_event,
        related_memory_ids=derived_from,
    )

    memory.append(new_memory)
    save_memory(memory)
    sync_memory_graph()

    embeddings = load_embeddings()
    embeddings[memory_text] = create_embedding(memory_text)
    save_embeddings(embeddings)

    return True


def add_memory(
    memory_text,
    memory_type="other",
    importance=1,
    chain_id=None,
    version=1,
    supersedes=None,
    valid_from=None,
    derived_from=None,
    source_text="",
    provenance_action="ADD",
    provenance_reason="new_memory",
    temporal_event="START",
    causal_links=None,
):
    """Idempotent public Memory ingestion entry point."""
    from memory_integrity import run_idempotent

    payload = {
        "memory": str(memory_text or "").strip(),
        "memory_type": str(memory_type or "other").strip(),
        "importance": int(importance) if isinstance(importance, (int, float, str)) and str(importance).strip().lstrip("-").isdigit() else importance,
        "chain_id": chain_id,
        "version": version,
        "supersedes": supersedes,
        "valid_from": valid_from,
        "derived_from": derived_from or [],
        "source_text": str(source_text or "").strip(),
        "provenance_action": str(provenance_action or "ADD").strip().upper(),
        "provenance_reason": str(provenance_reason or "new_memory").strip(),
        "temporal_event": str(temporal_event or "START").strip().upper(),
        "causal_links": causal_links or [],
    }

    result = run_idempotent(
        "MEMORY_ADD",
        payload,
        lambda: _add_memory_impl(
            memory_text,
            memory_type=memory_type,
            importance=importance,
            chain_id=chain_id,
            version=version,
            supersedes=supersedes,
            valid_from=valid_from,
            derived_from=derived_from,
            source_text=source_text,
            provenance_action=provenance_action,
            provenance_reason=provenance_reason,
            temporal_event=temporal_event,
            causal_links=causal_links,
        ),
    )
    return bool(result.get("result"))



# ==================================================
# Update Memory
# ==================================================
def resolve_memory_conflict(
    old_memory,
    new_memory,
    memory_type="other",
    importance=1,
    effective_from=None,
    effective_to=None,
    source_text="",
    temporal_event="CHANGE",
):
    """Idempotent temporal Memory replacement preserving history."""
    from memory_integrity import run_idempotent

    payload = {
        "old_memory": str(old_memory or "").strip(),
        "new_memory": str(new_memory or "").strip(),
        "memory_type": str(memory_type or "other").strip(),
        "importance": importance,
        "effective_from": effective_from,
        "effective_to": effective_to,
        "source_text": str(source_text or "").strip(),
        "temporal_event": str(temporal_event or "CHANGE").strip().upper(),
    }
    result = run_idempotent(
        "MEMORY_UPDATE",
        payload,
        lambda: _resolve_memory_conflict_impl(
            old_memory,
            new_memory,
            memory_type=memory_type,
            importance=importance,
            effective_from=effective_from,
            effective_to=effective_to,
            source_text=source_text,
            temporal_event=temporal_event,
        ),
    )
    return bool(result.get("result"))



def update_memory(
    old_memory,
    new_memory,
    memory_type="other",
    importance=1,
    effective_from=None,
    source_text="",
    temporal_event="CHANGE",
):
    return resolve_memory_conflict(
        old_memory,
        new_memory,
        memory_type,
        importance,
        effective_from=effective_from,
        source_text=source_text,
        temporal_event=temporal_event,
    )


# ==================================================
# Resolve Memory Conflict With History Preservation
# ==================================================

def _resolve_memory_conflict_impl(
    old_memory,
    new_memory,
    memory_type="other",
    importance=1,
    effective_from=None,
    effective_to=None,
    source_text="",
    temporal_event="CHANGE",
):
    """Replace an outdated memory while preserving its temporal history."""
    if not old_memory or not new_memory:
        return False

    old_memory = old_memory.strip()
    new_memory = new_memory.strip()

    if not old_memory or not new_memory or old_memory == new_memory:
        return False

    active = get_memory()
    old_item = None

    for item in active:
        if item.get("memory") == old_memory:
            old_item = item
            break

    if old_item is None:
        return False

    normalized_effective_from = normalize_temporal_date(effective_from)
    if normalized_effective_from is None:
        normalized_effective_from = current_timestamp()

    old_valid_from = normalize_temporal_date(old_item.get("valid_from"))
    old_start = parse_timestamp(old_valid_from) if old_valid_from else None
    new_start = parse_timestamp(normalized_effective_from)

    if old_start and new_start and new_start < old_start:
        return False

    old_memory_id = old_item.get("memory_id") or generate_memory_id()
    chain_id = old_item.get("chain_id") or generate_chain_id()
    old_version = normalize_version(old_item.get("version", 1))
    new_version = old_version + 1

    if not archive_memory(
        old_memory,
        reason="conflict_replaced",
        provenance_action="SUPERSEDE",
        source_text=source_text,
        temporal_event=temporal_event,
    ):
        return False

    if not add_memory(
        new_memory,
        memory_type,
        importance,
        chain_id=chain_id,
        version=new_version,
        supersedes=old_memory_id,
        valid_from=normalized_effective_from,
        derived_from=[old_memory_id],
        source_text=source_text,
        provenance_action="UPDATE",
        provenance_reason="temporal_change",
        temporal_event=temporal_event,
    ):
        restore_memory(old_memory)
        return False

    active_after = get_memory()
    new_item = None

    for item in active_after:
        if item.get("memory") == new_memory:
            new_item = item
            break

    if new_item is None:
        restore_memory(old_memory)
        return False

    new_memory_id = new_item.get("memory_id") or generate_memory_id()

    new_item["valid_from"] = normalized_effective_from
    new_item["valid_to"] = None
    new_item["chain_id"] = chain_id
    new_item["version"] = new_version
    new_item["supersedes"] = old_memory_id
    new_item["superseded_by"] = None
    new_item["temporal_status"] = TEMPORAL_CURRENT
    new_item["updated_at"] = current_timestamp()

    archive = get_archived_memory()
    archived_old = None

    for item in archive:
        if item.get("memory") == old_memory:
            archived_old = item
            break

    if archived_old is not None:
        archived_old["valid_to"] = normalized_effective_from
        archived_old["superseded_by"] = new_memory_id
        archived_old["temporal_status"] = TEMPORAL_HISTORICAL
        archived_old["chain_id"] = chain_id
        archived_old["version"] = old_version
        append_provenance(
            archived_old,
            "SUPERSEDED_BY",
            reason="linked_to_new_version",
            source_text=source_text,
            event=temporal_event,
            related_memory_ids=[new_memory_id],
        )
        archived_old["updated_at"] = current_timestamp()
        save_archived_memory(archive)

    save_memory(active_after)
    sync_memory_graph()
    return True


def end_memory(
    memory_text,
    effective_to=None,
    reason="temporal_end",
    source_text="",
    temporal_event="END",
):
    """End the validity of a current memory without deleting its history."""
    if not memory_text or not memory_text.strip():
        return False

    memory_text = memory_text.strip()
    active = get_memory()
    target = None

    for item in active:
        if item.get("memory") == memory_text:
            target = item
            break

    if target is None:
        return False

    normalized_effective_to = normalize_temporal_date(effective_to)
    if normalized_effective_to is None:
        normalized_effective_to = current_timestamp()

    valid_from = parse_timestamp(target.get("valid_from"))
    valid_to = parse_timestamp(normalized_effective_to)

    if valid_from and valid_to:
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)

        if valid_to <= valid_from:
            return False

    chain_id = target.get("chain_id")
    memory_id = target.get("memory_id")

    if not archive_memory(
        memory_text,
        reason=reason,
        provenance_action="END",
        source_text=source_text,
        temporal_event=temporal_event,
    ):
        return False

    archive = get_archived_memory()
    archived_target = None

    for item in archive:
        if item.get("memory") == memory_text and item.get("memory_id") == memory_id:
            archived_target = item
            break

    if archived_target is None:
        for item in reversed(archive):
            if item.get("memory") == memory_text:
                archived_target = item
                break

    if archived_target is None:
        return False

    archived_target["valid_to"] = normalized_effective_to
    archived_target["temporal_status"] = TEMPORAL_ENDED
    archived_target["archive_reason"] = reason
    archived_target["chain_id"] = chain_id
    append_provenance(
        archived_target,
        "END_CONFIRMED",
        reason=reason,
        source_text=source_text,
        event=temporal_event,
    )
    archived_target["updated_at"] = current_timestamp()
    save_archived_memory(archive)
    sync_memory_graph()

    return True



def apply_causal_relations(causal_relations, source_text=""):
    """Apply explicitly supported causal relationships after governance."""
    if not causal_relations:
        return 0

    applied = 0
    for relation in causal_relations:
        if not isinstance(relation, dict):
            continue

        source_memory = str(relation.get("source_memory", "")).strip()
        target_memory = str(relation.get("target_memory", "")).strip()
        relation_type = relation.get("relation", "CAUSES")
        confidence = relation.get("confidence", 0.0)
        evidence = relation.get("evidence", "") or source_text

        if source_memory == "__NEW_MEMORY__" or target_memory == "__NEW_MEMORY__":
            # Caller should resolve this token to the actual memory text.
            continue

        if add_causal_relationship(
            source_memory,
            target_memory,
            relation_type,
            confidence=confidence,
            evidence=evidence,
        ):
            applied += 1

    return applied


# ==================================================
# Unified Memory Governance
# ==================================================

def _govern_memory_action_impl(
    action,
    memory_text="",
    memory_type="other",
    importance=1,
    old_memory="",
    similar_memories=None,
    consolidation_memory="",
    consolidation_type="other",
    consolidation_importance=1,
    effective_from=None,
    effective_to=None,
    source_text="",
    decision_reason="",
    temporal_event="NONE",
    causal_relations=None,
):
    """Central execution layer for memory actions."""
    action = str(action or "IGNORE").strip().upper()
    memory_text = str(memory_text or "").strip()
    old_memory = str(old_memory or "").strip()

    valid_actions = {
        "ADD",
        "UPDATE",
        "DELETE",
        "IGNORE",
        "CONSOLIDATE",
        "END",
    }

    if action not in valid_actions:
        action = "IGNORE"

    if action == "IGNORE":
        return {
            "success": True,
            "action": "IGNORE",
            "reason": "ignored",
        }

    if action == "DELETE":
        if not old_memory:
            return {
                "success": False,
                "action": "DELETE",
                "reason": "missing_old_memory",
            }

        success = archive_memory(
            old_memory,
            reason="manual_delete_request",
            provenance_action="DELETE",
            source_text=source_text,
            temporal_event=temporal_event,
        )

        return {
            "success": success,
            "action": "DELETE",
            "reason": "archived" if success else "not_found",
        }

    if action == "END":
        if not old_memory:
            return {
                "success": False,
                "action": "END",
                "reason": "missing_old_memory",
            }

        success = end_memory(
            old_memory,
            effective_to=effective_to,
            source_text=source_text,
            temporal_event=temporal_event,
        )

        return {
            "success": success,
            "action": "END",
            "reason": "temporal_end" if success else "end_failed",
        }

    if action == "UPDATE":
        if not old_memory or not memory_text:
            return {
                "success": False,
                "action": "UPDATE",
                "reason": "missing_memory_data",
            }

        success = resolve_memory_conflict(
            old_memory,
            memory_text,
            memory_type,
            importance,
            effective_from=effective_from,
            source_text=source_text,
            temporal_event=temporal_event,
        )

        return {
            "success": success,
            "action": "UPDATE",
            "reason": "conflict_replaced" if success else "update_failed",
        }

    if action == "CONSOLIDATE":
        if not consolidation_memory:
            return {
                "success": False,
                "action": "CONSOLIDATE",
                "reason": "missing_consolidated_memory",
            }

        target_memories = [
            item.get("memory")
            for item in (similar_memories or [])
            if isinstance(item, dict) and item.get("memory")
        ]

        if not target_memories:
            return {
                "success": False,
                "action": "CONSOLIDATE",
                "reason": "no_target_memories",
            }

        success = consolidate_memories(
            target_memories,
            consolidation_memory,
            consolidation_type,
            consolidation_importance,
            source_text=source_text,
            provenance_reason=decision_reason or "semantic_consolidation",
        )

        return {
            "success": success,
            "action": "CONSOLIDATE",
            "reason": "consolidated" if success else "consolidation_failed",
        }

    if old_memory and memory_text:
        success = resolve_memory_conflict(
            old_memory,
            memory_text,
            memory_type,
            importance,
            effective_from=effective_from,
            source_text=source_text,
            temporal_event=temporal_event,
        )

        return {
            "success": success,
            "action": "UPDATE",
            "reason": "conflict_replaced" if success else "conflict_resolution_failed",
        }

    if consolidation_memory and similar_memories:
        target_memories = [
            item.get("memory")
            for item in similar_memories
            if isinstance(item, dict) and item.get("memory")
        ]

        if target_memories:
            success = consolidate_memories(
                target_memories,
                consolidation_memory,
                consolidation_type,
                consolidation_importance,
                source_text=source_text,
                provenance_reason=decision_reason or "semantic_consolidation",
            )

            if success:
                return {
                    "success": True,
                    "action": "CONSOLIDATE",
                    "reason": "consolidated",
                }

    if not memory_text:
        return {
            "success": False,
            "action": "ADD",
            "reason": "missing_memory",
        }

    success = add_memory(
        memory_text,
        memory_type,
        importance,
        source_text=source_text,
        provenance_action="ADD",
        provenance_reason=decision_reason or "new_memory",
        temporal_event=temporal_event,
    )

    if success and causal_relations:
        for relation in causal_relations:
            if not isinstance(relation, dict):
                continue
            source_text_memory = str(relation.get("source_memory", "")).strip()
            target_text_memory = str(relation.get("target_memory", "")).strip()
            causal_relation = relation.get("relation", "CAUSES")
            causal_confidence = relation.get("confidence", 0.0)
            evidence = relation.get("evidence", "") or source_text

            # The new memory can be one endpoint. For newly added memories,
            # the model normally names the existing/source memory explicitly.
            if source_text_memory == "__NEW_MEMORY__":
                source_text_memory = memory_text
            if target_text_memory == "__NEW_MEMORY__":
                target_text_memory = memory_text

            add_causal_relationship(
                source_text_memory,
                target_text_memory,
                causal_relation,
                confidence=causal_confidence,
                evidence=evidence,
            )

    return {
        "success": success,
        "action": "ADD",
        "reason": "added" if success else "duplicate_or_rejected",
    }


def govern_memory_action(
    action,
    memory_text="",
    memory_type="other",
    importance=1,
    old_memory="",
    similar_memories=None,
    consolidation_memory="",
    consolidation_type="other",
    consolidation_importance=1,
    effective_from=None,
    effective_to=None,
    source_text="",
    decision_reason="",
    temporal_event="NONE",
    causal_relations=None,
):
    """Idempotent top-level Memory governance entry point."""
    from memory_integrity import run_idempotent

    payload = {
        "action": str(action or "IGNORE").strip().upper(),
        "memory_text": str(memory_text or "").strip(),
        "memory_type": str(memory_type or "other").strip(),
        "importance": importance,
        "old_memory": str(old_memory or "").strip(),
        "similar_memories": similar_memories or [],
        "consolidation_memory": str(consolidation_memory or "").strip(),
        "consolidation_type": str(consolidation_type or "other").strip(),
        "consolidation_importance": consolidation_importance,
        "effective_from": effective_from,
        "effective_to": effective_to,
        "source_text": str(source_text or "").strip(),
        "decision_reason": str(decision_reason or "").strip(),
        "temporal_event": str(temporal_event or "NONE").strip().upper(),
        "causal_relations": causal_relations or [],
    }
    result = run_idempotent(
        "MEMORY_GOVERN",
        payload,
        lambda: _govern_memory_action_impl(
            action,
            memory_text=memory_text,
            memory_type=memory_type,
            importance=importance,
            old_memory=old_memory,
            similar_memories=similar_memories,
            consolidation_memory=consolidation_memory,
            consolidation_type=consolidation_type,
            consolidation_importance=consolidation_importance,
            effective_from=effective_from,
            effective_to=effective_to,
            source_text=source_text,
            decision_reason=decision_reason,
            temporal_event=temporal_event,
            causal_relations=causal_relations,
        ),
    )
    return result.get("result")



# ==================================================
# Delete Memory -> Archive Instead
# ==================================================

def delete_memory(memory_text, source_text=""):
    return archive_memory(
        memory_text,
        reason="manual_delete_request",
        provenance_action="DELETE",
        source_text=source_text,
        temporal_event="NONE",
    )


# ==================================================
# Build Missing Embeddings
# ==================================================

def build_missing_embeddings():
    memory = get_memory()
    archive = get_archived_memory()
    embeddings = load_embeddings()
    changed = False

    all_items = memory + archive

    for item in all_items:
        if not isinstance(item, dict):
            continue

        memory_text = item.get("memory")
        if not memory_text:
            continue

        if memory_text not in embeddings:
            embeddings[memory_text] = create_embedding(memory_text)
            changed = True

    valid_memory_texts = {
        item.get("memory")
        for item in all_items
        if isinstance(item, dict) and item.get("memory")
    }

    for memory_text in list(embeddings.keys()):
        if memory_text not in valid_memory_texts:
            del embeddings[memory_text]
            changed = True

    if changed:
        save_embeddings(embeddings)


# ==================================================
# Calculate Memory Score
# ==================================================

def calculate_memory_score(
    similarity,
    importance,
    access_count=0,
    lifecycle_score=0,
    confidence=INITIAL_CONFIDENCE_MEDIUM,
):
    importance_score = normalize_importance(importance) / 5
    reinforcement_score = calculate_reinforcement_score(access_count)
    confidence_score = normalize_confidence(confidence)

    return (
        similarity * 0.55
        + importance_score * 0.15
        + reinforcement_score * 0.10
        + lifecycle_score * 0.10
        + confidence_score * 0.10
    )


# ==================================================
# Semantic Memory Search
# ==================================================

def search_memory(query, max_results=5, threshold=DEFAULT_SIMILARITY_THRESHOLD):
    if not query or not query.strip():
        return []

    update_memory_lifecycle()
    archive_eligible_memories()
    build_missing_embeddings()

    embeddings = load_embeddings()
    if not embeddings:
        return []

    query_embedding = create_embedding(query)
    all_memory = get_memory()

    memory_lookup = {
        item.get("memory"): item
        for item in all_memory
        if isinstance(item, dict) and item.get("memory")
    }

    results = []

    for memory_text, memory_embedding in embeddings.items():
        item = memory_lookup.get(memory_text)
        if not item:
            continue

        similarity = cosine_similarity(query_embedding, memory_embedding)
        if similarity < threshold:
            continue

        importance = normalize_importance(item.get("importance", 1))

        try:
            access_count = int(item.get("access_count", 0))
        except (ValueError, TypeError):
            access_count = 0

        lifecycle_score = calculate_lifecycle_score(item)
        confidence = calculate_confidence_score(item)

        score = calculate_memory_score(
            similarity,
            importance,
            access_count,
            lifecycle_score,
            confidence,
        )

        results.append({
            "memory": memory_text,
            "type": item.get("type", "other"),
            "importance": importance,
            "similarity": round(similarity, 4),
            "reinforcement": round(calculate_reinforcement_score(access_count), 4),
            "confidence": round(confidence, 4),
            "lifecycle": item.get("status", "active"),
            "access_count": access_count,
            "score": round(score, 4),
            "memory_id": item.get("memory_id"),
            "chain_id": item.get("chain_id"),
            "version": item.get("version", 1),
            "temporal_status": item.get("temporal_status", TEMPORAL_CURRENT),
            "valid_from": item.get("valid_from"),
            "valid_to": item.get("valid_to"),
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    recovered = recover_relevant_archived_memory(
        query,
        active_results=results[:max_results],
    )

    if recovered:
        return search_memory(
            query,
            max_results=max_results,
            threshold=threshold,
        )

    final_results = results[:max_results]

    if final_results:
        memory = get_memory()
        now = current_timestamp()
        selected_texts = {item["memory"] for item in final_results}
        changed = False

        for item in memory:
            if item.get("memory") not in selected_texts:
                continue

            try:
                access_count = int(item.get("access_count", 0))
            except (ValueError, TypeError):
                access_count = 0

            item["access_count"] = max(0, access_count) + 1
            reinforce_confidence(item)
            item["last_accessed"] = now
            item["status"] = "active"
            item["updated_at"] = now
            changed = True

        if changed:
            save_memory(memory)

    return final_results


# ==================================================
# Search Archived Memory
# ==================================================

def search_archived_memory(query, max_results=5, threshold=DEFAULT_SIMILARITY_THRESHOLD):
    if not query or not query.strip():
        return []

    build_missing_embeddings()
    embeddings = load_embeddings()
    archive = get_archived_memory()

    if not embeddings or not archive:
        return []

    query_embedding = create_embedding(query)

    archive_lookup = {
        item.get("memory"): item
        for item in archive
        if isinstance(item, dict) and item.get("memory")
    }

    results = []

    for memory_text, memory_embedding in embeddings.items():
        item = archive_lookup.get(memory_text)
        if not item:
            continue

        similarity = cosine_similarity(query_embedding, memory_embedding)
        if similarity < threshold:
            continue

        results.append({
            "memory": memory_text,
            "type": item.get("type", "other"),
            "importance": normalize_importance(item.get("importance", 1)),
            "similarity": round(similarity, 4),
            "access_count": item.get("access_count", 0),
            "archived_at": item.get("archived_at", ""),
            "archive_reason": item.get("archive_reason", ""),
            "confidence": calculate_confidence_score(item),
            "memory_id": item.get("memory_id"),
            "chain_id": item.get("chain_id"),
            "version": item.get("version", 1),
            "temporal_status": item.get("temporal_status", TEMPORAL_HISTORICAL),
            "valid_from": item.get("valid_from"),
            "valid_to": item.get("valid_to"),
        })

    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:max_results]


# ==================================================
# Archive Recovery Score
# ==================================================

ARCHIVE_RECOVERY_SIMILARITY_THRESHOLD = 0.55
ARCHIVE_RECOVERY_SCORE_THRESHOLD = 0.62


def calculate_recovery_score(item, similarity):
    if not isinstance(item, dict):
        return 0.0

    importance = normalize_importance(item.get("importance", 1))

    try:
        access_count = max(0, int(item.get("access_count", 0)))
    except (ValueError, TypeError):
        access_count = 0

    reinforcement = calculate_reinforcement_score(access_count)
    importance_value = importance / 5

    archive_age = days_since(item.get("archived_at"))
    age_penalty = min(0.20, archive_age / 3650)

    return max(
        0.0,
        similarity * 0.60
        + importance_value * 0.25
        + reinforcement * 0.15
        - age_penalty,
    )


# ==================================================
# Automatic Archive Recovery
# ==================================================

def recover_relevant_archived_memory(
    query,
    active_results=None,
    similarity_threshold=ARCHIVE_RECOVERY_SIMILARITY_THRESHOLD,
):
    if not query or not query.strip():
        return None

    if active_results is None:
        active_results = []

    if active_results:
        active_similarities = [
            float(item.get("similarity", 0))
            for item in active_results
            if isinstance(item, dict)
        ]
        if active_similarities and max(active_similarities) >= 0.70:
            return None

    archived_results = search_archived_memory(
        query,
        max_results=5,
        threshold=similarity_threshold,
    )

    if not archived_results:
        return None

    for item in archived_results:
        item["recovery_score"] = round(
            calculate_recovery_score(
                item,
                item.get("similarity", 0),
            ),
            4,
        )

    archived_results.sort(
        key=lambda x: x.get("recovery_score", 0),
        reverse=True,
    )

    candidate = archived_results[0]

    if candidate.get("recovery_score", 0) < ARCHIVE_RECOVERY_SCORE_THRESHOLD:
        return None

    memory_text = candidate.get("memory")
    if not memory_text:
        return None

    if not restore_memory(memory_text):
        return None

    reinforce_memory(memory_text)

    print(
        f"\n[Memory Recovery] Restored archived memory: {memory_text}"
    )

    candidate["recovered"] = True
    candidate["status"] = "active"
    return candidate


# ==================================================
# Consolidate Similar Memories
# ==================================================

def _consolidate_memories_impl(
    memory_texts,
    new_memory,
    memory_type="other",
    importance=1,
    source_text="",
    provenance_reason="semantic_consolidation",
):
    if not new_memory:
        return False

    new_memory = new_memory.strip()
    if not new_memory:
        return False

    memory = get_memory()
    archive = get_archived_memory()
    target_memories = set(memory_texts or [])
    remaining = []
    removed_items = []

    for item in memory:
        text = item.get("memory")

        if text in target_memories:
            removed_items.append(item)
        else:
            remaining.append(item)

    if not removed_items:
        return False

    inherited_access_count = 0
    inherited_importance = normalize_importance(importance)
    inherited_confidence = initial_memory_confidence(inherited_importance)
    earliest_created_at = None
    derived_from = []

    for item in removed_items:
        item_importance = normalize_importance(item.get("importance", 1))
        inherited_importance = max(inherited_importance, item_importance)
        inherited_confidence = max(
            inherited_confidence,
            normalize_confidence(
                item.get(
                    "confidence",
                    initial_memory_confidence(item_importance),
                )
            ),
        )

        try:
            item_access_count = int(item.get("access_count", 0))
        except (ValueError, TypeError):
            item_access_count = 0

        inherited_access_count += max(0, item_access_count)

        created_at = item.get("created_at")
        if created_at:
            if earliest_created_at is None or created_at < earliest_created_at:
                earliest_created_at = created_at

        if item.get("memory_id"):
            derived_from.append(item["memory_id"])

    now = current_timestamp()
    consolidated_id = generate_memory_id()
    consolidated_chain_id = generate_chain_id()

    consolidated_item = {
        "memory": new_memory,
        "type": memory_type,
        "importance": inherited_importance,
        "confidence": normalize_confidence(inherited_confidence),
        "created_at": earliest_created_at or now,
        "updated_at": now,
        "last_accessed": now,
        "access_count": inherited_access_count,
        "status": "active",
        "memory_id": consolidated_id,
        "chain_id": consolidated_chain_id,
        "version": 1,
        "valid_from": now,
        "valid_to": None,
        "supersedes": None,
        "superseded_by": None,
        "temporal_status": TEMPORAL_CURRENT,
        "derived_from": derived_from,
        "provenance": [],
    }

    append_provenance(
        consolidated_item,
        "CONSOLIDATE",
        reason=provenance_reason,
        source_text=source_text,
        event="CHANGE",
        related_memory_ids=derived_from,
    )

    for item in removed_items:
        archived_item = dict(item)
        archived_item["status"] = "archived"
        archived_item["archived_at"] = now
        archived_item["archive_reason"] = "consolidated_into"
        archived_item["valid_to"] = archived_item.get("valid_to") or now
        archived_item["temporal_status"] = TEMPORAL_HISTORICAL
        archived_item["superseded_by"] = consolidated_id
        archived_item["updated_at"] = now
        append_provenance(
            archived_item,
            "CONSOLIDATED_INTO",
            reason=provenance_reason,
            source_text=source_text,
            event="CHANGE",
            related_memory_ids=[consolidated_id],
        )

        archive = [
            old_item
            for old_item in archive
            if old_item.get("memory_id") != archived_item.get("memory_id")
        ]
        archive.append(archived_item)

    remaining.append(consolidated_item)
    save_memory(remaining)
    save_archived_memory(archive)
    sync_memory_graph()

    embeddings = load_embeddings()

    for text in target_memories:
        embeddings.pop(text, None)

    embeddings[new_memory] = create_embedding(new_memory)
    save_embeddings(embeddings)

    return True

