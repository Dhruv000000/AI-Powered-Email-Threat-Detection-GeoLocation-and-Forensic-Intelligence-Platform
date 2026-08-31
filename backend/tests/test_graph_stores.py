import pytest
from app.graph.memory import InMemoryGraphStore
from app.graph.neo4j import Neo4jGraphStore


def test_in_memory_graph_store_isolation_and_crud(memory_graph_store):
    store = memory_graph_store

    # 1. Create nodes for Inv-1 and Inv-2
    store.create_or_merge_nodes([
        {
            "id": "email:ANL-1",
            "investigation_id": "INV-1",
            "type": "Email",
            "display_label": "Email 1",
            "properties": {"risk_score": 80},
        },
        {
            "id": "domain:bad.xyz",
            "investigation_id": "INV-1",
            "type": "Domain",
            "display_label": "bad.xyz",
            "properties": {},
        },
        {
            "id": "email:ANL-2",
            "investigation_id": "INV-2",
            "type": "Email",
            "display_label": "Email 2",
            "properties": {"risk_score": 20},
        },
    ])

    # 2. Create relationships
    store.create_or_merge_relationships([
        {
            "id": "rel:1",
            "investigation_id": "INV-1",
            "source_id": "email:ANL-1",
            "target_id": "domain:bad.xyz",
            "type": "LINKS_TO",
            "provenance": "email_body",
            "confidence": 1.0,
        }
    ])

    # 3. Test Graph Isolation
    graph1 = store.get_investigation_graph("INV-1")
    assert graph1["node_count"] == 2
    assert graph1["edge_count"] == 1
    assert any(n["id"] == "email:ANL-1" for n in graph1["nodes"])
    assert not any(n["id"] == "email:ANL-2" for n in graph1["nodes"])

    graph2 = store.get_investigation_graph("INV-2")
    assert graph2["node_count"] == 1
    assert graph2["edge_count"] == 0

    # 4. Neighbors & Entity lookup
    ent = store.get_entity("domain:bad.xyz", "INV-1")
    assert ent is not None
    assert ent["display_label"] == "bad.xyz"

    neighbors = store.get_neighbors("email:ANL-1", "INV-1", max_depth=1)
    neighbor_ids = {n["id"] for n in neighbors["nodes"]}
    assert "domain:bad.xyz" in neighbor_ids

    # 5. Cross-investigation matches
    matches = store.find_cross_investigation_matches(["domain:bad.xyz"], current_investigation_id="INV-2")
    assert len(matches) == 1
    assert matches[0]["other_investigation_id"] == "INV-1"

    matches_same = store.find_cross_investigation_matches(["domain:bad.xyz"], current_investigation_id="INV-1")
    assert len(matches_same) == 0

    # 6. Delete graph
    store.delete_investigation_graph("INV-1")
    graph1_after = store.get_investigation_graph("INV-1")
    assert graph1_after["node_count"] == 0


def test_neo4j_resilience_unreachable_fails_cleanly():
    # If Neo4j is pointed to an unreachable port, it must raise ConnectionError (no silent fallback)
    with pytest.raises(ConnectionError):
        Neo4jGraphStore(
            uri="bolt://127.0.0.1:59999", # Non-existent port
            username="neo4j",
            password="wrongpassword",
            database="neo4j",
        )
