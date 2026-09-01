import pytest
from app.core.config import settings
from app.graph.memory_store import InMemoryGraphStore
from app.graph.neo4j import Neo4jGraphStore
from app.graph.neo4j_client import (
    get_driver,
    get_session,
    check_neo4j_health,
    close_driver,
)
from app.graph.constraints import (
    CONSTRAINT_STATEMENTS,
    INDEX_STATEMENTS,
    setup_constraints,
    apply_neo4j_constraints,
)
from app.graph import get_graph_store
from app.schemas.investigation import (
    InvestigationCreateRequest,
    GraphNodeData,
    GraphNode,
    GraphEdgeData,
    GraphEdge,
    CytoscapeGraphResponse,
    ThreatPath,
    InvestigationResponse,
)
from app.db.models.investigation import (
    Investigation,
    InvestigationFinding,
)


def test_in_memory_graph_store_canonical_methods():
    """Verify merge_node, create_edge, get_graph, find_paths, and clear."""
    store = InMemoryGraphStore()
    store.clear()

    # 1. merge_node
    n1 = store.merge_node("Email", "email:ANL-100", {"display_label": "Phishing Email", "risk_score": 85})
    assert n1["id"] == "email:ANL-100"
    assert n1["type"] == "Email"
    assert n1["properties"]["risk_score"] == 85

    n2 = store.merge_node("URL", "url:https://evil.com/login", {"display_label": "https://evil.com/login"})
    n3 = store.merge_node("Domain", "domain:evil.com", {"display_label": "evil.com"})
    n4 = store.merge_node("IP", "ip:198.51.100.22", {"display_label": "198.51.100.22"})

    # 2. create_edge
    e1 = store.create_edge("email:ANL-100", "url:https://evil.com/login", "CONTAINS_URL")
    assert e1["source_id"] == "email:ANL-100"
    assert e1["target_id"] == "url:https://evil.com/login"
    assert e1["type"] == "CONTAINS_URL"

    e2 = store.create_edge("url:https://evil.com/login", "domain:evil.com", "HOSTED_ON")
    e3 = store.create_edge("domain:evil.com", "ip:198.51.100.22", "RESOLVES_TO")

    # 3. get_graph
    g = store.get_graph()
    assert g["node_count"] == 4
    assert g["edge_count"] == 3
    assert len(g["nodes"]) == 4
    assert len(g["edges"]) == 3

    # 4. find_paths
    paths = store.find_paths("Email -> URL -> Domain -> IP")
    assert len(paths) == 1
    assert paths[0]["node_ids"] == [
        "email:ANL-100",
        "url:https://evil.com/login",
        "domain:evil.com",
        "ip:198.51.100.22",
    ]

    # 5. clear
    store.clear()
    g_after = store.get_graph()
    assert g_after["node_count"] == 0
    assert g_after["edge_count"] == 0


def test_in_memory_graph_store_isolation_and_crud(memory_graph_store):
    """Verify investigation-scoped isolation, neighbor discovery, cross-matches, and deletion."""
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


def test_neo4j_client_offline_graceful_degradation():
    """Verify that neo4j_client functions gracefully handle offline Neo4j without crashing."""
    # Close any existing connection
    close_driver()

    # Health check should return False without raising an exception when offline
    health = check_neo4j_health()
    assert health is False

    # get_session should raise ConnectionError when offline
    with pytest.raises(ConnectionError) as exc_info:
        get_session()
    assert "not connected or offline" in str(exc_info.value)

    # close_driver should be safe to call anytime
    close_driver()


def test_neo4j_resilience_unreachable_direct_store_fails_cleanly():
    """Verify Neo4jGraphStore raises ConnectionError when pointed to an unreachable endpoint."""
    with pytest.raises(ConnectionError):
        Neo4jGraphStore(
            uri="bolt://127.0.0.1:59999",
            username="neo4j",
            password="wrongpassword",
            database="neo4j",
        )


def test_dual_store_resilience_get_graph_store_fallback():
    """Verify get_graph_store() seamlessly falls back to InMemoryGraphStore when Neo4j is offline."""
    store = get_graph_store(force_memory=False)
    assert store is not None
    # When Neo4j is offline, it falls back to InMemoryGraphStore
    assert isinstance(store, InMemoryGraphStore)
    assert store.ping() is True


def test_constraints_definitions():
    """Verify that all required Cypher constraint statements are defined."""
    required_entities = [
        "e.analysis_id IS UNIQUE",
        "a.address IS UNIQUE",
        "d.domain_name IS UNIQUE",
        "u.normalized_url IS UNIQUE",
        "i.ip IS UNIQUE",
        "att.sha256 IS UNIQUE",
    ]

    for req in required_entities:
        assert any(req in stmt for stmt in CONSTRAINT_STATEMENTS), f"Missing required constraint for: {req}"

    # Setup constraints returns False when Neo4j is offline without crashing
    res = setup_constraints()
    assert res is False


def test_investigation_pydantic_v2_schemas():
    """Verify Pydantic v2 DTO schemas for investigations, nodes, edges, threat paths, and responses."""
    req = InvestigationCreateRequest(analysis_id="ANL-999-TEST")
    assert req.analysis_id == "ANL-999-TEST"

    node_data = GraphNodeData(
        id="node:1",
        label="Phishing Site",
        type="URL",
        risk_score=90,
        properties={"domain": "phish.com"},
    )
    node = GraphNode(data=node_data)
    assert node.data.id == "node:1"
    assert node.data.name == "Phishing Site"
    assert node.data.risk_score == 90

    edge_data = GraphEdgeData(
        id="edge:1",
        source="node:1",
        target="node:2",
        label="HOSTED_ON",
        provenance="whois_parser",
    )
    edge = GraphEdge(data=edge_data)
    assert edge.data.source == "node:1"
    assert edge.data.provenance == "whois_parser"

    graph_resp = CytoscapeGraphResponse(nodes=[node], edges=[edge])
    assert graph_resp.node_count == 1
    assert graph_resp.edge_count == 1

    path = ThreatPath(
        path_id="path-1",
        title="Credential Harvesting Flow",
        severity="critical",
        description="User redirected to fake login page",
        node_ids=["node:1", "node:2"],
        edge_ids=["edge:1"],
    )
    assert path.path_id == "path-1"
    assert path.severity == "critical"

    resp = InvestigationResponse(
        investigation_id="INV-999",
        analysis_id="ANL-999-TEST",
        status="completed",
        node_count=1,
        edge_count=1,
        threat_path_count=1,
        summary="Phishing activity detected",
    )
    assert resp.investigation_id == "INV-999"
    assert resp.threat_path_count == 1


def test_investigation_db_models():
    """Verify SQLAlchemy models Investigation and InvestigationFinding."""
    inv = Investigation(
        investigation_id="INV-MODEL-001",
        analysis_id="ANL-MODEL-001",
        status="completed",
        summary="Automated forensic investigation summary",
        node_count=15,
        edge_count=20,
        threat_path_count=2,
    )
    assert inv.__tablename__ == "investigations"
    assert inv.investigation_id == "INV-MODEL-001"
    assert inv.node_count == 15

    finding = InvestigationFinding(
        investigation_id="INV-MODEL-001",
        finding_code="HOMOGLYPH_DOMAIN_SPOOF",
        severity="high",
        title="Homoglyph Domain Impersonation Detected",
        description="Domain mimics authentic banking portal.",
        evidence_json={"similarity_score": 0.98},
    )
    assert finding.__tablename__ == "investigation_findings"
    assert finding.finding_code == "HOMOGLYPH_DOMAIN_SPOOF"
    assert finding.severity == "high"
