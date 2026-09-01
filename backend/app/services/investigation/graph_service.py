from typing import Dict, Any, List, Optional
from app.graph.base import GraphStore
from app.core.logging import logger
from app.schemas.investigation import (
    CytoscapeGraphResponse,
    GraphNode,
    GraphNodeData,
    GraphEdge,
    GraphEdgeData,
    ThreatPath,
)


class GraphService:
    """
    Service layer providing graph query operations and Cytoscape data formatting
    using the configured GraphStore (Neo4j in production, InMemoryGraphStore in local/CI).
    """

    def __init__(self, store: GraphStore):
        self.store = store

    def sync_investigation_graph(
        self,
        investigation_id: str,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ) -> None:
        """
        Synchronize entities and relationships to the graph store.
        If graph store raises an error, exception is propagated to orchestrator for clean failure handling.
        """
        logger.info(
            f"Synchronizing investigation {investigation_id} to graph store "
            f"({len(entities)} nodes, {len(relationships)} edges)..."
        )
        self.store.create_or_merge_nodes(entities)
        self.store.create_or_merge_relationships(relationships)
        logger.info(f"Successfully synchronized graph for {investigation_id}.")

    def get_investigation_graph(
        self,
        investigation_id: str,
        max_nodes: int = 250,
        max_edges: int = 500,
    ) -> Dict[str, Any]:
        """
        Retrieve Cytoscape formatted graph as a dictionary:
        {
          "investigation_id": "...",
          "node_count": N,
          "edge_count": M,
          "nodes": [ { "group": "nodes", "data": { ... } }, ... ],
          "edges": [ { "group": "edges", "data": { ... } }, ... ]
        }
        """
        raw_graph = self.store.get_investigation_graph(
            investigation_id=investigation_id,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

        nodes = []
        for n in raw_graph.get("nodes", []):
            node_id = n["id"]
            display_name = n.get("display_label") or n.get("label") or n.get("name") or node_id
            nodes.append({
                "group": "nodes",
                "data": {
                    "id": node_id,
                    "label": display_name,
                    "name": display_name,
                    "type": n.get("type", "Entity"),
                    "severity": n.get("severity"),
                    "risk_score": n.get("risk_score"),
                    "is_origin": n.get("is_origin", False),
                    "is_suspicious": n.get("is_suspicious", False),
                    "evidence_reference": n.get("evidence_reference"),
                    "properties": n.get("properties", {}),
                }
            })

        edges = []
        for e in raw_graph.get("edges", []):
            edge_id = e["id"]
            src = e.get("source_id") or e.get("source")
            tgt = e.get("target_id") or e.get("target")
            lbl = e.get("type") or e.get("label") or "RELATION"
            edges.append({
                "group": "edges",
                "data": {
                    "id": edge_id,
                    "source": src,
                    "target": tgt,
                    "label": lbl,
                    "provenance": e.get("provenance"),
                    "source_reference": e.get("source_reference"),
                    "confidence": e.get("confidence", 1.0),
                    "properties": e.get("properties", {}),
                }
            })

        return {
            "investigation_id": investigation_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }

    def get_cytoscape_graph(
        self,
        investigation_id: str,
        max_nodes: int = 250,
        max_edges: int = 500,
    ) -> CytoscapeGraphResponse:
        """Retrieve Cytoscape formatted graph as a validated CytoscapeGraphResponse DTO."""
        graph_dict = self.get_investigation_graph(
            investigation_id=investigation_id,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
        return CytoscapeGraphResponse(**graph_dict)

    def get_entity_detail(self, entity_id: str, investigation_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get_entity(entity_id=entity_id, investigation_id=investigation_id)

    def get_entity_details(self, investigation_id: str, entity_id: str) -> Optional[Dict[str, Any]]:
        return self.get_entity_detail(entity_id=entity_id, investigation_id=investigation_id)

    def get_entity_neighbors(
        self,
        entity_id: str,
        investigation_id: str,
        max_depth: int = 1,
    ) -> Dict[str, List[Dict[str, Any]]]:
        return self.store.get_neighbors(
            entity_id=entity_id,
            investigation_id=investigation_id,
            max_depth=max_depth,
        )

    def find_threat_paths(self, investigation_id: str, max_paths: int = 10) -> List[Dict[str, Any]]:
        return self.store.find_threat_paths(investigation_id=investigation_id, max_paths=max_paths)

    def get_investigation_paths(self, investigation_id: str, max_paths: int = 10) -> List[ThreatPath]:
        raw_paths = self.find_threat_paths(investigation_id=investigation_id, max_paths=max_paths)
        return [ThreatPath(**p) if isinstance(p, dict) else p for p in raw_paths]

    def delete_investigation_graph(self, investigation_id: str) -> None:
        self.store.delete_investigation_graph(investigation_id=investigation_id)
