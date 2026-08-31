from typing import Protocol, List, Dict, Any, Optional, runtime_checkable


@runtime_checkable
class GraphStore(Protocol):
    """
    Protocol defining the required interface for graph persistence and traversal.
    Implemented by Neo4jGraphStore (production) and InMemoryGraphStore (unit tests).
    """

    def ping(self) -> bool:
        """Check if graph database / store is reachable and active."""
        ...

    def initialize_schema(self) -> None:
        """Create constraints, indexes, and schema definitions."""
        ...

    def create_or_merge_nodes(self, nodes: List[Dict[str, Any]]) -> None:
        """
        Idempotently create or merge nodes in the graph store.
        Each node dict must contain 'id', 'type', 'label', 'investigation_id', and optional 'properties'.
        """
        ...

    def create_or_merge_relationships(self, relationships: List[Dict[str, Any]]) -> None:
        """
        Idempotently create or merge relationships between nodes.
        Each relationship dict must contain 'id', 'source_id', 'target_id', 'type', 'investigation_id',
        'provenance', and optional 'confidence', 'properties'.
        """
        ...

    def get_investigation_graph(
        self, investigation_id: str, max_nodes: int = 250, max_edges: int = 500
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Retrieve isolated graph for a given investigation_id formatted as:
        {'nodes': [...], 'edges': [...]}
        """
        ...

    def get_entity(self, entity_id: str, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific entity and its properties by ID within an investigation."""
        ...

    def get_neighbors(
        self, entity_id: str, investigation_id: str, max_depth: int = 1
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieve n-hop subgraph surrounding an entity within an investigation."""
        ...

    def get_paths(
        self, investigation_id: str, start_entity_id: str, end_entity_id: str, max_depth: int = 5
    ) -> List[List[Dict[str, Any]]]:
        """Find bounded paths between two entities within an investigation."""
        ...

    def find_threat_paths(
        self, investigation_id: str, max_depth: int = 5, max_paths: int = 10
    ) -> List[Dict[str, Any]]:
        """Identify key security threat paths (e.g. Email -> URL -> Domain -> IP)."""
        ...

    def find_cross_investigation_matches(
        self, entity_ids: List[str], current_investigation_id: str
    ) -> List[Dict[str, Any]]:
        """Look for historical occurrences of the specified entity IDs in other investigations."""
        ...

    def delete_investigation_graph(self, investigation_id: str) -> None:
        """Delete all nodes and relationships associated with the investigation."""
        ...

    def close(self) -> None:
        """Close connection pools or cleanup resources."""
        ...
