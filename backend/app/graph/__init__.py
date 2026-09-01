from typing import Optional
from app.core.config import settings
from app.core.logging import logger
from app.graph.base import GraphStore
from app.graph.memory_store import InMemoryGraphStore
from app.graph.neo4j import Neo4jGraphStore
from app.graph.neo4j_client import (
    get_driver,
    get_session,
    check_neo4j_health,
    close_driver,
)
from app.graph.constraints import (
    apply_neo4j_constraints,
    setup_constraints,
)

__all__ = [
    "GraphStore",
    "InMemoryGraphStore",
    "Neo4jGraphStore",
    "get_graph_store",
    "get_driver",
    "get_session",
    "check_neo4j_health",
    "close_driver",
    "apply_neo4j_constraints",
    "setup_constraints",
]

# Singleton in-memory store for memory mode testing / resilient fallback
_memory_store_instance: Optional[InMemoryGraphStore] = None


def get_graph_store(force_memory: bool = False) -> GraphStore:
    """
    Factory to retrieve appropriate GraphStore.
    If force_memory or settings.GRAPH_STORE_TYPE == 'memory', returns InMemoryGraphStore.
    If settings.GRAPH_STORE_TYPE == 'neo4j', verifies health before connecting;
    if Neo4j is offline or unreachable, seamlessly falls back to InMemoryGraphStore.
    """
    global _memory_store_instance

    if force_memory or settings.GRAPH_STORE_TYPE.lower() == "memory":
        if _memory_store_instance is None:
            _memory_store_instance = InMemoryGraphStore()
        return _memory_store_instance

    # Check health before attempting Neo4j store initialization
    try:
        is_healthy = check_neo4j_health()
        if not is_healthy:
            logger.info("Neo4j offline. Using InMemoryGraphStore resilient fallback.")
            if _memory_store_instance is None:
                _memory_store_instance = InMemoryGraphStore()
            return _memory_store_instance

        username = getattr(settings, "NEO4J_USER", None) or settings.NEO4J_USERNAME
        store = Neo4jGraphStore(
            uri=settings.NEO4J_URI,
            username=username,
            password=settings.NEO4J_PASSWORD,
            database=settings.NEO4J_DATABASE,
        )
        return store
    except Exception as e:
        logger.warning(
            f"Neo4j instance is unreachable ({e}). "
            "Resiliently falling back to InMemoryGraphStore without interruption."
        )
        if _memory_store_instance is None:
            _memory_store_instance = InMemoryGraphStore()
        return _memory_store_instance
