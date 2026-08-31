from typing import Optional
from app.core.config import settings
from app.core.logging import logger
from app.graph.base import GraphStore
from app.graph.memory import InMemoryGraphStore
from app.graph.neo4j import Neo4jGraphStore

__all__ = [
    "GraphStore",
    "InMemoryGraphStore",
    "Neo4jGraphStore",
    "get_graph_store",
]

# Singleton in-memory store for memory mode testing
_memory_store_instance: Optional[InMemoryGraphStore] = None


def get_graph_store(force_memory: bool = False) -> GraphStore:
    """
    Factory to retrieve appropriate GraphStore.
    If force_memory or settings.GRAPH_STORE_TYPE == 'memory', returns InMemoryGraphStore.
    Otherwise returns Neo4jGraphStore in production.
    """
    global _memory_store_instance
    if force_memory or settings.GRAPH_STORE_TYPE.lower() == "memory":
        if _memory_store_instance is None:
            _memory_store_instance = InMemoryGraphStore()
        return _memory_store_instance

    # Production Neo4j Store (Strict: never silently falls back to in-memory)
    return Neo4jGraphStore(
        uri=settings.NEO4J_URI,
        username=settings.NEO4J_USERNAME,
        password=settings.NEO4J_PASSWORD,
        database=settings.NEO4J_DATABASE,
    )
