"""
Backward-compatibility alias module for InMemoryGraphStore.
Main implementation resides in app.graph.memory_store.
"""
from app.graph.memory_store import InMemoryGraphStore

__all__ = ["InMemoryGraphStore"]
