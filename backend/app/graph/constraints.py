from typing import Any
from app.core.logging import logger
from app.graph.queries import (
    CREATE_ENTITY_ID_CONSTRAINT,
    CREATE_INVESTIGATION_INDEX,
    CREATE_ENTITY_TYPE_INDEX,
)


def apply_neo4j_constraints(session: Any) -> None:
    """Apply unique constraints and indexes to the connected Neo4j database instance."""
    queries = [
        ("Entity ID Constraint", CREATE_ENTITY_ID_CONSTRAINT),
        ("Investigation Index", CREATE_INVESTIGATION_INDEX),
        ("Entity Type Index", CREATE_ENTITY_TYPE_INDEX),
    ]

    for name, query in queries:
        try:
            session.run(query)
            logger.info(f"Applied Neo4j schema constraint/index: {name}")
        except Exception as e:
            logger.warning(f"Could not apply Neo4j constraint '{name}': {e}")
