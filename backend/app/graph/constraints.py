from typing import Any, List, Optional
from app.core.logging import logger
from app.graph.neo4j_client import get_session, check_neo4j_health

# Automated Cypher constraint statements
CONSTRAINT_STATEMENTS: List[str] = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Email) REQUIRE e.analysis_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (a:EmailAddress) REQUIRE a.address IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.domain_name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:URL) REQUIRE u.normalized_url IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.ip IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (att:Attachment) REQUIRE att.sha256 IS UNIQUE",
    "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE",
]

INDEX_STATEMENTS: List[str] = [
    "CREATE INDEX entity_investigation_idx IF NOT EXISTS FOR (n:Entity) ON (n.investigation_id)",
    "CREATE INDEX entity_type_idx IF NOT EXISTS FOR (n:Entity) ON (n.type)",
]


def apply_neo4j_constraints(session: Any) -> None:
    """
    Apply unique constraints and indexes to an active Neo4j database session.
    Logs each operation and handles failures gracefully without crashing.
    """
    all_statements = [(f"Constraint {idx + 1}", stmt) for idx, stmt in enumerate(CONSTRAINT_STATEMENTS)] + [
        (f"Index {idx + 1}", stmt) for idx, stmt in enumerate(INDEX_STATEMENTS)
    ]

    for name, query in all_statements:
        try:
            session.run(query)
            logger.info(f"Applied Neo4j schema constraint/index: {name}")
        except Exception as e:
            logger.warning(f"Could not apply Neo4j constraint '{name}': {e}")


def setup_constraints(session: Optional[Any] = None) -> bool:
    """
    Automated constraint setup entry point.
    If session is not provided, attempts to acquire one via neo4j_client.
    Returns True if constraints were applied, False if Neo4j is offline.
    """
    if session is not None:
        apply_neo4j_constraints(session)
        return True

    if not check_neo4j_health():
        logger.info("Neo4j is offline; skipping constraint setup.")
        return False

    try:
        with get_session() as active_session:
            apply_neo4j_constraints(active_session)
            return True
    except Exception as e:
        logger.warning(f"Failed to execute automated constraint setup: {e}")
        return False
