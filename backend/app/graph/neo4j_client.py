from typing import Optional
from neo4j import GraphDatabase, Driver, Session
from app.core.config import settings
from app.core.logging import logger

_driver: Optional[Driver] = None


def get_driver() -> Optional[Driver]:
    """
    Retrieve or initialize the singleton Neo4j driver instance.
    Returns None if driver creation or connection verification fails.
    """
    global _driver
    if _driver is not None:
        return _driver

    username = getattr(settings, "NEO4J_USER", None) or settings.NEO4J_USERNAME
    try:
        driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(username, settings.NEO4J_PASSWORD),
            max_connection_lifetime=settings.NEO4J_MAX_CONNECTION_LIFETIME,
            connection_acquisition_timeout=settings.NEO4J_CONNECTION_TIMEOUT,
            connection_timeout=settings.NEO4J_CONNECTION_TIMEOUT,
        )
        # Verify connectivity with short timeout
        driver.verify_connectivity()
        _driver = driver
        logger.info(f"Neo4j driver initialized successfully for {settings.NEO4J_URI}")
        return _driver
    except Exception as e:
        logger.warning(f"Unable to connect to Neo4j instance at {settings.NEO4J_URI}: {e}")
        return None


def get_session(database: Optional[str] = None) -> Session:
    """
    Acquire a new Neo4j Session from the active driver pool.
    Raises ConnectionError if the driver is not connected.
    """
    driver = get_driver()
    if driver is None:
        raise ConnectionError(f"Neo4j driver is not connected or offline ({settings.NEO4J_URI})")
    target_db = database or settings.NEO4J_DATABASE
    return driver.session(database=target_db)


def check_neo4j_health() -> bool:
    """
    Verify Neo4j connectivity within short timeout (2-3s).
    Returns True if healthy, False otherwise without throwing exceptions.
    """
    try:
        driver = get_driver()
        if driver is None:
            return False
        driver.verify_connectivity()
        return True
    except Exception as e:
        logger.warning(f"Neo4j health check failed: {e}")
        return False


def close_driver() -> None:
    """
    Safely close and reset the active Neo4j driver connection pool.
    """
    global _driver
    if _driver is not None:
        try:
            _driver.close()
            logger.info("Neo4j driver connection pool closed.")
        except Exception as e:
            logger.warning(f"Error while closing Neo4j driver: {e}")
        finally:
            _driver = None
