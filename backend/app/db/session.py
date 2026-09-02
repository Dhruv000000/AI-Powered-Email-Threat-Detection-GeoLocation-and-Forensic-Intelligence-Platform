"""Database session management and SQLite schema verification for AEGIS."""

from typing import Generator
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import logger


def get_engine():
    """Initialize the SQLAlchemy engine with support for SQLite and PostgreSQL."""
    db_url = getattr(settings, "DATABASE_URL", "sqlite:///./aegis.db")
    sql_echo = getattr(settings, "SQL_ECHO", False)

    try:
        if db_url.startswith("sqlite"):
            engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                echo=sql_echo,
            )
            _verify_sqlite_schema(engine)
        else:
            engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
                echo=sql_echo,
            )
            # Test connectivity
            with engine.connect():
                pass
        return engine
    except Exception as e:
        logger.warning(f"Failed to initialize primary database ({db_url}): {e}. Falling back to local SQLite.")
        fallback_url = "sqlite:///./aegis_local_dev.db"
        engine = create_engine(
            fallback_url,
            connect_args={"check_same_thread": False},
            echo=sql_echo,
        )
        _verify_sqlite_schema(engine)
        return engine


def _verify_sqlite_schema(engine):
    """Ensure local development SQLite database has all required columns across schema updates."""
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        with engine.begin() as conn:
            # 1. Check email_analyses table
            if "email_analyses" in tables:
                columns = [c["name"] for c in inspector.get_columns("email_analyses")]
                if "feature_hash" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN feature_hash VARCHAR(64);"))
                if "score_components" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN score_components JSON;"))

            # 2. Check investigations table
            if "investigations" in tables:
                inv_cols = [c["name"] for c in inspector.get_columns("investigations")]
                missing_cols = {
                    "summary": "TEXT",
                    "node_count": "INTEGER DEFAULT 0",
                    "edge_count": "INTEGER DEFAULT 0",
                    "threat_path_count": "INTEGER DEFAULT 0",
                    "stage": "VARCHAR(64) DEFAULT 'loading_analysis'",
                    "progress": "INTEGER DEFAULT 0",
                    "threat_type": "VARCHAR(64)",
                    "risk_score": "INTEGER",
                    "severity": "VARCHAR(32)",
                    "ai_confidence": "FLOAT",
                    "investigation_confidence": "FLOAT DEFAULT 0.0",
                    "error_code": "VARCHAR(64)",
                    "error_message_safe": "TEXT",
                    "summary_json": "JSON",
                    "metrics_json": "JSON",
                    "completed_at": "DATETIME",
                }
                for col_name, col_type in missing_cols.items():
                    if col_name not in inv_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE investigations ADD COLUMN {col_name} {col_type};"))
                        except Exception as e:
                            logger.debug(f"Could not add column {col_name} to investigations: {e}")

            # 3. Check investigation_findings table
            if "investigation_findings" in tables:
                find_cols = [c["name"] for c in inspector.get_columns("investigation_findings")]
                find_missing = {
                    "finding_code": "VARCHAR(64) DEFAULT 'SUSPICIOUS_PATTERN'",
                    "evidence_json": "JSON",
                    "finding_id": "VARCHAR(64)",
                    "reason_code": "VARCHAR(64)",
                    "confidence": "FLOAT DEFAULT 0.8",
                    "evidence_references": "JSON",
                    "entity_ids": "JSON",
                    "relationship_ids": "JSON",
                }
                for col_name, col_type in find_missing.items():
                    if col_name not in find_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE investigation_findings ADD COLUMN {col_name} {col_type};"))
                        except Exception as e:
                            logger.debug(f"Could not add column {col_name} to investigation_findings: {e}")

    except Exception as e:
        logger.debug(f"SQLite schema inspection note: {e}")


# Initialize global engine and sessionmaker
engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database session with automatic lifecycle closing."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()