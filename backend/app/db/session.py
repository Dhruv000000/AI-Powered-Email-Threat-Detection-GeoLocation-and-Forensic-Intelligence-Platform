from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import logger

def get_engine():
    db_url = settings.DATABASE_URL
    try:
        if db_url.startswith("sqlite"):
            engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                echo=settings.SQL_ECHO
            )
        else:
            engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
                echo=settings.SQL_ECHO
            )
            # Test connectivity
            with engine.connect() as conn:
                pass
        return engine
    except Exception as e:
        fallback_url = "sqlite:///./aegis_local_dev.db"
        engine = create_engine(
            fallback_url,
            connect_args={"check_same_thread": False},
            echo=settings.SQL_ECHO
        )
        _verify_sqlite_schema(engine)
        return engine

def _verify_sqlite_schema(engine):
    """Ensure local development SQLite has required columns if tables were created previously."""
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        with engine.begin() as conn:
            if "email_analyses" in tables:
                columns = [c["name"] for c in inspector.get_columns("email_analyses")]
                if "feature_hash" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN feature_hash VARCHAR(64);"))
                if "score_components" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN score_components JSON;"))

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

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
