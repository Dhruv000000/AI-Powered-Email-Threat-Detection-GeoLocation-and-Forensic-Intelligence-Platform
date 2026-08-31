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
        if "email_analyses" in inspector.get_table_names():
            columns = [c["name"] for c in inspector.get_columns("email_analyses")]
            with engine.begin() as conn:
                if "feature_hash" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN feature_hash VARCHAR(64);"))
                if "score_components" not in columns:
                    conn.execute(text("ALTER TABLE email_analyses ADD COLUMN score_components JSON;"))
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
