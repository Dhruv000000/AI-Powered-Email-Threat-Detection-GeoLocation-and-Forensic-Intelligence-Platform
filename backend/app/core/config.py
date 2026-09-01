import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PROJECT_NAME: str = "AEGIS — Email Threat Intelligence & Forensic Platform"
    API_V1_PREFIX: str = "/api/v1"
    
    # Application & Forensic Versions
    ANALYSIS_ENGINE_VERSION: str = "1.0.0"
    FEATURE_SCHEMA_VERSION: str = "1.0"
    ML_MODEL_NAME: str = "aegis-email-classifier"
    ML_MODEL_VERSION: str = "0.1.0"

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/aegis_db",
        description="PostgreSQL Connection URL"
    )
    SQL_ECHO: bool = False

    # Redis Cache & Worker
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis Connection URL"
    )
    REDIS_QUEUE_NAME: str = "email_analysis_jobs"

    # Authentication & Security
    JWT_SECRET: str = Field(
        default="aegis-dfir-super-secure-jwt-secret-key-change-in-production-2026",
        description="Secret key for signing JWT tokens"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Ingest Constraints
    MAX_EMAIL_SIZE_MB: int = Field(default=10, description="Max allowed email file size in MB")
    
    @property
    def max_email_size_bytes(self) -> int:
        return self.MAX_EMAIL_SIZE_MB * 1024 * 1024

    # Storage
    STORAGE_BACKEND: str = Field(default="local", description="local or s3")
    LOCAL_STORAGE_PATH: str = Field(
        default=str(Path(__file__).resolve().parent.parent.parent / "storage"),
        description="Root path for evidence storage"
    )

    # ML Model Artifacts
    ML_MODEL_PATH: str = Field(
        default=str(Path(__file__).resolve().parent.parent.parent / "ml" / "models" / "aegis_email_classifier.joblib"),
        description="Trained Scikit-learn model artifact path"
    )

    # CORS
    FRONTEND_URL: str = "http://localhost:5173"

    # Neo4j Graph Database
    NEO4J_URI: str = Field(default="bolt://localhost:7687", description="Neo4j Bolt connection URI")
    NEO4J_USERNAME: str = Field(default="neo4j", description="Neo4j username")
    NEO4J_USER: str = Field(default="neo4j", description="Neo4j username alias")
    NEO4J_PASSWORD: str = Field(default="neo4jpassword", description="Neo4j password")
    NEO4J_DATABASE: str = Field(default="neo4j", description="Neo4j database name")
    NEO4J_MAX_CONNECTION_LIFETIME: int = Field(default=3600, description="Max connection lifetime in seconds")
    NEO4J_CONNECTION_TIMEOUT: float = Field(default=2.0, description="Neo4j connection acquisition and healthcheck timeout in seconds")

    # Investigation & Graph Store
    GRAPH_STORE_TYPE: str = Field(default="neo4j", description="'neo4j' for production or 'memory' for unit testing")
    REDIS_INVESTIGATION_QUEUE_NAME: str = "investigation_jobs"
    MAX_GRAPH_NODES: int = 250
    MAX_GRAPH_EDGES: int = 500
    MAX_PATH_LENGTH: int = 5
    MAX_PATH_RESULTS: int = 10

    # Risk Thresholds
    RISK_LOW_MAX: int = 19
    RISK_MODERATE_MAX: int = 39
    RISK_MEDIUM_MAX: int = 59
    RISK_HIGH_MAX: int = 79
    # 80-100 is Critical

settings = Settings()
