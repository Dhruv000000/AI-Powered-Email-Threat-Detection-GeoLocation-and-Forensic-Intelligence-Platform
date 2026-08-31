import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
# Force in-memory graph store for all unit tests
settings.GRAPH_STORE_TYPE = "memory"

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.storage.local import LocalEvidenceStorage
from app.services.email_analysis.orchestrator import AnalysisOrchestrator
from app.graph.memory import InMemoryGraphStore
from app.services.investigation.orchestrator import InvestigationOrchestrator
from app.api.deps import get_investigation_orchestrator, get_storage

TEST_DB_URL = "sqlite:///./test_aegis.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_aegis.db"):
        try:
            os.remove("./test_aegis.db")
        except Exception:
            pass


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def test_storage(tmp_path):
    return LocalEvidenceStorage(base_path=str(tmp_path))


@pytest.fixture
def memory_graph_store():
    store = InMemoryGraphStore()
    yield store
    store.close()


@pytest.fixture
def test_orchestrator(db_session, test_storage):
    return AnalysisOrchestrator(db=db_session, storage=test_storage)


@pytest.fixture
def test_investigation_orchestrator(db_session, memory_graph_store):
    return InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)


@pytest.fixture
def client(db_session, test_storage, memory_graph_store):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    def override_get_storage():
        return test_storage

    def override_get_investigation_orchestrator():
        return InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage] = override_get_storage
    app.dependency_overrides[LocalEvidenceStorage] = override_get_storage
    app.dependency_overrides[get_investigation_orchestrator] = override_get_investigation_orchestrator

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def fixtures_dir():
    return Path(__file__).resolve().parent / "fixtures"
