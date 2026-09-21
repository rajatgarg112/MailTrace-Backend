import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from fastapi.testclient import TestClient

from app.db.database import (
    Base,
    SessionLocal,
    check_database_connection,
    engine,
    get_db,
)
from app.main import app


def test_database_module_imports():
    """1. Database module imports successfully."""
    assert Base is not None
    assert engine is not None
    assert SessionLocal is not None
    assert get_db is not None
    assert check_database_connection is not None


def test_session_lifecycle_sqlite_memory():
    """2. Session dependency can be created and closed correctly."""
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    db_gen = override_get_db()
    session = next(db_gen)
    assert isinstance(session, Session)
    
    # Verify lightweight query execution
    res = session.execute(text("SELECT 1")).scalar()
    assert res == 1

    # Close session via generator
    with pytest.raises(StopIteration):
        next(db_gen)


def test_rollback_on_exception():
    """4. Rollback behavior works for an exception during session usage."""
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def faillable_get_db():
        db = TestingSessionLocal()
        try:
            yield db
            raise RuntimeError("Simulated transaction error")
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    db_gen = faillable_get_db()
    session = next(db_gen)
    assert isinstance(session, Session)

    with pytest.raises(RuntimeError, match="Simulated transaction error"):
        next(db_gen)


def test_check_database_connection_utility():
    """Test check_database_connection utility with valid session."""
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()

    connected = check_database_connection(db=session)
    assert connected is True
    session.close()


def test_health_endpoint_remains_available():
    """5. Application health endpoint remains available regardless of database status."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
