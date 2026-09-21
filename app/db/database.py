from typing import Generator, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# Engine configuration with SQLite connect_args support
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

# Session factory for DB dependency injection
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


class Base(DeclarativeBase):
    """Base declarative class for M5 ORM models integration."""
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_database_connection(db: Optional[Session] = None) -> bool:
    """Lightweight utility checking database connectivity without failing application startup."""
    close_after = False
    if db is None:
        try:
            db = SessionLocal()
            close_after = True
        except Exception:
            return False

    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
    finally:
        if close_after and db is not None:
            db.close()
