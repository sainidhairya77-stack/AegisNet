"""
Database initialization and session management
"""

import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from app.config import get_settings
from app.models import Base

logger = logging.getLogger(__name__)

settings = get_settings()


def _create_db_engine(db_url: str):
    is_sqlite = db_url.startswith("sqlite")
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": not is_sqlite,
    }
    if is_sqlite:
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    elif settings.is_development:
        engine_kwargs["poolclass"] = NullPool

    return create_engine(db_url, **engine_kwargs)


engine = _create_db_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """
    Dependency injection for database session.
    Used in FastAPI route dependencies.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables with automatic fallback if PostgreSQL is unreachable"""
    global engine, SessionLocal
    logger.info("Initializing database tables...")

    try:
        # Pre-flight check connection
        with engine.connect():
            pass
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created successfully on primary engine")

    except Exception as exc:
        logger.warning(
            f"⚠️ Could not connect to primary database ({settings.database_url}): {exc}"
        )
        # Automatic fallback to embedded SQLite for zero-crash resilience
        fallback_dir = os.path.abspath(os.path.join(os.getcwd(), "data"))
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_path = os.path.join(fallback_dir, "aegisnet.db")
        sqlite_url = f"sqlite:///{fallback_path}"
        logger.info(f"🔄 Falling back to embedded SQLite database: {sqlite_url}")

        engine = _create_db_engine(sqlite_url)
        SessionLocal.configure(bind=engine)
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Embedded SQLite database initialized successfully")


def drop_db() -> None:
    """Drop all database tables (dangerous - only for testing)"""
    logger.warning("Dropping all database tables!")
    Base.metadata.drop_all(bind=engine)
