"""
Database initialization and session management
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from app.config import get_settings
from app.models import Base
import logging

logger = logging.getLogger(__name__)

settings = get_settings()

# Create engine with connection pooling
engine = create_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,  # Test connections before using
    poolclass=NullPool if settings.is_development else None
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """
    Dependency injection for database session.
    Used in FastAPI route dependencies.
    
    Example:
        @app.get("/items")
        def list_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables"""
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def drop_db() -> None:
    """Drop all database tables (dangerous - only for testing)"""
    logger.warning("Dropping all database tables!")
    Base.metadata.drop_all(bind=engine)
