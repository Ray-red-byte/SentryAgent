"""
app/databases/postgres.py
SQLAlchemy engine, session factory, and Base for PostgreSQL.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

POSTGRES_USER = os.getenv("POSTGRES_USER", "sentry_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "sentry_pass")
POSTGRES_SERVER = os.getenv("POSTGRES_SERVER", "db")   # docker-compose service name
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentry_db")

SQLALCHEMY_DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}/{POSTGRES_DB}"
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a SQLAlchemy session and guarantees cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()