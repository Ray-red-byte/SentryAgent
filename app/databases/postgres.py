"""
/app/databases/postgres.py
Use same structure as redis.py
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Use Environment Variables for security, with defaults matching docker-compose
# POSTGRES_USER = os.getenv("POSTGRES_USER", "sentry_user")
# POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "sentry_pass")
# POSTGRES_SERVER = os.getenv("POSTGRES_SERVER", "db") # 'db' is the docker service name
# POSTGRES_DB = os.getenv("POSTGRES_DB", "sentry_db")

# # Connection String: postgresql://user:password@host:port/dbname
# SQLALCHEMY_DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}/{POSTGRES_DB}"

# engine = create_engine(SQLALCHEMY_DATABASE_URL)

# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base = declarative_base()

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()