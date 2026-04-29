import os
from pathlib import Path

# API Config
ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()]

# API Credentials & Auth
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "changeme")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-a-long-random-string")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

# Gemini Config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# ChromaDB Config
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")

# Redis Config
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# Postgres Config
POSTGRES_USER = os.getenv("POSTGRES_USER", "sentry_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "sentry_pass")
POSTGRES_SERVER = os.getenv("POSTGRES_SERVER", "db")
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentry_db")

# Workspace Config
WORKSPACE_DIR_NAME = os.getenv("WORKSPACE_DIR", "temp_workspaces")
WORKSPACE_DIR = Path(WORKSPACE_DIR_NAME)
