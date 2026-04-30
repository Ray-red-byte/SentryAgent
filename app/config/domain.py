"""
Domain and codebase parsing configuration.
"""

# ---------------------------------------------------------------------------
# Security-domain heuristics
# ---------------------------------------------------------------------------
# Each entry maps a domain label to the keywords that signal membership.
# path_keywords  — matched against the relative file path (lower-cased).
# import_keywords — matched against raw import strings extracted from the file.
# A file qualifies for a domain when ANY keyword in either list matches.
# ---------------------------------------------------------------------------
DOMAIN_HEURISTICS: dict[str, dict[str, list[str]]] = {
    "authentication": {
        "path_keywords": [
            "auth", "jwt", "login", "logout", "session",
            "token", "oauth", "password", "credential",
        ],
        "import_keywords": [
            "jwt", "passlib", "python_jose", "bcrypt", "oauth2", "authlib",
        ],
    },
    "data_injection": {
        "path_keywords": [
            "database", "databases", "/db/", "model", "schema",
            "orm", "crud", "repository", "repo", "migration",
        ],
        "import_keywords": [
            "sqlalchemy", "psycopg2", "psycopg", "pymongo",
            "databases", "tortoise", "alembic", "asyncpg",
        ],
    },
    "rate_limiting": {
        "path_keywords": ["rate", "limit", "throttle", "middleware"],
        "import_keywords": ["slowapi", "ratelimit", "limits"],
    },
    "secrets_management": {
        "path_keywords": ["config", "settings", "env", "secret", "key"],
        "import_keywords": ["dotenv", "pydantic_settings", "decouple", "dynaconf"],
    },
    "input_validation": {
        "path_keywords": ["schema", "validator", "sanitize", "serializ", "deserializ"],
        "import_keywords": ["pydantic", "marshmallow", "cerberus", "wtforms", "voluptuous"],
    },
    "access_control": {
        "path_keywords": [
            "permission", "role", "rbac", "acl", "policy",
            "guard", "authz", "authorization",
        ],
        "import_keywords": ["casbin", "authlib"],
    },
}

# ---------------------------------------------------------------------------
# File discovery skip rules
# ---------------------------------------------------------------------------
SKIP_DIRS = frozenset({
    "__pycache__", "__MACOSX", "venv", ".venv", "env", ".env",
    "node_modules", ".git", ".tox", "dist", "build", ".mypy_cache",
})
SKIP_EXTS = frozenset({".pyc", ".pyo", ".pyd"})
