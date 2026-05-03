# app/core/utils.py
import hashlib
import json
import os
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security_scheme = HTTPBearer()

from app.config.settings import JWT_SECRET_KEY as SECRET_KEY
ALGORITHM = "HS256"

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
):
    """
    Validates a JWT Bearer token from the Authorization header.
    
    Raises HTTP 401 if the token is missing or invalid.
    Raises HTTP 403 if the token lacks required permissions.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "viewer")
        permissions: list = payload.get("permissions", [])

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token: missing subject.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {"username": username, "role": role, "permissions": permissions}

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def fix_cache_key(session_id: str, file_path: str, vulnerabilities) -> str:
    """
    Build a stable Redis cache key for a generated patch.
    Includes a short hash of the vulnerability list so different vuln sets
    for the same file get independent cache entries.
    """
    try:
        vuln_hash = hashlib.sha1(
            json.dumps(vulnerabilities, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]
    except Exception:
        vuln_hash = "0"
    return f"fix_result:{session_id}:{file_path}:{vuln_hash}"