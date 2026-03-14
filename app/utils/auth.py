# app/core/utils.py
import os
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security_scheme = HTTPBearer()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-a-long-random-string")
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