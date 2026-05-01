# app/api/auth.py
"""
FastAPI routes using LangGraph workflows.

This is the new API layer that uses LangGraph for orchestration.
It provides the same endpoints as routes.py but with better state management.
"""

import logging
import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
import jwt

from app.config.settings import API_USERNAME, API_PASSWORD, JWT_SECRET_KEY as JWT_SECRET, JWT_ALGORITHM, TOKEN_EXPIRE_HOURS

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Exchange username + password for a JWT Bearer token.

    Set credentials via API_USERNAME and API_PASSWORD environment variables.
    Default dev credentials: admin / changeme  (change in production!)
    """
    if form_data.username != API_USERNAME or form_data.password != API_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS)
    token_payload = {
        "sub": form_data.username,
        "role": "admin",
        "permissions": ["audit", "fix", "export"],
        "exp": expire,
    }
    token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in_hours": TOKEN_EXPIRE_HOURS}