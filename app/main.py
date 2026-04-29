from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router as api_router_v2
from app.databases.postgres import engine, Base
from app.core.workspace import WorkspaceManager
import os

Base.metadata.create_all(bind=engine)

# Only allow explicitly listed origins. Override via ALLOWED_ORIGINS env var
# (comma-separated list). Never use "*" alongside allow_credentials=True.
from app.config.settings import ALLOWED_ORIGINS

app = FastAPI(
    title="Vibe Security Agent",
    description="AI-powered security auditor for FastAPI backends",
    version="0.4.0-langgraph",
)

# Restrict CORS to known frontend origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Connect the new LangGraph Router (v2)
app.include_router(api_router_v2, tags=["v2 - LangGraph"])

# Init workspace at startup
workspace_manager = WorkspaceManager()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)