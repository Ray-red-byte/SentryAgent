import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router as api_router_v2
from app.databases.postgres import engine, Base
from app.core.workspace import WorkspaceManager
from app.config.settings import ALLOWED_ORIGINS
from app.memory.cache_manager import GeminiCacheManager
from app.utils.logger import get_logger

logger = get_logger(__name__)

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    # Delete any Gemini caches that survived a previous server crash so we
    # don't pay idle storage fees for stale context.
    try:
        GeminiCacheManager().sweep_orphaned_caches()
        logger.info("Startup cache sweep complete.")
    except Exception as e:
        logger.warning("Startup cache sweep failed (non-fatal): %s", e)

    yield  # server is running

    # ── Shutdown ──────────────────────────────────────────────────────────────
    # Gracefully delete any active caches before the process exits.
    try:
        GeminiCacheManager().sweep_orphaned_caches()
        logger.info("Shutdown cache sweep complete.")
    except Exception as e:
        logger.warning("Shutdown cache sweep failed (non-fatal): %s", e)


app = FastAPI(
    title="Vibe Security Agent",
    description="AI-powered security auditor for FastAPI backends",
    version="0.4.0-langgraph",
    lifespan=lifespan,
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