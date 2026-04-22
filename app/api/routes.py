# app/api/routes_langgraph.py
"""
FastAPI routes using LangGraph workflows.

This is the new API layer that uses LangGraph for orchestration.
It provides the same endpoints as routes.py but with better state management.
"""
import io
import os
import json
import zipfile
import logging
import datetime
import asyncio
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
import jwt

# --- DB & Infra Imports ---
from app.databases.postgres import get_db
from app.databases.redis import get_redis
from app.memory.cache_manager import GeminiCacheManager

# --- LangGraph Workflows ---
from app.workflows.graphs import (
    run_full_scan,
    run_file_audit,
    run_patch_generation,
    run_chat,
)

# --- Core Imports ---
from app.core.workspace import WorkspaceManager
from app.core.report_generator import ReportGenerator
from app.utils.auth import get_current_user

# --- Models ---
from app.models.audit_log import AuditLog
from app.models.schemas import (
    AuditRequest,
    ScanRequest,
    ExplainRequest,
    ExportRequest,
    ChatRequest,
    ApplyFixRequest
)

# --- Memory ---
from app.memory.knowledge_base import SecurityKnowledgeBase

# --- Error Handling ---
from app.utils.error import safe_http_error

# --- Legacy Agents (for features not yet migrated) ---
from app.agent.translator import SecurityTranslator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v2")  # New API version
workspace_manager = WorkspaceManager()

# Credentials are set via environment variables
_API_USERNAME = os.getenv("API_USERNAME", "admin")
_API_PASSWORD = os.getenv("API_PASSWORD", "changeme")
_JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-a-long-random-string")
_JWT_ALGORITHM = "HS256"
_TOKEN_EXPIRE_HOURS = 8

# ============================================================================
# AUTH ENDPOINT — Issue JWT tokens
# ============================================================================

@router.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Exchange username + password for a JWT Bearer token.

    Set credentials via API_USERNAME and API_PASSWORD environment variables.
    Default dev credentials: admin / changeme  (change in production!)
    """
    if form_data.username != _API_USERNAME or form_data.password != _API_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=_TOKEN_EXPIRE_HOURS)
    token_payload = {
        "sub": form_data.username,
        "role": "admin",
        "permissions": ["audit", "fix", "export"],
        "exp": expire,
    }
    token = jwt.encode(token_payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in_hours": _TOKEN_EXPIRE_HOURS}


# ============================================================================
# UPLOAD ENDPOINT
# ============================================================================

@router.post("/upload", dependencies=[Depends(get_current_user)])
async def upload_codebase(
    file: UploadFile = File(...),
    redis_client=Depends(get_redis),
):
    """Upload and cache a codebase for scanning. Requires authentication."""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    session_id = workspace_manager.create_workspace()
    await workspace_manager.save_and_extract_code(session_id, file)

    # Trigger Cache Creation
    try:
        session_path = workspace_manager.get_workspace_path(session_id)
        cache_mgr = GeminiCacheManager()

        # 1. Create Google Cache
        cache_name = cache_mgr.create_cache_for_session(session_id, str(session_path))

        # 2. Save Mapping to Redis
        if redis_client:
            redis_client.setex(
                name=f"cache:{session_id}",
                time=3600,  # 1 hour TTL
                value=cache_name,
            )
            logger.info("Cache stored in Redis for %s", session_id)
        else:
            logger.warning("Redis unavailable; cache reference lost (stateless).")

    except Exception as e:
        # Non-fatal: caching is opportunistic. Log and continue.
        logger.warning("Cache creation warning for session %s: %s", session_id, e)

    return {"session_id": session_id, "message": "Uploaded & Cached."}


# ============================================================================
# SCAN ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/scan", dependencies=[Depends(get_current_user)])
async def scan_codebase(
    request: ScanRequest,
    redis_client=Depends(get_redis),
):
    """
    Scan the uploaded codebase using LangGraph workflow. Requires authentication.

    This endpoint uses a state machine to:
    1. Discover files
    2. Parse and scan for hotspots
    3. Load organizational memory
    4. Conditionally deep audit high-risk files
    5. Prioritize vulnerabilities
    6. Generate report
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Configuration
        config = {
            "risk_threshold": 5,   # Files with risk_score >= 5 get deep audit
            "max_audit_files": 10  # Limit deep audits to top 10 files
        }

        # Run the LangGraph workflow
        report = await run_full_scan(
            session_id=request.session_id,
            root_dir=str(session_path),
            cache_name=cache_name,
            config=config,
        )

        return {
            "status": "complete",
            "session_id": request.session_id,
            "report": report,
        }

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Scan failed due to an internal error.", e)


# ============================================================================
# AUDIT ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/audit", dependencies=[Depends(get_current_user)])
async def audit_code(
    request: AuditRequest,
    redis_client=Depends(get_redis),
):
    """Audit a single file using LangGraph workflow."""
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Run the LangGraph workflow
        report = await run_file_audit(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            cache_name=cache_name,
        )

        return {"file": request.file_path, "report": report}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Audit failed due to an internal error.", e)


# ============================================================================
# FIX ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(
    request: AuditRequest,
    redis_client=Depends(get_redis),
):
    """
    Generate security fixes using LangGraph workflow.

    This workflow:
    1. Generates patch
    2. Saves to organizational memory
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check (was missing in original code)
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Run the LangGraph workflow
        fixed_content = await run_patch_generation(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            cache_name=cache_name,
        )

        return {"file": request.file_path, "fixed_code": fixed_content}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Fix generation failed due to an internal error.", e)


# ============================================================================
# CHAT ENDPOINT (Legacy - Not yet migrated to LangGraph)
# ============================================================================

@router.post("/chat", dependencies=[Depends(get_current_user)])
async def chat_with_code(
    request: ChatRequest,
    redis_client=Depends(get_redis),
):
    """
    Chat with code using the LangGraph ChatState workflow.
    Answers developer questions about a specific file, using the Gemini cache
    when available for faster responses.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Check Cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Run the LangGraph chat workflow
        response = await run_chat(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            query=request.query,
            cache_name=cache_name,
        )

        return {"response": response}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Chat request failed due to an internal error.", e)


# ============================================================================
# APPLY FIX ENDPOINT
# ============================================================================

@router.post("/apply", dependencies=[Depends(get_current_user)])
async def apply_fix(
    request: ApplyFixRequest,
    redis_client=Depends(get_redis),
):
    """
    Apply a security fix to the file in the session workspace.
    After applying, the user can call /download to get a zip of all fixed files.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        full_target_path = (session_path / request.file_path).resolve()

        # Security: Prevent overwriting files outside the session
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # 1. Read original for learning
        original_code = ""
        try:
            with open(full_target_path, "r", encoding="utf-8") as f:
                original_code = f.read()
        except Exception:
            pass

        # 2. Overwrite the file with fixed code
        with open(full_target_path, "w", encoding="utf-8") as f:
            f.write(request.fixed_code)
        logger.info("Fix applied to %s in session %s", request.file_path, request.session_id)

        # 3. Teach the knowledge base about this fix (async — don't block response)
        try:
            kb = SecurityKnowledgeBase()
            # Store diff as the lesson: what changed
            diff_snippet = f"BEFORE (first 500 chars):\n{original_code[:500]}\n\nAFTER:\n{request.fixed_code[:500]}"
            kb.learn_fix(
                vuln_type=getattr(request, 'vuln_type', 'Security Fix'),
                description=f"Fix applied to {request.file_path}",
                fix_code=diff_snippet,
                file_path=request.file_path,
                severity=getattr(request, 'severity', 'UNKNOWN'),
            )
        except Exception as e:
            logger.warning("Could not persist fix to knowledge base: %s", e)

        # 4. Invalidate Gemini cache (code has changed)
        if redis_client:
            redis_client.delete(f"cache:{request.session_id}")
            logger.info("Cache invalidated for session %s", request.session_id)

        return {
            "status": "applied",
            "message": "Fix applied successfully. Use /download to get the updated codebase.",
            "download_url": f"/v2/download/{request.session_id}",
        }

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Apply failed due to an internal error.", e)


# ============================================================================
# DOWNLOAD ENDPOINT — get the (patched) codebase as a ZIP
# ============================================================================

@router.get("/download/{session_id}", dependencies=[Depends(get_current_user)])
async def download_session_zip(session_id: str):
    """
    Package the entire session workspace into a ZIP and return it.
    Call this after applying one or more fixes to download the updated codebase.
    """
    try:
        session_path = workspace_manager.get_workspace_path(session_id)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in Path(session_path).rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(session_path)
                    zf.write(file_path, arcname)
        buf.seek(0)

        filename = f"sentry_fixed_{session_id[:8]}.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Download failed due to an internal error.", e)


@router.get("/download/{session_id}/{file_path:path}", dependencies=[Depends(get_current_user)])
async def download_single_file(session_id: str, file_path: str):
    """Download a single (possibly patched) file from the session workspace."""
    try:
        session_path = workspace_manager.get_workspace_path(session_id)
        full_path = (session_path / file_path).resolve()

        if not str(full_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found.")

        return FileResponse(
            path=str(full_path),
            filename=Path(file_path).name,
            media_type="application/octet-stream",
        )

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "File download failed.", e)


# ============================================================================
# STATUS / PROGRESS — Server-Sent Events for real-time workflow updates
# ============================================================================

@router.get("/status/{session_id}", dependencies=[Depends(get_current_user)])
async def stream_status(session_id: str, redis_client=Depends(get_redis)):
    """
    Server-Sent Events stream that broadcasts real-time scan/audit progress.
    The frontend connects here and receives JSON events as the LangGraph
    workflow progresses through its nodes.

    Emits events with shape: {"stage": "...", "message": "...", "progress": 0-100}
    Closes automatically when the 'complete' or 'error' stage is received.
    """
    async def event_generator():
        max_wait_seconds = 300  # 5 minute timeout
        poll_interval = 0.5
        elapsed = 0.0
        last_stage = None

        while elapsed < max_wait_seconds:
            stage_data = None

            if redis_client:
                raw = redis_client.get(f"status:{session_id}")
                if raw:
                    try:
                        stage_data = json.loads(raw)
                    except Exception:
                        pass

            if stage_data:
                stage = stage_data.get("stage", "unknown")

                # Only emit when stage changes
                if stage != last_stage:
                    last_stage = stage
                    yield f"data: {json.dumps(stage_data)}\n\n"

                    if stage in ("complete", "error"):
                        # Cleanup and close
                        if redis_client:
                            redis_client.delete(f"status:{session_id}")
                        return

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        yield f'data: {{"stage": "error", "message": "Status stream timed out", "progress": 0}}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


# ============================================================================
# EXPLAIN ENDPOINT (Legacy)
# ============================================================================

@router.post("/explain", dependencies=[Depends(get_current_user)])
async def explain_report(request: ExplainRequest):
    """Explain a security report in plain language."""
    try:
        translator = SecurityTranslator()
        explanation = translator.translate_report(request.report)
        return {"explanation": explanation}
    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Explain request failed due to an internal error.", e)


# ============================================================================
# EXPORT ENDPOINT
# ============================================================================

@router.post("/export", dependencies=[Depends(get_current_user)])
async def export_report(
    request: ExportRequest,
    db: Session = Depends(get_db),
):
    """Export scan results as PDF. Requires authentication."""
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Query Postgres for all audits in this session
        db_logs = (
            db.query(AuditLog)
            .filter(AuditLog.session_id == request.session_id)
            .all()
        )

        # Convert to dict
        audits_dict = {log.file_path: log.vuln_report for log in db_logs}

        # Generate PDF
        generator = ReportGenerator(session_path)
        pdf_path = generator.generate_pdf(
            request.session_id, request.scan_results, audits_dict
        )

        return FileResponse(
            path=pdf_path,
            filename=f"sentry_report_{request.session_id}.pdf",
            media_type="application/pdf",
        )

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Export failed due to an internal error.", e)


# ============================================================================
# HEALTH CHECK
# ============================================================================

@router.get("/health")
async def health_check():
    """Health check endpoint (unauthenticated, returns minimal info)."""
    return {
        "status": "active",
        "version": "0.4.0-langgraph",
        "workflow_engine": "LangGraph",
    }
