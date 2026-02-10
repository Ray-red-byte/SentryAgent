# app/api/routes_langgraph.py
"""
FastAPI routes using LangGraph workflows.

This is the new API layer that uses LangGraph for orchestration.
It provides the same endpoints as routes.py but with better state management.
"""
import os
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

# --- DB & Infra Imports ---
from app.databases.postgres import get_db
from app.databases.redis import get_redis
from app.memory.cache_manager import GeminiCacheManager

# --- LangGraph Workflows ---
from app.workflows.graphs import (
    run_full_scan,
    run_file_audit,
    run_patch_generation
)

# --- Core Imports ---
from app.core.workspace import WorkspaceManager
from app.core.report_generator import ReportGenerator
from app.core.utils import get_current_user

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

# --- Legacy Agents (for features not yet migrated) ---
from app.agent.translator import SecurityTranslator
from app.agent.auditor import SecurityAuditor

router = APIRouter(prefix="/v2")  # New API version
workspace_manager = WorkspaceManager()


# ============================================================================
# UPLOAD ENDPOINT (Same as before)
# ============================================================================

@router.post("/upload")
async def upload_codebase(
    file: UploadFile = File(...),
    redis_client = Depends(get_redis)
):
    """Upload and cache a codebase for scanning."""
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
                value=cache_name
            )
            print(f"🧠 Cache stored in Redis for {session_id}")
        else:
            print("⚠️ Redis unavailable, cache reference lost (stateless).")
        
    except Exception as e:
        print(f"⚠️ Cache creation warning: {e}")

    return {"session_id": session_id, "message": "Uploaded & Cached."}


# ============================================================================
# SCAN ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/scan")
async def scan_codebase(
    request: ScanRequest,
    redis_client = Depends(get_redis)
):
    """
    Scan the uploaded codebase using LangGraph workflow.
    
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
            "risk_threshold": 5,  # Files with risk_score >= 5 get deep audit
            "max_audit_files": 10  # Limit deep audits to top 10 files
        }
        
        # Run the LangGraph workflow
        report = await run_full_scan(
            session_id=request.session_id,
            root_dir=str(session_path),
            cache_name=cache_name,
            config=config
        )
        
        return {
            "status": "complete",
            "session_id": request.session_id,
            "report": report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# AUDIT ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/audit", dependencies=[Depends(get_current_user)])
async def audit_code(
    request: AuditRequest,
    redis_client = Depends(get_redis)
):
    """
    Audit a single file using LangGraph workflow.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
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
            cache_name=cache_name
        )
        
        return {"file": request.file_path, "report": report}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# FIX ENDPOINT (Using LangGraph)
# ============================================================================

@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(
    request: AuditRequest,
    redis_client = Depends(get_redis)
):
    """
    Generate security fixes using LangGraph workflow.
    
    This workflow:
    1. Generates patch
    2. Saves to organizational memory
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        
        # Run the LangGraph workflow
        fixed_content = await run_patch_generation(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            cache_name=cache_name
        )
        
        return {"file": request.file_path, "fixed_code": fixed_content}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CHAT ENDPOINT (Legacy - Not yet migrated to LangGraph)
# ============================================================================

@router.post("/chat", dependencies=[Depends(get_current_user)])
async def chat_with_code(
    request: ChatRequest,
    redis_client = Depends(get_redis)
):
    """
    Chat with code (using legacy auditor for now).
    
    TODO: Migrate to LangGraph ChatState workflow
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Security Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Check Cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Use legacy auditor for now
        auditor = SecurityAuditor(root_dir=str(session_path))
        
        response = auditor.chat_with_file(
            file_path=request.file_path,
            query=request.query,
            cache_name=cache_name,
            full_path=str(full_target_path)
        )

        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# APPLY FIX ENDPOINT (Same as before)
# ============================================================================

@router.post("/apply", dependencies=[Depends(get_current_user)])
async def apply_fix(
    request: ApplyFixRequest,
    redis_client = Depends(get_redis)
):
    """Apply a security fix to a file."""
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        full_target_path = (session_path / request.file_path).resolve()
        
        # Security: Prevent overwriting files outside the session
        if not str(full_target_path).startswith(str(session_path.resolve())):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # 1. Overwrite the file
        with open(full_target_path, "w", encoding="utf-8") as f:
            f.write(request.fixed_code)
            
        # 2. INVALIDATE CACHE
        if redis_client:
            redis_client.delete(f"cache:{request.session_id}")
            print(f"🧹 Cache invalidated for session {request.session_id}")

        return {"status": "applied", "message": "Fix applied. Cache cleared."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# EXPORT ENDPOINT (Same as before)
# ============================================================================

@router.post("/export")
async def export_report(
    request: ExportRequest,
    db: Session = Depends(get_db)
):
    """Export scan results as PDF."""
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Query Postgres for all audits in this session
        db_logs = db.query(AuditLog).filter(AuditLog.session_id == request.session_id).all()
        
        # Convert to dict
        audits_dict = {log.file_path: log.vuln_report for log in db_logs}
        
        # Generate PDF
        generator = ReportGenerator(session_path)
        pdf_path = generator.generate_pdf(request.session_id, request.scan_results, audits_dict)
        
        return FileResponse(
            path=pdf_path, 
            filename=f"sentry_report_{request.session_id}.pdf",
            media_type='application/pdf'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "active", 
        "version": "0.4.0-langgraph",
        "workflow_engine": "LangGraph"
    }
