import io
import os
import zipfile
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.databases.postgres import get_db
from app.databases.redis import get_redis
from app.memory.cache_manager import GeminiCacheManager
from app.core.workspace import WorkspaceManager
from app.core.report_generator import ReportGenerator
from app.utils.auth import get_current_user
from app.models.audit_log import AuditLog
from app.models.schemas import ExportRequest, ApplyFixRequest
from app.memory.knowledge_base import SecurityKnowledgeBase
from app.utils.error import safe_http_error

logger = logging.getLogger(__name__)
router = APIRouter()
workspace_manager = WorkspaceManager()

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

        # 4. Invalidate Gemini cache and per-file audit/fix cache (code has changed)
        if redis_client:
            redis_client.delete(f"cache:{request.session_id}")
            redis_client.delete(f"audit_result:{request.session_id}:{request.file_path}")
            redis_client.delete(f"fix_result:{request.session_id}:{request.file_path}")
            logger.info("Cache invalidated for session %s / file %s", request.session_id, request.file_path)

        return {
            "status": "applied",
            "message": "Fix applied successfully. Use /download to get the updated codebase.",
            "download_url": f"/v2/download/{request.session_id}",
        }

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Apply failed due to an internal error.", e)

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
