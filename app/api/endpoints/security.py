import os
import json
import logging
from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from sqlalchemy.orm import Session
from app.databases.redis import get_redis
from app.databases.postgres import get_db
from app.memory.cache_manager import GeminiCacheManager
from app.utils.cost_tracker import sync_cost_to_db
from app.workflows.graph import (
    run_full_scan,
    run_file_audit,
    run_bundle_audit,
    run_patch_generation,
    run_chat,
)
from app.core.workspace import WorkspaceManager
from app.utils.auth import get_current_user, fix_cache_key
from app.models.schemas import (
    AuditRequest,
    FixRequest,
    FixRejectRequest,
    ScanRequest,
    ExplainRequest,
    ChatRequest
)
from app.utils.error import safe_http_error
from app.agent.translator import SecurityTranslator

logger = logging.getLogger(__name__)
router = APIRouter()
workspace_manager = WorkspaceManager()


def _delete_gemini_cache(cache_name: str, session_id: str) -> None:
    """Background task: destroy Gemini Context Cache after fix completes."""
    from app.databases.redis import get_redis
    try:
        cache_mgr = GeminiCacheManager()
        cache_mgr.delete_cache(cache_name, redis_client=get_redis())
    except Exception as e:
        logger.warning("Cache deletion failed for session %s: %s", session_id, e)

@router.post("/scan", dependencies=[Depends(get_current_user)])
async def scan_codebase(
    request: ScanRequest,
    redis_client=Depends(get_redis),
    db: Session = Depends(get_db),
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

        sync_cost_to_db(request.session_id, db, redis_client)
        return {
            "status": "complete",
            "session_id": request.session_id,
            "report": report,
        }

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Scan failed due to an internal error.", e)

@router.post("/audit", dependencies=[Depends(get_current_user)])
async def audit_code(
    request: AuditRequest,
    redis_client=Depends(get_redis),
    db: Session = Depends(get_db),
):
    """Audit a single file using LangGraph workflow."""
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Return cached audit result if available (invalidated by /apply)
        audit_key = f"audit_result:{request.session_id}:{request.file_path}"
        if redis_client:
            cached = redis_client.get(audit_key)
            if cached:
                logger.info("Returning cached audit for %s", request.file_path)
                return {"file": request.file_path, "report": json.loads(cached), "cached": True}

        # Check Redis for active Gemini cache; create lazily for bundle requests
        cache_name = None
        is_bundle = request.involved_files and len(request.involved_files) > 1
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        if is_bundle and cache_name is None:
            try:
                cache_mgr = GeminiCacheManager()
                cache_name = cache_mgr.create_cache_for_session(
                    request.session_id, str(session_path), redis_client=redis_client
                )
                logger.info("Lazy cache created for bundle audit, session %s", request.session_id)
            except Exception as e:
                logger.warning("Lazy cache creation failed for session %s: %s", request.session_id, e)

        # Run the LangGraph workflow — bundle or single-file
        if is_bundle:
            report = await run_bundle_audit(
                session_id=request.session_id,
                bundle_name=request.bundle_name or request.file_path,
                involved_files=request.involved_files,
                root_dir=str(session_path),
                cache_name=cache_name,
            )
        else:
            report = await run_file_audit(
                session_id=request.session_id,
                file_path=request.file_path,
                root_dir=str(session_path),
                cache_name=cache_name,
            )

        # Persist result so switching back to this file/bundle is instant
        if redis_client:
            redis_client.setex(audit_key, 3600, json.dumps(report))

        sync_cost_to_db(request.session_id, db, redis_client)
        label = request.bundle_name if is_bundle else request.file_path
        return {"file": label, "report": report}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Audit failed due to an internal error.", e)

@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(
    request: FixRequest,
    background_tasks: BackgroundTasks,
    redis_client=Depends(get_redis),
    db: Session = Depends(get_db),
):
    """
    Generate security fixes using LangGraph workflow.

    This workflow:
    1. Generates patch
    2. Saves to organizational memory

    When bundle_name + involved_files are provided, the ReAct agent receives
    the full security-domain context and may fix vulnerabilities across all
    files in the bundle in one pass.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        fix_key = fix_cache_key(request.session_id, request.file_path, request.vulnerabilities)

        # Return cached patch if available (invalidated by /apply)
        if redis_client:
            cached = redis_client.get(fix_key)
            if cached:
                logger.info("Returning cached fix for %s", request.file_path)
                fixed_str = cached if isinstance(cached, str) else cached.decode()
                return {"file": request.file_path, "fixed_code": fixed_str, "cached": True}

        # Check Redis for active Gemini cache; create lazily for bundle fix requests
        cache_name = None
        is_bundle_fix = request.involved_files and len(request.involved_files) > 1
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        if is_bundle_fix and cache_name is None:
            try:
                cache_mgr = GeminiCacheManager()
                cache_name = cache_mgr.create_cache_for_session(
                    request.session_id, str(session_path), redis_client=redis_client
                )
                logger.info("Lazy cache created for bundle fix, session %s", request.session_id)
            except Exception as e:
                logger.warning("Lazy cache creation failed for session %s: %s", request.session_id, e)

        # Run the LangGraph workflow — pass bundle context + vulnerabilities when available
        fixed_content = await run_patch_generation(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            cache_name=cache_name,
            involved_files=request.involved_files or None,
            vulnerabilities=request.vulnerabilities or [],
        )

        # Persist so switching back to this file/bundle restores the patch instantly
        if redis_client:
            redis_client.setex(fix_key, 3600, fixed_content)

        sync_cost_to_db(request.session_id, db, redis_client)

        # Cache no longer needed after fix — delete it to stop idle billing
        if cache_name:
            if redis_client:
                redis_client.delete(f"cache:{request.session_id}")
            background_tasks.add_task(_delete_gemini_cache, cache_name, request.session_id)

        return {"file": request.file_path, "fixed_code": fixed_content}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Fix generation failed due to an internal error.", e)

@router.post("/fix/reject", dependencies=[Depends(get_current_user)])
async def reject_fix(
    request: FixRejectRequest,
    background_tasks: BackgroundTasks,
    redis_client=Depends(get_redis),
    db: Session = Depends(get_db),
):
    """
    User rejects a previously generated patch and provides feedback.

    This endpoint:
    1. Invalidates the cached fix for this file
    2. Re-invokes patch generation with the user's feedback injected
    3. Returns the new fixed_code for the frontend to display
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)

        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve()) + os.sep):
            raise HTTPException(status_code=400, detail="Invalid file path.")

        # Invalidate the cached patch for this exact vuln set
        fix_key = fix_cache_key(request.session_id, request.file_path, request.vulnerabilities)
        if redis_client:
            redis_client.delete(fix_key)

        # Check Redis for active Gemini cache; create lazily for bundle re-fix requests
        cache_name = None
        is_bundle_refix = request.involved_files and len(request.involved_files) > 1
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        if is_bundle_refix and cache_name is None:
            try:
                cache_mgr = GeminiCacheManager()
                cache_name = cache_mgr.create_cache_for_session(
                    request.session_id, str(session_path), redis_client=redis_client
                )
                logger.info("Lazy cache created for bundle re-fix, session %s", request.session_id)
            except Exception as e:
                logger.warning("Lazy cache creation failed for session %s: %s", request.session_id, e)

        # Re-generate patch with user feedback
        logger.info(
            "User rejected fix for %s. Feedback: %s",
            request.file_path,
            request.feedback[:100],
        )
        fixed_content = await run_patch_generation(
            session_id=request.session_id,
            file_path=request.file_path,
            root_dir=str(session_path),
            cache_name=cache_name,
            involved_files=request.involved_files or None,
            vulnerabilities=request.vulnerabilities or [],
            user_feedback=request.feedback,
        )

        # Cache the new patch
        if redis_client:
            redis_client.setex(fix_key, 3600, fixed_content)

        sync_cost_to_db(request.session_id, db, redis_client)

        # Cache no longer needed after fix — delete it to stop idle billing
        if cache_name:
            if redis_client:
                redis_client.delete(f"cache:{request.session_id}")
            background_tasks.add_task(_delete_gemini_cache, cache_name, request.session_id)

        return {"file": request.file_path, "fixed_code": fixed_content}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Fix re-generation failed due to an internal error.", e)

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
