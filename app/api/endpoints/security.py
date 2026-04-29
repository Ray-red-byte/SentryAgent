import os
import json
import logging
from fastapi import APIRouter, HTTPException, Depends
from app.databases.redis import get_redis
from app.workflows.graphs import (
    run_full_scan,
    run_file_audit,
    run_bundle_audit,
    run_patch_generation,
    run_chat,
)
from app.core.workspace import WorkspaceManager
from app.utils.auth import get_current_user
from app.models.schemas import (
    AuditRequest,
    FixRequest,
    ScanRequest,
    ExplainRequest,
    ChatRequest
)
from app.utils.error import safe_http_error
from app.agent.translator import SecurityTranslator

logger = logging.getLogger(__name__)
router = APIRouter()
workspace_manager = WorkspaceManager()

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

        # Return cached audit result if available (invalidated by /apply)
        audit_key = f"audit_result:{request.session_id}:{request.file_path}"
        if redis_client:
            cached = redis_client.get(audit_key)
            if cached:
                logger.info("Returning cached audit for %s", request.file_path)
                return {"file": request.file_path, "report": json.loads(cached), "cached": True}

        # Check Redis for active Gemini cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

        # Run the LangGraph workflow — bundle or single-file
        is_bundle = request.involved_files and len(request.involved_files) > 1
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

        label = request.bundle_name if is_bundle else request.file_path
        return {"file": label, "report": report}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Audit failed due to an internal error.", e)

@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(
    request: FixRequest,
    redis_client=Depends(get_redis),
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

        # Bundle fix uses a separate cache key so it doesn't collide with single-file fixes
        is_bundle_fix = bool(request.bundle_name and request.involved_files and len(request.involved_files) > 1)
        if is_bundle_fix:
            fix_key = f"fix_result:{request.session_id}:bundle:{request.bundle_name}"
        else:
            fix_key = f"fix_result:{request.session_id}:{request.file_path}"

        # Return cached patch if available (invalidated by /apply)
        if redis_client:
            cached = redis_client.get(fix_key)
            if cached:
                label = request.bundle_name if is_bundle_fix else request.file_path
                logger.info("Returning cached fix for %s", label)
                fixed_str = cached if isinstance(cached, str) else cached.decode()
                return {"file": label, "fixed_code": fixed_str, "cached": True}

        # Check Redis for active Gemini cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")

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

        label = request.bundle_name if is_bundle_fix else request.file_path
        return {"file": label, "fixed_code": fixed_content}

    except HTTPException:
        raise
    except Exception as e:
        safe_http_error(500, "Fix generation failed due to an internal error.", e)

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
