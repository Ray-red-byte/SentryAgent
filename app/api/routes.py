# app/api/routes.py
import os
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

# --- DB & Infra Imports ---
from app.databases.postgres import get_db
from app.databases.redis import get_redis
from app.memory.cache_manager import GeminiCacheManager

# --- Agent & Tool Imports ---
from app.agent.auditor import SecurityAuditor
from app.agent.patcher import SecurityPatcher
from app.agent.translator import SecurityTranslator
from app.tools.parser.python_parser import PythonParser
from app.core.workspace import WorkspaceManager
from app.core.report_generator import ReportGenerator
from app.core.utils import get_current_user
from app.models.schemas import ChatRequest, ApplyFixRequest

# --- Models ---
from app.models.audit_log import AuditLog
from app.models.schemas import (
    AuditRequest, ScanRequest, ExplainRequest, ExportRequest
)

from app.memory.knowledge_base import SecurityKnowledgeBase

router = APIRouter()
workspace_manager = WorkspaceManager()

# --- 1. UPLOAD ---
@router.post("/upload")
async def upload_codebase(
    file: UploadFile = File(...),
    redis_client = Depends(get_redis) # Inject Redis
):
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
                time=3600, # 1 hour TTL
                value=cache_name
            )
            print(f"🧠 Cache stored in Redis for {session_id}")
        else:
            print("⚠️ Redis unavailable, cache reference lost (stateless).")
        
    except Exception as e:
        print(f"⚠️ Cache creation warning: {e}")

    return {"session_id": session_id, "message": "Uploaded & Cached."}

# --- 2. SCAN (Restored) ---
@router.post("/scan")
async def scout_codebase(request: ScanRequest):
    """
    Scans the uploaded codebase for that specific session.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        root_dir = session_path

        print("--------------root_dir----------------", root_dir)
        
        parser = PythonParser()
        scan_results = []
        
        print(f"🕵️ Scout scanning session: {root_dir}")

        for file_path in root_dir.rglob("*.py"):
            # Skip virtual environments and cache
            if "venv" in str(file_path) or "__pycache__" in str(file_path):
                continue
            
            try:
                with open(file_path, "rb") as f:
                    code = f.read()
                
                # Use Parser to find entry points and hotspots
                routes = parser.find_entry_points(code)
                hotspots = parser.find_security_hotspots(code)
                
                if routes or hotspots:
                    rel_path = file_path.relative_to(root_dir)
                    # Simple scoring heuristic
                    risk_score = len(routes) + (len(hotspots) * 5)
                    
                    scan_results.append({
                        "file": str(rel_path),
                        "risk_score": risk_score,
                        "routes": len(routes),
                        "hotspots": hotspots
                    })
                    
            except Exception as e:
                print(f"⚠️ Error scanning {file_path}: {e}")
                continue

        # Sort by highest risk first
        scan_results.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "status": "complete",
            "session_id": request.session_id,
            "results": scan_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 3. AUDIT ---
@router.post("/audit", dependencies=[Depends(get_current_user)])
async def audit_code(
    request: AuditRequest,
    redis_client = Depends(get_redis) # Inject Redis
):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Security: Path Traversal Check
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
             raise HTTPException(status_code=400, detail="Invalid file path.")

        auditor = SecurityAuditor(root_dir=str(session_path))
        
        # Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        
        if cache_name:
            # FAST PATH
            report = auditor.audit_file_with_cache(request.file_path, cache_name)
        else:
            # SLOW PATH
            report = auditor.audit_file(request.file_path)

        return {"file": request.file_path, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 4. PATCHER ---
@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(
    request: AuditRequest,
    redis_client = Depends(get_redis)
):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # 2. Check Redis for active cache
        cache_name = None
        if redis_client:
            cache_name = redis_client.get(f"cache:{request.session_id}")
        
        # 3. Initialize Patcher
        patcher = SecurityPatcher(root_dir=str(session_path))
        
        # 4. Generate Fix (Pass cache_name!)
        fixed_content = patcher.patch_file(request.file_path, cache_name=cache_name)
        
        # 5. SAVE TO MEMORY (The Learning Step)
        try:
            historian = SecurityKnowledgeBase()
            historian.learn_fix(
                vuln_type="General Fix", 
                description=f"Security Patch for {request.file_path}", 
                fix_code=fixed_content[:1000] 
            )
        except Exception as e:
            print(f"⚠️ Memory save failed (non-critical): {e}")

        return {"file": request.file_path, "fixed_code": fixed_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/chat", dependencies=[Depends(get_current_user)])
async def chat_with_code(
    request: ChatRequest,
    redis_client = Depends(get_redis)
):
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

        # Initialize Auditor
        auditor = SecurityAuditor(root_dir=str(session_path))
        
        # DELEGATE TO AGENT
        response = auditor.chat_with_file(
            file_path=request.file_path,
            query=request.query,
            cache_name=cache_name,
            full_path=str(full_target_path)
        )

        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/apply", dependencies=[Depends(get_current_user)])
async def apply_fix(
    request: ApplyFixRequest,
    redis_client = Depends(get_redis)
):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        full_target_path = (session_path / request.file_path).resolve()
        
        # Security: Prevent overwriting files outside the session
        if not str(full_target_path).startswith(str(session_path.resolve())):
             raise HTTPException(status_code=400, detail="Invalid file path.")

        # 1. Overwrite the file
        with open(full_target_path, "w", encoding="utf-8") as f:
            f.write(request.fixed_code)
            
        # 2. INVALIDATE CACHE (Crucial!)
        # The cache now holds the OLD code. We must force a refresh.
        if redis_client:
            redis_client.delete(f"cache:{request.session_id}")
            print(f"🧹 Cache invalidated for session {request.session_id}")

        return {"status": "applied", "message": "Fix applied. Cache cleared."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# --- 5. EXPLAINER ---
@router.post("/explain", dependencies=[Depends(get_current_user)])
async def explain_report(request: ExplainRequest):
    try:
        translator = SecurityTranslator()
        explanation = translator.translate_report(request.report)
        return {"explanation": explanation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 6. EXPORT ---
@router.post("/export")
async def export_report(
    request: ExportRequest,
    db: Session = Depends(get_db)
):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Query Postgres for all audits in this session
        db_logs = db.query(AuditLog).filter(AuditLog.session_id == request.session_id).all()
        
        # Convert List[AuditLog Object] -> Dict { "filename": [vulns] }
        audits_dict = { log.file_path: log.vuln_report for log in db_logs }
        
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
    return {"status": "active", "version": "0.3.0-refactored"}