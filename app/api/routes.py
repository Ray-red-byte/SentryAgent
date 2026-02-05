import os
import shutil
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

# --- Import Core & Agents ---
from app.agent.auditor import SecurityAuditor
from app.agent.patcher import SecurityPatcher
from app.parser.python_parser import PythonParser
from app.agent.translator import SecurityTranslator
from app.core.workspace import WorkspaceManager
from app.core.database import get_db
from app.core.report_generator import ReportGenerator

# --- Import Models (Refactored) ---
from app.models.audit_log import AuditLog
from app.models.schemas import (
    AuditRequest, 
    ScanRequest, 
    ExplainRequest, 
    ExportRequest
)

# Initialize Managers
router = APIRouter()
workspace_manager = WorkspaceManager()

# --- Authentication Placeholder ---
async def get_current_user():
    return {"username": "secure_admin", "roles": ["admin"]}

# --- 1. UPLOAD (The Landing Zone) ---
@router.post("/upload")
async def upload_codebase(file: UploadFile = File(...)):
    """
    Accepts a .zip file, creates a session, and returns the session_id.
    """
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    session_id = workspace_manager.create_workspace()
    await workspace_manager.save_and_extract_code(session_id, file)
    
    print(f"✅ Created workspace: {session_id}")
    return {"session_id": session_id, "message": "Codebase uploaded successfully."}

# --- 2. SCOUT (Session Aware) ---
@router.post("/scan")
async def scout_codebase(request: ScanRequest):
    """
    Scans the uploaded codebase for that specific session.
    """
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        root_dir = session_path
        
        parser = PythonParser()
        scan_results = []
        total_hotspots = 0

        print(f"🕵️ Scout scanning session: {root_dir}")

        for file_path in root_dir.rglob("*.py"):
            if "venv" in str(file_path) or "__pycache__" in str(file_path):
                continue
            
            try:
                with open(file_path, "rb") as f:
                    code = f.read()
                
                routes = parser.find_entry_points(code)
                hotspots = parser.find_security_hotspots(code)
                
                if routes or hotspots:
                    rel_path = file_path.relative_to(root_dir)
                    risk_score = len(routes) + (len(hotspots) * 5)
                    scan_results.append({
                        "file": str(rel_path),
                        "risk_score": risk_score,
                        "routes": len(routes),
                        "hotspots": hotspots,
                        "route_details": [{"method": r["method"], "line": r["line"]} for r in routes]
                    })
                    total_hotspots += len(hotspots)
                    
            except Exception as e:
                print(f"⚠️ Error scanning {file_path}: {e}")
                continue

        scan_results.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "status": "complete",
            "session_id": request.session_id,
            "results": scan_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 3. AUDIT (Session Aware) ---
@router.post("/audit", dependencies=[Depends(get_current_user)])
async def audit_code(request: AuditRequest):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # Security: Prevent path traversal
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
             raise HTTPException(status_code=400, detail="Invalid file path.")

        auditor = SecurityAuditor(root_dir=str(session_path))
        report = auditor.audit_file(request.file_path)
        return {"file": request.file_path, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 4. PATCHER (Session Aware) ---
@router.post("/fix", dependencies=[Depends(get_current_user)])
async def fix_code(request: AuditRequest):
    try:
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
             raise HTTPException(status_code=400, detail="Invalid file path.")

        patcher = SecurityPatcher(root_dir=str(session_path))
        fixed_content = patcher.patch_file(request.file_path)
        return {"file": request.file_path, "fixed_code": fixed_content}
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