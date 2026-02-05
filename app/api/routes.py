import os
import shutil
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile
from pydantic import BaseModel
from typing import List, Optional

# Import Agents & Core
from app.agent.auditor import SecurityAuditor
from app.agent.patcher import SecurityPatcher
from app.parser.python_parser import PythonParser
from app.agent.translator import SecurityTranslator
from app.core.workspace import WorkspaceManager

# Initialize Managers
router = APIRouter()
workspace_manager = WorkspaceManager()

# --- Authentication Placeholder ---
async def get_current_user():
    return {"username": "secure_admin", "roles": ["admin"]}

# --- Request Models (Now with session_id) ---
class AuditRequest(BaseModel):
    session_id: str
    file_path: str

class ScanRequest(BaseModel):
    session_id: str

class ExplainRequest(BaseModel):
    report: List[dict]

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
        # Get the real path for this session (e.g., temp_workspaces/abc-123/app)
        session_path = workspace_manager.get_workspace_path(request.session_id)
        
        # We assume the zip contained an "app" folder or similar. 
        # We scan the whole session folder.
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
                    # Make path relative to the session root for display
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
        
        # Security: Prevent path traversal out of session
        full_target_path = (session_path / request.file_path).resolve()
        if not str(full_target_path).startswith(str(session_path.resolve())):
             raise HTTPException(status_code=400, detail="Invalid file path.")

        # Initialize Auditor with the SESSION DIRECTORY
        auditor = SecurityAuditor(root_dir=str(session_path))
        
        # Pass the relative file path to the auditor
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

# --- 5. EXPLAINER (No File Access Needed) ---
@router.post("/explain", dependencies=[Depends(get_current_user)])
async def explain_report(request: ExplainRequest):
    try:
        translator = SecurityTranslator()
        explanation = translator.translate_report(request.report)
        return {"explanation": explanation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    return {"status": "active", "version": "0.2.0-session-aware"}