import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List

# Import Agents
from app.agent.auditor import SecurityAuditor
from app.agent.patcher import SecurityPatcher
from app.parser.python_parser import PythonParser

# --- Authentication Dependency Placeholder ---
async def get_current_user():
    # In a real app, you would decode a JWT or check a session here.
    return {"username": "secure_admin", "roles": ["admin"]}

# --- Input Validation Helper ---
def validate_file_path_within_root(requested_path: str, root_dir_str: str) -> Path:
    """
    Prevents Path Traversal (e.g., '../../etc/passwd').
    Ensures the file is actually inside the 'app' folder.
    """
    base_path = Path(root_dir_str).resolve()
    full_resolved_path = (Path.cwd() / requested_path).resolve()

    if not full_resolved_path.is_file():
        raise HTTPException(status_code=400, detail=f"File not found: '{requested_path}'")

    # The Logic: Is the full path inside the base path?
    try:
        relative_to_root = full_resolved_path.relative_to(base_path)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path: Path traversal attempt detected.")

    return relative_to_root

router = APIRouter()

class AuditRequest(BaseModel):
    file_path: str

@router.get("/health")
async def health_check():
    return {"status": "active", "version": "0.1.0"}

@router.get("/scan")
async def scout_codebase():
    """
    Advanced SAST Scan.
    Identifies Attack Surface (Routes) AND Dangerous Sinks (Hotspots).
    """
    root_dir = Path("app")
    parser = PythonParser()
    
    scan_results = []
    total_hotspots = 0

    print(f"🕵️ Scout scanning directory: {root_dir.absolute()}")

    for file_path in root_dir.rglob("*.py"):
        if "venv" in str(file_path) or "__pycache__" in str(file_path):
            continue
        
        try:
            with open(file_path, "rb") as f:
                code = f.read()
            
            # 1. Find Attack Surface (Routes)
            routes = parser.find_entry_points(code)
            
            # 2. Find Dangerous Sinks (Hotspots)
            hotspots = parser.find_security_hotspots(code)
            
            # Logic: A file is interesting if it has Routes OR Hotspots
            if routes or hotspots:
                risk_score = len(routes) + (len(hotspots) * 5) # Hotspots are weighted higher
                
                scan_results.append({
                    "file": str(file_path),
                    "risk_score": risk_score,
                    "routes": len(routes),
                    "hotspots": hotspots, # List of specific dangers
                    "route_details": [{"method": r["method"], "line": r["line"]} for r in routes]
                })
                total_hotspots += len(hotspots)
                
        except Exception as e:
            print(f"⚠️ Error scanning {file_path}: {e}")
            continue

    # Sort results so the most dangerous files are at the top
    scan_results.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "status": "complete",
        "total_files_flagged": len(scan_results),
        "total_security_hotspots": total_hotspots,
        "results": scan_results
    }

# --- SECURE ENDPOINTS ---

@router.post("/audit", dependencies=[Depends(get_current_user)]) # <--- LOCKED
async def audit_code(request: AuditRequest):
    try:
        root_dir = "app"
        # Validate Input
        safe_path = validate_file_path_within_root(request.file_path, root_dir)
        
        auditor = SecurityAuditor(root_dir=root_dir)
        report = auditor.audit_file(str(safe_path))
        return {"file": request.file_path, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/fix", dependencies=[Depends(get_current_user)]) # <--- LOCKED
async def fix_code(request: AuditRequest):
    try:
        root_dir = "app"
        # Validate Input
        safe_path = validate_file_path_within_root(request.file_path, root_dir)
        
        patcher = SecurityPatcher(root_dir=root_dir)
        fixed_content = patcher.patch_file(str(safe_path))
        return {"file": request.file_path, "fixed_code": fixed_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))