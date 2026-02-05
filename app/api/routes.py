from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.agent.auditor import SecurityAuditor

# Create a Router (like a mini-app)
router = APIRouter()

# Move the Pydantic Model here
class AuditRequest(BaseModel):
    file_path: str

@router.get("/health")
async def health_check():
    return {"status": "active", "version": "0.1.0"}

@router.post("/audit")
async def audit_code(request: AuditRequest):
    """
    Triggers the AI to audit a specific file.
    Example payload: {"file_path": "main.py"}
    """
    try:
        # We assume the root is 'app' since this runs inside Docker
        auditor = SecurityAuditor(root_dir="app")
        report = auditor.audit_file(request.file_path)
        return {"file": request.file_path, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))