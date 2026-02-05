from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import our new Auditor
from app.agent.auditor import SecurityAuditor

app = FastAPI(
    title="Vibe Security Agent",
    description="AI-powered security auditor for FastAPI backends",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    file_path: str

@app.get("/health")
async def health_check():
    return {"status": "active", "version": "0.1.0"}

@app.post("/audit")
async def audit_code(request: AuditRequest):
    """
    Triggers the AI to audit a specific file.
    Example payload: {"file_path": "main.py"}
    """
    try:
        # Initialize auditor (pointing to the internal /app/app directory)
        auditor = SecurityAuditor(root_dir="app")
        report = auditor.audit_file(request.file_path)
        return {"file": request.file_path, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)