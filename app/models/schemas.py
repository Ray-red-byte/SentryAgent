from pydantic import BaseModel
from typing import List, Optional

# --- Request Models ---

class AuditRequest(BaseModel):
    session_id: str
    file_path: str

class ScanRequest(BaseModel):
    session_id: str

class ExplainRequest(BaseModel):
    report: List[dict]

class ExportRequest(BaseModel):
    session_id: str
    scan_results: List[dict]

class ChatRequest(BaseModel):
    session_id: str
    file_path: str
    query: str

class ApplyFixRequest(BaseModel):
    session_id: str
    file_path: str
    fixed_code: str
    # Optional metadata for knowledge base learning
    vuln_type: Optional[str] = "Security Fix"
    severity: Optional[str] = "UNKNOWN"
    cwe: Optional[str] = ""