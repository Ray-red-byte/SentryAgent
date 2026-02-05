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