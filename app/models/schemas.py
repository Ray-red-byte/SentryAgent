from pydantic import BaseModel
from typing import List, Optional

# --- Request Models ---

class AuditRequest(BaseModel):
    session_id: str
    file_path: str
    # Bundle audit fields (optional — omit for single-file audit)
    bundle_name: Optional[str] = None
    involved_files: Optional[List[str]] = None

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

class FixRequest(BaseModel):
    session_id: str
    file_path: str
    # Bundle fields — omit for single-file fixes
    bundle_name: Optional[str] = None
    involved_files: Optional[List[str]] = None
    # Vulnerability list — when provided, the patcher targets every item
    vulnerabilities: Optional[List[dict]] = None

class ApplyFixRequest(BaseModel):
    session_id: str
    file_path: str
    fixed_code: str
    # Optional metadata for knowledge base learning
    vuln_type: Optional[str] = "Security Fix"
    severity: Optional[str] = "UNKNOWN"
    cwe: Optional[str] = ""

class FixRejectRequest(BaseModel):
    """User rejects a generated patch and provides feedback for re-generation."""
    session_id: str
    file_path: str
    feedback: str  # User's reason for rejection (e.g. "Use argon2 instead of bcrypt")
    # Re-pass the original context so we can re-invoke the patcher
    bundle_name: Optional[str] = None
    involved_files: Optional[List[str]] = None
    vulnerabilities: Optional[List[dict]] = None