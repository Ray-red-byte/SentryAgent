from typing import TypedDict, Literal, Optional
from app.workflows.state.common import Vulnerability

class AuditState(TypedDict):
    """State for single-file or security-bundle audit workflow."""
    session_id: str
    root_dir: str
    cache_name: Optional[str]

    # Single-file path (optional — kept for /audit endpoint backward compat).
    # When auditing a bundle, set to None; involved_files carries the paths.
    file_path: Optional[str]

    # Bundle fields (new). For a single-file audit the caller sets:
    #   security_bundle_name = filename, involved_files = [file_path]
    security_bundle_name: Optional[str]   # e.g. "authentication"
    involved_files: list[str]             # all file paths in this bundle

    # Results
    vulnerabilities: list[Vulnerability]
    audit_report: dict

    # Workflow
    current_stage: Literal["init", "analyzing", "complete", "error"]
    error: Optional[str]
