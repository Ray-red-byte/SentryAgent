from typing import TypedDict, Annotated, Literal, Optional
import operator
from app.workflows.state.common import ScanResult, Vulnerability

class ScanState(TypedDict):
    """
    State passed between workflow nodes.

    This state is the single source of truth for the entire scanning workflow.
    Each node reads from and writes to this state.
    """
    # Session Information
    session_id: str
    root_dir: str
    cache_name: Optional[str]

    # Files to Process
    files_to_scan: list[str]          # raw file list from discover_files
    current_file: Optional[str]

    # Security domain bundles: domain_name -> [file_paths]
    security_bundles: dict[str, list[str]]

    # Scan Results (accumulated across all files)
    scan_results: list[ScanResult]
    vulnerabilities: Annotated[list[Vulnerability], operator.add]

    # Workflow Control
    current_stage: Literal[
        "init",
        "discovered",
        "scanned",   # after parse_and_scan
        "bundled",   # after bundle_into_security_domains
        "complete",
        "error",
    ]

    # Metadata
    scan_metadata: dict
    errors: Annotated[list[str], operator.add]

    # Configuration
    config: dict  # Scan configuration (depth, rules, etc.)
