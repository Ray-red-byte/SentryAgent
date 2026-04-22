"""
State definitions for LangGraph workflows.
This module defines the shared state that flows through the security scanning workflow.
"""
from typing import TypedDict, Annotated, Literal, Optional
import operator
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Vulnerability:
    """Represents a single security vulnerability."""
    type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    file: str
    line: int
    description: str
    fix_suggestion: str
    cvss_score: float = 0.0
    exploitability: float = 0.0
    fix_available: bool = False
    
    def priority_score(self) -> int:
        """Calculate fix priority based on severity and exploitability."""
        base = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10
        }[self.severity]
        
        if self.exploitability > 0.8:
            base *= 1.5
        if self.fix_available:
            base *= 1.2
            
        return int(base)


@dataclass
class ScanResult:
    """Results from scanning a single file."""
    file_path: str
    risk_score: int
    routes: int
    hotspots: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


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
    files_to_scan: list[str]
    current_file: Optional[str]
    
    # Scan Results (accumulated across all files)
    scan_results: list[ScanResult]
    vulnerabilities: Annotated[list[Vulnerability], operator.add]
    
    # Workflow Control
    current_stage: Literal[
        "init",
        "discovered", 
        "parsed",
        "scanned",
        "audited",
        "prioritized",
        "patched",
        "reported",
        "complete",
        "error"
    ]
    
    # Metadata
    scan_metadata: dict
    errors: Annotated[list[str], operator.add]
    
    # Context for AI agents
    organizational_memory: list[str]  # Past lessons from knowledge base
    
    # Configuration
    config: dict  # Scan configuration (depth, rules, etc.)


class AuditState(TypedDict):
    """State for single-file audit workflow."""
    session_id: str
    file_path: str
    root_dir: str
    cache_name: Optional[str]
    
    # Results
    vulnerabilities: list[Vulnerability]
    audit_report: dict
    
    # Workflow
    current_stage: Literal["init", "analyzing", "complete", "error"]
    error: Optional[str]


class PatchState(TypedDict):
    """State for patching workflow."""
    session_id: str
    file_path: str
    root_dir: str
    cache_name: Optional[str]
    
    # Input
    vulnerabilities: list[Vulnerability]
    original_code: str
    
    # Output
    patched_code: str
    patch_applied: bool
    
    # Workflow
    current_stage: Literal["init", "analyzing", "patching", "validating", "complete", "error"]
    error: Optional[str]

    review_feedback: Optional[str]  # Feedback from the reviewer LLM
    is_approved: bool               # Flag to determine routing
    retry_count: int                # Counter to prevent infinite loops


class ChatState(TypedDict):
    """State for interactive chat workflow."""
    session_id: str
    file_path: str
    root_dir: str
    query: str
    cache_name: Optional[str]
    
    # Context
    conversation_history: list[dict]
    
    # Response
    response: str
    
    # Workflow
    current_stage: Literal["init", "processing", "complete", "error"]
    error: Optional[str]
