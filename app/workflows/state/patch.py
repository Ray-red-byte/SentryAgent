from typing import TypedDict, Literal, Optional
from app.workflows.state.common import Vulnerability

class PatchState(TypedDict):
    """State for patching workflow."""
    session_id: str
    root_dir: str
    cache_name: Optional[str]

    # Primary file being patched (required — patcher tools target a single file)
    file_path: str

    # All files in the originating security bundle. The ReAct agent uses these
    # for cross-file data-flow context and may call patch tools on any of them.
    involved_files: list[str]

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
    user_feedback: Optional[str]    # Feedback from the human user (reject & retry)
    is_approved: bool               # Flag to determine routing
    retry_count: int                # Counter to prevent infinite loops
