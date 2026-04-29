from typing import TypedDict, Literal, Optional

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
