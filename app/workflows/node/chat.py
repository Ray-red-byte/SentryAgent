"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
from app.workflows.state import ChatState
from app.agent.auditor import SecurityAuditor

import logging

logger = logging.getLogger(__name__)

def run_chat_node(state: ChatState) -> ChatState:
    """
    Chat workflow node: answers developer questions about a specific file.
    Uses the Gemini cache (fast path) when available, otherwise reads the file
    directly (slow path).
    """
    print(f"💬 [CHAT] Processing query for {state['file_path']}...")

    try:
        auditor = SecurityAuditor(root_dir=state["root_dir"])

        # Build the full path for the slow-path fallback
        from pathlib import Path as _Path
        full_path = str(_Path(state["root_dir"]) / state["file_path"])

        response = auditor.chat_with_file(
            file_path=state["file_path"],
            query=state["query"],
            cache_name=state.get("cache_name"),
            full_path=full_path,
        )

        print("✅ [CHAT] Response generated")

        return {
            **state,
            "response": response,
            "current_stage": "complete"
        }

    except Exception as e:
        print(f"❌ [CHAT] Error: {e}")
        return {
            **state,
            "response": f"Error: {str(e)}",
            "current_stage": "error",
            "error": str(e)
        }