"""
LangGraph workflow definitions for SentryAgent.

This module defines the state machines that orchestrate the security scanning process.
"""
from langgraph.graph import StateGraph, END
from app.workflows.edge.patch import is_patch_approved
from app.workflows.edge.scan import should_deep_audit, should_prioritize
from app.workflows.node.patch import review_patch_node
from app.workflows.state import ScanState, AuditState, PatchState, ChatState
from app.workflows.node.scan import (
    discover_files,
    parse_and_scan,
    load_organizational_memory,
    deep_audit_high_risk_files,
    prioritize_vulnerabilities,
    generate_report,
)
from app.workflows.node.audit import audit_single_file
from app.workflows.node.chat import run_chat_node
from app.workflows.node.patch import generate_patch, save_patch_to_memory



# ============================================================================
# FULL SCAN WORKFLOW
# ============================================================================

def create_scan_workflow():
    """
    Creates the main security scanning workflow.
    
    Flow:
    1. Discover files
    2. Parse and scan for hotspots
    3. Load organizational memory (parallel)
    4. Conditional: Deep audit if high-risk files found
    5. Conditional: Prioritize if vulnerabilities found
    6. Generate report
    """
    workflow = StateGraph(ScanState)
    
    # Add nodes
    workflow.add_node("discover", discover_files)
    workflow.add_node("parse", parse_and_scan)
    workflow.add_node("memory", load_organizational_memory)
    workflow.add_node("audit", deep_audit_high_risk_files)
    workflow.add_node("prioritize", prioritize_vulnerabilities)
    workflow.add_node("report", generate_report)
    
    # Define the flow
    workflow.set_entry_point("discover")
    workflow.add_edge("discover", "parse")
    workflow.add_edge("parse", "memory")
    
    # Conditional: Should we do deep audit?
    workflow.add_conditional_edges(
        "memory",
        should_deep_audit,
        {
            "audit": "audit",
            "report": "report"
        }
    )
    
    # Conditional: Should we prioritize?
    workflow.add_conditional_edges(
        "audit",
        should_prioritize,
        {
            "prioritize": "prioritize",
            "report": "report"
        }
    )
    
    workflow.add_edge("prioritize", "report")
    workflow.add_edge("report", END)
    
    return workflow.compile()


# ============================================================================
# SINGLE FILE AUDIT WORKFLOW
# ============================================================================

def create_audit_workflow():
    """
    Creates a simple workflow for auditing a single file.
    
    Flow:
    1. Audit file
    2. End
    """
    workflow = StateGraph(AuditState)
    
    workflow.add_node("audit", audit_single_file)
    
    workflow.set_entry_point("audit")
    workflow.add_edge("audit", END)
    
    return workflow.compile()


# ============================================================================
# PATCH GENERATION WORKFLOW
# ============================================================================

def create_patch_workflow():
    workflow = StateGraph(PatchState)
    
    # 1. Generate the fix
    workflow.add_node("patch", generate_patch)
    # 2. Critically review the fix
    workflow.add_node("review", review_patch_node)
    # 3. Save to DB
    workflow.add_node("save_memory", save_patch_to_memory)
    
    workflow.set_entry_point("patch")
    workflow.add_edge("patch", "review")
    
    # ADD A CONDITIONAL LOOP FOR REFLECTION
    workflow.add_conditional_edges(
        "review",
        is_patch_approved,
        {
            "approved": "save_memory",  # If good, save it
            "rejected": "patch"         # If bad, loop back to patcher with feedback
        }
    )
    
    workflow.add_edge("save_memory", END)
    
    return workflow.compile()


# ============================================================================
# CHAT WORKFLOW
# ============================================================================

def create_chat_workflow():
    """
    Creates a simple workflow for chatting about a single file.

    Flow:
    1. Run chat node (calls SecurityAuditor.chat_with_file)
    2. End
    """
    workflow = StateGraph(ChatState)

    workflow.add_node("chat", run_chat_node)

    workflow.set_entry_point("chat")
    workflow.add_edge("chat", END)

    return workflow.compile()


# ============================================================================
# WORKFLOW INSTANCES (Singletons)
# ============================================================================

# Pre-compile workflows for reuse
scan_workflow = create_scan_workflow()
audit_workflow = create_audit_workflow()
patch_workflow = create_patch_workflow()
chat_workflow = create_chat_workflow()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def run_full_scan(
    session_id: str,
    root_dir: str,
    cache_name: str = None,
    config: dict = None
) -> dict:
    """
    Execute a full security scan using the LangGraph workflow.
    
    Args:
        session_id: Unique session identifier
        root_dir: Root directory to scan
        cache_name: Optional Gemini cache name for faster analysis
        config: Scan configuration (risk_threshold, max_audit_files, etc.)
    
    Returns:
        Final report dictionary
    """
    initial_state: ScanState = {
        "session_id": session_id,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "files_to_scan": [],
        "current_file": None,
        "scan_results": [],
        "vulnerabilities": [],
        "current_stage": "init",
        "scan_metadata": {},
        "errors": [],
        "organizational_memory": [],
        "config": config or {
            "risk_threshold": 5,
            "max_audit_files": 10
        }
    }
    
    print(f"🚀 Starting full scan for session: {session_id}")
    print(f"📁 Root directory: {root_dir}")
    
    # Run the workflow
    result = await scan_workflow.ainvoke(initial_state)
    
    print(f"✅ Scan complete! Stage: {result['current_stage']}")
    
    return result["scan_metadata"]["final_report"]


async def run_file_audit(
    session_id: str,
    file_path: str,
    root_dir: str,
    cache_name: str = None
) -> dict:
    """
    Audit a single file using the LangGraph workflow.
    
    Args:
        session_id: Unique session identifier
        file_path: Relative path to file
        root_dir: Root directory
        cache_name: Optional Gemini cache name
    
    Returns:
        Audit report
    """
    initial_state: AuditState = {
        "session_id": session_id,
        "file_path": file_path,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "vulnerabilities": [],
        "audit_report": {},
        "current_stage": "init",
        "error": None
    }
    
    print(f"🕵️ Auditing file: {file_path}")
    
    result = await audit_workflow.ainvoke(initial_state)
    
    if result["current_stage"] == "error":
        raise Exception(result["error"])
    
    return result["audit_report"]


async def run_patch_generation(
    session_id: str,
    file_path: str,
    root_dir: str,
    cache_name: str = None
) -> str:
    """
    Generate a security patch using the LangGraph workflow.
    
    Args:
        session_id: Unique session identifier
        file_path: Relative path to file
        root_dir: Root directory
        cache_name: Optional Gemini cache name
    
    Returns:
        Patched code
    """
    initial_state: PatchState = {
        "session_id": session_id,
        "file_path": file_path,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "vulnerabilities": [],
        "original_code": "",
        "patched_code": "",
        "patch_applied": False,
        "current_stage": "init",
        "error": None,
        # Required by is_patch_approved() and review_patch_node()
        "retry_count": 0,
        "is_approved": False,
        "review_feedback": None,
    }
    
    print(f"🔧 Generating patch for: {file_path}")
    
    result = await patch_workflow.ainvoke(initial_state)
    
    if result["current_stage"] == "error":
        raise Exception(result["error"])
    
    return result["patched_code"]


async def run_chat(
    session_id: str,
    file_path: str,
    root_dir: str,
    query: str,
    cache_name: str = None,
) -> str:
    """
    Answer a developer's question about a specific file using the LangGraph chat workflow.

    Args:
        session_id: Unique session identifier
        file_path: Relative path to the file being discussed
        root_dir: Root directory of the workspace
        query: Developer's question
        cache_name: Optional Gemini cache name

    Returns:
        AI-generated response string
    """
    initial_state: ChatState = {
        "session_id": session_id,
        "file_path": file_path,
        "root_dir": root_dir,
        "query": query,
        "cache_name": cache_name,
        "conversation_history": [],
        "response": "",
        "current_stage": "init",
        "error": None,
    }

    print(f"💬 Starting chat for file: {file_path}")

    result = await chat_workflow.ainvoke(initial_state)

    if result["current_stage"] == "error":
        raise Exception(result.get("error", "Chat failed"))

    return result["response"]
