from app.workflows.graph.scan import create_scan_workflow
from app.workflows.graph.audit import create_audit_workflow
from app.workflows.graph.patch import create_patch_workflow
from app.workflows.graph.chat import create_chat_workflow
from app.workflows.state import ScanState, AuditState, PatchState, ChatState
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Centralized workflow singletons
scan_workflow = create_scan_workflow()
audit_workflow = create_audit_workflow()
patch_workflow = create_patch_workflow()
chat_workflow = create_chat_workflow()

async def run_full_scan(
    session_id: str,
    root_dir: str,
    cache_name: str = None,
    config: dict = None
) -> dict:
    initial_state: ScanState = {
        "session_id": session_id,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "files_to_scan": [],
        "current_file": None,
        "security_bundles": {},
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
    
    logger.info("Starting full scan for session: %s", session_id)
    logger.info("Root directory: %s", root_dir)
    
    result = await scan_workflow.ainvoke(initial_state)
    
    logger.info("Scan complete! Stage: %s", result['current_stage'])
    return result["scan_metadata"]["final_report"]


async def run_file_audit(
    session_id: str,
    file_path: str,
    root_dir: str,
    cache_name: str = None
) -> dict:
    initial_state: AuditState = {
        "session_id": session_id,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "file_path": file_path,
        "security_bundle_name": file_path,
        "involved_files": [file_path],
        "vulnerabilities": [],
        "audit_report": {},
        "current_stage": "init",
        "error": None,
    }

    logger.info("Auditing file: %s", file_path)

    result = await audit_workflow.ainvoke(initial_state)

    if result["current_stage"] == "error":
        raise Exception(result["error"])

    return result["audit_report"]


async def run_bundle_audit(
    session_id: str,
    bundle_name: str,
    involved_files: list[str],
    root_dir: str,
    cache_name: str = None,
) -> dict:
    initial_state: AuditState = {
        "session_id": session_id,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "file_path": None,
        "security_bundle_name": bundle_name,
        "involved_files": involved_files,
        "vulnerabilities": [],
        "audit_report": {},
        "current_stage": "init",
        "error": None,
    }

    logger.info("Auditing bundle '%s' (%d file(s))", bundle_name, len(involved_files))

    result = await audit_workflow.ainvoke(initial_state)

    if result["current_stage"] == "error":
        raise Exception(result["error"])

    return result["audit_report"]


async def run_patch_generation(
    session_id: str,
    file_path: str,
    root_dir: str,
    cache_name: str = None,
    involved_files: list[str] = None,
    vulnerabilities: list = None,
) -> str:
    initial_state: PatchState = {
        "session_id": session_id,
        "file_path": file_path,
        "root_dir": root_dir,
        "cache_name": cache_name,
        "involved_files": involved_files if involved_files is not None else [file_path],
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
        "original_code": "",
        "patched_code": "",
        "patch_applied": False,
        "current_stage": "init",
        "error": None,
        "retry_count": 0,
        "is_approved": False,
        "review_feedback": None,
    }
    
    logger.info("Generating patch for: %s", file_path)
    
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

    logger.info("Starting chat for file: %s", file_path)

    result = await chat_workflow.ainvoke(initial_state)

    if result["current_stage"] == "error":
        raise Exception(result.get("error", "Chat failed"))

    return result["response"]
