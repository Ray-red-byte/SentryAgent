from langgraph.graph import StateGraph, END
from app.workflows.state import ScanState
from app.workflows.node.scan import (
    discover_files,
    parse_and_scan,
    bundle_into_security_domains,
    generate_report,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_scan_workflow():
    """
    Lean scan workflow: discover → parse → bundle → report.

    No LLM calls during scan. Per-bundle auditing happens on demand via /audit.
    ChromaDB lessons are queried directly by SecurityAuditor and generate_patch
    at call time, so pre-loading organizational memory into ScanState is unnecessary.
    """
    workflow = StateGraph(ScanState)

    workflow.add_node("discover", discover_files)
    workflow.add_node("parse", parse_and_scan)
    workflow.add_node("bundle", bundle_into_security_domains)
    workflow.add_node("report", generate_report)

    workflow.set_entry_point("discover")
    workflow.add_edge("discover", "parse")
    workflow.add_edge("parse", "bundle")
    workflow.add_edge("bundle", "report")
    workflow.add_edge("report", END)

    return workflow.compile()
