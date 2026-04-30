from langgraph.graph import StateGraph, END
from app.workflows.state import ScanState
from app.workflows.node.scan import (
    discover_files,
    parse_and_scan,
    bundle_into_security_domains,
    load_organizational_memory,
    generate_report,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_scan_workflow():
    """
    Lean scan workflow: discover → parse → bundle → memory → report.

    The deep AI audit step has been removed from this graph.
    Per-bundle auditing happens on demand via the /audit endpoint,
    keeping the /scan response fast (no LLM calls during scan).
    """
    workflow = StateGraph(ScanState)

    workflow.add_node("discover", discover_files)
    workflow.add_node("parse", parse_and_scan)
    workflow.add_node("bundle", bundle_into_security_domains)
    workflow.add_node("memory", load_organizational_memory)
    workflow.add_node("report", generate_report)

    workflow.set_entry_point("discover")
    workflow.add_edge("discover", "parse")
    workflow.add_edge("parse", "bundle")
    workflow.add_edge("bundle", "memory")
    workflow.add_edge("memory", "report")
    workflow.add_edge("report", END)

    return workflow.compile()
