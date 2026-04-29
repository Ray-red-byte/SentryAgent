from langgraph.graph import StateGraph, END
from app.workflows.edge.scan import should_deep_audit, should_prioritize
from app.workflows.state import ScanState
from app.workflows.node.scan import (
    discover_files,
    parse_and_scan,
    bundle_into_security_domains,
    load_organizational_memory,
    deep_audit_high_risk_files,
    prioritize_vulnerabilities,
    generate_report,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_scan_workflow():
    workflow = StateGraph(ScanState)
    # Add nodes
    workflow.add_node("discover", discover_files)
    workflow.add_node("parse", parse_and_scan)
    workflow.add_node("bundle", bundle_into_security_domains)
    workflow.add_node("memory", load_organizational_memory)
    workflow.add_node("audit", deep_audit_high_risk_files)
    workflow.add_node("prioritize", prioritize_vulnerabilities)
    workflow.add_node("report", generate_report)

    # Define the flow
    workflow.set_entry_point("discover")
    workflow.add_edge("discover", "parse")
    workflow.add_edge("parse", "bundle")
    workflow.add_edge("bundle", "memory")

    workflow.add_conditional_edges(
        "memory",
        should_deep_audit,
        {
            "audit": "audit",
            "report": "report"
        }
    )

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
