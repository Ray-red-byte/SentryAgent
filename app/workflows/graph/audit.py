from langgraph.graph import StateGraph, END
from app.workflows.state import AuditState
from app.workflows.node.audit import audit_security_bundle
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_audit_workflow():
    workflow = StateGraph(AuditState)
    workflow.add_node("audit", audit_security_bundle)
    workflow.set_entry_point("audit")
    workflow.add_edge("audit", END)
    return workflow.compile()
