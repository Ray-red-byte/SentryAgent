from langgraph.graph import StateGraph, END
from app.workflows.edge.patch import is_patch_approved, route_after_patch
from app.workflows.node.patch import review_patch_node, generate_patch, save_patch_to_memory
from app.workflows.state import PatchState
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_patch_workflow():
    workflow = StateGraph(PatchState)
    workflow.add_node("patch", generate_patch)
    workflow.add_node("review", review_patch_node)
    workflow.add_node("save_memory", save_patch_to_memory)
    
    workflow.set_entry_point("patch")
    
    workflow.add_conditional_edges(
        "patch",
        route_after_patch,
        {
            "review": "review",
            "error": END
        }
    )
    
    workflow.add_conditional_edges(
        "review",
        is_patch_approved,
        {
            "approved": "save_memory",
            "rejected": "patch"
        }
    )
    
    workflow.add_edge("save_memory", END)
    
    return workflow.compile()
