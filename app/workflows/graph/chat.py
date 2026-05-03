from langgraph.graph import StateGraph, END
from app.workflows.state import ChatState
from app.workflows.node.chat import run_chat_node
from app.utils.logger import get_logger

logger = get_logger(__name__)

def create_chat_workflow():
    workflow = StateGraph(ChatState)
    workflow.add_node("chat", run_chat_node)
    workflow.set_entry_point("chat")
    workflow.add_edge("chat", END)
    return workflow.compile()
