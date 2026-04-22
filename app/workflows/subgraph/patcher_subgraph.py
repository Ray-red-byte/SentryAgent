from langgraph.prebuilt import create_react_agent
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager  # Import your manager
from app.tools.patch import (
    search_owasp_guidelines,
    read_file,
    write_code_patch,
    check_syntax,
    run_security_scanner,
)

def build_patcher_agent():
    """
    Compiles the ReAct agent using centralized prompts from the /prompts folder.
    """
    llm = GeminiClient().get_model()
    pm = PromptManager()

    # Centralized tools list
    tools = [
        search_owasp_guidelines,
        read_file,
        write_code_patch,
        check_syntax,
        run_security_scanner,
    ]

    # Load the system prompt from prompts/patcher/default.md
    # Note: We don't pass variables here because this is the SYSTEM instruction.
    # The variables like {target_file} will be filled by the LLM during the ReAct loop 
    # or passed in the user message.
    prompt = pm.get_prompt("patcher.default")

    return create_react_agent(
        model=llm,
        tools=tools,
        prompt=prompt,
    )

patcher_graph = build_patcher_agent()