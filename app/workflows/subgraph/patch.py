from langgraph.prebuilt import create_react_agent
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager  # Import your manager
from app.tools.patch import (
    search_owasp_guidelines,
    read_file,
    replace_function,          # NEW — preferred surgical tool
    replace_class_method,      # NEW — preferred for method-level fixes
    apply_diff,                # NEW — fallback diff tool
    write_code_patch,          # KEPT — last-resort full-file rewrite
    check_syntax,
    run_security_scanner,
    run_unit_tests,            # NEW — functional verification
)

def build_patcher_agent():
    """
    Compiles the ReAct agent using centralized prompts from the /prompts folder.
    Now registers surgical patching tools in preferred order.
    """
    llm = GeminiClient().get_model()
    pm = PromptManager()

    # Centralized tools list — ordered by preference (most surgical first)
    tools = [
        search_owasp_guidelines,
        read_file,
        replace_function,          # PREFERRED — surgical function-level fix
        replace_class_method,      # PREFERRED — surgical method-level fix
        apply_diff,                # FALLBACK — line-level search-replace
        write_code_patch,          # LAST RESORT — full-file rewrite
        check_syntax,
        run_security_scanner,
        run_unit_tests,            # VERIFICATION — functional regression check
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