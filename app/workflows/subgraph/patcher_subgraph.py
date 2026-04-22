"""
app/workflows/subgraph/patcher_subgraph.py

LangGraph ReAct subgraph that autonomously researches, writes, and verifies
security patches using a loop of specialised tools.

The agent follows a strict ReAct cycle:
  1. search_owasp_guidelines  — understand the correct fix pattern
  2. read_file                — inspect the current (vulnerable) code
  3. write_code_patch         — apply a surgical fix
  4. check_syntax             — confirm the patched code is valid Python
  5. run_security_scanner     — confirm the vulnerability is resolved
  → repeat steps 3-5 until both checks pass, then return the final code.

Usage (invoked from app/workflows/node/patch.py):
    from app.workflows.subgraph.patcher_subgraph import patcher_graph
    result = patcher_graph.invoke({"messages": [("user", message)]})
"""

from langgraph.prebuilt import create_react_agent

from app.agent.gemini_client import GeminiClient
from app.tools.patch import (
    search_owasp_guidelines,
    read_file,
    write_code_patch,
    check_syntax,
    run_security_scanner,
)

# ---------------------------------------------------------------------------
# System prompt — drives the ReAct loop
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """
You are an elite Senior Security Engineer specialising in Python application hardening.
Your mission: fix security vulnerabilities with minimal, surgical code changes.

## Strict workflow — follow this order every time

1. **Research** — Call `search_owasp_guidelines` with the vulnerability type (e.g.
   "SQL Injection Python parameterized queries") to retrieve authoritative fix patterns
   from the OWASP knowledge base BEFORE writing any code.

2. **Read** — Call `read_file` with the absolute file path to understand the current
   code structure. Never guess what the file contains.

3. **Patch** — Call `write_code_patch` with the complete corrected source.  
   Rules for a good patch:
   - Fix ONLY the reported vulnerabilities. Do not refactor unrelated code.
   - Preserve all existing imports, function signatures, and logic.
   - Add only the minimal imports required by your fix.
   - Never introduce new security issues.

4. **Syntax check** — Call `check_syntax` on the patched file.
   If it returns a SYNTAX ERROR, fix the code and call `write_code_patch` +
   `check_syntax` again. Do not proceed until syntax is clean.

5. **Security scan** — Call `run_security_scanner` on the patched file.
   If it reports HIGH-severity issues related to the original vulnerability,
   refine your patch and repeat steps 3-5.

6. **Done** — Once both checks pass, output a concise summary of what you changed
   and enclose the complete final patched file content inside a ```python ... ```
   code block. This is mandatory — the system extracts the patch from your final
   message.

## Important constraints
- Never skip the search_owasp_guidelines step.
- Never skip check_syntax.
- If run_security_scanner is unavailable, note it and rely on check_syntax instead.
- Do not truncate the patched code in your final response.
""".strip()


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_patcher_agent():
    """
    Compiles and returns a LangGraph ReAct agent (StateGraph) wired with the
    five security-patching tools.

    Returns a compiled LangGraph runnable ready to be called with:
        result = patcher_graph.invoke({"messages": [("user", ...)]})
    """
    llm = GeminiClient().get_model()

    tools = [
        search_owasp_guidelines,
        read_file,
        write_code_patch,
        check_syntax,
        run_security_scanner,
    ]

    return create_react_agent(
        model=llm,
        tools=tools,
        prompt=_SYSTEM_PROMPT,
    )


# ---------------------------------------------------------------------------
# Module-level singleton — import this in node files
# ---------------------------------------------------------------------------

patcher_graph = build_patcher_agent()
