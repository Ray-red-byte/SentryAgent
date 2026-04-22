"""
app/tools/patch.py

Granular @tool functions used by the ReAct patcher agent.
Each tool is a pure, standalone function with robust error-handling so a
single failure never crashes the entire agent loop.
"""

import ast
import os
import subprocess
from langchain_core.tools import tool

@tool
def search_owasp_guidelines(query: str) -> str:
    """
    Searches the SentryAgent SecurityKnowledgeBase (ChromaDB) for mitigation
    strategies relevant to a given vulnerability type or query.

    Use this FIRST before writing any patch. For example, if the vulnerability
    is "SQL Injection", call search_owasp_guidelines("SQL Injection mitigation
    Python parameterized queries") to retrieve authoritative fix patterns.

    Returns a formatted string of the top matching knowledge entries.
    """
    try:
        from app.memory.knowledge_base import SecurityKnowledgeBase
        kb = SecurityKnowledgeBase()
        lessons = kb.recall_relevant_lessons(query, n_results=3)
        if not lessons:
            return "No specific OWASP guidance found for this query. Use general secure coding best practices."
        return "\n\n".join(lessons)
    except Exception as e:
        return f"Knowledge base unavailable: {e}. Proceed with standard OWASP best practices."
    
@tool
def read_file(file_path: str) -> str:
    """
    Reads and returns the current contents of a file from disk.

    Use this BEFORE writing a patch to understand the existing code structure.
    The file_path must be an absolute path to the file inside the session workspace.

    Returns the file contents as a string, or an error message if the file
    cannot be found.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return f"ERROR: File not found: {file_path}"
    except OSError as e:
        return f"ERROR: Could not read {file_path}: {e}"

@tool
def write_code_patch(file_path: str, patched_code: str) -> str:
    """
    Overwrites the file at file_path with the provided patched_code.

    Call this AFTER formulating the complete, corrected source. Always call
    check_syntax immediately afterwards to verify the written code is valid.

    Returns a success or error message.
    """
    try:
        # Ensure the parent directory exists
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(patched_code)
        return f"SUCCESS: Patch written to {file_path} ({len(patched_code)} chars)."
    except OSError as e:
        return f"ERROR: Could not write patch to {file_path}: {e}"
    
@tool
def check_syntax(file_path: str) -> str:
    """
    Reads the file at file_path and validates that it contains syntactically
    correct Python using the built-in `ast` module.

    Call this AFTER write_code_patch. If syntax errors are found, fix the code
    and call write_code_patch + check_syntax again until it passes.

    Returns "SYNTAX OK" on success, or a description of the SyntaxError.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        ast.parse(source)
        return "SYNTAX OK: The file contains valid Python syntax."
    except FileNotFoundError:
        return f"ERROR: File not found: {file_path}"
    except SyntaxError as e:
        return (
            f"SYNTAX ERROR on line {e.lineno}: {e.msg}\n"
            f"  Offending text: {e.text!r}\n"
            "Fix the syntax error and call write_code_patch + check_syntax again."
        )
    except OSError as e:
        return f"ERROR: Could not read {file_path}: {e}"

@tool
def run_security_scanner(file_path: str) -> str:
    """
    Runs the `bandit` static security analyser on the file at file_path to
    verify that known vulnerabilities have been resolved in the patched code.

    Call this LAST in the loop, after check_syntax passes. If bandit still
    reports HIGH or MEDIUM severity issues related to the original vulnerability,
    refine the patch and repeat the cycle.

    Returns a summary of bandit findings or "NO ISSUES" if the file is clean.
    If bandit is not installed, falls back to a short note so the agent can
    continue gracefully.
    """
    try:
        result = subprocess.run(
            ["bandit", "-r", file_path, "-f", "text", "-ll"],  # -ll = only HIGH severity
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode == 0:
            return "SECURITY SCAN PASSED: No high-severity issues found by bandit."
        # returncode 1 = issues found
        # Truncate to avoid overwhelming the agent context
        return f"SECURITY SCAN FINDINGS (HIGH severity):\n{output[:2000]}"
    except FileNotFoundError:
        # bandit not installed in the container — degrade gracefully
        return (
            "bandit is not installed. Skipping automated security scan. "
            "Ensure the patch addresses each reported vulnerability manually."
        )
    except subprocess.TimeoutExpired:
        return "SECURITY SCAN TIMEOUT: bandit took too long. Proceed with manual review."
    except Exception as e:
        return f"SECURITY SCAN ERROR: {e}"


# ============================================================================
# LEGACY TOOLS (kept for backward compatibility with older subgraph versions)
# ============================================================================

@tool
def run_pytest(file_path: str) -> str:
    """
    Executes pytest on a specific file to verify syntax and logic.
    Returns the STDOUT and STDERR of the test run.
    """
    try:
        result = subprocess.run(
            ["pytest", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        status = "PASSED" if result.returncode == 0 else "FAILED"
        return f"pytest {status}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    except Exception as e:
        return f"ERROR: {e}"


@tool
def write_to_file(file_path: str, content: str) -> str:
    """
    Writes the provided content to the specified file_path.
    Kept for backward compatibility. Prefer write_code_patch for new code.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"SUCCESS: wrote to {file_path}"
    except Exception as e:
        return f"ERROR: {e}"


@tool
def ast_check(code: str) -> str:
    """
    Validates that a Python code string has valid syntax using the AST parser.
    Kept for backward compatibility. Prefer check_syntax for new code.
    """
    try:
        ast.parse(code)
        return "SYNTAX OK: valid Python."
    except SyntaxError as e:
        return f"SYNTAX ERROR on line {e.lineno}: {e.msg}"
