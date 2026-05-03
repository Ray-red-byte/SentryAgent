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
from app.utils.logger import get_logger

logger = get_logger(__name__)

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
    logger.debug("[TOOL] search_owasp_guidelines: %s", query[:80])
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
    logger.debug("[TOOL] read_file: %s", file_path)
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
    logger.info("[TOOL] write_code_patch: %s (%d chars)", file_path, len(patched_code))
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
    logger.debug("[TOOL] check_syntax: %s", file_path)
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
    Runs a static security scan on the file to verify that known vulnerabilities
    have been resolved in the patched code.

    Tries bandit first (HIGH severity only). If bandit is not installed, falls
    back to the built-in PythonParser hotspot detector so the tool is always
    functional inside the container.

    Call this LAST in the loop, after check_syntax passes. If findings remain,
    refine the patch and repeat the cycle.
    """
    logger.info("[TOOL] run_security_scanner: %s", file_path)
    # --- Primary: bandit ---
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
        return f"SECURITY SCAN FINDINGS (HIGH severity):\n{output[:2000]}"
    except subprocess.TimeoutExpired:
        return "SECURITY SCAN TIMEOUT: bandit took too long. Proceed with manual review."
    except FileNotFoundError:
        pass  # bandit not installed — fall through to PythonParser
    except Exception as e:
        return f"SECURITY SCAN ERROR: {e}"

    # --- Fallback: PythonParser hotspot detector ---
    try:
        from app.core.parser.python_parser import PythonParser
        with open(file_path, "rb") as f:
            code = f.read()
        hotspots = PythonParser().find_security_hotspots(code)
        if not hotspots:
            return "SECURITY SCAN PASSED: No high-severity issues found."
        lines = [
            f"  Line {h['line']}: [{h['severity']}] {h['type']} — {h['snippet'][:80]}"
            for h in hotspots
        ]
        return "SECURITY SCAN FINDINGS (remaining issues to fix):\n" + "\n".join(lines)
    except Exception as e:
        return f"SECURITY SCAN ERROR (fallback scanner): {e}"


# ============================================================================
# SURGICAL PATCHING TOOLS (Feature 1 — AST-Aware)
# ============================================================================

@tool
def replace_function(file_path: str, function_name: str, new_code: str) -> str:
    """
    Replaces an entire top-level function in the file with new_code using
    Tree-sitter AST to locate exact byte boundaries.

    PREFER this tool over write_code_patch when the fix is limited to a single
    function. It leaves the rest of the file completely untouched.

    Args:
        file_path: Absolute path to the Python file.
        function_name: Name of the top-level function to replace.
        new_code: The full replacement function source (including def line, decorators, etc.).

    Returns a success or error message.
    """
    try:
        logger.info("[TOOL] replace_function: %s in %s", function_name, file_path)
        from app.core.parser.python_parser import PythonParser

        with open(file_path, "rb") as f:
            source = f.read()

        parser = PythonParser()
        byte_range = parser.find_function_range(source, function_name)
        if byte_range is None:
            return (
                f"ERROR: Function '{function_name}' not found in {file_path}. "
                "Use read_file to check the actual function names."
            )

        start, end = byte_range
        patched = source[:start] + new_code.encode("utf-8") + source[end:]

        with open(file_path, "wb") as f:
            f.write(patched)

        return (
            f"SUCCESS: Replaced function '{function_name}' in {file_path} "
            f"(bytes {start}–{end} → {len(new_code)} chars)."
        )
    except Exception as e:
        return f"ERROR: replace_function failed: {e}"


@tool
def replace_class_method(
    file_path: str, class_name: str, method_name: str, new_code: str
) -> str:
    """
    Replaces a single method inside a class with new_code using Tree-sitter
    AST to locate exact byte boundaries.

    PREFER this tool when the vulnerability is inside one method of a class.
    It leaves the rest of the class and file completely untouched.

    Args:
        file_path: Absolute path to the Python file.
        class_name: Name of the class containing the method.
        method_name: Name of the method to replace.
        new_code: The full replacement method source (including def line,
                  decorators, correct indentation).

    Returns a success or error message.
    """
    try:
        logger.info("[TOOL] replace_class_method: %s.%s in %s", class_name, method_name, file_path)
        from app.core.parser.python_parser import PythonParser

        with open(file_path, "rb") as f:
            source = f.read()

        parser = PythonParser()
        byte_range = parser.find_method_range(source, class_name, method_name)
        if byte_range is None:
            return (
                f"ERROR: Method '{class_name}.{method_name}' not found in {file_path}. "
                "Use read_file to check the actual class/method names."
            )

        start, end = byte_range
        patched = source[:start] + new_code.encode("utf-8") + source[end:]

        with open(file_path, "wb") as f:
            f.write(patched)

        return (
            f"SUCCESS: Replaced method '{class_name}.{method_name}' in {file_path} "
            f"(bytes {start}–{end} → {len(new_code)} chars)."
        )
    except Exception as e:
        return f"ERROR: replace_class_method failed: {e}"


# ============================================================================
# STRICT DIFF TOOL (Feature 2)
# ============================================================================

@tool
def apply_diff(file_path: str, search_block: str, replace_block: str) -> str:
    """
    Exact search-and-replace: finds `search_block` verbatim in the file and
    replaces it with `replace_block`.

    Returns an error if the search_block is not found — this forces you to
    re-read the file and match indentation / whitespace exactly.

    Use this as a lightweight alternative to replace_function when the change
    is smaller than a full function (e.g. fixing one line or one expression).

    Args:
        file_path: Absolute path to the file.
        search_block: The exact text to find (must match verbatim including whitespace).
        replace_block: The replacement text.

    Returns a success or error message.
    """
    logger.info("[TOOL] apply_diff: %s", file_path)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if search_block not in content:
            return (
                "SEARCH BLOCK NOT FOUND — check indentation and whitespace. "
                "Use read_file to see the exact current contents, then try again."
            )

        # Guard: ensure only one occurrence to prevent ambiguous edits
        occurrences = content.count(search_block)
        if occurrences > 1:
            return (
                f"AMBIGUOUS: search_block appears {occurrences} times in {file_path}. "
                "Include more surrounding context to make the match unique."
            )

        patched = content.replace(search_block, replace_block, 1)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(patched)

        return (
            f"SUCCESS: Replaced 1 occurrence in {file_path} "
            f"({len(search_block)} chars → {len(replace_block)} chars)."
        )
    except Exception as e:
        return f"ERROR: apply_diff failed: {e}"


# ============================================================================
# FUNCTIONAL TEST TOOL (Feature 3)
# ============================================================================

@tool
def run_unit_tests(test_file_path: str = "") -> str:
    """
    Runs pytest to verify that the patched code does not break existing tests.

    Call this AFTER check_syntax and run_security_scanner to confirm no
    business-logic regressions were introduced by the patch.

    Args:
        test_file_path: (Optional) Absolute path to a specific test file.
                        If empty, runs the entire tests/ directory.

    Returns pass/fail status and truncated output.
    """
    logger.info("[TOOL] run_unit_tests: %s", test_file_path or "tests/")
    try:
        cmd = ["python", "-m", "pytest", "-x", "-q", "--tb=short"]
        if test_file_path:
            cmd.append(test_file_path)
        else:
            cmd.append("tests/")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        status = "PASSED" if result.returncode == 0 else "FAILED"
        output = (result.stdout + "\n" + result.stderr).strip()
        # Truncate to avoid overwhelming the agent context window
        return f"UNIT TESTS {status}:\n{output[:3000]}"
    except FileNotFoundError:
        return (
            "pytest is not installed or tests/ directory not found. "
            "Skipping unit tests. Ensure the patch is correct manually."
        )
    except subprocess.TimeoutExpired:
        return "UNIT TESTS TIMEOUT: pytest took too long (>60s). Proceed with manual review."
    except Exception as e:
        return f"UNIT TESTS ERROR: {e}"


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
