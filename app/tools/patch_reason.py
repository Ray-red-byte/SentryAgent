"""
app/tools/patch_reason.py
Utility to extract the "reasoning" behind a generated patch from the LLM's response.
"""

import subprocess
from langchain_core.tools import tool

@tool
def run_pytest(file_path: str):
    """
    Executes pytest on a specific file to verify syntax and logic.
    Returns the STDOUT and STDERR of the test run.
    """
    try:
        result = subprocess.run(
            ["pytest", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": "PASSED" if result.returncode == 0 else "FAILED"
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
    

"""
TODO
More functions can be added here to analyze the patch
"""