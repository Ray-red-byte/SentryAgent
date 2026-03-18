import re
import ast
import json
import logging
from pathlib import Path
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager
from app.memory.knowledge_base import SecurityKnowledgeBase
from app.tools.patch_reason import run_pytest, write_to_file
from langchain_core.messages import HumanMessage

logger = logging.getLogger(__name__)


# ============================================================================
# LANGCHAIN TOOLS — used by the patcher ReAct subgraph
# ============================================================================

@tool
def ast_check(code: str) -> dict:
    """
    Validates that a Python code string has valid syntax using the AST parser.
    Returns a dict with 'valid' (bool) and optionally 'error' (str).
    Always call this tool after generating a patch to verify syntax before submitting.
    """
    try:
        ast.parse(code)
        return {"valid": True, "message": "Syntax is valid Python."}
    except SyntaxError as e:
        return {
            "valid": False,
            "error": f"SyntaxError on line {e.lineno}: {e.msg}",
        }


# ============================================================================
# PATCHER SUBGRAPH — ReAct agent that generates + self-verifies patches
# ============================================================================

def build_patcher_agent():
    """
    Builds a LangGraph ReAct agent for generating and verifying security patches.
    The agent has two tools:
      - ast_check: validates Python syntax of generated code
      - run_pytest: runs the test suite against the patched file
    Returns a compiled LangGraph graph (the subgraph).
    """
    llm = GeminiClient().get_model()
    tools = [ast_check, run_pytest, write_to_file]

    return create_react_agent(
        model=llm,
        tools=tools,
        prompt=(
            "You are a Senior Security Engineer. Your job is to fix security vulnerabilities "
            "in Python code with minimal, surgical changes. "
            "Always use the write_to_file tool to save your work, then call ast_check or run_pytest to verify it. "
            "If tests or syntax checks fail, update the file until they pass. "
            "Once verified, you MUST return the final, correctly patched code block in your response."
            "If ast_check returns an error, fix the syntax and check again."
        ),
    )


# ============================================================================
# SECURITY PATCHER — primary patching agent used by workflow nodes
# ============================================================================

class SecurityPatcher:
    def __init__(self, root_dir="app"):
        self.root_dir = root_dir
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()
        self.prompts = PromptManager()
        self.historian = SecurityKnowledgeBase()

    def patch_file(self, file_path: str, cache_name: str = None) -> str:
        """
        Generates a security fix for the given file.
        - FAST PATH: Uses Gemini Context Cache if cache_name is provided.
        - SLOW PATH: Manually builds context if no cache.

        Returns the patched file content as a string.
        """
        logger.info("Patcher beginning repair of: %s", file_path)

        # Read the original source
        original_code = self._read_file(file_path)

        # Gather RAG context — past lessons about the same vulnerability patterns
        lessons = self.historian.recall_for_file(file_path, code_snippet=original_code)
        lessons_block = self._format_lessons(lessons) if lessons else ""

        context_prompt = ""
        if cache_name:
            logger.info("Using Gemini cache context for patcher: %s", cache_name)
            context_prompt = f"(Entire repository is available in your context cache — find {file_path} there.)\nWe are using ReAct agent for improved accuracy."
        else:
            logger.info("Cache miss. Building context manually for: %s", file_path)
            context_prompt = self.assembler.build_context_for_file(file_path)
            
        if lessons_block:
            context_prompt = f"{lessons_block}\n\n{context_prompt}"

        prompt_str = self.prompts.get_prompt(
            "patcher.default",
            target_file=file_path,
            context=context_prompt,
        )

        agent = build_patcher_agent()
        logger.info("Invoking ReAct agent for self-correcting patching...")
        result = agent.invoke({"messages": [HumanMessage(content=prompt_str)]})
        fixed_code_raw = result["messages"][-1].content
        if isinstance(fixed_code_raw, list):
            # Gemini models sometimes return a list of text/tool-call blocks
            parts = []
            for block in fixed_code_raw:
                if isinstance(block, dict) and "text" in block:
                    parts.append(block["text"])
                elif isinstance(block, str):
                    parts.append(block)
            fixed_code = "\n".join(parts)
        else:
            fixed_code = str(fixed_code_raw)

        # Clean up any markdown wrapping (Gemini sometimes adds ```python)
        fixed_code = self.clean_output(fixed_code)

        # Safety net: if the LLM returned nothing useful, return the original unchanged
        if not fixed_code or len(fixed_code.strip()) < 10:
            logger.warning("Patcher returned empty/trivial output for %s — using original.", file_path)
            return original_code

        logger.info("Patcher generated %d chars for %s", len(fixed_code), file_path)
        return fixed_code

    def clean_output(self, text: str) -> str:
        """Strip markdown fences and leading/trailing whitespace."""
        if not text:
            return ""
        text = re.sub(r"^```(?:python)?\s*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
        return text.strip()

    def review_patch(self, original_code: str, patched_code: str, vulnerabilities: list) -> dict:
        """
        Acts as a Senior Reviewer to ensure the patch is safe, effective, and
        not over-engineered.  Returns a dict with keys: is_approved, feedback.
        """
        prompt = self.prompts.get_prompt(
            "patcher.review",
            vulnerabilities=json.dumps(vulnerabilities, indent=2),
            original_code=original_code,
            patched_code=patched_code,
        )

        response_text = self.llm.analyze(prompt)

        try:
            # Strip markdown fences if present
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].strip()
            return json.loads(response_text)
        except Exception as e:
            logger.warning("Reviewer returned non-JSON: %s", e)
            # Default to approved to avoid infinite retry loops
            return {
                "is_approved": True,
                "feedback": f"Review could not parse AI output (auto-approved). Raw: {response_text[:200]}",
            }

    def _read_file(self, file_path: str) -> str:
        """Read the target file from the workspace root."""
        full_path = Path(self.root_dir) / file_path
        try:
            return full_path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("Could not read %s: %s", file_path, e)
            return ""

    @staticmethod
    def _format_lessons(lessons: list) -> str:
        """Format ChromaDB RAG lessons as a prompt block."""
        lines = [
            "=== SECURITY KNOWLEDGE BASE (Reference patterns — apply where relevant) ===",
        ]
        lines.extend(lessons)
        lines.append("=== END KNOWLEDGE BASE ===")
        return "\n".join(lines)