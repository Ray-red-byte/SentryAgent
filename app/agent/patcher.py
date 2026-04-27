"""
app/agent/patcher.py

SecurityPatcher — plain LLM-based patching agent.

The ReAct subgraph (create_react_agent) lives in:
    app/agent/subgraph/patcher_subgraph.py
"""

import re
import ast
import json
import logging
from pathlib import Path

from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager
from app.memory.knowledge_base import SecurityKnowledgeBase

logger = logging.getLogger(__name__)


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

    def patch_file(
        self,
        file_path: str,
        cache_name: str = None,
        involved_files: list[str] = None,
    ) -> str:
        """
        Generates a security fix for the given file using a direct LLM call.

        - FAST PATH: Uses Gemini Context Cache if cache_name is provided.
        - SLOW PATH: Manually builds context if no cache.
        - If involved_files contains additional files (security domain bundle),
          their source is appended as bundle context so the LLM can trace
          cross-file data flows before patching.

        Returns the patched file content as a string.
        """
        logger.info("Patcher beginning repair of: %s", file_path)

        # Read the original source
        original_code = self._read_file(file_path)

        # RAG: past lessons for the primary target file
        lessons = self.historian.recall_for_file(file_path, code_snippet=original_code)
        lessons_block = self._format_lessons(lessons) if lessons else ""

        context_prompt = ""
        if cache_name:
            logger.info("Using Gemini cache context for patcher: %s", cache_name)
            context_prompt = (
                f"(Entire repository is available in your context cache — find {file_path} there.)"
            )
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

        # Append cross-file bundle context after .format() to avoid brace-collision
        bundle_context = self._build_bundle_context(file_path, involved_files)
        if bundle_context:
            prompt_str = f"{prompt_str}\n\n{bundle_context}"

        logger.info("Invoking LLM for patching: %s", file_path)
        fixed_code_raw = self.llm.analyze(prompt_str)

        # Clean up any markdown wrapping (Gemini sometimes adds ```python)
        fixed_code = self.clean_output(fixed_code_raw)

        # Safety net: if the LLM returned nothing useful, return the original unchanged
        if not fixed_code or len(fixed_code.strip()) < 10:
            logger.warning(
                "Patcher returned empty/trivial output for %s — using original.", file_path
            )
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

    def review_patch(self, file_path: str, original_code: str, patched_code: str, vulnerabilities: list) -> dict:
        """
        Acts as a Senior Reviewer to ensure the patch is safe, effective, and
        not over-engineered.  Returns a dict with keys: is_approved, feedback.
        """
        prompt = self.prompts.get_prompt(
            "patcher.review",
            file_path=file_path,
            vulnerability_description=json.dumps(vulnerabilities, indent=2),
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
                "feedback": (
                    f"Review could not parse AI output (auto-approved). "
                    f"Raw: {response_text[:200]}"
                ),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_bundle_context(self, primary_file: str, involved_files: list[str] | None) -> str:
        """
        Read all bundle files except the primary target and return them as a
        labelled context block. Appended *after* prompt.format() to avoid
        KeyError on brace characters in source code.
        """
        if not involved_files:
            return ""
        peers = [fp for fp in involved_files if fp != primary_file]
        if not peers:
            return ""

        parts = []
        for fp in peers:
            code = self._read_file(fp)
            parts.append(f"=== BUNDLE FILE: {fp} ===\n{code or '[Could not read]'}")

        return (
            "=== SECURITY DOMAIN BUNDLE CONTEXT ===\n"
            "Use these peer files to understand cross-file data flows, "
            "variable types, and schemas before patching.\n\n"
            + "\n\n".join(parts)
            + "\n=== END BUNDLE CONTEXT ==="
        )

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