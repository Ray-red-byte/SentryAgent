import json
import re
import logging
from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager
from app.memory.knowledge_base import SecurityKnowledgeBase

logger = logging.getLogger(__name__)

# Fields the rest of the pipeline expects on every vulnerability dict.
_REQUIRED_VULN_FIELDS = {
    "type": "Unknown",
    "severity": "INFO",
    "file": "",
    "line": 0,
    "description": "No description provided.",
    "fix": "Review manually.",
    "cvss_score": 0.0,
    # Accuracy improvement fields
    "confidence": "medium",
    "cwe": "",
    "owasp": "",
}


class SecurityAuditor:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()
        self.prompts = PromptManager()
        self.historian = SecurityKnowledgeBase()

    # ------------------------------------------------------------------
    # PUBLIC METHODS
    # ------------------------------------------------------------------

    def audit_file_with_cache(self, file_path: str, cache_name: str):
        """
        Audits a file using Gemini Context Cache + Organizational Memory (RAG).
        FAST PATH — uses pre-cached repository context.
        """
        logger.info("Auditor checking %s via cache...", file_path)

        # 1. Inject past lessons into the prompt so the LLM knows what to re-check
        import os
        code_snippet = ""
        full_path = os.path.join(self.assembler.root_dir, file_path)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    code_snippet = f.read(1000)
            except Exception as e:
                logger.warning(f"Could not read snippet for knowledge recall: {e}")

        past_lessons = self.historian.recall_for_file(file_path, code_snippet=code_snippet)
        lessons_block = self._format_lessons(past_lessons)

        base_prompt = self.prompts.get_prompt(
            "auditor.audit_with_cache", file_path=file_path
        )
        final_prompt = (
            f"{base_prompt}\n\n{lessons_block}"
            if lessons_block
            else base_prompt
        )

        raw_response = self.llm.analyze_with_cache(final_prompt, cache_name)
        return self.parse_json_response(raw_response, source_file=file_path)

    def audit_file(self, file_path: str):
        """
        SLOW PATH (fallback): Audits a file using manual Context Assembly + RAG.
        """
        logger.info("Auditor investigating: %s (slow path)", file_path)

        context = self.assembler.build_context_for_file(file_path)

        # Extract a short code snippet for richer semantic search in ChromaDB
        code_snippet = context[:600] if context else ""
        past_lessons = self.historian.recall_for_file(file_path, code_snippet=code_snippet)
        lessons_block = self._format_lessons(past_lessons)

        # Prepend lessons to context so they show up in the prompt
        if lessons_block:
            enriched_context = f"{lessons_block}\n\n{context}"
        else:
            enriched_context = context

        prompt = self.prompts.get_prompt(
            "auditor.audit_with_context", file_path=file_path, context=enriched_context
        )

        raw_response = self.llm.analyze(prompt)
        return self.parse_json_response(raw_response, source_file=file_path)

    def audit_bundle(self, bundle_name: str, involved_files: list[str], cache_name: str = None):
        """
        Audit a security-domain bundle (one or more files) as a single prompt.

        Fast path (cache_name provided): sends only the file list; Gemini locates
        the files in its cached context.
        Slow path: concatenates all file contents and appends them after the
        rendered prompt to avoid brace-collision with .format().
        """
        logger.info("Auditor auditing bundle '%s' (%d files)", bundle_name, len(involved_files))

        # RAG: recall lessons relevant to any file in the bundle
        past_lessons = []
        for fp in involved_files:
            import os
            full_path = os.path.join(self.assembler.root_dir, fp)
            code_snippet = ""
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        code_snippet = f.read(600)
                except Exception:
                    pass
            past_lessons.extend(self.historian.recall_for_file(fp, code_snippet=code_snippet))

        lessons_block = self._format_lessons(past_lessons)
        file_list = "\n".join(f"- {fp}" for fp in involved_files)

        if cache_name:
            base_prompt = self.prompts.get_prompt(
                "auditor.audit_bundle_with_cache",
                bundle_name=bundle_name,
                file_list=file_list,
            )
            final_prompt = f"{base_prompt}\n\n{lessons_block}" if lessons_block else base_prompt
            raw_response = self.llm.analyze_with_cache(final_prompt, cache_name)
        else:
            base_prompt = self.prompts.get_prompt(
                "auditor.audit_bundle_with_context",
                bundle_name=bundle_name,
            )
            if lessons_block:
                base_prompt = f"{base_prompt}\n\n{lessons_block}"
            concatenated = self._build_concatenated_context(involved_files)
            final_prompt = f"{base_prompt}\n\n{concatenated}"
            raw_response = self.llm.analyze(final_prompt)

        return self.parse_json_response(raw_response, source_file=bundle_name)

    def _build_concatenated_context(self, involved_files: list[str]) -> str:
        """Concatenate all files in the bundle into one context block."""
        import os
        parts = []
        for fp in involved_files:
            full_path = os.path.join(self.assembler.root_dir, fp)
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    code = f.read()
                parts.append(f"=== FILE: {fp} ===\n{code}")
            except OSError as e:
                logger.warning("Could not read %s: %s", fp, e)
                parts.append(f"=== FILE: {fp} ===\n[Could not read file: {e}]")
        return "\n\n".join(parts)

    def chat_with_file(
        self,
        file_path: str,
        query: str,
        cache_name: str = None,
        full_path: str = None,
    ):
        """
        Handles interactive chat about a specific file.
        Uses the Gemini cache if available, otherwise falls back to reading the file.
        """
        logger.info("Chatting about %s...", file_path)

        prompt = self.prompts.get_prompt(
            "chat.default", file_path=file_path, query=query
        )

        if cache_name:
            # FAST PATH: cached context already contains the file
            return self.llm.analyze_with_cache(prompt, cache_name)

        # SLOW PATH: read the file and append its content to the prompt
        if not full_path:
            return "Error: File path required for non-cached chat."

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                code = f.read()
            final_prompt = f"{prompt}\n\n=== FILE CONTENT ===\n{code}"
            return self.llm.analyze(final_prompt)
        except OSError as e:
            logger.error("Could not read %s: %s", full_path, e)
            return "Error: Could not read the file for analysis."


    # ------------------------------------------------------------------
    # JSON PARSING — robust against Gemini's varied formatting habits
    # ------------------------------------------------------------------

    def parse_json_response(self, text: str, source_file: str = "") -> list:
        """
        Cleans and parses the LLM output into a validated Python list.

        Handles:
        - Markdown code fences (```json ... ```)
        - Leading/trailing prose before or after the JSON array
        - Missing required fields on individual vulnerability objects
        - Non-list responses (wraps single dict in a list)
        """
        if not text or not text.strip():
            logger.warning("Empty response from LLM for file: %s", source_file)
            return self._error_result("The AI returned an empty response.")

        cleaned = self._strip_to_json(text)

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning(
                "JSON decode failed for %s.\nError: %s\nRaw (first 500 chars): %s",
                source_file,
                e,
                text[:500],
            )
            return self._error_result(
                f"The AI returned an invalid JSON response. Parser error: {e.msg}"
            )

        # Normalise to a list
        if isinstance(parsed, dict):
            parsed = [parsed]
        elif not isinstance(parsed, list):
            return self._error_result(
                "The AI returned an unexpected data type (expected a JSON array)."
            )

        # Fill in any missing fields so downstream code never KeyErrors
        normalised = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            vuln = {**_REQUIRED_VULN_FIELDS, **item}
            # Ensure file is populated if the LLM left it blank
            if not vuln["file"] and source_file:
                vuln["file"] = source_file
            # Ensure severity is one of the accepted values
            if vuln["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"):
                vuln["severity"] = "INFO"
            # Ensure cvss_score is a float
            try:
                vuln["cvss_score"] = float(vuln["cvss_score"])
            except (TypeError, ValueError):
                vuln["cvss_score"] = 0.0
            # Normalise confidence
            if vuln.get("confidence") not in ("high", "medium", "low"):
                vuln["confidence"] = "medium"
            normalised.append(vuln)

        return _deduplicate(normalised)

    @staticmethod
    def _strip_to_json(text: str) -> str:
        """
        Extracts the first JSON array from text, tolerating surrounding prose
        and markdown code fences.
        """
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = text.replace("```", "").strip()

        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1]

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return f"[{text[start:end+1]}]"

        return text

    @staticmethod
    def _format_lessons(lessons: list) -> str:
        """Format RAG lessons into a prompt block."""
        if not lessons:
            return ""
        lines = ["=== ORGANIZATIONAL MEMORY (Known patterns to watch for) ==="]
        lines.extend(lessons)
        lines.append("=== END ORGANIZATIONAL MEMORY ===")
        lines.append("If the code matches any patterns above, flag them immediately.")
        return "\n".join(lines)

    @staticmethod
    def _error_result(description: str) -> list:
        """Return a structured error so the UI/pipeline handles it gracefully."""
        return [
            {
                **_REQUIRED_VULN_FIELDS,
                "severity": "ERROR",
                "type": "Parser Error",
                "description": description,
                "fix": "Try auditing the file again.",
            }
        ]


# ── Module-level helper — must be defined AFTER SecurityAuditor ───────────────

def _deduplicate(vulns: list[dict]) -> list[dict]:
    """
    Remove near-duplicate vulnerability findings.

    Two findings are considered duplicates when they share:
      - The same file
      - The same CWE (or vulnerability type when CWE is absent)
      - Line numbers within 5 of each other

    The higher-severity / higher-confidence finding wins.
    """
    if not vulns:
        return vulns

    _SEVERITY_RANK   = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "ERROR": 0}
    _CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

    kept: list[dict] = []
    for candidate in vulns:
        c_file = candidate.get("file", "")
        c_key  = candidate.get("cwe") or candidate.get("type", "")
        c_line = int(candidate.get("line") or 0)

        duplicate_idx = None
        for i, existing in enumerate(kept):
            e_file = existing.get("file", "")
            e_key  = existing.get("cwe") or existing.get("type", "")
            e_line = int(existing.get("line") or 0)
            if e_file == c_file and e_key == c_key and abs(e_line - c_line) <= 5:
                duplicate_idx = i
                break

        if duplicate_idx is None:
            kept.append(candidate)
        else:
            existing = kept[duplicate_idx]
            c_sev  = _SEVERITY_RANK.get(candidate.get("severity", "INFO"), 1)
            e_sev  = _SEVERITY_RANK.get(existing.get("severity", "INFO"), 1)
            c_conf = _CONFIDENCE_RANK.get(candidate.get("confidence", "medium"), 2)
            e_conf = _CONFIDENCE_RANK.get(existing.get("confidence", "medium"), 2)
            if (c_sev, c_conf) > (e_sev, e_conf):
                kept[duplicate_idx] = candidate

    return kept