"""
app/workflows/node/patch.py

LangGraph workflow nodes for the security patching pipeline.

Each node is a pure state-transition function — no agent or subgraph logic
lives here. The heavy lifting is delegated to the patcher_graph subgraph.
"""

import re
import logging
from app.workflows.state import PatchState
from app.memory.knowledge_base import SecurityKnowledgeBase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lazy import helper — avoids loading the LLM at module import time so that
# other workflow nodes (scan, audit, …) don't pay the initialisation cost.
# ---------------------------------------------------------------------------

_patcher_graph = None

def _get_patcher_graph():
    global _patcher_graph
    if _patcher_graph is None:
        from app.workflows.subgraph.patcher_subgraph import patcher_graph
        _patcher_graph = patcher_graph
    return _patcher_graph


# ============================================================================
# NODE: generate_patch
# ============================================================================

def generate_patch(state: PatchState) -> PatchState:
    """
    Invokes the ReAct patcher subgraph to autonomously:
      1. Research the correct fix via OWASP knowledge base
      2. Read the vulnerable file
      3. Apply a surgical patch
      4. Verify syntax
      5. Run a security scanner
    …looping until all checks pass.

    Updates PatchState with original_code, patched_code, and current_stage.
    """
    file_path = state["file_path"]
    root_dir  = state["root_dir"]
    full_path = f"{root_dir}/{file_path}"

    print(f"🔧 [PATCH] ReAct agent patch start on: {file_path}")

    original_code = state.get("original_code")
    if not original_code:
        original_code = _read_source(full_path)
    elif state.get("retry_count", 0) > 0:
        # Revert the physical file back to the original state before the ReAct agent runs again
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(original_code)

    # Build the initial message that drives the ReAct loop
    vulnerabilities = state.get("vulnerabilities", [])
    vuln_summary = _format_vulnerabilities(vulnerabilities)

    # ------------------------------------------------------------------
    # Feature 4 — RAG Golden Examples Injection
    # Query ChromaDB for similar past vulnerability fixes and inject them
    # into the prompt so the agent starts with proven fix patterns.
    # ------------------------------------------------------------------
    golden_section = ""
    try:
        kb = SecurityKnowledgeBase()
        vuln_query = " ".join([
            v.get("type", "") if isinstance(v, dict) else getattr(v, "type", "")
            for v in vulnerabilities
        ])
        if vuln_query.strip():
            golden_examples = kb.recall_relevant_lessons(f"fix for {vuln_query}", n_results=2)
            if golden_examples:
                golden_section = (
                    "=== GOLDEN EXAMPLES (proven fix patterns from past scans) ===\n"
                    + "\n\n".join(golden_examples)
                    + "\n=== END GOLDEN EXAMPLES ===\n\n"
                )
    except Exception as e:
        logger.warning("[PATCH] Could not load golden examples: %s", e)

    # Build cross-file bundle context for the ReAct agent
    bundle_section = ""
    involved_files = state.get("involved_files", [file_path])
    peer_files = [fp for fp in involved_files if fp != file_path]
    if peer_files:
        peer_parts = []
        for fp in peer_files:
            peer_path = f"{root_dir}/{fp}"
            try:
                with open(peer_path, "r", encoding="utf-8") as fh:
                    peer_code = fh.read()
                peer_parts.append(f"=== BUNDLE FILE: {fp} ===\n{peer_code}")
            except OSError as e:
                logger.warning("[PATCH] Could not read bundle peer %s: %s", fp, e)
                peer_parts.append(f"=== BUNDLE FILE: {fp} ===\n[Could not read: {e}]")
        bundle_section = (
            "=== SECURITY DOMAIN BUNDLE CONTEXT (READ-ONLY) ===\n"
            "These peer files are READ-ONLY reference material. Use them to understand "
            "cross-file data flows, variable types, and DB schemas before patching. "
            "You are NOT authorized to modify any of these files.\n\n"
            + "\n\n".join(peer_parts)
            + "\n=== END BUNDLE CONTEXT ===\n\n"
        )

    vuln_header = (
        f"Fix the security vulnerabilities listed below in the PRIMARY TARGET FILE.\n\n"
        f"**PRIMARY TARGET FILE (absolute path):** `{full_path}`\n\n"
        f"**Reported vulnerabilities ({len(vulnerabilities)} total):**\n{vuln_summary}\n\n"
        + (
            f"Peer bundle files above are provided as READ-ONLY context. "
            f"Your final `python` block MUST contain only the complete patched source "
            f"of the primary target file — do NOT output code for any peer file.\n\n"
            if peer_files else ""
        )
    )

    initial_message = (
        f"{golden_section}"
        f"{bundle_section}"
        f"{vuln_header}"
    )

    # NEW: Inject feedback if this is a retry
    retry_count = state.get("retry_count", 0)
    review_feedback = state.get("review_feedback")
    
    if retry_count > 0 and review_feedback:
        initial_message += (
            f"⚠️ **PREVIOUS PATCH REJECTED.** The reviewer provided this feedback:\n"
            f"{review_feedback}\n"
            f"Please read the original file again, fix the logic according to the feedback, and generate a new patch.\n\n"
        )

    initial_message += (
        f"Follow your strict workflow: search_owasp_guidelines → read_file → "
        f"replace_function / replace_class_method / apply_diff (prefer surgical tools) → "
        f"check_syntax → run_security_scanner → run_unit_tests.\n"
        f"Return the complete patched source in a ```python ... ``` block when done."
    )

    try:
        graph = _get_patcher_graph()
        result = graph.invoke({"messages": [("user", initial_message)]})

        # Extract the agent's final text message
        final_message = result["messages"][-1]
        raw_content   = _extract_content(final_message)

        # Pull the code block out of the agent's response
        patched_code = _extract_code_block(raw_content)

        # Safety net: if no code block was returned, fall back to the raw response
        if not patched_code or len(patched_code.strip()) < 10:
            logger.warning(
                "[PATCH] Agent returned no parseable code block for %s — using raw response.",
                file_path,
            )
            patched_code = raw_content.strip() or original_code

        print(f"✅ [PATCH] ReAct agent finished. Patch size: {len(patched_code)} chars.")

        return {
            **state,
            "original_code": original_code,
            "patched_code": patched_code,
            "current_stage": "patching",
        }

    except Exception as e:
        logger.error("[PATCH] ReAct agent failed for %s: %s", file_path, e)
        print(f"❌ [PATCH] ReAct agent error: {e}")
        return {
            **state,
            "original_code": original_code,
            "patched_code": original_code,  # safe fallback — return unchanged code
            "current_stage": "error",
            "error": str(e),
        }


# ============================================================================
# NODE: save_patch_to_memory
# ============================================================================

def save_patch_to_memory(state: PatchState) -> PatchState:
    """Save the approved patch to organisational memory for future learning."""
    print("🧠 [MEMORY] Saving patch to knowledge base...")

    try:
        kb = SecurityKnowledgeBase()
        kb.learn_fix(
            vuln_type="Security Patch",
            description=f"ReAct patch for {state['file_path']}",
            fix_code=state["patched_code"][:1000],
            file_path=state["file_path"],
        )
        print("✅ [MEMORY] Patch saved to knowledge base")
    except Exception as e:
        # Non-critical — log and continue
        logger.warning("[MEMORY] Failed to save patch: %s", e)
        print(f"⚠️  [MEMORY] Failed to save patch: {e}")

    return {**state, "current_stage": "complete"}


# ============================================================================
# NODE: review_patch_node
# ============================================================================

def review_patch_node(state: PatchState) -> dict:
    """
    LangGraph node that critically reviews the generated patch.
    Returns partial state updates consumed by the is_patch_approved edge.
    """
    import json
    from app.agent.patcher import SecurityPatcher

    attempt = state.get("retry_count", 0) + 1
    print(f"🧐 [REVIEW] Reviewing patch for {state['file_path']} (attempt {attempt})")

    if not state.get("patched_code"):
        return {
            "is_approved": False,
            "review_feedback": "No patch was generated.",
            "retry_count": attempt,
        }

    patcher = SecurityPatcher(root_dir=state.get("root_dir", "app"))
    review_result = patcher.review_patch(
        file_path=state["file_path"],
        original_code=state["original_code"],
        patched_code=state["patched_code"],
        vulnerabilities=state["vulnerabilities"],
    )

    # Defensive normalisaton
    if isinstance(review_result, list):
        review_result = review_result[0] if review_result else {}
    if not isinstance(review_result, dict):
        review_result = {"is_approved": True, "feedback": "Unexpected reviewer output — auto-approved."}

    return {
        "is_approved": review_result.get("is_approved", True),
        "review_feedback": review_result.get("feedback", "No feedback provided."),
        "retry_count": attempt,
    }

def _read_source(full_path: str) -> str:
    """Read source safely; return empty string on failure."""
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        logger.warning("[PATCH] Could not read %s: %s", full_path, e)
        return ""


def _format_vulnerabilities(vulnerabilities: list) -> str:
    """Format the vulnerability list into a concise numbered string."""
    if not vulnerabilities:
        return "No specific vulnerabilities listed — perform a general security hardening pass."

    lines = []
    for i, v in enumerate(vulnerabilities, 1):
        if hasattr(v, "__dict__"):
            # Dataclass / TypedDict object
            severity = getattr(v, "severity", "?")
            vtype    = getattr(v, "type", "?")
            line_no  = getattr(v, "line", "?")
            desc     = getattr(v, "description", "")
        elif isinstance(v, dict):
            severity = v.get("severity", "?")
            vtype    = v.get("type", "?")
            line_no  = v.get("line", "?")
            desc     = v.get("description", "")
        else:
            lines.append(f"{i}. {v}")
            continue

        lines.append(f"{i}. [{severity}] {vtype} (line {line_no}): {desc}")

    return "\n".join(lines)


def _extract_content(message) -> str:
    """Pull plain text out of a LangChain message object or raw string."""
    content = getattr(message, "content", message)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


def _extract_code_block(text: str) -> str:
    """
    Extract the first ```python ... ``` (or ``` ... ```) fenced code block.
    Falls back to stripping bare fences if no language tag is present.
    """
    # Try explicit ```python block first
    match = re.search(r"```python\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Generic ``` block
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # No fence found — return the whole text for the caller to decide
    return ""