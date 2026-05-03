"""
app/workflows/node/patch.py

LangGraph workflow nodes for the security patching pipeline.

Each node is a pure state-transition function — no agent or subgraph logic
lives here. The heavy lifting is delegated to the patcher_graph subgraph.
"""

import re
import time
from app.workflows.state import PatchState
from app.memory.knowledge_base import SecurityKnowledgeBase
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lazy import helper — avoids loading the LLM at module import time so that
# other workflow nodes (scan, audit, …) don't pay the initialisation cost.
# ---------------------------------------------------------------------------

_patcher_graph = None

def _get_patcher_graph():
    global _patcher_graph
    if _patcher_graph is None:
        from app.workflows.subgraph.patch import patcher_graph
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

    vuln_types = ", ".join(
        v.get("type", "?") if isinstance(v, dict) else getattr(v, "type", "?")
        for v in state.get("vulnerabilities", [])
    ) or "general hardening"
    logger.info(
        "[PATCH] START  file=%s  vulns=%d  (%s)",
        file_path, len(state.get("vulnerabilities", [])), vuln_types,
    )

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
            "Do NOT modify them — your output must contain only the primary target file.\n\n"
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

    # Inject feedback if this is a retry (auto-reviewer)
    retry_count = state.get("retry_count", 0)
    review_feedback = state.get("review_feedback")
    
    if retry_count > 0 and review_feedback:
        initial_message += (
            f"⚠️ **PREVIOUS PATCH REJECTED BY REVIEWER.** The reviewer provided this feedback:\n"
            f"{review_feedback}\n"
            f"Please read the original file again, fix the logic according to the feedback, and generate a new patch.\n\n"
        )

    # Inject human user feedback (reject & retry from the UI)
    user_feedback = state.get("user_feedback")
    if user_feedback:
        initial_message += (
            f"🚨 **USER REJECTED THE PREVIOUS PATCH.** The developer provided this feedback:\n"
            f'"{user_feedback}"\n'
            f"You MUST follow the user's instructions precisely. Read the original file again "
            f"and generate a new patch that addresses the user's specific concerns.\n\n"
        )


    initial_message += (
        f"Follow your strict workflow: search_owasp_guidelines → read_file → "
        f"replace_function / replace_class_method / apply_diff (prefer surgical tools) → "
        f"check_syntax → run_security_scanner → run_unit_tests.\n"
        f"Return the complete patched source in a ```python ... ``` block when done."
    )

    try:
        graph = _get_patcher_graph()
        _t0 = time.monotonic()
        from app.utils.cost_tracker import CostTrackingCallback
        from app.databases.redis import get_redis
        cost_cb = CostTrackingCallback(
            session_id=state.get("session_id", ""),
            model_name="gemini-2.5-flash",
            redis_client=get_redis(),
        )
        result = graph.invoke(
            {"messages": [("user", initial_message)]},
            config={"recursion_limit": 20, "callbacks": [cost_cb]},
        )

        # ──────────────────────────────────────────────────────────────────
        # IMPORTANT: The ReAct agent modifies files on disk via its tools
        # (write_code_patch, replace_function, apply_diff). The authoritative
        # patched source is whatever is currently on disk — NOT the code
        # block in the agent's conversational response, which may contain
        # code from peer files or an incomplete version.
        # ──────────────────────────────────────────────────────────────────
        disk_code = _read_source(full_path)

        if not disk_code or disk_code.strip() == original_code.strip():
            # Agent didn't modify the file on disk (or read failed).
            # Fallback: try to extract a code block from the response.
            final_message = result["messages"][-1]
            raw_content   = _extract_content(final_message)
            patched_code  = _extract_code_block(raw_content)

            if not patched_code or len(patched_code.strip()) < 10:
                logger.warning(
                    "[PATCH] Agent returned no parseable code block for %s — returning original.",
                    file_path,
                )
                patched_code = original_code
            else:
                # Write the extracted code to disk so /apply has the right content
                try:
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write(patched_code)
                except OSError:
                    pass
        else:
            patched_code = disk_code

        logger.info(
            "[PATCH] DONE   file=%s  elapsed=%.1fs  patch_size=%d chars",
            file_path, time.monotonic() - _t0, len(patched_code),
        )

        return {
            **state,
            "original_code": original_code,
            "patched_code": patched_code,
            "current_stage": "patching",
        }

    except Exception as e:
        logger.error(
            "[PATCH] ERROR  file=%s  elapsed=%.1fs  error=%s",
            file_path, time.monotonic() - _t0, e,
        )
        # Revert the file to original on error
        try:
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(original_code)
        except OSError:
            pass
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
    logger.info("[MEMORY] Saving patch to knowledge base...")

    try:
        kb = SecurityKnowledgeBase()
        kb.learn_fix(
            vuln_type="Security Patch",
            description=f"ReAct patch for {state['file_path']}",
            fix_code=state["patched_code"][:3000],
            file_path=state["file_path"],
        )
        logger.info("[MEMORY] Patch saved to knowledge base")
    except Exception as e:
        # Non-critical — log and continue
        logger.warning("[MEMORY] Failed to save patch: %s", e)
        logger.warning("[MEMORY] Failed to save patch: %s", e)

    return {**state, "current_stage": "complete"}


# ============================================================================
# NODE: review_patch_node
# ============================================================================

def review_patch_node(state: PatchState) -> dict:
    """
    LangGraph node that critically reviews the generated patch.

    Two-layer review:
      Layer 1 — AST validation (fast, deterministic, free)
        • Checks that both original and patched code parse without SyntaxError
        • Checks that the patch didn't silently *shrink* the file (>40% line loss
          is a red flag that the agent deleted unrelated code)
        • Checks that the patch is not identical to the original (no-op)

      Layer 2 — LLM security review (uses analyze_review → REVIEW_GENERATION_CONFIG)
        • Rates effectiveness, correctness, and side-effect safety

    On rejection, stores the anti-pattern in ChromaDB so future patches
    avoid repeating the same mistake.
    """
    import ast as _ast
    import json
    from app.agent.patcher import SecurityPatcher

    attempt = state.get("retry_count", 0) + 1
    logger.info("[REVIEW] Reviewing patch for %s (attempt %d)", state['file_path'], attempt)

    original_code = state.get("original_code", "")
    patched_code  = state.get("patched_code", "")

    if not patched_code:
        return {
            "is_approved": False,
            "review_feedback": "No patch was generated.",
            "retry_count": attempt,
        }

    # ── Layer 1: AST validation ─────────────────────────────────────────────
    def _ast_check(code: str, label: str):
        try:
            _ast.parse(code)
            return None
        except SyntaxError as e:
            return f"{label} has a SyntaxError on line {e.lineno}: {e.msg}"

    original_err = _ast_check(original_code, "Original code")
    if original_err:
        # Original was already broken — skip syntax check for patch
        logger.warning("[REVIEW] Original code has syntax errors (%s) — skipping syntax gate.", original_err)
    else:
        patch_err = _ast_check(patched_code, "Patched code")
        if patch_err:
            feedback = (
                f"AST VALIDATION FAILED: {patch_err}. "
                "Fix the syntax error before resubmitting."
            )
            logger.warning("[REVIEW] %s", feedback)
            _save_rejection(state, feedback)
            return {"is_approved": False, "review_feedback": feedback, "retry_count": attempt}

    # No-op check
    if original_code.strip() == patched_code.strip():
        feedback = "PATCH IS IDENTICAL TO ORIGINAL — no changes were made. The agent must actually modify the file."
        logger.warning("[REVIEW] %s", feedback)
        return {"is_approved": False, "review_feedback": feedback, "retry_count": attempt}

    # Shrinkage check (>40% line loss)
    orig_lines  = len([l for l in original_code.splitlines() if l.strip()])
    patch_lines = len([l for l in patched_code.splitlines() if l.strip()])
    if orig_lines > 20 and patch_lines < orig_lines * 0.6:
        feedback = (
            f"PATCH DELETED TOO MUCH CODE: original had {orig_lines} non-blank lines, "
            f"patch has {patch_lines} ({patch_lines/orig_lines:.0%}). "
            "Surgical patches should modify the vulnerable lines, not rewrite the whole file."
        )
        logger.warning("[REVIEW] %s", feedback)
        _save_rejection(state, feedback)
        return {"is_approved": False, "review_feedback": feedback, "retry_count": attempt}

    # ── Layer 2: LLM security review ────────────────────────────────────────
    patcher = SecurityPatcher(root_dir=state.get("root_dir", "app"), session_id=state.get("session_id"))
    review_result = patcher.review_patch(
        file_path=state["file_path"],
        original_code=original_code,
        patched_code=patched_code,
        vulnerabilities=state["vulnerabilities"],
    )

    if isinstance(review_result, list):
        review_result = review_result[0] if review_result else {}
    if not isinstance(review_result, dict):
        review_result = {"is_approved": True, "feedback": "Unexpected reviewer output — auto-approved."}

    is_approved    = review_result.get("is_approved", True)
    review_feedback = review_result.get("feedback", "No feedback provided.")

    if not is_approved:
        _save_rejection(state, review_feedback)

    return {
        "is_approved": is_approved,
        "review_feedback": review_feedback,
        "retry_count": attempt,
    }


def _save_rejection(state: PatchState, feedback: str) -> None:
    """Persist rejected patch anti-patterns to ChromaDB for future learning."""
    try:
        kb = SecurityKnowledgeBase()
        kb.learn_rejection(
            file_path=state.get("file_path", "unknown"),
            original_code=state.get("original_code", ""),
            rejected_patch=state.get("patched_code", ""),
            feedback=feedback,
            vulnerabilities=state.get("vulnerabilities", []),
        )
    except Exception as e:
        logger.warning("[REVIEW] Could not save rejection anti-pattern: %s", e)


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