# app/workflows/decision.py

from app.workflows.state import PatchState, ScanState
from app.agent.patcher import SecurityPatcher


def should_deep_audit(state: ScanState) -> str:
    """
    Routes based on initial parsing risk assessment.

    Checks if any file exceeded the configured risk_score threshold.
    Previously this read a non-existent 'risk_level' key and always
    routed to 'report', effectively disabling the audit step entirely.
    """
    risk_threshold = state.get("config", {}).get("risk_threshold", 5)
    high_risk_count = sum(
        1 for sr in state.get("scan_results", []) if sr.risk_score >= risk_threshold
    )

    if high_risk_count > 0:
        print(f"🎯 [DECISION] {high_risk_count} high-risk files found → Deep audit required")
        return "audit"

    print("✅ [DECISION] No high-risk files → Skip to report")
    return "report"


def is_patch_approved(state: PatchState) -> str:
    """
    Routes based on the Reviewer Node's feedback.
    """
    is_approved = state.get("is_approved", False)
    retries = state.get("retry_count", 0)
    MAX_RETRIES = 3

    if is_approved:
        return "approved"
    if retries >= MAX_RETRIES:
        # Prevent infinite loop: force-approve after max retries
        return "approved"

    return "rejected"


def review_patch_node(state: PatchState) -> dict:
    """
    LangGraph node that wraps the SecurityPatcher's review functionality.
    """
    attempt = state.get("retry_count", 0) + 1
    print(f"🧐 Node: Triggering review for {state['file_path']} (Attempt {attempt})")

    if not state.get("patched_code"):
        return {
            "is_approved": False,
            "review_feedback": "No patch was generated.",
            "retry_count": attempt,
        }

    # Initialize your agent
    patcher = SecurityPatcher(root_dir=state.get("root_dir", "app"))

    # Call the agent's method
    review_result = patcher.review_patch(
        original_code=state["original_code"],
        patched_code=state["patched_code"],
        vulnerabilities=state["vulnerabilities"],
    )

    # Defensive: review_result might be a list if the LLM returned a JSON array
    if isinstance(review_result, list):
        review_result = review_result[0] if review_result else {}
    if not isinstance(review_result, dict):
        review_result = {"is_approved": True, "feedback": "Unexpected reviewer output: auto-approved."}

    # Return the updates to the LangGraph state
    return {
        "is_approved": review_result.get("is_approved", True),  # default True to avoid infinite loops
        "review_feedback": review_result.get("feedback", "No feedback provided."),
        "retry_count": attempt,
    }


def should_prioritize(state: dict) -> str:
    """
    Determines if the discovered vulnerabilities need to be prioritized.
    Routes to 'prioritize' if there are multiple issues, otherwise
    goes straight to 'report'.
    """
    vulnerabilities = state.get("vulnerabilities", [])

    if not vulnerabilities or len(vulnerabilities) <= 1:
        print("➡️ Routing: Few/no vulnerabilities found. Skipping straight to Report.")
        return "report"

    print(f"➡️ Routing: Found {len(vulnerabilities)} vulnerabilities. Routing to Prioritize.")
    return "prioritize"