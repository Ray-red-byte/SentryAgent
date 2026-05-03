from app.workflows.state import PatchState

def is_patch_approved(state: PatchState) -> str:
    """
    Routes based on the Reviewer Node's feedback.
    """
    is_approved = state.get("is_approved", False)
    retries = state.get("retry_count", 0)
    MAX_RETRIES = 1

    if is_approved:
        return "approved"
    if retries >= MAX_RETRIES:
        # Prevent infinite loop: force-approve after max retries
        return "approved"

    return "rejected"

def route_after_patch(state: PatchState) -> str:
    if state.get("current_stage") == "error":
        return "error"
    return "review"
