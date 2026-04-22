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