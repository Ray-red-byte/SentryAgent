from app.workflows.state import PatchState, ScanState
from app.agent.patcher import SecurityPatcher
from app.utils.logger import get_logger

logger = get_logger(__name__)


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
        logger.info("[DECISION] %d high-risk file(s) found — deep audit required", high_risk_count)
        return "audit"

    logger.info("[DECISION] No high-risk files — skipping to report")
    return "report"

def should_prioritize(state: dict) -> str:
    """
    Determines if the discovered vulnerabilities need to be prioritized.
    Routes to 'prioritize' if there are multiple issues, otherwise
    goes straight to 'report'.
    """
    vulnerabilities = state.get("vulnerabilities", [])

    if not vulnerabilities or len(vulnerabilities) <= 1:
        logger.info("Routing: few/no vulnerabilities found — skipping to report")
        return "report"

    logger.info("Routing: found %d vulnerability(s) — routing to prioritize", len(vulnerabilities))
    return "prioritize"