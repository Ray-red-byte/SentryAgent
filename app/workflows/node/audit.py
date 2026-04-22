"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
from app.workflows.state import Vulnerability, AuditState
from app.agent.auditor import SecurityAuditor

import logging

logger = logging.getLogger(__name__)

def audit_single_file(state: AuditState) -> AuditState:
    """Audit a single file for vulnerabilities."""
    print(f"🕵️ [AUDIT] Analyzing {state['file_path']}...")

    try:
        auditor = SecurityAuditor(root_dir=state["root_dir"])

        # Use cache if available
        if state.get("cache_name"):
            report = auditor.audit_file_with_cache(
                state["file_path"],
                state["cache_name"]
            )
        else:
            report = auditor.audit_file(state["file_path"])

        # Convert to Vulnerability objects
        vulnerabilities = []
        for vuln_dict in report:
            if isinstance(vuln_dict, dict) and vuln_dict.get("severity") != "ERROR":
                vuln = Vulnerability(
                    type=vuln_dict.get("type", "Unknown"),
                    severity=vuln_dict.get("severity", "INFO"),
                    file=state["file_path"],
                    line=vuln_dict.get("line", 0),
                    description=vuln_dict.get("description", ""),
                    fix_suggestion=vuln_dict.get("fix", "")
                )
                vulnerabilities.append(vuln)

        print(f"✅ [AUDIT] Found {len(vulnerabilities)} issues")

        return {
            **state,
            "vulnerabilities": vulnerabilities,
            "audit_report": report,
            "current_stage": "complete"
        }

    except Exception as e:
        print(f"❌ [AUDIT] Error: {e}")
        return {
            **state,
            "current_stage": "error",
            "error": str(e)
        }