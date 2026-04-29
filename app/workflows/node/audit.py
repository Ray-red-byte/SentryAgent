"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
from app.workflows.state import Vulnerability, AuditState
from app.agent.auditor import SecurityAuditor
from app.utils.logger import get_logger

logger = get_logger(__name__)

def audit_security_bundle(state: AuditState) -> AuditState:
    """Audit a security-domain bundle (one or more files) for vulnerabilities."""
    involved_files = state.get("involved_files") or []
    bundle_name = state.get("security_bundle_name") or state.get("file_path") or "unknown"

    label = bundle_name if len(involved_files) != 1 else involved_files[0]
    logger.info("[AUDIT] Analyzing bundle '%s' (%d file(s))...", label, len(involved_files))

    try:
        auditor = SecurityAuditor(root_dir=state["root_dir"])
        cache_name = state.get("cache_name")

        if len(involved_files) == 1:
            # Single-file: use existing per-file path (cheaper prompt)
            fp = involved_files[0]
            if cache_name:
                report = auditor.audit_file_with_cache(fp, cache_name)
            else:
                report = auditor.audit_file(fp)
        else:
            # Multi-file bundle: send all files in one prompt
            report = auditor.audit_bundle(bundle_name, involved_files, cache_name=cache_name)

        vulnerabilities = []
        for vuln_dict in report:
            if isinstance(vuln_dict, dict) and vuln_dict.get("severity") != "ERROR":
                vuln = Vulnerability(
                    type=vuln_dict.get("type", "Unknown"),
                    severity=vuln_dict.get("severity", "INFO"),
                    file=vuln_dict.get("file") or (involved_files[0] if involved_files else bundle_name),
                    line=vuln_dict.get("line", 0),
                    description=vuln_dict.get("description", ""),
                    fix_suggestion=vuln_dict.get("fix", "")
                )
                vulnerabilities.append(vuln)

        logger.info("[AUDIT] Found %d issue(s) in '%s'", len(vulnerabilities), label)

        return {
            **state,
            "vulnerabilities": vulnerabilities,
            "audit_report": report,
            "current_stage": "complete"
        }

    except Exception as e:
        logger.error("[AUDIT] Error: %s", e)
        return {
            **state,
            "current_stage": "error",
            "error": str(e)
        }
