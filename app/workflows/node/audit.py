"""
Workflow node for the per-bundle security audit.

audit_security_bundle is the single node in the AuditState graph.
It delegates to SecurityAuditor.audit_bundle() which sends all files
in one prompt — one LLM call regardless of bundle size.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor

from app.workflows.state import Vulnerability, AuditState
from app.agent.auditor import SecurityAuditor
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Shared thread pool for blocking Gemini calls
_AUDIT_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="audit")


def _run_audit(auditor: SecurityAuditor, bundle_name: str,
               involved_files: list[str], cache_name: str | None) -> list:
    """Blocking audit call — executed in a thread pool worker."""
    if len(involved_files) == 1:
        fp = involved_files[0]
        if cache_name:
            return auditor.audit_file_with_cache(fp, cache_name)
        return auditor.audit_file(fp)

    # Multi-file: one consolidated prompt via audit_bundle()
    return auditor.audit_bundle(bundle_name, involved_files, cache_name=cache_name)


async def audit_security_bundle_async(state: AuditState) -> AuditState:
    """
    Async variant: runs the blocking Gemini call off the event loop.

    Uses audit_bundle() so N files in a bundle = 1 LLM call, not N.
    """
    involved_files = state.get("involved_files") or []
    bundle_name = state.get("security_bundle_name") or state.get("file_path") or "unknown"

    label = bundle_name if len(involved_files) != 1 else involved_files[0]
    logger.info("[AUDIT] Analyzing '%s' (%d file(s))...", label, len(involved_files))

    try:
        auditor = SecurityAuditor(root_dir=state["root_dir"], session_id=state.get("session_id"))
        cache_name = state.get("cache_name")

        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            _AUDIT_EXECUTOR,
            _run_audit,
            auditor,
            bundle_name,
            involved_files,
            cache_name,
        )

        vulnerabilities = [
            Vulnerability(
                type=v.get("type", "Unknown"),
                severity=v.get("severity", "INFO"),
                file=v.get("file") or (involved_files[0] if involved_files else bundle_name),
                line=v.get("line", 0),
                description=v.get("description", ""),
                fix_suggestion=v.get("fix", ""),
                cvss_score=float(v.get("cvss_score", 0.0)),
            )
            for v in report
            if isinstance(v, dict) and v.get("severity") != "ERROR"
        ]

        logger.info("[AUDIT] Found %d issue(s) in '%s'", len(vulnerabilities), label)

        return {
            **state,
            "vulnerabilities": vulnerabilities,
            "audit_report": report,
            "current_stage": "complete",
        }

    except Exception as e:
        logger.error("[AUDIT] Error auditing '%s': %s", label, e)
        return {
            **state,
            "current_stage": "error",
            "error": str(e),
        }


def audit_security_bundle(state: AuditState) -> AuditState:
    """
    Sync wrapper — LangGraph calls nodes synchronously.
    Delegates to the async implementation via asyncio.run().
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside an event loop (e.g. FastAPI with uvicorn)
            # Use run_in_executor to avoid blocking the loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(asyncio.run, audit_security_bundle_async(state))
                return future.result()
        return loop.run_until_complete(audit_security_bundle_async(state))
    except RuntimeError:
        return asyncio.run(audit_security_bundle_async(state))
