"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
from pathlib import Path
from app.workflows.state import ScanState, ScanResult, Vulnerability
from app.core.parser.python_parser import PythonParser
from app.agent.auditor import SecurityAuditor
from app.memory.knowledge_base import SecurityKnowledgeBase

import logging

logger = logging.getLogger(__name__)

def discover_files(state: ScanState) -> ScanState:
    """
    Node 1: Discover all code files to scan.

    Walks the directory tree and finds all Python files (excluding venv, cache).
    """
    print(f"🔍 [DISCOVER] Scanning directory: {state['root_dir']}")

    root_path = Path(state['root_dir'])
    files = []

    # Find all Python files
    for file_path in root_path.rglob("*.py"):
        # Skip virtual environments and cache
        if "venv" in str(file_path) or "__pycache__" in str(file_path):
            continue
        files.append(str(file_path.relative_to(root_path)))

    print(f"✅ [DISCOVER] Found {len(files)} files to scan")

    return {
        **state,
        "files_to_scan": files,
        "current_stage": "discovered"
    }


def parse_and_scan(state: ScanState) -> ScanState:
    """
    Node 2: Parse code files and perform initial security scan.

    Uses tree-sitter to parse files and identify entry points and hotspots.
    """
    print(f"🔍 [PARSE] Analyzing {len(state['files_to_scan'])} files...")

    parser = PythonParser()
    root_path = Path(state['root_dir'])
    scan_results = []
    errors = []

    for rel_file_path in state['files_to_scan']:
        try:
            full_path = root_path / rel_file_path

            with open(full_path, "rb") as f:
                code = f.read()

            # Use Parser to find entry points and hotspots
            routes = parser.find_entry_points(code)
            hotspots = parser.find_security_hotspots(code)

            if routes or hotspots:
                # Simple scoring heuristic
                risk_score = len(routes) + (len(hotspots) * 5)

                scan_results.append(ScanResult(
                    file_path=rel_file_path,
                    risk_score=risk_score,
                    routes=len(routes),
                    hotspots=hotspots
                ))

        except Exception as e:
            error_msg = f"Error scanning {rel_file_path}: {str(e)}"
            print(f"⚠️ {error_msg}")
            errors.append(error_msg)
            continue

    # Sort by highest risk first
    scan_results.sort(key=lambda x: x.risk_score, reverse=True)

    print(f"✅ [PARSE] Completed. Found {len(scan_results)} files with issues")

    return {
        **state,
        "scan_results": scan_results,
        "errors": errors,
        "current_stage": "scanned"
    }


def load_organizational_memory(state: ScanState) -> ScanState:
    """
    Node 3: Load relevant lessons from organizational memory (RAG).

    Queries the knowledge base for past vulnerabilities and fixes.
    """
    print("🧠 [MEMORY] Loading organizational memory...")

    try:
        kb = SecurityKnowledgeBase()

        # Query for general security lessons
        lessons = kb.recall_relevant_lessons("security audit")

        print(f"✅ [MEMORY] Loaded {len(lessons)} past lessons")

        return {
            **state,
            "organizational_memory": lessons,
            "current_stage": "scanned"
        }
    except Exception as e:
        print(f"⚠️ [MEMORY] Failed to load memory: {e}")
        existing_errors = list(state.get("errors", []))
        existing_errors.append(f"Memory load failed: {str(e)}")
        return {
            **state,
            "organizational_memory": [],
            "errors": existing_errors
        }


def deep_audit_high_risk_files(state: ScanState) -> ScanState:
    """
    Node 4: Perform deep AI-powered audit on high-risk files.

    Uses LLM with cache to analyze files for vulnerabilities.
    Only audits files with risk_score >= threshold.
    """
    print("🕵️ [AUDIT] Starting deep audit on high-risk files...")

    # Configuration
    risk_threshold = state.get("config", {}).get("risk_threshold", 5)
    max_files_to_audit = state.get("config", {}).get("max_audit_files", 10)

    # Filter high-risk files
    high_risk_files = [
        sr for sr in state["scan_results"]
        if sr.risk_score >= risk_threshold
    ][:max_files_to_audit]

    print(f"🎯 [AUDIT] Auditing {len(high_risk_files)} high-risk files (threshold: {risk_threshold})")

    auditor = SecurityAuditor(root_dir=state["root_dir"])
    all_vulnerabilities = []
    errors = []

    for scan_result in high_risk_files:
        try:
            print(f"  📄 Auditing: {scan_result.file_path}")

            # Use cache if available
            if state.get("cache_name"):
                report = auditor.audit_file_with_cache(
                    scan_result.file_path,
                    state["cache_name"]
                )
            else:
                report = auditor.audit_file(scan_result.file_path)

            # Convert report to Vulnerability objects
            for vuln_dict in report:
                if isinstance(vuln_dict, dict) and vuln_dict.get("severity") != "ERROR":
                    vuln = Vulnerability(
                        type=vuln_dict.get("type", "Unknown"),
                        severity=vuln_dict.get("severity", "INFO"),
                        file=scan_result.file_path,
                        line=vuln_dict.get("line", 0),
                        description=vuln_dict.get("description", ""),
                        fix_suggestion=vuln_dict.get("fix", ""),
                        cvss_score=vuln_dict.get("cvss_score", 0.0)
                    )
                    all_vulnerabilities.append(vuln)

        except Exception as e:
            error_msg = f"Audit failed for {scan_result.file_path}: {str(e)}"
            print(f"⚠️ {error_msg}")
            errors.append(error_msg)

    print(f"✅ [AUDIT] Found {len(all_vulnerabilities)} vulnerabilities")

    return {
        **state,
        "vulnerabilities": all_vulnerabilities,
        "errors": errors,
        "current_stage": "audited"
    }


def prioritize_vulnerabilities(state: ScanState) -> ScanState:
    """
    Node 5: Sort and prioritize vulnerabilities.

    Orders vulnerabilities by severity and exploitability.
    """
    print("📊 [PRIORITIZE] Sorting vulnerabilities...")

    _SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    sorted_vulns = sorted(
        state["vulnerabilities"],
        key=lambda v: (
            _SEVERITY_RANK.get(v.severity, 0),  # Unknown severities rank lowest
            -v.cvss_score
        ),
        reverse=True
    )

    # Calculate statistics
    stats = {
        "total": len(sorted_vulns),
        "critical": sum(1 for v in sorted_vulns if v.severity == "CRITICAL"),
        "high": sum(1 for v in sorted_vulns if v.severity == "HIGH"),
        "medium": sum(1 for v in sorted_vulns if v.severity == "MEDIUM"),
        "low": sum(1 for v in sorted_vulns if v.severity == "LOW"),
        "info": sum(1 for v in sorted_vulns if v.severity == "INFO"),
    }

    print(f"✅ [PRIORITIZE] Stats: {stats}")

    return {
        **state,
        "vulnerabilities": sorted_vulns,
        "scan_metadata": {
            **state.get("scan_metadata", {}),
            "vulnerability_stats": stats
        },
        "current_stage": "prioritized"
    }



def generate_report(state: ScanState) -> ScanState:
    """
    Node 6: Generate final scan report.

    Creates a comprehensive report with all findings.
    """
    print("📝 [REPORT] Generating final report...")

    report = {
        "session_id": state["session_id"],
        "summary": {
            "total_files_scanned": len(state["files_to_scan"]),
            "files_with_issues": len(state["scan_results"]),
            "total_vulnerabilities": len(state["vulnerabilities"]),
            **state.get("scan_metadata", {}).get("vulnerability_stats", {})
        },
        "scan_results": [
            {
                "file": sr.file_path,
                "risk_score": sr.risk_score,
                "routes": sr.routes,
                "hotspots": sr.hotspots
            }
            for sr in state["scan_results"]
        ],
        "vulnerabilities": [
            {
                "type": v.type,
                "severity": v.severity,
                "file": v.file,
                "line": v.line,
                "description": v.description,
                "fix": v.fix_suggestion,
                "priority_score": v.priority_score()
            }
            for v in state["vulnerabilities"]
        ],
        "errors": state.get("errors", [])
    }

    print("✅ [REPORT] Report generated successfully")

    return {
        **state,
        "scan_metadata": {
            **state.get("scan_metadata", {}),
            "final_report": report
        },
        "current_stage": "complete"
    }