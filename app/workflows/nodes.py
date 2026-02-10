"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
from pathlib import Path
from typing import Optional
from app.workflows.state import ScanState, ScanResult, Vulnerability, AuditState, PatchState
from app.tools.parser.python_parser import PythonParser
from app.agent.auditor import SecurityAuditor
from app.agent.patcher import SecurityPatcher
from app.memory.knowledge_base import SecurityKnowledgeBase


# ============================================================================
# SCAN WORKFLOW NODES
# ============================================================================

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
        return {
            **state,
            "organizational_memory": [],
            "errors": [f"Memory load failed: {str(e)}"]
        }


def deep_audit_high_risk_files(state: ScanState) -> ScanState:
    """
    Node 4: Perform deep AI-powered audit on high-risk files.
    
    Uses LLM with cache to analyze files for vulnerabilities.
    Only audits files with risk_score > threshold.
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
    
    sorted_vulns = sorted(
        state["vulnerabilities"],
        key=lambda v: (
            {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[v.severity],
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
    
    print(f"✅ [REPORT] Report generated successfully")
    
    return {
        **state,
        "scan_metadata": {
            **state.get("scan_metadata", {}),
            "final_report": report
        },
        "current_stage": "complete"
    }


# ============================================================================
# AUDIT WORKFLOW NODES (Single File)
# ============================================================================

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


# ============================================================================
# PATCH WORKFLOW NODES
# ============================================================================

def generate_patch(state: PatchState) -> PatchState:
    """Generate security patches for vulnerabilities."""
    print(f"🔧 [PATCH] Generating fixes for {state['file_path']}...")
    
    try:
        patcher = SecurityPatcher(root_dir=state["root_dir"])
        
        # Generate patch
        patched_code = patcher.patch_file(
            state["file_path"],
            cache_name=state.get("cache_name")
        )
        
        print(f"✅ [PATCH] Patch generated successfully")
        
        return {
            **state,
            "patched_code": patched_code,
            "current_stage": "patching"
        }
        
    except Exception as e:
        print(f"❌ [PATCH] Error: {e}")
        return {
            **state,
            "current_stage": "error",
            "error": str(e)
        }


def save_patch_to_memory(state: PatchState) -> PatchState:
    """Save the patch to organizational memory for future learning."""
    print("🧠 [MEMORY] Saving patch to knowledge base...")
    
    try:
        kb = SecurityKnowledgeBase()
        kb.learn_fix(
            vuln_type="Security Patch",
            description=f"Patch for {state['file_path']}",
            fix_code=state["patched_code"][:1000]  # Truncate for storage
        )
        
        print("✅ [MEMORY] Patch saved to knowledge base")
        
        return {
            **state,
            "current_stage": "complete"
        }
        
    except Exception as e:
        print(f"⚠️ [MEMORY] Failed to save patch: {e}")
        # Non-critical error, still mark as complete
        return {
            **state,
            "current_stage": "complete"
        }


# ============================================================================
# CONDITIONAL ROUTING FUNCTIONS
# ============================================================================

def should_deep_audit(state: ScanState) -> str:
    """
    Decide if deep audit is needed based on initial scan results.
    
    Returns:
        "audit" if high-risk files found
        "report" if no significant issues
    """
    risk_threshold = state.get("config", {}).get("risk_threshold", 5)
    high_risk_count = sum(1 for sr in state["scan_results"] if sr.risk_score >= risk_threshold)
    
    if high_risk_count > 0:
        print(f"🎯 [DECISION] {high_risk_count} high-risk files found → Deep audit required")
        return "audit"
    else:
        print("✅ [DECISION] No high-risk files → Skip to report")
        return "report"


def should_prioritize(state: ScanState) -> str:
    """
    Decide if prioritization is needed.
    
    Returns:
        "prioritize" if vulnerabilities found
        "report" if no vulnerabilities
    """
    vuln_count = len(state.get("vulnerabilities", []))
    
    if vuln_count > 0:
        print(f"📊 [DECISION] {vuln_count} vulnerabilities found → Prioritize")
        return "prioritize"
    else:
        print("✅ [DECISION] No vulnerabilities → Skip to report")
        return "report"
