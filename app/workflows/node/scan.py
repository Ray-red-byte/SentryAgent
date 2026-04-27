"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
import os
from pathlib import Path

from app.workflows.state import ScanState, ScanResult, Vulnerability
from app.core.parser.python_parser import PythonParser
from app.core.parser.dependency_graph import DependencyMapper
from app.agent.auditor import SecurityAuditor
from app.memory.knowledge_base import SecurityKnowledgeBase

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security-domain heuristics
# ---------------------------------------------------------------------------
# Each entry maps a domain label to the keywords that signal membership.
# path_keywords  — matched against the relative file path (lower-cased).
# import_keywords — matched against raw import strings extracted from the file.
# A file qualifies for a domain when ANY keyword in either list matches.
# ---------------------------------------------------------------------------
_DOMAIN_HEURISTICS: dict[str, dict[str, list[str]]] = {
    "authentication": {
        "path_keywords": [
            "auth", "jwt", "login", "logout", "session",
            "token", "oauth", "password", "credential",
        ],
        "import_keywords": [
            "jwt", "passlib", "python_jose", "bcrypt", "oauth2", "authlib",
        ],
    },
    "data_injection": {
        "path_keywords": [
            "database", "databases", "/db/", "model", "schema",
            "orm", "crud", "repository", "repo", "migration",
        ],
        "import_keywords": [
            "sqlalchemy", "psycopg2", "psycopg", "pymongo",
            "databases", "tortoise", "alembic", "asyncpg",
        ],
    },
    "rate_limiting": {
        "path_keywords": ["rate", "limit", "throttle", "middleware"],
        "import_keywords": ["slowapi", "ratelimit", "limits"],
    },
    "secrets_management": {
        "path_keywords": ["config", "settings", "env", "secret", "key"],
        "import_keywords": ["dotenv", "pydantic_settings", "decouple", "dynaconf"],
    },
    "input_validation": {
        "path_keywords": ["schema", "validator", "sanitize", "serializ", "deserializ"],
        "import_keywords": ["pydantic", "marshmallow", "cerberus", "wtforms", "voluptuous"],
    },
    "access_control": {
        "path_keywords": [
            "permission", "role", "rbac", "acl", "policy",
            "guard", "authz", "authorization",
        ],
        "import_keywords": ["casbin", "authlib"],
    },
}


# ---------------------------------------------------------------------------
# Module ↔ path helpers (must mirror DependencyMapper.build_graph logic)
# ---------------------------------------------------------------------------

def _path_to_module(rel_path: str) -> str:
    """Convert a relative file path to the dot-notation module key used in the graph."""
    return rel_path.replace("\\", "/").replace("/", ".").replace(".py", "")


def _module_to_path(module: str) -> str:
    """Inverse of _path_to_module — produces an OS-native relative path."""
    return module.replace(".", os.sep) + ".py"


# ---------------------------------------------------------------------------
# Node 1: discover_files
# ---------------------------------------------------------------------------

def discover_files(state: ScanState) -> ScanState:
    """
    Node 1: Discover all code files to scan.

    Walks the directory tree and finds all Python files (excluding venv, cache).
    """
    print(f"🔍 [DISCOVER] Scanning directory: {state['root_dir']}")

    root_path = Path(state['root_dir'])
    files = []

    for file_path in root_path.rglob("*.py"):
        if "venv" in str(file_path) or "__pycache__" in str(file_path):
            continue
        files.append(str(file_path.relative_to(root_path)))

    print(f"✅ [DISCOVER] Found {len(files)} files to scan")

    return {
        **state,
        "files_to_scan": files,
        "current_stage": "discovered",
    }


# ---------------------------------------------------------------------------
# Node 2: parse_and_scan
# ---------------------------------------------------------------------------

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

            routes = parser.find_entry_points(code)
            hotspots = parser.find_security_hotspots(code)

            if routes or hotspots:
                risk_score = len(routes) + (len(hotspots) * 5)
                scan_results.append(ScanResult(
                    file_path=rel_file_path,
                    risk_score=risk_score,
                    routes=len(routes),
                    hotspots=hotspots,
                ))

        except Exception as e:
            error_msg = f"Error scanning {rel_file_path}: {str(e)}"
            print(f"⚠️ {error_msg}")
            errors.append(error_msg)
            continue

    scan_results.sort(key=lambda x: x.risk_score, reverse=True)
    print(f"✅ [PARSE] Completed. Found {len(scan_results)} files with issues")

    return {
        **state,
        "scan_results": scan_results,
        "errors": errors,
        "current_stage": "scanned",
    }


# ---------------------------------------------------------------------------
# Node 2b: bundle_into_security_domains
# ---------------------------------------------------------------------------

def bundle_into_security_domains(state: ScanState) -> ScanState:
    """
    Node 2b: Group discovered files into security-domain bundles.

    Two-pass approach:
      Pass 1 — classify each file by path-keyword and import-keyword heuristics.
      Pass 2 — expand each bundle by one dependency hop: if file A is in domain X
               and A directly imports (or is imported by) file B, add B to domain X.
               This ensures that a route file that calls an auth service shares a
               bundle with that service.

    Files may appear in multiple bundles (intentional overlap).
    """
    print("🗂️  [BUNDLE] Grouping files into security domains...")

    root_path = Path(state["root_dir"])
    files_to_scan = state["files_to_scan"]

    if not files_to_scan:
        print("⚠️  [BUNDLE] No files to bundle.")
        return {**state, "security_bundles": {}, "current_stage": "bundled"}

    # --- 1. Build the internal-dependency graph ----------------------------
    try:
        mapper = DependencyMapper(state["root_dir"])
        graph = mapper.build_graph()
        print(f"  🔗 Dependency graph: {graph.number_of_nodes()} modules, "
              f"{graph.number_of_edges()} edges")
    except Exception as e:
        print(f"⚠️  [BUNDLE] Dependency graph failed ({e}). Heuristics-only mode.")
        mapper = None
        graph = None

    valid_paths = set(files_to_scan)

    # --- 2. Read raw import strings per file (for import-keyword matching) -
    # DependencyMapper.build_graph() tracks only app.* edges; we need all
    # imports to check third-party library keywords (jwt, passlib, etc.).
    file_import_str: dict[str, str] = {}
    if mapper is not None:
        for rel_path in files_to_scan:
            try:
                with open(root_path / rel_path, "rb") as fh:
                    raw_imports = mapper.find_imports(fh.read())
                file_import_str[rel_path] = " ".join(raw_imports).lower()
            except Exception:
                file_import_str[rel_path] = ""

    # --- 3. Pass 1: classify each file via heuristics ----------------------
    file_domains: dict[str, set[str]] = {f: set() for f in files_to_scan}

    for rel_path in files_to_scan:
        # Normalise path separators for keyword matching
        path_lower = rel_path.lower().replace("\\", "/")
        imports_str = file_import_str.get(rel_path, "")

        for domain, rules in _DOMAIN_HEURISTICS.items():
            path_hit = any(kw in path_lower for kw in rules["path_keywords"])
            import_hit = any(kw in imports_str for kw in rules["import_keywords"])
            if path_hit or import_hit:
                file_domains[rel_path].add(domain)

    # --- 4. Pass 2: 1-hop dependency expansion ----------------------------
    if graph is not None:
        for rel_path, domains in list(file_domains.items()):
            if not domains:
                continue

            module = _path_to_module(rel_path)
            if not graph.has_node(module):
                continue

            # Both directions: files this module imports AND files that import it
            neighbors = (
                list(graph.successors(module)) +
                list(graph.predecessors(module))
            )
            for neighbor_module in neighbors:
                neighbor_path = _module_to_path(neighbor_module)
                if neighbor_path in valid_paths:
                    for domain in domains:
                        file_domains[neighbor_path].add(domain)

    # --- 5. Assemble final bundles dict ------------------------------------
    bundles: dict[str, list[str]] = {}
    for rel_path, domains in file_domains.items():
        for domain in domains:
            bundles.setdefault(domain, []).append(rel_path)

    # Sort for deterministic ordering
    bundles = {domain: sorted(paths) for domain, paths in bundles.items()}

    if bundles:
        print(f"✅ [BUNDLE] Created {len(bundles)} security domain bundle(s):")
        for domain, paths in bundles.items():
            print(f"  📦 {domain}: {len(paths)} file(s)")
    else:
        print("⚠️  [BUNDLE] No files matched any domain heuristic. "
              "deep_audit_high_risk_files will fall back to per-file mode.")

    return {
        **state,
        "security_bundles": bundles,
        "current_stage": "bundled",
    }


# ---------------------------------------------------------------------------
# Node 3: load_organizational_memory
# ---------------------------------------------------------------------------

def load_organizational_memory(state: ScanState) -> ScanState:
    """
    Node 3: Load relevant lessons from organizational memory (RAG).

    Queries the knowledge base for past vulnerabilities and fixes.
    """
    print("🧠 [MEMORY] Loading organizational memory...")

    try:
        kb = SecurityKnowledgeBase()
        lessons = kb.recall_relevant_lessons("security audit")
        print(f"✅ [MEMORY] Loaded {len(lessons)} past lessons")

        return {
            **state,
            "organizational_memory": lessons,
            "current_stage": "scanned",
        }
    except Exception as e:
        print(f"⚠️ [MEMORY] Failed to load memory: {e}")
        existing_errors = list(state.get("errors", []))
        existing_errors.append(f"Memory load failed: {str(e)}")
        return {
            **state,
            "organizational_memory": [],
            "errors": existing_errors,
        }


# ---------------------------------------------------------------------------
# Node 4: deep_audit_high_risk_files
# ---------------------------------------------------------------------------

def deep_audit_high_risk_files(state: ScanState) -> ScanState:
    """
    Node 4: Deep AI-powered audit of high-risk security bundles.

    Bundle mode (security_bundles populated):
      A bundle is flagged when the *maximum* risk_score of any file inside it
      meets or exceeds the configured threshold (max-risk rule). All files in
      that bundle are audited so the LLM sees the full domain context.

      NOTE: max_audit_files caps the number of *bundles* audited, not files.
      With overlapping bundles each containing multiple files, the actual
      file count per run may exceed max_audit_files. Gemini's 1 M-token context
      makes this acceptable by design.

      Step 4 of the refactor will replace the per-file auditor.audit_file()
      calls below with auditor.audit_bundle(), which concatenates all files in
      a bundle into a single prompt for true cross-file data-flow analysis.

    Fallback mode (security_bundles empty or a high-risk file has no bundle):
      Falls back to the original per-file behaviour so no findings are silently
      lost when the heuristic classifier produces no matches.
    """
    print("🕵️  [AUDIT] Starting deep audit on high-risk security bundles...")

    risk_threshold = state.get("config", {}).get("risk_threshold", 5)
    # Caps bundles in bundle mode; caps files in fallback mode.
    max_audit = state.get("config", {}).get("max_audit_files", 10)

    security_bundles = state.get("security_bundles", {})
    risk_by_file: dict[str, int] = {
        sr.file_path: sr.risk_score for sr in state["scan_results"]
    }

    auditor = SecurityAuditor(root_dir=state["root_dir"])
    all_vulnerabilities: list[Vulnerability] = []
    errors: list[str] = []

    # ── Determine what to audit ────────────────────────────────────────────
    # files_to_audit: ordered list of relative paths, deduplicated.
    files_to_audit: list[str] = []
    audited_set: set[str] = set()   # dedup tracker

    if security_bundles:
        # Identify bundles where at least one file meets the threshold
        high_risk_bundles = [
            (name, paths)
            for name, paths in security_bundles.items()
            if max(
                (risk_by_file.get(fp, 0) for fp in paths), default=0
            ) >= risk_threshold
        ][:max_audit]

        print(
            f"🎯 [AUDIT] {len(high_risk_bundles)} high-risk bundle(s) "
            f"(threshold={risk_threshold}, cap={max_audit} bundles)"
        )

        for bundle_name, paths in high_risk_bundles:
            bundle_max = max((risk_by_file.get(fp, 0) for fp in paths), default=0)
            print(f"  📦 '{bundle_name}': max_risk={bundle_max}, {len(paths)} file(s)")
            for fp in paths:
                if fp not in audited_set:
                    audited_set.add(fp)
                    files_to_audit.append(fp)

        # Fallback for high-risk files that landed in no bundle
        bundled_files = {fp for paths in security_bundles.values() for fp in paths}
        uncovered = [
            sr for sr in state["scan_results"]
            if sr.risk_score >= risk_threshold
            and sr.file_path not in bundled_files
            and sr.file_path not in audited_set
        ]
        if uncovered:
            print(
                f"  ↩️  {len(uncovered)} high-risk file(s) not in any bundle "
                f"— auditing individually"
            )
            for sr in uncovered:
                audited_set.add(sr.file_path)
                files_to_audit.append(sr.file_path)

    else:
        # No bundles at all — original per-file behaviour
        print(
            "⚠️  [AUDIT] No security bundles found. "
            "Falling back to per-file mode (top files by risk score)."
        )
        high_risk = [
            sr for sr in state["scan_results"]
            if sr.risk_score >= risk_threshold
        ][:max_audit]
        files_to_audit = [sr.file_path for sr in high_risk]
        print(
            f"🎯 [AUDIT] {len(files_to_audit)} file(s) to audit "
            f"(threshold={risk_threshold})"
        )

    if not files_to_audit:
        print("✅ [AUDIT] Nothing to audit.")
        return {**state, "current_stage": "audited"}

    # ── Audit each file ────────────────────────────────────────────────────
    for rel_path in files_to_audit:
        try:
            print(f"  📄 Auditing: {rel_path}")

            if state.get("cache_name"):
                report = auditor.audit_file_with_cache(rel_path, state["cache_name"])
            else:
                report = auditor.audit_file(rel_path)

            for vuln_dict in report:
                if isinstance(vuln_dict, dict) and vuln_dict.get("severity") != "ERROR":
                    vuln = Vulnerability(
                        type=vuln_dict.get("type", "Unknown"),
                        severity=vuln_dict.get("severity", "INFO"),
                        file=rel_path,
                        line=vuln_dict.get("line", 0),
                        description=vuln_dict.get("description", ""),
                        fix_suggestion=vuln_dict.get("fix", ""),
                        cvss_score=vuln_dict.get("cvss_score", 0.0),
                    )
                    all_vulnerabilities.append(vuln)

        except Exception as e:
            error_msg = f"Audit failed for {rel_path}: {str(e)}"
            print(f"⚠️ {error_msg}")
            errors.append(error_msg)

    print(f"✅ [AUDIT] Found {len(all_vulnerabilities)} vulnerabilities")

    return {
        **state,
        "vulnerabilities": all_vulnerabilities,
        "errors": errors,
        "current_stage": "audited",
    }


# ---------------------------------------------------------------------------
# Node 5: prioritize_vulnerabilities
# ---------------------------------------------------------------------------

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
            _SEVERITY_RANK.get(v.severity, 0),
            -v.cvss_score,
        ),
        reverse=True,
    )

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
            "vulnerability_stats": stats,
        },
        "current_stage": "prioritized",
    }


# ---------------------------------------------------------------------------
# Node 6: generate_report
# ---------------------------------------------------------------------------

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
            "security_bundles": {
                domain: len(paths)
                for domain, paths in state.get("security_bundles", {}).items()
            },
            "files_with_issues": len(state["scan_results"]),
            "total_vulnerabilities": len(state["vulnerabilities"]),
            **state.get("scan_metadata", {}).get("vulnerability_stats", {}),
        },
        "scan_results": [
            {
                "file": sr.file_path,
                "risk_score": sr.risk_score,
                "routes": sr.routes,
                "hotspots": sr.hotspots,
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
                "priority_score": v.priority_score(),
            }
            for v in state["vulnerabilities"]
        ],
        "errors": state.get("errors", []),
    }

    print("✅ [REPORT] Report generated successfully")

    return {
        **state,
        "scan_metadata": {
            **state.get("scan_metadata", {}),
            "final_report": report,
        },
        "current_stage": "complete",
    }
