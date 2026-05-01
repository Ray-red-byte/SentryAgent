"""
Workflow nodes for the security scanning pipeline.
Each node is a pure function that takes state and returns updated state.
"""
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.workflows.state import ScanState, ScanResult, Vulnerability
from app.core.parser.python_parser import PythonParser
from app.core.parser.dependency_graph import DependencyMapper
from app.memory.knowledge_base import SecurityKnowledgeBase
from app.utils.logger import get_logger
from app.config.domain import DOMAIN_HEURISTICS, SKIP_DIRS, SKIP_EXTS

logger = get_logger(__name__)


def _path_to_module(rel_path: str) -> str:
    """Convert a relative file path to the dot-notation module key used in the graph."""
    return rel_path.replace("\\", "/").replace("/", ".").replace(".py", "")


def _module_to_path(module: str) -> str:
    """Inverse of _path_to_module — produces an OS-native relative path."""
    return module.replace(".", os.sep) + ".py"


def discover_files(state: ScanState) -> ScanState:
    """
    Node 1: Discover all source Python files to scan.

    Skips compiled bytecode (.pyc/.pyo/.pyd) and well-known non-source
    directories (__pycache__, venv, .git, etc.).
    """
    logger.info("[DISCOVER] Scanning directory: %s", state['root_dir'])

    root_path = Path(state['root_dir'])
    files = []

    for file_path in root_path.rglob("*.py"):
        if any(part in SKIP_DIRS for part in file_path.parts):
            continue
        if file_path.suffix in SKIP_EXTS:
            continue
        files.append(str(file_path.relative_to(root_path)))

    logger.info("[DISCOVER] Found %d file(s) to scan", len(files))

    return {
        **state,
        "files_to_scan": files,
        "current_stage": "discovered",
    }


def _parse_single_file(args) -> ScanResult | None:
    """Parse a single file — runs in a thread pool worker."""
    rel_file_path, root_path, parser = args
    try:
        full_path = root_path / rel_file_path
        with open(full_path, "rb") as f:
            code = f.read()

        routes = parser.find_entry_points(code)
        hotspots = parser.find_security_hotspots(code)

        if routes or hotspots:
            risk_score = len(routes) + (len(hotspots) * 5)
            return ScanResult(
                file_path=rel_file_path,
                risk_score=risk_score,
                routes=len(routes),
                hotspots=hotspots,
            )
    except Exception as e:
        logger.warning("Error scanning %s: %s", rel_file_path, e)
    return None


def parse_and_scan(state: ScanState) -> ScanState:
    """
    Node 2: Parse code files and perform initial security scan.

    Uses tree-sitter to parse files and identify entry points and hotspots.
    Parallelised with a ThreadPoolExecutor for faster throughput.
    """
    files = state['files_to_scan']
    logger.info("[PARSE] Analyzing %d file(s) in parallel...", len(files))

    parser = PythonParser()
    root_path = Path(state['root_dir'])
    errors = []

    max_workers = min(8, len(files) or 1)
    args_list = [(f, root_path, parser) for f in files]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(_parse_single_file, args_list))

    scan_results = [r for r in results if r is not None]
    scan_results.sort(key=lambda x: x.risk_score, reverse=True)

    logger.info("[PARSE] Completed. Found %d file(s) with issues", len(scan_results))

    return {
        **state,
        "scan_results": scan_results,
        "errors": errors,
        "current_stage": "scanned",
    }


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
    logger.info("[BUNDLE] Grouping files into security domains...")

    root_path = Path(state["root_dir"])
    files_to_scan = state["files_to_scan"]

    if not files_to_scan:
        logger.warning("[BUNDLE] No files to bundle.")
        return {**state, "security_bundles": {}, "current_stage": "bundled"}

    # --- 1. Build the internal-dependency graph ----------------------------
    try:
        mapper = DependencyMapper(state["root_dir"])
        graph = mapper.build_graph()
        logger.info("  Dependency graph: %d modules, %d edges",
                    graph.number_of_nodes(), graph.number_of_edges())
    except Exception as e:
        logger.warning("[BUNDLE] Dependency graph failed (%s). Heuristics-only mode.", e)
        mapper = None
        graph = None

    valid_paths = set(files_to_scan)

    # --- 2. Read raw import strings per file (for import-keyword matching) -
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
        path_lower = rel_path.lower().replace("\\", "/")
        imports_str = file_import_str.get(rel_path, "")

        for domain, rules in DOMAIN_HEURISTICS.items():
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

    bundles = {domain: sorted(paths) for domain, paths in bundles.items()}

    if bundles:
        logger.info("[BUNDLE] Created %d security domain bundle(s):", len(bundles))
        for domain, paths in bundles.items():
            logger.info("  %s: %d file(s)", domain, len(paths))
    else:
        logger.warning("[BUNDLE] No files matched any domain heuristic. "
                       "deep_audit_high_risk_files will fall back to per-file mode.")

    return {
        **state,
        "security_bundles": bundles,
        "current_stage": "bundled",
    }


def load_organizational_memory(state: ScanState) -> ScanState:
    """
    Node 3: Load relevant lessons from organizational memory (RAG).

    Queries the knowledge base for past vulnerabilities and fixes.
    Failures are non-fatal — scan continues with empty memory.
    """
    logger.info("[MEMORY] Loading organizational memory...")

    try:
        kb = SecurityKnowledgeBase()
        lessons = kb.recall_relevant_lessons("security audit")
        logger.info("[MEMORY] Loaded %d past lesson(s)", len(lessons))

        return {
            **state,
            "organizational_memory": lessons,
            "current_stage": "scanned",
        }
    except Exception as e:
        logger.warning("[MEMORY] Failed to load memory: %s", e)
        existing_errors = list(state.get("errors", []))
        existing_errors.append(f"Memory load failed: {str(e)}")
        return {
            **state,
            "organizational_memory": [],
            "errors": existing_errors,
        }


def generate_report(state: ScanState) -> ScanState:
    """
    Node 4 (final): Generate the structural scan report.

    Returns bundle structure, risk scores, and hotspot counts.
    No vulnerability findings here — those come from per-bundle /audit calls.
    """
    logger.info("[REPORT] Generating final report...")

    raw_bundles = state.get("security_bundles", {})
    report = {
        "session_id": state["session_id"],
        "security_bundles": dict(raw_bundles),
        "summary": {
            "total_files_scanned": len(state["files_to_scan"]),
            "security_bundles": {
                domain: len(paths) for domain, paths in raw_bundles.items()
            },
            "files_with_issues": len(state["scan_results"]),
            "total_vulnerabilities": 0,  # populated by /audit calls
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
        "vulnerabilities": [],   # populated by /audit calls
        "audit_mode": "on_demand",  # LLM audit triggered via POST /v2/audit per bundle
        "errors": state.get("errors", []),
    }

    logger.info("[REPORT] Report generated successfully")

    return {
        **state,
        "scan_metadata": {
            **state.get("scan_metadata", {}),
            "final_report": report,
        },
        "current_stage": "complete",
    }
