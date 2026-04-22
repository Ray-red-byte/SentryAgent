# SentryAgent - Practical Implementation Guide

## Quick Start: Refactoring Your Current Code

### Step 1: Install LangGraph
```bash
pip install langgraph langchain-anthropic langsmith
pip install semgrep bandit pip-audit  # Security tools
```

### Step 2: Project Structure
```
sentry-agent/
├── app/
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py      # Main workflow
│   │   ├── code_parser.py       # File parsing
│   │   ├── sast_scanner.py      # Security analysis
│   │   ├── dependency_scanner.py # SCA
│   │   └── report_generator.py  # Reporting
│   ├── core/
│   │   ├── models.py           # Pydantic models
│   │   ├── state.py            # Shared state
│   │   └── tools.py            # Scanning tools
│   ├── api/
│   │   ├── main.py             # FastAPI app
│   │   └── routes.py           # API endpoints
│   └── config.py
├── frontend/                    # Your existing frontend
├── tests/
├── docker-compose.yml
└── requirements.txt
```

### Step 3: Define Your State (app/core/state.py)
```python
from typing import TypedDict, Annotated, Literal
from pydantic import BaseModel
import operator

class Vulnerability(BaseModel):
    """Individual vulnerability finding"""
    id: str
    type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    cwe_id: str | None = None
    cvss_score: float | None = None
    fix_suggestion: str | None = None
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"

class ScanState(TypedDict):
    """Global state shared across all agents"""
    # Input
    scan_id: str
    uploaded_files: list[str]
    project_type: str  # "python", "javascript", etc.
    
    # Processing
    files_to_scan: list[str]
    current_file: str | None
    
    # Results
    vulnerabilities: Annotated[list[Vulnerability], operator.add]
    errors: Annotated[list[str], operator.add]
    
    # Metadata
    scan_stage: str
    start_time: float
    stats: dict
```

### Step 4: Implement Agents

#### A. Code Parser Agent (app/agents/code_parser.py)
```python
import ast
import os
from pathlib import Path
from app.core.state import ScanState

async def parse_files_agent(state: ScanState) -> ScanState:
    """
    Discover and parse all code files
    """
    uploaded_dir = f"/tmp/scans/{state['scan_id']}"
    files_to_scan = []
    
    # Language-specific extensions
    extensions = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
    }
    
    exts = extensions.get(state["project_type"], [".py"])
    
    # Find all relevant files
    for ext in exts:
        files_to_scan.extend(
            str(p) for p in Path(uploaded_dir).rglob(f"*{ext}")
        )
    
    return {
        **state,
        "files_to_scan": files_to_scan,
        "scan_stage": "files_discovered",
        "stats": {
            "total_files": len(files_to_scan)
        }
    }
```

#### B. SAST Scanner Agent (app/agents/sast_scanner.py)
```python
import subprocess
import json
from app.core.state import ScanState, Vulnerability

async def sast_scanner_agent(state: ScanState) -> ScanState:
    """
    Run static analysis security testing
    """
    vulnerabilities = []
    
    # Run Semgrep for multi-language support
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config=auto",  # Use Semgrep Registry rules
                "--json",
                "--quiet",
                *state["files_to_scan"]
            ],
            capture_output=True,
            text=True,
            timeout=300  # 5 min timeout
        )
        
        if result.returncode == 0 or result.returncode == 1:  # 1 = findings
            findings = json.loads(result.stdout)
            
            for finding in findings.get("results", []):
                vuln = Vulnerability(
                    id=f"SAST-{finding['check_id']}",
                    type=finding["check_id"],
                    severity=map_severity(finding["extra"]["severity"]),
                    file_path=finding["path"],
                    line_number=finding["start"]["line"],
                    code_snippet=finding["extra"]["lines"],
                    description=finding["extra"]["message"],
                    cwe_id=finding["extra"].get("metadata", {}).get("cwe"),
                    confidence="HIGH"
                )
                vulnerabilities.append(vuln)
    
    except subprocess.TimeoutExpired:
        return {
            **state,
            "errors": [f"SAST scan timeout"],
            "scan_stage": "sast_timeout"
        }
    except Exception as e:
        return {
            **state,
            "errors": [f"SAST scan error: {str(e)}"],
            "scan_stage": "sast_error"
        }
    
    return {
        **state,
        "vulnerabilities": vulnerabilities,
        "scan_stage": "sast_complete"
    }

def map_severity(semgrep_severity: str) -> str:
    """Map Semgrep severity to our scale"""
    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW"
    }
    return mapping.get(semgrep_severity, "MEDIUM")
```

#### C. Dependency Scanner (app/agents/dependency_scanner.py)
```python
import subprocess
import json
from pathlib import Path
from app.core.state import ScanState, Vulnerability

async def dependency_scanner_agent(state: ScanState) -> ScanState:
    """
    Scan dependencies for known vulnerabilities
    """
    vulnerabilities = []
    scan_dir = Path(state["files_to_scan"][0]).parent
    
    # Python: pip-audit
    if state["project_type"] == "python":
        req_file = scan_dir / "requirements.txt"
        if req_file.exists():
            try:
                result = subprocess.run(
                    ["pip-audit", "-r", str(req_file), "--format=json"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    for vuln in data.get("vulnerabilities", []):
                        v = Vulnerability(
                            id=f"DEP-{vuln['id']}",
                            type="Vulnerable Dependency",
                            severity="HIGH" if vuln.get("fix_versions") else "MEDIUM",
                            file_path=str(req_file),
                            line_number=0,
                            code_snippet=f"{vuln['name']}=={vuln['version']}",
                            description=vuln["description"],
                            fix_suggestion=f"Update to {vuln.get('fix_versions', ['latest'])[0]}",
                            confidence="HIGH"
                        )
                        vulnerabilities.append(v)
            except Exception as e:
                pass
    
    # JavaScript/TypeScript: npm audit
    elif state["project_type"] in ["javascript", "typescript"]:
        package_json = scan_dir / "package.json"
        if package_json.exists():
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=scan_dir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    for vuln_id, vuln in data.get("vulnerabilities", {}).items():
                        v = Vulnerability(
                            id=f"DEP-{vuln_id}",
                            type="Vulnerable Dependency",
                            severity=vuln["severity"].upper(),
                            file_path=str(package_json),
                            line_number=0,
                            code_snippet=vuln_id,
                            description=vuln.get("via", [{}])[0].get("title", ""),
                            confidence="HIGH"
                        )
                        vulnerabilities.append(v)
            except Exception as e:
                pass
    
    return {
        **state,
        "vulnerabilities": vulnerabilities,
        "scan_stage": "dependency_scan_complete"
    }
```

#### D. Report Generator (app/agents/report_generator.py)
```python
from collections import Counter
from app.core.state import ScanState

async def report_generator_agent(state: ScanState) -> ScanState:
    """
    Generate final scan report
    """
    vulns = state["vulnerabilities"]
    
    # Group by severity
    severity_counts = Counter(v.severity for v in vulns)
    
    # Group by type
    type_counts = Counter(v.type for v in vulns)
    
    # Calculate risk score
    risk_score = (
        severity_counts["CRITICAL"] * 10 +
        severity_counts["HIGH"] * 7 +
        severity_counts["MEDIUM"] * 4 +
        severity_counts["LOW"] * 1
    )
    
    report = {
        "scan_id": state["scan_id"],
        "summary": {
            "total_vulnerabilities": len(vulns),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "info": severity_counts["INFO"],
            "risk_score": risk_score,
            "files_scanned": state["stats"]["total_files"]
        },
        "findings_by_type": dict(type_counts),
        "vulnerabilities": [
            {
                "id": v.id,
                "type": v.type,
                "severity": v.severity,
                "file": v.file_path,
                "line": v.line_number,
                "description": v.description,
                "fix": v.fix_suggestion
            }
            for v in sorted(vulns, key=lambda x: (
                {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[x.severity],
                -x.cvss_score if x.cvss_score else 0
            ), reverse=True)
        ]
    }
    
    return {
        **state,
        "scan_stage": "complete",
        "stats": {
            **state["stats"],
            "report": report
        }
    }
```

### Step 5: Build the Workflow (app/agents/orchestrator.py)
```python
from langgraph.graph import StateGraph, END
from app.core.state import ScanState
from app.agents.code_parser import parse_files_agent
from app.agents.sast_scanner import sast_scanner_agent
from app.agents.dependency_scanner import dependency_scanner_agent
from app.agents.report_generator import report_generator_agent

def should_run_deep_scan(state: ScanState) -> str:
    """Conditional: run deep scan if many vulns found"""
    if len(state["vulnerabilities"]) > 10:
        return "deep_scan"
    return "report"

def build_scan_workflow():
    """Build the complete scanning workflow"""
    
    workflow = StateGraph(ScanState)
    
    # Add all agent nodes
    workflow.add_node("parse_files", parse_files_agent)
    workflow.add_node("sast_scan", sast_scanner_agent)
    workflow.add_node("dependency_scan", dependency_scanner_agent)
    workflow.add_node("generate_report", report_generator_agent)
    
    # Define the flow
    workflow.set_entry_point("parse_files")
    workflow.add_edge("parse_files", "sast_scan")
    workflow.add_edge("sast_scan", "dependency_scan")
    workflow.add_edge("dependency_scan", "generate_report")
    workflow.add_edge("generate_report", END)
    
    return workflow.compile()

# Create the app
scan_app = build_scan_workflow()
```

### Step 6: FastAPI Integration (app/api/main.py)
```python
from fastapi import FastAPI, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse
import uuid
import time
from pathlib import Path
import shutil

from app.agents.orchestrator import scan_app
from app.core.state import ScanState

app = FastAPI(title="SentryAgent API")

# In-memory store (use Redis in production)
scans_db = {}

@app.post("/api/scan")
async def create_scan(
    files: list[UploadFile],
    project_type: str,
    background_tasks: BackgroundTasks
):
    """
    Upload code and start vulnerability scan
    """
    scan_id = str(uuid.uuid4())
    
    # Save uploaded files
    upload_dir = Path(f"/tmp/scans/{scan_id}")
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    for file in files:
        file_path = upload_dir / file.filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with file_path.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    
    # Initialize scan state
    initial_state: ScanState = {
        "scan_id": scan_id,
        "uploaded_files": [f.filename for f in files],
        "project_type": project_type,
        "files_to_scan": [],
        "current_file": None,
        "vulnerabilities": [],
        "errors": [],
        "scan_stage": "initialized",
        "start_time": time.time(),
        "stats": {}
    }
    
    # Store initial state
    scans_db[scan_id] = {
        "status": "running",
        "state": initial_state
    }
    
    # Run scan in background
    background_tasks.add_task(run_scan, scan_id, initial_state)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan initiated successfully"
    }

async def run_scan(scan_id: str, initial_state: ScanState):
    """Background task to run the scan"""
    try:
        # Run the LangGraph workflow
        final_state = await scan_app.ainvoke(initial_state)
        
        scans_db[scan_id] = {
            "status": "complete",
            "state": final_state,
            "report": final_state["stats"].get("report")
        }
    except Exception as e:
        scans_db[scan_id] = {
            "status": "error",
            "error": str(e)
        }

@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and results"""
    if scan_id not in scans_db:
        return JSONResponse(
            status_code=404,
            content={"error": "Scan not found"}
        )
    
    scan_data = scans_db[scan_id]
    
    if scan_data["status"] == "complete":
        return {
            "scan_id": scan_id,
            "status": "complete",
            "report": scan_data["report"]
        }
    elif scan_data["status"] == "running":
        return {
            "scan_id": scan_id,
            "status": "running",
            "stage": scan_data["state"]["scan_stage"]
        }
    else:
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": scan_data["error"]
        }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
```

### Step 7: Docker Setup (docker-compose.yml)
```yaml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - LANGCHAIN_API_KEY=${LANGCHAIN_API_KEY}
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./app:/app/app
      - /tmp/scans:/tmp/scans
    depends_on:
      - redis
      - postgres
    command: uvicorn app.api.main:app --host 0.0.0.0 --reload

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app
    environment:
      - REACT_APP_API_URL=http://localhost:8000

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=sentryagent
      - POSTGRES_USER=sentry
      - POSTGRES_PASSWORD=secret
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Step 8: Environment Setup (.env)
```bash
# API Keys
ANTHROPIC_API_KEY=your_key_here
LANGCHAIN_API_KEY=your_langsmith_key

# Database
DATABASE_URL=postgresql://sentry:secret@postgres:5432/sentryagent
REDIS_URL=redis://redis:6379

# Security Tools
SEMGREP_APP_TOKEN=your_token  # Optional
```

### Step 9: Run the Application
```bash
# Start services
docker-compose up -d

# Check logs
docker-compose logs -f backend

# Test the API
curl -X POST http://localhost:8000/api/scan \
  -F "files=@test.py" \
  -F "project_type=python"
```

---

## Testing Your Agents

### Create test files (tests/test_agents.py)
```python
import pytest
from app.agents.orchestrator import scan_app
from app.core.state import ScanState

@pytest.mark.asyncio
async def test_full_scan_workflow():
    """Test complete scan workflow"""
    initial_state: ScanState = {
        "scan_id": "test-123",
        "uploaded_files": ["test.py"],
        "project_type": "python",
        "files_to_scan": [],
        "current_file": None,
        "vulnerabilities": [],
        "errors": [],
        "scan_stage": "initialized",
        "start_time": 0.0,
        "stats": {}
    }
    
    result = await scan_app.ainvoke(initial_state)
    
    assert result["scan_stage"] == "complete"
    assert "report" in result["stats"]
    assert isinstance(result["vulnerabilities"], list)
```

---

## Next Steps

1. **Add More Scanners**
   - Secret detection (TruffleHog)
   - License compliance
   - Code quality (complexity, maintainability)

2. **Enhance AI Features**
   - Use Claude to explain vulnerabilities
   - Generate contextual fix suggestions
   - Prioritize based on business context

3. **Build Frontend Dashboard**
   - Real-time scan progress
   - Interactive vulnerability explorer
   - Trend charts

4. **Add Integrations**
   - GitHub Actions
   - GitLab CI
   - Slack notifications
   - Jira ticket creation

Need help with any specific part? Let me know!
