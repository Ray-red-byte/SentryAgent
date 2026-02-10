# SentryAgent - AI-Powered Security Scanner

**Version:** 0.4.0-langgraph  
**Status:** ✅ Production Ready with LangGraph Orchestration

## Overview

SentryAgent is an AI-powered vulnerability scanning tool for developers ("vibe coders"). It uses **LangGraph** for intelligent workflow orchestration, providing:

- 🔍 **Smart Scanning** - Conditional deep analysis based on risk scores
- 🧠 **Organizational Memory** - Learns from past vulnerabilities (RAG)
- ⚡ **Fast & Efficient** - Only audits high-risk files
- 🎯 **Prioritized Results** - Sorted by severity and exploitability
- 🔄 **State Management** - Resume interrupted scans
- 📊 **Rich Reports** - Actionable insights with fix suggestions

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Server

```bash
# Development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production (Docker)
docker-compose up
```

### 3. Access the API

- **Swagger UI:** http://localhost:8000/docs
- **Legacy API (v1):** `/scan`, `/audit`, `/fix`
- **LangGraph API (v2):** `/v2/scan`, `/v2/audit`, `/v2/fix`

### 4. Run Your First Scan

```bash
# Upload codebase
curl -X POST "http://localhost:8000/v2/upload" \
  -F "file=@your_code.zip"

# Get session_id from response, then scan
curl -X POST "http://localhost:8000/v2/scan" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID"}'
```

## Architecture

### LangGraph Workflow

```
START → Discover Files → Parse & Scan → Load Memory
                                            ↓
                                    [High-risk files?]
                                      ↙         ↘
                                   YES          NO
                                    ↓            ↓
                              Deep Audit    Generate Report
                                    ↓
                            [Vulnerabilities?]
                              ↙         ↘
                           YES          NO
                            ↓            ↓
                       Prioritize   Generate Report
                            ↓
                      Generate Report → END
```

### Key Components

- **State Definitions** (`app/workflows/state.py`) - Typed state for workflows
- **Workflow Nodes** (`app/workflows/nodes.py`) - Pure functions for each step
- **Workflow Graphs** (`app/workflows/graphs.py`) - LangGraph orchestration
- **API Routes** (`app/api/routes_langgraph.py`) - FastAPI endpoints

## Features

### ✅ Implemented

- [x] LangGraph workflow orchestration
- [x] Conditional branching (skip unnecessary audits)
- [x] Organizational memory (RAG)
- [x] Risk-based prioritization
- [x] Gemini cache integration
- [x] Tree-sitter code parsing
- [x] Multi-file scanning
- [x] PDF report generation
- [x] Backward compatibility (v1 API still works)

### 🚧 In Progress

- [ ] Parallel file scanning
- [ ] Checkpointing for long scans
- [ ] LangSmith observability
- [ ] Custom rule injection

### 📋 Planned

- [ ] Multi-language support (JS, TS, Java, Go)
- [ ] IDE integration (VS Code, IntelliJ)
- [ ] CI/CD integration (GitHub Actions)
- [ ] Team collaboration features
- [ ] Compliance reporting (OWASP, PCI-DSS)

## API Endpoints

### V2 (LangGraph) - Recommended

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v2/upload` | POST | Upload codebase (zip) |
| `/v2/scan` | POST | Full scan with LangGraph |
| `/v2/audit` | POST | Audit single file |
| `/v2/fix` | POST | Generate security patches |
| `/v2/chat` | POST | Interactive code chat |
| `/v2/apply` | POST | Apply fixes to files |
| `/v2/explain` | POST | Explain vulnerabilities |
| `/v2/export` | POST | Export PDF report |
| `/v2/health` | GET | Health check |

### V1 (Legacy) - Deprecated

Same endpoints without `/v2` prefix. Still functional for backward compatibility.

## Configuration

### Scan Configuration

```python
config = {
    "risk_threshold": 5,      # Files with risk_score >= 5 get deep audit
    "max_audit_files": 10     # Limit deep audits to top N files
}
```

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/sentry
REDIS_URL=redis://localhost:6379

# AI
GOOGLE_API_KEY=your_gemini_api_key

# Security
SECRET_KEY=your_secret_key
```

## Documentation

- **[Quick Start Guide](./QUICKSTART_LANGGRAPH.md)** - Get started in 5 minutes
- **[LangGraph Refactoring Guide](./LANGGRAPH_REFACTORING.md)** - Deep dive into architecture
- **[Improvement Guideline](./improvement_guide/sentry_agent_review.md)** - Product roadmap

## Development

### Project Structure

```
SentryAgent/
├── app/
│   ├── workflows/          # LangGraph workflows ⭐ NEW
│   │   ├── state.py        # State definitions
│   │   ├── nodes.py        # Workflow nodes
│   │   └── graphs.py       # Workflow orchestration
│   ├── api/
│   │   ├── routes.py       # Legacy routes (v1)
│   │   └── routes_langgraph.py  # LangGraph routes (v2) ⭐ NEW
│   ├── agent/              # AI agents
│   ├── tools/              # Code parsers
│   ├── core/               # Core utilities
│   ├── databases/          # DB connections
│   ├── memory/             # RAG & caching
│   └── main.py             # FastAPI app
├── frontend/               # React UI
├── requirements.txt        # Python dependencies
└── docker-compose.yml      # Docker setup
```

### Running Tests

```bash
# Unit tests
pytest tests/

# Integration tests
pytest tests/integration/

# Test specific workflow
pytest tests/workflows/test_scan_workflow.py
```

### Adding a New Workflow Node

```python
# app/workflows/nodes.py
def my_new_node(state: ScanState) -> ScanState:
    """
    Description of what this node does.
    """
    print("🔧 [MY_NODE] Processing...")
    
    # Your logic here
    result = process_something(state)
    
    return {
        **state,
        "new_field": result,
        "current_stage": "my_stage"
    }
```

Then add to workflow:

```python
# app/workflows/graphs.py
workflow.add_node("my_node", my_new_node)
workflow.add_edge("previous_node", "my_node")
```

## Migration from V1 to V2

### For API Users

```javascript
// Old (v1)
fetch('/scan', { method: 'POST', body: JSON.stringify({ session_id }) })

// New (v2)
fetch('/v2/scan', { method: 'POST', body: JSON.stringify({ session_id }) })
```

### For Developers

See [LANGGRAPH_REFACTORING.md](./LANGGRAPH_REFACTORING.md) for detailed migration guide.

## Performance

### Before (v1)
- ❌ Audits all files sequentially
- ❌ No state management
- ❌ Can't resume interrupted scans
- ⏱️ ~5-10 minutes for 100 files

### After (v2)
- ✅ Only audits high-risk files
- ✅ State-driven workflow
- ✅ Can resume scans (future)
- ⏱️ ~1-3 minutes for 100 files (with risk_threshold=5)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Tech Stack

- **Backend:** FastAPI, Python 3.11+
- **Workflow:** LangGraph, LangChain
- **AI:** Google Gemini (Claude support coming)
- **Database:** PostgreSQL, Redis
- **Code Analysis:** Tree-sitter
- **Vector DB:** ChromaDB (RAG)
- **Frontend:** React, TypeScript

## License

MIT License - See [LICENSE](./LICENSE) for details

## Support

- **Documentation:** See [docs](./LANGGRAPH_REFACTORING.md)
- **Issues:** [GitHub Issues](https://github.com/your-org/sentry-agent/issues)
- **Discussions:** [GitHub Discussions](https://github.com/your-org/sentry-agent/discussions)

## Acknowledgments

- Built with [LangGraph](https://github.com/langchain-ai/langgraph)
- Inspired by [Semgrep](https://semgrep.dev/), [Snyk](https://snyk.io/), and [CodeQL](https://codeql.github.com/)
- Improvement guideline by AI security experts

---

**Made with ❤️ for vibe coders**

🚀 **Start scanning:** `curl -X POST http://localhost:8000/v2/scan`
