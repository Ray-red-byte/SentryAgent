"""
app/knowledge/security.py

This module defines the SecurityKnowledgeBase class, which serves as a long-term organizational memory 
for cybersecurity knowledge. It uses ChromaDB to store and 
retrieve information about 
 1. vulnerabilities
 2. attack patterns
 3. mitigation strategies.
"""

KNOWLEDGE_ENTRIES = [
    # ── OWASP A01 — Injection ─────────────────────────────────────────
    {
        "type": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A01:2021",
        "severity": "CRITICAL",
        "description": (
            "SQL Injection occurs when user-controlled input is concatenated directly "
            "into SQL queries without parameterization. An attacker can manipulate the "
            "query to dump, modify, or delete database contents, bypass authentication, "
            "or execute OS commands via DB stored procedures."
        ),
        "detection": (
            "Look for: f-strings in SQL queries, string concatenation with user input, "
            "execute() calls with % formatting, raw string interpolation in ORM queries."
        ),
        "fix": (
            "Always use parameterized queries or ORM methods:\n"
            "BAD:  cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "GOOD: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
            "GOOD (SQLAlchemy): db.query(User).filter(User.id == user_id).first()\n"
            "Never format SQL with user input. Use allowlists for dynamic column names."
        ),
    },
    {
        "type": "Command Injection",
        "cwe": "CWE-78",
        "owasp": "A01:2021",
        "severity": "CRITICAL",
        "description": (
            "Command Injection allows an attacker to execute arbitrary OS commands "
            "on the host server by injecting shell metacharacters into input that is "
            "passed to os.system(), subprocess.call(shell=True), or similar functions."
        ),
        "detection": (
            "Look for: os.system(), os.popen(), subprocess.run/call/Popen with shell=True, "
            "eval(), exec() with user-controlled strings."
        ),
        "fix": (
            "BAD:  os.system(f'ls {user_input}')\n"
            "GOOD: subprocess.run(['ls', user_input], shell=False, check=True)\n"
            "Never pass user input to shell=True. Use shell=False with a list of args. "
            "Validate and allowlist all inputs that interact with the OS."
        ),
    },
    {
        "type": "Code Injection",
        "cwe": "CWE-94",
        "owasp": "A01:2021",
        "severity": "CRITICAL",
        "description": (
            "Code injection allows attackers to inject and execute arbitrary code "
            "via eval(), exec(), or pickle.loads() on untrusted data."
        ),
        "detection": "Look for eval(), exec(), compile(), pickle.loads(), marshal.loads() with untrusted input.",
        "fix": (
            "BAD:  result = eval(user_code)\n"
            "GOOD: Use ast.literal_eval() for safe evaluation of literals only.\n"
            "Never deserialize untrusted pickle data — use JSON instead.\n"
            "If dynamic code execution is truly required, isolate it in a sandboxed subprocess."
        ),
    },
    # ── OWASP A02 — Broken Authentication ────────────────────────────
    {
        "type": "Broken Authentication",
        "cwe": "CWE-287",
        "owasp": "A02:2021",
        "severity": "CRITICAL",
        "description": (
            "Authentication flaws allow attackers to compromise passwords, keys, or "
            "session tokens. Common issues: hardcoded credentials, weak JWT secrets, "
            "missing token expiry, tokens stored in plaintext logs."
        ),
        "detection": (
            "Look for: hardcoded password strings, JWT secrets in source code, "
            "missing token validation, always-true authentication stubs, "
            "comparing password hashes insecurely."
        ),
        "fix": (
            "Use strong randomly generated secrets (32+ bytes) from environment variables.\n"
            "Always validate JWT tokens cryptographically (algorithm, signature, expiry).\n"
            "Store passwords with bcrypt/argon2, never MD5/SHA1.\n"
            "Example JWT validation:\n"
            "  payload = jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "  # This raises ExpiredSignatureError or InvalidTokenError automatically."
        ),
    },
    {
        "type": "Hardcoded Credentials",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "severity": "HIGH",
        "description": (
            "Hardcoded credentials in source code can be extracted by anyone with "
            "repository access and are nearly impossible to rotate without a code deploy."
        ),
        "detection": "Look for: password =, secret =, api_key = assigned to string literals in source files.",
        "fix": (
            "Load all credentials from environment variables:\n"
            "  SECRET = os.environ['SECRET_KEY']  # raises KeyError if missing — good!\n"
            "  SECRET = os.getenv('SECRET_KEY')   # returns None — add a None check\n"
            "Use python-dotenv for local dev. Never commit .env to version control."
        ),
    },
    # ── OWASP A03 — Path Traversal ────────────────────────────────────
    {
        "type": "Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A03:2021",
        "severity": "CRITICAL",
        "description": (
            "Path traversal allows an attacker to access files outside the intended "
            "directory by injecting ../ sequences. In file upload/download endpoints, "
            "this can expose /etc/passwd, private keys, or allow overwriting system files."
        ),
        "detection": (
            "Look for: open(user_path), os.path.join(base, user_input) without resolve(), "
            "zipfile.extractall() without member path validation (ZipSlip)."
        ),
        "fix": (
            "Always resolve and validate paths:\n"
            "  safe_path = (base_dir / user_input).resolve()\n"
            "  if not str(safe_path).startswith(str(base_dir.resolve()) + os.sep):\n"
            "      raise HTTPException(400, 'Invalid path')\n"
            "For ZipSlip: validate each zip member path before extraction."
        ),
    },
    # ── OWASP A04 — Insecure Design / IDOR ───────────────────────────
    {
        "type": "Insecure Direct Object Reference (IDOR)",
        "cwe": "CWE-639",
        "owasp": "A01:2021",
        "severity": "HIGH",
        "description": (
            "IDOR occurs when an application uses user-supplied input (like an ID) "
            "to access objects without verifying the caller is authorized to access them."
        ),
        "detection": "Look for: endpoints that fetch records by ID without checking if the ID belongs to the current user.",
        "fix": (
            "Always scope queries to the authenticated user:\n"
            "  BAD:  record = db.query(Record).filter(Record.id == record_id).first()\n"
            "  GOOD: record = db.query(Record).filter(\n"
            "            Record.id == record_id,\n"
            "            Record.owner_id == current_user['id']\n"
            "        ).first()"
        ),
    },
    # ── OWASP A05 — Security Misconfiguration ─────────────────────────
    {
        "type": "CORS Misconfiguration",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "severity": "HIGH",
        "description": (
            "Using allow_origins=['*'] with allow_credentials=True is invalid per the "
            "CORS spec and allows any website to make credentialed requests to your API "
            "using the victim's browser cookies/tokens."
        ),
        "detection": "Look for: allow_origins=['*'] combined with allow_credentials=True in CORS middleware.",
        "fix": (
            "Use an explicit allowlist:\n"
            "  origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')\n"
            "  app.add_middleware(CORSMiddleware,\n"
            "      allow_origins=origins, allow_credentials=True,\n"
            "      allow_methods=['GET','POST'], allow_headers=['Authorization','Content-Type'])"
        ),
    },
    # ── OWASP A06 — Vulnerable and Outdated Components ────────────────
    {
        "type": "Insecure Deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "severity": "CRITICAL",
        "description": (
            "Deserializing untrusted data with pickle, marshal, or yaml.load() can "
            "lead to arbitrary code execution because these formats support object "
            "instantiation during deserialization."
        ),
        "detection": "Look for: pickle.loads(), yaml.load() (not safe_load), marshal.loads() with external data.",
        "fix": (
            "BAD:  data = pickle.loads(user_bytes)\n"
            "GOOD: data = json.loads(user_string)  # JSON cannot execute code\n"
            "For YAML: always use yaml.safe_load() — never yaml.load().\n"
            "Never deserialize data from untrusted sources with pickle."
        ),
    },
    # ── OWASP A07 — Identification & Authentication Failures ──────────
    {
        "type": "Missing Authentication on Sensitive Endpoint",
        "cwe": "CWE-306",
        "owasp": "A07:2021",
        "severity": "CRITICAL",
        "description": (
            "API endpoints that modify data, expose PII, or trigger expensive operations "
            "must require authentication. Unauthenticated endpoints are trivially abused."
        ),
        "detection": "Look for: POST/PUT/DELETE route handlers that don't have Depends(get_current_user) or equivalent.",
        "fix": (
            "Add authentication dependency to every sensitive route:\n"
            "  @router.post('/sensitive', dependencies=[Depends(get_current_user)])\n"
            "  async def sensitive_endpoint(request: Request): ..."
        ),
    },
    # ── OWASP A08 — Sensitive Data Exposure ──────────────────────────
    {
        "type": "Sensitive Data Exposure in Error Responses",
        "cwe": "CWE-209",
        "owasp": "A09:2021",
        "severity": "MEDIUM",
        "description": (
            "Returning raw exception messages in HTTP error responses leaks internal "
            "information: stack traces, file paths, SQL queries, library versions — "
            "all useful to an attacker for reconnaissance."
        ),
        "detection": "Look for: raise HTTPException(detail=str(e)) — this sends internal exception messages to users.",
        "fix": (
            "Log internally, return generic message:\n"
            "  except Exception as e:\n"
            "      logger.exception('Internal error in endpoint: %s', e)\n"
            "      raise HTTPException(status_code=500, detail='An internal error occurred.')"
        ),
    },
    # ── OWASP A09 — Logging Failures ─────────────────────────────────
    {
        "type": "Insufficient Logging",
        "cwe": "CWE-778",
        "owasp": "A09:2021",
        "severity": "LOW",
        "description": (
            "Without structured security logs for authentication failures, "
            "authorization errors, and input validation failures, attacks go undetected."
        ),
        "detection": "Look for: authentication or authorization code with no logging on failure paths.",
        "fix": (
            "Log all security-relevant events:\n"
            "  logger.warning('Failed login for user %s from IP %s', username, client_ip)\n"
            "  logger.warning('Authorization denied: user %s tried to access %s', user_id, resource)\n"
            "Use structured logging (JSON) in production for SIEM ingestion."
        ),
    },
    # ── OWASP A10 — SSRF ─────────────────────────────────────────────
    {
        "type": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "severity": "HIGH",
        "description": (
            "SSRF allows attackers to make the server fetch arbitrary URLs, "
            "potentially reaching internal services (AWS metadata, Redis, DB) "
            "that are not exposed externally."
        ),
        "detection": "Look for: requests.get(user_url), httpx.get(user_url) without URL validation.",
        "fix": (
            "Validate URLs against an allowlist of permitted domains/IPs:\n"
            "  from urllib.parse import urlparse\n"
            "  parsed = urlparse(url)\n"
            "  if parsed.hostname not in ALLOWED_HOSTS:\n"
            "      raise HTTPException(400, 'URL not permitted')\n"
            "Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x) entirely."
        ),
    },
    # ── Upload Security ───────────────────────────────────────────────
    {
        "type": "Unrestricted File Upload",
        "cwe": "CWE-434",
        "owasp": "A01:2021",
        "severity": "HIGH",
        "description": (
            "Accepting file uploads without validating type, size, or content "
            "allows attackers to upload server-side scripts, DoS via large files, "
            "or overwrite critical files (combined with path traversal)."
        ),
        "detection": "Look for: file upload handlers with no size limit, no type check, no content validation.",
        "fix": (
            "Validate type, size, and content:\n"
            "  MAX_SIZE = 50 * 1024 * 1024  # 50 MB\n"
            "  if not file.filename.endswith('.zip'): raise HTTPException(400, 'Only .zip allowed')\n"
            "  content = await file.read(MAX_SIZE + 1)\n"
            "  if len(content) > MAX_SIZE: raise HTTPException(413, 'File too large')\n"
            "Store uploads in an isolated directory, never executable paths."
        ),
    },
    # ── Rate Limiting / DoS ───────────────────────────────────────────
    {
        "type": "Missing Rate Limiting",
        "cwe": "CWE-770",
        "owasp": "A05:2021",
        "severity": "MEDIUM",
        "description": (
            "Without rate limiting, brute-force attacks against login endpoints, "
            "or resource exhaustion via expensive AI/scan endpoints are trivial."
        ),
        "detection": "Look for: authentication or AI-triggered endpoints with no rate limiting middleware.",
        "fix": (
            "Add rate limiting with slowapi or similar:\n"
            "  from slowapi import Limiter\n"
            "  limiter = Limiter(key_func=get_remote_address)\n"
            "  @app.post('/login')\n"
            "  @limiter.limit('5/minute')\n"
            "  async def login(request: Request): ..."
        ),
    },
    # ── FastAPI/Python Specific ────────────────────────────────────────
    {
        "type": "UUID / Session ID Validation",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "severity": "HIGH",
        "description": (
            "Using unvalidated session IDs in filesystem paths allows attackers "
            "to inject path traversal sequences or access other users' sessions."
        ),
        "detection": "Look for: os.path.join(base, session_id) without validating session_id is a UUID.",
        "fix": (
            "Validate session_id against UUID format before use:\n"
            "  import re\n"
            "  UUID4_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')\n"
            "  if not UUID4_RE.match(session_id): raise HTTPException(400, 'Invalid session')"
        ),
    },
]
