"""
app/knowledge/security.py

Curated OWASP Top 10 + CWE cybersecurity knowledge entries used to pre-seed
the ChromaDB vector store. Each entry is a dict with keys:
    type, cwe, owasp, severity, description, detection, fix
"""

KNOWLEDGE_ENTRIES = [
    {
        "type": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "severity": "CRITICAL",
        "description": (
            "User-controlled input is concatenated directly into a SQL query without "
            "parameterisation, allowing an attacker to alter the query logic, dump data, "
            "or execute admin operations."
        ),
        "detection": (
            "Look for string formatting (f-string, %-format, .format()) or concatenation "
            "used to build SQL strings. Trigger: cursor.execute(f'... {var} ...') or "
            "query = 'SELECT ... WHERE x = ' + user_input."
        ),
        "fix": (
            "Replace string interpolation with parameterised queries:\n"
            "  # BAD\n"
            "  cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "  # GOOD\n"
            "  cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
            "For ORMs use query builder methods (filter(), where()) instead of raw()."
        ),
    },
    {
        "type": "Command Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "severity": "CRITICAL",
        "description": (
            "User-supplied data flows into a shell command (os.system, subprocess with "
            "shell=True, eval, exec) allowing arbitrary OS command execution."
        ),
        "detection": (
            "Search for: os.system(, subprocess.run(... shell=True, eval(, exec(. "
            "Check whether any argument contains user-controlled data."
        ),
        "fix": (
            "Use subprocess with a list of arguments and shell=False:\n"
            "  # BAD\n"
            "  os.system(f'convert {filename}')\n"
            "  # GOOD\n"
            "  subprocess.run(['convert', filename], shell=False, check=True)\n"
            "Never pass user input to eval() or exec()."
        ),
    },
    {
        "type": "Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "severity": "HIGH",
        "description": (
            "User-controlled path components (e.g. '../../../etc/passwd') allow reading "
            "or writing files outside the intended directory."
        ),
        "detection": (
            "Look for open(), os.path.join(), or file operations where the path argument "
            "includes a request parameter without normalisation or prefix checking."
        ),
        "fix": (
            "Resolve and validate the path before use:\n"
            "  import os\n"
            "  BASE = '/var/app/uploads'\n"
            "  safe = os.path.realpath(os.path.join(BASE, user_filename))\n"
            "  if not safe.startswith(BASE + os.sep):\n"
            "      raise ValueError('Path traversal detected')\n"
            "  with open(safe) as f: ..."
        ),
    },
    {
        "type": "Broken Authentication",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "severity": "CRITICAL",
        "description": (
            "Authentication mechanisms are missing, bypassable, or improperly implemented — "
            "e.g. hardcoded credentials, missing token validation, or predictable session IDs."
        ),
        "detection": (
            "Search for: hardcoded passwords, missing @login_required / Depends(get_current_user), "
            "JWT verification skipped (verify=False), or compare_digest not used for token comparison."
        ),
        "fix": (
            "Enforce authentication on every protected route:\n"
            "  # FastAPI example\n"
            "  @router.get('/admin')\n"
            "  async def admin(user=Depends(get_current_user)):\n"
            "      ...\n"
            "Use hmac.compare_digest() for constant-time token comparison. "
            "Store passwords with bcrypt/argon2, never plaintext or MD5/SHA1."
        ),
    },
    {
        "type": "Broken Access Control",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "severity": "HIGH",
        "description": (
            "The application does not verify that the authenticated user is authorised to "
            "access the requested resource, enabling Insecure Direct Object Reference (IDOR) "
            "or privilege escalation attacks."
        ),
        "detection": (
            "Check whether object lookups use only the user-supplied ID without also "
            "filtering by the authenticated user's ID or role. E.g. "
            "db.query(Order).filter(Order.id == order_id) without owner check."
        ),
        "fix": (
            "Always scope queries to the authenticated principal:\n"
            "  # BAD — any user can read any order\n"
            "  order = db.query(Order).filter(Order.id == order_id).first()\n"
            "  # GOOD — scope to authenticated user\n"
            "  order = db.query(Order).filter(\n"
            "      Order.id == order_id,\n"
            "      Order.user_id == current_user.id\n"
            "  ).first()\n"
            "  if not order:\n"
            "      raise HTTPException(status_code=404)"
        ),
    },
    {
        "type": "Sensitive Data Exposure",
        "cwe": "CWE-312",
        "owasp": "A02:2021",
        "severity": "HIGH",
        "description": (
            "Sensitive data (passwords, tokens, PII, credit card numbers) is stored or "
            "transmitted in cleartext, logged, or included in API responses."
        ),
        "detection": (
            "Search for password/secret fields returned in API responses, logged with "
            "logger.info/print, or stored without hashing. Look for 'password' in response "
            "serialisers or SELECT * queries whose result is returned directly."
        ),
        "fix": (
            "Exclude secrets from serialisation and logs:\n"
            "  class UserOut(BaseModel):\n"
            "      id: int\n"
            "      email: str\n"
            "      # no 'password' field\n"
            "Hash passwords with bcrypt before storage. "
            "Use response_model=UserOut in FastAPI to strip sensitive fields automatically."
        ),
    },
    {
        "type": "Hardcoded Secrets",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "severity": "CRITICAL",
        "description": (
            "Secret keys, API tokens, database passwords, or cryptographic keys are "
            "embedded directly in source code rather than read from environment variables "
            "or a secrets manager."
        ),
        "detection": (
            "Grep for patterns like: SECRET_KEY = 'abc', password = 'pass', "
            "API_KEY = 'sk-...', token = 'Bearer xyz' that are string literals rather "
            "than os.getenv() calls."
        ),
        "fix": (
            "Move secrets to environment variables:\n"
            "  # BAD\n"
            "  SECRET_KEY = 'super_secret_123'\n"
            "  # GOOD\n"
            "  import os\n"
            "  SECRET_KEY = os.environ['SECRET_KEY']  # raises if missing — intentional\n"
            "Use python-dotenv in dev and a secrets manager (Vault, AWS SSM) in prod."
        ),
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "severity": "HIGH",
        "description": (
            "User-supplied data is rendered in HTML responses without escaping, allowing "
            "injection of malicious scripts that execute in the victim's browser."
        ),
        "detection": (
            "In Jinja2 templates look for {{ var | safe }} or Markup(user_input). "
            "In Python look for HTMLResponse(content=f'<p>{user_input}</p>') where "
            "user_input is not escaped."
        ),
        "fix": (
            "Always escape untrusted data before rendering in HTML:\n"
            "  from markupsafe import escape\n"
            "  safe_name = escape(user_input)\n"
            "  return HTMLResponse(f'<p>{safe_name}</p>')\n"
            "Prefer Jinja2 auto-escaping (enabled by default) and never use | safe "
            "on user-controlled values."
        ),
    },
    {
        "type": "Insecure Deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "severity": "CRITICAL",
        "description": (
            "Untrusted data is deserialised using pickle, yaml.load, marshal, or similar "
            "unsafe deserializers, enabling remote code execution."
        ),
        "detection": (
            "Search for: pickle.loads(, yaml.load( (without Loader=yaml.SafeLoader), "
            "marshal.loads(, shelve.open( where the source data originates from user input "
            "or network data."
        ),
        "fix": (
            "Use safe alternatives:\n"
            "  # BAD\n"
            "  obj = pickle.loads(request.body)\n"
            "  data = yaml.load(user_string)\n"
            "  # GOOD\n"
            "  import json\n"
            "  data = json.loads(request.body)  # for structured data\n"
            "  data = yaml.safe_load(user_string)  # for YAML\n"
            "Never deserialise pickle/marshal data from untrusted sources."
        ),
    },
    {
        "type": "Security Misconfiguration",
        "cwe": "CWE-16",
        "owasp": "A05:2021",
        "severity": "MEDIUM",
        "description": (
            "Debug mode is enabled in production, CORS is overly permissive (allow_origins=['*']), "
            "detailed error tracebacks are exposed to clients, or default credentials are unchanged."
        ),
        "detection": (
            "Look for: DEBUG=True, allow_origins=['*'] in CORSMiddleware, "
            "app.run(debug=True), expose_headers with sensitive headers, "
            "or error handlers that return stack traces."
        ),
        "fix": (
            "Harden configuration for production:\n"
            "  # CORS — restrict to known origins\n"
            "  app.add_middleware(CORSMiddleware,\n"
            "      allow_origins=['https://app.example.com'],\n"
            "      allow_credentials=True,\n"
            "      allow_methods=['GET', 'POST'],\n"
            "  )\n"
            "  # Disable debug in prod\n"
            "  DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'"
        ),
    },
    {
        "type": "Rate Limiting Missing",
        "cwe": "CWE-400",
        "owasp": "A05:2021",
        "severity": "MEDIUM",
        "description": (
            "Authentication endpoints or expensive operations lack rate limiting, "
            "enabling brute-force attacks, credential stuffing, or denial-of-service."
        ),
        "detection": (
            "Look for login, password-reset, or token endpoints that have no "
            "slowapi @limiter.limit, no Redis-backed counter, and no account lockout logic."
        ),
        "fix": (
            "Add rate limiting with slowapi or a Redis counter:\n"
            "  from slowapi import Limiter\n"
            "  from slowapi.util import get_remote_address\n"
            "  limiter = Limiter(key_func=get_remote_address)\n\n"
            "  @router.post('/login')\n"
            "  @limiter.limit('5/minute')\n"
            "  async def login(request: Request, ...):\n"
            "      ..."
        ),
    },
    {
        "type": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "severity": "HIGH",
        "description": (
            "The application fetches a remote URL supplied by the user without validating "
            "the target, allowing attackers to reach internal services (metadata APIs, "
            "Redis, internal HTTP endpoints)."
        ),
        "detection": (
            "Look for: requests.get(user_url), httpx.get(url) where url comes from "
            "request parameters, with no allowlist validation of the scheme or host."
        ),
        "fix": (
            "Validate the URL against an allowlist before fetching:\n"
            "  from urllib.parse import urlparse\n"
            "  ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n"
            "  parsed = urlparse(user_url)\n"
            "  if parsed.scheme not in ('http', 'https') or parsed.hostname not in ALLOWED_HOSTS:\n"
            "      raise HTTPException(status_code=400, detail='URL not allowed')\n"
            "  response = requests.get(user_url, timeout=5)"
        ),
    },
    {
        "type": "Mass Assignment",
        "cwe": "CWE-915",
        "owasp": "A04:2021",
        "severity": "HIGH",
        "description": (
            "A model is created or updated directly from raw request data "
            "(e.g. **request.json()), allowing attackers to set internal fields such as "
            "is_admin, role, or account_balance."
        ),
        "detection": (
            "Look for ORM model(**request_dict) or model.update(**payload) where the "
            "payload is the raw request body without explicit field filtering."
        ),
        "fix": (
            "Use an explicit input schema and never pass raw dicts to ORM constructors:\n"
            "  class UserCreate(BaseModel):\n"
            "      username: str\n"
            "      email: EmailStr\n"
            "      password: str\n"
            "      # no is_admin, role, etc.\n\n"
            "  user = User(\n"
            "      username=data.username,\n"
            "      email=data.email,\n"
            "      hashed_password=hash_password(data.password),\n"
            "  )"
        ),
    },
    {
        "type": "Weak Cryptography",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "severity": "HIGH",
        "description": (
            "Broken or weak cryptographic algorithms (MD5, SHA1, DES, RC4) are used for "
            "hashing passwords or encrypting sensitive data, making them trivially reversible."
        ),
        "detection": (
            "Search for: hashlib.md5(, hashlib.sha1( used on passwords, "
            "Crypto.Cipher.DES, or short/static IV values in AES-CBC usage."
        ),
        "fix": (
            "Use modern, purpose-fit algorithms:\n"
            "  # Password hashing — use bcrypt or argon2\n"
            "  from passlib.context import CryptContext\n"
            "  pwd_ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')\n"
            "  hashed = pwd_ctx.hash(plain_password)\n\n"
            "  # General data hashing — use SHA-256+\n"
            "  import hashlib\n"
            "  digest = hashlib.sha256(data).hexdigest()"
        ),
    },
    {
        "type": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2021",
        "severity": "HIGH",
        "description": (
            "The XML parser is configured to resolve external entities, allowing attackers "
            "to read arbitrary files from the server or trigger SSRF via crafted XML."
        ),
        "detection": (
            "Look for lxml.etree.parse(, xml.etree.ElementTree.parse(, "
            "or defusedxml not being used. Check whether resolve_entities=True is set."
        ),
        "fix": (
            "Use defusedxml or disable external entity resolution:\n"
            "  # Use defusedxml instead of stdlib xml\n"
            "  import defusedxml.ElementTree as ET\n"
            "  tree = ET.parse(user_xml_stream)\n\n"
            "  # Or with lxml, disable network and DTD loading\n"
            "  parser = lxml.etree.XMLParser(\n"
            "      resolve_entities=False, no_network=True, load_dtd=False\n"
            "  )\n"
            "  tree = lxml.etree.parse(source, parser)"
        ),
    },
]
