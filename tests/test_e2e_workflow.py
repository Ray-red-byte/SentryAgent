#!/usr/bin/env python3
"""
tests/test_e2e_workflow.py

End-to-end integration test for the full SentryAgent workflow:
  1. Login  → get JWT
  2. Upload → ZIP with a deliberately vulnerable Python file
  3. Scan   → LangGraph full-scan workflow
  4. Audit  → single-file deep audit
  5. Fix    → patch generation
  6. Apply  → write patch to workspace + learn in ChromaDB
  7. Download → get patched ZIP

Run from project root:
    python -m pytest tests/test_e2e_workflow.py -v
OR directly:
    python tests/test_e2e_workflow.py
"""

import io
import os
import sys
import json
import zipfile
import time
import requests

# ---------------------------------------------------------------------------
# Config — override via env vars for CI/CD
# ---------------------------------------------------------------------------
BASE_URL   = os.getenv("TEST_API_URL",  "http://localhost:8000/v2")
USERNAME   = os.getenv("TEST_USERNAME", "admin")
PASSWORD   = os.getenv("TEST_PASSWORD", "changeme")
TIMEOUT    = int(os.getenv("TEST_TIMEOUT_S", "600"))  # seconds per request (allow for Gemini rate-limit retries)

# ---------------------------------------------------------------------------
# Deliberately vulnerable Python code to upload
# ---------------------------------------------------------------------------
VULNERABLE_CODE = '''
"""
intentionally_vulnerable.py
Contains multiple security issues for testing purposes.
"""
import os
import subprocess
import sqlite3


def get_user(user_id):
    """BAD: SQL injection — user_id is concatenated directly."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection (CWE-89)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def run_command(cmd):
    """BAD: Command injection — cmd comes from user input."""
    # VULNERABILITY: Command Injection (CWE-78)
    os.system(f"echo {cmd}")


def process_file(filename):
    """BAD: Path traversal — filename not validated."""
    # VULNERABILITY: Path Traversal (CWE-22)
    with open(f"/var/data/{filename}", "r") as f:
        return f.read()


def authenticate(username, password):
    """BAD: Hardcoded credentials."""
    # VULNERABILITY: Hardcoded Credentials (CWE-798)
    ADMIN_PASSWORD = "super_secret_admin_123"
    if password == ADMIN_PASSWORD:
        return True
    return False


def evaluate_expression(expr):
    """BAD: Code injection via eval."""
    # VULNERABILITY: Code Injection (CWE-94)
    return eval(expr)
'''


class SentryAgentE2ETest:
    """Runs the full upload → scan → audit → fix → apply → download workflow."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        self.token = None
        self.session_id = None
        self.target_file = "intentionally_vulnerable.py"
        self.fixed_code = None
        self.results = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _auth_header(self):
        return {"Authorization": f"Bearer {self.token}"}

    def _ok(self, step: str, res: requests.Response, expected: int = 200):
        if res.status_code != expected:
            print(f"  ✗ [{step}] HTTP {res.status_code}: {res.text[:300]}")
            return False
        print(f"  ✓ [{step}] HTTP {res.status_code}")
        return True

    def _print_section(self, title: str):
        print(f"\n{'─'*55}")
        print(f"  {title}")
        print(f"{'─'*55}")

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def step_login(self) -> bool:
        self._print_section("STEP 1 — Login")
        res = self.session.post(
            f"{BASE_URL}/auth/token",
            data={"username": USERNAME, "password": PASSWORD},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT,
        )
        if not self._ok("login", res):
            return False
        data = res.json()
        self.token = data["access_token"]
        self.session.headers["Authorization"] = f"Bearer {self.token}"
        print(f"  ✓ Token received (expires in {data.get('expires_in_hours','?')} hours)")
        return True

    def step_upload(self) -> bool:
        self._print_section("STEP 2 — Upload vulnerable codebase")

        # Build an in-memory ZIP with our vulnerable file
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(self.target_file, VULNERABLE_CODE)
        buf.seek(0)

        res = self.session.post(
            f"{BASE_URL}/upload",
            files={"file": ("test_codebase.zip", buf, "application/zip")},
            timeout=TIMEOUT,
        )
        if not self._ok("upload", res):
            return False
        self.session_id = res.json()["session_id"]
        print(f"  ✓ Session ID: {self.session_id}")
        return True

    def step_scan(self) -> bool:
        self._print_section("STEP 3 — Full scan (LangGraph)")
        print("  ⏳ This may take 30-90 seconds while the AI scans your code…")

        res = self.session.post(
            f"{BASE_URL}/scan",
            json={"session_id": self.session_id},
            timeout=TIMEOUT,
        )
        if not self._ok("scan", res):
            return False

        data = res.json()
        report = data.get("report", {})
        scan_results = report.get("scan_results", [])
        vulns = report.get("vulnerabilities", [])

        self.results["scan"] = report
        print(f"  ✓ Files with issues : {len(scan_results)}")
        print(f"  ✓ Vulnerabilities   : {len(vulns)}")

        # Summarise
        for v in vulns[:5]:
            print(f"     [{v.get('severity','?'):8}] {v.get('type','?')} — {v.get('file','?')}:{v.get('line','?')}")
        return True

    def step_audit(self) -> bool:
        self._print_section("STEP 4 — Single-file deep audit")
        print(f"  ⏳ Auditing: {self.target_file}…")

        res = self.session.post(
            f"{BASE_URL}/audit",
            json={"session_id": self.session_id, "file_path": self.target_file},
            timeout=TIMEOUT,
        )
        if not self._ok("audit", res):
            return False

        data = res.json()
        report = data.get("report", [])
        self.results["audit"] = report
        print(f"  ✓ Audit found {len(report)} finding(s)")
        for item in report[:5]:
            sev = item.get("severity", "?")
            typ = item.get("type", "?")
            line = item.get("line", "?")
            desc = item.get("description", "")[:80]
            print(f"     [{sev:8}] Line {line:3} — {typ}")
            print(f"              {desc}…")
        return True

    def step_fix(self) -> bool:
        self._print_section("STEP 5 — Generate security fix (LangGraph patch workflow)")
        print("  ⏳ Running patch generation + review loop…")

        res = self.session.post(
            f"{BASE_URL}/fix",
            json={"session_id": self.session_id, "file_path": self.target_file},
            timeout=TIMEOUT,
        )
        if not self._ok("fix", res):
            return False

        data = res.json()
        self.fixed_code = data.get("fixed_code", "")
        self.results["fix"] = {"length": len(self.fixed_code)}
        print(f"  ✓ Patch generated ({len(self.fixed_code)} chars)")

        # Quick sanity check
        checks = {
            "Removed dangerous eval()": "eval(" not in self.fixed_code or "# noqa" in self.fixed_code,
            "Has Python content": len(self.fixed_code) > 100,
        }
        for check, passed in checks.items():
            icon = "✓" if passed else "⚠"
            print(f"  {icon}  Check: {check}")
        return True

    def step_apply(self) -> bool:
        self._print_section("STEP 6 — Apply fix to workspace")

        res = self.session.post(
            f"{BASE_URL}/apply",
            json={
                "session_id": self.session_id,
                "file_path": self.target_file,
                "fixed_code": self.fixed_code,
                "vuln_type": "Multiple (SQLi, CMDi, Path Traversal, Hardcoded Creds, Code Injection)",
                "severity": "CRITICAL",
                "cwe": "CWE-89, CWE-78, CWE-22, CWE-798, CWE-94",
            },
            timeout=TIMEOUT,
        )
        if not self._ok("apply", res):
            return False
        data = res.json()
        print(f"  ✓ {data.get('message')}")
        print(f"  ✓ Download URL: {data.get('download_url')}")
        return True

    def step_download(self) -> bool:
        self._print_section("STEP 7 — Download patched codebase ZIP")

        res = self.session.get(
            f"{BASE_URL}/download/{self.session_id}",
            timeout=TIMEOUT,
            stream=True,
        )
        if not self._ok("download", res):
            return False

        content = res.content
        content_type = res.headers.get("content-type", "")
        filename = res.headers.get("content-disposition", "")

        print(f"  ✓ Received {len(content):,} bytes")
        print(f"  ✓ Content-Type: {content_type}")
        print(f"  ✓ Disposition : {filename}")

        # Verify it's a valid ZIP
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = zf.namelist()
                print(f"  ✓ ZIP contents: {names}")
                assert self.target_file in names, f"{self.target_file} not found in ZIP!"
        except zipfile.BadZipFile:
            print("  ✗ Response is not a valid ZIP file!")
            return False

        print("  ✓ ZIP is valid and contains the patched file")
        return True

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------

    def run(self):
        print("=" * 55)
        print("  SentryAgent — End-to-End Workflow Test")
        print("=" * 55)
        print(f"  Target: {BASE_URL}")

        steps = [
            ("Login",    self.step_login),
            ("Upload",   self.step_upload),
            ("Scan",     self.step_scan),
            ("Audit",    self.step_audit),
            ("Fix",      self.step_fix),
            ("Apply",    self.step_apply),
            ("Download", self.step_download),
        ]

        passed = []
        failed = []

        for name, fn in steps:
            t0 = time.time()
            try:
                ok = fn()
            except Exception as exc:
                print(f"  ✗ [{name}] Unexpected exception: {exc}")
                ok = False
            elapsed = time.time() - t0
            (passed if ok else failed).append(f"{name} ({elapsed:.1f}s)")
            if not ok:
                print(f"\n  ⛔ Stopping at step '{name}' — fix the issue and re-run.")
                break

        print(f"\n{'='*55}")
        print(f"  RESULTS: {len(passed)}/{len(steps)} steps passed")
        for s in passed:
            print(f"    ✓ {s}")
        for s in failed:
            print(f"    ✗ {s}")
        print("=" * 55)
        return len(failed) == 0


if __name__ == "__main__":
    ok = SentryAgentE2ETest().run()
    sys.exit(0 if ok else 1)
