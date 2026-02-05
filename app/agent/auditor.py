from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient

class SecurityAuditor:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()

    def audit_file(self, file_path: str):
        print(f"🕵️ Auditor investigating: {file_path}")
        
        # 1. Build Context
        context = self.assembler.build_context_for_file(file_path)
        
        # 2. Advanced Security Prompt (CoT + JSON Enforcement)
        prompt = f"""
        ### ROLE
        You are a Senior Application Security Engineer specializing in Python (FastAPI). 
        Your task is to perform a rigorous security audit on the provided code.

        ### INPUT CONTEXT
        The "TARGET FILE" is the code to be audited. 
        The "EXTERNAL DEPENDENCIES" are the definitions of functions imported by the target.
        Use dependencies to trace data flow (Source -> Sink).

        === CODE START ===
        {context}
        === CODE END ===

        ### AUDIT INSTRUCTIONS (Chain of Thought)
        1. **Analyze Traces:** Trace every user input (arguments to API endpoints) to see where it goes.
        2. **Check Auth:** Does every sensitive endpoint verify an Access Token? (Look for missing dependencies).
        3. **Check Injections:** Are inputs passed to `os.system`, `subprocess`, or SQL queries without sanitization?
        4. **Verify Logic:** Don't just look for keywords; understand the logic.

        ### VULNERABILITY CLASSIFICATION
        Focus on these specific categories:
        - **BROKEN ACCESS CONTROL:** Endpoints accessible without authentication.
        - **INJECTION:** SQLi, Command Injection, Path Traversal.
        - **SENSITIVE DATA:** Hardcoded API keys, secrets, or PII leaks.

        ### RESPONSE FORMAT
        You MUST respond with a valid JSON list. Do not include markdown formatting like ```json.
        
        Example Output:
        [
            {{
                "severity": "HIGH",
                "type": "Broken Access Control",
                "line": 15,
                "description": "The /delete-user endpoint is missing the `verify_token` dependency.",
                "fix": "@app.delete('/delete-user', dependencies=[Depends(verify_token)])"
            }}
        ]

        If the code is secure, return an empty list: []
        """
        
        # 3. Send to AI
        print("🤖 Asking Gemini (with Chain of Thought)...")
        return self.llm.analyze(prompt)

if __name__ == "__main__":
    # Test locally
    auditor = SecurityAuditor()
    print(auditor.audit_file("main.py"))