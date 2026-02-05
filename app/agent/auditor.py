from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient

class SecurityAuditor:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()

    def audit_file(self, file_path: str):
        # 1. Gather all relevant code (Target + Dependencies)
        print(f"🕵️ Auditor is investigating: {file_path}")
        context = self.assembler.build_context_for_file(file_path)
        
        # 2. Construct the Security Prompt
        prompt = f"""
        You are an expert Static Application Security Testing (SAST) agent.
        Your goal is to find security vulnerabilities in the following Python code.
        
        CONTEXT RULES:
        - The "TARGET FILE" is the code you must audit.
        - The "EXTERNAL DEPENDENCIES" are provided for context so you can trace data flow.
        
        VULNERABILITY CRITERIA:
        - SQL Injection (SQLi)
        - Command Injection
        - Hardcoded Secrets (API Keys, Passwords)
        - Insecure Deserialization
        - Cross-Site Scripting (XSS)
        
        === CODE START ===
        {context}
        === CODE END ===
        
        OUTPUT FORMAT:
        Return a JSON-style list of findings. If safe, return an empty list.
        [
            {{
                "severity": "HIGH" | "MEDIUM" | "LOW",
                "type": "Vulnerability Type",
                "line": <line_number>,
                "description": "Brief explanation of why this is dangerous.",
                "fix": "Code snippet showing how to fix it."
            }}
        ]
        """
        
        # 3. Ask Gemini
        print("🤖 Sending context to Gemini...")
        analysis = self.llm.analyze(prompt)
        return analysis

if __name__ == "__main__":
    # Test Logic (Requires GEMINI_API_KEY env var)
    try:
        auditor = SecurityAuditor()
        # We audit 'main.py' because we know it has endpoints
        report = auditor.audit_file("main.py")
        print("\n=== GEMINI SECURITY REPORT ===\n")
        print(report)
    except Exception as e:
        print(f"❌ Error: {e}")