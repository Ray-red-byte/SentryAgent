import json
import re
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
        
        # 2. Advanced Security Prompt
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

        ### AUDIT INSTRUCTIONS
        1. **Analyze Traces:** Trace every user input (arguments to API endpoints) to see where it goes.
        2. **Check Auth:** Does every sensitive endpoint verify an Access Token?
        3. **Check Injections:** Are inputs passed to `os.system`, `subprocess`, or SQL queries without sanitization?

        ### RESPONSE FORMAT
        You MUST respond with a valid JSON list. 
        Do NOT use markdown formatting. Just the raw JSON array.
        
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
        print("🤖 Asking Gemini...")
        raw_response = self.llm.analyze(prompt)
        
        # 4. Parse the Response (The Fix)
        return self.parse_json_response(raw_response)

    def parse_json_response(self, text):
        """
        Cleans and parses the LLM output into a Python list.
        """
        try:
            # 1. Remove Markdown code blocks if present
            text = re.sub(r"^```json\n", "", text, flags=re.MULTILINE)
            text = re.sub(r"^```\n", "", text, flags=re.MULTILINE)
            text = re.sub(r"\n```$", "", text, flags=re.MULTILINE)
            text = text.strip()

            # 2. Parse JSON
            return json.loads(text)
            
        except json.JSONDecodeError:
            print(f"⚠️ Failed to parse JSON from Gemini. Raw output:\n{text}")
            # Fallback: Return a "System Error" vulnerability so the UI doesn't crash
            return [{
                "severity": "ERROR",
                "type": "Parser Error",
                "line": 0,
                "description": "The AI returned an invalid response format.",
                "fix": "Try auditing the file again."
            }]

if __name__ == "__main__":
    # Test locally
    auditor = SecurityAuditor()
    print(auditor.audit_file("main.py"))