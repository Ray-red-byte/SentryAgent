import re
from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient

class SecurityPatcher:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()

    def patch_file(self, file_path: str):
        print(f"🔧 Patcher is fixing: {file_path}")
        
        # 1. Get the Vulnerable Code + Context
        context = self.assembler.build_context_for_file(file_path)
        
        # 2. The "Remediation" Prompt
        prompt = f"""
        ### ROLE
        You are a Senior Security Engineer. Your goal is to FIX security vulnerabilities in Python code.
        
        ### TASK
        Rewrite the "TARGET FILE" code to make it secure.
        
        ### SECURITY REQUIREMENTS
        1. **Authentication:** Ensure ALL sensitive API routes (POST/PUT/DELETE) use a dependency like `verify_token` or `get_current_user`.
        2. **Input Validation:** Sanitize any inputs used in file paths or system commands.
        3. **Functionality:** Do NOT change the business logic. Only add security controls.
        
        === CODE CONTEXT ===
        {context}
        
        ### OUTPUT FORMAT
        Return ONLY the full, valid Python code for the Target File. 
        Do not use Markdown blocks (```python). Just the raw code.
        """
        
        # 3. Get the Fix from Gemini
        print("🤖 Generating Fix...")
        fixed_code = self.llm.analyze(prompt)
        
        # 4. Clean up Markdown if Gemini adds it (safety net)
        fixed_code = self.clean_output(fixed_code)
        
        return fixed_code

    def clean_output(self, text):
        # Remove ```python and ``` if present
        text = re.sub(r"^```python\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^```\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n```$", "", text, flags=re.MULTILINE)
        return text

if __name__ == "__main__":
    # Test logic
    patcher = SecurityPatcher()
    print(patcher.patch_file("api/routes.py"))