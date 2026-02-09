import re
from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient

class SecurityPatcher:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()

    def patch_file(self, file_path: str, cache_name: str = None):
        """
        Generates a security fix for the given file.
        - FAST PATH: Uses Gemini Cache if cache_name is provided.
        - SLOW PATH: Manually builds context if no cache.
        """
        print(f"🔧 Patcher is fixing: {file_path}")
        
        # Base Prompt Template
        prompt_template = """
        ### ROLE
        You are a Senior Security Engineer. Your goal is to FIX security vulnerabilities in Python code.
        
        ### TASK
        Rewrite the "TARGET FILE" ({target_file}) code to make it secure.
        
        ### SECURITY REQUIREMENTS
        1. **Authentication:** Ensure ALL sensitive API routes (POST/PUT/DELETE) use a dependency like `verify_token` or `get_current_user`.
        2. **Input Validation:** Sanitize any inputs used in file paths or system commands.
        3. **Functionality:** Do NOT change the business logic. Only add security controls.
        
        ### OUTPUT FORMAT
        Return ONLY the full, valid Python code for the Target File. 
        Do not use Markdown blocks (```python). Just the raw code.
        """
        
        if cache_name:
            # --- FAST PATH (Cache) ---
            print(f"⚡ Using Cache for Patcher: {cache_name}")
            # The cache already contains the file content, so we just reference the filename
            prompt = prompt_template.format(target_file=file_path)
            
            # Use the cache-aware method in GeminiClient
            fixed_code = self.llm.analyze_with_cache(prompt, cache_name)
            
        else:
            # --- SLOW PATH (Manual Context) ---
            print("🐢 Cache miss. Building context manually...")
            context = self.assembler.build_context_for_file(file_path)
            
            # Inject the context explicitly
            prompt = prompt_template.format(target_file=file_path)
            full_prompt = f"{prompt}\n\n=== CODE CONTEXT ===\n{context}"
            
            fixed_code = self.llm.analyze(full_prompt)

        # 4. Clean up Markdown if Gemini adds it (safety net)
        fixed_code = self.clean_output(fixed_code)
        
        return fixed_code

    def clean_output(self, text):
        # Remove ```python and ``` if present
        text = re.sub(r"^```python\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^```\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n```$", "", text, flags=re.MULTILINE)
        return text.strip()

if __name__ == "__main__":
    # Test logic
    patcher = SecurityPatcher()
    # print(patcher.patch_file("api/routes.py"))