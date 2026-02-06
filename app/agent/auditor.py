import json
import re
from app.core.context_builder import ContextAssembler
from app.agent.gemini_client import GeminiClient
from app.prompts.manager import PromptManager 
from app.memory.knowledge_base import SecurityKnowledgeBase

class SecurityAuditor:
    def __init__(self, root_dir="app"):
        self.assembler = ContextAssembler(root_dir)
        self.llm = GeminiClient()
        self.prompts = PromptManager()
        self.historian = SecurityKnowledgeBase()

    def audit_file_with_cache(self, file_path: str, cache_name: str):
        """
        Audits a file using Gemini Cache + Organizational Memory (RAG).
        """
        print(f"🕵️ Auditor checking {file_path} using Cache...")
        
        # 1. Ask Historian: "What should I look out for in this file?"
        # We use the file path or name as a simple query hook for now
        past_lessons = self.historian.recall_relevant_lessons(file_path)
        
        lessons_text = ""
        if past_lessons:
            lessons_text = "\n=== 📚 ORGANIZATIONAL MEMORY (Past Issues we've seen) ===\n"
            lessons_text += "\n".join(past_lessons)
            lessons_text += "\n=======================================================\n"

        # 2. Build Prompt (Injecting History)
        # We manually construct the prompt string here to include the lessons
        base_prompt = self.prompts.get_prompt("auditor.audit_with_cache", file_path=file_path)
        
        final_prompt = f"{base_prompt}\n\n{lessons_text}\n\nIMPORTANT: If the code matches any patterns in 'ORGANIZATIONAL MEMORY', flag them immediately."
        
        # 3. Call LLM
        raw_response = self.llm.analyze_with_cache(final_prompt, cache_name)
        return self.parse_json_response(raw_response)

    def audit_file(self, file_path: str):
        """
        SLOW PATH (Fallback): Audits a file using manual Context Assembly (RAG).
        """
        print(f"🕵️ Auditor investigating: {file_path} (Legacy Mode)")
        
        # 1. Build Context manually
        context = self.assembler.build_context_for_file(file_path)
        
        # 2. Fetch unified prompt from Hub
        # This injects the huge code block and the "Here is the code" instruction
        prompt = self.prompts.get_prompt(
            "auditor.audit_with_context", 
            context=context
        )
        
        # 3. Send to AI
        print("🤖 Asking Gemini...")
        raw_response = self.llm.analyze(prompt)
        
        return self.parse_json_response(raw_response)

    def parse_json_response(self, text):
        """
        Cleans and parses the LLM output into a Python list.
        """
        try:
            if not text:
                raise ValueError("Empty response from LLM")

            # 1. Remove Markdown code blocks if present
            text = re.sub(r"^```json\n", "", text, flags=re.MULTILINE)
            text = re.sub(r"^```\n", "", text, flags=re.MULTILINE)
            text = re.sub(r"\n```$", "", text, flags=re.MULTILINE)
            text = text.strip()

            # 2. Parse JSON
            return json.loads(text)
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"⚠️ Failed to parse JSON from Gemini. Error: {e}")
            print(f"Raw output:\n{text}")
            
            # Return a structured error so the UI handles it gracefully
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
    # print(auditor.audit_file("main.py"))