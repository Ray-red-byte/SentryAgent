import json
from app.agent.gemini_client import GeminiClient

class SecurityTranslator:
    def __init__(self):
        self.llm = GeminiClient()

    def translate_report(self, vulnerability_report: list):
        """
        Takes a raw JSON vulnerability report and converts it into 
        'Explain It Like I'm 5' (ELI5) plain English.
        """
        print("👶 Translator is simplifying the report...")
        
        # Convert list to string for the prompt
        report_str = json.dumps(vulnerability_report, indent=2)

        prompt = f"""
        ### ROLE
        You are a helpful Security Translator. You talk to non-technical founders and "Vibe Coders".
        
        ### TASK
        Translate the provided "TECHNICAL REPORT" into a simple, easy-to-understand summary.
        
        ### TONE GUIDELINES
        - **No Jargon:** Do not use words like "Sanitization", "XSS", "Buffer Overflow" without explaining them simply.
        - **Analogy:** Use real-world analogies (e.g., "It's like leaving your front door open").
        - **Actionable:** Tell them exactly why it matters and what to do, simply.
        
        === TECHNICAL REPORT ===
        {report_str}
        
        ### OUTPUT FORMAT
        Return a plain text summary. Structure it as:
        1. **The Vibe Check:** (Overall safety rating: Safe / Sketchy / Dangerous)
        2. **What's Wrong:** (Simple explanation of the bugs)
        3. **Why You Should Care:** (The business risk: losing money, getting hacked)
        """
        
        return self.llm.analyze(prompt)

if __name__ == "__main__":
    # Test logic
    sample_report = [{
        "severity": "CRITICAL",
        "type": "Injection: Command Injection",
        "description": "os.system call with unsanitized user input."
    }]
    translator = SecurityTranslator()
    print(translator.translate_report(sample_report))