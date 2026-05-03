---
description: "Fast Path: Gemini Context Caching"
model: "gemini-1.5-pro"
---
{common_instructions}

### YOUR TASK
Audit the file: **`{file_path}`**

The ENTIRE repository is already loaded in your context cache.
1. Locate the file `{file_path}` in your cached memory.
2. Read it in full, then trace all data flows into and out of it.
3. Check all imported functions and dependencies — do not stop at the file boundary.
4. Apply every check from the VULNERABILITY CLASSES list above.

Return your findings as a JSON array following the STRICT OUTPUT FORMAT.
Use the exact relative path `{file_path}` for the "file" field in every finding.