---
description: "Slow Path: Manual Context Assembly + RAG"
model: "gemini-1.5-pro"
---

Before finalizing your report, you MUST call the search_knowledge_base tool to compare the identified code patterns against our internal OWASP security standards. Do not rely solely on your general training.

{common_instructions}

### YOUR TASK
Audit the file: **`{file_path}`**

=== ASSEMBLED CONTEXT ===
{context}
=== END CONTEXT ===

1. Read the assembled context above, which contains the target file and its relevant dependencies.
2. Trace all external inputs passing into the `context`. Be highly critical of data flows that lack validation.
3. Apply every check from the VULNERABILITY CLASSES list.

Return your findings as a JSON array following the STRICT OUTPUT FORMAT.
Use the exact relative path `{file_path}` for the "file" field in every finding.