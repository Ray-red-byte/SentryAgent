---
description: "Bundle Slow Path: full file contents appended after prompt rendering"
model: "gemini-2.5-flash"
---
{common_instructions}

### YOUR TASK — SECURITY DOMAIN BUNDLE AUDIT

You are auditing the **"{bundle_name}"** security domain bundle.

The complete source code for all files in this bundle is appended below.

**Cross-file analysis rules:**
1. Trace data flows *across* file boundaries. A vulnerability often spans files — for example, an HTTP parameter accepted in a route that flows unsanitised into a database call in a service layer.
2. For each finding, the `"file"` field MUST contain the *exact relative path* of the file where the dangerous operation (the sink) occurs — not the entry-point file.
3. If a vulnerability is self-contained in one file, still set the `"file"` field to that file's exact path.
4. Do not create duplicate findings for the same issue across different files.

Apply every check from the VULNERABILITY CLASSES list to the full bundle, tracing all cross-file data flows.

**⚠️ PRECISION REQUIREMENTS — MANDATORY:**
- Every finding MUST include a `"code_snippet"` field containing the exact 1–3 lines of vulnerable code copied verbatim from the source.
- The `"line"` field MUST be the exact integer line number where the dangerous operation occurs. Counting from line 1. Do not estimate or approximate.
- **Do NOT report a vulnerability if you cannot identify the exact line number and provide a real code snippet.** A vague finding with no pinpointed location must be omitted entirely.

Return your findings as a JSON array following the STRICT OUTPUT FORMAT. Each element must include all standard fields plus a `"code_snippet"` field with the verbatim vulnerable line(s).
