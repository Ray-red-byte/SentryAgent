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

Return your findings as a JSON array following the STRICT OUTPUT FORMAT.
