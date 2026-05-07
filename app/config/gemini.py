import google.generativeai as genai

# The models the cache manager creates caches for — must match here exactly.
CACHE_MODEL = "models/gemini-2.5-flash"

# Lite model for low-cost tasks (review, chat slow-path)
LITE_MODEL = "models/gemini-2.0-flash-lite"
PREFERRED_LITE_MODELS = [
    "models/gemini-2.0-flash-lite",
    "models/gemini-2.0-flash",
    "models/gemini-1.5-flash-latest",
    "models/gemini-1.5-flash",
]

# Preferred model order for non-cached calls
PREFERRED_MODELS = [
    "models/gemini-2.5-flash",
    "models/gemini-2.0-flash",
    "models/gemini-1.5-flash-latest",
    "models/gemini-1.5-flash",
    "models/gemini-1.5-flash-002",
    "models/gemini-1.5-pro",
    "models/gemini-pro",
    "models/gemini-1.0-pro",
]

# ── Audit config ───────────────────────────────────────────────────────────────
# response_mime_type="application/json" forces Gemini (1.5+) to produce valid
# JSON, eliminating parse failures caused by Markdown fences or prose preambles.
# temperature=0.1 → deterministic, low-hallucination vulnerability reports.
JSON_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=0.1,
    top_p=0.95,
    candidate_count=1,
    response_mime_type="application/json",
)

# ── Patch config ───────────────────────────────────────────────────────────────
# Patches need slightly more creativity for finding fix patterns, but NOT for
# the JSON review. Use plain text so the ReAct agent can emit fenced code blocks.
PATCH_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=0.15,
    top_p=0.95,
    candidate_count=1,
)

# ── Review config ──────────────────────────────────────────────────────────────
# Reviewer must return strict JSON — same mime_type as audit.
REVIEW_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=0.05,   # near-zero: reviewer must be consistent and decisive
    top_p=0.90,
    candidate_count=1,
    response_mime_type="application/json",
)