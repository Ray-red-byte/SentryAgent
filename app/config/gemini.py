import google.generativeai as genai

# The models the cache manager creates caches for — must match here exactly.
CACHE_MODEL = "models/gemini-2.5-flash"

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

# Generation config that strongly steers toward clean JSON output.
# response_mime_type="application/json" asks Gemini to constrain its output
# to valid JSON when the model supports it (1.5+).
JSON_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=0.1,          # Low temperature → more deterministic, less hallucination
    top_p=0.95,
    candidate_count=1,
)