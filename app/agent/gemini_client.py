import os
import re
import time
import logging
import google.generativeai as genai
from langchain_google_genai import ChatGoogleGenerativeAI

logger = logging.getLogger(__name__)

# The models the cache manager creates caches for — must match here exactly.
_CACHE_MODEL = "models/gemini-2.5-flash"

# Preferred model order for non-cached calls
_PREFERRED_MODELS = [
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
_JSON_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=0.1,          # Low temperature → more deterministic, less hallucination
    top_p=0.95,
    candidate_count=1,
)


class GeminiClient:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = None

        if not self.api_key:
            logger.error("GEMINI_API_KEY is not set. All AI calls will fail.")
            return

        genai.configure(api_key=self.api_key)
        self._auto_select_model()

    def _auto_select_model(self):
        """Auto-selects the best available Gemini model for this API key."""
        try:
            available = [
                m.name
                for m in genai.list_models()
                if "generateContent" in m.supported_generation_methods
            ]
            logger.info("Available Gemini models: %s", available)

            selected = next(
                (m for m in _PREFERRED_MODELS if m in available),
                available[0] if available else None,
            )

            if not selected:
                raise ValueError("No generative models found for this API key.")

            logger.info("Auto-selected Gemini model: %s", selected)
            self.model = genai.GenerativeModel(
                selected,
                generation_config=_JSON_GENERATION_CONFIG,
            )

        except Exception as e:
            logger.warning("Error listing models (%s). Falling back to gemini-pro.", e)
            self.model = genai.GenerativeModel(
                "models/gemini-pro",
                generation_config=_JSON_GENERATION_CONFIG,
            )

    # ------------------------------------------------------------------
    # PUBLIC METHODS
    # ------------------------------------------------------------------

    def analyze(self, prompt: str) -> str:
        """
        Sends a prompt to Gemini and returns the text response.
        Retries up to 3 times with exponential backoff on 429 rate-limit errors.
        """
        if not self._ready():
            return "[]"

        return self._call_with_retry(lambda: self.model.generate_content(prompt))

    def analyze_with_cache(self, prompt: str, cache_name: str) -> str:
        """
        Uses an existing Gemini Context Cache to answer the prompt.
        Falls back to standard `analyze()` if the cache is unavailable.
        """
        if not self._ready():
            return "[]"

        try:
            cache = genai.caching.CachedContent.get(cache_name)
            cached_model = genai.GenerativeModel.from_cached_content(
                cached_content=cache,
                generation_config=_JSON_GENERATION_CONFIG,
            )
            logger.info("Querying cache: %s", cache_name)
            return self._call_with_retry(lambda: cached_model.generate_content(prompt))

        except Exception as e:
            logger.warning(
                "Cache %s unavailable (%s). Falling back to standard call.", cache_name, e
            )
            return self.analyze(prompt)

    def generate_content_with_cache(self, prompt: str, cache_name: str) -> str:
        """
        Plain-text response variant of analyze_with_cache (used for chat).
        Returns the raw text instead of trying to parse JSON.
        """
        return self.analyze_with_cache(prompt, cache_name)

    def get_model(self) -> ChatGoogleGenerativeAI:
        """
        Returns a LangChain-compatible ChatGoogleGenerativeAI instance.
        Used by create_react_agent() in the patcher subgraph.
        Selects the same preferred model as _auto_select_model().
        """
        api_key = self.api_key or os.getenv("GEMINI_API_KEY", "")
        # Prefer gemini-2.5-flash as it's fast and supports tool-use well
        model_name = "gemini-2.5-flash"
        return ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=0.1,
            convert_system_message_to_human=True,
        )

    # ------------------------------------------------------------------
    # PRIVATE HELPERS
    # ------------------------------------------------------------------

    def _call_with_retry(self, call_fn, fallback: str = "[]", max_retries: int = 3) -> str:
        """
        Calls call_fn() and retries on 429 resource-exhausted errors.
        Waits: 15s → 30s → 60s between attempts.
        """
        wait_times = [15, 30, 60]
        for attempt in range(max_retries + 1):
            try:
                response = call_fn()
                return self._extract_text(response)
            except Exception as e:
                err_str = str(e)
                is_rate_limit = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str

                if is_rate_limit and attempt < max_retries:
                    # Parse retry-after hint from error message if present
                    wait = wait_times[attempt]
                    match = re.search(r"retry_delay\s*\{\s*seconds:\s*(\d+)", err_str)
                    if match:
                        wait = max(int(match.group(1)) + 2, wait)

                    logger.warning(
                        "Gemini rate limit hit (attempt %d/%d). Waiting %ds…",
                        attempt + 1, max_retries, wait
                    )
                    time.sleep(wait)
                else:
                    logger.error("Gemini generate_content failed: %s", e)
                    return fallback
        return fallback

    def _ready(self) -> bool:
        if not self.api_key or not self.model:
            logger.error("GeminiClient is not initialised (missing API key or model).")
            return False
        return True

    @staticmethod
    def _extract_text(response) -> str:
        """Safely extracts text from a Gemini response object."""
        try:
            return response.text
        except (AttributeError, ValueError) as e:
            # response.text raises ValueError if the response was blocked
            logger.warning("Could not extract text from Gemini response: %s", e)
            return "[]"