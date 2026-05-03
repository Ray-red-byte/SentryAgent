import os
import re
import time
import logging
import google.generativeai as genai
from langchain_google_genai import ChatGoogleGenerativeAI
from app.config.settings import GEMINI_API_KEY

from app.config.gemini import CACHE_MODEL, PREFERRED_MODELS, JSON_GENERATION_CONFIG, PATCH_GENERATION_CONFIG, REVIEW_GENERATION_CONFIG

logger = logging.getLogger(__name__)

class GeminiClient:
    def __init__(self, model_name: str = None):
        self.api_key = GEMINI_API_KEY
        self.model = None

        if not self.api_key:
            logger.error("GEMINI_API_KEY is not set. All AI calls will fail.")
            return

        genai.configure(api_key=self.api_key)
        self._auto_select_model(model_name=model_name)

    def _auto_select_model(self, model_name=None):
        """Auto-selects the best available Gemini model for this API key."""
        try:
            if model_name:
                logger.info("Selected specified Gemini model: %s", model_name)
                self.model = genai.GenerativeModel(
                    model_name,
                    generation_config=JSON_GENERATION_CONFIG,
                )

            available = [
                m.name
                for m in genai.list_models()
                if "generateContent" in m.supported_generation_methods
            ]
            logger.info("Available Gemini models: %s", available)

            selected = next(
                (m for m in PREFERRED_MODELS if m in available),
                available[0] if available else None,
            )

            if not selected:
                raise ValueError("No generative models found for this API key.")

            logger.info("Auto-selected Gemini model: %s", selected)
            # Audit/review model uses JSON_GENERATION_CONFIG (structured output)
            self.model = genai.GenerativeModel(
                selected,
                generation_config=JSON_GENERATION_CONFIG,
            )
            # Patch model uses PATCH_GENERATION_CONFIG (plain text for code blocks)
            self.patch_model = genai.GenerativeModel(
                selected,
                generation_config=PATCH_GENERATION_CONFIG,
            )
            # Review model uses near-zero temperature + JSON output
            self.review_model = genai.GenerativeModel(
                selected,
                generation_config=REVIEW_GENERATION_CONFIG,
            )

        except Exception as e:
            logger.warning("Error listing models (%s). Falling back to gemini-pro.", e)
            self.model = genai.GenerativeModel(
                "models/gemini-pro",
                generation_config=JSON_GENERATION_CONFIG,
            )
            
    def analyze(self, prompt: str, session_id: str = None) -> str:
        """
        Sends a prompt to Gemini and returns the text response.
        Used for audit and review calls — uses JSON_GENERATION_CONFIG.
        Retries up to 3 times with exponential backoff on 429 rate-limit errors.
        """
        if not self._ready():
            return "[]"
        model_name = getattr(self.model, "model_name", "unknown")
        return self._call_with_retry(
            lambda: self.model.generate_content(prompt),
            model_name=model_name,
            session_id=session_id,
        )

    def analyze_patch(self, prompt: str, session_id: str = None) -> str:
        """
        Sends a prompt for patch generation — uses PATCH_GENERATION_CONFIG
        (plain text, slightly higher temperature for creative fix patterns).
        """
        if not self._ready():
            return ""
        model = getattr(self, "patch_model", self.model)
        model_name = getattr(model, "model_name", "unknown")
        return self._call_with_retry(
            lambda: model.generate_content(prompt),
            fallback="",
            model_name=model_name,
            session_id=session_id,
        )

    def analyze_review(self, prompt: str, session_id: str = None) -> str:
        """
        Sends a prompt for patch review — uses REVIEW_GENERATION_CONFIG
        (near-zero temperature + JSON output for consistent pass/fail decisions).
        """
        if not self._ready():
            return "[]"
        model = getattr(self, "review_model", self.model)
        model_name = getattr(model, "model_name", "unknown")
        return self._call_with_retry(
            lambda: model.generate_content(prompt),
            model_name=model_name,
            session_id=session_id,
        )

    def analyze_with_cache(self, prompt: str, cache_name: str, session_id: str = None) -> str:
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
                generation_config=JSON_GENERATION_CONFIG,
            )
            logger.info("Querying cache: %s", cache_name)
            model_name = getattr(cached_model, "model_name", getattr(self.model, "model_name", "unknown"))
            return self._call_with_retry(
                lambda: cached_model.generate_content(prompt),
                model_name=model_name,
                session_id=session_id,
            )

        except Exception as e:
            logger.warning(
                "Cache %s unavailable (%s). Falling back to standard call.", cache_name, e
            )
            return self.analyze(prompt, session_id=session_id)

    def generate_content_with_cache(self, prompt: str, cache_name: str, session_id: str = None) -> str:
        """
        Plain-text response variant of analyze_with_cache (used for chat).
        Returns the raw text instead of trying to parse JSON.
        """
        return self.analyze_with_cache(prompt, cache_name, session_id=session_id)

    def get_model(self) -> ChatGoogleGenerativeAI:
        """
        Returns a LangChain-compatible ChatGoogleGenerativeAI instance.
        Used by create_react_agent() in the patcher subgraph.
        Selects the same preferred model as _auto_select_model().
        """
        api_key = GEMINI_API_KEY
        # Prefer gemini-2.5-flash as it's fast and supports tool-use well
        model_name = "gemini-2.5-flash"
        return ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=0.1,
            convert_system_message_to_human=True,
        )
    
    def _call_with_retry(
        self,
        call_fn,
        fallback: str = "[]",
        max_retries: int = 3,
        session_id: str = None,
        model_name: str = None,
    ) -> str:
        """
        Calls call_fn() and retries on 429 resource-exhausted errors.
        Waits: 15s → 30s → 60s between attempts.
        Captures usage_metadata before _extract_text so billing is tracked
        even when the response text is blocked/empty.
        """
        wait_times = [15, 30, 60]
        for attempt in range(max_retries + 1):
            try:
                response = call_fn()

                # Track usage before _extract_text; the latter can raise on blocked responses
                try:
                    from app.utils.cost_tracker import log_and_track_usage
                    from app.databases.redis import get_redis
                    log_and_track_usage(
                        session_id=session_id,
                        model_name=model_name or "unknown",
                        usage_metadata=getattr(response, "usage_metadata", None),
                        redis_client=get_redis() if session_id else None,
                    )
                except Exception as track_err:
                    logger.warning("[COST] Tracking error (non-fatal): %s", track_err)

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