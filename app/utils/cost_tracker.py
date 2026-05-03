"""
Token and cost tracking for Gemini API calls.

Pricing sourced from https://cloud.google.com/vertex-ai/generative-ai/pricing
and https://ai.google.dev/pricing — verify and update when rates change.
Last checked: 2025-05.
"""
import logging

logger = logging.getLogger(__name__)

# USD per 1 million tokens
_PRICING: dict[str, dict[str, float]] = {
    "gemini-2.5-flash": {"input": 0.15,   "output": 0.60,  "cached": 0.0375},
    "gemini-2.0-flash": {"input": 0.10,   "output": 0.40,  "cached": 0.025},
    "gemini-1.5-flash": {"input": 0.075,  "output": 0.30,  "cached": 0.01875},
    "gemini-1.5-pro":   {"input": 1.25,   "output": 5.00,  "cached": 0.3125},
    "gemini-1.0-pro":   {"input": 0.50,   "output": 1.50,  "cached": 0.0},
    "gemini-pro":       {"input": 0.50,   "output": 1.50,  "cached": 0.0},
}
_DEFAULT_PRICING = {"input": 0.10, "output": 0.40, "cached": 0.025}


def _normalize_model(model_name: str) -> str:
    name = model_name.lower().removeprefix("models/")
    for suffix in ("-latest", "-002", "-001"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def calculate_cost(
    model_name: str,
    prompt_tokens: int,
    candidate_tokens: int,
    cached_tokens: int = 0,
) -> float:
    """Return estimated USD cost for a single Gemini API call."""
    pricing = _PRICING.get(_normalize_model(model_name), _DEFAULT_PRICING)
    non_cached = max(0, prompt_tokens - cached_tokens)
    cost = (
        non_cached * pricing["input"]
        + cached_tokens * pricing["cached"]
        + candidate_tokens * pricing["output"]
    ) / 1_000_000
    return round(cost, 8)


def _record(
    session_id: str | None,
    model_name: str,
    prompt_tokens: int,
    candidate_tokens: int,
    cached_tokens: int,
    redis_client,
) -> None:
    """Log cost and atomically increment the per-session Redis counter."""
    cost = calculate_cost(model_name, prompt_tokens, candidate_tokens, cached_tokens)
    logger.info(
        "[COST] Gemini call: $%.6f  model=%s  in=%d  out=%d  cached=%d",
        cost, model_name, prompt_tokens, candidate_tokens, cached_tokens,
    )
    if session_id and redis_client:
        try:
            redis_client.incrbyfloat(f"cost:{session_id}", cost)
        except Exception as exc:
            logger.warning("[COST] Redis update failed for session %s: %s", session_id, exc)


def log_and_track_usage(
    session_id: str | None,
    model_name: str,
    usage_metadata,
    redis_client=None,
) -> None:
    """
    Extract token counts from a Google genai SDK usage_metadata object and record cost.
    Safe to call even if usage_metadata is None.
    """
    if usage_metadata is None:
        return
    prompt_tokens    = getattr(usage_metadata, "prompt_token_count", 0) or 0
    candidate_tokens = getattr(usage_metadata, "candidates_token_count", 0) or 0
    cached_tokens    = getattr(usage_metadata, "cached_content_token_count", 0) or 0
    _record(session_id, model_name, prompt_tokens, candidate_tokens, cached_tokens, redis_client)


# ── LangChain callback ──────────────────────────────────────────────────────

try:
    from langchain_core.callbacks import BaseCallbackHandler

    class CostTrackingCallback(BaseCallbackHandler):
        """
        LangChain callback that logs token usage and updates Redis after each LLM call.
        Attach via config={"callbacks": [CostTrackingCallback(...)]} in graph.invoke().
        """

        def __init__(self, session_id: str, model_name: str, redis_client=None):
            super().__init__()
            self.session_id = session_id
            self.model_name = model_name
            self.redis_client = redis_client

        def on_llm_end(self, response, **kwargs) -> None:
            try:
                prompt_tokens = candidate_tokens = cached_tokens = 0

                # LangChain ≥0.2: usage_metadata dict on the AIMessage
                gens = getattr(response, "generations", None)
                if gens and gens[0]:
                    msg = getattr(gens[0][0], "message", None)
                    if msg:
                        usage = getattr(msg, "usage_metadata", None) or {}
                        if isinstance(usage, dict):
                            prompt_tokens    = usage.get("input_tokens", 0) or 0
                            candidate_tokens = usage.get("output_tokens", 0) or 0
                            details          = usage.get("input_token_details", {}) or {}
                            cached_tokens    = details.get("cache_read", 0) or 0

                # Fallback: llm_output.token_usage (older LangChain / some providers)
                if prompt_tokens == 0:
                    llm_out = getattr(response, "llm_output", None) or {}
                    tok_use = llm_out.get("token_usage", {}) or {}
                    prompt_tokens    = tok_use.get("prompt_tokens", 0) or 0
                    candidate_tokens = tok_use.get("completion_tokens", 0) or 0

                _record(
                    self.session_id,
                    self.model_name,
                    prompt_tokens,
                    candidate_tokens,
                    cached_tokens,
                    self.redis_client,
                )
            except Exception as exc:
                logger.warning("[COST] Callback error: %s", exc)

except ImportError:
    class CostTrackingCallback:  # type: ignore[no-redef]
        """No-op stub when langchain_core is not installed."""
        def __init__(self, *args, **kwargs):
            pass
