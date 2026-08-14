"""Thin wrapper around the Gemini API (google-genai SDK). Used for two things
only in this pipeline: (1) semantic-duplicate judgment on fuzzy-ambiguous
finding pairs (dedup/llm_semantic.py), and (2) drafting human-readable text —
per-finding summaries and methodology deck content (ai/summary_prompt.py,
ai/deck_prompt.py). Scoring/ranking never calls this — that path stays
deterministic.
"""
from __future__ import annotations

import os
from functools import lru_cache

import httpx
from google import genai
from google.genai import errors as genai_errors
from tenacity import retry, retry_if_exception, stop_after_attempt

# Override via GEMINI_MODEL if you want a different one.
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")

# Cap how long any single retry waits, regardless of what the API suggests —
# the free tier's per-day quota error technically asks for hours-long waits,
# which we'd rather fail fast on than block the pipeline for.
_MAX_RETRY_WAIT_SECONDS = 65.0
_FALLBACK_WAIT_SECONDS = 15.0


def is_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


@lru_cache(maxsize=1)
def get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY not set — required for AI-assisted dedup/summaries. "
            "Check is_available() before calling into this module."
        )
    return genai.Client(api_key=api_key)


def _is_retryable(exc: BaseException) -> bool:
    # 429 = rate/quota limited — worth a backed-off retry. Other 4xx (401/403/404
    # etc.) are permanent misconfiguration and retrying just wastes time.
    if isinstance(exc, genai_errors.ClientError) and exc.code == 429:
        return True
    # Transient transport-level failures (e.g. "Server disconnected without
    # sending a response") — httpx raises these directly, not wrapped by genai.
    if isinstance(exc, (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout)):
        return True
    return False


def _extract_retry_delay_seconds(exc: BaseException) -> float | None:
    """Gemini 429 responses include a structured RetryInfo hint (e.g.
    retryDelay: "20s") — prefer waiting exactly that long over guessing."""
    details = getattr(exc, "details", None)
    if not isinstance(details, dict):
        return None
    error = details.get("error", details)
    for d in (error.get("details") or []) if isinstance(error, dict) else []:
        if str(d.get("@type", "")).endswith("RetryInfo"):
            raw = str(d.get("retryDelay", "")).rstrip("s")
            try:
                return float(raw)
            except ValueError:
                return None
    return None


def _wait_for_gemini(retry_state) -> float:
    exc = retry_state.outcome.exception()
    delay = _extract_retry_delay_seconds(exc) if exc else None
    if delay is None:
        delay = _FALLBACK_WAIT_SECONDS * retry_state.attempt_number
    return min(delay, _MAX_RETRY_WAIT_SECONDS)


@retry(retry=retry_if_exception(_is_retryable), stop=stop_after_attempt(3),
       wait=_wait_for_gemini, reraise=True)
def generate_content(*, model: str, contents, config=None):
    """Call site for every Gemini generate_content call in this package — retries
    429s (waiting the API's own suggested delay when given) and transient
    network errors; anything else propagates immediately to the caller, which
    already degrades gracefully (logs and continues without the AI result)."""
    kwargs = {"model": model, "contents": contents}
    if config is not None:
        kwargs["config"] = config
    return get_client().models.generate_content(**kwargs)
