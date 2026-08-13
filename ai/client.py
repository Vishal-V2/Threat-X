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

from google import genai

# A small/fast model is the right default: high-volume pairwise classification
# is cheap, latency-sensitive work, not generation quality work. Override via
# GEMINI_MODEL if you want a different one.
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")


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
