"""Semantic-duplicate judgment for finding pairs that fuzzy title matching flagged
as ambiguous. Uses Gemini's structured-output mode (a pydantic response schema)
so the response is always parseable JSON rather than free text.
"""
from __future__ import annotations

from google.genai import types
from pydantic import BaseModel

from ai.client import DEFAULT_MODEL, get_client


class PairVerdict(BaseModel):
    pair_id: str
    is_duplicate: bool
    confidence: float
    reasoning: str  # one short sentence


class DuplicateJudgments(BaseModel):
    pairs: list[PairVerdict]


def judge_duplicate_pairs(pairs: list[dict]) -> list[dict]:
    """pairs: [{pair_id, host, title_a, desc_a, title_b, desc_b}, ...].
    Returns the model's verdict for every pair_id in a single batched call."""
    if not pairs:
        return []

    lines = ["Judge whether each pair below describes the SAME underlying "
             "vulnerability or misconfiguration on the same host, just worded "
             "differently by different scanners (e.g. a missing-security-header "
             "alert from two different tools). Return a verdict for every pair_id.\n"]
    for p in pairs:
        lines.append(
            f"pair_id: {p['pair_id']}\n"
            f"  host: {p['host']}\n"
            f"  A: \"{p['title_a']}\" — {p.get('desc_a') or '(no description)'}\n"
            f"  B: \"{p['title_b']}\" — {p.get('desc_b') or '(no description)'}\n"
        )

    response = get_client().models.generate_content(
        model=DEFAULT_MODEL,
        contents="\n".join(lines),
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=DuplicateJudgments,
        ),
    )

    result = DuplicateJudgments.model_validate_json(response.text)
    return [v.model_dump() for v in result.pairs]
