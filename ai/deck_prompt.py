"""Drafts docs/methodology_deck.md content from a completed pipeline run's real
metrics — problem statement, architecture, dedup approach + achieved numbers,
scoring formula, and top results. Text generation only; never touches scoring.
"""
from __future__ import annotations

import json

from google.genai import types

from ai.client import DEFAULT_MODEL, get_client
from common.paths import final_scored_path, metrics_path
from ingest.schema import load_findings
from score.rank import ranked

_SYSTEM = ("You write a concise methodology slide deck (as markdown, one '## Slide N: Title' "
           "section per slide, 5-7 slides) for a security-engineering hackathon judge audience. "
           "Be specific and quantitative — use the real numbers given, don't invent any. No fluff.")


def draft_methodology_deck(scan_id: str) -> str:
    metrics = json.loads(metrics_path(scan_id).read_text())
    findings = load_findings(final_scored_path(scan_id))
    top5 = ranked(findings)[:5]

    top5_lines = "\n".join(
        f"- [{f.risk_score}] {f.title} ({f.host}) — CVSS {f.cvss_v3_score}, "
        f"EPSS {f.epss_score}, KEV {f.in_kev}, SLA {f.sla_tier}"
        for f in top5
    )

    prompt = f"""Draft the methodology deck for Threat-X (Hackathon Activity 4: Risk
Prioritization and Deduplication) using these real results from scan '{scan_id}':

Noise reduction metrics: {json.dumps(metrics, indent=2)}

Top 5 ranked findings:
{top5_lines}

Cover: (1) problem statement, (2) architecture (ingest 3 scanners -> normalize ->
dedup [deterministic + fuzzy + LLM semantic] -> enrich [NVD/KEV/EPSS/Exploit-DB] ->
score [weighted, explainable] -> ticket [GitHub Issues] -> dashboard), (3) dedup
approach and the noise-reduction numbers above, (4) the scoring formula (CVSS 35%,
EPSS 25%, asset criticality 15%, KEV +20, Exploit-DB +10 if not already
KEV-boosted), (5) results: the top 5 findings above, (6) what's deterministic vs.
AI-assisted and why (scoring is deterministic for explainability; dedup and
summaries use Gemini)."""

    response = get_client().models.generate_content(
        model=DEFAULT_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(system_instruction=_SYSTEM, max_output_tokens=3000),
    )
    return (response.text or "").strip()


if __name__ == "__main__":
    import sys

    from ai.client import is_available
    from common.paths import PROJECT_ROOT

    scan_id = sys.argv[1] if len(sys.argv) > 1 else "demo1"
    if not is_available():
        print("GEMINI_API_KEY not set — can't draft the deck. "
              "See docs/methodology_deck.md for a hand-written version.")
        raise SystemExit(1)

    deck = draft_methodology_deck(scan_id)
    out_path = PROJECT_ROOT / "docs" / "methodology_deck.md"
    out_path.write_text(deck)
    print(f"Wrote {out_path}")
