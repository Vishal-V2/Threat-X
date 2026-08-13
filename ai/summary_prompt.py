"""Drafts a plain-English 'why this matters' blurb per top-ranked finding, for
the dashboard and ticket body. Purely explanatory text — never used in scoring.
"""
from __future__ import annotations

from google.genai import types

from ai.client import DEFAULT_MODEL, get_client
from ingest.schema import Finding

_SYSTEM = ("You write one-sentence, plain-English risk explanations for security "
           "findings, for a ticket that a busy engineer will triage. State why the "
           "finding matters given its threat intel (CVSS/EPSS/KEV/exploit "
           "availability) — not what the finding technically is. No preamble.")


def summarize_finding(f: Finding) -> str:
    facts = [
        f"Title: {f.title}",
        f"Host: {f.host} (criticality: {f.asset_criticality})",
        f"CVE(s): {', '.join(f.cve_ids) if f.cve_ids else 'none'}",
        f"CVSS: {f.cvss_v3_score}",
        f"EPSS (probability of exploitation in the wild): {f.epss_score}",
        f"In CISA KEV (confirmed active exploitation): {f.in_kev}",
        f"Public exploit available (Exploit-DB): {f.exploit_db_available}",
        f"Risk score: {f.risk_score}/100",
    ]
    response = get_client().models.generate_content(
        model=DEFAULT_MODEL,
        contents="\n".join(facts),
        config=types.GenerateContentConfig(system_instruction=_SYSTEM, max_output_tokens=150),
    )
    return (response.text or "").strip()
