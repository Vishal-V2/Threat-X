from __future__ import annotations

from ingest.schema import Finding


def issue_title(f: Finding) -> str:
    return f"[{(f.sla_tier or 'unscored').upper()}] {f.title} — {f.host}"


def issue_body(f: Finding) -> str:
    breakdown = f.score_breakdown or {}
    rows = "\n".join(f"| {k.replace('_', ' ').title()} | {v} |" for k, v in breakdown.items())
    cve_list = ", ".join(f.cve_ids) if f.cve_ids else "none"
    scanners = ", ".join(f.contributing_scanners) if f.contributing_scanners else f.source_scanner
    evidence = str(f.raw_evidence or {})[:1500]

    return f"""## Risk Score: {f.risk_score}/100 ({f.sla_tier})

| Component | Contribution |
|---|---|
{rows}

**Why this matters:** {f.ai_summary or '_(AI summary not generated — GEMINI_API_KEY not set)_'}
**Advisory:** {f.advisory_url or 'n/a'}

- **Host:** {f.host}{f' (port {f.port})' if f.port else ''}
- **CVE(s):** {cve_list}
- **In CISA KEV:** {f.in_kev}
- **Public exploit available:** {f.exploit_db_available}
- **Found by:** {scanners}
- **SLA due:** {f.sla_due_date}
- **Owner:** {f.owner} ({f.team})

<details>
<summary>Evidence</summary>

```
{evidence}
```
</details>

<!-- threatx-dedup-key: {f.dedup_key} -->
"""


def issue_labels(f: Finding) -> list[str]:
    labels = ["threat-x-auto"]
    if f.sla_tier:
        labels.append(f"severity:{f.sla_tier}")
    if f.dedup_key:
        labels.append(f"dedupkey:{f.dedup_key[:12]}")
    return labels
