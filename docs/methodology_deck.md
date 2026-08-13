<!--
Hand-written using real output from a demo pipeline run (scan_id=demo2, fixture
scanner data — see tests/fixtures/). Regenerate from a live scan's real numbers
with: GEMINI_API_KEY=... python -m ai.deck_prompt <scan_id>
-->

## Slide 1: The Problem

Vulnerability scanners generate far more alerts than teams can act on — the same
issue reported three different ways by three different tools, mixed in with
informational noise and low-confidence findings, with no signal for which of the
hundreds of CVEs is actually being exploited in the wild right now.

**Threat-X** ingests raw findings from multiple scanners, strips duplicates and
noise, enriches every finding with public threat intelligence, and produces one
ranked, ticket-ready action list — so teams fix what's genuinely exploitable
first.

## Slide 2: Architecture

```
Nuclei ─┐
Nmap   ─┼─► normalize (shared schema) ─► dedup ─► enrich ─► score ─► ticket
ZAP    ─┘                              (3 passes)  (4 sources)  (explainable)
                                                                     │
                                                                     ▼
                                                              Streamlit dashboard
```

- **Ingest**: Nuclei + Nmap (`--script vuln,vulners`) + OWASP ZAP baseline scan,
  merged into one normalized `Finding` schema.
- **Dedup**: deterministic (host+CVE, then host+port+title) → fuzzy
  (rapidfuzz) → LLM semantic (Gemini, for near-duplicates with no CVE at all).
- **Enrich**: NVD (CVSS), CISA KEV, FIRST.org EPSS, Exploit-DB — cached locally.
- **Score**: deterministic weighted formula, no LLM in this path.
- **Ticket**: idempotent GitHub Issues creation.

## Slide 3: Deduplication — Results

From a merged dataset of **14 raw findings across 3 scanners** (Nuclei: 5,
Nmap: 4, ZAP: 5):

| Metric | Value |
|---|---|
| Duplicates removed | 2 (14.3%) |
| Suppressed (informational / accepted-risk) | 2 (14.3%) |
| **Total noise reduction** | **28.6%** |
| Final ranked findings | 10 |

The 2 duplicates were both exact `(host, CVE)` matches — the same Log4Shell
(CVE-2021-44228) reported by both Nuclei and Nmap, and the same Lodash
prototype-pollution CVE (CVE-2019-10744) reported by both Nuclei and ZAP. On a
real scan, worded-differently duplicates with no CVE (e.g. three separate
"missing CSP header" alerts across scanners) go through the LLM semantic pass for
a further reduction — every merge decision is logged
(`data/runs/<scan_id>/llm_dedup_log.json`) rather than silently applied.

## Slide 4: Scoring Formula

```
final_score = clip(
    (CVSS/10 × 100) × 0.35
  + (EPSS × 100)     × 0.25
  + asset_criticality × 0.15
  + 20  (if in CISA KEV)
  + 10  (if a public exploit exists, and not already KEV-boosted)
, 0, 100)
```

CVSS is capped at 35% of the weight on purpose — the rest comes from real
evidence of exploitation risk. No LLM is in this path, so every point is
traceable to a named component (`score_breakdown`), shown in both the dashboard
and the generated ticket body.

## Slide 5: Results — Top Ranked Findings

| Score | Tier | Finding | CVSS | EPSS | KEV |
|---|---|---|---|---|---|
| 91.2 | critical | Log4Shell RCE — juice-shop:3000 | 10.0 | 0.9999 | ✅ |
| 86.7 | high | Samba RCE (CVE-2017-7494) — metasploitable:445 | 9.8 | 0.9945 | ✅ |
| 65.9 | medium | vsftpd 2.3.4 backdoor — metasploitable:21 | 9.8 | 0.9618 | ❌ |
| 62.1 | medium | distccd RCE — metasploitable:3632 | 9.3 | 0.8820 | ❌ |
| 44.4 | medium | Lodash prototype pollution — juice-shop:3000 | 9.1 | 0.0501 | ❌ |

Note rows 3–4 vs. row 5: **near-identical CVSS (9.1–9.8) but wildly different
EPSS** (0.88–0.96 vs. 0.05) — this is exactly why raw CVSS alone is the wrong
signal. The Lodash finding would rank alongside the RCEs under CVSS-only
triage; under Threat-X's formula it correctly falls to medium priority because
it's a 5% real-world exploitation likelihood, not a >88% one.

## Slide 6: Deterministic vs. AI-Assisted

| Path | Deterministic | AI-assisted |
|---|---|---|
| Scoring/ranking | ✅ pure weighted formula | — (explainability is a judged criterion) |
| Exact/fuzzy dedup | ✅ CVE/title matching | — |
| Near-duplicate dedup (no CVE, worded differently) | — | ✅ Gemini, logged verdicts |
| Ticket "why this matters" summaries | — | ✅ Gemini, generation only |
| Methodology deck | — | ✅ Gemini, drafted from real run metrics |

AI is scoped to classification-with-logging and text generation — never to the
number that decides remediation priority.

## Slide 7: Outcomes

- ✅ 3 scanners merged into one normalized dataset (Key Criterion #1)
- ✅ Measurable noise reduction: 28.6% (dedup 14.3% + FP-removed 14.3%) (#2)
- ✅ Scoring driven by CVSS + EPSS + KEV + asset criticality, not CVSS alone (#3)
- ✅ Explainable, ticket-ready ranking with per-finding score breakdown, SLA due
  date, and owner (#4)
- One-command demo: `scripts/demo.sh` → pipeline run + criteria checklist +
  live dashboard.
