# Threat-X Architecture

## Pipeline

```
ingest (Nuclei + Nmap + ZAP)
    -> normalize (shared Finding schema, ingest/schema.py)
    -> dedup (deterministic -> fuzzy -> LLM semantic -> suppression)
    -> enrich (NVD, CISA KEV, FIRST EPSS, Exploit-DB)
    -> score (weighted, explainable formula + SLA/owner assignment)
    -> ticket (GitHub Issues, idempotent)
    -> dashboard (Streamlit)
```

Each phase reads and writes the same `Finding` pydantic model (`ingest/schema.py`),
persisted as parquet under `data/`, so every phase is independently runnable and
inspectable (`python -m dedup.pipeline --scan-id demo`, etc.) as well as chainable
via `python pipeline.py run --scan-id demo`.

## Scan targets — a documented assumption

OWASP Juice Shop (`bkimminich/juice-shop`) only exposes port 3000, so it gives Nmap
almost nothing to scan at the network layer. `scripts/setup_target.sh` also brings
up a Metasploitable2 container on the same isolated `threatx-net` Docker network
purely so Nmap's `--script vuln,vulners` has real CVEs to find (vsftpd 2.3.4
backdoor, distccd, a Samba RCE). Metasploitable2 is deliberately vulnerable and
must never be exposed outside that isolated network. Juice Shop remains the target
for Nuclei and ZAP (application-layer findings).

## Deduplication — three passes, in order of confidence

1. **Deterministic** (`dedup/deterministic.py`): exact match on `(host, CVE)`,
   then on `(host, port, normalized_title)` for CVE-less findings. Most
   cross-scanner overlap on the same CVE is caught here.
2. **Fuzzy** (`dedup/fuzzy.py`): `rapidfuzz` token-sort-ratio on title+description
   within the same host. Scores ≥90 auto-merge; scores 65-89 are ambiguous and
   deferred to the LLM pass rather than merged outright.
3. **LLM semantic** (`dedup/llm_semantic.py` + `ai/dedup_prompt.py`): Gemini
   judges the ambiguous pairs with structured JSON output, logging every verdict
   (including rejections) to `data/runs/<scan_id>/llm_dedup_log.json` for
   explainability. If `GEMINI_API_KEY` isn't set, this pass is skipped
   cleanly — candidates are left un-merged rather than guessed at.

False positives / accepted risk are then suppressed via `config/suppressions.yaml`
(`dedup/suppress.py`) — severity/confidence thresholds plus explicit rules with a
required `reason` string.

## Scoring — deterministic and explainable by design

No LLM is in the scoring path — `score/formula.py` is a pure weighted sum:

```
final_score = clip(
    (CVSS/10 * 100) * 0.35
  + (EPSS * 100)     * 0.25
  + asset_criticality_score * 0.15
  + kev_boost (20, if in CISA KEV)
  + exploitdb_boost (10, only if not already KEV-boosted)
, 0, 100)
```

CVSS is deliberately capped at 35% of the weight so the score reflects real-world
exploitation signal (EPSS, KEV, Exploit-DB) rather than raw CVSS severity alone.
Every component's contribution is stored in `score_breakdown` on the finding —
this is what's rendered in the dashboard and in every generated ticket, so the
ranking is auditable rather than a black box.

## Threat intel enrichment

`enrich/enrich_pipeline.py` orchestrates four free sources through a shared
SQLite cache (`enrich/cache.py`) so repeated pipeline runs don't re-hit rate
limits: NVD API v2.0 (CVSS), CISA KEV JSON feed, FIRST.org EPSS API, and local
`searchsploit` for Exploit-DB availability. CVE-less findings (most ZAP alerts,
many Nuclei exposure templates) fall back to a documented severity→pseudo-CVSS
table rather than being left unscored.

## Ticketing

`ticket/github_issues.py` creates one GitHub Issue per finding above the
configured score threshold, with idempotency via a stable `dedup_key` hash used
as both a GitHub label and a local `ticket_state.json` cache — re-running the
pipeline never creates duplicate tickets. It no-ops with a log message (not an
error) if `GITHUB_TOKEN`/`GITHUB_REPO` aren't set, so every earlier phase and the
dashboard work without them.
