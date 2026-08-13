# Threat-X

Risk prioritization & deduplication pipeline — Hackathon Activity 4. Ingests raw
findings from multiple vulnerability scanners, deduplicates and filters noise,
enriches every finding with public threat intelligence, and produces a ranked,
explainable, ticket-ready action list.

See `docs/architecture.md` for how it works and `docs/methodology_deck.md` for
the results deck. The full implementation plan is in
`/home/vishal/.claude/plans/hazy-orbiting-feather.md`.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in GEMINI_API_KEY / GITHUB_TOKEN as you get them

# Full pipeline against the committed fixture scanner output (no Docker/scanners needed):
python pipeline.py run --scan-id demo --use-fixtures

# Or one command that also launches the dashboard:
./scripts/demo.sh demo
```

Open the dashboard at http://localhost:8501.

## Running against a live scan

Requires Docker (with the daemon running) and `nuclei`/`nmap` on PATH:

```bash
./scripts/setup_target.sh          # brings up Juice Shop + Metasploitable2 on threatx-net
source data/.target_env
python -c "from ingest.run_scanners import run_scanners; \
  run_scanners('myrun', 'http://localhost:3000', ['$JUICE_IP', '$META_IP'])"
python pipeline.py ingest --scan-id myrun \
  --nuclei-path data/raw/myrun/nuclei/juice-shop.jsonl \
  --nmap-path data/raw/myrun/nmap/scan.xml \
  --zap-path data/raw/myrun/zap/zap-report.json
python pipeline.py dedup --scan-id myrun
python pipeline.py enrich --scan-id myrun
python pipeline.py score --scan-id myrun
python pipeline.py ticket --scan-id myrun   # no-ops unless GITHUB_TOKEN/GITHUB_REPO are set
streamlit run dashboard/app.py
```

## Verifying the hackathon's Key Criteria

```bash
python scripts/verify_key_criteria.py <scan-id>
```

Prints a pass/fail checklist for all 4 judged criteria (merged multi-scanner
dataset, measurable noise reduction, threat-intel-driven scoring, explainable
ticket-ready output).

## Tests

```bash
pytest tests/ -q
```

`tests/test_acceptance.py` runs the full pipeline against the committed
fixtures and re-checks the same 4 criteria — no live scanners/Docker required
(does make live NVD/EPSS/KEV calls, cached after the first run).

## Config

- `config/assets.yaml` — host → criticality/owner/team, used for scoring and SLA/owner assignment.
- `config/suppressions.yaml` — false-positive / accepted-risk rules.
- `config/scoring.yaml` — dedup thresholds, scoring weights, SLA tiers, ticketing thresholds.

## Environment variables (`.env`)

| Variable | Required for | Notes |
|---|---|---|
| `GEMINI_API_KEY` | LLM-assisted dedup + AI summaries + deck drafting | Without it, those steps skip cleanly (logged, not an error) |
| `NVD_API_KEY` | Enrichment | Optional — raises NVD rate limit 5→50 req/30s |
| `GITHUB_TOKEN` / `GITHUB_REPO` | Ticketing | Without them, `pipeline.py ticket` no-ops |
