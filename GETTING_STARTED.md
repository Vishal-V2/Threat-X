# Getting Started with Threat-X

This walks through getting the pipeline running on your machine, from nothing to
a live dashboard. It's split into two paths: **fixture mode** (works right away,
no Docker/scanner installs needed) and **live mode** (real scans against real
targets). Do fixture mode first — it proves the whole pipeline works before you
deal with scanner installs.

## 1. Prerequisites

Already required, no extra install:
- Python 3.12+ (check with `python3 --version`)
- Internet access (the enrichment phase calls NVD/CISA KEV/FIRST EPSS live)

Only required for **live mode** (scanning a real target instead of fixtures):
- Docker, with the daemon running (`docker info` should succeed)
- `nuclei` on PATH ([install docs](https://docs.projectdiscovery.io/tools/nuclei/install))
- `nmap` on PATH (`apt install nmap` / `brew install nmap`)

Optional, nice-to-have:
- `searchsploit` (`apt install exploitdb`) — without it, Exploit-DB availability
  just always reports `False` instead of erroring; everything else still works.

## 2. Install

```bash
cd /home/vishal/Threat-X
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Leave `.env` mostly empty for now — every credential in it is optional and the
pipeline degrades gracefully without them (details in section 4).

## 3. Run it — fixture mode (start here)

This uses committed sample scanner output (`tests/fixtures/`) instead of live
scans, so it works immediately with nothing but Python installed:

```bash
python pipeline.py run --scan-id demo --use-fixtures
python scripts/verify_key_criteria.py demo
```

You should see all 4 criteria pass:

```
[x] Key Criterion #1: >=2 scanner outputs merged into one normalized dataset
[x] Key Criterion #2: measurable noise reduction (dedup % + FPs removed)
[x] Key Criterion #3: scoring driven by real threat intel, not raw CVSS alone
[x] Key Criterion #4: explainable, ticket-ready ranking with owners/SLAs
```

Then launch the dashboard:

```bash
streamlit run dashboard/app.py
```

Open http://localhost:8501 and pick `demo` from the sidebar.

Or do all of the above in one command: `./scripts/demo.sh demo`

## 4. Run it — live mode (real scans)

Once fixture mode works, point it at a real (safe, self-hosted) target:

```bash
./scripts/setup_target.sh        # brings up Juice Shop + Metasploitable2 on an isolated Docker network
source data/.target_env          # sets $JUICE_IP / $META_IP for this shell

python -c "from ingest.run_scanners import run_scanners; \
  run_scanners('live1', 'http://localhost:3000', ['$JUICE_IP', '$META_IP'])"

python pipeline.py ingest --scan-id live1 \
  --nuclei-path data/raw/live1/nuclei/juice-shop.jsonl \
  --nmap-path data/raw/live1/nmap/scan.xml \
  --zap-path data/raw/live1/zap/zap-report.json
python pipeline.py dedup --scan-id live1
python pipeline.py enrich --scan-id live1
python pipeline.py score --scan-id live1
python pipeline.py ticket --scan-id live1
streamlit run dashboard/app.py
```

`scripts/setup_target.sh` explains in its comments why Metasploitable2 is there
(Juice Shop alone only exposes one port, so Nmap needs a second target to find
anything). Never expose Metasploitable2's ports outside that isolated network —
it's deliberately unpatched.

## 5. Verify everything

```bash
pytest tests/ -q
```

17 tests, covering the parsers, dedup logic, enrichment cache/fallback, scoring
formula, and a full acceptance test that re-runs the pipeline and re-checks all
4 Key Criteria. This makes live network calls to NVD/EPSS/KEV (cached after the
first run) but needs no Docker/scanners/API keys.

## 6. Troubleshooting

- **`streamlit run` hangs / asks for an email in the terminal**: first-run
  telemetry prompt, only happens with a truly blank terminal session. Add
  `--server.headless true` to the command, or just press Enter.
- **`docker info` fails**: the daemon isn't running — start Docker Desktop (or
  `sudo systemctl start docker` on Linux) before `setup_target.sh`.
- **NVD enrichment is slow / 403s**: you're rate-limited (5 req/30s
  unauthenticated). Get a free `NVD_API_KEY` (see next section) — it raises the
  limit to 50 req/30s. Results are cached in `data/cache/enrichment_cache.db`,
  so repeated runs against the same CVEs are instant regardless.
- **Ticketing says "skipping"**: expected until you set `GITHUB_TOKEN` +
  `GITHUB_REPO` — see next section.

## What's next

See the next section of this conversation (or `README.md`'s "Environment
variables" table) for exactly which API keys unlock which features, and where
to get each one.
