#!/usr/bin/env bash
# One-command end-to-end demo for judges. Uses live Docker targets + real scanner
# CLIs if available; otherwise falls back to the committed fixture scanner output
# so the pipeline (dedup -> enrichment -> scoring -> dashboard) is still fully
# demonstrable without Docker/nuclei/nmap installed.
set -euo pipefail

cd "$(dirname "$0")/.."
SCAN_ID="${1:-demo}"

if [ -f .env ]; then
  set -a; source .env; set +a
fi

# Prefer the project venv if one exists (created via `python3 -m venv .venv`),
# so this script works whether or not the caller has activated it themselves.
if [ -f .venv/bin/activate ]; then
  source .venv/bin/activate
fi

USE_FIXTURES=""
if command -v nuclei >/dev/null 2>&1 && command -v nmap >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "Live scanner tooling + Docker detected — bringing up targets and running real scans."
  ./scripts/setup_target.sh
  source data/.target_env
  python -c "
from ingest.run_scanners import run_scanners
run_scanners('$SCAN_ID', 'http://localhost:3000', ['$JUICE_IP', '$META_IP'])
"
  python pipeline.py ingest --scan-id "$SCAN_ID" \
    --nuclei-path "data/raw/$SCAN_ID/nuclei/juice-shop.jsonl" \
    --nmap-path "data/raw/$SCAN_ID/nmap/scan.xml" \
    --zap-path "data/raw/$SCAN_ID/zap/zap-report.json"
else
  echo "Docker/nuclei/nmap not fully available in this environment — using committed" \
       "fixture scanner output (tests/fixtures/) so the rest of the pipeline still runs."
  USE_FIXTURES="--use-fixtures"
  python pipeline.py ingest --scan-id "$SCAN_ID" $USE_FIXTURES
fi

python pipeline.py dedup --scan-id "$SCAN_ID"
python pipeline.py enrich --scan-id "$SCAN_ID"
python pipeline.py score --scan-id "$SCAN_ID"
python pipeline.py ticket --scan-id "$SCAN_ID"   # no-ops if GITHUB_TOKEN/GITHUB_REPO unset

echo ""
python scripts/verify_key_criteria.py "$SCAN_ID"

echo ""
echo "Launching dashboard — http://localhost:8501"
streamlit run dashboard/app.py --server.headless true
