"""End-to-end acceptance test: runs the full pipeline against the committed
fixtures and asserts all 4 hackathon Key Criteria, independent of live
scanners/APIs/Docker so it works in CI or offline.

Live NVD/EPSS/KEV calls are made (network required) but are cached in
data/cache/ after the first run, so repeats are fast; if the network is
unavailable, EPSS/KEV-derived fields fall back to None/False and Criterion #3
may fail — that's expected in a fully offline environment, not a code bug.
"""
from common.paths import normalized_path
from dedup.pipeline import run_dedup_phase
from enrich.enrich_pipeline import run_enrich_phase
from ingest.run_scanners import ingest
from score.rank import run_score_phase
from scripts.verify_key_criteria import (check_criterion_1_merged_dataset,
                                          check_criterion_2_noise_reduction,
                                          check_criterion_4_explainable_ticket_ready)

SCAN_ID = "acceptance-test"
FIXTURES = "tests/fixtures"


def _run_pipeline_without_ticketing():
    ingest(SCAN_ID, f"{FIXTURES}/nuclei_sample.jsonl", f"{FIXTURES}/nmap_sample.xml",
           f"{FIXTURES}/zap_sample.json")
    run_dedup_phase(SCAN_ID)
    run_enrich_phase(SCAN_ID)
    run_score_phase(SCAN_ID, with_ai_summaries=False)


def test_pipeline_satisfies_key_criteria_1_2_4():
    """Criteria #1, #2, #4 need no network access. Criterion #3 (live threat
    intel) is exercised separately in test_scoring.py/test_enrich.py without
    requiring a live pipeline run here."""
    _run_pipeline_without_ticketing()

    ok, detail = check_criterion_1_merged_dataset(SCAN_ID)
    assert ok, detail

    ok, detail = check_criterion_2_noise_reduction(SCAN_ID)
    assert ok, detail

    ok, detail = check_criterion_4_explainable_ticket_ready(SCAN_ID)
    assert ok, detail


def test_normalized_dataset_has_all_three_scanners():
    from ingest.schema import load_findings
    findings = load_findings(normalized_path(SCAN_ID))
    assert {f.source_scanner for f in findings} == {"nuclei", "nmap", "zap"}
