"""Asserts and prints a pass/fail checklist against the hackathon's four Key
Criteria, reading the artifacts a completed pipeline run produces. Doubles as
tests/test_acceptance.py (same assertions, pytest-wrapped) so verification
doesn't depend on live scanners/APIs during judging.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.paths import final_scored_path, metrics_path, normalized_path
from ingest.schema import load_findings


def check_criterion_1_merged_dataset(scan_id: str) -> tuple[bool, str]:
    findings = load_findings(normalized_path(scan_id))
    scanners = sorted({f.source_scanner for f in findings})
    ok = len(scanners) >= 2
    return ok, f"{len(scanners)} scanner(s) merged into one dataset: {scanners} ({len(findings)} findings)"


def check_criterion_2_noise_reduction(scan_id: str) -> tuple[bool, str]:
    metrics = json.loads(metrics_path(scan_id).read_text())
    ok = "dedup_pct" in metrics and "fp_removed_pct" in metrics
    return ok, (f"dedup={metrics.get('dedup_pct')}%, fp_removed={metrics.get('fp_removed_pct')}%, "
                f"total noise reduction={metrics.get('noise_reduction_pct')}% "
                f"({metrics.get('raw_count')} raw -> {metrics.get('final_count')} final)")


def check_criterion_3_real_threat_intel(scan_id: str) -> tuple[bool, str]:
    findings = [f for f in load_findings(final_scored_path(scan_id))
                if not f.is_duplicate and not f.suppressed]
    with_epss = sum(f.epss_score is not None for f in findings)
    with_kev = sum(f.in_kev for f in findings)
    nvd_sourced = sum(f.cvss_source == "nvd" for f in findings)
    ok = with_epss > 0 or with_kev > 0  # scoring pulled in something beyond raw CVSS
    return ok, (f"{nvd_sourced}/{len(findings)} findings have NVD-sourced CVSS, "
                f"{with_epss}/{len(findings)} have an EPSS score, {with_kev}/{len(findings)} are in CISA KEV")


def check_criterion_4_explainable_ticket_ready(scan_id: str) -> tuple[bool, str]:
    findings = [f for f in load_findings(final_scored_path(scan_id))
                if not f.is_duplicate and not f.suppressed]
    has_breakdown = all(f.score_breakdown for f in findings)
    has_sla = all(f.sla_tier and f.sla_due_date for f in findings)
    has_owner = all(f.owner for f in findings)
    ok = has_breakdown and has_sla and has_owner and len(findings) > 0
    return ok, (f"{len(findings)} ranked findings, all with score_breakdown={has_breakdown}, "
                f"SLA due-date={has_sla}, owner={has_owner}")


def run_all(scan_id: str) -> bool:
    checks = [
        ("Key Criterion #1: >=2 scanner outputs merged into one normalized dataset", check_criterion_1_merged_dataset),
        ("Key Criterion #2: measurable noise reduction (dedup % + FPs removed)", check_criterion_2_noise_reduction),
        ("Key Criterion #3: scoring driven by real threat intel, not raw CVSS alone", check_criterion_3_real_threat_intel),
        ("Key Criterion #4: explainable, ticket-ready ranking with owners/SLAs", check_criterion_4_explainable_ticket_ready),
    ]
    all_pass = True
    for label, fn in checks:
        ok, detail = fn(scan_id)
        all_pass &= ok
        print(f"[{'x' if ok else ' '}] {label}\n      {detail}")
    return all_pass


if __name__ == "__main__":
    scan_id = sys.argv[1] if len(sys.argv) > 1 else "demo1"
    passed = run_all(scan_id)
    sys.exit(0 if passed else 1)
