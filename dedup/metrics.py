"""Computes and persists the before/after noise-reduction metrics that satisfy
Key Criterion #2: measurable dedup % and false-positives-removed %.
"""
from __future__ import annotations

import json

from common.paths import metrics_path
from ingest.schema import Finding


def compute_metrics(findings: list[Finding], scan_id: str) -> dict:
    raw_count = len(findings)
    duplicate_count = sum(f.is_duplicate for f in findings)
    suppressed_count = sum(f.suppressed and not f.is_duplicate for f in findings)
    final_count = raw_count - duplicate_count - suppressed_count

    by_method: dict[str, int] = {}
    for f in findings:
        if f.is_duplicate and f.dedup_method:
            by_method[f.dedup_method] = by_method.get(f.dedup_method, 0) + 1

    by_scanner_raw: dict[str, int] = {}
    for f in findings:
        by_scanner_raw[f.source_scanner] = by_scanner_raw.get(f.source_scanner, 0) + 1

    metrics = {
        "scan_id": scan_id,
        "raw_count": raw_count,
        "duplicate_count": duplicate_count,
        "suppressed_count": suppressed_count,
        "final_count": final_count,
        "dedup_pct": round(duplicate_count / raw_count * 100, 2) if raw_count else 0.0,
        "fp_removed_pct": round(suppressed_count / raw_count * 100, 2) if raw_count else 0.0,
        "noise_reduction_pct": round((duplicate_count + suppressed_count) / raw_count * 100, 2) if raw_count else 0.0,
        "dedup_by_method": by_method,
        "raw_count_by_scanner": by_scanner_raw,
    }

    path = metrics_path(scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fp:
        json.dump(metrics, fp, indent=2)
    return metrics
