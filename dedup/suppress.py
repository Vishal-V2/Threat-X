"""False-positive / accepted-risk suppression, applied after dedup so only
canonical (non-duplicate) findings need a verdict — a finding merged away already
inherits its canonical's fate.
"""
from __future__ import annotations

import fnmatch
import re

from common.config import suppressions_config
from ingest.schema import Finding

_CONFIDENCE_RANK = {"false positive": 0, "low": 1, "unknown": 1, "medium": 2, "high": 3}


def _matches(finding: Finding, match: dict) -> bool:
    if "cve_id" in match and match["cve_id"] not in finding.cve_ids:
        return False
    if "template_id" in match:
        template_id = (finding.raw_evidence or {}).get("template-id", "")
        if not fnmatch.fnmatch(template_id, match["template_id"]):
            return False
    if "host" in match and finding.host != match["host"]:
        return False
    if "title_regex" in match and not re.search(match["title_regex"], finding.title):
        return False
    return True


def apply_suppressions(findings: list[Finding]) -> None:
    cfg = suppressions_config()
    rules = cfg.get("suppressions", []) or []
    defaults = cfg.get("defaults", {}) or {}
    exclude_severities = {s.lower() for s in defaults.get("exclude_severities", [])}
    min_confidence = defaults.get("min_confidence")
    min_rank = _CONFIDENCE_RANK.get((min_confidence or "").lower(), 0)

    for f in findings:
        if f.is_duplicate:
            continue

        if f.scanner_severity.lower() in exclude_severities:
            f.suppressed = True
            f.suppression_reason = f"Severity '{f.scanner_severity}' is below the reporting threshold."
            continue

        if f.scanner_confidence:
            rank = _CONFIDENCE_RANK.get(f.scanner_confidence.lower())
            if rank is not None and rank < min_rank:
                f.suppressed = True
                f.suppression_reason = f"Confidence '{f.scanner_confidence}' is below the reporting threshold."
                continue

        for rule in rules:
            if _matches(f, rule.get("match", {})):
                f.suppressed = True
                f.suppression_reason = rule.get("reason", "Matched suppression rule.")
                break
