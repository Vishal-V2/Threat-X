"""Findings API routes: serialize scored findings from Parquet cleanly for React."""
from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any
import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException

from common.paths import final_scored_path
from backend.schemas import FindingResponse, FindingsListResponse

router = APIRouter(prefix="/api/scans", tags=["findings"])


def _clean_val(val: Any) -> Any:
    """Converts numpy / pandas / NaN / timestamp types to JSON-safe Python types."""
    if val is None:
        return None
    if isinstance(val, (float, np.floating)) and (np.isnan(val) or pd.isna(val)):
        return None
    if pd.isna(val):
        return None
    if isinstance(val, (np.integer,)):
        return int(val)
    if isinstance(val, (np.floating,)):
        return float(val)
    if isinstance(val, (np.bool_,)):
        return bool(val)
    if isinstance(val, (datetime, pd.Timestamp)):
        return val.isoformat()
    if isinstance(val, date):
        return val.isoformat()
    return val


def _parse_json_field(val: Any, default_factory) -> Any:
    """Safely parse JSON-encoded column or return native structure."""
    if val is None or pd.isna(val):
        return default_factory()
    if isinstance(val, str):
        val = val.strip()
        if not val or val == "nan":
            return default_factory()
        try:
            return json.loads(val)
        except Exception:
            return default_factory()
    if isinstance(val, (list, dict)):
        return val
    return default_factory()


def _get_contributing_label(row: dict) -> str:
    scanners = row.get("contributing_scanners")
    if not isinstance(scanners, list):
        if isinstance(scanners, str):
            try:
                scanners = json.loads(scanners) if scanners else []
            except Exception:
                scanners = []
        else:
            scanners = []
    if not scanners:
        source = row.get("source_scanner")
        scanners = [source] if source else []
    return " + ".join(sorted(set(scanners)))


def load_findings_for_scan(scan_id: str) -> list[dict]:
    parquet_path = final_scored_path(scan_id)
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found or not yet scored.")

    df = pd.read_parquet(parquet_path)
    records = df.to_dict(orient="records")

    cleaned_findings = []
    for r in records:
        cve_ids = _parse_json_field(r.get("cve_ids"), list)
        exploit_db_ids = _parse_json_field(r.get("exploit_db_ids"), list)
        contributing_scanners = _parse_json_field(r.get("contributing_scanners"), list)
        raw_evidence = _parse_json_field(r.get("raw_evidence"), dict)
        score_breakdown = _parse_json_field(r.get("score_breakdown"), dict)

        # Normalize cve_ids to list of str
        if isinstance(cve_ids, list):
            cve_ids = [str(x) for x in cve_ids if x]
        else:
            cve_ids = []

        item = {
            "finding_id": str(r.get("finding_id", "")),
            "scan_id": scan_id,
            "source_scanner": str(r.get("source_scanner", "")),
            "host": str(r.get("host", "")),
            "port": _clean_val(r.get("port")),
            "service": _clean_val(r.get("service")),
            "title": str(r.get("title", "")),
            "description": _clean_val(r.get("description")),
            "cve_ids": cve_ids,
            "scanner_severity": str(r.get("scanner_severity", "info")),
            "scanner_confidence": _clean_val(r.get("scanner_confidence")),
            "raw_evidence": raw_evidence,
            "first_seen": _clean_val(r.get("first_seen")),
            "normalized_title": _clean_val(r.get("normalized_title")),
            "dedup_key": _clean_val(r.get("dedup_key")),
            "is_duplicate": bool(r.get("is_duplicate", False)),
            "duplicate_of": _clean_val(r.get("duplicate_of")),
            "dedup_method": _clean_val(r.get("dedup_method")),
            "contributing_scanners": contributing_scanners,
            "contributing_label": "",
            "suppressed": bool(r.get("suppressed", False)),
            "suppression_reason": _clean_val(r.get("suppression_reason")),
            "cvss_v3_score": _clean_val(r.get("cvss_v3_score")),
            "cvss_v3_vector": _clean_val(r.get("cvss_v3_vector")),
            "cvss_source": _clean_val(r.get("cvss_source")),
            "epss_score": _clean_val(r.get("epss_score")),
            "epss_percentile": _clean_val(r.get("epss_percentile")),
            "in_kev": bool(r.get("in_kev", False)),
            "kev_date_added": _clean_val(r.get("kev_date_added")),
            "kev_ransomware_known": _clean_val(r.get("kev_ransomware_known")),
            "exploit_db_available": bool(r.get("exploit_db_available", False)),
            "exploit_db_ids": exploit_db_ids,
            "enrichment_fetched_at": _clean_val(r.get("enrichment_fetched_at")),
            "risk_score": _clean_val(r.get("risk_score")),
            "score_breakdown": score_breakdown,
            "asset_criticality": _clean_val(r.get("asset_criticality")),
            "sla_tier": _clean_val(r.get("sla_tier")),
            "sla_due_date": _clean_val(r.get("sla_due_date")),
            "owner": _clean_val(r.get("owner")),
            "team": _clean_val(r.get("team")),
            "github_issue_number": _clean_val(r.get("github_issue_number")),
            "github_issue_url": _clean_val(r.get("github_issue_url")),
            "ticket_created_at": _clean_val(r.get("ticket_created_at")),
            "ai_summary": _clean_val(r.get("ai_summary")),
            "advisory_url": _clean_val(r.get("advisory_url")),
        }
        item["contributing_label"] = _get_contributing_label(item)
        cleaned_findings.append(item)

    return cleaned_findings


@router.get("/{scan_id}/findings", response_model=FindingsListResponse)
def get_findings(scan_id: str):
    findings_data = load_findings_for_scan(scan_id)
    actionable_count = sum(1 for f in findings_data if not f["is_duplicate"] and not f["suppressed"])

    return FindingsListResponse(
        scan_id=scan_id,
        total=len(findings_data),
        actionable_count=actionable_count,
        findings=[FindingResponse(**f) for f in findings_data],
    )
