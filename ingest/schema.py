"""The shared Finding contract. Every phase (ingest -> dedup -> enrich -> score ->
ticket) reads and writes this schema. Build/change this first; everything else depends
on it.
"""
from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import pandas as pd
from pydantic import BaseModel, Field, field_validator

SourceScanner = Literal["nuclei", "nmap", "zap"]
DedupMethod = Literal["exact_cve_host", "exact_title_host_port", "fuzzy", "llm_semantic"]
CvssSource = Literal["nvd", "scanner_severity_fallback"]
SlaTier = Literal["critical", "high", "medium", "low"]

# Columns holding nested structures — JSON-encoded when flattened to/from parquet
# since pyarrow can't reliably infer a schema for arbitrary Python dict/list columns.
_JSON_COLUMNS = ("cve_ids", "raw_evidence", "contributing_scanners", "exploit_db_ids",
                  "score_breakdown")


class Finding(BaseModel):
    # --- Identity ---
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    source_scanner: SourceScanner

    # --- Asset / location ---
    host: str
    port: Optional[int] = None
    service: Optional[str] = None

    # --- What was found (set by ingestion parsers) ---
    title: str
    description: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    scanner_severity: str  # normalized lowercase: info/low/medium/high/critical
    scanner_confidence: Optional[str] = None
    raw_evidence: dict = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("cve_ids")
    @classmethod
    def _normalize_cve_ids(cls, value: list[str]) -> list[str]:
        """NVD/EPSS/KEV all do exact-string CVE lookups — some scanner
        templates report CVE IDs in inconsistent case (e.g. a community
        Nuclei template's own YAML metadata used 'cve-2023-48795', lowercase,
        while NVD only recognizes 'CVE-2023-48795'), which would otherwise
        silently 404 during enrichment. Normalize once here so every phase
        downstream can assume canonical uppercase."""
        return [v.upper() for v in value]

    # --- Dedup phase ---
    normalized_title: Optional[str] = None
    dedup_key: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    dedup_method: Optional[DedupMethod] = None
    contributing_scanners: list[str] = Field(default_factory=list)
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    # --- Enrichment phase ---
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_source: Optional[CvssSource] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_ransomware_known: Optional[bool] = None
    exploit_db_available: bool = False
    exploit_db_ids: list[str] = Field(default_factory=list)
    enrichment_fetched_at: Optional[datetime] = None

    # --- Scoring phase ---
    risk_score: Optional[float] = None
    score_breakdown: Optional[dict[str, float]] = None
    asset_criticality: Optional[str] = None
    sla_tier: Optional[SlaTier] = None
    sla_due_date: Optional[date] = None
    owner: Optional[str] = None
    team: Optional[str] = None

    # --- Ticketing phase ---
    github_issue_number: Optional[int] = None
    github_issue_url: Optional[str] = None
    ticket_created_at: Optional[datetime] = None

    # --- AI-generated content ---
    ai_summary: Optional[str] = None


def findings_to_dataframe(findings: list[Finding]) -> pd.DataFrame:
    """Flatten Findings to a DataFrame, JSON-encoding nested columns so the result
    round-trips cleanly through parquet (pyarrow can't infer a schema for mixed
    dict/list-of-dict columns)."""
    rows = []
    for f in findings:
        row = f.model_dump(mode="json")
        for col in _JSON_COLUMNS:
            row[col] = json.dumps(row[col]) if row[col] is not None else None
        rows.append(row)
    return pd.DataFrame(rows)


def dataframe_to_findings(df: pd.DataFrame) -> list[Finding]:
    findings = []
    for row in df.to_dict(orient="records"):
        for col in _JSON_COLUMNS:
            val = row.get(col)
            row[col] = json.loads(val) if isinstance(val, str) else (val or ([] if col != "raw_evidence" and col != "score_breakdown" else {}))
        # pandas turns None into NaN for scalar columns; pydantic rejects NaN for Optional fields
        row = {k: (None if isinstance(v, float) and pd.isna(v) else v) for k, v in row.items()}
        findings.append(Finding(**row))
    return findings


def save_findings(findings: list[Finding], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    findings_to_dataframe(findings).to_parquet(path, index=False)


def load_findings(path: str | Path) -> list[Finding]:
    return dataframe_to_findings(pd.read_parquet(path))
