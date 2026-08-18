"""Pydantic request and response models for the Threat-X REST API."""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"


class ScanSummary(BaseModel):
    scan_id: str
    completed_at: Optional[str] = None
    is_latest: bool = False
    raw_count: Optional[int] = None
    final_count: Optional[int] = None
    noise_reduction_pct: Optional[float] = None


class ScansResponse(BaseModel):
    scans: list[ScanSummary]


class ScanDetailResponse(BaseModel):
    scan_id: str
    metrics: dict[str, Any] = Field(default_factory=dict)


class LaunchScanRequest(BaseModel):
    scan_id: str
    target_url: Optional[str] = None
    use_fixtures: bool = False
    fast: bool = True
    nmap_targets: list[str] = Field(default_factory=list)


class ScanJobStatus(BaseModel):
    scan_id: str
    status: str  # "pending", "running", "completed", "failed"
    progress_stage: Optional[str] = None  # "ingest", "dedup", "enrich", "score", "ticket", "done"
    message: Optional[str] = None
    error: Optional[str] = None
    completed_at: Optional[str] = None


class FindingResponse(BaseModel):
    finding_id: str
    scan_id: str
    source_scanner: str
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    title: str
    description: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    scanner_severity: str
    scanner_confidence: Optional[str] = None
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[str] = None

    normalized_title: Optional[str] = None
    dedup_key: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    dedup_method: Optional[str] = None
    contributing_scanners: list[str] = Field(default_factory=list)
    contributing_label: str = ""
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_source: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_ransomware_known: Optional[bool] = None
    exploit_db_available: bool = False
    exploit_db_ids: list[str] = Field(default_factory=list)
    enrichment_fetched_at: Optional[str] = None

    risk_score: Optional[float] = None
    score_breakdown: Optional[dict[str, Any]] = None
    asset_criticality: Optional[str] = None
    sla_tier: Optional[str] = None
    sla_due_date: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None

    github_issue_number: Optional[int] = None
    github_issue_url: Optional[str] = None
    ticket_created_at: Optional[str] = None
    ai_summary: Optional[str] = None
    advisory_url: Optional[str] = None


class FindingsListResponse(BaseModel):
    scan_id: str
    total: int
    actionable_count: int
    findings: list[FindingResponse]


class TicketAssignRequest(BaseModel):
    usernames: list[str] = Field(default_factory=list)


class TicketDetailResponse(BaseModel):
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    github_configured: bool
    assignees: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class TicketAssignResponse(BaseModel):
    success: bool
    issue_number: int
    assignees: list[str] = Field(default_factory=list)
    message: str
