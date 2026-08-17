"""Scans API routes: list available scans and retrieve scan metrics."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, HTTPException

from common.paths import DATA_DIR, final_scored_path, metrics_path, raw_dir
from backend.schemas import LaunchScanRequest, ScanDetailResponse, ScanJobStatus, ScanSummary, ScansResponse

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-memory scan job tracker
_scan_jobs: dict[str, dict] = {}


def _execute_pipeline_job(scan_id: str, target_url: str | None, use_fixtures: bool, fast: bool, nmap_targets: list[str]):
    import shutil
    import subprocess
    from urllib.parse import urlparse
    from dedup.pipeline import run_dedup_phase
    from enrich.enrich_pipeline import run_enrich_phase
    from ingest.run_scanners import ingest as run_ingest, run_scanners
    from score.rank import run_score_phase

    try:
        _scan_jobs[scan_id]["status"] = "running"

        if target_url:
            _scan_jobs[scan_id]["progress_stage"] = "live_scanning"
            _scan_jobs[scan_id]["message"] = f"Executing live scanners (Nuclei, Nmap, ZAP) against {target_url}..."

            # Verify prereqs
            if shutil.which("nuclei") is None:
                raise RuntimeError("Nuclei binary not found on system PATH.")
            if shutil.which("nmap") is None:
                raise RuntimeError("Nmap binary not found on system PATH.")

            host = urlparse(target_url).hostname or target_url
            targets = list(nmap_targets) or [host]

            subprocess.run(["docker", "network", "create", "threatx-net"], capture_output=True)
            run_scanners(scan_id, target_url, targets, fast=fast)

            raw = raw_dir(scan_id)
            nuclei_path = str(raw / "nuclei" / "juice-shop.jsonl")
            nmap_path = str(raw / "nmap" / "scan.xml")
            zap_path = str(raw / "zap" / "zap-report.json")
        else:
            nuclei_path = "tests/fixtures/nuclei_sample.jsonl"
            nmap_path = "tests/fixtures/nmap_sample.xml"
            zap_path = "tests/fixtures/zap_sample.json"

        # 1. Ingest
        _scan_jobs[scan_id]["progress_stage"] = "ingesting"
        _scan_jobs[scan_id]["message"] = "Ingesting and normalizing findings from scanner outputs..."
        run_ingest(scan_id, nuclei_path, nmap_path, zap_path)

        # 2. Dedup
        _scan_jobs[scan_id]["progress_stage"] = "deduplicating"
        _scan_jobs[scan_id]["message"] = "Running deterministic & fuzzy deduplication and suppression rules..."
        run_dedup_phase(scan_id)

        # 3. Enrich
        _scan_jobs[scan_id]["progress_stage"] = "enriching"
        _scan_jobs[scan_id]["message"] = "Enriching findings with NVD CVSS, CISA KEV, EPSS, and Exploit-DB..."
        run_enrich_phase(scan_id)

        # 4. Score
        _scan_jobs[scan_id]["progress_stage"] = "scoring"
        _scan_jobs[scan_id]["message"] = "Calculating explainable risk scores and assigning SLA tiers..."
        run_score_phase(scan_id, with_ai_summaries=True)

        _scan_jobs[scan_id]["status"] = "completed"
        _scan_jobs[scan_id]["progress_stage"] = "done"
        _scan_jobs[scan_id]["message"] = "Pipeline execution completed successfully."
        _scan_jobs[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        _scan_jobs[scan_id]["status"] = "failed"
        _scan_jobs[scan_id]["error"] = str(e)
        _scan_jobs[scan_id]["message"] = f"Pipeline failed: {str(e)}"


@router.post("/run", response_model=ScanJobStatus)
def launch_scan(req: LaunchScanRequest, background_tasks: BackgroundTasks):
    scan_id = req.scan_id.strip()
    if not scan_id:
        raise HTTPException(status_code=422, detail="scan_id is required.")

    if not req.use_fixtures and not req.target_url:
        raise HTTPException(
            status_code=422,
            detail="Specify either a 'target_url' for live scanning or set 'use_fixtures': true for simulation.",
        )

    # If job already running for this scan_id
    if scan_id in _scan_jobs and _scan_jobs[scan_id]["status"] == "running":
        raise HTTPException(status_code=409, detail=f"A scan job for '{scan_id}' is already in progress.")

    job_info = {
        "scan_id": scan_id,
        "status": "pending",
        "progress_stage": "initializing",
        "message": "Initializing scan orchestrator...",
        "error": None,
        "completed_at": None,
    }
    _scan_jobs[scan_id] = job_info

    background_tasks.add_task(
        _execute_pipeline_job,
        scan_id=scan_id,
        target_url=req.target_url,
        use_fixtures=req.use_fixtures,
        fast=req.fast,
        nmap_targets=req.nmap_targets,
    )

    return ScanJobStatus(**job_info)


@router.get("/status/{scan_id}", response_model=ScanJobStatus)
def get_scan_status(scan_id: str):
    if scan_id in _scan_jobs:
        return ScanJobStatus(**_scan_jobs[scan_id])

    # Check if scan exists in processed directory
    p_path = final_scored_path(scan_id)
    if p_path.exists():
        mtime = p_path.stat().st_mtime
        return ScanJobStatus(
            scan_id=scan_id,
            status="completed",
            progress_stage="done",
            message="Scan exists and is scored.",
            completed_at=datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
        )

    raise HTTPException(status_code=404, detail=f"No scan job found for '{scan_id}'.")


def get_available_scan_records() -> list[dict]:
    """Scans discovered from DATA_DIR / 'processed' containing final_scored.parquet,
    sorted newest first."""
    root = DATA_DIR / "processed"
    if not root.exists():
        return []

    scored_dirs = [p for p in root.iterdir() if p.is_dir() and (p / "final_scored.parquet").exists()]
    # Sort newest to oldest
    scored_dirs.sort(
        key=lambda p: (p / "final_scored.parquet").stat().st_mtime,
        reverse=True,
    )

    records = []
    for idx, p in enumerate(scored_dirs):
        scan_id = p.name
        mtime = (p / "final_scored.parquet").stat().st_mtime
        completed_at = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        
        m_path = metrics_path(scan_id)
        metrics = {}
        if m_path.exists():
            try:
                metrics = json.loads(m_path.read_text(encoding="utf-8"))
            except Exception:
                metrics = {}

        records.append({
            "scan_id": scan_id,
            "completed_at": completed_at,
            "is_latest": (idx == 0),
            "raw_count": metrics.get("raw_count"),
            "final_count": metrics.get("final_count"),
            "noise_reduction_pct": metrics.get("noise_reduction_pct"),
            "metrics": metrics,
        })
    return records


@router.get("", response_model=ScansResponse)
def list_scans():
    records = get_available_scan_records()
    return ScansResponse(
        scans=[
            ScanSummary(
                scan_id=r["scan_id"],
                completed_at=r["completed_at"],
                is_latest=r["is_latest"],
                raw_count=r["raw_count"],
                final_count=r["final_count"],
                noise_reduction_pct=r["noise_reduction_pct"],
            )
            for r in records
        ]
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str):
    parquet_path = final_scored_path(scan_id)
    if not parquet_path.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found or not yet scored.")

    m_path = metrics_path(scan_id)
    metrics = {}
    if m_path.exists():
        try:
            metrics = json.loads(m_path.read_text(encoding="utf-8"))
        except Exception:
            metrics = {}

    return ScanDetailResponse(scan_id=scan_id, metrics=metrics)
