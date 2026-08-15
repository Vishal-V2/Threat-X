from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common.paths import DATA_DIR, final_scored_path, metrics_path

app = FastAPI(
    title="Threat-X Prioritization API Bridge",
    description="REST API Bridge serving Threat-X Scored Findings and Pipeline Metrics",
    version="1.0.0"
)

# Enable CORS for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def clean_value(val: Any) -> Any:
    """Helper to convert pandas NaN / numpy types to standard JSON-serializable Python types."""
    if pd.isna(val):
        return None
    if hasattr(val, 'item'):
        return val.item()
    return val

def parse_json_safely(val: Any) -> Any:
    if val is None or pd.isna(val):
        return None
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if (val_str.startswith("{") and val_str.endswith("}")) or (val_str.startswith("[") and val_str.endswith("]")):
            try:
                return json.loads(val_str)
            except Exception:
                return val
    return val

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "service": "Threat-X Backend API Bridge",
        "version": "1.0.0",
        "data_dir": str(DATA_DIR)
    }

@app.get("/api/scans")
def list_scans():
    root = DATA_DIR / "processed"
    if not root.exists():
        return {"scans": []}
    
    scans = []
    for p in root.iterdir():
        parquet_file = p / "final_scored.parquet"
        if parquet_file.exists():
            m_path = metrics_path(p.name)
            metrics = {}
            if m_path.exists():
                try:
                    metrics = json.loads(m_path.read_text())
                except Exception:
                    pass
            
            scans.append({
                "scan_id": p.name,
                "timestamp": parquet_file.stat().st_mtime,
                "metrics": metrics
            })
            
    scans.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"scans": scans}

@app.get("/api/scan/{scan_id}")
def get_scan_details(scan_id: str):
    p_path = final_scored_path(scan_id)
    if not p_path.exists():
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found or not scored yet.")
    
    # Load metrics
    m_path = metrics_path(scan_id)
    metrics = {}
    if m_path.exists():
        try:
            metrics = json.loads(m_path.read_text())
        except Exception:
            pass

    # Read dataframe
    df = pd.read_parquet(p_path)
    
    records = []
    for _, row in df.iterrows():
        row_dict = {}
        for col in df.columns:
            val = row[col]
            if col in ["cve_ids", "contributing_scanners", "exploit_db_ids"]:
                row_dict[col] = parse_json_safely(val) or []
            elif col in ["raw_evidence", "score_breakdown"]:
                row_dict[col] = parse_json_safely(val) or {}
            else:
                row_dict[col] = clean_value(val)
        
        # Computed field: contributing_label
        scanners = row_dict.get("contributing_scanners") or []
        if not scanners and row_dict.get("source_scanner"):
            scanners = [row_dict.get("source_scanner")]
        row_dict["contributing_label"] = " + ".join(sorted(scanners)) if scanners else "Unknown"
        
        records.append(row_dict)

    # Separate categories
    actionable = [r for r in records if not r.get("is_duplicate") and not r.get("suppressed")]
    duplicates = [r for r in records if r.get("is_duplicate")]
    suppressed = [r for r in records if r.get("suppressed")]

    # Compute distribution stats
    scanner_breakdown = {}
    sla_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for r in records:
        sc = r.get("source_scanner", "unknown")
        scanner_breakdown[sc] = scanner_breakdown.get(sc, 0) + 1
        
    for r in actionable:
        tier = (r.get("sla_tier") or "").lower()
        if tier in sla_breakdown:
            sla_breakdown[tier] += 1

    return {
        "scan_id": scan_id,
        "metrics": metrics,
        "total_count": len(records),
        "actionable_count": len(actionable),
        "duplicate_count": len(duplicates),
        "suppressed_count": len(suppressed),
        "scanner_breakdown": scanner_breakdown,
        "sla_breakdown": sla_breakdown,
        "findings": records,
        "actionable_findings": actionable,
        "duplicate_findings": duplicates,
        "suppressed_findings": suppressed
    }

class TriggerScanRequest(BaseModel):
    scan_id: str = "demo"
    use_fixtures: bool = True

@app.post("/api/scan/trigger")
def trigger_scan(payload: TriggerScanRequest):
    cmd = [sys.executable, "pipeline.py", "run", "--scan-id", payload.scan_id]
    if payload.use_fixtures:
        cmd.append("--use-fixtures")
        
    try:
        result = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            check=True
        )
        return {
            "status": "success",
            "scan_id": payload.scan_id,
            "stdout": result.stdout,
            "message": f"Pipeline execution completed successfully for scan '{payload.scan_id}'"
        }
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline run failed: {e.stderr or e.stdout}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
