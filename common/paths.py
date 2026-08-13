from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"


def raw_dir(scan_id: str) -> Path:
    return DATA_DIR / "raw" / scan_id


def normalized_path(scan_id: str) -> Path:
    return DATA_DIR / "normalized" / scan_id / "normalized.parquet"


def deduped_path(scan_id: str) -> Path:
    return DATA_DIR / "processed" / scan_id / "deduped.parquet"


def enriched_path(scan_id: str) -> Path:
    return DATA_DIR / "processed" / scan_id / "enriched.parquet"


def final_scored_path(scan_id: str) -> Path:
    return DATA_DIR / "processed" / scan_id / "final_scored.parquet"


def run_dir(scan_id: str) -> Path:
    return DATA_DIR / "runs" / scan_id


def metrics_path(scan_id: str) -> Path:
    return run_dir(scan_id) / "metrics.json"


def llm_dedup_log_path(scan_id: str) -> Path:
    return run_dir(scan_id) / "llm_dedup_log.json"


def ticket_state_path(scan_id: str) -> Path:
    return run_dir(scan_id) / "ticket_state.json"


def cache_db_path() -> Path:
    return DATA_DIR / "cache" / "enrichment_cache.db"
