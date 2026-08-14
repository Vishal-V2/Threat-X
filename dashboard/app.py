"""Threat-X risk dashboard (Streamlit). Reads data/processed/<scan_id>/final_scored.parquet
and data/runs/<scan_id>/metrics.json for the latest pipeline run.

Palette: fixed categorical hues assigned by scanner identity (never by rank/filter
state), and the fixed status palette for SLA tiers — both from the dataviz skill's
validated default palette (references/palette.md), so hue always maps to the same
entity across every chart on the page.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Streamlit only adds this script's own directory (dashboard/) to sys.path, not
# the project root — so `common`/`ingest`/etc. aren't importable unless we add
# it ourselves. Must happen before any project-local import below.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from common.paths import DATA_DIR, final_scored_path, metrics_path

# --- Validated categorical + status palette (dataviz skill, light-mode steps) ---
SCANNER_COLORS = {"nuclei": "#2a78d6", "nmap": "#eb6834", "zap": "#1baf7a"}  # slots 1-3
SLA_COLORS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#0ca30c"}
INK_SECONDARY = "#52514e"
GRID = "#e1e0d9"

st.set_page_config(page_title="Threat-X Risk Dashboard", layout="wide")


@st.cache_data
def available_scan_ids() -> list[str]:
    """Ordered oldest -> newest by when each scan finished scoring, not
    alphabetically — the sidebar defaults to the last entry in this list, and
    "most recently completed" is what a user actually expects there, not
    whichever scan-id happens to sort last as a string (e.g. 'scanme' would
    always beat 'myapp' alphabetically regardless of which ran more recently)."""
    root = DATA_DIR / "processed"
    if not root.exists():
        return []
    scored = [p for p in root.iterdir() if (p / "final_scored.parquet").exists()]
    scored.sort(key=lambda p: (p / "final_scored.parquet").stat().st_mtime)
    return [p.name for p in scored]


def clean(val):
    """Missing Optional[str] fields (ai_summary, github_issue_url, ...) load from
    parquet as NaN (a truthy float, and pandas' string dtype keeps NaN — not
    None — as its missing-value marker even after reassignment), so an
    unguarded `row["x"] or fallback` would render the literal text "nan"
    instead of falling back. Use this at every such call site instead."""
    return val if pd.notna(val) else None


@st.cache_data
def load_scan(scan_id: str) -> tuple[pd.DataFrame, dict]:
    df = pd.read_parquet(final_scored_path(scan_id))
    m_path = metrics_path(scan_id)
    metrics = json.loads(m_path.read_text()) if m_path.exists() else {}
    return df, metrics


def contributing_label(row) -> str:
    scanners = row["contributing_scanners"]
    if isinstance(scanners, str):
        scanners = json.loads(scanners) if scanners else []
    if not scanners:
        scanners = [row["source_scanner"]]
    return " + ".join(sorted(scanners))


st.title("Threat-X — Risk Prioritization Dashboard")

scan_ids = available_scan_ids()
if not scan_ids:
    st.warning("No scored runs found yet. Run the pipeline first: "
               "`python pipeline.py run --scan-id <id>` (see scripts/demo.sh).")
    st.stop()

scan_id = st.sidebar.selectbox("Scan", scan_ids, index=len(scan_ids) - 1)
df, metrics = load_scan(scan_id)

# --- Before/after funnel ---------------------------------------------------
st.subheader("Noise reduction: before vs. after")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Raw findings", metrics.get("raw_count", "—"))
c2.metric("Duplicates removed", metrics.get("duplicate_count", "—"),
          f"-{metrics.get('dedup_pct', 0)}%")
c3.metric("Suppressed (FP / accepted risk)", metrics.get("suppressed_count", "—"),
          f"-{metrics.get('fp_removed_pct', 0)}%")
c4.metric("Final ranked findings", metrics.get("final_count", "—"),
          f"-{metrics.get('noise_reduction_pct', 0)}% total noise")

# --- Filters -----------------------------------------------------------
actionable = df[(~df["is_duplicate"]) & (~df["suppressed"])].copy()
actionable["contributing_label"] = actionable.apply(contributing_label, axis=1)

st.sidebar.header("Filters")
scanner_filter = st.sidebar.multiselect("Scanner", sorted(SCANNER_COLORS), default=[])
tier_filter = st.sidebar.multiselect("SLA tier", ["critical", "high", "medium", "low"], default=[])
host_filter = st.sidebar.multiselect("Host", sorted(actionable["host"].unique()), default=[])
kev_only = st.sidebar.checkbox("KEV only (confirmed active exploitation)")
min_score = st.sidebar.slider("Minimum risk score", 0, 100, 0)

filtered = actionable
if scanner_filter:
    filtered = filtered[filtered["contributing_label"].apply(
        lambda s: any(sc in s.split(" + ") for sc in scanner_filter))]
if tier_filter:
    filtered = filtered[filtered["sla_tier"].isin(tier_filter)]
if host_filter:
    filtered = filtered[filtered["host"].isin(host_filter)]
if kev_only:
    filtered = filtered[filtered["in_kev"]]
filtered = filtered[filtered["risk_score"].fillna(0) >= min_score]
filtered = filtered.sort_values("risk_score", ascending=False)

# --- Ranked findings table -----------------------------------------------
st.subheader(f"Ranked action list ({len(filtered)} of {len(actionable)} findings)")
display_cols = ["risk_score", "sla_tier", "title", "host", "cve_ids", "in_kev",
                 "epss_score", "cvss_v3_score", "contributing_label", "owner",
                 "sla_due_date", "github_issue_url"]
st.dataframe(
    filtered[display_cols].rename(columns={
        "risk_score": "Score", "sla_tier": "SLA", "title": "Finding", "host": "Host",
        "cve_ids": "CVE(s)", "in_kev": "KEV", "epss_score": "EPSS",
        "cvss_v3_score": "CVSS", "contributing_label": "Found by", "owner": "Owner",
        "sla_due_date": "Due", "github_issue_url": "Ticket",
    }),
    use_container_width=True, hide_index=True, height=420,
)

# --- Finding detail: score breakdown + evidence ----------------------------
st.subheader("Finding detail")
if len(filtered):
    labels = [f"[{row.risk_score:.1f}] {row.title[:70]} — {row.host}"
              for row in filtered.itertuples()]
    selected_idx = st.selectbox("Select a finding", range(len(labels)),
                                 format_func=lambda i: labels[i])
    row = filtered.iloc[selected_idx]

    left, right = st.columns([2, 3])
    with left:
        breakdown = row["score_breakdown"]
        breakdown = json.loads(breakdown) if isinstance(breakdown, str) else breakdown
        components = {k: v for k, v in (breakdown or {}).items()
                      if k not in ("raw_total_before_clip", "final_score")}
        fig = go.Figure(go.Bar(
            x=list(components.values()), y=list(components.keys()), orientation="h",
            marker_color=SCANNER_COLORS["nuclei"],
        ))
        fig.update_layout(title="Score breakdown (points contributed)", height=280,
                           margin=dict(l=10, r=10, t=40, b=10), template="plotly_white",
                           xaxis_gridcolor=GRID, plot_bgcolor="white")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        ai_summary = clean(row["ai_summary"])
        st.markdown(f"**Why this matters:** {ai_summary or '_(AI summary not generated — set GEMINI_API_KEY)_'}")
        st.markdown(f"- **SLA:** {row['sla_tier']} — due {row['sla_due_date']}, owner {row['owner']} ({row['team']})")
        st.markdown(f"- **Found by:** {row['contributing_label']}")
        issue_url = clean(row["github_issue_url"])
        if issue_url:
            st.markdown(f"- **Ticket:** [{issue_url}]({issue_url})")
        evidence = row["raw_evidence"]
        evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
        with st.expander("Evidence"):
            st.json(evidence)
else:
    st.info("No findings match the current filters.")

# --- Severity distribution & scanner overlap --------------------------
col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Raw findings by scanner")
    raw_counts = df["source_scanner"].value_counts()
    fig = go.Figure(go.Bar(
        x=raw_counts.index, y=raw_counts.values,
        marker_color=[SCANNER_COLORS.get(s, "#898781") for s in raw_counts.index],
    ))
    fig.update_layout(height=320, template="plotly_white", plot_bgcolor="white",
                       yaxis_gridcolor=GRID, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

with col_b:
    st.subheader("Final ranked findings by SLA tier")
    tier_order = ["critical", "high", "medium", "low"]
    tier_counts = actionable["sla_tier"].value_counts().reindex(tier_order).fillna(0)
    fig = go.Figure(go.Bar(
        x=tier_counts.index, y=tier_counts.values,
        marker_color=[SLA_COLORS[t] for t in tier_order],
    ))
    fig.update_layout(height=320, template="plotly_white", plot_bgcolor="white",
                       yaxis_gridcolor=GRID, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Scanner overlap on final findings")
overlap_counts = actionable["contributing_label"].value_counts().sort_values()
fig = go.Figure(go.Bar(
    x=overlap_counts.values, y=overlap_counts.index, orientation="h",
    marker_color=INK_SECONDARY,
))
fig.update_layout(height=max(200, 40 * len(overlap_counts)), template="plotly_white",
                   plot_bgcolor="white", xaxis_gridcolor=GRID,
                   margin=dict(l=10, r=10, t=10, b=10),
                   xaxis_title="Findings", yaxis_title="Contributing scanner(s)")
st.plotly_chart(fig, use_container_width=True)

st.caption(f"Scan `{scan_id}` — dedup: {metrics.get('dedup_pct', 0)}%, "
           f"FP removed: {metrics.get('fp_removed_pct', 0)}%, "
           f"total noise reduction: {metrics.get('noise_reduction_pct', 0)}%")
