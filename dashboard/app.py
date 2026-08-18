"""Threat-X risk dashboard (Streamlit). Reads data/processed/<scan_id>/final_scored.parquet
and data/runs/<scan_id>/metrics.json for the latest pipeline run.

Palette: committed dark theme end to end (page chrome via .streamlit/config.toml,
charts here) — fixed categorical hues assigned by scanner identity (never by
rank/filter state), and the fixed status palette for SLA tiers — all from the
dataviz skill's validated default palette (references/palette.md, dark-mode
column), so hue always maps to the same entity across every chart on the page,
and nothing reads as a mismatched light card floating in a dark app.
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
from dotenv import load_dotenv

from ai.remediation import generate_remediation_guidance
from common.paths import DATA_DIR, final_scored_path, metrics_path
from ticket.github_issues import add_remediation_comment, assign_issue, get_issue_assignees
from ticket.github_issues import is_configured as github_configured

load_dotenv()

# --- Validated categorical + status palette (dataviz skill, dark-mode steps —
# matches .streamlit/config.toml's dark theme) ---
SCANNER_COLORS = {"nuclei": "#3987e5", "nmap": "#d95926", "zap": "#199e70"}  # slots 1-3
SLA_COLORS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#0ca30c"}
SURFACE = "#1a1a19"       # chart/card surface
PAGE_PLANE = "#0d0d0d"
INK_PRIMARY = "#ffffff"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRID = "#2c2c2a"
BORDER = "rgba(255,255,255,0.10)"

# Plotly's dark template gets us close, but we still set surface/grid/font
# colors explicitly per-figure below so every chart matches these exact tokens
# rather than Plotly's own built-in dark palette (which doesn't match ours).
PLOTLY_DARK = dict(template="plotly_dark", plot_bgcolor=SURFACE, paper_bgcolor=SURFACE,
                    font_color=INK_SECONDARY)

st.markdown(f"""
<style>
/* Card styling for the funnel stat tiles (st.metric) — the dataviz skill's
   stat-tile contract (label/value/delta) doesn't get a container by default
   in Streamlit, so this gives each one a surface + hairline border instead of
   floating loose on the page plane. */
div[data-testid="stMetric"] {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 16px 18px;
}}
div[data-testid="stMetricLabel"] {{ color: {INK_MUTED}; }}
div[data-testid="stMetricValue"] {{ color: {INK_PRIMARY}; }}

/* Section headers get a bit more air and a hairline rule beneath them,
   instead of running straight into the next block. */
h3 {{
    border-bottom: 1px solid {BORDER};
    padding-bottom: 8px;
    margin-top: 28px !important;
}}

/* Dataframe / table container: same surface + border as everything else. */
div[data-testid="stDataFrame"] {{
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
</style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="Threat-X Risk Dashboard", layout="wide")


@st.cache_data(ttl=20)
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


@st.cache_data(ttl=20)
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


def assignee_display(row) -> str:
    """Deliberately NOT cached, unlike load_scan() above — this needs to show
    the true current assignee immediately after you use the Assign/Unassign
    buttons below (which already call st.rerun()), not a value that could
    still be sitting in a TTL'd cache from moments before the click."""
    issue_number = clean(row["github_issue_number"])
    if not issue_number:
        return "—"
    if not github_configured():
        return "_(set GITHUB_TOKEN to see)_"
    try:
        assignees = get_issue_assignees(int(issue_number))
    except Exception:
        return "_(lookup failed)_"
    return ", ".join(assignees) if assignees else "_unassigned_"


st.title("Threat-X — Risk Prioritization Dashboard")

# Data auto-refreshes every 20s (cache TTL below), but re-running a phase from
# the CLI and wanting to see it *right now* is common enough to also want an
# on-demand escape hatch rather than waiting out the TTL.
if st.sidebar.button("🔄 Refresh data"):
    st.cache_data.clear()
    st.rerun()

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

# --- Suppressed findings (false positives / accepted risk) -----------------
# These never leave the parquet — dedup/suppress.py only flags them
# (suppressed=True + a reason), it doesn't drop rows — so nothing extra needs
# fetching here; just show the rows that already carry the flag.
suppressed_df = df[df["suppressed"] & (~df["is_duplicate"])].copy()
with st.expander(f"🔎 View suppressed findings ({len(suppressed_df)}) — false positives & accepted risk"):
    if len(suppressed_df):
        suppressed_df["contributing_label"] = suppressed_df.apply(contributing_label, axis=1)
        sup_cols = ["title", "host", "scanner_severity", "cve_ids", "contributing_label", "suppression_reason"]
        st.dataframe(
            suppressed_df[sup_cols].rename(columns={
                "title": "Finding", "host": "Host", "scanner_severity": "Severity",
                "cve_ids": "CVE(s)", "contributing_label": "Found by",
                "suppression_reason": "Why suppressed",
            }),
            use_container_width=True, hide_index=True,
            column_config={
                "Finding": st.column_config.TextColumn(width="large"),
                "Why suppressed": st.column_config.TextColumn(width="large"),
            },
        )
    else:
        st.caption("No findings were suppressed in this scan.")

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
filtered = filtered.copy()
filtered["assignee_display"] = filtered.apply(assignee_display, axis=1)
display_cols = ["risk_score", "sla_tier", "title", "host", "cve_ids", "in_kev",
                 "epss_score", "cvss_v3_score", "contributing_label", "owner",
                 "sla_due_date", "github_issue_url", "assignee_display"]
st.dataframe(
    filtered[display_cols].rename(columns={
        "risk_score": "Score", "sla_tier": "SLA", "title": "Finding", "host": "Host",
        "cve_ids": "CVE(s)", "in_kev": "KEV", "epss_score": "EPSS",
        "cvss_v3_score": "CVSS", "contributing_label": "Found by", "owner": "Owner",
        "sla_due_date": "Due", "github_issue_url": "Ticket",
        "assignee_display": "Assigned to",
    }),
    use_container_width=True, hide_index=True, height=420,
    # Explicit widths on the widest columns so the grid's own content width
    # can exceed the container instead of squeezing everything to fit —
    # that's what actually turns on horizontal scrolling within the table.
    column_config={
        "Finding": st.column_config.TextColumn(width="large"),
        "CVE(s)": st.column_config.TextColumn(width="medium"),
        "Ticket": st.column_config.TextColumn(width="medium"),
        "Assigned to": st.column_config.TextColumn(width="medium"),
    },
)

# --- Finding detail: summary + evidence/fix tabs ---------------------------
st.subheader("Finding detail")
if len(filtered):
    labels = [f"[{row.risk_score:.1f}] {row.title[:70]} — {row.host}"
              for row in filtered.itertuples()]
    selected_idx = st.selectbox("Select a finding", range(len(labels)),
                                 format_func=lambda i: labels[i])
    row = filtered.iloc[selected_idx]
    finding_id = str(row["finding_id"])

    ai_summary = clean(row["ai_summary"])
    st.markdown(f"**Why this matters:** {ai_summary or '_(AI summary not generated — set GEMINI_API_KEY)_'}")
    st.markdown(f"- **SLA:** {row['sla_tier']} — due {row['sla_due_date']}, owner {row['owner']} ({row['team']})")
    st.markdown(f"- **Found by:** {row['contributing_label']}")
    issue_url = clean(row["github_issue_url"])
    issue_number = clean(row["github_issue_number"])
    if issue_url:
        st.markdown(f"- **Ticket:** [{issue_url}]({issue_url})")

    # Collapsed by default — the chart was previously always-on and pushed
    # everything else down; it's supplementary detail, not the headline.
    with st.expander("Score breakdown (points contributed)"):
        breakdown = row["score_breakdown"]
        breakdown = json.loads(breakdown) if isinstance(breakdown, str) else breakdown
        components = {k: v for k, v in (breakdown or {}).items()
                      if k not in ("raw_total_before_clip", "final_score")}
        fig = go.Figure(go.Bar(
            x=list(components.values()), y=list(components.keys()), orientation="h",
            marker_color=SCANNER_COLORS["nuclei"],
        ))
        fig.update_layout(height=280, margin=dict(l=10, r=10, t=10, b=10),
                           xaxis_gridcolor=GRID, **PLOTLY_DARK)
        st.plotly_chart(fig, use_container_width=True)

    tab_evidence, tab_fix = st.tabs(["🔍 Evidence", "🔧 Fix"])
    with tab_evidence:
        evidence = row["raw_evidence"]
        evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
        st.json(evidence)
    with tab_fix:
        rem_key = f"remediation_res_{finding_id}"
        if st.button("🤖 How Do I Resolve This?", key=f"btn_resolve_{finding_id}"):
            with st.spinner("Analyzing vulnerability context and generating AI remediation guide..."):
                res = generate_remediation_guidance(row)
                st.session_state[rem_key] = res
                st.rerun()

        if rem_key in st.session_state:
            res = st.session_state[rem_key]
            if not res.get("success", False):
                if res.get("error_type") == "missing_api_key":
                    st.warning("AI remediation guidance is unavailable because GEMINI_API_KEY is not configured.")
                else:
                    st.error(res.get("message", "An error occurred while generating guidance."))
            else:
                st.markdown(res["markdown"])

                col_copy, col_gh = st.columns(2)
                with col_copy:
                    st.download_button(
                        label="📋 Copy Guide",
                        data=res["markdown"],
                        file_name=f"remediation_{finding_id[:8]}.md",
                        mime="text/markdown",
                        key=f"dl_rem_{finding_id}",
                    )
                with col_gh:
                    if issue_number:
                        if st.button("🐙 Add Remediation Guide to GitHub Issue", key=f"btn_gh_rem_{finding_id}"):
                            if not github_configured():
                                st.warning("Set GITHUB_TOKEN and GITHUB_REPO in .env to add comments to GitHub issues.")
                            else:
                                try:
                                    comment_url = add_remediation_comment(int(issue_number), res["markdown"])
                                    st.success(f"Added remediation guide to GitHub Issue #{int(issue_number)}: {comment_url}")
                                except Exception as e:
                                    st.error(f"Failed to post comment to GitHub: {str(e)}")
                    else:
                        st.caption("_No ticket yet for this finding — cannot post comment._")

    # --- Assign the ticket, right from here — the one write action this
    # dashboard performs; everything else on the page stays read-only. ---
    if issue_number:
        issue_number = int(issue_number)
        st.markdown("**Assign ticket**")
        if not github_configured():
            st.caption("_Set GITHUB_TOKEN/GITHUB_REPO in .env to enable assignment._")
        else:
            from github.GithubException import GithubException

            try:
                current = get_issue_assignees(issue_number)
            except GithubException as e:
                current = []
                st.caption(f"Couldn't fetch current assignees ({e.status}).")
            st.caption(f"Currently assigned: {', '.join(current) if current else '_none_'}")

            new_names = st.text_input(
                "GitHub username(s), comma-separated", key=f"assign_input_{issue_number}",
                placeholder="e.g. alice, bob",
            )
            col_assign, col_unassign = st.columns(2)
            with col_assign:
                if st.button("Assign", key=f"assign_btn_{issue_number}"):
                    usernames = [u.strip() for u in new_names.split(",") if u.strip()]
                    if not usernames:
                        st.warning("Enter at least one GitHub username first.")
                    else:
                        try:
                            assign_issue(issue_number, usernames)
                            st.success(f"Issue #{issue_number} assigned to: {', '.join(usernames)}")
                            st.rerun()
                        except GithubException as e:
                            st.error(f"GitHub API error ({e.status}): usually means that "
                                     f"username isn't a collaborator on this repo yet.")
            with col_unassign:
                if st.button("Unassign all", key=f"unassign_btn_{issue_number}"):
                    try:
                        assign_issue(issue_number, [])
                        st.success(f"Issue #{issue_number} unassigned.")
                        st.rerun()
                    except GithubException as e:
                        st.error(f"GitHub API error ({e.status}).")
    else:
        st.caption("_No ticket yet for this finding — nothing to assign._")
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
    fig.update_layout(height=320, yaxis_gridcolor=GRID,
                       margin=dict(l=10, r=10, t=10, b=10), **PLOTLY_DARK)
    st.plotly_chart(fig, use_container_width=True)

with col_b:
    st.subheader("Final ranked findings by SLA tier")
    tier_order = ["critical", "high", "medium", "low"]
    tier_counts = actionable["sla_tier"].value_counts().reindex(tier_order).fillna(0)
    fig = go.Figure(go.Bar(
        x=tier_counts.index, y=tier_counts.values,
        marker_color=[SLA_COLORS[t] for t in tier_order],
    ))
    fig.update_layout(height=320, yaxis_gridcolor=GRID,
                       margin=dict(l=10, r=10, t=10, b=10), **PLOTLY_DARK)
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Scanner overlap on final findings")
overlap_counts = actionable["contributing_label"].value_counts().sort_values()
fig = go.Figure(go.Bar(
    x=overlap_counts.values, y=overlap_counts.index, orientation="h",
    marker_color=INK_SECONDARY,
))
fig.update_layout(height=max(200, 40 * len(overlap_counts)), xaxis_gridcolor=GRID,
                   margin=dict(l=10, r=10, t=10, b=10),
                   xaxis_title="Findings", yaxis_title="Contributing scanner(s)",
                   **PLOTLY_DARK)
st.plotly_chart(fig, use_container_width=True)

st.caption(f"Scan `{scan_id}` — dedup: {metrics.get('dedup_pct', 0)}%, "
           f"FP removed: {metrics.get('fp_removed_pct', 0)}%, "
           f"total noise reduction: {metrics.get('noise_reduction_pct', 0)}%")
