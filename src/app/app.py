"""GRC Control Center - ACME Corp

A Databricks App that showcases an end-to-end GRC (Governance, Risk & Compliance)
security intelligence solution built on the Databricks Data Intelligence Platform:

  sources -> Lakeflow Spark Declarative Pipeline (bronze/silver/gold + AI enrichment)
          -> Unity Catalog metric views -> AI/BI dashboard + Genie -> this app
"""
import os
import time
import itertools
from datetime import datetime, timezone, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.sql import StatementState

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# All values are injected by the bundle (resources/grc_app.app.yml) - no workspace-specific defaults.
WAREHOUSE_ID = os.getenv("DATABRICKS_WAREHOUSE_ID", "")
CATALOG = os.getenv("GRC_CATALOG", "workspace")
PIPELINE_ID = os.getenv("GRC_PIPELINE_ID", "")
JOB_ID = os.getenv("GRC_JOB_ID", "")
DASHBOARD_ID = os.getenv("GRC_DASHBOARD_ID", "")
GENIE_SPACE_ID = os.getenv("GENIE_SPACE_ID", "")
GENIE_SPACE_TITLE = os.getenv("GENIE_SPACE_TITLE", "GRC Security Assistant")
LLM_ENDPOINT = os.getenv("GRC_LLM_ENDPOINT", "databricks-gpt-oss-120b")
ALERT_IDS = [a for a in os.getenv("GRC_ALERT_IDS", "").split(",") if a]
WS_URL = os.getenv("WORKSPACE_URL", "").rstrip("/")
WS_ID = os.getenv("WORKSPACE_ID", "")
C = f"`{CATALOG}`"  # always backtick-quote (catalog names may contain hyphens)

NAVY, BLUE, CYAN, GREEN, ROSE, GOLD, GREY = (
    "#1F354B", "#2272B4", "#15AFDD", "#52A870", "#C85070", "#C89930", "#8A8F98")
BAND_COLORS = {"Effective": GREEN, "Partially Effective": GOLD, "Ineffective": ROSE,
               "Not Mapped": GREY}
STATUS_COLORS = {"On Target": GREEN, "Off Target": ROSE, "Monitor": GOLD}


def ws_link(path: str) -> str:
    sep = "&" if "?" in path else "?"
    return f"{WS_URL}{path}{sep}o={WS_ID}" if WS_ID else f"{WS_URL}{path}"


st.set_page_config(page_title="GRC Control Center", layout="wide")

st.markdown(f"""
<style>
  .block-container {{padding-top: 1.6rem;}}
  .hero {{background: linear-gradient(120deg, {NAVY} 0%, {BLUE} 100%); color: #F4F6F8;
          padding: 22px 28px; border-radius: 14px; margin-bottom: 14px;}}
  .hero h1 {{color: #FFFFFF; font-size: 1.9rem; margin: 0 0 4px 0;}}
  .hero p {{margin: 0; opacity: .9;}}
  .pill {{display:inline-block; padding: 2px 10px; border-radius: 999px; font-size: .75rem;
          font-weight: 600; margin-right: 6px; background: rgba(255,255,255,.18);}}
  .kpi {{background:#FFFFFF; border-radius:12px; padding:14px 16px; border:1px solid #E3E6EA;
         box-shadow: 0 1px 3px rgba(16,24,40,.06); height: 100%;}}
  .kpi .lbl {{color:#5B6573; font-size:.78rem; text-transform: uppercase; letter-spacing:.04em;}}
  .kpi .val {{color:{NAVY}; font-size:1.75rem; font-weight:700; line-height:1.2; margin:4px 0;}}
  .kpi .tgt {{color:#5B6573; font-size:.78rem;}}
  .chip {{display:inline-block; padding:1px 8px; border-radius:999px; font-size:.7rem;
          font-weight:600; color:#FFFFFF;}}
  .ai {{border-left: 4px solid {CYAN}; background:#F3FAFD; padding: 10px 14px; border-radius: 6px;
        font-size: .9rem;}}
  .ai-tag {{color:{BLUE}; font-weight:700; font-size:.72rem; text-transform:uppercase;}}
  .layer {{border-radius:10px; padding:12px 14px; color:#FFFFFF; height:100%;}}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------
@st.cache_resource
def ws() -> WorkspaceClient:
    return WorkspaceClient()


@st.cache_data(ttl=600, show_spinner=False)
def find_genie_space(title: str) -> str:
    """Look up the Genie space created by the setup job by its title (empty string if not found)."""
    try:
        token = None
        while True:
            q = {"page_size": 100}
            if token:
                q["page_token"] = token
            r = ws().api_client.do("GET", "/api/2.0/genie/spaces", query=q)
            for s in r.get("spaces", []):
                if s.get("title") == title:
                    return s["space_id"]
            token = r.get("next_page_token")
            if not token:
                return ""
    except Exception:
        return ""


if not GENIE_SPACE_ID:
    GENIE_SPACE_ID = find_genie_space(GENIE_SPACE_TITLE)
if not WS_ID:
    try:
        WS_ID = str(ws().get_workspace_id())
    except Exception:
        WS_ID = ""


_NUMERIC = {"INT", "LONG", "SHORT", "BYTE", "DOUBLE", "FLOAT", "DECIMAL"}


def run_sql(statement: str) -> pd.DataFrame:
    w = ws()
    r = w.statement_execution.execute_statement(
        warehouse_id=WAREHOUSE_ID, statement=statement, wait_timeout="50s")
    while r.status and r.status.state in (StatementState.PENDING, StatementState.RUNNING):
        time.sleep(1.5)
        r = w.statement_execution.get_statement(r.statement_id)
    if r.status.state != StatementState.SUCCEEDED:
        msg = r.status.error.message if r.status.error else str(r.status.state)
        raise RuntimeError(msg)
    cols = r.manifest.schema.columns
    rows = (r.result.data_array or []) if r.result else []
    df = pd.DataFrame(rows, columns=[c.name for c in cols])
    for c in cols:
        if c.type_name and c.type_name.value in _NUMERIC:
            df[c.name] = pd.to_numeric(df[c.name], errors="coerce")
    return df


@st.cache_data(ttl=300, show_spinner=False)
def q(statement: str) -> pd.DataFrame:
    return run_sql(statement)


def safe_q(statement: str) -> pd.DataFrame | None:
    try:
        return q(statement)
    except Exception as e:  # noqa: BLE001
        st.warning(f"Query failed: {e}")
        return None


def ms_to_dt(ms) -> datetime | None:
    if ms in (None, ""):
        return None
    return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)


def ago(dt: datetime | None) -> str:
    if not dt:
        return "n/a"
    s = (datetime.now(timezone.utc) - dt).total_seconds()
    if s < 90:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    if s < 86400:
        return f"{s / 3600:.1f} h ago"
    return f"{s / 86400:.1f} days ago"


def fmt_kpi(value, unit) -> str:
    if value is None or pd.isna(value):
        return "n/a"
    u = (unit or "").lower()
    if "usd" in u or "$" in u:
        v = float(value)
        return f"${v / 1e6:.1f}M" if abs(v) >= 1e6 else f"${v / 1e3:.0f}K" if abs(v) >= 1e3 else f"${v:,.0f}"
    if "%" in u or "pct" in u or "percent" in u:
        return f"{float(value):.1f}%"
    if "day" in u or "hour" in u:
        return f"{float(value):,.1f} {unit}"
    v = float(value)
    return f"{v:,.0f}" if v.is_integer() else f"{v:,.2f}"


def kpi_card(label, value, sub="", status=None):
    chip = ""
    if status:
        chip = f'<span class="chip" style="background:{STATUS_COLORS.get(status, GREY)}">{status}</span>'
    st.markdown(f'<div class="kpi"><div class="lbl">{label}</div><div class="val">{value}</div>'
                f'<div class="tgt">{sub} {chip}</div></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
kpis = safe_q(f"SELECT * FROM {C}.grc_gold.grc_kpi_summary ORDER BY kpi_domain, kpi_id")
as_of = str(kpis["as_of_date"].iloc[0]) if kpis is not None and len(kpis) else "n/a"

st.markdown(f"""
<div class="hero">
  <span class="pill">ACME Corp</span><span class="pill">Data as of {as_of}</span>
  <span class="pill">NIST CSF 2.0 | ISO 27001 | SOC 2 | CIS v8</span>
  <h1>GRC Control Center</h1>
  <p>Continuous control monitoring, risk and compliance posture - from raw security telemetry to
     audit-ready evidence, governed in Unity Catalog and enriched with AI.</p>
</div>
""", unsafe_allow_html=True)

tab_overview, tab_dash, tab_pipe, tab_genie, tab_build = st.tabs(
    ["Executive Overview", "AI/BI Dashboard", "Pipeline & Data Health", "Ask Genie", "How It's Built"])

# ---------------------------------------------------------------------------
# Tab 1 - Executive overview
# ---------------------------------------------------------------------------
with tab_overview:
    if kpis is not None and len(kpis):
        hero_ids = ["KPI-CTL-01", "KPI-CTL-03", "KPI-VUL-03", "KPI-IAM-01", "KPI-GOV-04"]
        hero = kpis[kpis["kpi_id"].isin(hero_ids)].set_index("kpi_id").reindex(hero_ids).dropna(how="all")
        cols = st.columns(max(len(hero), 1))
        for col, (kid, r) in zip(cols, hero.iterrows()):
            with col:
                tgt = "" if pd.isna(r.get("target_value")) else f"Target {fmt_kpi(r['target_value'], r['unit'])}"
                kpi_card(r["kpi_name"], fmt_kpi(r["kpi_value"], r["unit"]), tgt, r.get("kpi_status"))

        st.write("")
        off = kpis[kpis["kpi_status"] == "Off Target"]
        on = kpis[kpis["kpi_status"] == "On Target"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("KPIs tracked", len(kpis))
        m2.metric("Off target", len(off))
        m3.metric("On target", len(on))
        m4.metric("Domains", kpis["kpi_domain"].nunique())

    c1, c2 = st.columns([1.25, 1])
    with c1:
        st.subheader("Framework posture")
        post = safe_q(f"""
            SELECT framework_name, requirement_status, COUNT(*) AS requirements,
                   MAX(framework_requirements_effective_pct) AS effective_pct
            FROM {C}.grc_gold.compliance_posture GROUP BY ALL""")
        if post is not None and len(post):
            fig = px.bar(post, x="requirements", y="framework_name", color="requirement_status",
                         orientation="h", color_discrete_map=BAND_COLORS,
                         category_orders={"requirement_status": list(BAND_COLORS)})
            fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0), legend_title=None,
                              yaxis_title=None, xaxis_title="Requirements", barmode="stack")
            st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.subheader("Residual risk heatmap (open risks)")
        rk = safe_q(f"""
            SELECT likelihood, impact, COUNT(*) AS risks, SUM(residual_ale_usd) AS ale
            FROM {C}.grc_gold.risk_register_scored WHERE is_open GROUP BY ALL""")
        if rk is not None and len(rk):
            grid = (rk.pivot_table(index="impact", columns="likelihood", values="risks", aggfunc="sum")
                      .reindex(index=[5, 4, 3, 2, 1], columns=[1, 2, 3, 4, 5]).fillna(0))
            fig = go.Figure(go.Heatmap(z=grid.values, x=[str(c) for c in grid.columns],
                                       y=[str(i) for i in grid.index], text=grid.values.astype(int),
                                       texttemplate="%{text}", colorscale=[[0, "#EEF3F8"], [.5, GOLD], [1, ROSE]],
                                       showscale=False))
            fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                              xaxis_title="Likelihood", yaxis_title="Impact")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Where to act now")
    a1, a2, a3 = st.columns(3)
    with a1:
        st.markdown("**Ineffective controls**")
        ctl = safe_q(f"""
            SELECT control_id, control_name, ROUND(pass_rate_pct, 1) AS pass_rate_pct, exception_count
            FROM {C}.grc_gold.control_test_results WHERE effectiveness_band = 'Ineffective'
            ORDER BY pass_rate_pct""")
        if ctl is not None:
            st.dataframe(ctl, hide_index=True, use_container_width=True, height=300)
    with a2:
        st.markdown("**Exceptions expired but still active**")
        exc = safe_q(f"""
            SELECT exception_id, exception_title, bu_name, days_past_expiry
            FROM {C}.grc_gold.exception_tracker WHERE tracker_state = 'Expired - Still Active'
            ORDER BY days_past_expiry DESC""")
        if exc is not None:
            st.dataframe(exc, hide_index=True, use_container_width=True, height=300)
    with a3:
        st.markdown("**Highest-risk identities**")
        idr = safe_q(f"""
            SELECT login, bu_name, risk_level, risk_score, array_join(risk_flags, ', ') AS flags
            FROM {C}.grc_gold.identity_risk WHERE risk_level IN ('Critical','High')
            ORDER BY risk_score DESC LIMIT 25""")
        if idr is not None:
            st.dataframe(idr, hide_index=True, use_container_width=True, height=300)

    st.subheader("AI control-failure narratives")
    st.caption("Generated in the pipeline with ai_query() on a foundation model. Drafts for human review.")
    nar = safe_q(f"""
        SELECT test_id, control_name, effectiveness_band, pass_rate_pct, owner_narrative,
               auditor_commentary, array_join(recommended_actions, ' || ') AS actions
        FROM {C}.grc_gold.control_failure_narrative
        WHERE owner_narrative IS NOT NULL ORDER BY pass_rate_pct LIMIT 6""")
    if nar is not None:
        for _, r in nar.iterrows():
            with st.expander(f"{r['test_id']} | {r['control_name']} | {r['effectiveness_band']} "
                             f"({float(r['pass_rate_pct']):.1f}% pass)"):
                x, y = st.columns(2)
                x.markdown(f'<div class="ai"><div class="ai-tag">Owner narrative (AI draft)</div>'
                           f'{r["owner_narrative"]}</div>', unsafe_allow_html=True)
                y.markdown(f'<div class="ai"><div class="ai-tag">Auditor commentary (AI draft)</div>'
                           f'{r["auditor_commentary"]}</div>', unsafe_allow_html=True)
                st.markdown("**Recommended actions**")
                for act in str(r["actions"] or "").split(" || "):
                    if act.strip():
                        st.markdown(f"- {act.strip()}")

    if kpis is not None and len(kpis):
        with st.expander("Full KPI scorecard"):
            st.dataframe(kpis[["kpi_id", "kpi_domain", "kpi_name", "kpi_value", "unit", "target_value",
                               "target_direction", "kpi_status", "related_control_id"]],
                         hide_index=True, use_container_width=True)

# ---------------------------------------------------------------------------
# Tab 2 - Embedded AI/BI dashboard
# ---------------------------------------------------------------------------
with tab_dash:
    st.subheader("GRC Security Intelligence - AI/BI dashboard")
    b1, b2, b3 = st.columns([1, 1, 3])
    b1.link_button("Open published dashboard", ws_link(f"/dashboardsv3/{DASHBOARD_ID}/published"))
    b2.link_button("Open draft (edit)", ws_link(f"/dashboardsv3/{DASHBOARD_ID}"))
    b3.caption("6 pages: Executive posture | Control health & evidence | Vulnerability & asset risk | "
               "Identity & access | Policy, risk & exceptions | Physical security. "
               "Published with embedded credentials.")
    components.iframe(ws_link(f"/embed/dashboardsv3/{DASHBOARD_ID}"), height=1150, scrolling=True)
    st.caption("If the frame is blank, a workspace admin needs to allow dashboard embedding for "
               "*.databricksapps.com (Settings > Security > Embed dashboards), and you must be signed in "
               "to the workspace in this browser.")

# ---------------------------------------------------------------------------
# Tab 3 - Pipeline & data health
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60, show_spinner=False)
def pipeline_info():
    w = ws()
    p = w.pipelines.get(PIPELINE_ID)
    ups = w.pipelines.list_updates(PIPELINE_ID, max_results=15).updates or []
    events = list(itertools.islice(w.pipelines.list_pipeline_events(PIPELINE_ID, max_results=250), 600))
    return p, ups, events


@st.cache_data(ttl=60, show_spinner=False)
def job_info():
    w = ws()
    job = w.jobs.get(int(JOB_ID))
    runs = list(itertools.islice(w.jobs.list_runs(job_id=int(JOB_ID), limit=10), 10))
    return job, runs


def next_daily_run(hour_utc=6) -> datetime:
    now = datetime.now(timezone.utc)
    nxt = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    return nxt if nxt > now else nxt + timedelta(days=1)


with tab_pipe:
    st.subheader("GRC Security Intelligence Medallion pipeline")
    try:
        p, ups, events = pipeline_info()
        last = ups[0] if ups else None
        last_dt = ms_to_dt(last.creation_time) if last else None
        states = [u.state.value if u.state else "" for u in ups]
        success_rate = (sum(s == "COMPLETED" for s in states) / len(states) * 100) if states else 0

        k1, k2, k3, k4, k5 = st.columns(5)
        with k1:
            kpi_card("Pipeline state", p.state.value if p.state else "n/a")
        with k2:
            kpi_card("Last update", last.state.value if last and last.state else "n/a", ago(last_dt))
        with k3:
            kpi_card("Health", p.health.value if getattr(p, "health", None) else "n/a", "pipeline health")
        with k4:
            kpi_card("Update success", f"{success_rate:.0f}%", f"last {len(states)} updates")
        with k5:
            kpi_card("Next scheduled refresh", next_daily_run().strftime("%b %d %H:%M UTC"), "daily job, 06:00 UTC")

        st.write("")
        l1, l2, l3, l4 = st.columns(4)
        l1.link_button("Pipeline editor", ws_link(f"/pipelines/{PIPELINE_ID}"))
        if last:
            l2.link_button("Latest update graph", ws_link(f"/pipelines/{PIPELINE_ID}/updates/{last.update_id}"))
        if JOB_ID:
            l3.link_button("Refresh job", ws_link(f"/jobs/{JOB_ID}"))
        l4.link_button("Gold schema in Catalog", ws_link(f"/explore/data/{CATALOG}/grc_gold"))

        u1, u2 = st.columns([1, 1])
        with u1:
            st.markdown("**Update history**")
            hist = pd.DataFrame([{
                "started (UTC)": ms_to_dt(u.creation_time).strftime("%Y-%m-%d %H:%M") if u.creation_time else "",
                "state": u.state.value if u.state else "",
                "cause": u.cause.value if u.cause else "",
                "full refresh": bool(u.full_refresh),
                "link": ws_link(f"/pipelines/{PIPELINE_ID}/updates/{u.update_id}"),
            } for u in ups])
            st.dataframe(hist, hide_index=True, use_container_width=True,
                         column_config={"link": st.column_config.LinkColumn("open", display_text="view")})
        with u2:
            st.markdown("**Latest update - flow progress**")
            if last:
                lev = [e for e in events if e.origin and e.origin.update_id == last.update_id]
                flows = {}
                for e in reversed(lev):  # chronological
                    if e.event_type == "flow_progress" and e.origin.flow_name:
                        msg = e.message or ""
                        status = next((s for s in ("COMPLETED", "FAILED", "RUNNING", "STARTING", "QUEUED",
                                                   "PLANNING", "SKIPPED", "EXCLUDED") if s in msg.upper()), "")
                        if status:
                            flows[e.origin.flow_name.split(".")[-1].strip("`")] = status
                if flows:
                    fdf = pd.DataFrame(sorted(flows.items()), columns=["flow", "status"])
                    cnt = fdf["status"].value_counts().reset_index()
                    cnt.columns = ["status", "flows"]
                    fig = px.bar(cnt, x="flows", y="status", orientation="h", color="status",
                                 color_discrete_map={"COMPLETED": GREEN, "FAILED": ROSE, "RUNNING": CYAN,
                                                     "SKIPPED": GREY, "EXCLUDED": GREY})
                    fig.update_layout(height=180, margin=dict(l=0, r=0, t=0, b=0), showlegend=False,
                                      yaxis_title=None)
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(fdf, hide_index=True, use_container_width=True, height=220)
                else:
                    st.info("No flow events found for the latest update.")

        issues = [e for e in events if e.level and e.level.value in ("ERROR", "WARN")][:20]
        with st.expander(f"Warnings & errors in recent events ({len(issues)})"):
            if issues:
                st.dataframe(pd.DataFrame([{"time": e.timestamp, "level": e.level.value,
                                            "type": e.event_type, "message": e.message} for e in issues]),
                             hide_index=True, use_container_width=True)
            else:
                st.success("No warnings or errors in recent pipeline events.")
    except Exception as e:  # noqa: BLE001
        st.error(f"Could not read pipeline status: {e}. Grant the app service principal CAN VIEW on the pipeline.")

    st.divider()
    st.subheader("Orchestration - daily refresh job")
    if JOB_ID:
        try:
            job, runs = job_info()
            j1, j2 = st.columns([2, 1])
            with j1:
                rdf = pd.DataFrame([{
                    "run": r.run_id,
                    "started (UTC)": ms_to_dt(r.start_time).strftime("%Y-%m-%d %H:%M") if r.start_time else "",
                    "duration (min)": round((r.run_duration or 0) / 60000, 1),
                    "lifecycle": r.state.life_cycle_state.value if r.state and r.state.life_cycle_state else "",
                    "result": r.state.result_state.value if r.state and r.state.result_state else "",
                    "trigger": r.trigger.value if r.trigger else "",
                    "link": r.run_page_url,
                } for r in runs])
                if len(rdf):
                    st.dataframe(rdf, hide_index=True, use_container_width=True,
                                 column_config={"link": st.column_config.LinkColumn("open", display_text="view")})
                else:
                    st.info("The job has not run yet - the first scheduled run is 06:00 UTC.")
            with j2:
                sched = job.settings.schedule
                st.markdown(f"**{job.settings.name}**")
                if sched:
                    st.caption(f"Schedule: `{sched.quartz_cron_expression}` ({sched.timezone_id}), "
                               f"{sched.pause_status.value if sched.pause_status else ''}")
                confirm = st.checkbox("I want to trigger a pipeline refresh now")
                if st.button("Run refresh now", type="primary", disabled=not confirm):
                    run = ws().jobs.run_now(job_id=int(JOB_ID))
                    st.success(f"Triggered run {run.run_id}.")
                    job_info.clear()
                    pipeline_info.clear()
        except Exception as e:  # noqa: BLE001
            st.error(f"Could not read job status: {e}")

    st.divider()
    st.subheader("Data freshness by layer")
    fresh = safe_q(f"""
        SELECT table_schema AS layer, table_name, table_type, last_altered, comment
        FROM {C}.information_schema.tables
        WHERE table_schema IN ('grc_bronze','grc_silver','grc_gold')
        ORDER BY layer, table_name""")
    if fresh is not None and len(fresh):
        fresh["last_altered"] = pd.to_datetime(fresh["last_altered"], errors="coerce", utc=True)
        summ = fresh.groupby("layer").agg(objects=("table_name", "count"),
                                          latest=("last_altered", "max"),
                                          oldest=("last_altered", "min")).reset_index()
        cols = st.columns(len(summ))
        palette = {"grc_bronze": "#A0703A", "grc_silver": "#7A8794", "grc_gold": GOLD}
        for col, (_, r) in zip(cols, summ.iterrows()):
            col.markdown(f'<div class="layer" style="background:{palette.get(r.layer, BLUE)}">'
                         f'<b>{r.layer.replace("grc_", "").upper()}</b><br>{r.objects} objects<br>'
                         f'latest refresh {ago(r.latest.to_pydatetime() if pd.notna(r.latest) else None)}</div>',
                         unsafe_allow_html=True)
        st.write("")
        st.dataframe(fresh, hide_index=True, use_container_width=True, height=360)

# ---------------------------------------------------------------------------
# Tab 4 - Genie
# ---------------------------------------------------------------------------
def genie_result_df(space_id, conv_id, msg_id, att_id):
    w = ws()
    fn = getattr(w.genie, "get_message_attachment_query_result", None) or \
        getattr(w.genie, "get_message_query_result_by_attachment")
    res = fn(space_id, conv_id, msg_id, att_id)
    sr = res.statement_response
    cols = [c.name for c in sr.manifest.schema.columns]
    rows = (sr.result.data_array or []) if sr.result else []
    return pd.DataFrame(rows, columns=cols)


def ask_genie(question: str):
    w = ws()
    conv_id = st.session_state.get("genie_conv")
    if conv_id:
        msg = w.genie.create_message_and_wait(GENIE_SPACE_ID, conv_id, question)
    else:
        msg = w.genie.start_conversation_and_wait(GENIE_SPACE_ID, question)
        st.session_state["genie_conv"] = msg.conversation_id
    out = {"role": "assistant", "text": "", "sql": None, "df": None}
    for att in msg.attachments or []:
        if att.text and att.text.content:
            out["text"] += att.text.content + "\n\n"
        if att.query:
            out["text"] += (att.query.description or "") + "\n\n"
            out["sql"] = att.query.query
            try:
                out["df"] = genie_result_df(GENIE_SPACE_ID, msg.conversation_id, msg.id, att.attachment_id)
            except Exception as e:  # noqa: BLE001
                out["text"] += f"_(could not fetch result: {e})_"
    if not out["text"] and msg.error:
        out["text"] = f"Genie error: {msg.error}"
    return out


def render_msg(m):
    with st.chat_message(m["role"]):
        st.markdown(m["text"] or "_(no text)_")
        if m.get("sql"):
            with st.expander("Generated SQL"):
                st.code(m["sql"], language="sql")
        if m.get("df") is not None:
            st.dataframe(m["df"], hide_index=True, use_container_width=True)


with tab_genie:
    g1, g2 = st.columns([3, 1])
    g1.subheader("Ask the GRC Security Assistant")
    g1.caption("Natural-language questions over the governed gold/silver tables via the Genie Conversation API.")
    g2.link_button("Open in Genie", ws_link(f"/genie/rooms/{GENIE_SPACE_ID}"))
    if g2.button("New conversation"):
        st.session_state.pop("genie_conv", None)
        st.session_state["genie_msgs"] = []
    st.session_state.setdefault("genie_msgs", [])

    samples = ["Which key controls are ineffective and who owns them?",
               "How many orphaned accounts signed in after termination, by business unit?",
               "Show open KEV findings past SLA on Tier 0 assets",
               "Which policy exceptions expired but are still active?"]
    sc = st.columns(len(samples))
    picked = None
    for col, s in zip(sc, samples):
        if col.button(s, use_container_width=True):
            picked = s

    for m in st.session_state["genie_msgs"]:
        render_msg(m)
    prompt = st.chat_input("Ask about controls, risks, vulnerabilities, identities...") or picked
    if prompt:
        user_m = {"role": "user", "text": prompt}
        st.session_state["genie_msgs"].append(user_m)
        render_msg(user_m)
        with st.spinner("Genie is thinking..."):
            try:
                ans = ask_genie(prompt)
            except Exception as e:  # noqa: BLE001
                ans = {"role": "assistant", "text": f"Genie request failed: {e}", "sql": None, "df": None}
        st.session_state["genie_msgs"].append(ans)
        render_msg(ans)

# ---------------------------------------------------------------------------
# Tab 5 - How it's built
# ---------------------------------------------------------------------------
with tab_build:
    st.subheader("Architecture")
    st.graphviz_chart("""
    digraph G {
      rankdir=LR; bgcolor="transparent"; node [shape=box style="rounded,filled" fontname=Helvetica fontsize=11 color="#1F354B" fontcolor="#1F354B"];
      subgraph cluster_src { label="Sources (simulated in a UC Volume)"; color="#C8CDD3"; fontname=Helvetica;
        node [fillcolor="#EEF3F8"];
        hr [label="Workday HR"]; okta [label="Okta IdP"]; snow [label="ServiceNow\\nCMDB / incidents"];
        aws [label="AWS CloudTrail\\n& config"]; ten [label="Tenable vulns"]; cs [label="CrowdStrike EDR"];
        lms [label="LMS training"]; tprm [label="TPRM vendors"]; sp [label="SharePoint\\npolicies (PDF)"];
        nas [label="On-prem NAS\\nbadge & visitor logs"]; }
      lfc [label="Lakeflow Connect\\nmanaged SaaS, file & SFTP\\nconnectors / Auto Loader" fillcolor="#2272B4" fontcolor="white"];
      bronze [label="Bronze\\n24 streaming tables\\nread_files / Auto Loader" fillcolor="#E8D3BC"];
      silver [label="Silver\\nconformed entities, SCD2\\nai_parse_document / ai_extract\\nai_classify" fillcolor="#DDE2E7"];
      gold [label="Gold\\ncontrol tests & evidence,\\nposture, risk, KPIs\\nai_query narratives" fillcolor="#F1E2B8"];
      mv [label="UC metric views\\nmv_grc_metrics\\nmv_vuln_metrics" fillcolor="#D6E9F5"];
      dash [label="AI/BI dashboard" fillcolor="#D6E9F5"]; genie [label="Genie space" fillcolor="#D6E9F5"];
      alerts [label="SQL alerts" fillcolor="#D6E9F5"]; pbi [label="Power BI\\n(DirectQuery / Import)" fillcolor="#D6E9F5"];
      app [label="GRC Control Center\\n(Databricks App)" fillcolor="#1F354B" fontcolor="white"];
      {hr okta snow aws ten cs lms tprm sp nas} -> lfc -> bronze -> silver -> gold -> mv;
      gold -> {genie alerts pbi}; mv -> {dash pbi}; {dash genie gold} -> app;
      job [label="Lakeflow Job\\ndaily 06:00 UTC" shape=ellipse fillcolor="#FFFFFF"]; job -> bronze [style=dashed];
    }""", use_container_width=True)

    st.subheader("Solution components")
    comps = [
        ("Lakeflow Connect", "Ingestion layer: managed connectors (Workday, ServiceNow, SharePoint, CrowdStrike), "
         "SFTP connector and Auto Loader for file drops - simulated here via a UC volume",
         "https://docs.databricks.com/aws/en/ingestion/overview/"),
        ("Lakeflow Spark Declarative Pipeline", "Bronze/silver/gold in SQL, serverless, triggered; AI enrichment inline",
         ws_link(f"/pipelines/{PIPELINE_ID}")),
        ("Lakeflow Job", "Daily orchestration of the pipeline refresh", ws_link(f"/jobs/{JOB_ID}") if JOB_ID else ""),
        ("Unity Catalog - gold", "Governed, commented gold tables and metric views",
         ws_link(f"/explore/data/{CATALOG}/grc_gold")),
        ("Unity Catalog - silver", "Conformed entities, AI-extracted policy facts, AI-classified incidents",
         ws_link(f"/explore/data/{CATALOG}/grc_silver")),
        ("Unity Catalog - reference", "Frameworks, requirements, unified controls & crosswalk, SLAs",
         ws_link(f"/explore/data/{CATALOG}/grc_ref")),
        ("AI/BI dashboard", "6-page GRC Security Intelligence dashboard (incl. Physical Security)",
         ws_link(f"/dashboardsv3/{DASHBOARD_ID}/published")),
        ("Genie space", "GRC Security Assistant - natural-language analytics",
         ws_link(f"/genie/rooms/{GENIE_SPACE_ID}")),
    ] + [(f"SQL alert {i + 1}", "KEV on T0 / root no-MFA / key controls / expired exceptions",
          ws_link(f"/sql/alerts-v2/{a}")) for i, a in enumerate(ALERT_IDS)]
    st.dataframe(pd.DataFrame(comps, columns=["component", "what it does", "link"]), hide_index=True,
                 use_container_width=True,
                 column_config={"link": st.column_config.LinkColumn("open", display_text="open")})

    st.subheader("AI functions in the pipeline")
    st.caption("All AI enrichment runs inside the Lakeflow Spark Declarative Pipeline as SQL AI Functions on "
               "every refresh. Results are stored in Unity Catalog tables; this app only reads them. "
               "AI-generated text is a draft that requires human review.")
    ai_funcs = pd.DataFrame([
        ("Parse policy PDFs", "ai_parse_document", "Built-in document parsing",
         "grc_silver.policy_document_parsed",
         "Turns each SharePoint policy PDF into structured text, tables and pages"),
        ("Extract policy facts", "ai_extract", "Built-in extraction",
         "grc_silver.policy_document_extract",
         "Owner, version, approval / next review dates, controls, remediation SLAs - compared with the "
         "Policy Register to flag conflicts (Policy page on the dashboard)"),
        ("Classify incidents", "ai_classify", "Built-in classification",
         "grc_silver.incident_classification",
         "Attack category and primary control domain per incident, with confidence and rationale "
         "(Incidents chart on the dashboard)"),
        ("Write control-failure narratives", "ai_query", f"{LLM_ENDPOINT} (Foundation Model API)",
         "grc_gold.control_failure_narrative",
         "Owner narrative, auditor commentary and 3 recommended actions per failing control test "
         "(Executive Overview tab and Control Health page)"),
    ], columns=["step", "AI function", "model", "output table", "what it produces / where it shows"])
    st.dataframe(ai_funcs, hide_index=True, use_container_width=True)
    st.markdown(
        '<div class="ai"><div class="ai-tag">Genie vs. AI Functions</div>'
        'AI Functions enrich data at pipeline time and persist the results. The <b>Ask Genie</b> tab is '
        'different: Genie answers natural-language questions live by generating SQL over the governed '
        'tables - it does not create or change any stored data.</div>', unsafe_allow_html=True)
    st.write("")

    st.subheader("Source ingestion map - Lakeflow Connect")
    st.caption("How each source would be ingested in production, and how this demo simulates it. Bronze uses "
               "the same Auto Loader engine (read_files) that powers Lakeflow Connect file and SFTP connectors, "
               "so swapping the landing path for a real connector does not change silver or gold.")
    ingest = pd.DataFrame([
        ("Workday HR (workers, terminations)", "Managed SaaS connector - Workday Reports", "Snapshot files in landing/hr"),
        ("ServiceNow (CMDB, incidents, tickets)", "Managed SaaS connector - ServiceNow", "Export files in landing/servicenow"),
        ("SharePoint policy library (PDF)", "Managed file connector - Microsoft SharePoint", "PDFs in landing/sharepoint"),
        ("CrowdStrike EDR", "Managed connector - CrowdStrike Falcon Event Stream", "Device files in landing/crowdstrike"),
        ("Okta IdP (users, sign-ins)", "Auto Loader on Okta System Log exports", "Files in landing/okta"),
        ("AWS CloudTrail & config", "Auto Loader on S3 (cloud object storage)", "Files in landing/aws"),
        ("Tenable vulnerability scans", "SFTP connector or Auto Loader on scan exports", "Files in landing/tenable"),
        ("LMS training / TPRM vendors", "SFTP connector (file drops) or Google Drive / OneDrive file connector",
         "Files in landing/lms, landing/tprm"),
        ("On-prem NAS share \\\\acme-nas01\\security (badge access, visitor log)",
         "SFTP connector on the NAS, or NAS-to-cloud sync + Auto Loader",
         "Mirrored share in volume grc_bronze.nas_share (daily LenelS2 exports, weekly visitor logs)"),
    ], columns=["source", "production ingestion (Lakeflow Connect)", "demo simulation"])
    st.dataframe(ingest, hide_index=True, use_container_width=True)

    st.subheader("Build your own - the playbook")
    st.markdown("""
1. **Model the control framework once** - frameworks, requirements and a unified control catalog with a
   crosswalk (`grc_ref`). Each control gets a machine-testable definition (population, pass condition, threshold).
2. **Land the evidence** - drop source extracts into a Unity Catalog volume or use Lakeflow Connect;
   bronze streaming tables ingest them incrementally with `read_files`.
3. **Conform in silver** - identities (SCD2), assets, vulnerabilities, events, policies, risks, exceptions.
   Use `ai_parse_document` + `ai_extract` to turn policy PDFs into facts and flag register conflicts,
   and `ai_classify` to map incidents to attack categories and control domains.
4. **Test controls in gold** - row-level evidence (`control_test_evidence`) rolls up to test results,
   framework posture, risk scoring and KPIs; `ai_query` drafts owner and auditor narratives.
5. **Serve** - metric views for consistent measures, an AI/BI dashboard, a Genie space, SQL alerts and
   Power BI - all reading the same governed tables.
6. **Productize** - wrap it in a Databricks App (this one) using the app service principal, app resources
   (SQL warehouse, job, Genie space) and the Databricks SDK. No data leaves the platform.
""")
    st.subheader("Power BI integration")
    st.caption("The same governed gold tables and metric views power Power BI - no data copies, one set of numbers.")
    pbi_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "powerbi")

    def _read(name: str) -> str:
        try:
            with open(os.path.join(pbi_dir, name), encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    pbids, dax, guide = (_read("GRC_Databricks.pbids"), _read("GRC_DAX_Measures.dax"),
                         _read("GRC_PowerBI_Connection_Guide.md"))
    p1, p2, p3 = st.columns(3)
    with p1:
        st.markdown("**1. Connect**  \nOpen the .pbids file in Power BI Desktop - host, HTTP path, "
                    "catalog and schema are pre-filled.")
        st.download_button("Download GRC_Databricks.pbids", pbids, file_name="GRC_Databricks.pbids",
                           mime="application/json", disabled=not pbids, use_container_width=True)
    with p2:
        st.markdown("**2. Model**  \nLoad the gold tables, build the star schema, then paste the DAX "
                    "measure library.")
        st.download_button("Download GRC_DAX_Measures.dax", dax, file_name="GRC_DAX_Measures.dax",
                           mime="text/plain", disabled=not dax, use_container_width=True)
    with p3:
        st.markdown("**3. Govern**  \nOr query the UC metric views via native SQL so Power BI matches the "
                    "AI/BI dashboard and Genie exactly.")
        st.download_button("Download connection guide (.md)", guide,
                           file_name="GRC_PowerBI_Connection_Guide.md", mime="text/markdown",
                           disabled=not guide, use_container_width=True)
    if guide:
        with st.expander("Power BI connection guide", expanded=False):
            st.markdown(guide)
    if dax:
        with st.expander("DAX measure library"):
            st.code(dax, language="sql")
    st.caption("Source files are deployed with the app in the `powerbi/` folder: "
               "GRC_PowerBI_Connection_Guide.md | GRC_Databricks.pbids | GRC_DAX_Measures.dax "
               "(replace <your-workspace-host> and <warehouse-id> in the .pbids file).")

    with st.expander("How this app works"):
        st.markdown(f"""
- **Framework:** Streamlit on Databricks Apps, `databricks-sdk` for everything (no extra drivers).
- **Data:** SQL Statement Execution API on warehouse `{WAREHOUSE_ID}` against `{CATALOG}` (5-minute cache).
- **Pipeline/job status:** Pipelines and Jobs APIs (60-second cache); refresh button calls `jobs.run_now`.
- **Dashboard:** published AI/BI dashboard embedded via iframe.
- **Genie:** Genie Conversation API with follow-up messages in the same conversation.
- **Power BI:** connection file, DAX library and guide ship with the app source (`powerbi/` folder).
- **Security:** runs as the app service principal; access is governed by Unity Catalog grants and app resources.
""")
