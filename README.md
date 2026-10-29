# GRC Security Intelligence on Databricks

End-to-end Governance, Risk & Compliance (GRC) security demo packaged as a **Declarative Automation Bundle**.
It runs on **Databricks Free Edition** (serverless only) and on any Unity Catalog workspace.

ACME Corp, 5 business units, 10 simulated security sources, 90-day window 2026-07-29 .. 2026-10-27.
Controls are mapped to NIST CSF 2.0, ISO 27001:2022, SOC 2 and CIS v8.

## What gets deployed

| Resource | Bundle key | Notes |
| --- | --- | --- |
| Lakeflow Spark Declarative Pipeline | `grc_medallion` | Bronze (24 streaming tables) -> silver (conformed, SCD2, AI enrichment) -> gold (control tests, posture, risk, KPIs, physical security) |
| Job - One-time Setup | `grc_setup` | Reference data -> synthetic sources -> NAS badge / visitor files -> full pipeline run -> metric views, Genie space, app grants |
| Job - Daily Refresh | `grc_refresh` | Pipeline refresh at 06:00 UTC (**paused** by default) |
| AI/BI dashboard | `grc_dashboard` | 6 pages incl. Physical Security, published with embedded credentials |
| SQL alerts | `kev_t0`, `root_no_mfa`, `expired_exceptions`, `ineffective_key_controls` | **Paused** by default |
| Databricks App | `grc_app` | GRC Control Center (Streamlit) |
| Genie space | created by the setup job | "GRC Security Assistant" from `src/genie/grc_security_assistant_space.json` |

AI functions used in the pipeline: `ai_parse_document` (policy PDFs), `ai_extract` (policy facts vs. register),
`ai_classify` (incidents), `ai_query` with `${var.llm_endpoint}` (control-failure narratives).

## Layout

```
databricks.yml                 bundle + variables + target
resources/                     pipeline, jobs, dashboard, alerts, app
src/setup/                     00_reference_setup, 01_generate_synthetic_data (+ gen_helpers.py),
                               02_generate_nas_data, 03_semantic_layer_and_genie
src/pipeline/transformations/  bronze/ silver/ gold/ SQL
src/dashboards/                GRC Security Intelligence.lvdash.json
src/genie/                     Genie space template
src/app/                       GRC Control Center app (+ Power BI kit in powerbi/)
```

## Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `catalog` | `workspace` | Catalog for grc_bronze / grc_silver / grc_gold / grc_ref / grc_synth (Free Edition's default catalog) |
| `warehouse_name` | `Serverless Starter Warehouse` | SQL warehouse looked up by name (Free Edition's warehouse) |
| `llm_endpoint` | `databricks-gpt-oss-120b` | Foundation Model endpoint for `ai_query` |
| `as_of_date` | `2026-10-27` | Reporting date of the synthetic story |

Override at deploy time, e.g. `--var catalog=main --var warehouse_name="Shared Warehouse"`.

## Deploy to Databricks Free Edition

1. **Get the code into the workspace**: push this repo to GitHub, then in Free Edition choose
   *Workspace > Create > Git folder* and clone it.
2. **Deploy**: open the Git folder, click the **Deployments** (rocket) icon, choose target `free`, click **Deploy**.
   CLI alternative: `databricks bundle deploy -t free`.
3. **Build the data** (about 25-40 min on Free Edition): run the job **GRC Security Intelligence - One-time Setup**
   (Deployments panel > play icon, or `databricks bundle run grc_setup -t free`).
4. **Start the app** if it is not running (Compute > Apps). Free Edition stops apps after 24 h - just restart it.
5. Optional: allow dashboard embedding for the app (Settings > Security > Embed dashboards: add `*.databricksapps.com`),
   unpause the 4 alerts and the Daily Refresh job.

## Expected results (as of 2026-10-27)

* 24 controls tested, KPIs in `grc_gold.grc_kpi_summary` (40 KPIs).
* Policy PDF conflicts: POL-002 (review date) and POL-004 (30-day Critical SLA vs. 15-day standard).
* Physical security: KPI-PHY-01 = 6 people badging in after termination, KPI-PHY-02 = 4 critical-zone door alarms,
  KPI-PHY-03 = 12 unescorted restricted visits, KPI-PHY-04 = 88.75% visitor-log completeness.

## Free Edition notes

* Serverless only, one 2X-Small SQL warehouse, max 5 concurrent job tasks, one active pipeline - the setup job runs sequentially.
* If `ai_parse_document` / `ai_extract` / `ai_classify` or the chosen model are not available in your region, the pipeline
  fails on those tables; set `llm_endpoint` to an available model (Serving > Endpoints) and redeploy.
* All data is synthetic. Ground truth for the injected stories is in `grc_synth`.
