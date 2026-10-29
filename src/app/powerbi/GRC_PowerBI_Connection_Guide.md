## 1. Connection details

| Setting | Value |
| --- | --- |
| Server hostname | `<your-workspace-host>` |
| HTTP path | `/sql/1.0/warehouses/<warehouse-id>` |
| Catalog | `workspace` |
| Schemas | `grc_gold` (reporting), `grc_ref` (reference / crosswalk), `grc_silver` (drill-through only) |
| Recommended mode | DirectQuery for evidence / drill-through tables; Import for small gold tables (refresh after the daily pipeline run) |
| Authentication | Microsoft Entra ID (OAuth) recommended; personal access token for testing only |

Quick start: open `GRC_Databricks.pbids` in Power BI Desktop - it pre-fills host, HTTP path, catalog and schema. Alternatively use **Get Data > Azure Databricks / Databricks** and paste the values above, or use **Partner Connect** in Databricks to download a pre-configured file.

## 2. Tables to load

| Power BI table | Source | Grain | Mode |
| --- | --- | --- | --- |
| grc_kpi_summary | grc_gold.grc_kpi_summary | 1 row per KPI | Import |
| control_test_results | grc_gold.control_test_results | 1 row per control test | Import |
| control_health_daily | grc_gold.control_health_daily | control test x day | Import |
| compliance_posture | grc_gold.compliance_posture | framework requirement | Import |
| control_failure_narrative | grc_gold.control_failure_narrative | failing test (AI drafts) | Import |
| vuln_sla_compliance | grc_gold.vuln_sla_compliance | BU x tier x severity | Import |
| identity_risk | grc_gold.identity_risk | identity | Import |
| asset_coverage_gaps | grc_gold.asset_coverage_gaps | asset | Import |
| risk_register_scored | grc_gold.risk_register_scored | risk | Import |
| policy_lifecycle | grc_gold.policy_lifecycle | policy | Import |
| exception_tracker | grc_gold.exception_tracker | exception | Import |
| audit_evidence_index | grc_gold.audit_evidence_index | control test | Import |
| remediation_backlog | grc_gold.remediation_backlog | open work item | DirectQuery |
| control_test_evidence | grc_gold.control_test_evidence | population member per test (~51K) | DirectQuery |
| controls, business_units, frameworks, framework_requirements, control_crosswalk | grc_ref.* | dimensions | Import |

## 3. Relationships (star schema)

* `controls[control_id]` 1 -> * `control_test_results[control_id]`, `control_test_evidence[control_id]`, `control_health_daily[control_id]`, `control_crosswalk[control_id]`, `control_failure_narrative[control_id]`
* `business_units[bu_id]` 1 -> * `bu_id` on control_test_evidence, vuln_sla_compliance, identity_risk, asset_coverage_gaps, risk_register_scored, exception_tracker, remediation_backlog
* `frameworks[framework_id]` 1 -> * `framework_requirements[framework_id]`, `compliance_posture[framework_id]`
* `control_test_results[test_id]` 1 -> * `control_test_evidence[test_id]` (drill-through), 1 -> 1 `audit_evidence_index[test_id]`
* Use single-direction filtering from dimensions to facts. Do not relate `control_crosswalk` bidirectionally; use it as a bridge with `CROSSFILTER` in measures if needed.

## 4. Measures

Paste the measures from `GRC_DAX_Measures.dax`. They re-aggregate numerators / denominators so pass rates and SLA % are correct at any slice (do not average `pass_rate_pct`). Effectiveness bands: Effective >= 95%, Partially Effective 80-95%, Ineffective < 80%.

### Governed alternative: metric views

Two Unity Catalog metric views hold the same KPI logic centrally, so Power BI, AI/BI dashboards and Genie report identical numbers:

* `workspace.grc_gold.mv_grc_metrics` - control-test Population, Exceptions, Critical / Overdue Exceptions, Pass Rate Pct, Effectiveness Band, Controls Tested by test, control, domain, business unit, severity.
* `workspace.grc_gold.mv_vuln_metrics` - Findings, Open Findings, Open Past SLA, Open KEV Findings, SLA Compliance Pct, MTTR Days, Hosts With Open Findings by business unit, tier, severity, environment, internet-facing, KEV.

Query them from Power BI with a native SQL query (Advanced options) in DirectQuery, for example:

```sql
SELECT `Business Unit`, `Control Domain`,
       MEASURE(`Pass Rate Pct`) AS pass_rate_pct,
       MEASURE(`Exceptions`)    AS exceptions
FROM `workspace`.grc_gold.mv_grc_metrics
GROUP BY ALL
```

## 5. Suggested report pages

1. Executive GRC posture - KPI cards from grc_kpi_summary, framework posture bars, residual risk heatmap.
2. Control health & evidence - control_test_results matrix with band conditional formatting, control_health_daily trend, drill-through to control_test_evidence, AI narrative from control_failure_narrative.
3. Vulnerability & asset risk - SLA compliance by BU / tier, KEV exposure, assets missing EDR.
4. Identity & access - orphaned accounts, post-termination sign-ins, privileged without phishing-resistant MFA.
5. Policy, risk & exceptions - overdue policies, document-vs-register conflicts (grc_silver.policy_document_extract), expiring / expired exceptions.

## 6. Refresh and security

* The Lakeflow pipeline `GRC Security Intelligence Medallion` refreshes gold daily; schedule Power BI Import refresh after it (for example 07:00 UTC) or trigger it from the job with the Power BI task.
* Grant the Power BI service principal / users `USE CATALOG` on `workspace`, `USE SCHEMA` and `SELECT` on `grc_gold` and `grc_ref`, and `CAN USE` on the SQL warehouse.
* `control_test_evidence` and `identity_risk` contain personal data (logins, names). Apply Unity Catalog row filters / column masks rather than Power BI RLS where possible so the same rules apply in Genie and dashboards.
* AI-generated columns (control_failure_narrative, policy_document_extract) are drafts - label them as such in reports.
