-- Gold: auditor-facing index from control -> test -> evidence tables, row counts, frameworks and retrieval queries.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.audit_evidence_index (
  control_id STRING COMMENT 'Unified control id',
  control_name STRING COMMENT 'Control name',
  control_domain STRING COMMENT 'Control domain',
  owner_role STRING COMMENT 'Control owner role',
  key_control BOOLEAN COMMENT 'Key control',
  test_id STRING COMMENT 'Control test id',
  test_name STRING COMMENT 'Test name',
  test_population STRING COMMENT 'Tested population definition',
  pass_condition STRING COMMENT 'Pass condition',
  evidence_type STRING COMMENT 'Evidence type',
  catalog_source_tables STRING COMMENT 'Source tables declared in the test catalog',
  evidence_source_table STRING COMMENT 'Silver table supplying evidence rows',
  evidence_source_row_count BIGINT COMMENT 'Total rows in the evidence source table',
  evidence_detail_table STRING COMMENT 'Gold table holding row-level evidence (grc_gold.control_test_evidence)',
  population_rows BIGINT COMMENT 'Evidence rows tested from this source',
  exception_rows BIGINT COMMENT 'Exception rows from this source',
  evidence_window_start_ts TIMESTAMP COMMENT 'Earliest observed_ts in evidence',
  evidence_window_end_ts TIMESTAMP COMMENT 'Latest observed_ts in evidence',
  pass_rate_pct DECIMAL(27,2) COMMENT 'Test pass rate',
  test_result STRING COMMENT 'Pass or Fail',
  effectiveness_band STRING COMMENT 'Effectiveness band',
  frameworks ARRAY<STRING> COMMENT 'Frameworks the control maps to',
  framework_requirements ARRAY<STRING> COMMENT 'Framework requirement ids (framework:requirement)',
  population_query STRING COMMENT 'Ready-to-run SQL returning the tested population',
  exceptions_query STRING COMMENT 'Ready-to-run SQL returning the exceptions',
  test_run_date DATE COMMENT 'Control test run date (as_of_date)',
  CONSTRAINT valid_test_id EXPECT (test_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT evidence_present EXPECT (population_rows > 0)
)
COMMENT 'Gold: one row per control test x silver evidence source table. Links each unified control and test to its row-level evidence (grc_gold.control_test_evidence), the silver source table and its current row count, population / exception row counts, evidence time window, latest result and effectiveness, the framework requirements the control satisfies (grc_ref.control_crosswalk) and ready-to-run SQL to retrieve the full population and the exceptions. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH ev AS (
  SELECT test_id, source_table,
         count(*) AS population_rows,
         count_if(is_exception) AS exception_rows,
         min(observed_ts) AS evidence_window_start_ts,
         max(observed_ts) AS evidence_window_end_ts
  FROM grc_gold.control_test_evidence
  GROUP BY test_id, source_table
),
src AS (
  SELECT 'grc_silver.identity' AS source_table, count(*) AS source_row_count FROM grc_silver.identity
  UNION ALL SELECT 'grc_silver.entitlement', count(*) FROM grc_silver.entitlement
  UNION ALL SELECT 'grc_silver.asset', count(*) FROM grc_silver.asset
  UNION ALL SELECT 'grc_silver.vulnerability_finding', count(*) FROM grc_silver.vulnerability_finding
  UNION ALL SELECT 'grc_silver.security_event', count(*) FROM grc_silver.security_event
  UNION ALL SELECT 'grc_silver.cloud_config', count(*) FROM grc_silver.cloud_config
  UNION ALL SELECT 'grc_silver.remediation_ticket', count(*) FROM grc_silver.remediation_ticket
  UNION ALL SELECT 'grc_silver.training_status', count(*) FROM grc_silver.training_status
  UNION ALL SELECT 'grc_silver.vendor', count(*) FROM grc_silver.vendor
  UNION ALL SELECT 'grc_silver.policy', count(*) FROM grc_silver.policy
  UNION ALL SELECT 'grc_silver.risk', count(*) FROM grc_silver.risk
  UNION ALL SELECT 'grc_silver.risk_exception', count(*) FROM grc_silver.risk_exception
),
fw AS (
  SELECT control_id,
         array_sort(collect_set(concat(framework_id, ' ', requirement_id))) AS framework_requirements,
         array_sort(collect_set(framework_id)) AS frameworks
  FROM grc_ref.control_crosswalk
  GROUP BY control_id
)
SELECT
  r.control_id,
  r.control_name,
  r.control_domain,
  r.owner_role,
  r.key_control,
  r.test_id,
  r.test_name,
  r.test_population,
  r.pass_condition,
  r.evidence_type,
  r.catalog_source_tables,
  ev.source_table AS evidence_source_table,
  src.source_row_count AS evidence_source_row_count,
  'grc_gold.control_test_evidence' AS evidence_detail_table,
  ev.population_rows,
  ev.exception_rows,
  ev.evidence_window_start_ts,
  ev.evidence_window_end_ts,
  r.pass_rate_pct,
  r.test_result,
  r.effectiveness_band,
  fw.frameworks,
  fw.framework_requirements,
  concat('SELECT * FROM `${grc_catalog}`.grc_gold.control_test_evidence WHERE test_id = ''', r.test_id, '''') AS population_query,
  concat('SELECT * FROM `${grc_catalog}`.grc_gold.control_test_evidence WHERE test_id = ''', r.test_id, ''' AND is_exception') AS exceptions_query,
  r.test_run_date
FROM grc_gold.control_test_results r
LEFT JOIN ev ON r.test_id = ev.test_id
LEFT JOIN src ON ev.source_table = src.source_table
LEFT JOIN fw ON r.control_id = fw.control_id;
