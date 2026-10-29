-- Gold: one row per automated control test (grc_ref.control_test_catalog) with population, exceptions, pass rate and effectiveness.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.control_test_results (
  test_run_date DATE COMMENT 'Control test run date (as_of_date)',
  test_id STRING COMMENT 'Control test id (primary key)',
  control_id STRING COMMENT 'Unified control id tested',
  control_name STRING COMMENT 'Control name',
  control_domain STRING COMMENT 'Control domain (IAM, Vulnerability, Logging, ...)',
  control_description STRING COMMENT 'Control description',
  control_type STRING COMMENT 'Preventive, Detective or Corrective',
  owner_role STRING COMMENT 'Role accountable for the control',
  test_frequency STRING COMMENT 'Planned test frequency',
  automated BOOLEAN COMMENT 'True if the control test is automated',
  key_control BOOLEAN COMMENT 'True for key (SOX / audit-relied) controls',
  test_name STRING COMMENT 'Test name',
  test_population STRING COMMENT 'Definition of the tested population',
  pass_condition STRING COMMENT 'Condition each member must satisfy to pass',
  metric STRING COMMENT 'Metric reported by the test',
  evidence_type STRING COMMENT 'Evidence type (system-generated, configuration, ...)',
  catalog_source_tables STRING COMMENT 'Source tables declared in the test catalog',
  population_count BIGINT COMMENT 'Number of population members tested',
  exception_count BIGINT COMMENT 'Number of members failing the test',
  pass_count BIGINT COMMENT 'Number of members passing the test',
  pass_rate_pct DECIMAL(27,2) COMMENT 'Pass count / population count x 100',
  evidence_source_tables ARRAY<STRING> COMMENT 'Silver tables evidence rows were derived from',
  evidence_window_start_ts TIMESTAMP COMMENT 'Earliest observed_ts among evidence rows',
  evidence_window_end_ts TIMESTAMP COMMENT 'Latest observed_ts among evidence rows',
  effective_threshold_pct DOUBLE COMMENT 'Minimum pass rate for an Effective rating',
  test_result STRING COMMENT 'Pass if no exceptions or pass rate reaches the Effective threshold, else Fail',
  effectiveness_band STRING COMMENT 'Effective, Partially Effective or Ineffective (grc_ref.control_effectiveness_bands)',
  effectiveness_color STRING COMMENT 'Hex color of the effectiveness band',
  effectiveness_sort INT COMMENT 'Band sort order (1 = best)',
  evidence_query STRING COMMENT 'Ready-to-run SQL returning the exceptions for this test',
  CONSTRAINT valid_test_id EXPECT (test_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT tested_population EXPECT (population_count > 0),
  CONSTRAINT valid_pass_rate EXPECT (pass_rate_pct IS NULL OR pass_rate_pct BETWEEN 0 AND 100)
)
COMMENT 'Gold: latest result of each of the 24 automated control tests in grc_ref.control_test_catalog, aggregated from grc_gold.control_test_evidence. Includes the unified control (grc_ref.controls), test population/pass condition, population_count, exception_count, pass_rate_pct, Pass/Fail against the Effective threshold (95%), and the effectiveness band (Effective >= 95%, Partially Effective 80-95%, Ineffective < 80%; grc_ref.control_effectiveness_bands). evidence_query retrieves the failing population. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH agg AS (
  SELECT
    test_id,
    count(*) AS population_count,
    count_if(is_exception) AS exception_count,
    array_sort(collect_set(source_table)) AS evidence_source_tables,
    min(observed_ts) AS evidence_window_start_ts,
    max(observed_ts) AS evidence_window_end_ts
  FROM grc_gold.control_test_evidence
  GROUP BY test_id
),
thr AS (
  SELECT min_pass_pct AS effective_threshold_pct FROM grc_ref.control_effectiveness_bands WHERE status = 'Effective'
),
r AS (
  SELECT
    cat.test_id,
    cat.control_id,
    c.control_name,
    c.control_domain,
    c.control_description,
    c.control_type,
    c.owner_role,
    c.test_frequency,
    c.automated,
    c.key_control,
    cat.test_name,
    cat.test_population,
    cat.pass_condition,
    cat.metric,
    cat.evidence_type,
    cat.source_tables AS catalog_source_tables,
    coalesce(agg.population_count, 0) AS population_count,
    coalesce(agg.exception_count, 0) AS exception_count,
    coalesce(agg.population_count, 0) - coalesce(agg.exception_count, 0) AS pass_count,
    round(100.0 * (agg.population_count - agg.exception_count) / nullif(agg.population_count, 0), 2) AS pass_rate_pct,
    agg.evidence_source_tables,
    agg.evidence_window_start_ts,
    agg.evidence_window_end_ts,
    thr.effective_threshold_pct
  FROM grc_ref.control_test_catalog cat
  JOIN grc_ref.controls c ON cat.control_id = c.control_id
  LEFT JOIN agg ON cat.test_id = agg.test_id
  CROSS JOIN thr
)
SELECT
  CAST(:as_of_date AS DATE) AS test_run_date,
  r.*,
  CASE
    WHEN r.population_count = 0 THEN 'Not Tested'
    WHEN r.pass_rate_pct >= r.effective_threshold_pct THEN 'Pass'
    ELSE 'Fail'
  END AS test_result,
  coalesce(b.status, 'Not Tested') AS effectiveness_band,
  b.color_hex AS effectiveness_color,
  coalesce(b.sort_order, 99) AS effectiveness_sort,
  concat('SELECT * FROM `${grc_catalog}`.grc_gold.control_test_evidence WHERE test_id = ''', r.test_id, ''' AND is_exception') AS evidence_query
FROM r
LEFT JOIN grc_ref.control_effectiveness_bands b
  ON r.pass_rate_pct >= b.min_pass_pct
 AND (r.pass_rate_pct < b.max_pass_pct OR b.max_pass_pct >= 100);
