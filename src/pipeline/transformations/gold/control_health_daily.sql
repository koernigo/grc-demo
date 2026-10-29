-- Gold: daily control health trend. Event-driven tests are measured per day (or per weekly scan); state-based tests contribute their as-of snapshot.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.control_health_daily (
  metric_date DATE COMMENT 'Date the control health was measured',
  test_id STRING COMMENT 'Control test id',
  control_id STRING COMMENT 'Unified control id',
  control_name STRING COMMENT 'Control name',
  control_domain STRING COMMENT 'Control domain',
  test_name STRING COMMENT 'Test name',
  measurement_basis STRING COMMENT 'daily_events (per-day events), weekly_scan (per scan date) or snapshot (as_of_date only)',
  measure_description STRING COMMENT 'What the population and exceptions represent on each date',
  population_count BIGINT COMMENT 'Population measured on metric_date',
  exception_count BIGINT COMMENT 'Exceptions on metric_date',
  pass_rate_pct DECIMAL(27,2) COMMENT 'Pass rate on metric_date',
  effectiveness_band STRING COMMENT 'Effectiveness band for the pass rate',
  effectiveness_color STRING COMMENT 'Hex color of the band',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_metric_date EXPECT (metric_date IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_test_id EXPECT (test_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_pass_rate EXPECT (pass_rate_pct IS NULL OR pass_rate_pct BETWEEN 0 AND 100)
)
COMMENT 'Gold: control health time series for trend charts. measurement_basis = daily_events (sign-ins with MFA, root logins, production changes with tickets, CloudTrail delivery per trail, EDR alert triage, incident containment - measured on each event day), weekly_scan (vulnerability SLA adherence per Tenable scan date) or snapshot (state-based tests, one row at as_of_date from grc_gold.control_test_results). Includes population, exceptions, pass rate and effectiveness band per day x test.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH win AS (
  SELECT CAST(:as_of_date AS DATE) AS as_of, date_sub(CAST(:as_of_date AS DATE), 90) AS window_start
),
mfa_daily AS (
  SELECT a.event_date AS metric_date, 'T-IAM-01' AS test_id, 'daily_events' AS measurement_basis,
         'Successful workforce sign-ins with MFA verified' AS measure_description,
         count(*) AS population_count, count_if(NOT a.mfa_verified) AS exception_count
  FROM grc_silver.authentication_event a
  JOIN grc_silver.identity i ON a.user_id = i.user_id
  CROSS JOIN win
  WHERE a.result = 'SUCCESS' AND i.user_type = 'workforce' AND a.event_date BETWEEN win.window_start AND win.as_of
  GROUP BY a.event_date
),
event_tests AS (
  SELECT to_date(e.observed_ts) AS metric_date, e.test_id, 'daily_events' AS measurement_basis,
         CASE e.test_id
           WHEN 'T-IAM-07' THEN 'Root console logins with MFA and change ticket'
           WHEN 'T-CFG-02' THEN 'Production IAM/infra changes with approved change ticket'
           WHEN 'T-LOG-02' THEN 'EDR alerts triaged within severity SLA'
           WHEN 'T-IR-01' THEN 'Incidents contained within SLA with PIR (by declared date)'
         END AS measure_description,
         count(*) AS population_count, count_if(e.is_exception) AS exception_count
  FROM grc_gold.control_test_evidence e
  CROSS JOIN win
  WHERE e.test_id IN ('T-IAM-07', 'T-CFG-02', 'T-LOG-02', 'T-IR-01')
    AND to_date(e.observed_ts) BETWEEN win.window_start AND win.as_of
  GROUP BY to_date(e.observed_ts), e.test_id
),
trails AS (
  SELECT account_id, region FROM grc_silver.cloud_config WHERE resource_kind = 'CloudTrail Trail'
),
ct_days AS (
  SELECT DISTINCT event_date, account_id, region
  FROM grc_silver.security_event
  WHERE event_source_system = 'aws_cloudtrail'
),
days AS (
  SELECT explode(sequence(win.window_start, win.as_of, INTERVAL 1 DAY)) AS metric_date FROM win
),
log_daily AS (
  SELECT d.metric_date, 'T-LOG-01' AS test_id, 'daily_events' AS measurement_basis,
         'CloudTrail trails (account x region) delivering events that day' AS measure_description,
         count(*) AS population_count, count_if(c.account_id IS NULL) AS exception_count
  FROM days d
  CROSS JOIN trails t
  LEFT JOIN ct_days c ON c.event_date = d.metric_date AND c.account_id = t.account_id AND c.region = t.region
  WHERE d.metric_date >= (SELECT min(event_date) FROM ct_days)
  GROUP BY d.metric_date
),
vuln_weekly AS (
  SELECT t.scan_date AS metric_date, 'T-VUL-02' AS test_id, 'weekly_scan' AS measurement_basis,
         'Findings on scan within severity x tier SLA (age at scan date)' AS measure_description,
         count(*) AS population_count,
         count_if(t.state = 'Active' AND datediff(t.scan_date, t.first_found) > f.sla_days) AS exception_count
  FROM grc_bronze.tenable_vuln_export t
  JOIN grc_silver.vulnerability_finding f ON lower(t.hostname) = lower(f.hostname) AND t.cve = f.cve
  CROSS JOIN win
  WHERE t.scan_date BETWEEN win.window_start AND win.as_of
  GROUP BY t.scan_date
),
kev_weekly AS (
  SELECT t.scan_date AS metric_date, 'T-VUL-03' AS test_id, 'weekly_scan' AS measurement_basis,
         'KEV findings on scan open no more than 14 days' AS measure_description,
         count(*) AS population_count,
         count_if(t.state = 'Active' AND datediff(t.scan_date, t.first_found) > 14) AS exception_count
  FROM grc_bronze.tenable_vuln_export t
  CROSS JOIN win
  WHERE t.cisa_kev AND t.scan_date BETWEEN win.window_start AND win.as_of
  GROUP BY t.scan_date
),
snap AS (
  SELECT test_run_date AS metric_date, test_id, 'snapshot' AS measurement_basis,
         concat(test_population, ' - ', pass_condition) AS measure_description,
         population_count, exception_count
  FROM grc_gold.control_test_results
  WHERE test_id NOT IN ('T-IAM-01', 'T-IAM-07', 'T-CFG-02', 'T-LOG-01', 'T-LOG-02', 'T-IR-01', 'T-VUL-02', 'T-VUL-03')
),
u AS (
  SELECT * FROM mfa_daily
  UNION ALL SELECT * FROM event_tests
  UNION ALL SELECT * FROM log_daily
  UNION ALL SELECT * FROM vuln_weekly
  UNION ALL SELECT * FROM kev_weekly
  UNION ALL SELECT * FROM snap
),
m AS (
  SELECT u.*, round(100.0 * (population_count - exception_count) / nullif(population_count, 0), 2) AS pass_rate_pct
  FROM u
)
SELECT
  m.metric_date,
  m.test_id,
  cat.control_id,
  c.control_name,
  c.control_domain,
  cat.test_name,
  m.measurement_basis,
  m.measure_description,
  m.population_count,
  m.exception_count,
  m.pass_rate_pct,
  coalesce(b.status, 'Not Tested') AS effectiveness_band,
  b.color_hex AS effectiveness_color,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM m
JOIN grc_ref.control_test_catalog cat ON m.test_id = cat.test_id
JOIN grc_ref.controls c ON cat.control_id = c.control_id
LEFT JOIN grc_ref.control_effectiveness_bands b
  ON m.pass_rate_pct >= b.min_pass_pct
 AND (m.pass_rate_pct < b.max_pass_pct OR b.max_pass_pct >= 100);
