-- Gold: vulnerability remediation SLA compliance by business unit x asset tier x severity.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.vuln_sla_compliance (
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  tier STRING COMMENT 'Asset criticality tier',
  severity STRING COMMENT 'Vulnerability severity',
  total_findings BIGINT COMMENT 'Findings (open + remediated) in the window',
  open_findings BIGINT COMMENT 'Currently open findings',
  open_past_sla BIGINT COMMENT 'Open findings past their SLA due date',
  remediated_findings BIGINT COMMENT 'Remediated findings',
  remediated_within_sla BIGINT COMMENT 'Findings remediated within SLA',
  findings_within_sla BIGINT COMMENT 'Findings not breaching SLA (open or remediated)',
  sla_compliance_pct DECIMAL(27,2) COMMENT 'findings_within_sla / total_findings x 100',
  open_kev_findings BIGINT COMMENT 'Open CISA KEV findings',
  open_kev_past_14d BIGINT COMMENT 'Open KEV findings older than the 14-day KEV SLA',
  open_internet_facing_findings BIGINT COMMENT 'Open findings on internet-facing assets',
  hosts_with_open_findings BIGINT COMMENT 'Distinct hosts with at least one open finding',
  mean_days_to_remediate DOUBLE COMMENT 'Mean days to remediate (remediated findings)',
  median_days_to_remediate INT COMMENT 'Median days to remediate',
  oldest_open_days INT COMMENT 'Age in days of the oldest open finding',
  avg_sla_days DOUBLE COMMENT 'Average effective SLA days',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_severity EXPECT (severity IN ('Critical', 'High', 'Medium', 'Low')),
  CONSTRAINT valid_compliance_pct EXPECT (sla_compliance_pct BETWEEN 0 AND 100)
)
COMMENT 'Gold: vulnerability SLA adherence (control GRC-VUL-02) by business unit, asset tier and severity over open findings plus findings remediated in the last 90 days. Includes open findings, open past SLA, remediated within SLA, SLA compliance %, CISA KEV exposure (open, open > 14 days), mean/median days to remediate, oldest open finding age and average SLA days (severity SLA x tier multiplier). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH f AS (
  SELECT *
  FROM grc_silver.vulnerability_finding
  WHERE is_open OR remediated_date >= date_sub(CAST(:as_of_date AS DATE), 90)
)
SELECT
  coalesce(f.bu_id, 'Unknown') AS bu_id,
  coalesce(b.bu_name, 'Unknown') AS bu_name,
  coalesce(f.tier, 'Unknown') AS tier,
  f.severity,
  count(*) AS total_findings,
  count_if(f.is_open) AS open_findings,
  count_if(f.is_open AND f.is_overdue) AS open_past_sla,
  count_if(NOT f.is_open) AS remediated_findings,
  count_if(NOT f.is_open AND NOT f.sla_breached) AS remediated_within_sla,
  count_if(NOT f.sla_breached) AS findings_within_sla,
  round(100.0 * count_if(NOT f.sla_breached) / count(*), 2) AS sla_compliance_pct,
  count_if(f.is_kev AND f.is_open) AS open_kev_findings,
  count_if(f.is_kev AND f.is_open AND f.days_open > 14) AS open_kev_past_14d,
  count_if(f.is_open AND f.internet_facing) AS open_internet_facing_findings,
  count(DISTINCT CASE WHEN f.is_open THEN f.hostname END) AS hosts_with_open_findings,
  round(avg(CASE WHEN NOT f.is_open THEN f.days_open END), 1) AS mean_days_to_remediate,
  percentile_approx(CASE WHEN NOT f.is_open THEN f.days_open END, 0.5) AS median_days_to_remediate,
  max(CASE WHEN f.is_open THEN f.days_open END) AS oldest_open_days,
  round(avg(f.sla_days), 1) AS avg_sla_days,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM f
LEFT JOIN grc_ref.business_units b ON f.bu_id = b.bu_id
GROUP BY ALL;
