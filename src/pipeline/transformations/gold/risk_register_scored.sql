-- Gold: risk register with inherent and control-adjusted residual scores driven by linked control test results.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.risk_register_scored (
  risk_id STRING COMMENT 'Risk id (primary key)',
  risk_title STRING COMMENT 'Risk title',
  risk_category_id STRING COMMENT 'Risk category id',
  risk_category STRING COMMENT 'Risk category',
  risk_domain STRING COMMENT 'Risk domain',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  bu_risk_appetite STRING COMMENT 'Business unit risk appetite',
  owner_email STRING COMMENT 'Risk owner email',
  has_owner BOOLEAN COMMENT 'Risk owner assigned',
  likelihood INT COMMENT 'Likelihood 1-5',
  impact INT COMMENT 'Impact 1-5',
  inherent_score INT COMMENT 'Inherent score (likelihood x impact)',
  inherent_rating STRING COMMENT 'Inherent rating band',
  inherent_rating_color STRING COMMENT 'Hex color of inherent rating',
  linked_controls ARRAY<STRING> COMMENT 'Mitigating unified control ids',
  linked_control_count BIGINT COMMENT 'Linked controls with test results',
  avg_linked_control_pass_rate_pct DECIMAL(28,2) COMMENT 'Average pass rate of linked control tests',
  effective_linked_controls BIGINT COMMENT 'Linked controls rated Effective',
  partially_effective_linked_controls BIGINT COMMENT 'Linked controls rated Partially Effective',
  ineffective_linked_controls BIGINT COMMENT 'Linked controls rated Ineffective',
  controls_needing_attention ARRAY<STRING> COMMENT 'Linked controls not rated Effective',
  control_reduction_factor DECIMAL(4,3) COMMENT 'Average reduction from linked controls (Effective 0.5, Partially 0.25, else 0)',
  residual_score INT COMMENT 'Residual score = inherent x (1 - control_reduction_factor)',
  residual_rating STRING COMMENT 'Residual rating band',
  residual_rating_color STRING COMMENT 'Hex color of residual rating',
  ale_usd BIGINT COMMENT 'Inherent annual loss expectancy (USD)',
  residual_ale_usd BIGINT COMMENT 'ALE after control reduction (USD)',
  treatment_plan STRING COMMENT 'Treatment plan',
  treatment_status STRING COMMENT 'Treatment status',
  is_open BOOLEAN COMMENT 'Risk is open',
  last_reviewed_date DATE COMMENT 'Last review date',
  days_since_review INT COMMENT 'Days since last review',
  review_overdue BOOLEAN COMMENT 'Review older than the 90-day SLA',
  is_hygiene_compliant BOOLEAN COMMENT 'Has owner, treatment plan and timely review',
  active_exceptions BIGINT COMMENT 'Active policy exceptions linked to the risk',
  expired_active_exceptions BIGINT COMMENT 'Linked exceptions active past expiry',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_risk_id EXPECT (risk_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_residual EXPECT (residual_score BETWEEN 1 AND inherent_score)
)
COMMENT 'Gold: one row per risk in the SharePoint risk register with inherent score/rating (likelihood x impact) and a control-adjusted residual score. Each linked unified control reduces the inherent score by its effectiveness (Effective 50%, Partially Effective 25%, Ineffective / Not Tested 0%), averaged across linked controls; residual_ale_usd applies the same factor to ALE. Includes linked control pass rates, controls needing attention, hygiene flags (no owner, review overdue), and active / expired-but-active exceptions linked to the risk. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH rl AS (
  SELECT risk_id, explode(linked_controls) AS control_id FROM grc_silver.risk
),
agg AS (
  SELECT
    rl.risk_id,
    count(*) AS linked_control_count,
    round(avg(t.pass_rate_pct), 2) AS avg_linked_control_pass_rate_pct,
    count_if(t.effectiveness_band = 'Effective') AS effective_linked_controls,
    count_if(t.effectiveness_band = 'Partially Effective') AS partially_effective_linked_controls,
    count_if(t.effectiveness_band = 'Ineffective') AS ineffective_linked_controls,
    array_sort(collect_set(CASE WHEN coalesce(t.effectiveness_band, 'Not Tested') <> 'Effective' THEN rl.control_id END)) AS controls_needing_attention,
    avg(CASE t.effectiveness_band WHEN 'Effective' THEN 0.5 WHEN 'Partially Effective' THEN 0.25 ELSE 0.0 END) AS control_reduction_factor
  FROM rl
  LEFT JOIN grc_gold.control_test_results t ON rl.control_id = t.control_id
  GROUP BY rl.risk_id
),
exc AS (
  SELECT linked_risk_id,
         count_if(exception_status = 'Active') AS active_exceptions,
         count_if(is_expired_but_active) AS expired_active_exceptions
  FROM grc_silver.risk_exception
  WHERE linked_risk_id IS NOT NULL
  GROUP BY linked_risk_id
),
s AS (
  SELECT
    r.*,
    coalesce(agg.linked_control_count, 0) AS linked_control_count,
    agg.avg_linked_control_pass_rate_pct,
    coalesce(agg.effective_linked_controls, 0) AS effective_linked_controls,
    coalesce(agg.partially_effective_linked_controls, 0) AS partially_effective_linked_controls,
    coalesce(agg.ineffective_linked_controls, 0) AS ineffective_linked_controls,
    agg.controls_needing_attention,
    round(coalesce(agg.control_reduction_factor, 0.0), 3) AS control_reduction_factor,
    greatest(1, CAST(round(r.inherent_score * (1 - coalesce(agg.control_reduction_factor, 0.0))) AS INT)) AS residual_score,
    coalesce(exc.active_exceptions, 0) AS active_exceptions,
    coalesce(exc.expired_active_exceptions, 0) AS expired_active_exceptions
  FROM grc_silver.risk r
  LEFT JOIN agg ON r.risk_id = agg.risk_id
  LEFT JOIN exc ON r.risk_id = exc.linked_risk_id
)
SELECT
  s.risk_id,
  s.risk_title,
  s.risk_category_id,
  s.risk_category,
  s.risk_domain,
  s.bu_id,
  bu.bu_name,
  bu.risk_appetite AS bu_risk_appetite,
  s.owner_email,
  s.has_owner,
  s.likelihood,
  s.impact,
  s.inherent_score,
  s.inherent_rating,
  s.inherent_rating_color,
  s.linked_controls,
  s.linked_control_count,
  s.avg_linked_control_pass_rate_pct,
  s.effective_linked_controls,
  s.partially_effective_linked_controls,
  s.ineffective_linked_controls,
  s.controls_needing_attention,
  s.control_reduction_factor,
  s.residual_score,
  rb.rating AS residual_rating,
  rb.color_hex AS residual_rating_color,
  s.ale_usd,
  CAST(round(s.ale_usd * (1 - s.control_reduction_factor)) AS BIGINT) AS residual_ale_usd,
  s.treatment_plan,
  s.treatment_status,
  s.is_open,
  s.last_reviewed_date,
  s.days_since_review,
  s.review_overdue,
  s.is_hygiene_compliant,
  s.active_exceptions,
  s.expired_active_exceptions,
  s.as_of_date
FROM s
LEFT JOIN grc_ref.risk_rating_bands rb ON s.residual_score BETWEEN rb.min_score AND rb.max_score
LEFT JOIN grc_ref.business_units bu ON s.bu_id = bu.bu_id;
