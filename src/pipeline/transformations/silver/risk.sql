-- Silver: SharePoint Risk Register flattened, scored and rated.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.risk (
  risk_id STRING COMMENT 'Risk identifier, e.g. RSK-001 (primary key)',
  sp_list_item_id BIGINT COMMENT 'SharePoint list item id',
  risk_title STRING COMMENT 'Risk title',
  risk_category_id STRING COMMENT 'Risk category id (grc_ref.risk_taxonomy)',
  risk_category STRING COMMENT 'Risk category name',
  risk_domain STRING COMMENT 'Risk domain',
  bu_id STRING COMMENT 'Owning business unit',
  owner_email STRING COMMENT 'Lower-cased risk owner email (null if unassigned)',
  has_owner BOOLEAN COMMENT 'True if a risk owner is assigned',
  likelihood INT COMMENT 'Likelihood score 1-5',
  impact INT COMMENT 'Impact score 1-5',
  inherent_score INT COMMENT 'Likelihood x impact (1-25)',
  register_inherent_score INT COMMENT 'Inherent score as entered in the register',
  inherent_rating STRING COMMENT 'Rating band for inherent_score (grc_ref.risk_rating_bands)',
  inherent_rating_color STRING COMMENT 'Hex color of the inherent rating',
  ale_usd BIGINT COMMENT 'Annual loss expectancy in USD',
  treatment_plan STRING COMMENT 'Risk treatment plan',
  treatment_status STRING COMMENT 'Treatment status',
  is_open BOOLEAN COMMENT 'True unless treatment status is Closed',
  linked_controls ARRAY<STRING> COMMENT 'Unified control ids mitigating the risk',
  last_reviewed_date DATE COMMENT 'Date the risk was last reviewed',
  days_since_review INT COMMENT 'Days since last review as of as_of_date',
  review_sla_days INT COMMENT 'RISK_REVIEW SLA in days',
  review_overdue BOOLEAN COMMENT 'Not reviewed within review_sla_days',
  is_hygiene_compliant BOOLEAN COMMENT 'Owner, treatment plan and timely review present (control GRC-RSK-01)',
  created_ts TIMESTAMP COMMENT 'Register item created time',
  modified_ts TIMESTAMP COMMENT 'Register item modified time',
  sp_site STRING COMMENT 'SharePoint site',
  sp_etag STRING COMMENT 'SharePoint item etag',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the Risk Register export',
  CONSTRAINT valid_risk_id EXPECT (risk_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_likelihood EXPECT (likelihood BETWEEN 1 AND 5),
  CONSTRAINT valid_impact EXPECT (impact BETWEEN 1 AND 5),
  CONSTRAINT has_owner EXPECT (has_owner),
  CONSTRAINT known_category EXPECT (risk_category IS NOT NULL)
)
COMMENT 'Silver: one row per risk from the SharePoint Risk Register with category/domain (grc_ref.risk_taxonomy), BU, owner email (missing owner flagged), likelihood x impact inherent score and rating (grc_ref.risk_rating_bands), ALE, treatment plan/status, linked unified controls (array) and review currency vs RISK_REVIEW (90 days). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH r AS (
  SELECT *
  FROM grc_bronze.sp_risk_register
  QUALIFY row_number() OVER (PARTITION BY RiskId ORDER BY to_timestamp(Modified) DESC, _ingest_ts DESC) = 1
),
cfg AS (
  SELECT max(sla_value) AS review_sla_days FROM grc_ref.sla_policy WHERE sla_type = 'RISK_REVIEW'
)
SELECT
  r.RiskId AS risk_id,
  r.id AS sp_list_item_id,
  r.Title AS risk_title,
  r.RiskCategoryId AS risk_category_id,
  tx.risk_category,
  tx.risk_domain,
  r.BusinessUnit AS bu_id,
  lower(r.RiskOwner.Email) AS owner_email,
  r.RiskOwner.Email IS NOT NULL AS has_owner,
  CAST(r.Likelihood AS INT) AS likelihood,
  CAST(r.Impact AS INT) AS impact,
  CAST(r.Likelihood * r.Impact AS INT) AS inherent_score,
  CAST(r.InherentScore AS INT) AS register_inherent_score,
  b.rating AS inherent_rating,
  b.color_hex AS inherent_rating_color,
  r.AnnualLossExpectancyUSD AS ale_usd,
  r.TreatmentPlan AS treatment_plan,
  r.TreatmentStatus AS treatment_status,
  coalesce(r.TreatmentStatus, '') <> 'Closed' AS is_open,
  r.LinkedControls AS linked_controls,
  to_date(r.LastReviewed) AS last_reviewed_date,
  datediff(CAST(:as_of_date AS DATE), to_date(r.LastReviewed)) AS days_since_review,
  cfg.review_sla_days,
  coalesce(datediff(CAST(:as_of_date AS DATE), to_date(r.LastReviewed)) > cfg.review_sla_days, true) AS review_overdue,
  r.RiskOwner.Email IS NOT NULL
    AND coalesce(trim(r.TreatmentPlan), '') <> ''
    AND coalesce(datediff(CAST(:as_of_date AS DATE), to_date(r.LastReviewed)) <= cfg.review_sla_days, false) AS is_hygiene_compliant,
  to_timestamp(r.Created) AS created_ts,
  to_timestamp(r.Modified) AS modified_ts,
  r._sp_site AS sp_site,
  r._sp_etag AS sp_etag,
  CAST(:as_of_date AS DATE) AS as_of_date,
  r._source_file
FROM r
CROSS JOIN cfg
LEFT JOIN grc_ref.risk_taxonomy tx ON r.RiskCategoryId = tx.risk_category_id
LEFT JOIN grc_ref.risk_rating_bands b ON r.Likelihood * r.Impact BETWEEN b.min_score AND b.max_score;
