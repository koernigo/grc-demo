-- Gold: policy lifecycle status with linked control performance and exceptions.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.policy_lifecycle (
  policy_id STRING COMMENT 'Policy id (primary key)',
  policy_title STRING COMMENT 'Policy title',
  owner_email STRING COMMENT 'Policy owner email',
  version STRING COMMENT 'Policy version',
  status STRING COMMENT 'Register status',
  lifecycle_stage STRING COMMENT 'Current, Review Due Soon, Review Overdue, Draft or Retired',
  last_review_date DATE COMMENT 'Last review date',
  next_review_date DATE COMMENT 'Next review date',
  days_since_review INT COMMENT 'Days since last review',
  days_until_next_review INT COMMENT 'Days until next review (negative = overdue)',
  days_overdue INT COMMENT 'Days past next review date (0 if not overdue)',
  is_review_overdue BOOLEAN COMMENT 'Review overdue (control GRC-POL-01)',
  review_cycle_days INT COMMENT 'Review cycle in days',
  mapped_controls ARRAY<STRING> COMMENT 'Unified controls supported by the policy',
  mapped_control_count BIGINT COMMENT 'Mapped controls with test results',
  failing_control_count BIGINT COMMENT 'Mapped controls whose test failed',
  failing_controls ARRAY<STRING> COMMENT 'Failing mapped control ids',
  avg_mapped_control_pass_rate_pct DECIMAL(28,2) COMMENT 'Average pass rate of mapped control tests',
  total_exceptions BIGINT COMMENT 'Exceptions raised against the policy',
  active_exceptions BIGINT COMMENT 'Exceptions with Active status',
  expired_active_exceptions BIGINT COMMENT 'Active exceptions past expiry',
  document_url STRING COMMENT 'SharePoint document URL',
  document_name STRING COMMENT 'Document file name',
  document_volume_path STRING COMMENT 'UC volume path of the document',
  document_modified_ts TIMESTAMP COMMENT 'Document last modified time',
  document_modified_by STRING COMMENT 'Document last modifier',
  register_document_date_mismatch BOOLEAN COMMENT 'Register review date differs from document modified date',
  register_modified_ts TIMESTAMP COMMENT 'Register item modified time',
  register_modified_by STRING COMMENT 'Register item last editor',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_policy_id EXPECT (policy_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_lifecycle_stage EXPECT (lifecycle_stage IS NOT NULL)
)
COMMENT 'Gold: one row per policy in the SharePoint Policy Register with lifecycle_stage (Current, Review Due Soon <= 60 days, Review Overdue, or the non-published status), review dates, owner, document metadata (name, UC volume path, last modified, register/document date mismatch), mapped unified controls with their latest test results (failing controls, average pass rate) and policy exceptions (total, active, expired-but-active). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH pc AS (
  SELECT policy_id, explode(mapped_controls) AS control_id FROM grc_silver.policy
),
pca AS (
  SELECT
    pc.policy_id,
    count(*) AS mapped_control_count,
    count_if(t.test_result = 'Fail') AS failing_control_count,
    round(avg(t.pass_rate_pct), 2) AS avg_mapped_control_pass_rate_pct,
    array_sort(collect_set(CASE WHEN t.test_result = 'Fail' THEN pc.control_id END)) AS failing_controls
  FROM pc
  LEFT JOIN grc_gold.control_test_results t ON pc.control_id = t.control_id
  GROUP BY pc.policy_id
),
ex AS (
  SELECT policy_id,
         count(*) AS total_exceptions,
         count_if(exception_status = 'Active') AS active_exceptions,
         count_if(is_expired_but_active) AS expired_active_exceptions
  FROM grc_silver.risk_exception
  GROUP BY policy_id
)
SELECT
  p.policy_id,
  p.policy_title,
  p.owner_email,
  p.version,
  p.status,
  CASE
    WHEN p.status <> 'Published' THEN p.status
    WHEN p.is_review_overdue THEN 'Review Overdue'
    WHEN p.days_until_next_review <= 60 THEN 'Review Due Soon'
    ELSE 'Current'
  END AS lifecycle_stage,
  p.last_review_date,
  p.next_review_date,
  p.days_since_review,
  p.days_until_next_review,
  greatest(0, -p.days_until_next_review) AS days_overdue,
  p.is_review_overdue,
  p.review_cycle_days,
  p.mapped_controls,
  coalesce(pca.mapped_control_count, 0) AS mapped_control_count,
  coalesce(pca.failing_control_count, 0) AS failing_control_count,
  pca.failing_controls,
  pca.avg_mapped_control_pass_rate_pct,
  coalesce(ex.total_exceptions, 0) AS total_exceptions,
  coalesce(ex.active_exceptions, 0) AS active_exceptions,
  coalesce(ex.expired_active_exceptions, 0) AS expired_active_exceptions,
  p.document_url,
  p.document_name,
  p.document_volume_path,
  p.document_modified_ts,
  p.document_modified_by,
  p.register_document_date_mismatch,
  p.modified_ts AS register_modified_ts,
  p.editor_email AS register_modified_by,
  p.as_of_date
FROM grc_silver.policy p
LEFT JOIN pca ON p.policy_id = pca.policy_id
LEFT JOIN ex ON p.policy_id = ex.policy_id;
