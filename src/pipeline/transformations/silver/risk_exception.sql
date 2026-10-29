-- Silver: SharePoint Policy Exceptions list flattened with validity / expiry flags.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.risk_exception (
  exception_id STRING COMMENT 'Exception identifier, e.g. EXC-001 (primary key)',
  sp_list_item_id BIGINT COMMENT 'SharePoint list item id',
  exception_title STRING COMMENT 'Exception title',
  policy_id STRING COMMENT 'Excepted policy id',
  control_id STRING COMMENT 'Excepted unified control id',
  bu_id STRING COMMENT 'Requesting business unit',
  requester_email STRING COMMENT 'Lower-cased requester email',
  approver_email STRING COMMENT 'Lower-cased approver email',
  approval_status STRING COMMENT 'Approval status (Approved, Pending, Rejected)',
  exception_status STRING COMMENT 'List status (Active, Closed, Draft)',
  start_date DATE COMMENT 'Exception start date',
  expiry_date DATE COMMENT 'Exception expiry date',
  duration_days INT COMMENT 'Days between start and expiry',
  max_duration_days INT COMMENT 'EXCEPTION_MAX_DURATION in days',
  days_to_expiry INT COMMENT 'Days from as_of_date to expiry (negative = expired)',
  compensating_controls STRING COMMENT 'Compensating controls description',
  linked_risk_id STRING COMMENT 'Linked risk id in the risk register',
  is_expired BOOLEAN COMMENT 'Expiry date before as_of_date',
  is_expired_but_active BOOLEAN COMMENT 'Status Active but expiry date passed',
  exceeds_max_duration BOOLEAN COMMENT 'Duration longer than max_duration_days',
  is_valid BOOLEAN COMMENT 'Approved, not expired and within max duration (control GRC-POL-02)',
  expiring_within_30d BOOLEAN COMMENT 'Active and expiring in the next 30 days',
  created_ts TIMESTAMP COMMENT 'List item created time',
  modified_ts TIMESTAMP COMMENT 'List item modified time',
  sp_site STRING COMMENT 'SharePoint site',
  sp_etag STRING COMMENT 'SharePoint item etag',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the Policy Exceptions export',
  CONSTRAINT valid_exception_id EXPECT (exception_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_dates EXPECT (start_date IS NOT NULL AND expiry_date IS NOT NULL AND expiry_date >= start_date),
  CONSTRAINT has_approver EXPECT (approver_email IS NOT NULL),
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL)
)
COMMENT 'Silver: one row per policy exception from the SharePoint Policy Exceptions list (policy, control, BU, requester/approver emails, approval status, start/expiry dates, compensating controls, linked risk, list status). Flags: is_expired, is_expired_but_active (list status Active but expiry date passed), exceeds_max_duration (> EXCEPTION_MAX_DURATION 180 days), is_valid (approved, not expired, within max duration), expiring_within_30d. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH e AS (
  SELECT *
  FROM grc_bronze.sp_policy_exceptions
  QUALIFY row_number() OVER (PARTITION BY ExceptionId ORDER BY to_timestamp(Modified) DESC, _ingest_ts DESC) = 1
),
cfg AS (
  SELECT max(sla_value) AS max_duration_days FROM grc_ref.sla_policy WHERE sla_type = 'EXCEPTION_MAX_DURATION'
)
SELECT
  e.ExceptionId AS exception_id,
  e.id AS sp_list_item_id,
  e.Title AS exception_title,
  e.PolicyId AS policy_id,
  e.ControlId AS control_id,
  e.BusinessUnit AS bu_id,
  lower(e.Requester.Email) AS requester_email,
  lower(e.Approver.Email) AS approver_email,
  e.ApprovalStatus AS approval_status,
  e.ExceptionStatus AS exception_status,
  to_date(e.StartDate) AS start_date,
  to_date(e.ExpiryDate) AS expiry_date,
  datediff(to_date(e.ExpiryDate), to_date(e.StartDate)) AS duration_days,
  cfg.max_duration_days,
  datediff(to_date(e.ExpiryDate), CAST(:as_of_date AS DATE)) AS days_to_expiry,
  e.CompensatingControls AS compensating_controls,
  e.LinkedRiskId AS linked_risk_id,
  coalesce(to_date(e.ExpiryDate) < CAST(:as_of_date AS DATE), false) AS is_expired,
  e.ExceptionStatus = 'Active' AND coalesce(to_date(e.ExpiryDate) < CAST(:as_of_date AS DATE), false) AS is_expired_but_active,
  coalesce(datediff(to_date(e.ExpiryDate), to_date(e.StartDate)) > cfg.max_duration_days, false) AS exceeds_max_duration,
  e.ApprovalStatus = 'Approved'
    AND coalesce(to_date(e.ExpiryDate) >= CAST(:as_of_date AS DATE), false)
    AND coalesce(datediff(to_date(e.ExpiryDate), to_date(e.StartDate)) <= cfg.max_duration_days, false) AS is_valid,
  e.ExceptionStatus = 'Active'
    AND coalesce(datediff(to_date(e.ExpiryDate), CAST(:as_of_date AS DATE)) BETWEEN 0 AND 30, false) AS expiring_within_30d,
  to_timestamp(e.Created) AS created_ts,
  to_timestamp(e.Modified) AS modified_ts,
  e._sp_site AS sp_site,
  e._sp_etag AS sp_etag,
  CAST(:as_of_date AS DATE) AS as_of_date,
  e._source_file
FROM e
CROSS JOIN cfg;
