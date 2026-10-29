-- Silver: IdP group memberships (entitlements) enriched with group name, privileged flag and access review status.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.entitlement (
  entitlement_id STRING COMMENT 'Entitlement key: user_id:group_id',
  user_id STRING COMMENT 'Okta user id holding the entitlement',
  login STRING COMMENT 'Lower-cased login of the user',
  user_type STRING COMMENT 'Okta userType: workforce, service, admin',
  idp_status STRING COMMENT 'Okta account status (ACTIVE, SUSPENDED, DEPROVISIONED, ...)',
  is_identity_enabled BOOLEAN COMMENT 'True if the Okta account is ACTIVE',
  bu_id STRING COMMENT 'Business unit from the Okta profile department',
  group_id STRING COMMENT 'Okta group id',
  group_name STRING COMMENT 'Okta group (entitlement) name',
  group_description STRING COMMENT 'Okta group description',
  is_privileged BOOLEAN COMMENT 'True if the group is listed in grc_ref.privileged_entitlements',
  granted_ts TIMESTAMP COMMENT 'Time the membership was granted',
  last_access_review_date DATE COMMENT 'Date the membership was last recertified',
  reviewed_by STRING COMMENT 'Reviewer of the last access review',
  days_since_review INT COMMENT 'Days between last_access_review_date and as_of_date',
  review_sla_days INT COMMENT 'PRIV_ACCESS_REVIEW SLA in days (grc_ref.sla_policy)',
  review_overdue BOOLEAN COMMENT 'Privileged and not reviewed within the SLA (control GRC-IAM-05)',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the group membership export',
  CONSTRAINT valid_user_id EXPECT (user_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_group_id EXPECT (group_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT known_identity EXPECT (idp_status IS NOT NULL),
  CONSTRAINT privileged_has_review_date EXPECT (NOT is_privileged OR last_access_review_date IS NOT NULL)
)
COMMENT 'Silver: one row per Okta user x group membership (entitlement), enriched with the group name/description, privileged flag (group listed in grc_ref.privileged_entitlements), last access review date/reviewer, days since review and review_overdue (privileged and not reviewed within the PRIV_ACCESS_REVIEW SLA, 90 days). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH m AS (
  SELECT *
  FROM grc_bronze.okta_group_memberships
  QUALIFY row_number() OVER (PARTITION BY user_id, group_id ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
g AS (
  SELECT group_id, profile.name AS group_name, profile.description AS group_description
  FROM grc_bronze.okta_groups
  QUALIFY row_number() OVER (PARTITION BY group_id ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
u AS (
  SELECT id AS user_id, status AS idp_status, profile.userType AS user_type, profile.department AS bu_id
  FROM grc_bronze.okta_users
  QUALIFY row_number() OVER (PARTITION BY id ORDER BY _snapshot_date DESC, _ingest_ts DESC) = 1
),
p AS (
  SELECT DISTINCT group_name FROM grc_ref.privileged_entitlements
),
sla AS (
  SELECT max(sla_value) AS review_sla_days FROM grc_ref.sla_policy WHERE sla_type = 'PRIV_ACCESS_REVIEW'
)
SELECT
  concat(m.user_id, ':', m.group_id) AS entitlement_id,
  m.user_id,
  lower(m.login) AS login,
  u.user_type,
  u.idp_status,
  coalesce(u.idp_status = 'ACTIVE', false) AS is_identity_enabled,
  u.bu_id,
  m.group_id,
  coalesce(g.group_name, m.group_name) AS group_name,
  g.group_description,
  p.group_name IS NOT NULL AS is_privileged,
  m.added_ts AS granted_ts,
  m.last_access_review_date,
  m.reviewed_by,
  datediff(CAST(:as_of_date AS DATE), m.last_access_review_date) AS days_since_review,
  sla.review_sla_days,
  (p.group_name IS NOT NULL)
    AND (m.last_access_review_date IS NULL
         OR datediff(CAST(:as_of_date AS DATE), m.last_access_review_date) > sla.review_sla_days) AS review_overdue,
  CAST(:as_of_date AS DATE) AS as_of_date,
  m._source_file
FROM m
LEFT JOIN g ON m.group_id = g.group_id
LEFT JOIN u ON m.user_id = u.user_id
LEFT JOIN p ON coalesce(g.group_name, m.group_name) = p.group_name
CROSS JOIN sla;
