-- Silver: one row per IdP account, joined to its HR worker record, with lifecycle / MFA / privilege / SoD risk flags.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.identity (
  user_id STRING COMMENT 'Okta user id (primary key)',
  login STRING COMMENT 'Lower-cased Okta login',
  email STRING COMMENT 'Lower-cased email from the Okta profile',
  first_name STRING COMMENT 'First name',
  last_name STRING COMMENT 'Last name',
  user_type STRING COMMENT 'Okta userType: workforce, service, admin (break-glass)',
  idp_status STRING COMMENT 'Okta account status',
  is_enabled BOOLEAN COMMENT 'True if the Okta account is ACTIVE',
  created_ts TIMESTAMP COMMENT 'Okta account creation time',
  status_changed_ts TIMESTAMP COMMENT 'Time of last Okta status change',
  disabled_ts TIMESTAMP COMMENT 'Time the account left ACTIVE status (null if still active)',
  bu_id STRING COMMENT 'Business unit (HR first, Okta department fallback)',
  job_title STRING COMMENT 'Job title (HR first, Okta fallback)',
  location STRING COMMENT 'HR work location',
  hr_employee_id STRING COMMENT 'Matched Workday employee_id (null if no HR match)',
  worker_type STRING COMMENT 'HR worker type (Employee, Contractor, ...)',
  hire_date DATE COMMENT 'HR hire date',
  hr_employment_status STRING COMMENT 'HR employment status (Active, Terminated, ...)',
  hr_termination_date DATE COMMENT 'HR termination date',
  hr_termination_reason STRING COMMENT 'HR termination reason',
  termination_ts TIMESTAMP COMMENT 'Assumed termination time (termination_date 17:00 UTC)',
  deprovision_hours DECIMAL(23,1) COMMENT 'Hours from termination_ts to disabled_ts',
  leaver_sla_hours INT COMMENT 'LEAVER_DEPROVISION SLA in hours (grc_ref.sla_policy)',
  is_orphan BOOLEAN COMMENT 'Terminated in HR but still ACTIVE in the IdP',
  signins_after_termination BIGINT COMMENT 'Sign-in events after the HR termination date',
  last_signin_after_termination_ts TIMESTAMP COMMENT 'Latest sign-in after termination',
  last_signin_ts TIMESTAMP COMMENT 'Latest successful sign-in (Okta lastLogin or System Log)',
  days_since_last_signin INT COMMENT 'Days since last sign-in (or creation) as of as_of_date',
  dormant_days INT COMMENT 'DORMANT_ACCOUNT threshold in days (grc_ref.sla_policy)',
  is_dormant BOOLEAN COMMENT 'Enabled with no sign-in for more than dormant_days (control GRC-IAM-04)',
  mfa_factor_types ARRAY<STRING> COMMENT 'Active MFA factor types enrolled',
  mfa_enrolled BOOLEAN COMMENT 'True if at least one active MFA factor (control GRC-IAM-01)',
  mfa_type STRING COMMENT 'Strongest factor: fido2, push_number_match, totp, sms or none',
  phishing_resistant_mfa BOOLEAN COMMENT 'True for fido2 or push_number_match (control GRC-IAM-02)',
  entitlement_count BIGINT COMMENT 'Number of group memberships',
  is_privileged BOOLEAN COMMENT 'Holds at least one privileged entitlement',
  privileged_groups ARRAY<STRING> COMMENT 'Privileged groups held',
  overdue_privileged_reviews BIGINT COMMENT 'Privileged entitlements past the 90-day review',
  sod_conflict_count INT COMMENT 'Number of grc_ref.sod_ruleset rules violated (control GRC-IAM-06)',
  sod_rules ARRAY<STRING> COMMENT 'SoD rule ids violated',
  signin_events_in_window BIGINT COMMENT 'Sign-in events in the System Log window',
  no_mfa_signin_count BIGINT COMMENT 'Successful sign-ins without MFA verified',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the Okta user export',
  CONSTRAINT valid_user_id EXPECT (user_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_login EXPECT (login IS NOT NULL),
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL),
  CONSTRAINT workforce_matched_to_hr EXPECT (user_type <> 'workforce' OR hr_employee_id IS NOT NULL),
  CONSTRAINT valid_created_ts EXPECT (created_ts IS NOT NULL)
)
COMMENT 'Silver: one row per Okta account (workforce, service, admin/break-glass) joined to the latest Workday worker record by employeeNumber (fallback: email). Flags: is_orphan (terminated in HR but still ACTIVE in the IdP), is_dormant (enabled and no sign-in for more than 90 days), mfa_enrolled / mfa_type / phishing_resistant_mfa, is_privileged, SoD conflicts (grc_ref.sod_ruleset) and leaver deprovisioning hours. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH u AS (
  SELECT *
  FROM grc_bronze.okta_users
  QUALIFY row_number() OVER (PARTITION BY id ORDER BY _snapshot_date DESC, _ingest_ts DESC) = 1
),
hr AS (
  SELECT *
  FROM grc_bronze.hr_workers
  QUALIFY row_number() OVER (PARTITION BY employee_id ORDER BY _snapshot_date DESC, _ingest_ts DESC) = 1
),
uh AS (
  SELECT u.*, hr.employee_id AS hr_employee_id, hr.bu_id AS hr_bu_id, hr.job_title AS hr_job_title, hr.location AS hr_location,
         hr.worker_type, hr.hire_date, hr.employment_status, hr.termination_date, hr.termination_reason
  FROM u
  LEFT JOIN hr
    ON hr.employee_id = u.profile.employeeNumber
    OR (u.profile.employeeNumber IS NULL AND lower(hr.email) = lower(u.profile.login))
),
ent AS (
  SELECT
    user_id,
    count_if(is_privileged) AS privileged_entitlement_count,
    array_sort(collect_set(CASE WHEN is_privileged THEN group_name END)) AS privileged_groups,
    count_if(review_overdue) AS overdue_privileged_reviews,
    count(*) AS entitlement_count
  FROM grc_silver.entitlement
  GROUP BY user_id
),
sod AS (
  SELECT a.user_id, array_sort(collect_set(r.rule_id)) AS sod_rules
  FROM grc_silver.entitlement a
  JOIN grc_ref.sod_ruleset r ON a.group_name = r.entitlement_a
  JOIN grc_silver.entitlement b ON b.user_id = a.user_id AND b.group_name = r.entitlement_b
  GROUP BY a.user_id
),
auth AS (
  SELECT
    user_id,
    max(CASE WHEN result = 'SUCCESS' THEN event_ts END) AS last_successful_signin_ts,
    count(*) AS signin_events_in_window,
    count_if(result = 'SUCCESS' AND NOT mfa_verified) AS no_mfa_signin_count
  FROM grc_silver.authentication_event
  GROUP BY user_id
),
post AS (
  SELECT a.user_id, count(*) AS signins_after_termination, max(a.event_ts) AS last_signin_after_termination_ts
  FROM grc_silver.authentication_event a
  JOIN uh ON a.user_id = uh.id
  WHERE uh.termination_date IS NOT NULL AND a.event_date > uh.termination_date
  GROUP BY a.user_id
),
cfg AS (
  SELECT
    max(CASE WHEN sla_type = 'DORMANT_ACCOUNT' THEN sla_value END) AS dormant_days,
    max(CASE WHEN sla_type = 'LEAVER_DEPROVISION' THEN sla_value END) AS leaver_sla_hours
  FROM grc_ref.sla_policy
)
SELECT
  uh.id AS user_id,
  lower(uh.profile.login) AS login,
  lower(uh.profile.email) AS email,
  uh.profile.firstName AS first_name,
  uh.profile.lastName AS last_name,
  uh.profile.userType AS user_type,
  uh.status AS idp_status,
  uh.status = 'ACTIVE' AS is_enabled,
  to_timestamp(uh.created) AS created_ts,
  to_timestamp(uh.statusChanged) AS status_changed_ts,
  CASE WHEN uh.status <> 'ACTIVE' THEN to_timestamp(uh.statusChanged) END AS disabled_ts,
  coalesce(uh.hr_bu_id, uh.profile.department) AS bu_id,
  coalesce(uh.hr_job_title, uh.profile.title) AS job_title,
  uh.hr_location AS location,
  uh.hr_employee_id,
  uh.worker_type,
  uh.hire_date,
  uh.employment_status AS hr_employment_status,
  uh.termination_date AS hr_termination_date,
  uh.termination_reason AS hr_termination_reason,
  CASE WHEN uh.termination_date IS NOT NULL THEN CAST(uh.termination_date AS TIMESTAMP) + INTERVAL 17 HOURS END AS termination_ts,
  round((unix_timestamp(disabled_ts) - unix_timestamp(termination_ts)) / 3600.0, 1) AS deprovision_hours,
  cfg.leaver_sla_hours,
  coalesce(uh.employment_status = 'Terminated' AND uh.status = 'ACTIVE', false) AS is_orphan,
  coalesce(post.signins_after_termination, 0) AS signins_after_termination,
  post.last_signin_after_termination_ts,
  greatest(to_timestamp(uh.lastLogin), auth.last_successful_signin_ts) AS last_signin_ts,
  datediff(CAST(:as_of_date AS DATE), coalesce(last_signin_ts, created_ts)) AS days_since_last_signin,
  cfg.dormant_days,
  is_enabled AND coalesce(days_since_last_signin > cfg.dormant_days, false) AS is_dormant,
  transform(filter(uh.factors, f -> f.status = 'ACTIVE'), f -> f.factorType) AS mfa_factor_types,
  size(mfa_factor_types) > 0 AS mfa_enrolled,
  CASE
    WHEN array_contains(mfa_factor_types, 'fido2') THEN 'fido2'
    WHEN array_contains(mfa_factor_types, 'push_number_match') THEN 'push_number_match'
    WHEN array_contains(mfa_factor_types, 'totp') THEN 'totp'
    WHEN array_contains(mfa_factor_types, 'sms') THEN 'sms'
    WHEN size(mfa_factor_types) > 0 THEN element_at(mfa_factor_types, 1)
    ELSE 'none'
  END AS mfa_type,
  mfa_type IN ('fido2', 'push_number_match') AS phishing_resistant_mfa,
  coalesce(ent.entitlement_count, 0) AS entitlement_count,
  coalesce(ent.privileged_entitlement_count, 0) > 0 AS is_privileged,
  ent.privileged_groups,
  coalesce(ent.overdue_privileged_reviews, 0) AS overdue_privileged_reviews,
  coalesce(size(sod.sod_rules), 0) AS sod_conflict_count,
  sod.sod_rules,
  coalesce(auth.signin_events_in_window, 0) AS signin_events_in_window,
  coalesce(auth.no_mfa_signin_count, 0) AS no_mfa_signin_count,
  CAST(:as_of_date AS DATE) AS as_of_date,
  uh._source_file
FROM uh
CROSS JOIN cfg
LEFT JOIN ent ON uh.id = ent.user_id
LEFT JOIN sod ON uh.id = sod.user_id
LEFT JOIN auth ON uh.id = auth.user_id
LEFT JOIN post ON uh.id = post.user_id;
