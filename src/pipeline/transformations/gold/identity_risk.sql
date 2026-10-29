-- Gold: per-identity access risk profile with risk flags and a weighted risk score.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.identity_risk (
  user_id STRING COMMENT 'Okta user id (primary key)',
  login STRING COMMENT 'Lower-cased login',
  first_name STRING COMMENT 'First name',
  last_name STRING COMMENT 'Last name',
  user_type STRING COMMENT 'workforce, service or admin',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  job_title STRING COMMENT 'Job title',
  idp_status STRING COMMENT 'Okta account status',
  is_enabled BOOLEAN COMMENT 'Okta account is ACTIVE',
  hr_employee_id STRING COMMENT 'Workday employee id',
  hr_employment_status STRING COMMENT 'HR employment status',
  hr_termination_date DATE COMMENT 'HR termination date',
  is_orphan BOOLEAN COMMENT 'Terminated in HR but active in the IdP',
  signins_after_termination BIGINT COMMENT 'Sign-ins after termination',
  last_signin_after_termination_ts TIMESTAMP COMMENT 'Latest sign-in after termination',
  deprovision_hours DECIMAL(23,1) COMMENT 'Hours from termination to IdP disable',
  last_signin_ts TIMESTAMP COMMENT 'Latest sign-in',
  days_since_last_signin INT COMMENT 'Days since last sign-in',
  is_dormant BOOLEAN COMMENT 'Enabled with no sign-in for more than 90 days',
  mfa_enrolled BOOLEAN COMMENT 'Has an active MFA factor',
  mfa_type STRING COMMENT 'Strongest MFA factor type',
  phishing_resistant_mfa BOOLEAN COMMENT 'Uses fido2 or push number matching',
  is_privileged BOOLEAN COMMENT 'Holds a privileged entitlement',
  privileged_groups ARRAY<STRING> COMMENT 'Privileged groups held',
  overdue_privileged_reviews BIGINT COMMENT 'Privileged entitlements past review SLA',
  sod_conflict_count INT COMMENT 'SoD rules violated',
  sod_rules ARRAY<STRING> COMMENT 'SoD rule ids violated',
  no_mfa_signin_count BIGINT COMMENT 'Successful sign-ins without MFA',
  risk_flags ARRAY<STRING> COMMENT 'Risk flags raised (ORPHANED_ACCOUNT, POST_TERMINATION_SIGNIN, NO_MFA, ...)',
  risk_score INT COMMENT 'Additive identity risk score (orphan 40, post-term sign-in 30, no MFA 25, weak privileged MFA 20, dormant 15, SoD 15, overdue review 10, privileged 10, no-MFA sign-ins 5)',
  risk_level STRING COMMENT 'Critical, High, Medium, Low or None from risk_score',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_user_id EXPECT (user_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_risk_score EXPECT (risk_score >= 0)
)
COMMENT 'Gold: one row per IdP identity with access risk flags (ORPHANED_ACCOUNT, POST_TERMINATION_SIGNIN, NO_MFA, WEAK_PRIVILEGED_MFA, DORMANT, SOD_CONFLICT, PRIV_REVIEW_OVERDUE, LATE_DEPROVISION, NO_MFA_SIGNINS), a weighted risk_score (orphan 40, post-termination sign-in 30, workforce no MFA 25, weak privileged MFA 20, dormant 15, SoD 15, overdue privileged review 10, privileged 10, no-MFA sign-ins 5) and risk_level (Critical >= 60, High >= 35, Medium >= 15, Low > 0, None). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH i AS (
  SELECT
    *,
    is_enabled AND user_type = 'workforce' AND NOT mfa_enrolled AS flag_no_mfa,
    is_enabled AND is_privileged AND NOT phishing_resistant_mfa AS flag_weak_priv_mfa,
    coalesce(deprovision_hours > leaver_sla_hours, false) AS flag_late_deprovision
  FROM grc_silver.identity
),
s AS (
  SELECT
    i.*,
    40 * CAST(is_orphan AS INT)
      + 30 * CAST(signins_after_termination > 0 AS INT)
      + 25 * CAST(flag_no_mfa AS INT)
      + 20 * CAST(flag_weak_priv_mfa AS INT)
      + 15 * CAST(is_dormant AS INT)
      + 15 * CAST(sod_conflict_count > 0 AND is_enabled AS INT)
      + 10 * CAST(overdue_privileged_reviews > 0 AND is_enabled AS INT)
      + 10 * CAST(is_privileged AND is_enabled AS INT)
      + 5 * CAST(no_mfa_signin_count > 0 AS INT) AS risk_score
  FROM i
)
SELECT
  s.user_id,
  s.login,
  s.first_name,
  s.last_name,
  s.user_type,
  s.bu_id,
  b.bu_name,
  s.job_title,
  s.idp_status,
  s.is_enabled,
  s.hr_employee_id,
  s.hr_employment_status,
  s.hr_termination_date,
  s.is_orphan,
  s.signins_after_termination,
  s.last_signin_after_termination_ts,
  s.deprovision_hours,
  s.last_signin_ts,
  s.days_since_last_signin,
  s.is_dormant,
  s.mfa_enrolled,
  s.mfa_type,
  s.phishing_resistant_mfa,
  s.is_privileged,
  s.privileged_groups,
  s.overdue_privileged_reviews,
  s.sod_conflict_count,
  s.sod_rules,
  s.no_mfa_signin_count,
  filter(array(
    CASE WHEN s.is_orphan THEN 'ORPHANED_ACCOUNT' END,
    CASE WHEN s.signins_after_termination > 0 THEN 'POST_TERMINATION_SIGNIN' END,
    CASE WHEN s.flag_no_mfa THEN 'NO_MFA' END,
    CASE WHEN s.flag_weak_priv_mfa THEN 'WEAK_PRIVILEGED_MFA' END,
    CASE WHEN s.is_dormant THEN 'DORMANT' END,
    CASE WHEN s.sod_conflict_count > 0 AND s.is_enabled THEN 'SOD_CONFLICT' END,
    CASE WHEN s.overdue_privileged_reviews > 0 AND s.is_enabled THEN 'PRIV_REVIEW_OVERDUE' END,
    CASE WHEN s.flag_late_deprovision THEN 'LATE_DEPROVISION' END,
    CASE WHEN s.no_mfa_signin_count > 0 THEN 'NO_MFA_SIGNINS' END
  ), x -> x IS NOT NULL) AS risk_flags,
  s.risk_score,
  CASE
    WHEN s.risk_score >= 60 THEN 'Critical'
    WHEN s.risk_score >= 35 THEN 'High'
    WHEN s.risk_score >= 15 THEN 'Medium'
    WHEN s.risk_score > 0 THEN 'Low'
    ELSE 'None'
  END AS risk_level,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM s
LEFT JOIN grc_ref.business_units b ON s.bu_id = b.bu_id;
