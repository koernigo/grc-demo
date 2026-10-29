-- Silver: SCD Type 2 history of IdP account status / MFA / department changes across Okta user exports.
CREATE TEMPORARY VIEW okta_user_changes AS
SELECT
  id AS user_id,
  lower(profile.login) AS login,
  profile.userType AS user_type,
  profile.department AS department,
  profile.title AS job_title,
  status AS idp_status,
  size(filter(factors, f -> f.status = 'ACTIVE')) > 0 AS mfa_enrolled,
  to_timestamp(statusChanged) AS status_changed_ts,
  _snapshot_date AS observed_snapshot_date,
  _source_file
FROM STREAM(grc_bronze.okta_users);

CREATE OR REFRESH STREAMING TABLE grc_silver.identity_history (
  user_id STRING COMMENT 'Okta user id (CDC key)',
  login STRING COMMENT 'Lower-cased Okta login',
  user_type STRING COMMENT 'Okta userType (history tracked)',
  department STRING COMMENT 'Okta profile department / BU (history tracked)',
  job_title STRING COMMENT 'Okta profile title',
  idp_status STRING COMMENT 'Okta account status (history tracked)',
  mfa_enrolled BOOLEAN COMMENT 'At least one active MFA factor (history tracked)',
  status_changed_ts TIMESTAMP COMMENT 'Okta statusChanged; CDC sequencing column',
  observed_snapshot_date DATE COMMENT 'Okta export snapshot date the version was observed in',
  _source_file STRING COMMENT 'Landing file of the Okta user export',
  __START_AT TIMESTAMP COMMENT 'SCD2 version valid-from (status_changed_ts)',
  __END_AT TIMESTAMP COMMENT 'SCD2 version valid-to; null for the current version'
)
COMMENT 'Silver: SCD Type 2 history of Okta accounts keyed by user_id. A new version is created when idp_status, mfa_enrolled, department or user_type changes; validity is given by __START_AT / __END_AT (sequenced by the Okta statusChanged timestamp). Current rows have __END_AT IS NULL.'
TBLPROPERTIES ('quality' = 'silver');

CREATE FLOW identity_history_cdc AS AUTO CDC INTO grc_silver.identity_history
FROM STREAM(okta_user_changes)
KEYS (user_id)
SEQUENCE BY status_changed_ts
STORED AS SCD TYPE 2
TRACK HISTORY ON idp_status, mfa_enrolled, department, user_type;
