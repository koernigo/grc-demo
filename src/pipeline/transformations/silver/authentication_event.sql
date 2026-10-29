-- Silver: Okta sign-in events flattened (incremental, append-only).
CREATE OR REFRESH STREAMING TABLE grc_silver.authentication_event (
  event_id STRING COMMENT 'Okta System Log event uuid',
  event_ts TIMESTAMP COMMENT 'Event time (Okta published timestamp, UTC)',
  event_date DATE COMMENT 'Event date (UTC)',
  event_type STRING COMMENT 'Okta eventType, e.g. user.session.start',
  user_id STRING COMMENT 'Okta user id of the actor; joins grc_silver.identity.user_id',
  login STRING COMMENT 'Lower-cased actor login (alternateId)',
  display_name STRING COMMENT 'Actor display name',
  app_name STRING COMMENT 'Target application name (first target)',
  source_ip STRING COMMENT 'Client IP address',
  country STRING COMMENT 'Client geolocation country',
  client_os STRING COMMENT 'Client operating system',
  client_browser STRING COMMENT 'Client browser',
  result STRING COMMENT 'Outcome result: SUCCESS or FAILURE',
  failure_reason STRING COMMENT 'Outcome reason for failures',
  credential_type STRING COMMENT 'Authentication credential type',
  mfa_verified BOOLEAN COMMENT 'True if MFA was verified for the sign-in',
  _source_file STRING COMMENT 'Landing file the event was ingested from',
  _ingest_ts TIMESTAMP COMMENT 'Time the event was ingested into bronze',
  CONSTRAINT valid_event_id EXPECT (event_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_event_ts EXPECT (event_ts IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_user EXPECT (user_id IS NOT NULL),
  CONSTRAINT known_result EXPECT (result IN ('SUCCESS', 'FAILURE'))
)
COMMENT 'Silver: one row per Okta user.session.start sign-in event, flattened from the System Log: user, timestamp, application, client IP/country/OS/browser, outcome and whether MFA was verified. Source for MFA, dormant-account and post-termination sign-in analytics.'
TBLPROPERTIES ('quality' = 'silver')
CLUSTER BY (event_date, user_id)
AS SELECT
  uuid AS event_id,
  to_timestamp(published) AS event_ts,
  coalesce(event_date, to_date(to_timestamp(published))) AS event_date,
  eventType AS event_type,
  actor.id AS user_id,
  lower(actor.alternateId) AS login,
  actor.displayName AS display_name,
  target[0].displayName AS app_name,
  client.ipAddress AS source_ip,
  client.geographicalContext.country AS country,
  client.userAgent.os AS client_os,
  client.userAgent.browser AS client_browser,
  outcome.result AS result,
  outcome.reason AS failure_reason,
  authenticationContext.credentialType AS credential_type,
  coalesce(authenticationContext.mfaVerified, false) AS mfa_verified,
  _source_file,
  _ingest_ts
FROM STREAM(grc_bronze.okta_system_log);
