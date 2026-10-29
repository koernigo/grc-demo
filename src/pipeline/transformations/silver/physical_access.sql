-- Silver: physical access (LenelS2 badge events + visitor log) from the simulated NAS share \\acme-nas01\security.
-- Time handling: bronze event_time is site-local wall-clock time. UTC is derived by parsing the string together with
-- its IANA zone (pattern VV), which is independent of the session time zone; local time is kept as TIMESTAMP_NTZ.

CREATE OR REFRESH MATERIALIZED VIEW grc_silver.badge_access_event (
  event_id STRING COMMENT 'LenelS2 event identifier (primary key, deduplicated)',
  event_ts_utc TIMESTAMP COMMENT 'Event time converted to UTC using site_tz',
  event_ts_local TIMESTAMP_NTZ COMMENT 'Event wall-clock time at the site (no time zone)',
  event_date_local DATE COMMENT 'Event date at the site (local calendar day)',
  event_hour_local INT COMMENT 'Hour of day at the site (0-23)',
  site_tz STRING COMMENT 'IANA time zone of the site',
  site_code STRING COMMENT 'Facility code, e.g. HQ-NYC, DC-1',
  door_id STRING COMMENT 'Door / reader location identifier, e.g. DC1-SR-01',
  door_name STRING COMMENT 'Door name',
  zone STRING COMMENT 'Security zone of the door: Perimeter, Office, Restricted or Critical',
  is_restricted_zone BOOLEAN COMMENT 'True for Restricted or Critical zones',
  badge_id STRING COMMENT 'Badge / credential identifier (null when no badge was presented, e.g. forced door)',
  cardholder_name STRING COMMENT 'Cardholder name from the access-control system',
  cardholder_email STRING COMMENT 'Lower-cased, trimmed cardholder email (null if none); joins grc_silver.identity.login',
  cardholder_type STRING COMMENT 'Employee, Contractor or Unknown',
  event_type STRING COMMENT 'ACCESS_GRANTED, ACCESS_DENIED_BADGE_DISABLED, ACCESS_DENIED_NO_CLEARANCE, DOOR_FORCED_OPEN or DOOR_HELD_OPEN',
  is_access_granted BOOLEAN COMMENT 'True for ACCESS_GRANTED',
  is_door_alarm BOOLEAN COMMENT 'True for DOOR_FORCED_OPEN or DOOR_HELD_OPEN',
  is_after_hours BOOLEAN COMMENT 'Local time before 06:00, at/after 20:00, or on a weekend',
  reader_serial STRING COMMENT 'Badge reader serial number',
  _source_file STRING COMMENT 'NAS export file the event was ingested from',
  _export_date DATE COMMENT 'Export date from the file name',
  _ingest_ts TIMESTAMP COMMENT 'Time the event was ingested into bronze',
  CONSTRAINT valid_event_id EXPECT (event_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_event_ts EXPECT (event_ts_utc IS NOT NULL AND event_ts_local IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT known_event_type EXPECT (event_type IN ('ACCESS_GRANTED', 'ACCESS_DENIED_BADGE_DISABLED', 'ACCESS_DENIED_NO_CLEARANCE', 'DOOR_FORCED_OPEN', 'DOOR_HELD_OPEN')),
  CONSTRAINT known_zone EXPECT (zone IN ('Perimeter', 'Office', 'Restricted', 'Critical')),
  CONSTRAINT granted_has_badge EXPECT (NOT is_access_granted OR badge_id IS NOT NULL)
)
COMMENT 'Silver: one row per physical access-control event (LenelS2 badge reader), deduplicated on event_id, typed and cleaned: UTC and site-local timestamps, local date/hour, after-hours and restricted-zone flags, lower-cased cardholder email. Source: grc_bronze.nas_badge_access (simulated on-prem NAS share).'
TBLPROPERTIES ('quality' = 'silver', 'delta.feature.timestampNtz' = 'supported')
CLUSTER BY (event_date_local, door_id)
AS
WITH b AS (
  SELECT *
  FROM grc_bronze.nas_badge_access
  WHERE event_id IS NOT NULL
  QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY _ingest_ts DESC, _source_file DESC) = 1
)
SELECT
  trim(event_id) AS event_id,
  try_to_timestamp(concat(trim(event_time), ' ', trim(site_tz)), 'yyyy-MM-dd HH:mm:ss VV') AS event_ts_utc,
  CAST(try_to_timestamp(trim(event_time), 'yyyy-MM-dd HH:mm:ss') AS TIMESTAMP_NTZ) AS event_ts_local,
  to_date(event_ts_local) AS event_date_local,
  hour(event_ts_local) AS event_hour_local,
  trim(site_tz) AS site_tz,
  upper(trim(site_code)) AS site_code,
  upper(trim(door_id)) AS door_id,
  trim(door_name) AS door_name,
  initcap(trim(zone)) AS zone,
  initcap(trim(b.zone)) IN ('Restricted', 'Critical') AS is_restricted_zone,
  nullif(trim(badge_id), '') AS badge_id,
  nullif(trim(cardholder_name), '') AS cardholder_name,
  nullif(lower(trim(cardholder_email)), '') AS cardholder_email,
  coalesce(nullif(trim(cardholder_type), ''), 'Unknown') AS cardholder_type,
  upper(trim(event_type)) AS event_type,
  upper(trim(b.event_type)) = 'ACCESS_GRANTED' AS is_access_granted,
  upper(trim(b.event_type)) IN ('DOOR_FORCED_OPEN', 'DOOR_HELD_OPEN') AS is_door_alarm,
  event_hour_local < 6 OR event_hour_local >= 20 OR dayofweek(event_ts_local) IN (1, 7) AS is_after_hours,
  nullif(trim(reader_serial), '') AS reader_serial,
  _source_file,
  _export_date,
  _ingest_ts
FROM b;

CREATE OR REFRESH MATERIALIZED VIEW grc_silver.badge_access_identity (
  event_id STRING COMMENT 'LenelS2 event identifier (primary key); joins grc_silver.badge_access_event',
  event_ts_utc TIMESTAMP COMMENT 'Event time (UTC)',
  event_ts_local TIMESTAMP_NTZ COMMENT 'Event wall-clock time at the site',
  event_date_local DATE COMMENT 'Event date at the site',
  site_code STRING COMMENT 'Facility code',
  door_id STRING COMMENT 'Door identifier',
  door_name STRING COMMENT 'Door name',
  zone STRING COMMENT 'Security zone of the door',
  badge_id STRING COMMENT 'Badge identifier',
  cardholder_email STRING COMMENT 'Lower-cased cardholder email',
  cardholder_type STRING COMMENT 'Employee, Contractor or Unknown',
  event_type STRING COMMENT 'Access event type',
  is_after_hours BOOLEAN COMMENT 'Local time before 06:00, at/after 20:00, or on a weekend',
  user_id STRING COMMENT 'Matched Okta user id (null if the cardholder is not a known identity); joins grc_silver.identity.user_id',
  login STRING COMMENT 'Matched identity login',
  first_name STRING COMMENT 'Identity first name',
  last_name STRING COMMENT 'Identity last name',
  user_type STRING COMMENT 'Identity type: workforce, service or admin',
  bu_id STRING COMMENT 'Business unit of the identity',
  bu_name STRING COMMENT 'Business unit name',
  hr_employee_id STRING COMMENT 'Workday employee id',
  hr_employment_status STRING COMMENT 'HR employment status (Active, Terminated, ...)',
  hr_termination_date DATE COMMENT 'HR termination date',
  is_orphan BOOLEAN COMMENT 'Terminated in HR but still ACTIVE in the IdP',
  idp_is_enabled BOOLEAN COMMENT 'Okta account is ACTIVE',
  signins_after_termination BIGINT COMMENT 'IdP sign-ins after the HR termination date',
  is_identity_matched BOOLEAN COMMENT 'True if the cardholder email matched an identity',
  is_after_termination BOOLEAN COMMENT 'Event local date is after the HR termination date',
  CONSTRAINT valid_event_id EXPECT (event_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT employee_matched_to_identity EXPECT (cardholder_type <> 'Employee' OR is_identity_matched)
)
COMMENT 'Silver: badge access events linked to the workforce identity by lower-cased email (grc_silver.identity.login), carrying business unit, HR employment status and termination date, IdP orphan flag and IdP post-termination sign-ins. is_after_termination marks events on a local date after the HR termination date (same day-level rule as grc_silver.identity sign-ins). Unmatched cardholders (contractor badges, forced doors) are kept with null identity columns.'
TBLPROPERTIES ('quality' = 'silver', 'delta.feature.timestampNtz' = 'supported')
CLUSTER BY (event_date_local, user_id)
AS SELECT
  e.event_id,
  e.event_ts_utc,
  e.event_ts_local,
  e.event_date_local,
  e.site_code,
  e.door_id,
  e.door_name,
  e.zone,
  e.badge_id,
  e.cardholder_email,
  e.cardholder_type,
  e.event_type,
  e.is_after_hours,
  i.user_id,
  i.login,
  i.first_name,
  i.last_name,
  i.user_type,
  i.bu_id,
  bu.bu_name,
  i.hr_employee_id,
  i.hr_employment_status,
  i.hr_termination_date,
  i.is_orphan,
  i.is_enabled AS idp_is_enabled,
  i.signins_after_termination,
  i.user_id IS NOT NULL AS is_identity_matched,
  coalesce(e.event_date_local > i.hr_termination_date, false) AS is_after_termination
FROM grc_silver.badge_access_event e
LEFT JOIN grc_silver.identity i ON e.cardholder_email = i.login
LEFT JOIN grc_ref.business_units bu ON i.bu_id = bu.bu_id;

CREATE OR REFRESH MATERIALIZED VIEW grc_silver.visitor_visit (
  visit_id STRING COMMENT 'Visitor management visit identifier (primary key, deduplicated)',
  visit_date DATE COMMENT 'Visit date (site local)',
  site_code STRING COMMENT 'Facility visited, e.g. HQ-NYC, DC-1',
  site_tz STRING COMMENT 'IANA time zone of the site (from badge events; null if the site has no badge data)',
  visitor_name STRING COMMENT 'Visitor full name',
  visitor_company STRING COMMENT 'Company the visitor represents',
  host_email STRING COMMENT 'Lower-cased email of the hosting employee',
  escort_email STRING COMMENT 'Lower-cased email of the escort (null if unescorted)',
  area_visited STRING COMMENT 'Area / zone visited, e.g. Server room 1',
  sign_in_ts_local TIMESTAMP_NTZ COMMENT 'Sign-in wall-clock time at the site',
  sign_out_ts_local TIMESTAMP_NTZ COMMENT 'Sign-out wall-clock time at the site (null if not signed out)',
  sign_in_ts_utc TIMESTAMP COMMENT 'Sign-in time converted to UTC using site_tz',
  visit_minutes INT COMMENT 'Minutes between sign-in and sign-out (null if not signed out)',
  is_escorted BOOLEAN COMMENT 'True if an escort email is recorded',
  nda_signed BOOLEAN COMMENT 'True if the visitor signed an NDA (Y), false for N, null if blank',
  is_signed_out BOOLEAN COMMENT 'True if a sign-out time is recorded',
  host_user_id STRING COMMENT 'Okta user id of the host (null if not matched)',
  host_is_active BOOLEAN COMMENT 'Host is an active employee in HR',
  _source_file STRING COMMENT 'NAS weekly visitor log file the visit was ingested from',
  _log_week STRING COMMENT 'ISO week of the source log file',
  _ingest_ts TIMESTAMP COMMENT 'Time the visit was ingested into bronze',
  CONSTRAINT valid_visit_id EXPECT (visit_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_visit_date EXPECT (visit_date IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_sign_in EXPECT (sign_in_ts_local IS NOT NULL),
  CONSTRAINT known_nda_flag EXPECT (nda_signed IS NOT NULL),
  CONSTRAINT sign_out_after_sign_in EXPECT (sign_out_ts_local IS NULL OR sign_out_ts_local >= sign_in_ts_local)
)
COMMENT 'Silver: one row per visitor visit from the weekly visitor logs on the NAS share, deduplicated on visit_id, typed and cleaned: visit date, local and UTC sign-in time, local sign-out time, duration, is_escorted (escort recorded), nda_signed (Y/N to boolean), is_signed_out, and host identity. Source: grc_bronze.nas_visitor_log.'
TBLPROPERTIES ('quality' = 'silver', 'delta.feature.timestampNtz' = 'supported')
AS
WITH v AS (
  SELECT *
  FROM grc_bronze.nas_visitor_log
  WHERE visit_id IS NOT NULL
  QUALIFY row_number() OVER (PARTITION BY visit_id ORDER BY _ingest_ts DESC, _source_file DESC) = 1
),
sites AS (
  SELECT site_code, max(site_tz) AS site_tz
  FROM grc_silver.badge_access_event
  GROUP BY site_code
)
SELECT
  trim(v.visit_id) AS visit_id,
  to_date(try_to_timestamp(trim(v.visit_date), 'yyyy-MM-dd')) AS visit_date,
  upper(trim(v.site_code)) AS site_code,
  s.site_tz,
  nullif(trim(v.visitor_name), '') AS visitor_name,
  nullif(trim(v.visitor_company), '') AS visitor_company,
  nullif(lower(trim(v.host_email)), '') AS host_email,
  nullif(lower(trim(v.escort_email)), '') AS escort_email,
  nullif(trim(v.area_visited), '') AS area_visited,
  CAST(try_to_timestamp(concat(trim(v.visit_date), ' ', nullif(trim(v.sign_in_time), '')), 'yyyy-MM-dd HH:mm') AS TIMESTAMP_NTZ) AS sign_in_ts_local,
  CAST(try_to_timestamp(concat(trim(v.visit_date), ' ', nullif(trim(v.sign_out_time), '')), 'yyyy-MM-dd HH:mm') AS TIMESTAMP_NTZ) AS sign_out_ts_local,
  try_to_timestamp(concat(trim(v.visit_date), ' ', nullif(trim(v.sign_in_time), ''), ' ', s.site_tz), 'yyyy-MM-dd HH:mm VV') AS sign_in_ts_utc,
  CAST(timestampdiff(MINUTE, sign_in_ts_local, sign_out_ts_local) AS INT) AS visit_minutes,
  nullif(trim(v.escort_email), '') IS NOT NULL AS is_escorted,
  CASE upper(trim(v.nda_signed)) WHEN 'Y' THEN true WHEN 'N' THEN false END AS nda_signed,
  sign_out_ts_local IS NOT NULL AS is_signed_out,
  i.user_id AS host_user_id,
  coalesce(i.hr_employment_status = 'Active', false) AS host_is_active,
  v._source_file,
  v._log_week,
  v._ingest_ts
FROM v
LEFT JOIN sites s ON upper(trim(v.site_code)) = s.site_code
LEFT JOIN grc_silver.identity i ON nullif(lower(trim(v.host_email)), '') = i.login;
