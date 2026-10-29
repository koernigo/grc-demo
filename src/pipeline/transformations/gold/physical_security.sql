-- Gold: physical-security view (post-termination badge use, restricted/critical-zone anomalies, visitor findings)
-- for the AI/BI dashboard, GRC Control Center app and Genie.
-- Control mapping: grc_ref has no dedicated physical-access control (no GRC-PHY-* control and no physical-security
-- framework requirement in grc_ref.framework_requirements). Post-termination badge use is mapped to the closest
-- existing control, GRC-IAM-03 (timely deprovisioning of leavers), as a RELATED mapping; zone anomalies and visitor
-- findings have control_id NULL and an explicit control-gap note. No control ids are invented.

CREATE OR REFRESH MATERIALIZED VIEW grc_gold.physical_post_termination_badge_use (
  user_id STRING COMMENT 'Okta user id (primary key); joins grc_gold.identity_risk.user_id',
  login STRING COMMENT 'Lower-cased login / cardholder email',
  first_name STRING COMMENT 'First name',
  last_name STRING COMMENT 'Last name',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  hr_employee_id STRING COMMENT 'Workday employee id',
  hr_employment_status STRING COMMENT 'HR employment status',
  hr_termination_date DATE COMMENT 'HR termination date',
  is_orphan BOOLEAN COMMENT 'Terminated in HR but still ACTIVE in the IdP',
  idp_is_enabled BOOLEAN COMMENT 'Okta account is ACTIVE',
  first_badge_in_after_termination_ts_local TIMESTAMP_NTZ COMMENT 'First granted badge-in after termination (site local time)',
  last_badge_in_after_termination_ts_local TIMESTAMP_NTZ COMMENT 'Latest granted badge-in after termination (site local time)',
  first_badge_in_after_termination_ts_utc TIMESTAMP COMMENT 'First granted badge-in after termination (UTC)',
  last_badge_in_after_termination_ts_utc TIMESTAMP COMMENT 'Latest granted badge-in after termination (UTC)',
  badge_in_events_after_termination BIGINT COMMENT 'Number of ACCESS_GRANTED events after the termination date',
  badge_in_days_after_termination BIGINT COMMENT 'Distinct local days with a granted badge-in after termination',
  days_termination_to_last_badge_in INT COMMENT 'Days from HR termination date to the latest badge-in',
  sites_entered ARRAY<STRING> COMMENT 'Sites entered after termination',
  doors_entered ARRAY<STRING> COMMENT 'Doors used after termination',
  restricted_zone_entries BIGINT COMMENT 'Granted entries into Restricted or Critical zones after termination',
  denied_attempts_after_termination BIGINT COMMENT 'ACCESS_DENIED_BADGE_DISABLED events after termination',
  idp_signins_after_termination BIGINT COMMENT 'IdP (Okta) sign-ins after termination (grc_silver.identity)',
  also_signed_in_idp_after_termination BOOLEAN COMMENT 'True if the person also signed in to the IdP after termination',
  severity STRING COMMENT 'Critical (also signed in to the IdP or entered a restricted zone) or High',
  control_id STRING COMMENT 'Related grc_ref control: GRC-IAM-03 (closest existing control; no physical-access control exists)',
  control_name STRING COMMENT 'Related control name from grc_ref.controls',
  control_mapping STRING COMMENT 'Mapping strength and gap note for the control mapping',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_user_id EXPECT (user_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_termination_date EXPECT (hr_termination_date IS NOT NULL),
  CONSTRAINT badge_after_termination EXPECT (first_badge_in_after_termination_ts_local >= CAST(date_add(hr_termination_date, 1) AS TIMESTAMP_NTZ))
)
COMMENT 'Gold: one row per person with a granted physical badge-in after their HR termination date (badge credential not revoked at offboarding): first/last badge-in after termination (local and UTC), event and day counts, sites/doors and restricted-zone entries, denied attempts, and whether they also signed in to the IdP after termination. Related control GRC-IAM-03 (no physical-access control exists in grc_ref). Source: grc_silver.badge_access_identity, grc_silver.identity.'
TBLPROPERTIES ('quality' = 'gold', 'delta.feature.timestampNtz' = 'supported')
AS
WITH post AS (
  SELECT
    user_id,
    min(CASE WHEN event_type = 'ACCESS_GRANTED' THEN event_ts_local END) AS first_local,
    max(CASE WHEN event_type = 'ACCESS_GRANTED' THEN event_ts_local END) AS last_local,
    min(CASE WHEN event_type = 'ACCESS_GRANTED' THEN event_ts_utc END) AS first_utc,
    max(CASE WHEN event_type = 'ACCESS_GRANTED' THEN event_ts_utc END) AS last_utc,
    count_if(event_type = 'ACCESS_GRANTED') AS granted_events,
    count(DISTINCT CASE WHEN event_type = 'ACCESS_GRANTED' THEN event_date_local END) AS granted_days,
    array_sort(collect_set(CASE WHEN event_type = 'ACCESS_GRANTED' THEN site_code END)) AS sites,
    array_sort(collect_set(CASE WHEN event_type = 'ACCESS_GRANTED' THEN door_id END)) AS doors,
    count_if(event_type = 'ACCESS_GRANTED' AND zone IN ('Restricted', 'Critical')) AS restricted_entries,
    count_if(event_type = 'ACCESS_DENIED_BADGE_DISABLED') AS denied_attempts
  FROM grc_silver.badge_access_identity
  WHERE is_identity_matched AND is_after_termination
  GROUP BY user_id
),
ctl AS (
  SELECT control_id, control_name FROM grc_ref.controls WHERE control_id = 'GRC-IAM-03'
)
SELECT
  i.user_id,
  i.login,
  i.first_name,
  i.last_name,
  i.bu_id,
  bu.bu_name,
  i.hr_employee_id,
  i.hr_employment_status,
  i.hr_termination_date,
  i.is_orphan,
  i.is_enabled AS idp_is_enabled,
  p.first_local AS first_badge_in_after_termination_ts_local,
  p.last_local AS last_badge_in_after_termination_ts_local,
  p.first_utc AS first_badge_in_after_termination_ts_utc,
  p.last_utc AS last_badge_in_after_termination_ts_utc,
  p.granted_events AS badge_in_events_after_termination,
  p.granted_days AS badge_in_days_after_termination,
  datediff(to_date(p.last_local), i.hr_termination_date) AS days_termination_to_last_badge_in,
  p.sites AS sites_entered,
  p.doors AS doors_entered,
  p.restricted_entries AS restricted_zone_entries,
  p.denied_attempts AS denied_attempts_after_termination,
  coalesce(i.signins_after_termination, 0) AS idp_signins_after_termination,
  coalesce(i.signins_after_termination, 0) > 0 AS also_signed_in_idp_after_termination,
  CASE WHEN coalesce(i.signins_after_termination, 0) > 0 OR p.restricted_entries > 0 THEN 'Critical' ELSE 'High' END AS severity,
  ctl.control_id,
  ctl.control_name,
  'Related (partial): GRC-IAM-03 covers disabling leaver accounts; grc_ref has no physical-access control for badge revocation' AS control_mapping,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM post p
JOIN grc_silver.identity i ON p.user_id = i.user_id
LEFT JOIN grc_ref.business_units bu ON i.bu_id = bu.bu_id
CROSS JOIN ctl
WHERE p.granted_events > 0;

CREATE OR REFRESH MATERIALIZED VIEW grc_gold.physical_zone_anomalies (
  site_code STRING COMMENT 'Facility code',
  door_id STRING COMMENT 'Door identifier',
  door_name STRING COMMENT 'Door name',
  zone STRING COMMENT 'Restricted or Critical',
  event_date_local DATE COMMENT 'Local calendar date of the anomalies',
  forced_open_events BIGINT COMMENT 'DOOR_FORCED_OPEN events',
  held_open_events BIGINT COMMENT 'DOOR_HELD_OPEN events',
  after_hours_access_events BIGINT COMMENT 'ACCESS_GRANTED events outside 06:00-20:00 local or on weekends',
  denied_no_clearance_events BIGINT COMMENT 'ACCESS_DENIED_NO_CLEARANCE events',
  anomaly_events BIGINT COMMENT 'Total anomaly events (sum of the four categories)',
  distinct_badges_denied BIGINT COMMENT 'Distinct badges with ACCESS_DENIED_NO_CLEARANCE',
  denied_badge_ids ARRAY<STRING> COMMENT 'Badges with ACCESS_DENIED_NO_CLEARANCE',
  anomaly_types ARRAY<STRING> COMMENT 'Anomaly categories present (FORCED_OPEN, HELD_OPEN, AFTER_HOURS_ACCESS, DENIED_NO_CLEARANCE)',
  first_anomaly_ts_local TIMESTAMP_NTZ COMMENT 'First anomaly event (site local time)',
  last_anomaly_ts_local TIMESTAMP_NTZ COMMENT 'Latest anomaly event (site local time)',
  first_anomaly_ts_utc TIMESTAMP COMMENT 'First anomaly event (UTC)',
  last_anomaly_ts_utc TIMESTAMP COMMENT 'Latest anomaly event (UTC)',
  severity STRING COMMENT 'Critical (forced open in a Critical zone, or denied attempts followed by forced/held open), High (any door alarm), Medium otherwise',
  control_id STRING COMMENT 'Mapped grc_ref control (NULL: no physical-access control exists in grc_ref)',
  control_mapping STRING COMMENT 'Control-gap note',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_door EXPECT (door_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_date EXPECT (event_date_local IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_anomaly EXPECT (anomaly_events > 0)
)
COMMENT 'Gold: one row per Restricted/Critical-zone door and local date with physical-access anomalies: forced-open, held-open, after-hours granted access (outside 06:00-20:00 local or weekend) and denied-no-clearance events, with first/last time (local and UTC), denied badges and a severity. control_id is NULL because grc_ref has no physical-access control (control gap). Source: grc_silver.badge_access_event.'
TBLPROPERTIES ('quality' = 'gold', 'delta.feature.timestampNtz' = 'supported')
AS
WITH a AS (
  SELECT
    *,
    CASE
      WHEN event_type = 'DOOR_FORCED_OPEN' THEN 'FORCED_OPEN'
      WHEN event_type = 'DOOR_HELD_OPEN' THEN 'HELD_OPEN'
      WHEN event_type = 'ACCESS_DENIED_NO_CLEARANCE' THEN 'DENIED_NO_CLEARANCE'
      WHEN event_type = 'ACCESS_GRANTED' AND is_after_hours THEN 'AFTER_HOURS_ACCESS'
    END AS anomaly_type
  FROM grc_silver.badge_access_event
  WHERE is_restricted_zone
),
agg AS (
  SELECT
    site_code, door_id, door_name, zone, event_date_local,
    count_if(anomaly_type = 'FORCED_OPEN') AS forced_open_events,
    count_if(anomaly_type = 'HELD_OPEN') AS held_open_events,
    count_if(anomaly_type = 'AFTER_HOURS_ACCESS') AS after_hours_access_events,
    count_if(anomaly_type = 'DENIED_NO_CLEARANCE') AS denied_no_clearance_events,
    count(*) AS anomaly_events,
    count(DISTINCT CASE WHEN anomaly_type = 'DENIED_NO_CLEARANCE' THEN badge_id END) AS distinct_badges_denied,
    array_sort(collect_set(CASE WHEN anomaly_type = 'DENIED_NO_CLEARANCE' THEN badge_id END)) AS denied_badge_ids,
    array_sort(collect_set(anomaly_type)) AS anomaly_types,
    min(event_ts_local) AS first_anomaly_ts_local,
    max(event_ts_local) AS last_anomaly_ts_local,
    min(event_ts_utc) AS first_anomaly_ts_utc,
    max(event_ts_utc) AS last_anomaly_ts_utc,
    min(CASE WHEN anomaly_type = 'DENIED_NO_CLEARANCE' THEN event_ts_local END) AS first_denied_local,
    min(CASE WHEN anomaly_type IN ('FORCED_OPEN', 'HELD_OPEN') THEN event_ts_local END) AS first_alarm_local
  FROM a
  WHERE anomaly_type IS NOT NULL
  GROUP BY site_code, door_id, door_name, zone, event_date_local
)
SELECT
  site_code, door_id, door_name, zone, event_date_local,
  forced_open_events, held_open_events, after_hours_access_events, denied_no_clearance_events,
  anomaly_events, distinct_badges_denied, denied_badge_ids, anomaly_types,
  first_anomaly_ts_local, last_anomaly_ts_local, first_anomaly_ts_utc, last_anomaly_ts_utc,
  CASE
    WHEN zone = 'Critical' AND forced_open_events > 0 THEN 'Critical'
    WHEN first_denied_local IS NOT NULL AND first_alarm_local > first_denied_local THEN 'Critical'
    WHEN forced_open_events + held_open_events > 0 THEN 'High'
    ELSE 'Medium'
  END AS severity,
  CAST(NULL AS STRING) AS control_id,
  'Control gap: no physical-access / secure-area monitoring control in grc_ref (none mapped)' AS control_mapping,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM agg;

CREATE OR REFRESH MATERIALIZED VIEW grc_gold.physical_visitor_findings (
  visit_id STRING COMMENT 'Visit identifier (primary key); joins grc_silver.visitor_visit',
  visit_date DATE COMMENT 'Visit date (site local)',
  site_code STRING COMMENT 'Facility visited',
  is_dc1 BOOLEAN COMMENT 'True for the DC-1 data center',
  area_visited STRING COMMENT 'Area visited',
  area_zone STRING COMMENT 'Security zone of the area (matched to the badge door of the same name at the site; null if not a badged door)',
  is_restricted_area BOOLEAN COMMENT 'Area is a Restricted or Critical zone',
  visitor_name STRING COMMENT 'Visitor full name',
  visitor_company STRING COMMENT 'Visitor company',
  host_email STRING COMMENT 'Host email',
  escort_email STRING COMMENT 'Escort email (null if unescorted)',
  sign_in_ts_local TIMESTAMP_NTZ COMMENT 'Sign-in time (site local)',
  sign_out_ts_local TIMESTAMP_NTZ COMMENT 'Sign-out time (site local; null if not signed out)',
  is_escorted BOOLEAN COMMENT 'Escort recorded',
  nda_signed BOOLEAN COMMENT 'NDA signed',
  is_signed_out BOOLEAN COMMENT 'Sign-out recorded',
  finding_types ARRAY<STRING> COMMENT 'Findings: UNESCORTED, NO_NDA, NOT_SIGNED_OUT',
  finding_count INT COMMENT 'Number of findings',
  severity STRING COMMENT 'Critical (DC-1 restricted area, unescorted), High (other restricted area unescorted, or any DC-1 finding), Medium otherwise',
  control_id STRING COMMENT 'Mapped grc_ref control (NULL: no visitor-management control exists in grc_ref)',
  control_mapping STRING COMMENT 'Control-gap note',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_visit_id EXPECT (visit_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_finding EXPECT (finding_count > 0)
)
COMMENT 'Gold: one row per visitor visit with at least one finding (UNESCORTED, NO_NDA, NOT_SIGNED_OUT), with the security zone of the area visited, DC-1 emphasis (is_dc1) and a severity (Critical = unescorted in a DC-1 restricted/critical area). control_id is NULL because grc_ref has no visitor-management / physical-access control (control gap). Source: grc_silver.visitor_visit, grc_silver.badge_access_event (door zones).'
TBLPROPERTIES ('quality' = 'gold', 'delta.feature.timestampNtz' = 'supported')
AS
WITH zones AS (
  SELECT site_code, lower(door_name) AS area_key, max(zone) AS zone
  FROM grc_silver.badge_access_event
  GROUP BY site_code, lower(door_name)
),
v AS (
  SELECT
    vv.*,
    z.zone AS area_zone,
    coalesce(z.zone IN ('Restricted', 'Critical'), false) AS is_restricted_area,
    filter(array(
      CASE WHEN NOT vv.is_escorted THEN 'UNESCORTED' END,
      CASE WHEN NOT coalesce(vv.nda_signed, false) THEN 'NO_NDA' END,
      CASE WHEN NOT vv.is_signed_out THEN 'NOT_SIGNED_OUT' END
    ), x -> x IS NOT NULL) AS finding_types
  FROM grc_silver.visitor_visit vv
  LEFT JOIN zones z ON vv.site_code = z.site_code AND lower(vv.area_visited) = z.area_key
)
SELECT
  visit_id,
  visit_date,
  site_code,
  site_code = 'DC-1' AS is_dc1,
  area_visited,
  area_zone,
  is_restricted_area,
  visitor_name,
  visitor_company,
  host_email,
  escort_email,
  sign_in_ts_local,
  sign_out_ts_local,
  is_escorted,
  nda_signed,
  is_signed_out,
  finding_types,
  size(finding_types) AS finding_count,
  CASE
    WHEN site_code = 'DC-1' AND is_restricted_area AND NOT is_escorted THEN 'Critical'
    WHEN (is_restricted_area AND NOT is_escorted) OR site_code = 'DC-1' THEN 'High'
    ELSE 'Medium'
  END AS severity,
  CAST(NULL AS STRING) AS control_id,
  'Control gap: no visitor-management / physical-access control in grc_ref (none mapped)' AS control_mapping,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM v
WHERE size(finding_types) > 0;
