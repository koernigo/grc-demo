-- Bronze: simulated on-prem NAS share \\acme-nas01\security, landed in a UC volume.
-- Stands in for Lakeflow Connect SFTP connector / NAS-to-cloud sync ingestion (same Auto Loader engine).
-- Explicit all-STRING schema: event_time is site-local wall-clock time (zone in site_tz) and sign-in/out are
-- clock values, so schema inference would mis-type them. Typing and time-zone handling belong in silver.

CREATE OR REFRESH STREAMING TABLE grc_bronze.nas_badge_access (
  event_id STRING COMMENT 'LenelS2 access-control event identifier.',
  event_time STRING COMMENT 'Event time as exported, yyyy-MM-dd HH:mm:ss in the site local time zone (see site_tz). Not UTC.',
  site_tz STRING COMMENT 'IANA time zone of the site, used to convert event_time to UTC.',
  site_code STRING COMMENT 'Facility code, e.g. HQ-NYC, DC-1.',
  door_id STRING COMMENT 'Door / reader location identifier, e.g. DC1-SR-01.',
  door_name STRING COMMENT 'Human-readable door name.',
  zone STRING COMMENT 'Security zone of the door (e.g. Perimeter, Restricted).',
  badge_id STRING COMMENT 'Physical badge / credential identifier.',
  cardholder_name STRING COMMENT 'Cardholder display name from the access-control system.',
  cardholder_email STRING COMMENT 'Cardholder corporate email - join key to HR / identity data.',
  cardholder_type STRING COMMENT 'Cardholder category, e.g. Employee, Contractor, Visitor.',
  event_type STRING COMMENT 'Access event type, e.g. ACCESS_GRANTED, ACCESS_DENIED, DOOR_FORCED_OPEN, DOOR_HELD_OPEN.',
  reader_serial STRING COMMENT 'Serial number of the badge reader that logged the event.',
  _rescued_data STRING COMMENT 'Auto Loader rescued data: values that did not match the declared schema.',
  _source_file STRING COMMENT 'Full path of the source export file on the NAS share volume.',
  _source_file_modified_ts TIMESTAMP COMMENT 'Modification time of the source file.',
  _export_date DATE COMMENT 'Export date parsed from the file name (LenelS2_export_YYYYMMDD.csv).',
  _ingest_ts TIMESTAMP COMMENT 'Time the row was ingested into bronze.'
)
COMMENT 'Bronze: raw physical access control (LenelS2) badge event exports from \\\\acme-nas01\\security (physical/badge_access/YYYY/MM/LenelS2_export_YYYYMMDD.csv), ingested incrementally from /Volumes/${grc_catalog}/grc_bronze/nas_share - simulates Lakeflow Connect SFTP / NAS-to-cloud sync ingestion. One row per access event, all source columns as strings, plus _source_file, _source_file_modified_ts, _export_date and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'LenelS2 (NAS share)')
AS SELECT
  event_id, event_time, site_tz, site_code, door_id, door_name, zone, badge_id,
  cardholder_name, cardholder_email, cardholder_type, event_type, reader_serial,
  _rescued_data,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  to_date(regexp_extract(_metadata.file_path, 'LenelS2_export_([0-9]{8})', 1), 'yyyyMMdd') AS _export_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/nas_share/acme-nas01/security/physical/badge_access/',
  format => 'csv',
  header => true,
  recursiveFileLookup => true,
  pathGlobFilter => '*.csv',
  schema => 'event_id STRING, event_time STRING, site_tz STRING, site_code STRING, door_id STRING, door_name STRING, zone STRING, badge_id STRING, cardholder_name STRING, cardholder_email STRING, cardholder_type STRING, event_type STRING, reader_serial STRING',
  rescuedDataColumn => '_rescued_data'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.nas_visitor_log (
  visit_id STRING COMMENT 'Visitor management system visit identifier.',
  visit_date STRING COMMENT 'Date of the visit as exported (yyyy-MM-dd).',
  site_code STRING COMMENT 'Facility visited, e.g. HQ-NYC, DC-1.',
  visitor_name STRING COMMENT 'Visitor full name.',
  visitor_company STRING COMMENT 'Company the visitor represents.',
  host_email STRING COMMENT 'Corporate email of the employee hosting the visit.',
  escort_email STRING COMMENT 'Corporate email of the escort; empty means the visitor was not escorted.',
  area_visited STRING COMMENT 'Area / zone visited, e.g. Floor 2, Server room.',
  sign_in_time STRING COMMENT 'Sign-in clock time as exported (site local time).',
  sign_out_time STRING COMMENT 'Sign-out clock time as exported (site local time); empty if not signed out.',
  nda_signed STRING COMMENT 'Whether the visitor signed an NDA (Y/N).',
  _rescued_data STRING COMMENT 'Auto Loader rescued data: values that did not match the declared schema.',
  _source_file STRING COMMENT 'Full path of the source weekly log file on the NAS share volume.',
  _source_file_modified_ts TIMESTAMP COMMENT 'Modification time of the source file.',
  _log_week STRING COMMENT 'ISO week parsed from the file name (visitor_log_YYYY-Www.csv), e.g. 2026-W31.',
  _ingest_ts TIMESTAMP COMMENT 'Time the row was ingested into bronze.'
)
COMMENT 'Bronze: raw weekly visitor sign-in logs from \\\\acme-nas01\\security (physical/visitor_log/YYYY/visitor_log_YYYY-Www.csv), ingested incrementally from /Volumes/${grc_catalog}/grc_bronze/nas_share - simulates Lakeflow Connect SFTP / NAS-to-cloud sync ingestion. One row per visit, all source columns as strings, plus _source_file, _source_file_modified_ts, _log_week and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Visitor management (NAS share)')
AS SELECT
  visit_id, visit_date, site_code, visitor_name, visitor_company, host_email, escort_email,
  area_visited, sign_in_time, sign_out_time, nda_signed,
  _rescued_data,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  regexp_extract(_metadata.file_path, 'visitor_log_([0-9]{4}-W[0-9]{2})', 1) AS _log_week,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/nas_share/acme-nas01/security/physical/visitor_log/',
  format => 'csv',
  header => true,
  recursiveFileLookup => true,
  pathGlobFilter => '*.csv',
  schema => 'visit_id STRING, visit_date STRING, site_code STRING, visitor_name STRING, visitor_company STRING, host_email STRING, escort_email STRING, area_visited STRING, sign_in_time STRING, sign_out_time STRING, nda_signed STRING',
  rescuedDataColumn => '_rescued_data'
);
