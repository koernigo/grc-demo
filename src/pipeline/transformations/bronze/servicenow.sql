-- Bronze: ServiceNow exports (CMDB configuration items, change requests, security incidents, vulnerable items).

CREATE OR REFRESH STREAMING TABLE grc_bronze.sn_cmdb_ci
COMMENT 'Bronze: raw ServiceNow cmdb_ci snapshot export (CSV, snapshot_<date>/ folders read recursively). Contains duplicate CI records by name - deduplicated in silver. Plus _source_file, _source_file_modified_ts, _snapshot_date and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'ServiceNow')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  coalesce(to_date(regexp_extract(_metadata.file_path, '([0-9]{4}-[0-9]{2}-[0-9]{2})', 1)), to_date(_metadata.file_modification_time)) AS _snapshot_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/servicenow/cmdb_ci/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv',
  schemaHints => 'u_criticality_tier STRING, ip_address STRING'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sn_change_request
COMMENT 'Bronze: raw ServiceNow change_request export (CSV). Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'ServiceNow')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/servicenow/change_request/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sn_security_incident
COMMENT 'Bronze: raw ServiceNow sn_si_incident (security incident) export (CSV with quoted free-text fields). Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'ServiceNow')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/servicenow/sn_si_incident/',
  format => 'csv',
  header => true,
  escape => '"',
  multiLine => true,
  pathGlobFilter => '*.csv'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sn_vulnerable_item
COMMENT 'Bronze: raw ServiceNow sn_vul_vulnerable_item (vulnerability remediation task) export (CSV). Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'ServiceNow')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/servicenow/sn_vul_vulnerable_item/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv',
  schemaHints => 'u_asset_tier STRING'
);
