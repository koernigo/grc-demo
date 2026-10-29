-- Bronze: Tenable weekly vulnerability scan exports (CSV partitioned by scan_date).
CREATE OR REFRESH STREAMING TABLE grc_bronze.tenable_vuln_export
COMMENT 'Bronze: raw Tenable vulnerability export rows - one row per host x plugin/CVE per weekly scan (scan_date partition), with state Active/Fixed, CVSS v3 score, severity and CISA KEV flag. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Tenable')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/tenable/vuln_export/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);
