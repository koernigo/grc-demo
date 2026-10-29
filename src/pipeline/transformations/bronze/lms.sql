-- Bronze: Learning management system exports (training enrollments, phishing simulation results).

CREATE OR REFRESH STREAMING TABLE grc_bronze.lms_enrollments
COMMENT 'Bronze: raw LMS course enrollment export (CSV) - one row per user x course with assigned/due/completion dates, status and score. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'LMS')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/lms/enrollments/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.lms_phishing_results
COMMENT 'Bronze: raw phishing simulation results (CSV) - one row per user x campaign with delivered/opened/clicked/data_entered/reported flags. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'LMS')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/lms/phishing_results/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);
