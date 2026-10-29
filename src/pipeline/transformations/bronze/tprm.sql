-- Bronze: Third-party risk management (TPRM) vendor assessment export.
CREATE OR REFRESH STREAMING TABLE grc_bronze.tprm_vendor_assessments
COMMENT 'Bronze: raw TPRM vendor register / assessment export (CSV) - one row per vendor with criticality, data access, spend, last assessment date and score, SOC 2 report expiry and open findings. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'TPRM')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/tprm/vendor_assessments/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);
