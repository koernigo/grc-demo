-- Bronze: Workday worker snapshots (CSV). Snapshot folders (workers_snapshot_<date>/) are discovered recursively by Auto Loader.
CREATE OR REFRESH STREAMING TABLE grc_bronze.hr_workers
COMMENT 'Bronze: raw Workday worker snapshot rows (one row per worker per snapshot file) ingested incrementally from /Volumes/${grc_catalog}/grc_bronze/landing/hr. Raw source columns plus _source_file, _source_file_modified_ts, _snapshot_date (date parsed from the snapshot folder) and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Workday')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  coalesce(to_date(regexp_extract(_metadata.file_path, '([0-9]{4}-[0-9]{2}-[0-9]{2})', 1)), to_date(_metadata.file_modification_time)) AS _snapshot_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/hr/',
  format => 'csv',
  header => true,
  pathGlobFilter => '*.csv'
);
