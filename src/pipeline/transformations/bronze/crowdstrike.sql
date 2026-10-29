-- Bronze: CrowdStrike Falcon EDR device inventory snapshots and detection alerts.

CREATE OR REFRESH STREAMING TABLE grc_bronze.crowdstrike_devices
COMMENT 'Bronze: raw CrowdStrike device inventory snapshot (JSON, devices/<date>/ folders read recursively) - one row per sensor/device with first_seen, last_seen, status (normal/contained) and agent version. Plus _source_file, _source_file_modified_ts, _snapshot_date and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'CrowdStrike')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  coalesce(to_date(regexp_extract(_metadata.file_path, '([0-9]{4}-[0-9]{2}-[0-9]{2})', 1)), to_date(_metadata.file_modification_time)) AS _snapshot_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/crowdstrike/devices/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.crowdstrike_alerts
COMMENT 'Bronze: raw CrowdStrike detection alerts (JSON partitioned by dt) with severity, MITRE tactic/technique, status, analyst, device struct and linked ServiceNow incident. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'CrowdStrike')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/crowdstrike/alerts/',
  format => 'json',
  pathGlobFilter => '*.json'
);
