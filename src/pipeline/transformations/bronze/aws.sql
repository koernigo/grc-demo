-- Bronze: AWS Config snapshot (S3 buckets, RDS instances, CloudTrail trails) and CloudTrail management events.

CREATE OR REFRESH STREAMING TABLE grc_bronze.aws_config_snapshot
COMMENT 'Bronze: raw AWS Config configuration items (JSON, config_snapshot/<date>/ folders read recursively) for AWS::S3::Bucket, AWS::RDS::DBInstance and AWS::CloudTrail::Trail. The nested configuration struct holds the union of resource-type specific fields. Plus _source_file, _source_file_modified_ts, _snapshot_date and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'AWS Config')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  coalesce(to_date(regexp_extract(_metadata.file_path, '([0-9]{4}-[0-9]{2}-[0-9]{2})', 1)), to_date(_metadata.file_modification_time)) AS _snapshot_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/aws/config_snapshot/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.aws_cloudtrail
COMMENT 'Bronze: raw AWS CloudTrail management events. Each delivered file row holds a Records array; records are exploded to one row per event and keep the raw CloudTrail record fields (userIdentity, eventTime, eventSource, eventName, requestParameters, ...) plus partition dt, _rescued_data, _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'AWS CloudTrail')
AS SELECT
  rec.*,
  dt,
  _rescued_data,
  _source_file,
  _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM (
  SELECT
    explode(Records) AS rec,
    dt,
    _rescued_data,
    _metadata.file_path AS _source_file,
    _metadata.file_modification_time AS _source_file_modified_ts
  FROM STREAM read_files(
    '/Volumes/${grc_catalog}/grc_bronze/landing/aws/cloudtrail/',
    format => 'json',
    pathGlobFilter => '*.json'
  )
);
