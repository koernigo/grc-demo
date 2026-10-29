-- Bronze: Okta identity provider exports (users, groups, group memberships, System Log sign-ins).

CREATE OR REFRESH STREAMING TABLE grc_bronze.okta_users
COMMENT 'Bronze: raw Okta /api/v1/users export (one row per user per export file) with nested profile struct and factors array. Plus _source_file, _source_file_modified_ts, _snapshot_date and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Okta')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  coalesce(to_date(regexp_extract(_metadata.file_path, '([0-9]{4}-[0-9]{2}-[0-9]{2})', 1)), to_date(_metadata.file_modification_time)) AS _snapshot_date,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/okta/users/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.okta_groups
COMMENT 'Bronze: raw Okta groups export (group_id, profile.name/description, type, created). Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Okta')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/okta/groups/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.okta_group_memberships
COMMENT 'Bronze: raw Okta group membership export (Parquet) - one row per user x group, including added_ts and last_access_review_date / reviewed_by from the access review tool. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Okta')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/okta/group_memberships/',
  format => 'parquet',
  pathGlobFilter => '*.parquet'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.okta_system_log
COMMENT 'Bronze: raw Okta System Log user.session.start events (JSON, partitioned by event_date) with nested actor, client, outcome, authenticationContext and target structs. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'Okta')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/okta/system_log/',
  format => 'json',
  pathGlobFilter => '*.json'
);
