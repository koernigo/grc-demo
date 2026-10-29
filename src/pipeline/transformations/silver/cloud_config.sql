-- Silver: cloud resource posture from the latest AWS Config snapshot (S3 buckets, RDS instances, CloudTrail trails).
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.cloud_config (
  resource_arn STRING COMMENT 'AWS resource ARN (primary key)',
  resource_type STRING COMMENT 'AWS Config resourceType, e.g. AWS::S3::Bucket',
  resource_kind STRING COMMENT 'Normalized kind: S3 Bucket, RDS Instance, CloudTrail Trail',
  resource_id STRING COMMENT 'AWS resourceId',
  resource_name STRING COMMENT 'AWS resource name',
  account_id STRING COMMENT 'AWS account id',
  account_name STRING COMMENT 'Account name taken from CloudTrail trail tags',
  is_production_account BOOLEAN COMMENT 'False for accounts whose name contains dev or sandbox',
  region STRING COMMENT 'AWS region',
  capture_ts TIMESTAMP COMMENT 'AWS Config configurationItemCaptureTime',
  bu_id STRING COMMENT 'Owning business unit from resource tag bu',
  data_classification STRING COMMENT 'Data classification from resource tag',
  tier STRING COMMENT 'Criticality tier from resource tag (T0-T3)',
  cmdb_sys_id STRING COMMENT 'Linked ServiceNow CMDB sys_id from resource tag',
  is_public BOOLEAN COMMENT 'S3 only: bucket ACL grants AllUsers (control GRC-CFG-01)',
  public_access_block_enabled BOOLEAN COMMENT 'S3 only: S3 Block Public Access enabled',
  access_logging_enabled BOOLEAN COMMENT 'S3 only: server access logging enabled',
  encryption_algorithm STRING COMMENT 'Server-side encryption algorithm (S3)',
  is_encrypted BOOLEAN COMMENT 'S3/RDS: encryption at rest enabled (control GRC-DAT-01)',
  db_engine STRING COMMENT 'RDS only: database engine',
  backup_retention_days BIGINT COMMENT 'RDS only: automated backup retention period in days',
  last_backup_ts TIMESTAMP COMMENT 'RDS only: latest restorable time (last successful backup)',
  last_restore_test_date DATE COMMENT 'RDS only: date of last restore test',
  backup_within_24h BOOLEAN COMMENT 'RDS only: successful backup within 24h of the end of as_of_date (control GRC-DAT-02)',
  restore_test_within_90d BOOLEAN COMMENT 'RDS only: restore tested within 90 days of as_of_date',
  is_logging BOOLEAN COMMENT 'CloudTrail only: trail logging enabled',
  last_delivery_ts TIMESTAMP COMMENT 'CloudTrail only: latest log delivery time',
  delivering_within_24h BOOLEAN COMMENT 'CloudTrail only: logging and delivered within 24h of the end of as_of_date (control GRC-LOG-01)',
  is_multi_region_trail BOOLEAN COMMENT 'CloudTrail only: multi-region trail',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the AWS Config snapshot',
  CONSTRAINT valid_resource_arn EXPECT (resource_arn IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT known_resource_type EXPECT (resource_kind IS NOT NULL),
  CONSTRAINT account_mapped EXPECT (account_name IS NOT NULL),
  CONSTRAINT valid_capture_ts EXPECT (capture_ts IS NOT NULL)
)
COMMENT 'Silver: one row per AWS resource in the latest AWS Config snapshot. S3 buckets: is_public (ACL grants AllUsers), public access block, encryption, access logging. RDS instances: storage encryption, last backup (latestRestorableTime), backup within 24h, last restore test and restore test within 90 days. CloudTrail trails: is_logging, last delivery and delivering within 24h. Account names come from the trail tags; is_production_account = account name not matching dev/sandbox. Evaluated as of the end of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH c AS (
  SELECT *
  FROM grc_bronze.aws_config_snapshot
  WHERE _snapshot_date = (SELECT max(_snapshot_date) FROM grc_bronze.aws_config_snapshot)
  QUALIFY row_number() OVER (PARTITION BY ARN ORDER BY to_timestamp(configurationItemCaptureTime) DESC, _ingest_ts DESC) = 1
),
acct AS (
  SELECT awsAccountId, max(tags.account_name) AS account_name
  FROM c
  WHERE resourceType = 'AWS::CloudTrail::Trail'
  GROUP BY awsAccountId
)
SELECT
  c.ARN AS resource_arn,
  c.resourceType AS resource_type,
  CASE c.resourceType
    WHEN 'AWS::S3::Bucket' THEN 'S3 Bucket'
    WHEN 'AWS::RDS::DBInstance' THEN 'RDS Instance'
    WHEN 'AWS::CloudTrail::Trail' THEN 'CloudTrail Trail'
  END AS resource_kind,
  c.resourceId AS resource_id,
  c.resourceName AS resource_name,
  c.awsAccountId AS account_id,
  acct.account_name,
  NOT coalesce(acct.account_name RLIKE 'dev|sandbox', false) AS is_production_account,
  c.awsRegion AS region,
  to_timestamp(c.configurationItemCaptureTime) AS capture_ts,
  c.tags.bu AS bu_id,
  c.tags.data_classification AS data_classification,
  c.tags.tier AS tier,
  c.tags.cmdb_sys_id AS cmdb_sys_id,
  CASE WHEN c.resourceType = 'AWS::S3::Bucket' THEN coalesce(c.configuration.aclGrantsAllUsers, false) END AS is_public,
  CASE WHEN c.resourceType = 'AWS::S3::Bucket' THEN c.configuration.publicAccessBlockEnabled END AS public_access_block_enabled,
  CASE WHEN c.resourceType = 'AWS::S3::Bucket' THEN c.configuration.serverAccessLoggingEnabled END AS access_logging_enabled,
  c.configuration.sseAlgorithm AS encryption_algorithm,
  CASE
    WHEN c.resourceType = 'AWS::S3::Bucket' THEN c.configuration.sseAlgorithm IS NOT NULL
    WHEN c.resourceType = 'AWS::RDS::DBInstance' THEN coalesce(c.configuration.storageEncrypted, false)
  END AS is_encrypted,
  c.configuration.engine AS db_engine,
  c.configuration.backupRetentionPeriod AS backup_retention_days,
  to_timestamp(c.configuration.latestRestorableTime) AS last_backup_ts,
  to_date(c.configuration.lastRestoreTestDate) AS last_restore_test_date,
  CASE WHEN c.resourceType = 'AWS::RDS::DBInstance' THEN
    coalesce(to_timestamp(c.configuration.latestRestorableTime) >= CAST(date_add(CAST(:as_of_date AS DATE), 1) AS TIMESTAMP) - INTERVAL 24 HOURS, false)
  END AS backup_within_24h,
  CASE WHEN c.resourceType = 'AWS::RDS::DBInstance' THEN
    coalesce(datediff(CAST(:as_of_date AS DATE), to_date(c.configuration.lastRestoreTestDate)) <= 90, false)
  END AS restore_test_within_90d,
  c.configuration.isLogging AS is_logging,
  to_timestamp(c.configuration.latestDeliveryTime) AS last_delivery_ts,
  CASE WHEN c.resourceType = 'AWS::CloudTrail::Trail' THEN
    coalesce(c.configuration.isLogging AND to_timestamp(c.configuration.latestDeliveryTime) >= CAST(date_add(CAST(:as_of_date AS DATE), 1) AS TIMESTAMP) - INTERVAL 24 HOURS, false)
  END AS delivering_within_24h,
  c.configuration.isMultiRegionTrail AS is_multi_region_trail,
  CAST(:as_of_date AS DATE) AS as_of_date,
  c._source_file
FROM c
LEFT JOIN acct ON c.awsAccountId = acct.awsAccountId;
