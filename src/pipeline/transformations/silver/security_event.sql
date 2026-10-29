-- Silver: normalized security events (OCSF-style) from AWS CloudTrail and CrowdStrike EDR alerts, one append flow per source.
CREATE OR REFRESH STREAMING TABLE grc_silver.security_event (
  event_id STRING COMMENT 'CloudTrail eventID or CrowdStrike composite_id',
  event_source_system STRING COMMENT 'aws_cloudtrail or crowdstrike_edr',
  event_class STRING COMMENT 'OCSF-style class: Authentication, API Activity, Detection Finding',
  event_category STRING COMMENT 'login, security_config_change, read, write or edr_alert',
  event_time TIMESTAMP COMMENT 'Event time (UTC)',
  event_date DATE COMMENT 'Event date (UTC)',
  actor STRING COMMENT 'CloudTrail: lower-cased user / role name, or root',
  actor_arn STRING COMMENT 'CloudTrail: principal ARN',
  principal_type STRING COMMENT 'CloudTrail: Root, Human (SSO) or Service',
  account_id STRING COMMENT 'CloudTrail: AWS account id',
  region STRING COMMENT 'CloudTrail: AWS region',
  service STRING COMMENT 'AWS eventSource or crowdstrike.falcon',
  action STRING COMMENT 'CloudTrail eventName or EDR technique',
  is_read_only BOOLEAN COMMENT 'CloudTrail: read-only API call',
  mfa_used BOOLEAN COMMENT 'CloudTrail: MFA used for console login / session',
  source_ip STRING COMMENT 'CloudTrail: source IP address',
  user_agent STRING COMMENT 'CloudTrail: user agent',
  status STRING COMMENT 'CloudTrail: Success / Failure; EDR: Open / Closed',
  error_code STRING COMMENT 'CloudTrail: error code for failed calls',
  target_resource STRING COMMENT 'Target resource (bucket, role, user, DB, SG, trail or host)',
  policy_arn STRING COMMENT 'CloudTrail: attached IAM policy ARN',
  cidr_ip STRING COMMENT 'CloudTrail: CIDR opened by a security group change',
  acl_grant STRING COMMENT 'CloudTrail: S3 ACL granted',
  severity STRING COMMENT 'EDR: alert severity',
  tactic STRING COMMENT 'EDR: MITRE ATT&CK tactic',
  technique_id STRING COMMENT 'EDR: MITRE ATT&CK technique id',
  technique STRING COMMENT 'EDR: MITRE ATT&CK technique name',
  alert_status STRING COMMENT 'EDR: alert workflow status',
  assigned_to STRING COMMENT 'EDR: assigned analyst',
  triaged_ts TIMESTAMP COMMENT 'EDR: first status change (triage) time',
  triage_minutes DOUBLE COMMENT 'EDR: minutes from alert creation to triage',
  device_id STRING COMMENT 'EDR: CrowdStrike device id',
  device_hostname STRING COMMENT 'EDR: device hostname',
  linked_incident_id STRING COMMENT 'EDR: linked ServiceNow security incident number',
  _source_file STRING COMMENT 'Landing file the event was ingested from',
  _ingest_ts TIMESTAMP COMMENT 'Time the event was ingested into bronze',
  CONSTRAINT valid_event_id EXPECT (event_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_event_time EXPECT (event_time IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_actor_or_device EXPECT (actor IS NOT NULL OR device_hostname IS NOT NULL),
  CONSTRAINT edr_alert_has_severity EXPECT (event_source_system <> 'crowdstrike_edr' OR severity IS NOT NULL)
)
COMMENT 'Silver: unified, OCSF-style security event table. event_source_system = aws_cloudtrail (API Activity / Authentication: actor, principal type, account, region, service, action, MFA used, source IP, target resource) or crowdstrike_edr (Detection Finding: severity, MITRE tactic/technique, alert status, analyst, triage time, device, linked incident). Columns not applicable to a source are NULL.'
TBLPROPERTIES ('quality' = 'silver')
CLUSTER BY (event_date, event_source_system);

CREATE FLOW security_event_cloudtrail
COMMENT 'Normalize AWS CloudTrail management events into grc_silver.security_event'
AS INSERT INTO grc_silver.security_event BY NAME
SELECT
  eventID AS event_id,
  'aws_cloudtrail' AS event_source_system,
  CASE WHEN eventName = 'ConsoleLogin' THEN 'Authentication' ELSE 'API Activity' END AS event_class,
  CASE
    WHEN eventName = 'ConsoleLogin' THEN 'login'
    WHEN eventName IN ('AttachRolePolicy', 'PutRolePolicy', 'CreateUser', 'CreateAccessKey', 'AttachUserPolicy',
                       'AuthorizeSecurityGroupIngress', 'PutBucketPolicy', 'PutBucketAcl', 'DeletePublicAccessBlock',
                       'ModifyDBInstance', 'DisableKey', 'StopLogging', 'DeleteTrail') THEN 'security_config_change'
    WHEN readOnly THEN 'read'
    ELSE 'write'
  END AS event_category,
  to_timestamp(eventTime) AS event_time,
  to_date(to_timestamp(eventTime)) AS event_date,
  CASE WHEN userIdentity.type = 'Root' THEN 'root' ELSE lower(userIdentity.userName) END AS actor,
  userIdentity.arn AS actor_arn,
  CASE
    WHEN userIdentity.type = 'Root' THEN 'Root'
    WHEN userIdentity.arn LIKE '%AWSReservedSSO%' THEN 'Human (SSO)'
    ELSE 'Service'
  END AS principal_type,
  coalesce(recipientAccountId, userIdentity.accountId) AS account_id,
  awsRegion AS region,
  eventSource AS service,
  eventName AS action,
  readOnly AS is_read_only,
  CASE
    WHEN eventName = 'ConsoleLogin' THEN additionalEventData.MFAUsed = 'Yes'
    ELSE userIdentity.sessionContext.attributes.mfaAuthenticated = 'true'
  END AS mfa_used,
  sourceIPAddress AS source_ip,
  userAgent AS user_agent,
  CASE WHEN errorCode IS NULL THEN 'Success' ELSE 'Failure' END AS status,
  errorCode AS error_code,
  coalesce(requestParameters.bucketName, requestParameters.roleName, requestParameters.userName,
           requestParameters.dBInstanceIdentifier, requestParameters.groupId, requestParameters.name) AS target_resource,
  requestParameters.policyArn AS policy_arn,
  requestParameters.cidrIp AS cidr_ip,
  requestParameters.accessControlList AS acl_grant,
  CAST(NULL AS STRING) AS severity,
  CAST(NULL AS STRING) AS tactic,
  CAST(NULL AS STRING) AS technique_id,
  CAST(NULL AS STRING) AS technique,
  CAST(NULL AS STRING) AS alert_status,
  CAST(NULL AS STRING) AS assigned_to,
  CAST(NULL AS TIMESTAMP) AS triaged_ts,
  CAST(NULL AS DOUBLE) AS triage_minutes,
  CAST(NULL AS STRING) AS device_id,
  CAST(NULL AS STRING) AS device_hostname,
  CAST(NULL AS STRING) AS linked_incident_id,
  _source_file,
  _ingest_ts
FROM STREAM(grc_bronze.aws_cloudtrail);

CREATE FLOW security_event_edr_alerts
COMMENT 'Normalize CrowdStrike detection alerts into grc_silver.security_event'
AS INSERT INTO grc_silver.security_event BY NAME
SELECT
  composite_id AS event_id,
  'crowdstrike_edr' AS event_source_system,
  'Detection Finding' AS event_class,
  'edr_alert' AS event_category,
  to_timestamp(created_timestamp) AS event_time,
  to_date(to_timestamp(created_timestamp)) AS event_date,
  CAST(NULL AS STRING) AS actor,
  CAST(NULL AS STRING) AS actor_arn,
  CAST(NULL AS STRING) AS principal_type,
  CAST(NULL AS STRING) AS account_id,
  CAST(NULL AS STRING) AS region,
  'crowdstrike.falcon' AS service,
  technique AS action,
  CAST(NULL AS BOOLEAN) AS is_read_only,
  CAST(NULL AS BOOLEAN) AS mfa_used,
  CAST(NULL AS STRING) AS source_ip,
  CAST(NULL AS STRING) AS user_agent,
  CASE WHEN status IN ('closed', 'false_positive') THEN 'Closed' ELSE 'Open' END AS status,
  CAST(NULL AS STRING) AS error_code,
  device.hostname AS target_resource,
  CAST(NULL AS STRING) AS policy_arn,
  CAST(NULL AS STRING) AS cidr_ip,
  CAST(NULL AS STRING) AS acl_grant,
  severity_name AS severity,
  tactic,
  technique_id,
  technique,
  status AS alert_status,
  assigned_to_name AS assigned_to,
  to_timestamp(first_status_change_timestamp) AS triaged_ts,
  CAST(round((unix_timestamp(to_timestamp(first_status_change_timestamp)) - unix_timestamp(to_timestamp(created_timestamp))) / 60.0, 1) AS DOUBLE) AS triage_minutes,
  device.device_id AS device_id,
  device.hostname AS device_hostname,
  linked_incident AS linked_incident_id,
  _source_file,
  _ingest_ts
FROM STREAM(grc_bronze.crowdstrike_alerts);
