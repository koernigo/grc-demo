-- Silver: CMDB assets deduplicated and reconciled with EDR inventory and vulnerability scan coverage.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.asset (
  asset_id STRING COMMENT 'ServiceNow CMDB sys_id of the configuration item (surviving record after name dedup)',
  asset_name STRING COMMENT 'Hostname / CI name; join key to EDR and scanner hostnames (case-insensitive)',
  asset_class STRING COMMENT 'ServiceNow CI class (sys_class_name), e.g. cmdb_ci_linux_server',
  asset_category STRING COMMENT 'Normalized category: Server, Endpoint, Database, Network Device, Other',
  os STRING COMMENT 'Operating system from CMDB',
  ip_address STRING COMMENT 'Primary IP address from CMDB',
  bu_id STRING COMMENT 'Owning business unit (grc_ref.business_units.bu_id)',
  owner_email STRING COMMENT 'Lower-cased email of the CI owner (owned_by)',
  tier STRING COMMENT 'Criticality tier T0 (crown jewel) to T3 (low)',
  tier_name STRING COMMENT 'Tier display name from grc_ref.asset_tiers',
  tier_sla_multiplier DOUBLE COMMENT 'Multiplier applied to vulnerability remediation SLA days for this tier',
  environment STRING COMMENT 'Deployment environment (prod, staging, dev, ...)',
  internet_facing BOOLEAN COMMENT 'True if the asset is exposed to the internet',
  cloud_account STRING COMMENT 'Cloud account name hosting the asset, if any',
  data_classification STRING COMMENT 'Highest data classification processed by the asset',
  install_status STRING COMMENT 'CMDB install status (Installed, Retired, ...)',
  is_active BOOLEAN COMMENT 'True when install_status = Installed; defines the active asset population',
  cmdb_updated_ts TIMESTAMP COMMENT 'CMDB sys_updated_on of the surviving record',
  cmdb_record_count BIGINT COMMENT 'Number of CMDB records sharing this asset name in the latest snapshot',
  has_duplicate_cmdb_records BOOLEAN COMMENT 'True if more than one CMDB record exists for the name',
  is_cmdb_complete BOOLEAN COMMENT 'True if owner, business unit and tier are all populated (control GRC-AST-01)',
  edr_required BOOLEAN COMMENT 'True for servers and endpoints, which must run the EDR agent',
  edr_device_id STRING COMMENT 'CrowdStrike device_id matched by hostname from the latest device inventory',
  has_edr BOOLEAN COMMENT 'True if a CrowdStrike agent is registered for the host',
  edr_last_seen_ts TIMESTAMP COMMENT 'Last EDR agent check-in time',
  edr_status STRING COMMENT 'CrowdStrike device status',
  edr_agent_version STRING COMMENT 'Installed CrowdStrike sensor version',
  edr_reduced_functionality BOOLEAN COMMENT 'True if the sensor runs in reduced functionality mode',
  edr_stale BOOLEAN COMMENT 'True if the agent has not checked in for more than 7 days before the end of as_of_date',
  edr_healthy BOOLEAN COMMENT 'True if an EDR agent exists and is not stale (control GRC-AST-02)',
  last_scan_date DATE COMMENT 'Most recent Tenable scan date that reported the host',
  days_since_last_scan INT COMMENT 'Days between last_scan_date and as_of_date',
  scanned_last_14d BOOLEAN COMMENT 'True if scanned within 14 days of as_of_date',
  open_vuln_count BIGINT COMMENT 'Distinct open CVEs on the host latest scan',
  open_critical_count BIGINT COMMENT 'Distinct open Critical-severity CVEs on the host latest scan',
  open_kev_count BIGINT COMMENT 'Distinct open CISA KEV CVEs on the host latest scan',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file the CMDB record was ingested from',
  CONSTRAINT valid_asset_id EXPECT (asset_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_asset_name EXPECT (asset_name IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL),
  CONSTRAINT has_owner EXPECT (owner_email IS NOT NULL),
  CONSTRAINT valid_tier EXPECT (tier IN ('T0', 'T1', 'T2', 'T3'))
)
COMMENT 'Silver: one row per configuration item from the latest ServiceNow CMDB snapshot, deduplicated by name (latest sys_updated_on wins; cmdb_record_count shows duplicates). Reconciled with the latest CrowdStrike device inventory (has_edr, edr_last_seen_ts, edr_stale > 7 days) and Tenable scans (last_scan_date, scanned_last_14d, open vulnerability counts on the host''s latest scan). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH c_all AS (
  SELECT *
  FROM grc_bronze.sn_cmdb_ci
  WHERE _snapshot_date = (SELECT max(_snapshot_date) FROM grc_bronze.sn_cmdb_ci)
),
c AS (
  SELECT *, count(*) OVER (PARTITION BY lower(name)) AS cmdb_record_count
  FROM c_all
  QUALIFY row_number() OVER (PARTITION BY lower(name) ORDER BY sys_updated_on DESC, sys_id) = 1
),
d AS (
  SELECT
    lower(hostname) AS host_key,
    device_id,
    to_timestamp(last_seen) AS last_seen_ts,
    status,
    agent_version,
    reduced_functionality_mode
  FROM grc_bronze.crowdstrike_devices
  WHERE _snapshot_date = (SELECT max(_snapshot_date) FROM grc_bronze.crowdstrike_devices)
  QUALIFY row_number() OVER (PARTITION BY lower(hostname) ORDER BY to_timestamp(last_seen) DESC) = 1
),
s AS (
  SELECT lower(hostname) AS host_key, max(scan_date) AS last_scan_date
  FROM grc_bronze.tenable_vuln_export
  GROUP BY lower(hostname)
),
o AS (
  SELECT
    lower(t.hostname) AS host_key,
    count(DISTINCT t.cve) AS open_vuln_count,
    count(DISTINCT CASE WHEN t.severity = 'Critical' THEN t.cve END) AS open_critical_count,
    count(DISTINCT CASE WHEN t.cisa_kev THEN t.cve END) AS open_kev_count
  FROM grc_bronze.tenable_vuln_export t
  JOIN s ON lower(t.hostname) = s.host_key AND t.scan_date = s.last_scan_date
  WHERE t.state = 'Active'
  GROUP BY lower(t.hostname)
),
t AS (
  SELECT tier_code, tier_name, sla_multiplier FROM grc_ref.asset_tiers
)
SELECT
  c.sys_id AS asset_id,
  c.name AS asset_name,
  c.sys_class_name AS asset_class,
  CASE c.sys_class_name
    WHEN 'cmdb_ci_linux_server' THEN 'Server'
    WHEN 'cmdb_ci_win_server' THEN 'Server'
    WHEN 'cmdb_ci_computer' THEN 'Endpoint'
    WHEN 'cmdb_ci_db_instance' THEN 'Database'
    WHEN 'cmdb_ci_netgear' THEN 'Network Device'
    ELSE 'Other'
  END AS asset_category,
  c.os,
  c.ip_address,
  c.u_business_unit AS bu_id,
  lower(c.owned_by) AS owner_email,
  c.u_criticality_tier AS tier,
  t.tier_name,
  t.sla_multiplier AS tier_sla_multiplier,
  c.environment,
  c.internet_facing,
  c.cloud_account,
  c.data_classification,
  c.install_status,
  c.install_status = 'Installed' AS is_active,
  c.sys_updated_on AS cmdb_updated_ts,
  c.cmdb_record_count,
  c.cmdb_record_count > 1 AS has_duplicate_cmdb_records,
  (c.owned_by IS NOT NULL AND c.u_business_unit IS NOT NULL AND c.u_criticality_tier IS NOT NULL) AS is_cmdb_complete,
  c.sys_class_name IN ('cmdb_ci_linux_server', 'cmdb_ci_win_server', 'cmdb_ci_computer') AS edr_required,
  d.device_id AS edr_device_id,
  d.device_id IS NOT NULL AS has_edr,
  d.last_seen_ts AS edr_last_seen_ts,
  d.status AS edr_status,
  d.agent_version AS edr_agent_version,
  coalesce(d.reduced_functionality_mode = 'yes', false) AS edr_reduced_functionality,
  coalesce(d.last_seen_ts < CAST(date_add(CAST(:as_of_date AS DATE), 1) AS TIMESTAMP) - INTERVAL 7 DAYS, false) AS edr_stale,
  d.device_id IS NOT NULL AND NOT edr_stale AS edr_healthy,
  s.last_scan_date,
  datediff(CAST(:as_of_date AS DATE), s.last_scan_date) AS days_since_last_scan,
  coalesce(datediff(CAST(:as_of_date AS DATE), s.last_scan_date) <= 14, false) AS scanned_last_14d,
  coalesce(o.open_vuln_count, 0) AS open_vuln_count,
  coalesce(o.open_critical_count, 0) AS open_critical_count,
  coalesce(o.open_kev_count, 0) AS open_kev_count,
  CAST(:as_of_date AS DATE) AS as_of_date,
  c._source_file
FROM c
LEFT JOIN d ON lower(c.name) = d.host_key
LEFT JOIN s ON lower(c.name) = s.host_key
LEFT JOIN o ON lower(c.name) = o.host_key
LEFT JOIN t ON c.u_criticality_tier = t.tier_code;
