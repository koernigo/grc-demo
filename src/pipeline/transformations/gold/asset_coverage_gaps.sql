-- Gold: active assets with at least one security tooling / inventory coverage gap.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.asset_coverage_gaps (
  asset_id STRING COMMENT 'CMDB asset id (primary key)',
  asset_name STRING COMMENT 'Hostname / CI name',
  asset_class STRING COMMENT 'ServiceNow CI class',
  asset_category STRING COMMENT 'Server, Endpoint, Database, Network Device, Other',
  os STRING COMMENT 'Operating system',
  ip_address STRING COMMENT 'IP address',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  owner_email STRING COMMENT 'Asset owner email',
  tier STRING COMMENT 'Criticality tier',
  environment STRING COMMENT 'Environment',
  internet_facing BOOLEAN COMMENT 'Internet facing',
  data_classification STRING COMMENT 'Data classification',
  edr_required BOOLEAN COMMENT 'EDR agent required (servers and endpoints)',
  has_edr BOOLEAN COMMENT 'EDR agent registered',
  edr_last_seen_ts TIMESTAMP COMMENT 'Last EDR check-in',
  edr_stale BOOLEAN COMMENT 'EDR agent not seen for more than 7 days',
  last_scan_date DATE COMMENT 'Last vulnerability scan date',
  days_since_last_scan INT COMMENT 'Days since last scan',
  open_vuln_count BIGINT COMMENT 'Open vulnerabilities',
  open_critical_count BIGINT COMMENT 'Open critical vulnerabilities',
  open_kev_count BIGINT COMMENT 'Open KEV vulnerabilities',
  cmdb_record_count BIGINT COMMENT 'CMDB records sharing this name',
  gap_types ARRAY<STRING> COMMENT 'Coverage gaps: NO_EDR, EDR_STALE, NOT_SCANNED_7D, CMDB_INCOMPLETE, DUPLICATE_CMDB, ...',
  gap_count INT COMMENT 'Number of gap types',
  gap_priority STRING COMMENT 'Critical, High, Medium or Low based on tier, exposure and gap type',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_asset_id EXPECT (asset_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_gap EXPECT (gap_count > 0)
)
COMMENT 'Gold: one row per active (Installed) CMDB asset with at least one coverage gap: NO_EDR (server/endpoint without CrowdStrike agent), STALE_EDR (agent not seen for > 7 days), NOT_SCANNED (no vulnerability scan in last 7 days), CMDB_INCOMPLETE (missing owner/BU/tier), DUPLICATE_CMDB_RECORD, OPEN_KEV (open CISA KEV finding) and INTERNET_FACING_CRITICAL (internet-facing with open critical findings). gap_priority ranks remediation (Critical/High/Medium/Low) by tier, exposure and gap type. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH a AS (
  SELECT
    *,
    filter(array(
      CASE WHEN edr_required AND NOT has_edr THEN 'NO_EDR' END,
      CASE WHEN has_edr AND edr_stale THEN 'STALE_EDR' END,
      CASE WHEN NOT coalesce(days_since_last_scan <= 7, false) THEN 'NOT_SCANNED' END,
      CASE WHEN NOT is_cmdb_complete THEN 'CMDB_INCOMPLETE' END,
      CASE WHEN has_duplicate_cmdb_records THEN 'DUPLICATE_CMDB_RECORD' END,
      CASE WHEN open_kev_count > 0 THEN 'OPEN_KEV' END,
      CASE WHEN internet_facing AND open_critical_count > 0 THEN 'INTERNET_FACING_CRITICAL' END
    ), x -> x IS NOT NULL) AS gap_types
  FROM grc_silver.asset
  WHERE is_active
)
SELECT
  a.asset_id,
  a.asset_name,
  a.asset_class,
  a.asset_category,
  a.os,
  a.ip_address,
  a.bu_id,
  b.bu_name,
  a.owner_email,
  a.tier,
  a.environment,
  a.internet_facing,
  a.data_classification,
  a.edr_required,
  a.has_edr,
  a.edr_last_seen_ts,
  a.edr_stale,
  a.last_scan_date,
  a.days_since_last_scan,
  a.open_vuln_count,
  a.open_critical_count,
  a.open_kev_count,
  a.cmdb_record_count,
  a.gap_types,
  size(a.gap_types) AS gap_count,
  CASE
    WHEN (a.tier IN ('T0', 'T1') OR a.internet_facing) AND (array_contains(a.gap_types, 'NO_EDR') OR array_contains(a.gap_types, 'OPEN_KEV') OR array_contains(a.gap_types, 'INTERNET_FACING_CRITICAL')) THEN 'Critical'
    WHEN array_contains(a.gap_types, 'NO_EDR') OR array_contains(a.gap_types, 'OPEN_KEV') OR array_contains(a.gap_types, 'STALE_EDR') THEN 'High'
    WHEN array_contains(a.gap_types, 'NOT_SCANNED') OR array_contains(a.gap_types, 'CMDB_INCOMPLETE') THEN 'Medium'
    ELSE 'Low'
  END AS gap_priority,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM a
LEFT JOIN grc_ref.business_units b ON a.bu_id = b.bu_id
WHERE size(a.gap_types) > 0;
