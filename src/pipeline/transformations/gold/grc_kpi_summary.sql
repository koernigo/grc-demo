-- Gold: executive GRC KPI summary (long format: one row per KPI) with targets and status.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.grc_kpi_summary (
  kpi_id STRING COMMENT 'KPI id, e.g. KPI-IAM-01 (primary key)',
  kpi_name STRING COMMENT 'KPI display name',
  kpi_domain STRING COMMENT 'KPI domain (Controls, Identity & Access, Cloud, Vulnerability, Assets, Detection & Response, Governance, People, Third Party, Physical Security)',
  kpi_value DOUBLE COMMENT 'KPI value as of as_of_date',
  unit STRING COMMENT 'Unit: count, %, USD',
  target_value DOUBLE COMMENT 'Target value (null = monitor only)',
  target_direction STRING COMMENT 'higher_is_better or lower_is_better',
  kpi_status STRING COMMENT 'On Target, Off Target or Monitor',
  related_control_id STRING COMMENT 'Unified control the KPI evidences',
  related_control_test_result STRING COMMENT 'Latest test result of the related control',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_kpi_id EXPECT (kpi_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT kpi_has_value EXPECT (kpi_value IS NOT NULL)
)
COMMENT 'Gold: one row per executive GRC KPI as of pipeline parameter as_of_date - control effectiveness, identity (orphans, post-termination sign-ins, MFA gaps, dormant, SoD, privileged reviews), cloud (root logins without MFA, StopLogging events, trails not logging, public buckets, unencrypted confidential data, backups), vulnerability (open, critical, KEV, SLA compliance), asset coverage (EDR, scanning, CMDB), detection and response (alert triage SLA, incidents), governance (policies overdue, expired-but-active exceptions, risks without owner, ALE), people (training, phishing), third-party (vendor assessments, SOC 2) and physical security (post-termination badge use, critical-zone door alarms, unescorted restricted visits, visitor log completeness). Includes unit, target, direction, On Target / Off Target status and related control.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH ctl AS (
  SELECT
    round(avg(pass_rate_pct), 2) AS avg_pass_rate,
    count_if(effectiveness_band = 'Effective') AS effective,
    count_if(effectiveness_band = 'Partially Effective') AS partial,
    count_if(effectiveness_band = 'Ineffective') AS ineffective,
    count(*) AS total
  FROM grc_gold.control_test_results
),
idn AS (
  SELECT
    count_if(is_orphan) AS orphans,
    count_if(is_orphan AND signins_after_termination > 0) AS orphans_with_signins,
    count_if(is_enabled AND user_type = 'workforce' AND NOT mfa_enrolled) AS workforce_no_mfa,
    round(100.0 * count_if(is_enabled AND user_type = 'workforce' AND mfa_enrolled) / nullif(count_if(is_enabled AND user_type = 'workforce'), 0), 2) AS mfa_coverage_pct,
    count_if(is_dormant) AS dormant,
    count_if(is_enabled AND sod_conflict_count > 0) AS sod_users,
    count_if(is_enabled AND is_privileged AND NOT phishing_resistant_mfa) AS weak_priv_mfa
  FROM grc_silver.identity
),
ent AS (
  SELECT count_if(review_overdue AND is_identity_enabled) AS priv_reviews_overdue FROM grc_silver.entitlement
),
fin AS (
  SELECT count(*) AS fin_no_mfa_signins_30d
  FROM grc_silver.authentication_event a
  JOIN grc_silver.identity i ON a.user_id = i.user_id
  WHERE i.bu_id = 'BU-FIN' AND a.result = 'SUCCESS' AND NOT a.mfa_verified
    AND a.event_date > date_sub(CAST(:as_of_date AS DATE), 30) AND a.event_date <= CAST(:as_of_date AS DATE)
),
sec AS (
  SELECT
    count_if(principal_type = 'Root' AND action = 'ConsoleLogin' AND NOT coalesce(mfa_used, false)) AS root_no_mfa,
    count_if(action IN ('StopLogging', 'DeleteTrail')) AS stoplogging,
    count_if(event_source_system = 'crowdstrike_edr') AS edr_alerts
  FROM grc_silver.security_event
),
cld AS (
  SELECT
    count_if(resource_kind = 'CloudTrail Trail' AND NOT delivering_within_24h) AS trails_not_logging,
    count_if(resource_kind = 'S3 Bucket' AND is_public) AS public_buckets,
    count_if(resource_kind IN ('S3 Bucket', 'RDS Instance') AND data_classification IN ('Confidential', 'Restricted') AND NOT coalesce(is_encrypted, false)) AS unencrypted_confidential,
    count_if(resource_kind = 'RDS Instance' AND tier IN ('T0', 'T1') AND NOT backup_within_24h) AS backup_failures
  FROM grc_silver.cloud_config
),
vul AS (
  SELECT
    count_if(is_open) AS open_findings,
    count_if(is_open AND severity = 'Critical') AS open_critical,
    count_if(is_open_on_latest_scan AND is_kev) AS open_kev_latest,
    count_if(is_open AND is_overdue) AS open_past_sla,
    round(100.0 * count_if(NOT sla_breached AND (is_open OR remediated_date >= date_sub(CAST(:as_of_date AS DATE), 90)))
          / nullif(count_if(is_open OR remediated_date >= date_sub(CAST(:as_of_date AS DATE), 90)), 0), 2) AS sla_pct
  FROM grc_silver.vulnerability_finding
),
ast AS (
  SELECT
    count_if(is_active AND edr_required AND NOT has_edr) AS no_edr,
    round(100.0 * count_if(is_active AND edr_required AND edr_healthy) / nullif(count_if(is_active AND edr_required), 0), 2) AS edr_coverage_pct,
    round(100.0 * count_if(is_active AND coalesce(days_since_last_scan <= 7, false)) / nullif(count_if(is_active), 0), 2) AS scan_coverage_pct,
    round(100.0 * count_if(is_active AND is_cmdb_complete) / nullif(count_if(is_active), 0), 2) AS cmdb_complete_pct
  FROM grc_silver.asset
),
tri AS (
  SELECT round(100.0 * count_if(NOT is_exception) / nullif(count(*), 0), 2) AS triage_sla_pct
  FROM grc_gold.control_test_evidence WHERE test_id = 'T-LOG-02'
),
inc AS (
  SELECT
    count_if(is_open) AS open_incidents,
    count_if(NOT coalesce(containment_sla_met, false)) AS containment_breaches
  FROM grc_silver.remediation_ticket WHERE ticket_type = 'security_incident'
),
inc_alerts AS (
  SELECT coalesce(max(n), 0) AS alerts_linked_top_incident
  FROM (
    SELECT linked_incident_id, count(*) AS n
    FROM grc_silver.security_event
    WHERE event_source_system = 'crowdstrike_edr' AND linked_incident_id IS NOT NULL
    GROUP BY linked_incident_id
  )
),
gov AS (
  SELECT
    (SELECT count_if(is_review_overdue) FROM grc_silver.policy) AS policies_overdue,
    (SELECT count_if(is_expired_but_active) FROM grc_silver.risk_exception) AS expired_active_exc,
    (SELECT count_if(NOT has_owner) FROM grc_silver.risk) AS risks_no_owner,
    (SELECT count_if(residual_rating IN ('Critical', 'High')) FROM grc_gold.risk_register_scored) AS high_residual_risks,
    (SELECT sum(residual_ale_usd) FROM grc_gold.risk_register_scored WHERE is_open) AS residual_ale
),
trn AS (
  SELECT
    round(100.0 * count_if(training_current) / nullif(count(*), 0), 2) AS training_pct,
    round(100.0 * sum(phishing_clicked) / nullif(sum(phishing_campaigns_received), 0), 2) AS click_rate_pct
  FROM grc_silver.training_status
),
vnd AS (
  SELECT
    count_if(requires_annual_assessment AND assessment_overdue) AS vendors_overdue,
    count_if(criticality = 'Critical' AND assessment_age_days > 365) AS critical_vendors_over_365,
    count_if(criticality IN ('Critical', 'High') AND soc2_expired) AS soc2_expired
  FROM grc_silver.vendor
),
chg AS (
  SELECT count_if(is_exception) AS unticketed_changes FROM grc_gold.control_test_evidence WHERE test_id = 'T-CFG-02'
),
-- Physical security (NAS badge / visitor data). Only PHY-01 has a related control (GRC-IAM-03, partial);
-- grc_ref has no physical-access control, so PHY-02..04 have no related_control_id (control gap).
phy AS (
  SELECT
    (SELECT count(*) FROM grc_gold.physical_post_termination_badge_use) AS post_term_badge_people,
    (SELECT coalesce(sum(forced_open_events + held_open_events), 0) FROM grc_gold.physical_zone_anomalies
      WHERE zone = 'Critical' AND event_date_local > date_sub(CAST(:as_of_date AS DATE), 30) AND event_date_local <= CAST(:as_of_date AS DATE)) AS critical_door_alarms_30d,
    (SELECT count(*) FROM grc_gold.physical_visitor_findings
      WHERE array_contains(finding_types, 'UNESCORTED') AND area_zone IN ('Restricted', 'Critical')
        AND visit_date > date_sub(CAST(:as_of_date AS DATE), 30) AND visit_date <= CAST(:as_of_date AS DATE)) AS unescorted_restricted_visits_30d,
    (SELECT round(100.0 * count_if(f.visit_id IS NULL) / nullif(count(*), 0), 2)
      FROM grc_silver.visitor_visit v
      LEFT JOIN (
        SELECT visit_id FROM grc_gold.physical_visitor_findings
        WHERE array_contains(finding_types, 'NO_NDA') OR array_contains(finding_types, 'NOT_SIGNED_OUT')
           OR (array_contains(finding_types, 'UNESCORTED') AND area_zone IN ('Restricted', 'Critical'))
      ) f ON v.visit_id = f.visit_id
      WHERE v.visit_date > date_sub(CAST(:as_of_date AS DATE), 30) AND v.visit_date <= CAST(:as_of_date AS DATE)) AS visitor_log_complete_pct_30d
),
k AS (
  SELECT stack(40,
    'KPI-CTL-01', 'Average control test pass rate', 'Controls', CAST(ctl.avg_pass_rate AS DOUBLE), '%', 95.0D, 'higher_is_better', CAST(NULL AS STRING),
    'KPI-CTL-02', 'Controls rated Effective', 'Controls', CAST(ctl.effective AS DOUBLE), 'count', CAST(ctl.total AS DOUBLE), 'higher_is_better', CAST(NULL AS STRING),
    'KPI-CTL-03', 'Controls rated Ineffective', 'Controls', CAST(ctl.ineffective AS DOUBLE), 'count', 0.0D, 'lower_is_better', CAST(NULL AS STRING),
    'KPI-IAM-01', 'Orphaned accounts (terminated in HR, active in IdP)', 'Identity', CAST(idn.orphans AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-03',
    'KPI-IAM-02', 'Orphaned accounts with sign-ins after termination', 'Identity', CAST(idn.orphans_with_signins AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-03',
    'KPI-IAM-03', 'Active workforce accounts without MFA', 'Identity', CAST(idn.workforce_no_mfa AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-01',
    'KPI-IAM-04', 'Workforce MFA coverage', 'Identity', CAST(idn.mfa_coverage_pct AS DOUBLE), '%', 99.0D, 'higher_is_better', 'GRC-IAM-01',
    'KPI-IAM-05', 'Finance sign-ins without MFA (last 30 days)', 'Identity', CAST(fin.fin_no_mfa_signins_30d AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-01',
    'KPI-IAM-06', 'Dormant enabled accounts (> 90 days)', 'Identity', CAST(idn.dormant AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-04',
    'KPI-IAM-07', 'Users with SoD conflicts', 'Identity', CAST(idn.sod_users AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-06',
    'KPI-IAM-08', 'Privileged entitlements past 90-day review', 'Identity', CAST(ent.priv_reviews_overdue AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-05',
    'KPI-IAM-09', 'Privileged accounts without phishing-resistant MFA', 'Identity', CAST(idn.weak_priv_mfa AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-02',
    'KPI-CLD-01', 'Root console logins without MFA', 'Cloud', CAST(sec.root_no_mfa AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-07',
    'KPI-CLD-02', 'CloudTrail StopLogging / DeleteTrail events', 'Cloud', CAST(sec.stoplogging AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-LOG-01',
    'KPI-CLD-03', 'CloudTrail trails not delivering (24h)', 'Cloud', CAST(cld.trails_not_logging AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-LOG-01',
    'KPI-CLD-04', 'Public S3 buckets', 'Cloud', CAST(cld.public_buckets AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-CFG-01',
    'KPI-CLD-05', 'Unencrypted confidential data stores', 'Cloud', CAST(cld.unencrypted_confidential AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-DAT-01',
    'KPI-CLD-06', 'Tier 0/1 databases without backup in 24h', 'Cloud', CAST(cld.backup_failures AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-DAT-02',
    'KPI-CLD-07', 'Unapproved production changes', 'Cloud', CAST(chg.unticketed_changes AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-CFG-02',
    'KPI-VUL-01', 'Open vulnerability findings', 'Vulnerability', CAST(vul.open_findings AS DOUBLE), 'count', CAST(NULL AS DOUBLE), 'lower_is_better', 'GRC-VUL-02',
    'KPI-VUL-02', 'Open critical findings', 'Vulnerability', CAST(vul.open_critical AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-VUL-02',
    'KPI-VUL-03', 'Open CISA KEV findings on latest scan', 'Vulnerability', CAST(vul.open_kev_latest AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-VUL-03',
    'KPI-VUL-04', 'Vulnerability SLA compliance', 'Vulnerability', CAST(vul.sla_pct AS DOUBLE), '%', 95.0D, 'higher_is_better', 'GRC-VUL-02',
    'KPI-AST-01', 'Active servers/endpoints without EDR', 'Assets', CAST(ast.no_edr AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-AST-02',
    'KPI-AST-02', 'EDR healthy coverage', 'Assets', CAST(ast.edr_coverage_pct AS DOUBLE), '%', 98.0D, 'higher_is_better', 'GRC-AST-02',
    'KPI-AST-03', 'Vulnerability scan coverage (7 days)', 'Assets', CAST(ast.scan_coverage_pct AS DOUBLE), '%', 95.0D, 'higher_is_better', 'GRC-VUL-01',
    'KPI-AST-04', 'CMDB completeness', 'Assets', CAST(ast.cmdb_complete_pct AS DOUBLE), '%', 98.0D, 'higher_is_better', 'GRC-AST-01',
    'KPI-IR-01', 'EDR alerts triaged within SLA', 'Detection & Response', CAST(tri.triage_sla_pct AS DOUBLE), '%', 95.0D, 'higher_is_better', 'GRC-LOG-02',
    'KPI-IR-02', 'Max EDR alerts linked to a single incident', 'Detection & Response', CAST(inc_alerts.alerts_linked_top_incident AS DOUBLE), 'count', CAST(NULL AS DOUBLE), 'lower_is_better', 'GRC-IR-01',
    'KPI-IR-03', 'Incidents breaching containment SLA', 'Detection & Response', CAST(inc.containment_breaches AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IR-01',
    'KPI-GOV-01', 'Policies overdue for review', 'Governance', CAST(gov.policies_overdue AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-POL-01',
    'KPI-GOV-02', 'Active exceptions past expiry', 'Governance', CAST(gov.expired_active_exc AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-POL-02',
    'KPI-GOV-03', 'Risks without owner', 'Governance', CAST(gov.risks_no_owner AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-RSK-01',
    'KPI-GOV-04', 'Open residual ALE (USD)', 'Governance', CAST(gov.residual_ale AS DOUBLE), 'USD', CAST(NULL AS DOUBLE), 'lower_is_better', 'GRC-RSK-01',
    'KPI-PPL-01', 'Security awareness training completion', 'People', CAST(trn.training_pct AS DOUBLE), '%', 95.0D, 'higher_is_better', 'GRC-TRN-01',
    'KPI-TPR-01', 'Critical vendors with assessment older than 365 days', 'Third Party', CAST(vnd.critical_vendors_over_365 AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-VND-01',
    'KPI-PHY-01', 'People badging in after termination', 'Physical Security', CAST(phy.post_term_badge_people AS DOUBLE), 'count', 0.0D, 'lower_is_better', 'GRC-IAM-03',
    'KPI-PHY-02', 'Critical-zone door alarms (forced/held open, last 30 days)', 'Physical Security', CAST(phy.critical_door_alarms_30d AS DOUBLE), 'count', 0.0D, 'lower_is_better', CAST(NULL AS STRING),
    'KPI-PHY-03', 'Unescorted restricted-area visits (last 30 days)', 'Physical Security', CAST(phy.unescorted_restricted_visits_30d AS DOUBLE), 'count', 0.0D, 'lower_is_better', CAST(NULL AS STRING),
    'KPI-PHY-04', 'Visitor log completeness (last 30 days)', 'Physical Security', CAST(phy.visitor_log_complete_pct_30d AS DOUBLE), '%', 98.0D, 'higher_is_better', CAST(NULL AS STRING)
  ) AS (kpi_id, kpi_name, kpi_domain, kpi_value, unit, target_value, target_direction, related_control_id)
  FROM ctl, idn, ent, fin, sec, cld, vul, ast, tri, inc, inc_alerts, gov, trn, vnd, chg, phy
)
SELECT
  k.kpi_id,
  k.kpi_name,
  k.kpi_domain,
  k.kpi_value,
  k.unit,
  k.target_value,
  k.target_direction,
  CASE
    WHEN k.target_value IS NULL THEN 'Monitor'
    WHEN k.target_direction = 'higher_is_better' AND k.kpi_value >= k.target_value THEN 'On Target'
    WHEN k.target_direction = 'lower_is_better' AND k.kpi_value <= k.target_value THEN 'On Target'
    ELSE 'Off Target'
  END AS kpi_status,
  k.related_control_id,
  t.test_result AS related_control_test_result,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM k
LEFT JOIN grc_gold.control_test_results t ON k.related_control_id = t.control_id;
