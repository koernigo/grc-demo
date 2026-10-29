-- Gold: row-level control test evidence. One row per (test, population member) with a pass/exception outcome.
-- All 24 tests from grc_ref.control_test_catalog are evaluated here; grc_gold.control_test_results aggregates this table.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.control_test_evidence (
  test_run_date DATE COMMENT 'Control test run date (pipeline parameter as_of_date)',
  test_id STRING COMMENT 'Control test id (grc_ref.control_test_catalog)',
  control_id STRING COMMENT 'Unified control id tested (grc_ref.controls)',
  evidence_id STRING COMMENT 'Unique evidence row key: test_id:entity_id',
  entity_type STRING COMMENT 'Type of population member: identity, entitlement, asset, finding, event, resource, policy, risk, exception, vendor, incident, change',
  entity_id STRING COMMENT 'Key of the population member in its source silver table',
  entity_name STRING COMMENT 'Human-readable name of the population member',
  bu_id STRING COMMENT 'Business unit of the population member',
  owner_email STRING COMMENT 'Accountable owner for remediation',
  severity STRING COMMENT 'Severity of the exception (Critical, High, Medium, Low)',
  observed_ts TIMESTAMP COMMENT 'Time the condition was observed (event time, scan date or snapshot time)',
  due_date DATE COMMENT 'Remediation due date where an SLA applies',
  is_exception BOOLEAN COMMENT 'True if the member fails the test pass condition (null treated as exception)',
  exception_reason STRING COMMENT 'Why the member failed the test (null when passing)',
  source_table STRING COMMENT 'Silver table the evidence row was derived from',
  CONSTRAINT valid_test_id EXPECT (test_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_entity_id EXPECT (entity_id IS NOT NULL),
  CONSTRAINT exception_has_reason EXPECT (NOT is_exception OR exception_reason IS NOT NULL)
)
COMMENT 'Gold: audit-ready, row-level evidence for every automated control test in grc_ref.control_test_catalog. One row per test x population member (identity, entitlement, asset, finding, cloud resource, event, ticket, policy, exception, risk, vendor) with is_exception, a human-readable exception_reason, severity, owner, due date and the silver source table. Filter is_exception = true for the failing population of a test. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
CLUSTER BY (test_id)
AS
WITH cfg AS (
  SELECT
    CAST(:as_of_date AS DATE) AS as_of,
    CAST(date_add(CAST(:as_of_date AS DATE), 1) AS TIMESTAMP) AS as_of_end_ts,
    max(CASE WHEN sla_type = 'SCAN_FREQUENCY' THEN sla_value END) AS scan_days,
    max(CASE WHEN sla_type = 'KEV_REMEDIATION' THEN sla_value END) AS kev_days,
    max(CASE WHEN sla_type = 'LEAVER_DEPROVISION' THEN sla_value END) AS leaver_hours
  FROM grc_ref.sla_policy
),
acct AS (
  SELECT DISTINCT account_id, account_name, is_production_account
  FROM grc_silver.cloud_config
  WHERE account_name IS NOT NULL
),
chg AS (
  SELECT ticket_id, cloud_account, assigned_to, planned_start_ts, planned_end_ts
  FROM grc_silver.remediation_ticket
  WHERE ticket_type = 'change' AND approval_status = 'approved'
),
root_logins AS (
  SELECT e.event_id, e.event_time, e.source_ip, e.mfa_used, a.account_name,
         max(CASE WHEN c.ticket_id IS NOT NULL THEN 1 ELSE 0 END) = 1 AS has_ticket
  FROM grc_silver.security_event e
  LEFT JOIN acct a ON e.account_id = a.account_id
  LEFT JOIN chg c ON c.cloud_account = a.account_name AND e.event_time BETWEEN c.planned_start_ts AND c.planned_end_ts
  WHERE e.event_source_system = 'aws_cloudtrail' AND e.principal_type = 'Root' AND e.action = 'ConsoleLogin'
  GROUP BY e.event_id, e.event_time, e.source_ip, e.mfa_used, a.account_name
),
prod_changes AS (
  SELECT e.event_id, e.event_time, e.actor, e.action, e.target_resource, a.account_name,
         max(CASE WHEN c.ticket_id IS NOT NULL THEN 1 ELSE 0 END) = 1 AS has_ticket
  FROM grc_silver.security_event e
  JOIN acct a ON e.account_id = a.account_id
  LEFT JOIN chg c
    ON c.cloud_account = a.account_name
   AND c.assigned_to = e.actor
   AND e.event_time BETWEEN c.planned_start_ts AND c.planned_end_ts
  WHERE e.event_source_system = 'aws_cloudtrail'
    AND e.event_category = 'security_config_change'
    AND a.is_production_account
  GROUP BY e.event_id, e.event_time, e.actor, e.action, e.target_resource, a.account_name
),
s3 AS (
  SELECT c.resource_arn, c.resource_name, c.bu_id, c.data_classification, c.capture_ts, c.is_public,
         max(CASE WHEN x.exception_id IS NOT NULL THEN 1 ELSE 0 END) = 1 AS has_valid_exception
  FROM grc_silver.cloud_config c
  LEFT JOIN grc_silver.risk_exception x
    ON x.control_id = 'GRC-CFG-01' AND x.is_valid AND x.bu_id = c.bu_id
  WHERE c.resource_kind = 'S3 Bucket'
  GROUP BY c.resource_arn, c.resource_name, c.bu_id, c.data_classification, c.capture_ts, c.is_public
),
alerts AS (
  SELECT e.event_id, e.event_time, e.severity, e.technique, e.device_hostname, e.assigned_to, e.triaged_ts,
         e.triage_minutes, s.sla_value AS sla_hours, ast.bu_id
  FROM grc_silver.security_event e
  LEFT JOIN grc_ref.sla_policy s ON s.sla_type = 'ALERT_TRIAGE' AND s.severity = e.severity
  LEFT JOIN grc_silver.asset ast ON lower(e.device_hostname) = lower(ast.asset_name)
  WHERE e.event_source_system = 'crowdstrike_edr'
),
vf AS (
  SELECT f.*, a.owner_email
  FROM grc_silver.vulnerability_finding f
  CROSS JOIN cfg
  LEFT JOIN grc_silver.asset a ON f.asset_id = a.asset_id
  WHERE f.is_open OR f.remediated_date >= date_sub(cfg.as_of, 90)
),
ev AS (
  -- T-IAM-01 Workforce MFA enrollment
  SELECT 'T-IAM-01' AS test_id, 'identity' AS entity_type, user_id AS entity_id, login AS entity_name, bu_id,
         login AS owner_email, 'High' AS severity, last_signin_ts AS observed_ts, CAST(NULL AS DATE) AS due_date,
         NOT mfa_enrolled AS is_exception,
         CASE WHEN NOT mfa_enrolled THEN 'Active workforce account has no active MFA factor enrolled' END AS exception_reason,
         'grc_silver.identity' AS source_table
  FROM grc_silver.identity
  WHERE user_type = 'workforce' AND is_enabled

  UNION ALL
  -- T-IAM-02 Privileged MFA enforcement
  SELECT 'T-IAM-02', 'identity', user_id, login, bu_id, login, 'Critical', last_signin_ts, CAST(NULL AS DATE),
         NOT phishing_resistant_mfa,
         CASE WHEN NOT phishing_resistant_mfa THEN concat('Privileged account (', array_join(privileged_groups, ', '), ') uses MFA type: ', mfa_type) END,
         'grc_silver.identity'
  FROM grc_silver.identity
  WHERE is_enabled AND is_privileged

  UNION ALL
  -- T-IAM-03 Leaver deprovisioning timeliness
  SELECT 'T-IAM-03', 'identity', i.user_id, i.login, i.bu_id, i.login,
         CASE WHEN i.signins_after_termination > 0 THEN 'Critical' WHEN i.disabled_ts IS NULL THEN 'High' ELSE 'Medium' END,
         i.termination_ts,
         to_date(i.termination_ts + make_interval(0, 0, 0, 0, cfg.leaver_hours, 0, 0)),
         NOT coalesce(i.deprovision_hours <= cfg.leaver_hours, false)
           AND NOT (i.disabled_ts IS NULL AND i.termination_ts > cfg.as_of_end_ts - make_interval(0, 0, 0, 0, cfg.leaver_hours, 0, 0)),
         CASE
           WHEN coalesce(i.deprovision_hours <= cfg.leaver_hours, false) THEN NULL
           WHEN i.disabled_ts IS NULL AND i.termination_ts > cfg.as_of_end_ts - make_interval(0, 0, 0, 0, cfg.leaver_hours, 0, 0) THEN NULL
           WHEN i.disabled_ts IS NULL THEN concat('Terminated in HR on ', CAST(i.hr_termination_date AS STRING), ' but IdP account still ACTIVE',
                CASE WHEN i.signins_after_termination > 0 THEN concat(' - ', CAST(i.signins_after_termination AS STRING), ' sign-in events after termination') ELSE '' END)
           ELSE concat('Account disabled ', CAST(i.deprovision_hours AS STRING), 'h after termination (SLA ', CAST(cfg.leaver_hours AS STRING), 'h)')
         END,
         'grc_silver.identity'
  FROM grc_silver.identity i
  CROSS JOIN cfg
  WHERE i.user_type = 'workforce' AND i.hr_termination_date IS NOT NULL AND i.hr_termination_date <= cfg.as_of

  UNION ALL
  -- T-IAM-04 Dormant account check
  SELECT 'T-IAM-04', 'identity', user_id, login, bu_id, login,
         CASE WHEN is_privileged OR user_type = 'admin' THEN 'High' ELSE 'Medium' END,
         last_signin_ts, CAST(NULL AS DATE),
         is_dormant,
         CASE WHEN is_dormant THEN concat('Enabled ', user_type, ' account with no sign-in for ', CAST(days_since_last_signin AS STRING), ' days') END,
         'grc_silver.identity'
  FROM grc_silver.identity
  WHERE is_enabled

  UNION ALL
  -- T-IAM-05 Privileged access recertification
  SELECT 'T-IAM-05', 'entitlement', entitlement_id, concat(login, ' -> ', group_name), bu_id, reviewed_by, 'High',
         CAST(last_access_review_date AS TIMESTAMP), date_add(last_access_review_date, review_sla_days),
         review_overdue,
         CASE WHEN review_overdue THEN concat('Privileged entitlement ', group_name, ' last reviewed ',
              coalesce(CAST(last_access_review_date AS STRING), 'never'), ' (', coalesce(CAST(days_since_review AS STRING), 'n/a'), ' days ago)') END,
         'grc_silver.entitlement'
  FROM grc_silver.entitlement
  WHERE is_privileged AND is_identity_enabled

  UNION ALL
  -- T-IAM-06 SoD conflict scan
  SELECT 'T-IAM-06', 'identity', user_id, login, bu_id, login, 'High', last_signin_ts, CAST(NULL AS DATE),
         sod_conflict_count > 0,
         CASE WHEN sod_conflict_count > 0 THEN concat('Toxic entitlement combination: ', array_join(sod_rules, ', ')) END,
         'grc_silver.identity'
  FROM grc_silver.identity
  WHERE is_enabled

  UNION ALL
  -- T-IAM-07 Root account usage review
  SELECT 'T-IAM-07', 'security_event', event_id, concat('Root ConsoleLogin - ', coalesce(account_name, 'unknown account'), ' from ', source_ip),
         CAST(NULL AS STRING), CAST(NULL AS STRING), 'Critical', event_time, CAST(NULL AS DATE),
         NOT (coalesce(mfa_used, false) AND has_ticket),
         nullif(concat_ws('; ',
           CASE WHEN NOT coalesce(mfa_used, false) THEN 'Root console login without MFA' END,
           CASE WHEN NOT has_ticket THEN 'No approved change ticket covering the login' END), ''),
         'grc_silver.security_event'
  FROM root_logins

  UNION ALL
  -- T-AST-01 CMDB completeness
  SELECT 'T-AST-01', 'asset', asset_id, asset_name, bu_id, owner_email, 'Medium', cmdb_updated_ts, CAST(NULL AS DATE),
         NOT is_cmdb_complete,
         CASE WHEN NOT is_cmdb_complete THEN concat('CMDB record missing: ', concat_ws(', ',
           CASE WHEN owner_email IS NULL THEN 'owner' END,
           CASE WHEN bu_id IS NULL THEN 'business unit' END,
           CASE WHEN tier IS NULL THEN 'criticality tier' END)) END,
         'grc_silver.asset'
  FROM grc_silver.asset
  WHERE is_active

  UNION ALL
  -- T-AST-02 EDR agent health
  SELECT 'T-AST-02', 'asset', asset_id, asset_name, bu_id, owner_email,
         CASE WHEN tier IN ('T0', 'T1') OR internet_facing THEN 'High' ELSE 'Medium' END,
         edr_last_seen_ts, CAST(NULL AS DATE),
         NOT edr_healthy,
         CASE WHEN NOT has_edr THEN concat('No EDR agent on ', asset_category, ' (', coalesce(os, 'unknown OS'), ')')
              WHEN edr_stale THEN concat('EDR agent stale - last check-in ', CAST(edr_last_seen_ts AS STRING)) END,
         'grc_silver.asset'
  FROM grc_silver.asset
  WHERE is_active AND edr_required

  UNION ALL
  -- T-VUL-01 Scanner coverage
  SELECT 'T-VUL-01', 'asset', a.asset_id, a.asset_name, a.bu_id, a.owner_email, 'Medium',
         CAST(a.last_scan_date AS TIMESTAMP), CAST(NULL AS DATE),
         NOT coalesce(a.days_since_last_scan <= cfg.scan_days, false),
         CASE WHEN a.last_scan_date IS NULL THEN 'Asset never seen by the vulnerability scanner'
              WHEN a.days_since_last_scan > cfg.scan_days THEN concat('Last scanned ', CAST(a.last_scan_date AS STRING), ' (', CAST(a.days_since_last_scan AS STRING), ' days ago)') END,
         'grc_silver.asset'
  FROM grc_silver.asset a
  CROSS JOIN cfg
  WHERE a.is_active

  UNION ALL
  -- T-VUL-02 Vulnerability SLA adherence
  SELECT 'T-VUL-02', 'vulnerability_finding', finding_id, concat(hostname, ' / ', cve), bu_id, owner_email, severity,
         CAST(first_found AS TIMESTAMP), sla_due_date,
         sla_breached,
         CASE WHEN sla_breached AND is_open THEN concat(severity, ' ', cve, ' open ', CAST(days_open AS STRING), ' days (SLA ', CAST(sla_days AS STRING), ' days)')
              WHEN sla_breached THEN concat(severity, ' ', cve, ' remediated after ', CAST(days_open AS STRING), ' days (SLA ', CAST(sla_days AS STRING), ' days)') END,
         'grc_silver.vulnerability_finding'
  FROM vf

  UNION ALL
  -- T-VUL-03 KEV remediation
  SELECT 'T-VUL-03', 'vulnerability_finding', vf.finding_id, concat(vf.hostname, ' / ', vf.cve), vf.bu_id, vf.owner_email, 'Critical',
         CAST(vf.first_found AS TIMESTAMP), date_add(vf.first_found, cfg.kev_days),
         vf.days_open > cfg.kev_days,
         CASE WHEN vf.days_open > cfg.kev_days THEN concat('CISA KEV ', vf.cve, CASE WHEN vf.is_open THEN ' open ' ELSE ' remediated after ' END,
              CAST(vf.days_open AS STRING), ' days (SLA ', CAST(cfg.kev_days AS STRING), ' days)') END,
         'grc_silver.vulnerability_finding'
  FROM vf
  CROSS JOIN cfg
  WHERE vf.is_kev

  UNION ALL
  -- T-CFG-01 Public storage exposure
  SELECT 'T-CFG-01', 'cloud_resource', resource_arn, resource_name, bu_id, CAST(NULL AS STRING),
         CASE WHEN data_classification IN ('Confidential', 'Restricted') THEN 'Critical' ELSE 'High' END,
         capture_ts, CAST(NULL AS DATE),
         is_public AND NOT has_valid_exception,
         CASE WHEN is_public AND NOT has_valid_exception THEN concat('S3 bucket ACL grants AllUsers (', coalesce(data_classification, 'unclassified'), ' data) with no valid exception') END,
         'grc_silver.cloud_config'
  FROM s3

  UNION ALL
  -- T-CFG-02 Unapproved change detection
  SELECT 'T-CFG-02', 'security_event', event_id, concat(action, ' on ', coalesce(target_resource, 'n/a'), ' (', account_name, ')'),
         CAST(NULL AS STRING), actor, 'High', event_time, CAST(NULL AS DATE),
         NOT has_ticket,
         CASE WHEN NOT has_ticket THEN concat('Production change by ', actor, ' with no approved change ticket in window') END,
         'grc_silver.security_event'
  FROM prod_changes

  UNION ALL
  -- T-LOG-01 Audit logging enabled
  SELECT 'T-LOG-01', 'cloud_resource', resource_arn, concat(account_name, ' / ', region), bu_id, CAST(NULL AS STRING), 'Critical',
         last_delivery_ts, CAST(NULL AS DATE),
         NOT delivering_within_24h,
         CASE WHEN NOT coalesce(is_logging, false) THEN concat('CloudTrail logging stopped; last delivery ', coalesce(CAST(last_delivery_ts AS STRING), 'never'))
              WHEN NOT delivering_within_24h THEN concat('No CloudTrail delivery in last 24h; last delivery ', coalesce(CAST(last_delivery_ts AS STRING), 'never')) END,
         'grc_silver.cloud_config'
  FROM grc_silver.cloud_config
  WHERE resource_kind = 'CloudTrail Trail'

  UNION ALL
  -- T-LOG-02 Alert triage timeliness
  SELECT 'T-LOG-02', 'security_event', a.event_id, concat(a.severity, ' ', coalesce(a.technique, 'alert'), ' on ', coalesce(a.device_hostname, 'unknown host')),
         a.bu_id, a.assigned_to, a.severity, a.event_time,
         to_date(a.event_time + make_interval(0, 0, 0, 0, a.sla_hours, 0, 0)),
         CASE WHEN a.triaged_ts IS NOT NULL THEN a.triaged_ts > a.event_time + make_interval(0, 0, 0, 0, a.sla_hours, 0, 0)
              ELSE cfg.as_of_end_ts > a.event_time + make_interval(0, 0, 0, 0, a.sla_hours, 0, 0) END,
         CASE WHEN a.triaged_ts IS NOT NULL AND a.triaged_ts > a.event_time + make_interval(0, 0, 0, 0, a.sla_hours, 0, 0)
                THEN concat('Triaged after ', CAST(round(a.triage_minutes / 60.0, 1) AS STRING), 'h (SLA ', CAST(a.sla_hours AS STRING), 'h)')
              WHEN a.triaged_ts IS NULL AND cfg.as_of_end_ts > a.event_time + make_interval(0, 0, 0, 0, a.sla_hours, 0, 0)
                THEN concat('Not triaged; SLA of ', CAST(a.sla_hours AS STRING), 'h exceeded') END,
         'grc_silver.security_event'
  FROM alerts a
  CROSS JOIN cfg

  UNION ALL
  -- T-DAT-01 Encryption at rest
  SELECT 'T-DAT-01', 'cloud_resource', resource_arn, resource_name, bu_id, CAST(NULL AS STRING), 'High', capture_ts, CAST(NULL AS DATE),
         NOT coalesce(is_encrypted, false),
         CASE WHEN NOT coalesce(is_encrypted, false) THEN concat(resource_kind, ' holding ', data_classification, ' data is not encrypted at rest') END,
         'grc_silver.cloud_config'
  FROM grc_silver.cloud_config
  WHERE resource_kind IN ('S3 Bucket', 'RDS Instance') AND data_classification IN ('Confidential', 'Restricted')

  UNION ALL
  -- T-DAT-02 Backup success
  SELECT 'T-DAT-02', 'cloud_resource', resource_arn, resource_name, bu_id, CAST(NULL AS STRING),
         CASE WHEN tier = 'T0' THEN 'Critical' ELSE 'High' END, last_backup_ts, CAST(NULL AS DATE),
         NOT backup_within_24h,
         CASE WHEN NOT backup_within_24h THEN concat('No successful backup in last 24h; latest restorable time ', coalesce(CAST(last_backup_ts AS STRING), 'never')) END,
         'grc_silver.cloud_config'
  FROM grc_silver.cloud_config
  WHERE resource_kind = 'RDS Instance' AND tier IN ('T0', 'T1')

  UNION ALL
  -- T-IR-01 Incident containment SLA
  SELECT 'T-IR-01', 'ticket', ticket_id, short_description, bu_id, assignment_group,
         CASE severity WHEN 'SEV1' THEN 'Critical' WHEN 'SEV2' THEN 'High' ELSE 'Medium' END,
         declared_ts, to_date(due_ts),
         NOT (coalesce(containment_sla_met, false) AND coalesce(pir_completed, false)),
         nullif(concat_ws('; ',
           CASE WHEN NOT coalesce(containment_sla_met, false) THEN
             CASE WHEN contained_ts IS NULL THEN concat('Not contained after ', CAST(containment_hours AS STRING), 'h (SLA ', CAST(containment_sla_hours AS STRING), 'h)')
                  ELSE concat('Contained after ', CAST(containment_hours AS STRING), 'h (SLA ', CAST(containment_sla_hours AS STRING), 'h)') END END,
           CASE WHEN NOT coalesce(pir_completed, false) THEN 'Post-incident review not completed' END), ''),
         'grc_silver.remediation_ticket'
  FROM grc_silver.remediation_ticket
  WHERE ticket_type = 'security_incident'

  UNION ALL
  -- T-POL-01 Policy review currency
  SELECT 'T-POL-01', 'policy', policy_id, policy_title, CAST(NULL AS STRING), owner_email, 'Medium',
         CAST(last_review_date AS TIMESTAMP), next_review_date,
         is_review_overdue,
         CASE WHEN is_review_overdue THEN concat('Policy review overdue - last reviewed ', CAST(last_review_date AS STRING), ', next review was due ', CAST(next_review_date AS STRING)) END,
         'grc_silver.policy'
  FROM grc_silver.policy
  WHERE status = 'Published'

  UNION ALL
  -- T-POL-02 Exception validity
  SELECT 'T-POL-02', 'exception', exception_id, exception_title, bu_id, approver_email, 'High',
         CAST(start_date AS TIMESTAMP), expiry_date,
         NOT is_valid,
         nullif(concat_ws('; ',
           CASE WHEN approval_status <> 'Approved' THEN concat('Approval status ', approval_status) END,
           CASE WHEN is_expired THEN concat('Expired on ', CAST(expiry_date AS STRING), ' but still Active') END,
           CASE WHEN exceeds_max_duration THEN concat('Duration ', CAST(duration_days AS STRING), ' days exceeds max ', CAST(max_duration_days AS STRING)) END), ''),
         'grc_silver.risk_exception'
  FROM grc_silver.risk_exception
  WHERE exception_status = 'Active'

  UNION ALL
  -- T-RSK-01 Risk register hygiene
  SELECT 'T-RSK-01', 'risk', risk_id, risk_title, bu_id, owner_email, coalesce(inherent_rating, 'Medium'),
         CAST(last_reviewed_date AS TIMESTAMP), date_add(last_reviewed_date, review_sla_days),
         NOT is_hygiene_compliant,
         nullif(concat_ws('; ',
           CASE WHEN NOT has_owner THEN 'No risk owner assigned' END,
           CASE WHEN coalesce(trim(treatment_plan), '') = '' THEN 'No treatment plan' END,
           CASE WHEN review_overdue THEN concat('Last reviewed ', coalesce(CAST(last_reviewed_date AS STRING), 'never')) END), ''),
         'grc_silver.risk'
  FROM grc_silver.risk
  WHERE is_open

  UNION ALL
  -- T-TRN-01 Training completion
  SELECT 'T-TRN-01', 'identity', user_id, login, bu_id, login, 'Low',
         CAST(completion_date AS TIMESTAMP), due_date,
         NOT training_current,
         CASE WHEN NOT training_current THEN concat('Annual security awareness training not completed in last 365 days (', training_status, ')') END,
         'grc_silver.training_status'
  FROM grc_silver.training_status

  UNION ALL
  -- T-VND-01 Vendor assessment currency
  SELECT 'T-VND-01', 'vendor', vendor_id, vendor_name, bu_id, relationship_owner_email, criticality,
         CAST(last_assessment_date AS TIMESTAMP), date_add(last_assessment_date, reassessment_sla_days),
         assessment_overdue,
         CASE WHEN assessment_overdue THEN concat(criticality, ' vendor last assessed ', coalesce(CAST(last_assessment_date AS STRING), 'never'),
              ' (', coalesce(CAST(assessment_age_days AS STRING), 'n/a'), ' days ago)') END,
         'grc_silver.vendor'
  FROM grc_silver.vendor
  WHERE requires_annual_assessment
)
SELECT
  CAST(:as_of_date AS DATE) AS test_run_date,
  ev.test_id,
  cat.control_id,
  concat(ev.test_id, ':', ev.entity_id) AS evidence_id,
  ev.entity_type,
  ev.entity_id,
  ev.entity_name,
  ev.bu_id,
  ev.owner_email,
  ev.severity,
  ev.observed_ts,
  ev.due_date,
  coalesce(ev.is_exception, true) AS is_exception,
  CASE WHEN ev.is_exception IS NULL THEN 'Insufficient evidence to evaluate the test condition' ELSE ev.exception_reason END AS exception_reason,
  ev.source_table
FROM ev
LEFT JOIN grc_ref.control_test_catalog cat ON ev.test_id = cat.test_id;
