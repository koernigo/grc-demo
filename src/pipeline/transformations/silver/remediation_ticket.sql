-- Silver: ServiceNow change requests, security incidents and vulnerability remediation tasks in one conformed ticket shape.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.remediation_ticket (
  ticket_id STRING COMMENT 'ServiceNow ticket number (CHG, INC or VIT)',
  ticket_type STRING COMMENT 'change, security_incident or vulnerability',
  short_description STRING COMMENT 'Ticket short description',
  category STRING COMMENT 'Change type, incident category or Vulnerability Remediation',
  severity STRING COMMENT 'Incident severity (SEV1-SEV3) or vulnerability risk rating',
  state STRING COMMENT 'ServiceNow ticket state',
  is_open BOOLEAN COMMENT 'True if the ticket is not closed or cancelled',
  bu_id STRING COMMENT 'Business unit (vulnerability tickets: from the CMDB CI)',
  assignment_group STRING COMMENT 'Assignment group',
  assigned_to STRING COMMENT 'Change only: lower-cased implementer',
  approved_by STRING COMMENT 'Change only: lower-cased approver',
  approval_status STRING COMMENT 'Change only: approval state',
  cmdb_ci STRING COMMENT 'Affected configuration item name',
  cloud_account STRING COMMENT 'Change only: target cloud account name',
  cve STRING COMMENT 'Vulnerability only: CVE id',
  opened_ts TIMESTAMP COMMENT 'Ticket opened time',
  due_ts TIMESTAMP COMMENT 'Due time (incident containment SLA or vulnerability due date)',
  closed_ts TIMESTAMP COMMENT 'Ticket closed time',
  planned_start_ts TIMESTAMP COMMENT 'Change only: planned window start',
  planned_end_ts TIMESTAMP COMMENT 'Change only: planned window end',
  first_activity_ts TIMESTAMP COMMENT 'Incident only: first malicious activity',
  declared_ts TIMESTAMP COMMENT 'Incident only: incident declared (opened) time',
  contained_ts TIMESTAMP COMMENT 'Incident only: containment time',
  detection_hours DOUBLE COMMENT 'Incident only: hours from first activity to declaration',
  containment_hours DOUBLE COMMENT 'Incident only: hours from declaration to containment (or end of as_of_date if open)',
  containment_sla_hours INT COMMENT 'Incident only: INCIDENT_CONTAINMENT SLA hours for the severity',
  containment_sla_met BOOLEAN COMMENT 'Incident only: contained within SLA',
  pir_completed BOOLEAN COMMENT 'Incident only: post-incident review completed',
  mitre_technique STRING COMMENT 'Incident only: MITRE ATT&CK technique',
  work_notes STRING COMMENT 'Incident only: analyst work notes',
  is_self_approved BOOLEAN COMMENT 'Change only: implementer approved own change',
  sla_breached BOOLEAN COMMENT 'Incident: containment SLA missed; vulnerability: closed or still open after due date',
  _source_file STRING COMMENT 'Landing file the ticket was ingested from',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_ticket_id EXPECT (ticket_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_ticket_type EXPECT (ticket_type IN ('change', 'security_incident', 'vulnerability')),
  CONSTRAINT valid_opened_ts EXPECT (opened_ts IS NOT NULL),
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL)
)
COMMENT 'Silver: conformed ServiceNow tickets. ticket_type = change (change_request: planned window, assignee, approver, cloud account, self-approval flag), security_incident (sn_si_incident: first activity, declared, contained, detection/containment hours vs grc_ref.sla_policy INCIDENT_CONTAINMENT, PIR completed) or vulnerability (sn_vul_vulnerable_item: CVE, CI, due date, SLA breach). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH chg AS (
  SELECT * FROM grc_bronze.sn_change_request
  QUALIFY row_number() OVER (PARTITION BY number ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
inc AS (
  SELECT * FROM grc_bronze.sn_security_incident
  QUALIFY row_number() OVER (PARTITION BY number ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
vit AS (
  SELECT * FROM grc_bronze.sn_vulnerable_item
  QUALIFY row_number() OVER (PARTITION BY number ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
isla AS (
  SELECT severity, sla_value FROM grc_ref.sla_policy WHERE sla_type = 'INCIDENT_CONTAINMENT'
),
ast AS (
  SELECT asset_name, bu_id FROM grc_silver.asset
),
changes AS (
  SELECT
    number AS ticket_id,
    'change' AS ticket_type,
    short_description,
    type AS category,
    CAST(NULL AS STRING) AS severity,
    state,
    state NOT IN ('Closed', 'Cancelled') AS is_open,
    u_business_unit AS bu_id,
    assignment_group,
    lower(assigned_to) AS assigned_to,
    lower(approved_by) AS approved_by,
    approval AS approval_status,
    cmdb_ci,
    u_cloud_account AS cloud_account,
    CAST(NULL AS STRING) AS cve,
    sys_created_on AS opened_ts,
    CAST(NULL AS TIMESTAMP) AS due_ts,
    CASE WHEN state = 'Closed' THEN end_date END AS closed_ts,
    start_date AS planned_start_ts,
    end_date AS planned_end_ts,
    CAST(NULL AS TIMESTAMP) AS first_activity_ts,
    CAST(NULL AS TIMESTAMP) AS declared_ts,
    CAST(NULL AS TIMESTAMP) AS contained_ts,
    CAST(NULL AS DOUBLE) AS detection_hours,
    CAST(NULL AS DOUBLE) AS containment_hours,
    CAST(NULL AS INT) AS containment_sla_hours,
    CAST(NULL AS BOOLEAN) AS containment_sla_met,
    CAST(NULL AS BOOLEAN) AS pir_completed,
    CAST(NULL AS STRING) AS mitre_technique,
    CAST(NULL AS STRING) AS work_notes,
    coalesce(lower(assigned_to) = lower(approved_by), false) AS is_self_approved,
    CAST(NULL AS BOOLEAN) AS sla_breached,
    _source_file
  FROM chg
),
incidents AS (
  SELECT
    i.number AS ticket_id,
    'security_incident' AS ticket_type,
    i.short_description,
    i.category,
    i.u_severity AS severity,
    i.state,
    i.state <> 'Closed' AS is_open,
    i.u_business_unit AS bu_id,
    i.assignment_group,
    CAST(NULL AS STRING) AS assigned_to,
    CAST(NULL AS STRING) AS approved_by,
    CAST(NULL AS STRING) AS approval_status,
    CAST(NULL AS STRING) AS cmdb_ci,
    CAST(NULL AS STRING) AS cloud_account,
    CAST(NULL AS STRING) AS cve,
    i.opened_at AS opened_ts,
    i.opened_at + make_interval(0, 0, 0, 0, s.sla_value, 0, 0) AS due_ts,
    i.closed_at AS closed_ts,
    CAST(NULL AS TIMESTAMP) AS planned_start_ts,
    CAST(NULL AS TIMESTAMP) AS planned_end_ts,
    i.u_first_activity AS first_activity_ts,
    i.opened_at AS declared_ts,
    i.u_contained_at AS contained_ts,
    round((unix_timestamp(i.opened_at) - unix_timestamp(i.u_first_activity)) / 3600.0, 1) AS detection_hours,
    round((unix_timestamp(coalesce(i.u_contained_at, CAST(date_add(CAST(:as_of_date AS DATE), 1) AS TIMESTAMP))) - unix_timestamp(i.opened_at)) / 3600.0, 1) AS containment_hours,
    s.sla_value AS containment_sla_hours,
    i.u_contained_at IS NOT NULL AND containment_hours <= s.sla_value AS containment_sla_met,
    coalesce(i.u_pir_completed, false) AS pir_completed,
    i.u_mitre_technique AS mitre_technique,
    i.work_notes,
    CAST(NULL AS BOOLEAN) AS is_self_approved,
    NOT (i.u_contained_at IS NOT NULL AND containment_hours <= s.sla_value) AS sla_breached,
    i._source_file
  FROM inc i
  LEFT JOIN isla s ON i.u_severity = s.severity
),
vulns AS (
  SELECT
    v.number AS ticket_id,
    'vulnerability' AS ticket_type,
    concat('Remediate ', v.cve, ' on ', v.cmdb_ci) AS short_description,
    'Vulnerability Remediation' AS category,
    v.risk_rating AS severity,
    v.state,
    v.state <> 'Closed' AS is_open,
    a.bu_id,
    v.assignment_group,
    CAST(NULL AS STRING) AS assigned_to,
    CAST(NULL AS STRING) AS approved_by,
    CAST(NULL AS STRING) AS approval_status,
    v.cmdb_ci,
    CAST(NULL AS STRING) AS cloud_account,
    v.cve,
    CAST(v.opened_at AS TIMESTAMP) AS opened_ts,
    CAST(v.due_date AS TIMESTAMP) AS due_ts,
    CAST(v.closed_at AS TIMESTAMP) AS closed_ts,
    CAST(NULL AS TIMESTAMP) AS planned_start_ts,
    CAST(NULL AS TIMESTAMP) AS planned_end_ts,
    CAST(NULL AS TIMESTAMP) AS first_activity_ts,
    CAST(NULL AS TIMESTAMP) AS declared_ts,
    CAST(NULL AS TIMESTAMP) AS contained_ts,
    CAST(NULL AS DOUBLE) AS detection_hours,
    CAST(NULL AS DOUBLE) AS containment_hours,
    CAST(NULL AS INT) AS containment_sla_hours,
    CAST(NULL AS BOOLEAN) AS containment_sla_met,
    CAST(NULL AS BOOLEAN) AS pir_completed,
    CAST(NULL AS STRING) AS mitre_technique,
    CAST(NULL AS STRING) AS work_notes,
    CAST(NULL AS BOOLEAN) AS is_self_approved,
    coalesce(coalesce(v.closed_at, CAST(:as_of_date AS DATE)) > v.due_date, false) AS sla_breached,
    v._source_file
  FROM vit v
  LEFT JOIN ast a ON lower(v.cmdb_ci) = lower(a.asset_name)
)
SELECT *, CAST(:as_of_date AS DATE) AS as_of_date FROM changes
UNION ALL
SELECT *, CAST(:as_of_date AS DATE) AS as_of_date FROM incidents
UNION ALL
SELECT *, CAST(:as_of_date AS DATE) AS as_of_date FROM vulns;
