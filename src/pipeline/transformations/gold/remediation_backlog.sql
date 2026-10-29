-- Gold: prioritized remediation backlog = every open control test exception with owner, due date and priority.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.remediation_backlog (
  backlog_item_id STRING COMMENT 'Backlog item key (evidence_id of the failing evidence row)',
  test_id STRING COMMENT 'Failing control test id',
  control_id STRING COMMENT 'Unified control id',
  control_name STRING COMMENT 'Control name',
  control_domain STRING COMMENT 'Control domain',
  key_control BOOLEAN COMMENT 'Key control',
  entity_type STRING COMMENT 'Type of failing entity',
  entity_id STRING COMMENT 'Failing entity key',
  entity_name STRING COMMENT 'Failing entity name',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  owner_email STRING COMMENT 'Remediation owner',
  severity STRING COMMENT 'Severity',
  exception_reason STRING COMMENT 'Why the entity failed the test',
  observed_ts TIMESTAMP COMMENT 'Time the issue was observed',
  due_date DATE COMMENT 'Remediation due date',
  days_overdue INT COMMENT 'Days past due date (0 if not overdue)',
  age_days INT COMMENT 'Days since observed',
  priority STRING COMMENT 'P1 (most urgent) to P4 from severity, key control and overdue status',
  linked_ticket_id STRING COMMENT 'Matching open ServiceNow vulnerability ticket, if any',
  source_table STRING COMMENT 'Silver table the evidence came from',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_item_id EXPECT (backlog_item_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_owner_or_bu EXPECT (owner_email IS NOT NULL OR bu_id IS NOT NULL),
  CONSTRAINT valid_priority EXPECT (priority IN ('P1', 'P2', 'P3', 'P4'))
)
COMMENT 'Gold: one row per open remediation item, i.e. each control test exception in grc_gold.control_test_evidence (excluding historical event-based exceptions older than 30 days for alert triage and remediated vulnerabilities). Carries control/test, entity, BU, owner, severity, exception reason, due date, days overdue, age, priority (P1 Critical / key control, P2 High, P3 Medium, P4 Low) and a linked ServiceNow vulnerability ticket where one exists. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH e AS (
  SELECT ev.*
  FROM grc_gold.control_test_evidence ev
  LEFT JOIN grc_silver.vulnerability_finding f
    ON ev.entity_type = 'vulnerability_finding' AND ev.entity_id = f.finding_id
  WHERE ev.is_exception
    AND NOT (ev.entity_type = 'vulnerability_finding' AND NOT coalesce(f.is_open, false))
    AND NOT (ev.test_id = 'T-LOG-02' AND to_date(ev.observed_ts) < date_sub(CAST(:as_of_date AS DATE), 30))
),
vit AS (
  SELECT lower(cmdb_ci) AS host_key, cve, max(ticket_id) AS ticket_id
  FROM grc_silver.remediation_ticket
  WHERE ticket_type = 'vulnerability' AND is_open
  GROUP BY lower(cmdb_ci), cve
),
fx AS (
  SELECT finding_id, lower(hostname) AS host_key, cve FROM grc_silver.vulnerability_finding
)
SELECT
  e.evidence_id AS backlog_item_id,
  e.test_id,
  e.control_id,
  c.control_name,
  c.control_domain,
  c.key_control,
  e.entity_type,
  e.entity_id,
  e.entity_name,
  e.bu_id,
  bu.bu_name,
  e.owner_email,
  e.severity,
  e.exception_reason,
  e.observed_ts,
  e.due_date,
  greatest(0, datediff(CAST(:as_of_date AS DATE), e.due_date)) AS days_overdue,
  datediff(CAST(:as_of_date AS DATE), to_date(e.observed_ts)) AS age_days,
  CASE
    WHEN e.severity = 'Critical' THEN 'P1'
    WHEN e.severity = 'High' AND c.key_control THEN 'P1'
    WHEN e.severity = 'High' THEN 'P2'
    WHEN e.severity = 'Medium' THEN 'P3'
    ELSE 'P4'
  END AS priority,
  vit.ticket_id AS linked_ticket_id,
  e.source_table,
  e.test_run_date AS as_of_date
FROM e
LEFT JOIN grc_ref.controls c ON e.control_id = c.control_id
LEFT JOIN grc_ref.business_units bu ON e.bu_id = bu.bu_id
LEFT JOIN fx ON e.entity_type = 'vulnerability_finding' AND e.entity_id = fx.finding_id
LEFT JOIN vit ON fx.host_key = vit.host_key AND fx.cve = vit.cve;
