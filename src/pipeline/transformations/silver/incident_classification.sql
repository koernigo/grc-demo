-- Silver: security incidents enriched with linked EDR alert context and classified with ai_classify (attack category, primary control domain).
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.incident_classification (
  CONSTRAINT valid_ticket_id EXPECT (ticket_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT classified_attack_category EXPECT (attack_category IS NOT NULL),
  CONSTRAINT classified_control_domain EXPECT (control_domain IS NOT NULL)
)
COMMENT 'Silver: one row per ServiceNow security incident with linked CrowdStrike alert statistics (alert count, hosts, MITRE tactics / techniques) and AI classification: attack_category and the primary control_domain (grc_ref.controls.control_domain) whose failure enabled or would have prevented the incident, each with confidence score and rationale.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH alerts AS (
  SELECT
    linked_incident_id,
    count(*) AS linked_alert_count,
    count(DISTINCT device_hostname) AS linked_host_count,
    array_sort(collect_set(tactic)) AS linked_tactics,
    array_sort(collect_set(technique)) AS linked_techniques,
    min(event_time) AS first_alert_ts,
    max(event_time) AS last_alert_ts
  FROM grc_silver.security_event
  WHERE event_source_system = 'crowdstrike_edr' AND linked_incident_id IS NOT NULL
  GROUP BY linked_incident_id
),
ctx AS (
  SELECT
    t.ticket_id,
    t.short_description,
    t.category AS servicenow_category,
    t.severity,
    t.state,
    t.is_open,
    t.bu_id,
    t.opened_ts,
    t.contained_ts,
    t.containment_hours,
    t.containment_sla_met,
    t.mitre_technique,
    t.work_notes,
    coalesce(a.linked_alert_count, 0) AS linked_alert_count,
    coalesce(a.linked_host_count, 0) AS linked_host_count,
    coalesce(a.linked_tactics, array()) AS linked_tactics,
    coalesce(a.linked_techniques, array()) AS linked_techniques,
    a.first_alert_ts,
    a.last_alert_ts,
    concat_ws('\n',
      concat('Incident: ', t.ticket_id, ' (', t.severity, ')'),
      concat('Short description: ', t.short_description),
      concat('ServiceNow category: ', t.category),
      concat('MITRE technique on ticket: ', coalesce(t.mitre_technique, 'n/a')),
      concat('Work notes: ', coalesce(t.work_notes, 'n/a')),
      concat('Linked EDR alerts: ', coalesce(a.linked_alert_count, 0), ' on ', coalesce(a.linked_host_count, 0), ' hosts'),
      concat('EDR tactics: ', coalesce(array_join(a.linked_tactics, ', '), 'n/a')),
      concat('EDR techniques: ', coalesce(array_join(a.linked_techniques, ', '), 'n/a'))
    ) AS incident_context
  FROM grc_silver.remediation_ticket t
  LEFT JOIN alerts a ON a.linked_incident_id = t.ticket_id
  WHERE t.ticket_type = 'security_incident'
),
classified AS (
  SELECT
    *,
    ai_classify(
      incident_context,
      '{
        "Ransomware / Malware": "Malicious code execution, ransomware precursors, droppers, lateral movement tooling",
        "Credential Compromise": "Stolen, phished, brute-forced or misused credentials and accounts",
        "Phishing / Social Engineering": "Phishing emails, business email compromise, social engineering of staff",
        "Cloud Misconfiguration / Data Exposure": "Publicly exposed storage, overly permissive cloud configuration, data leakage",
        "Privilege Misuse / Insider": "Policy violations, unauthorized access or misuse of access by insiders",
        "Lost or Stolen Device": "Lost, stolen or unrecovered endpoints and media",
        "Other": "Anything that does not fit the categories above"
      }',
      map('version', '2.1', 'instructions', 'Classify the security incident by its primary attack category.', 'enableConfidenceScores', 'true', 'enableRationales', 'true')
    ) AS attack_classification,
    ai_classify(
      incident_context,
      '{
        "Identity & Access": "MFA, provisioning, deprovisioning, privileged access, SoD",
        "Asset Management": "Inventory, EDR coverage, device management",
        "Vulnerability Management": "Patching, scanning, exploited vulnerabilities",
        "Configuration Management": "Secure configuration, public exposure of cloud resources",
        "Change Management": "Unapproved or unauthorized changes",
        "Logging & Monitoring": "Audit logging, detection and alert triage",
        "Data Protection": "Encryption, backup, data loss",
        "Incident Response": "Containment and response process",
        "People": "Security awareness, phishing susceptibility, human error",
        "Third-Party Risk": "Vendor or supplier caused incidents",
        "Governance": "Policy and exception management",
        "Risk Management": "Risk assessment and treatment"
      }',
      map('version', '2.1', 'instructions', 'Pick the single control domain whose control weakness most directly enabled this incident, or whose control would most likely have prevented it.', 'enableConfidenceScores', 'true', 'enableRationales', 'true')
    ) AS domain_classification
  FROM ctx
)
SELECT
  ticket_id,
  short_description,
  servicenow_category,
  severity,
  state,
  is_open,
  bu_id,
  opened_ts,
  contained_ts,
  containment_hours,
  containment_sla_met,
  mitre_technique,
  linked_alert_count,
  linked_host_count,
  linked_tactics,
  linked_techniques,
  first_alert_ts,
  last_alert_ts,
  CAST(attack_classification:response[0].value AS STRING) AS attack_category,
  CAST(attack_classification:response[0].confidence_score AS DOUBLE) AS attack_category_confidence,
  CAST(attack_classification:response[0].rationale AS STRING) AS attack_category_rationale,
  CAST(domain_classification:response[0].value AS STRING) AS control_domain,
  CAST(domain_classification:response[0].confidence_score AS DOUBLE) AS control_domain_confidence,
  CAST(domain_classification:response[0].rationale AS STRING) AS control_domain_rationale,
  incident_context,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM classified;
