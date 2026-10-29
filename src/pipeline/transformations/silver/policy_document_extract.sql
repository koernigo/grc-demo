-- Silver: structured policy attributes extracted from parsed PDFs with ai_extract, reconciled against the SharePoint Policy Register.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.policy_document_extract (
  CONSTRAINT valid_policy_id EXPECT (policy_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT extracted_without_error EXPECT (extract_error IS NULL),
  CONSTRAINT register_matches_document EXPECT (NOT has_register_conflict)
)
COMMENT 'Silver: AI-extracted policy metadata (owner, approval / next review dates, version, scope, referenced controls, stated remediation SLAs) from each policy PDF, compared with the Policy Register and grc_ref.sla_policy. Conflict flags highlight where the authoritative document disagrees with the register (e.g. stale review date, SLA stated in the document that differs from the enforced SLA).'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH ex AS (
  SELECT
    policy_id,
    document_name,
    document_volume_path,
    document_modified_ts,
    ai_extract(
      parsed_content,
      '{
        "policy_id": {"type": "string", "description": "Document ID such as POL-004"},
        "policy_title": {"type": "string", "description": "Title of the policy or standard"},
        "version": {"type": "string", "description": "Document version"},
        "owner_email": {"type": "string", "description": "Email address of the policy owner"},
        "approved_by": {"type": "string", "description": "Role or person who approved the document"},
        "approval_date": {"type": "string", "description": "Approval / last review date in YYYY-MM-DD format"},
        "next_review_date": {"type": "string", "description": "Next review date in YYYY-MM-DD format"},
        "scope_summary": {"type": "string", "description": "One sentence summary of the scope section"},
        "referenced_controls": {"type": "array", "items": {"type": "string"}, "description": "Control identifiers referenced, formatted like GRC-IAM-01"},
        "critical_remediation_days": {"type": "integer", "description": "Days allowed to remediate Critical severity vulnerabilities, only if the document states it"},
        "high_remediation_days": {"type": "integer", "description": "Days allowed to remediate High severity vulnerabilities, only if the document states it"},
        "key_requirements": {"type": "array", "items": {"type": "string"}, "description": "Up to 5 key mandatory requirements, each a short sentence"}
      }',
      map('version', '2.1', 'instructions', 'These are ACME Corp information security policies and standards exported from SharePoint. The header table holds document ID, version, owner, approver, approval date and next review date.')
    ) AS extraction
  FROM grc_silver.policy_document_parsed
),
flat AS (
  SELECT
    policy_id,
    document_name,
    document_volume_path,
    document_modified_ts,
    extraction,
    CAST(extraction:error_message AS STRING) AS extract_error,
    CAST(extraction:response.policy_title.value AS STRING) AS doc_policy_title,
    CAST(extraction:response.version.value AS STRING) AS doc_version,
    lower(trim(CAST(extraction:response.owner_email.value AS STRING))) AS doc_owner_email,
    CAST(extraction:response.approved_by.value AS STRING) AS doc_approved_by,
    try_to_date(CAST(extraction:response.approval_date.value AS STRING)) AS doc_approval_date,
    try_to_date(CAST(extraction:response.next_review_date.value AS STRING)) AS doc_next_review_date,
    CAST(extraction:response.scope_summary.value AS STRING) AS doc_scope_summary,
    transform(CAST(extraction:response.referenced_controls AS ARRAY<VARIANT>), x -> upper(CAST(x:value AS STRING))) AS doc_referenced_controls,
    CAST(extraction:response.critical_remediation_days.value AS INT) AS doc_critical_remediation_days,
    CAST(extraction:response.high_remediation_days.value AS INT) AS doc_high_remediation_days,
    transform(CAST(extraction:response.key_requirements AS ARRAY<VARIANT>), x -> CAST(x:value AS STRING)) AS doc_key_requirements
  FROM ex
),
sla AS (
  SELECT
    max(CASE WHEN severity = 'Critical' THEN sla_value END) AS critical_sla_days,
    max(CASE WHEN severity = 'High' THEN sla_value END) AS high_sla_days
  FROM grc_ref.sla_policy
  WHERE sla_type = 'VULN_REMEDIATION'
),
joined AS (
  SELECT
    f.*,
    p.policy_title AS register_policy_title,
    p.owner_email AS register_owner_email,
    p.version AS register_version,
    p.last_review_date AS register_last_review_date,
    p.next_review_date AS register_next_review_date,
    p.mapped_controls AS register_mapped_controls,
    sla.critical_sla_days AS enforced_critical_sla_days,
    sla.high_sla_days AS enforced_high_sla_days
  FROM flat f
  LEFT JOIN grc_silver.policy p ON f.policy_id = p.policy_id
  CROSS JOIN sla
)
SELECT
  policy_id,
  document_name,
  document_volume_path,
  document_modified_ts,
  doc_policy_title,
  doc_version,
  doc_owner_email,
  doc_approved_by,
  doc_approval_date,
  doc_next_review_date,
  doc_scope_summary,
  doc_referenced_controls,
  doc_critical_remediation_days,
  doc_high_remediation_days,
  doc_key_requirements,
  register_policy_title,
  register_owner_email,
  register_version,
  register_last_review_date,
  register_next_review_date,
  register_mapped_controls,
  enforced_critical_sla_days,
  enforced_high_sla_days,
  coalesce(doc_owner_email <> register_owner_email, false) AS owner_mismatch,
  coalesce(doc_version <> register_version, false) AS version_mismatch,
  coalesce(doc_approval_date <> register_last_review_date, false) AS review_date_mismatch,
  datediff(register_last_review_date, doc_approval_date) AS register_vs_document_review_gap_days,
  coalesce(doc_next_review_date < CAST(:as_of_date AS DATE), false) AS document_review_overdue,
  coalesce(NOT array_sort(array_distinct(doc_referenced_controls)) <=> array_sort(array_distinct(register_mapped_controls)), false)
    AND size(doc_referenced_controls) > 0 AS control_mapping_mismatch,
  array_except(doc_referenced_controls, coalesce(register_mapped_controls, array())) AS controls_only_in_document,
  array_except(coalesce(register_mapped_controls, array()), doc_referenced_controls) AS controls_only_in_register,
  coalesce(doc_critical_remediation_days <> enforced_critical_sla_days, false)
    OR coalesce(doc_high_remediation_days <> enforced_high_sla_days, false) AS sla_conflict,
  (coalesce(doc_owner_email <> register_owner_email, false)
    OR coalesce(doc_approval_date <> register_last_review_date, false)
    OR coalesce(doc_critical_remediation_days <> enforced_critical_sla_days, false)
    OR coalesce(doc_high_remediation_days <> enforced_high_sla_days, false)) AS has_register_conflict,
  extract_error,
  extraction AS extraction_raw,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM joined;
