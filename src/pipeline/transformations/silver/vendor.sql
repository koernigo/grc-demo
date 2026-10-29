-- Silver: third-party vendors with assessment currency and SOC 2 report status.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.vendor (
  vendor_id STRING COMMENT 'TPRM vendor id (primary key)',
  vendor_name STRING COMMENT 'Vendor name',
  service STRING COMMENT 'Service provided',
  criticality STRING COMMENT 'Vendor criticality: Critical, High, Medium, Low',
  data_access STRING COMMENT 'Type of company data the vendor can access',
  bu_id STRING COMMENT 'Owning business unit',
  relationship_owner_email STRING COMMENT 'Lower-cased relationship owner email',
  annual_spend_usd DOUBLE COMMENT 'Annual spend in USD',
  questionnaire STRING COMMENT 'Security questionnaire used',
  last_assessment_date DATE COMMENT 'Date of last security assessment',
  assessment_score INT COMMENT 'Last assessment score',
  assessment_age_days INT COMMENT 'Days since last assessment as of as_of_date',
  reassessment_sla_days INT COMMENT 'VENDOR_REASSESSMENT SLA in days for the criticality (null = none)',
  requires_annual_assessment BOOLEAN COMMENT 'Critical or High vendor (in scope of GRC-VND-01)',
  assessment_overdue BOOLEAN COMMENT 'Assessment older than reassessment_sla_days (control GRC-VND-01)',
  soc2_report_expiry DATE COMMENT 'SOC 2 report expiry date',
  soc2_expired BOOLEAN COMMENT 'SOC 2 report expired before as_of_date',
  days_to_soc2_expiry INT COMMENT 'Days from as_of_date to SOC 2 expiry',
  open_findings INT COMMENT 'Open assessment findings',
  contract_security_clause BOOLEAN COMMENT 'Contract contains a security clause',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the TPRM export',
  CONSTRAINT valid_vendor_id EXPECT (vendor_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT valid_criticality EXPECT (criticality IN ('Critical', 'High', 'Medium', 'Low')),
  CONSTRAINT in_scope_vendor_assessed EXPECT (criticality NOT IN ('Critical', 'High') OR last_assessment_date IS NOT NULL),
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL)
)
COMMENT 'Silver: one row per third-party vendor from the TPRM register with criticality, data access, spend, owning BU, last assessment date and score, assessment_age_days, reassessment SLA from grc_ref.sla_policy VENDOR_REASSESSMENT (Critical/High 365 days, Medium 730 days, Low none), assessment_overdue, SOC 2 report expiry/expired flag, open findings and contract security clause. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH v AS (
  SELECT *
  FROM grc_bronze.tprm_vendor_assessments
  QUALIFY row_number() OVER (PARTITION BY vendor_id ORDER BY _source_file_modified_ts DESC, _ingest_ts DESC) = 1
),
sla AS (
  SELECT severity AS criticality, sla_value FROM grc_ref.sla_policy WHERE sla_type = 'VENDOR_REASSESSMENT'
)
SELECT
  v.vendor_id,
  v.vendor_name,
  v.service,
  v.criticality,
  v.data_access,
  v.bu_owner AS bu_id,
  lower(v.relationship_owner) AS relationship_owner_email,
  v.annual_spend_usd,
  v.questionnaire,
  v.last_assessment_date,
  v.assessment_score,
  datediff(CAST(:as_of_date AS DATE), v.last_assessment_date) AS assessment_age_days,
  sla.sla_value AS reassessment_sla_days,
  v.criticality IN ('Critical', 'High') AS requires_annual_assessment,
  CASE WHEN sla.sla_value IS NULL THEN false
       ELSE v.last_assessment_date IS NULL OR datediff(CAST(:as_of_date AS DATE), v.last_assessment_date) > sla.sla_value
  END AS assessment_overdue,
  v.soc2_report_expiry,
  coalesce(v.soc2_report_expiry < CAST(:as_of_date AS DATE), false) AS soc2_expired,
  datediff(v.soc2_report_expiry, CAST(:as_of_date AS DATE)) AS days_to_soc2_expiry,
  v.open_findings,
  v.contract_security_clause,
  CAST(:as_of_date AS DATE) AS as_of_date,
  v._source_file
FROM v
LEFT JOIN sla ON v.criticality = sla.criticality;
