-- Silver: SharePoint Policy Register flattened and joined to policy document library metadata.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.policy (
  policy_id STRING COMMENT 'Policy identifier, e.g. POL-001 (primary key)',
  sp_list_item_id BIGINT COMMENT 'SharePoint list item id',
  policy_title STRING COMMENT 'Policy title',
  owner_email STRING COMMENT 'Lower-cased policy owner email',
  version STRING COMMENT 'Policy version',
  status STRING COMMENT 'Register status (Published, Draft, Retired, ...)',
  last_review_date DATE COMMENT 'Last review date per the register',
  next_review_date DATE COMMENT 'Next scheduled review date per the register',
  review_cycle_days INT COMMENT 'POLICY_REVIEW cycle in days (grc_ref.sla_policy)',
  days_since_review INT COMMENT 'Days since last review as of as_of_date',
  days_until_next_review INT COMMENT 'Days until next review (negative = overdue)',
  is_review_overdue BOOLEAN COMMENT 'Published and next review passed or last review older than the cycle (control GRC-POL-01)',
  mapped_controls ARRAY<STRING> COMMENT 'Unified control ids the policy supports',
  document_url STRING COMMENT 'SharePoint URL of the policy document',
  document_item_id STRING COMMENT 'SharePoint driveItem id of the matched document',
  document_name STRING COMMENT 'Policy document file name',
  document_volume_path STRING COMMENT 'UC volume path of the landed policy document',
  document_size_bytes BIGINT COMMENT 'Document size in bytes',
  document_mime_type STRING COMMENT 'Document MIME type',
  document_modified_ts TIMESTAMP COMMENT 'Document last modified time',
  document_modified_by STRING COMMENT 'Lower-cased email of the document last modifier',
  register_document_date_mismatch BOOLEAN COMMENT 'Register last review date differs from the document last modified date',
  created_ts TIMESTAMP COMMENT 'Register item created time',
  modified_ts TIMESTAMP COMMENT 'Register item modified time',
  author_email STRING COMMENT 'Register item author email',
  editor_email STRING COMMENT 'Register item last editor email',
  sp_site STRING COMMENT 'SharePoint site',
  sp_list STRING COMMENT 'SharePoint list name',
  sp_etag STRING COMMENT 'SharePoint item etag',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  _source_file STRING COMMENT 'Landing file of the Policy Register export',
  CONSTRAINT valid_policy_id EXPECT (policy_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_owner EXPECT (owner_email IS NOT NULL),
  CONSTRAINT valid_review_dates EXPECT (last_review_date IS NOT NULL AND next_review_date IS NOT NULL),
  CONSTRAINT document_found EXPECT (document_item_id IS NOT NULL)
)
COMMENT 'Silver: one row per policy from the SharePoint Policy Register list (owner, version, status, last/next review date, mapped unified controls) joined to the Policies document library driveItem metadata by URL (document name, UC volume path, size, last modified). is_review_overdue = published and next review date passed or last review older than POLICY_REVIEW (365 days). register_document_date_mismatch flags register review dates that differ from the document''s last modified date. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH p AS (
  SELECT *
  FROM grc_bronze.sp_policy_register
  QUALIFY row_number() OVER (PARTITION BY PolicyId ORDER BY to_timestamp(Modified) DESC, _ingest_ts DESC) = 1
),
d AS (
  SELECT
    webUrl,
    id AS document_item_id,
    name AS document_name,
    _volume_path AS document_volume_path,
    size AS document_size_bytes,
    to_timestamp(lastModifiedDateTime) AS document_modified_ts,
    lower(lastModifiedBy.user.email) AS document_modified_by,
    file.mimeType AS document_mime_type
  FROM grc_bronze.sp_documents_metadata
  QUALIFY row_number() OVER (PARTITION BY webUrl ORDER BY to_timestamp(lastModifiedDateTime) DESC, _ingest_ts DESC) = 1
),
cfg AS (
  SELECT max(sla_value) AS review_cycle_days FROM grc_ref.sla_policy WHERE sla_type = 'POLICY_REVIEW'
)
SELECT
  p.PolicyId AS policy_id,
  p.id AS sp_list_item_id,
  p.Title AS policy_title,
  lower(p.PolicyOwner) AS owner_email,
  p.Version AS version,
  p.Status AS status,
  to_date(p.LastReviewDate) AS last_review_date,
  to_date(p.NextReviewDate) AS next_review_date,
  cfg.review_cycle_days,
  datediff(CAST(:as_of_date AS DATE), to_date(p.LastReviewDate)) AS days_since_review,
  datediff(to_date(p.NextReviewDate), CAST(:as_of_date AS DATE)) AS days_until_next_review,
  p.Status = 'Published'
    AND (to_date(p.NextReviewDate) < CAST(:as_of_date AS DATE)
         OR datediff(CAST(:as_of_date AS DATE), to_date(p.LastReviewDate)) > cfg.review_cycle_days) AS is_review_overdue,
  p.MappedControls AS mapped_controls,
  p.DocumentUrl AS document_url,
  d.document_item_id,
  d.document_name,
  d.document_volume_path,
  d.document_size_bytes,
  d.document_mime_type,
  d.document_modified_ts,
  d.document_modified_by,
  coalesce(to_date(d.document_modified_ts) <> to_date(p.LastReviewDate), false) AS register_document_date_mismatch,
  to_timestamp(p.Created) AS created_ts,
  to_timestamp(p.Modified) AS modified_ts,
  lower(p.Author.Email) AS author_email,
  lower(p.Editor.Email) AS editor_email,
  p._sp_site AS sp_site,
  p._sp_list AS sp_list,
  p._sp_etag AS sp_etag,
  CAST(:as_of_date AS DATE) AS as_of_date,
  p._source_file
FROM p
CROSS JOIN cfg
LEFT JOIN d ON p.DocumentUrl = d.webUrl;
