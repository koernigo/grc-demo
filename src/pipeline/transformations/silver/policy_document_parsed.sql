-- Silver: policy PDFs parsed into structured document elements with ai_parse_document (step 1 of policy document AI enrichment).
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.policy_document_parsed (
  CONSTRAINT valid_policy_id EXPECT (policy_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT parsed_without_error EXPECT (parse_error IS NULL)
)
COMMENT 'Silver: one row per SharePoint policy PDF with ai_parse_document output (VARIANT: document elements, tables, pages). Feeds grc_silver.policy_document_extract.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH latest AS (
  SELECT *
  FROM grc_bronze.sp_policy_documents
  QUALIFY row_number() OVER (PARTITION BY path ORDER BY modificationTime DESC, _ingest_ts DESC) = 1
),
parsed AS (
  SELECT
    regexp_extract(path, '(POL-[0-9]+)', 1) AS policy_id,
    regexp_replace(path, '^dbfs:', '') AS document_volume_path,
    regexp_extract(path, '([^/]+)$', 1) AS document_name,
    length AS document_size_bytes,
    modificationTime AS document_modified_ts,
    ai_parse_document(content, map('version', '2.0')) AS parsed_content
  FROM latest
)
SELECT
  policy_id,
  document_name,
  document_volume_path,
  document_size_bytes,
  document_modified_ts,
  parsed_content,
  CAST(parsed_content:error_status AS STRING) AS parse_error,
  size(CAST(parsed_content:document:pages AS ARRAY<VARIANT>)) AS page_count,
  size(CAST(parsed_content:document:elements AS ARRAY<VARIANT>)) AS element_count
FROM parsed;
