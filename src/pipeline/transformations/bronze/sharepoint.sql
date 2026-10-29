-- Bronze: SharePoint GRC site (simulated Lakeflow Connect SharePoint output) - list items and document library metadata.
-- Policy PDFs in sharepoint/documents/Policies/ are landed as binary in grc_bronze.sp_policy_documents (AI enrichment in silver).

CREATE OR REFRESH STREAMING TABLE grc_bronze.sp_policy_register
COMMENT 'Bronze: raw SharePoint "Policy Register" list items (JSON lines) - policy id, title, owner, version, status, review dates, mapped controls and document URL, with SharePoint system fields (_sp_site, _sp_list, _sp_etag). Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'SharePoint')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/sharepoint/lists/policy_register/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sp_policy_exceptions
COMMENT 'Bronze: raw SharePoint "Policy Exceptions" list items (JSON lines) - exception id, policy/control, business unit, requester/approver person fields, approval status, start/expiry dates, compensating controls and linked risk. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'SharePoint')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/sharepoint/lists/policy_exceptions/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sp_risk_register
COMMENT 'Bronze: raw SharePoint "Risk Register" list items (JSON lines) - risk id, category, business unit, owner person field, likelihood/impact, ALE, treatment plan/status, linked controls and last reviewed date. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'SharePoint')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/sharepoint/lists/risk_register/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sp_documents_metadata
COMMENT 'Bronze: raw SharePoint "Policies" document library driveItem metadata (JSON lines) - item id, file name, webUrl, size, created/modified timestamps and users, mime type and the UC volume path of the downloaded file. Plus _source_file, _source_file_modified_ts and _ingest_ts.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'SharePoint')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/sharepoint/documents_metadata/',
  format => 'json',
  pathGlobFilter => '*.json'
);

CREATE OR REFRESH STREAMING TABLE grc_bronze.sp_policy_documents
COMMENT 'Bronze: raw binary policy documents (PDF) from the SharePoint "Policies" document library (simulated Lakeflow Connect file output) - path, modificationTime, length, content. Plus _source_file, _source_file_modified_ts and _ingest_ts. Parsed with ai_parse_document in grc_silver.policy_document_extract.'
TBLPROPERTIES ('quality' = 'bronze', 'source_system' = 'SharePoint')
AS SELECT
  *,
  _metadata.file_path AS _source_file,
  _metadata.file_modification_time AS _source_file_modified_ts,
  current_timestamp() AS _ingest_ts
FROM STREAM read_files(
  '/Volumes/${grc_catalog}/grc_bronze/landing/sharepoint/documents/Policies/',
  format => 'binaryFile',
  pathGlobFilter => '*.pdf'
);
