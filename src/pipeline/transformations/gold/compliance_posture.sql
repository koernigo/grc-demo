-- Gold: framework requirement posture derived from unified control test results via the control crosswalk.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.compliance_posture (
  framework_id STRING COMMENT 'Framework id (NIST_CSF_2, ISO_27001, SOC2, CIS_V8)',
  framework_name STRING COMMENT 'Framework name',
  framework_version STRING COMMENT 'Framework version',
  requirement_id STRING COMMENT 'Framework requirement id',
  requirement_group STRING COMMENT 'Requirement family / function',
  requirement_title STRING COMMENT 'Requirement title',
  mapped_control_count BIGINT COMMENT 'Unified controls mapped via grc_ref.control_crosswalk',
  primary_control_count BIGINT COMMENT 'Controls mapped as Primary',
  mapped_controls ARRAY<STRING> COMMENT 'Mapped unified control ids',
  failing_controls ARRAY<STRING> COMMENT 'Mapped controls whose test failed',
  effective_controls BIGINT COMMENT 'Mapped controls rated Effective',
  partially_effective_controls BIGINT COMMENT 'Mapped controls rated Partially Effective',
  ineffective_controls BIGINT COMMENT 'Mapped controls rated Ineffective',
  weighted_pass_rate_pct DECIMAL(35,2) COMMENT 'Population-weighted pass rate across mapped control tests',
  requirement_status STRING COMMENT 'Worst band among mapped controls, or Not Mapped',
  requirement_status_color STRING COMMENT 'Hex color of requirement_status',
  framework_requirement_count BIGINT COMMENT 'Requirements in the framework',
  framework_requirements_effective_pct DECIMAL(27,2) COMMENT 'Percent of framework requirements rated Effective',
  framework_avg_pass_rate_pct DECIMAL(35,2) COMMENT 'Average weighted pass rate across framework requirements',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_requirement EXPECT (framework_id IS NOT NULL AND requirement_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT requirement_mapped EXPECT (mapped_control_count > 0)
)
COMMENT 'Gold: one row per framework requirement (NIST CSF 2.0, ISO 27001:2022 Annex A, SOC 2 TSC, PCI DSS v4.0 from grc_ref.framework_requirements) with the unified controls mapped through grc_ref.control_crosswalk and their latest test results. requirement_status is the worst effectiveness band among Primary-mapped controls (falls back to all mapped controls; Not Mapped if none). weighted_pass_rate_pct weights Primary mappings 1.0 and Supporting 0.5. Framework-level rollups (requirements effective %, framework pass rate) are repeated on each row for convenience.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH r AS (
  SELECT control_id, test_id, pass_rate_pct, test_result, effectiveness_band, effectiveness_sort
  FROM grc_gold.control_test_results
),
x AS (
  SELECT cw.framework_id, cw.requirement_id, cw.control_id, cw.mapping_strength,
         CASE WHEN cw.mapping_strength = 'Primary' THEN 1.0 ELSE 0.5 END AS weight,
         r.pass_rate_pct, r.test_result, r.effectiveness_band, r.effectiveness_sort
  FROM grc_ref.control_crosswalk cw
  LEFT JOIN r ON cw.control_id = r.control_id
),
req AS (
  SELECT
    fr.framework_id,
    f.framework_name,
    f.version AS framework_version,
    fr.requirement_id,
    fr.requirement_group,
    fr.requirement_title,
    count(x.control_id) AS mapped_control_count,
    count_if(x.mapping_strength = 'Primary') AS primary_control_count,
    count_if(x.effectiveness_band = 'Effective') AS effective_controls,
    count_if(x.effectiveness_band = 'Partially Effective') AS partially_effective_controls,
    count_if(x.effectiveness_band = 'Ineffective') AS ineffective_controls,
    round(sum(x.pass_rate_pct * x.weight) / nullif(sum(CASE WHEN x.pass_rate_pct IS NOT NULL THEN x.weight END), 0), 2) AS weighted_pass_rate_pct,
    max(CASE WHEN x.mapping_strength = 'Primary' AND x.effectiveness_sort < 99 THEN x.effectiveness_sort END) AS worst_primary_sort,
    max(CASE WHEN x.effectiveness_sort < 99 THEN x.effectiveness_sort END) AS worst_any_sort,
    array_sort(collect_set(x.control_id)) AS mapped_controls,
    array_sort(collect_set(CASE WHEN x.test_result = 'Fail' THEN x.control_id END)) AS failing_controls
  FROM grc_ref.framework_requirements fr
  JOIN grc_ref.frameworks f ON fr.framework_id = f.framework_id
  LEFT JOIN x ON fr.framework_id = x.framework_id AND fr.requirement_id = x.requirement_id
  GROUP BY fr.framework_id, f.framework_name, f.version, fr.requirement_id, fr.requirement_group, fr.requirement_title
),
st AS (
  SELECT req.*,
         CASE
           WHEN mapped_control_count = 0 THEN 'Not Mapped'
           ELSE coalesce(b.status, 'Not Tested')
         END AS requirement_status,
         b.color_hex AS requirement_status_color
  FROM req
  LEFT JOIN grc_ref.control_effectiveness_bands b ON b.sort_order = coalesce(req.worst_primary_sort, req.worst_any_sort)
)
SELECT
  st.framework_id,
  st.framework_name,
  st.framework_version,
  st.requirement_id,
  st.requirement_group,
  st.requirement_title,
  st.mapped_control_count,
  st.primary_control_count,
  st.mapped_controls,
  st.failing_controls,
  st.effective_controls,
  st.partially_effective_controls,
  st.ineffective_controls,
  st.weighted_pass_rate_pct,
  st.requirement_status,
  st.requirement_status_color,
  count(*) OVER (PARTITION BY st.framework_id) AS framework_requirement_count,
  round(100.0 * sum(CASE WHEN st.requirement_status = 'Effective' THEN 1 ELSE 0 END) OVER (PARTITION BY st.framework_id)
        / count(*) OVER (PARTITION BY st.framework_id), 2) AS framework_requirements_effective_pct,
  round(avg(st.weighted_pass_rate_pct) OVER (PARTITION BY st.framework_id), 2) AS framework_avg_pass_rate_pct,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM st;
