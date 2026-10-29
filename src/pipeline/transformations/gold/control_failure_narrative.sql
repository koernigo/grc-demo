-- Gold: plain-English failure narratives for every failing control test, generated with ai_query from test results and top exception reasons.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.control_failure_narrative (
  CONSTRAINT valid_test_id EXPECT (test_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT narrative_generated EXPECT (owner_narrative IS NOT NULL)
)
COMMENT 'Gold: one row per failing control test with an AI-generated (ai_query, ${llm_endpoint}) control-owner narrative, draft auditor commentary and recommended remediation actions, grounded in grc_gold.control_test_results, the top exception reasons and business unit breakdown from grc_gold.control_test_evidence, and mapped framework requirements. Drafts require human review before use in audit workpapers.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH reasons AS (
  SELECT test_id, exception_reason, count(*) AS n
  FROM grc_gold.control_test_evidence
  WHERE is_exception
  GROUP BY test_id, exception_reason
),
top_reasons AS (
  SELECT test_id,
    array_join(transform(slice(array_sort(collect_list(named_struct('n', -n, 'r', exception_reason))), 1, 5), x -> concat(x.r, ' (', -x.n, ')')), '; ') AS top_exception_reasons
  FROM reasons
  GROUP BY test_id
),
bu AS (
  SELECT test_id, bu_id, count(*) AS n
  FROM grc_gold.control_test_evidence
  WHERE is_exception
  GROUP BY test_id, bu_id
),
bu_breakdown AS (
  SELECT test_id,
    array_join(transform(slice(array_sort(collect_list(named_struct('n', -n, 'b', coalesce(bu_id, 'Unassigned')))), 1, 5), x -> concat(x.b, ': ', -x.n)), ', ') AS exceptions_by_bu
  FROM bu
  GROUP BY test_id
),
fw AS (
  SELECT x.control_id, array_join(array_sort(collect_set(concat(x.framework_id, ' ', x.requirement_id))), ', ') AS framework_requirements
  FROM grc_ref.control_crosswalk x
  GROUP BY x.control_id
),
ctx AS (
  SELECT
    r.test_id,
    r.control_id,
    r.control_name,
    r.control_domain,
    r.owner_role,
    r.key_control,
    r.test_name,
    r.population_count,
    r.exception_count,
    r.pass_rate_pct,
    r.effectiveness_band,
    t.top_exception_reasons,
    b.exceptions_by_bu,
    fw.framework_requirements,
    concat_ws('\n',
      concat('Control: ', r.control_id, ' - ', r.control_name, ' (', r.control_domain, ', owner role: ', r.owner_role, CASE WHEN r.key_control THEN ', key control' ELSE '' END, ')'),
      concat('Control description: ', r.control_description),
      concat('Test: ', r.test_id, ' - ', r.test_name),
      concat('Population: ', r.test_population),
      concat('Pass condition: ', r.pass_condition),
      concat('Result as of ', CAST(r.test_run_date AS STRING), ': ', r.exception_count, ' exceptions out of ', r.population_count, ' (pass rate ', CAST(r.pass_rate_pct AS STRING), '%, rated ', r.effectiveness_band, ')'),
      concat('Top exception reasons (count): ', coalesce(t.top_exception_reasons, 'n/a')),
      concat('Exceptions by business unit: ', coalesce(b.exceptions_by_bu, 'n/a')),
      concat('Mapped framework requirements: ', coalesce(fw.framework_requirements, 'n/a'))
    ) AS prompt_context
  FROM grc_gold.control_test_results r
  LEFT JOIN top_reasons t ON t.test_id = r.test_id
  LEFT JOIN bu_breakdown b ON b.test_id = r.test_id
  LEFT JOIN fw ON fw.control_id = r.control_id
  WHERE r.test_result = 'Fail'
),
gen AS (
  SELECT
    *,
    ai_query(
      '${llm_endpoint}',
      concat(
        'You are a GRC analyst at ACME Corp. Using ONLY the facts below, write: ',
        'owner_narrative - 2-3 sentences for the control owner explaining what failed, the scale, and where it is concentrated; ',
        'auditor_commentary - 2-3 sentences in neutral audit language describing the deficiency, its likely root cause and the framework requirements affected; ',
        'recommended_actions - exactly 3 short, specific remediation actions. Do not invent numbers.\n\n',
        prompt_context
      ),
      responseFormat => 'STRUCT<result:STRUCT<owner_narrative:STRING, auditor_commentary:STRING, recommended_actions:ARRAY<STRING>>>',
      failOnError => false
    ) AS llm
  FROM ctx
),
parsed AS (
  SELECT
    *,
    from_json(llm.result, 'STRUCT<owner_narrative:STRING, auditor_commentary:STRING, recommended_actions:ARRAY<STRING>>') AS out
  FROM gen
)
SELECT
  test_id,
  control_id,
  control_name,
  control_domain,
  owner_role,
  key_control,
  test_name,
  population_count,
  exception_count,
  pass_rate_pct,
  effectiveness_band,
  top_exception_reasons,
  exceptions_by_bu,
  framework_requirements,
  out.owner_narrative AS owner_narrative,
  out.auditor_commentary AS auditor_commentary,
  out.recommended_actions AS recommended_actions,
  '${llm_endpoint}' AS model_endpoint,
  llm.errorMessage AS generation_error,
  prompt_context,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM parsed;
