-- Gold: policy exception tracker with lifecycle state, linked policy/risk/control context.
CREATE OR REFRESH MATERIALIZED VIEW grc_gold.exception_tracker (
  exception_id STRING COMMENT 'Exception id (primary key)',
  exception_title STRING COMMENT 'Exception title',
  tracker_state STRING COMMENT 'Expired - Still Active, Exceeds Max Duration, Expiring Within 30 Days, Pending Approval, Rejected, Valid or Closed',
  exception_status STRING COMMENT 'List status',
  approval_status STRING COMMENT 'Approval status',
  bu_id STRING COMMENT 'Business unit',
  bu_name STRING COMMENT 'Business unit name',
  requester_email STRING COMMENT 'Requester email',
  approver_email STRING COMMENT 'Approver email',
  start_date DATE COMMENT 'Start date',
  expiry_date DATE COMMENT 'Expiry date',
  days_to_expiry INT COMMENT 'Days to expiry (negative = expired)',
  days_past_expiry INT COMMENT 'Days past expiry (0 if not expired)',
  duration_days INT COMMENT 'Approved duration in days',
  max_duration_days INT COMMENT 'Maximum allowed duration',
  is_valid BOOLEAN COMMENT 'Approved, unexpired and within max duration',
  is_expired BOOLEAN COMMENT 'Expired',
  is_expired_but_active BOOLEAN COMMENT 'Active past expiry',
  exceeds_max_duration BOOLEAN COMMENT 'Duration exceeds maximum',
  expiring_within_30d BOOLEAN COMMENT 'Expires within 30 days',
  compensating_controls STRING COMMENT 'Compensating controls',
  policy_id STRING COMMENT 'Excepted policy id',
  policy_title STRING COMMENT 'Excepted policy title',
  policy_owner_email STRING COMMENT 'Excepted policy owner',
  control_id STRING COMMENT 'Excepted control id',
  control_name STRING COMMENT 'Excepted control name',
  control_test_result STRING COMMENT 'Latest test result of the excepted control',
  control_pass_rate_pct DECIMAL(27,2) COMMENT 'Latest pass rate of the excepted control',
  linked_risk_id STRING COMMENT 'Linked risk id',
  linked_risk_title STRING COMMENT 'Linked risk title',
  linked_risk_inherent_rating STRING COMMENT 'Linked risk inherent rating',
  linked_risk_residual_rating STRING COMMENT 'Linked risk residual rating',
  action_required BOOLEAN COMMENT 'True when the state requires follow-up (expired active, over max duration, expiring soon, pending)',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_exception_id EXPECT (exception_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT linked_policy_exists EXPECT (policy_title IS NOT NULL)
)
COMMENT 'Gold: one row per policy exception with tracker_state (Valid, Expiring Within 30 Days, Expired - Still Active, Exceeds Max Duration, Pending Approval, Rejected, Closed, Review Required), requester/approver, start/expiry, days to expiry / days past expiry, duration vs 180-day maximum, compensating controls, the excepted policy and unified control (with its latest test result) and the linked risk (inherent/residual rating). action_required is true for states needing GRC follow-up. Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'gold')
AS
SELECT
  e.exception_id,
  e.exception_title,
  CASE
    WHEN e.approval_status = 'Rejected' THEN 'Rejected'
    WHEN e.approval_status = 'Pending' THEN 'Pending Approval'
    WHEN e.exception_status = 'Closed' THEN 'Closed'
    WHEN e.is_expired_but_active THEN 'Expired - Still Active'
    WHEN e.exceeds_max_duration THEN 'Exceeds Max Duration'
    WHEN e.expiring_within_30d THEN 'Expiring Within 30 Days'
    WHEN e.is_valid THEN 'Valid'
    ELSE 'Review Required'
  END AS tracker_state,
  e.exception_status,
  e.approval_status,
  e.bu_id,
  bu.bu_name,
  e.requester_email,
  e.approver_email,
  e.start_date,
  e.expiry_date,
  e.days_to_expiry,
  greatest(0, -e.days_to_expiry) AS days_past_expiry,
  e.duration_days,
  e.max_duration_days,
  e.is_valid,
  e.is_expired,
  e.is_expired_but_active,
  e.exceeds_max_duration,
  e.expiring_within_30d,
  e.compensating_controls,
  e.policy_id,
  p.policy_title,
  p.owner_email AS policy_owner_email,
  e.control_id,
  c.control_name,
  t.test_result AS control_test_result,
  t.pass_rate_pct AS control_pass_rate_pct,
  e.linked_risk_id,
  r.risk_title AS linked_risk_title,
  r.inherent_rating AS linked_risk_inherent_rating,
  r.residual_rating AS linked_risk_residual_rating,
  (e.exception_status = 'Active' AND NOT e.is_valid) OR e.expiring_within_30d OR e.approval_status = 'Pending' AS action_required,
  e.as_of_date
FROM grc_silver.risk_exception e
LEFT JOIN grc_silver.policy p ON e.policy_id = p.policy_id
LEFT JOIN grc_ref.controls c ON e.control_id = c.control_id
LEFT JOIN grc_gold.control_test_results t ON e.control_id = t.control_id
LEFT JOIN grc_gold.risk_register_scored r ON e.linked_risk_id = r.risk_id
LEFT JOIN grc_ref.business_units bu ON e.bu_id = bu.bu_id;
