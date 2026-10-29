-- Silver: per active workforce user annual security awareness training status + phishing simulation outcomes.
CREATE OR REFRESH MATERIALIZED VIEW grc_silver.training_status (
  user_id STRING COMMENT 'Okta user id of the active workforce identity',
  login STRING COMMENT 'Lower-cased login / email',
  hr_employee_id STRING COMMENT 'Workday employee id',
  bu_id STRING COMMENT 'Business unit',
  job_title STRING COMMENT 'Job title',
  location STRING COMMENT 'Work location',
  hire_date DATE COMMENT 'HR hire date',
  enrollment_id STRING COMMENT 'Latest Security Awareness Training enrollment id',
  course_name STRING COMMENT 'Course name',
  is_enrolled BOOLEAN COMMENT 'True if an enrollment exists',
  assigned_date DATE COMMENT 'Enrollment assigned date',
  due_date DATE COMMENT 'Enrollment due date',
  completion_date DATE COMMENT 'Completion date (null if not completed)',
  lms_status STRING COMMENT 'LMS enrollment status',
  score INT COMMENT 'Assessment score',
  recert_days INT COMMENT 'TRAINING_RECERT period in days',
  training_current BOOLEAN COMMENT 'Completed within recert_days of as_of_date (control GRC-TRN-01)',
  training_compliant BOOLEAN COMMENT 'Current, or not completed but not yet due',
  training_status STRING COMMENT 'Completed, In Progress, Overdue or Not Enrolled',
  phishing_campaigns_received BIGINT COMMENT 'Phishing simulations delivered',
  phishing_opened BIGINT COMMENT 'Simulations opened',
  phishing_clicked BIGINT COMMENT 'Simulations clicked',
  phishing_data_entered BIGINT COMMENT 'Simulations where credentials were entered',
  phishing_reported BIGINT COMMENT 'Simulations reported',
  phishing_click_rate DOUBLE COMMENT 'Clicked / received',
  is_repeat_clicker BOOLEAN COMMENT 'Clicked two or more simulations',
  last_phishing_click_date DATE COMMENT 'Send date of the latest clicked simulation',
  as_of_date DATE COMMENT 'Evaluation date (pipeline parameter as_of_date)',
  CONSTRAINT valid_user_id EXPECT (user_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT has_business_unit EXPECT (bu_id IS NOT NULL),
  CONSTRAINT enrolled_in_training EXPECT (is_enrolled),
  CONSTRAINT valid_completion_date EXPECT (completion_date IS NULL OR completion_date >= assigned_date)
)
COMMENT 'Silver: one row per active workforce identity (enabled in Okta and active in HR) with the latest Security Awareness Training enrollment (assigned/due/completion dates, LMS status, score), training_current (completed within TRAINING_RECERT 365 days), training_compliant (current, or not yet due) and phishing simulation outcomes across campaigns (received, opened, clicked, data entered, reported, click rate, repeat clicker). Evaluated as of pipeline parameter as_of_date.'
TBLPROPERTIES ('quality' = 'silver')
AS
WITH idn AS (
  SELECT user_id, login, hr_employee_id, bu_id, job_title, location, hire_date
  FROM grc_silver.identity
  WHERE user_type = 'workforce' AND is_enabled AND coalesce(hr_employment_status, 'Active') = 'Active'
),
enr AS (
  SELECT *
  FROM grc_bronze.lms_enrollments
  WHERE course_name LIKE 'Security Awareness Training%'
  QUALIFY row_number() OVER (PARTITION BY lower(user_email) ORDER BY assigned_date DESC, completion_date DESC NULLS LAST, _ingest_ts DESC) = 1
),
ph AS (
  SELECT
    lower(user_email) AS login,
    count(*) AS phishing_campaigns_received,
    count_if(opened) AS phishing_opened,
    count_if(clicked) AS phishing_clicked,
    count_if(data_entered) AS phishing_data_entered,
    count_if(reported) AS phishing_reported,
    max(CASE WHEN clicked THEN send_date END) AS last_phishing_click_date
  FROM grc_bronze.lms_phishing_results
  WHERE delivered
  GROUP BY lower(user_email)
),
cfg AS (
  SELECT max(sla_value) AS recert_days FROM grc_ref.sla_policy WHERE sla_type = 'TRAINING_RECERT'
)
SELECT
  idn.user_id,
  idn.login,
  idn.hr_employee_id,
  idn.bu_id,
  idn.job_title,
  idn.location,
  idn.hire_date,
  enr.enrollment_id,
  enr.course_name,
  enr.enrollment_id IS NOT NULL AS is_enrolled,
  enr.assigned_date,
  enr.due_date,
  enr.completion_date,
  enr.status AS lms_status,
  enr.score,
  cfg.recert_days,
  coalesce(datediff(CAST(:as_of_date AS DATE), enr.completion_date) <= cfg.recert_days, false) AS training_current,
  training_current OR coalesce(enr.completion_date IS NULL AND enr.due_date >= CAST(:as_of_date AS DATE), false) AS training_compliant,
  CASE
    WHEN training_current THEN 'Completed'
    WHEN enr.enrollment_id IS NULL THEN 'Not Enrolled'
    WHEN enr.due_date < CAST(:as_of_date AS DATE) THEN 'Overdue'
    ELSE 'In Progress'
  END AS training_status,
  coalesce(ph.phishing_campaigns_received, 0) AS phishing_campaigns_received,
  coalesce(ph.phishing_opened, 0) AS phishing_opened,
  coalesce(ph.phishing_clicked, 0) AS phishing_clicked,
  coalesce(ph.phishing_data_entered, 0) AS phishing_data_entered,
  coalesce(ph.phishing_reported, 0) AS phishing_reported,
  round(coalesce(ph.phishing_clicked, 0) / nullif(ph.phishing_campaigns_received, 0), 3) AS phishing_click_rate,
  coalesce(ph.phishing_clicked, 0) >= 2 AS is_repeat_clicker,
  ph.last_phishing_click_date,
  CAST(:as_of_date AS DATE) AS as_of_date
FROM idn
CROSS JOIN cfg
LEFT JOIN enr ON idn.login = lower(enr.user_email)
LEFT JOIN ph ON idn.login = ph.login;
