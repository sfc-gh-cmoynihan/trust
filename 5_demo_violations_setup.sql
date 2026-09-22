-- ============================================================================
-- DEMO VIOLATIONS SETUP
-- SWT London 2026: Trust Center — Populate All Tabs
-- ============================================================================
-- Creates deliberate security violations so every Trust Center tab has data:
--   Overview, Violations, Detections, Data Security, AI Security, Manage Scanners
-- All objects use DEMO_ prefix for easy identification and cleanup.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- SECTION 1: INSECURE USERS
-- Triggers: CIS 1.4 (Critical), CIS 1.10-1.12, CIS 1.8,
--           TI MFA Readiness (Critical), SE Strong Auth
-- ============================================================================

-- No MFA user — password only
CREATE USER IF NOT EXISTS DEMO_NO_MFA_USER
  TYPE = PERSON
  PASSWORD = 'Demo!Pass2026x'
  MUST_CHANGE_PASSWORD = FALSE;

-- Admin user with no email and ACCOUNTADMIN as default role
CREATE USER IF NOT EXISTS DEMO_BAD_ADMIN
  TYPE = PERSON
  PASSWORD = 'Admin!Pass2026x'
  MUST_CHANGE_PASSWORD = FALSE
  DEFAULT_ROLE = ACCOUNTADMIN;
GRANT ROLE ACCOUNTADMIN TO USER DEMO_BAD_ADMIN;

-- Dormant user — disabled, never logged in
CREATE USER IF NOT EXISTS DEMO_DORMANT_USER
  TYPE = PERSON
  PASSWORD = 'Dormant!2026x'
  MUST_CHANGE_PASSWORD = FALSE
  DISABLED = TRUE;

-- Over-privileged custom role with ACCOUNTADMIN grant (CIS 1.13)
CREATE ROLE IF NOT EXISTS DEMO_OVERPRIVILEGED_ROLE;
GRANT ROLE ACCOUNTADMIN TO ROLE DEMO_OVERPRIVILEGED_ROLE;

-- Grant MANAGE GRANTS to trigger TI MANAGE_GRANTS_PRIVILEGE_MONITORING detection
GRANT MANAGE GRANTS ON ACCOUNT TO ROLE DEMO_OVERPRIVILEGED_ROLE;

-- ============================================================================
-- SECTION 2: ADMIN-PRIVILEGED OBJECTS
-- Triggers: CIS 1.14 (tasks owned by admin), CIS 1.15 (tasks run as admin),
--           CIS 1.16 (procs owned by admin), CIS 1.17 (procs run as admin)
-- ============================================================================

CREATE OR REPLACE TASK DEMO_DB.PUBLIC.DEMO_ADMIN_TASK
  WAREHOUSE = COMPUTE_WH
  SCHEDULE = '1440 MINUTE'
AS SELECT 1;

CREATE OR REPLACE PROCEDURE DEMO_DB.PUBLIC.DEMO_ADMIN_PROC()
  RETURNS STRING
  LANGUAGE SQL
  EXECUTE AS OWNER
AS
BEGIN
  RETURN 'This proc runs with ACCOUNTADMIN privileges';
END;

-- ============================================================================
-- SECTION 3: DISABLE AI GUARDRAILS
-- Triggers: AI_SECURITY_ADVANCED_PROMPT_INJECTION_GUARDRAIL (High)
-- Currently enabled — disabling so the scanner flags it as a violation.
-- Teardown script re-enables them.
-- ============================================================================

ALTER ACCOUNT UNSET AI_SETTINGS;

-- ============================================================================
-- SECTION 4: CORTEX SEARCH SERVICE + AGENT OVER CLASSIFIED DATA
-- Triggers: AI_SECURITY_CORTEX_SEARCH_SERVICE_PRIVILEGED_ROLES (High)
--           AI_SECURITY_AGENT_SENSITIVE_DATA_ACCESS (High Detection)
-- ============================================================================

-- Search service over HR data (contains PII: emails, names, ages)
-- Owned by ACCOUNTADMIN — triggers privileged roles scanner
CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_HR_SEARCH
  ON EMAIL_ADDRESS
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.HR_DATA);

-- Agent that queries the search service with classified PII data
CREATE OR REPLACE AGENT DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT
  COMMENT = 'Demo agent accessing classified HR data without guardrails'
  FROM SPECIFICATION
  $$
  models:
    orchestration: auto
  instructions:
    response: "Answer questions about HR employee data including names and emails"
  tools:
    - tool_spec:
        type: "cortex_search"
        name: "HRSearch"
        description: "Search HR employee records including personally identifiable information"
  tool_resources:
    HRSearch:
      search_service: "DEMO_DB.PUBLIC.DEMO_HR_SEARCH"
      max_results: "5"
  $$;

-- ============================================================================
-- SECTION 4B: ADDITIONAL AGENTS OVER CLASSIFIED DATA
-- Triggers: More AI_SECURITY_AGENT_SENSITIVE_DATA_ACCESS detections
--           More AI_SECURITY_CORTEX_SEARCH_SERVICE_PRIVILEGED_ROLES violations
-- NOTE: Access history has ~2 hour latency. Run agent invocations (Section 7B)
--       at least 2 hours before the demo for detections to appear.
-- ============================================================================

-- Customer financial data (SSN, credit card, income)
CREATE OR REPLACE TABLE DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA (
    CUSTOMER_ID INT,
    FULL_NAME VARCHAR,
    SSN VARCHAR,
    CREDIT_CARD_NUMBER VARCHAR,
    ANNUAL_INCOME NUMBER(12,2),
    CREDIT_SCORE INT
) AS
SELECT
    SEQ4() AS CUSTOMER_ID,
    CONCAT(
        CASE MOD(SEQ4(), 5) WHEN 0 THEN 'John' WHEN 1 THEN 'Sarah' WHEN 2 THEN 'Michael' WHEN 3 THEN 'Emily' ELSE 'David' END,
        ' ',
        CASE MOD(SEQ4(), 4) WHEN 0 THEN 'Smith' WHEN 1 THEN 'Johnson' WHEN 2 THEN 'Williams' ELSE 'Brown' END
    ) AS FULL_NAME,
    CONCAT(LPAD(MOD(SEQ4() * 7, 999)::VARCHAR, 3, '0'), '-', LPAD(MOD(SEQ4() * 13, 99)::VARCHAR, 2, '0'), '-', LPAD(MOD(SEQ4() * 17, 9999)::VARCHAR, 4, '0')) AS SSN,
    CONCAT('4', LPAD(MOD(SEQ4() * 31, 999999999999999)::VARCHAR, 15, '0')) AS CREDIT_CARD_NUMBER,
    ROUND(50000 + UNIFORM(0::FLOAT, 150000::FLOAT, RANDOM()), 2) AS ANNUAL_INCOME,
    600 + MOD(SEQ4() * 7, 200) AS CREDIT_SCORE
FROM TABLE(GENERATOR(ROWCOUNT => 50));

-- Patient medical records (PHI: names, DOB, diagnoses, medications)
CREATE OR REPLACE TABLE DEMO_DB.PUBLIC.PATIENT_RECORDS (
    PATIENT_ID INT,
    PATIENT_NAME VARCHAR,
    DATE_OF_BIRTH DATE,
    PHONE_NUMBER VARCHAR,
    MEDICAL_RECORD_NUMBER VARCHAR,
    DIAGNOSIS VARCHAR,
    MEDICATION VARCHAR
) AS
SELECT
    SEQ4() AS PATIENT_ID,
    CONCAT(
        CASE MOD(SEQ4(), 5) WHEN 0 THEN 'Alice' WHEN 1 THEN 'Bob' WHEN 2 THEN 'Carol' WHEN 3 THEN 'Daniel' ELSE 'Eva' END,
        ' ',
        CASE MOD(SEQ4(), 4) WHEN 0 THEN 'Martinez' WHEN 1 THEN 'Garcia' WHEN 2 THEN 'Lee' ELSE 'Patel' END
    ) AS PATIENT_NAME,
    DATEADD('day', -UNIFORM(7000, 25000, RANDOM()), CURRENT_DATE()) AS DATE_OF_BIRTH,
    CONCAT('+1-', LPAD(MOD(SEQ4() * 11, 999)::VARCHAR, 3, '0'), '-', LPAD(MOD(SEQ4() * 23, 9999)::VARCHAR, 4, '0')) AS PHONE_NUMBER,
    CONCAT('MRN-', LPAD(SEQ4()::VARCHAR, 6, '0')) AS MEDICAL_RECORD_NUMBER,
    CASE MOD(SEQ4(), 5) WHEN 0 THEN 'Hypertension' WHEN 1 THEN 'Type 2 Diabetes' WHEN 2 THEN 'Asthma' WHEN 3 THEN 'Depression' ELSE 'Migraine' END AS DIAGNOSIS,
    CASE MOD(SEQ4(), 5) WHEN 0 THEN 'Lisinopril' WHEN 1 THEN 'Metformin' WHEN 2 THEN 'Albuterol' WHEN 3 THEN 'Sertraline' ELSE 'Sumatriptan' END AS MEDICATION
FROM TABLE(GENERATOR(ROWCOUNT => 50));

-- Classify the new tables as sensitive
CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA')
);
CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.PATIENT_RECORDS',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.PATIENT_RECORDS')
);

-- Search services over classified data (owned by ACCOUNTADMIN)
CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_FINANCIAL_SEARCH
  ON FULL_NAME
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA);

CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_PATIENT_SEARCH
  ON PATIENT_NAME
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.PATIENT_RECORDS);

-- Agent accessing financial PII (SSN, credit cards)
CREATE OR REPLACE AGENT DEMO_DB.PUBLIC.DEMO_FINANCIAL_AGENT
  COMMENT = 'Demo agent accessing classified financial data — SSN, credit cards'
  FROM SPECIFICATION
  $$
  models:
    orchestration: auto
  instructions:
    response: "Answer questions about customer financial records"
  tools:
    - tool_spec:
        type: "cortex_search"
        name: "FinancialSearch"
        description: "Search customer financial records including names and income data"
  tool_resources:
    FinancialSearch:
      search_service: "DEMO_DB.PUBLIC.DEMO_FINANCIAL_SEARCH"
      max_results: "5"
  $$;

-- Agent accessing patient medical records (PHI)
CREATE OR REPLACE AGENT DEMO_DB.PUBLIC.DEMO_PATIENT_AGENT
  COMMENT = 'Demo agent accessing classified patient medical records'
  FROM SPECIFICATION
  $$
  models:
    orchestration: auto
  instructions:
    response: "Answer questions about patient medical records"
  tools:
    - tool_spec:
        type: "cortex_search"
        name: "PatientSearch"
        description: "Search patient medical records including names, diagnoses, and medications"
  tool_resources:
    PatientSearch:
      search_service: "DEMO_DB.PUBLIC.DEMO_PATIENT_SEARCH"
      max_results: "5"
  $$;

-- ============================================================================
-- SECTION 4C: TRIGGER THREAT INTELLIGENCE EVENT-DRIVEN DETECTIONS
-- Triggers: AUTHENTICATION_POLICY_CHANGES, SENSITIVE_POLICY_CHANGES,
--           SENSITIVE_PARAMETER_PROTECTION
-- ============================================================================

-- Weak auth policy — triggers TI AUTHENTICATION_POLICY_CHANGES
CREATE OR REPLACE AUTHENTICATION POLICY DEMO_DB.PUBLIC.DEMO_WEAK_AUTH_POLICY
  COMMENT = 'Demo auth policy for detection trigger';

-- Weak password policy — triggers TI SENSITIVE_POLICY_CHANGES
CREATE OR REPLACE PASSWORD POLICY DEMO_DB.PUBLIC.DEMO_WEAK_PASSWORD_POLICY
  PASSWORD_MIN_LENGTH = 8
  PASSWORD_MAX_AGE_DAYS = 999
  PASSWORD_HISTORY = 0
  COMMENT = 'Demo weak password policy for detection trigger';

-- Overly permissive session policy — triggers TI SENSITIVE_POLICY_CHANGES
CREATE OR REPLACE SESSION POLICY DEMO_DB.PUBLIC.DEMO_LONG_SESSION_POLICY
  SESSION_IDLE_TIMEOUT_MINS = 240
  SESSION_UI_IDLE_TIMEOUT_MINS = 240
  COMMENT = 'Demo overly permissive session policy';

-- Alter sensitive parameter — triggers TI SENSITIVE_PARAMETER_PROTECTION
ALTER ACCOUNT SET ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION = TRUE;

-- ============================================================================
-- SECTION 5: DATA SECURITY — Classification Profile
-- Populates: Data Security tab (Dashboard, Sensitive objects, Settings)
-- Also makes AI Security "Sensitive Data Accessed by Agent" scanner fire
-- ============================================================================
-- The Data Security tab requires a CLASSIFICATION_PROFILE set on databases.
-- There is a ~1 hour delay before automatic classification begins.
-- We also run SYSTEM$CLASSIFY manually on key tables for immediate results.

-- Grant required role for profile creation
GRANT DATABASE ROLE SNOWFLAKE.CLASSIFICATION_ADMIN TO ROLE ACCOUNTADMIN;

-- Create governance schema for the classification profile
CREATE SCHEMA IF NOT EXISTS DEMO_DB.GOVERNANCE;
GRANT CREATE SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE ON SCHEMA DEMO_DB.GOVERNANCE TO ROLE ACCOUNTADMIN;

-- Create classification profile with auto-tagging enabled
CREATE OR REPLACE SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE
  DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE({
    'minimum_object_age_for_classification_days': 0,
    'maximum_classification_validity_days': 30,
    'auto_tag': true,
    'classify_views': false
  });

-- Set the profile on both databases
ALTER DATABASE DEMO_DB
  SET CLASSIFICATION_PROFILE = 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE';

ALTER DATABASE RBAC_DEMO_DB
  SET CLASSIFICATION_PROFILE = 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE';

-- Remove any manually applied tags that would conflict with auto-classification
-- (SYSTEM$CLASSIFY fails if manual tags are present)
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;

-- Manually classify key tables for immediate Data Security tab results
CALL SYSTEM$CLASSIFY('DEMO_DB.PUBLIC.HR_DATA', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');
CALL SYSTEM$CLASSIFY('RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');
CALL SYSTEM$CLASSIFY('DEMO_DB.PUBLIC.PERSONS', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');

-- ============================================================================
-- SECTION 6: ENABLE ALL SCANNER PACKAGES
-- Populates: Manage Scanners tab — all 4 packages active
-- ============================================================================

-- AI Security and Threat Intelligence are currently disabled
CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- SECTION 7: RUN ALL SCANNERS
-- Populates: Overview, Violations, Detections, AI Security charts
-- ============================================================================

CALL snowflake.trust_center.execute_scanner('CIS_BENCHMARKS');
CALL snowflake.trust_center.execute_scanner('SECURITY_ESSENTIALS');
CALL snowflake.trust_center.execute_scanner('AI_SECURITY');
CALL snowflake.trust_center.execute_scanner('THREAT_INTELLIGENCE');

-- ============================================================================
-- SECTION 7B: INVOKE AGENTS TO TRIGGER AI SECURITY DETECTIONS
-- NOTE: Access history has ~2 hour latency. Run this section at least 2 hours
--       before the demo, then re-run Section 7 scanners before going on stage.
-- ============================================================================

-- Invoke HR agent — accesses classified PII (emails, names, age)
SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "List all employee email addresses"}]}]}',
  TRUE
);

-- Invoke financial agent — accesses classified financial data (SSN, credit cards)
SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_FINANCIAL_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "What customers do you have records for?"}]}]}',
  TRUE
);

-- Invoke patient agent — accesses classified medical records (PHI)
SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_PATIENT_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "What patients are on Metformin?"}]}]}',
  TRUE
);

-- ============================================================================
-- SECTION 8: VERIFY
-- ============================================================================

-- Check all packages are enabled
SELECT ID, NAME, STATE FROM snowflake.trust_center.scanner_packages ORDER BY NAME;

-- Check findings across all packages
SELECT
    SCANNER_PACKAGE_NAME,
    SEVERITY,
    SCANNER_TYPE,
    COUNT(*) AS FINDING_COUNT,
    SUM(TOTAL_AT_RISK_COUNT) AS TOTAL_AT_RISK
FROM snowflake.trust_center.findings
WHERE UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
GROUP BY SCANNER_PACKAGE_NAME, SEVERITY, SCANNER_TYPE
ORDER BY SCANNER_PACKAGE_NAME,
    CASE SEVERITY
        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
    END;

-- ============================================================================
-- SETUP COMPLETE
-- All Trust Center tabs should now be populated:
--   Overview:        Summary from all 4 packages
--   Violations:      CIS compliance + AI Security violations
--   Detections:      Client security + agent sensitive data + TI events
--   Data Security:   Classification profile + classified tables (HR_DATA, STOCK_ANALYST_DATA, PERSONS)
--   AI Security:     36+ agents, 4/4 scanners, guardrails flagged
--   Manage Scanners: All 4 packages enabled
-- ============================================================================
