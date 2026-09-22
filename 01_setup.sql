-- ============================================================================
-- DEMO SETUP — Run BEFORE going on stage (at least 2 hours before)
-- SWT London 2026: Innovate at Scale — Powering a Secure and Resilient AI Estate
-- ============================================================================
-- This script:
--   1. Creates demo users, roles, tasks, procs to trigger violations
--   2. Disables AI Guardrails so the scanner flags it
--   3. Creates classified tables + agents over them for AI Security detections
--   4. Triggers Threat Intelligence event-driven detections
--   5. Sets up Data Security classification profile
--   6. Enables all scanner packages and runs scanners
--   7. Invokes agents to generate access events (need ~2 hour propagation)
--
-- All objects use DEMO_ prefix for easy identification and cleanup.
-- Run teardown.sql after the demo to reset everything.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- 1. INSECURE USERS
-- Triggers: CIS 1.4 (Critical), CIS 1.10-1.12, CIS 1.8,
--           TI MFA Readiness (Critical), SE Strong Auth
-- ============================================================================

CREATE USER IF NOT EXISTS DEMO_NO_MFA_USER
  TYPE = PERSON
  PASSWORD = 'Demo!Pass2026x'
  MUST_CHANGE_PASSWORD = FALSE;

CREATE USER IF NOT EXISTS DEMO_BAD_ADMIN
  TYPE = PERSON
  PASSWORD = 'Admin!Pass2026x'
  MUST_CHANGE_PASSWORD = FALSE
  DEFAULT_ROLE = ACCOUNTADMIN;
GRANT ROLE ACCOUNTADMIN TO USER DEMO_BAD_ADMIN;

CREATE USER IF NOT EXISTS DEMO_DORMANT_USER
  TYPE = PERSON
  PASSWORD = 'Dormant!2026x'
  MUST_CHANGE_PASSWORD = FALSE
  DISABLED = TRUE;

CREATE ROLE IF NOT EXISTS DEMO_OVERPRIVILEGED_ROLE;
GRANT ROLE ACCOUNTADMIN TO ROLE DEMO_OVERPRIVILEGED_ROLE;
GRANT MANAGE GRANTS ON ACCOUNT TO ROLE DEMO_OVERPRIVILEGED_ROLE;

-- ============================================================================
-- 2. ADMIN-PRIVILEGED OBJECTS
-- Triggers: CIS 1.14/1.15 (tasks), CIS 1.16/1.17 (procs)
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
-- 3. DISABLE AI GUARDRAILS
-- Triggers: AI_SECURITY_ADVANCED_PROMPT_INJECTION_GUARDRAIL (High)
-- ============================================================================

ALTER ACCOUNT UNSET AI_SETTINGS;

-- ============================================================================
-- 4. CORTEX SEARCH SERVICES + AGENTS OVER CLASSIFIED DATA
-- Triggers: AI_SECURITY_CORTEX_SEARCH_SERVICE_PRIVILEGED_ROLES (High)
--           AI_SECURITY_AGENT_SENSITIVE_DATA_ACCESS (High Detection)
-- ============================================================================

-- HR data agent (PII: emails, names, ages)
CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_HR_SEARCH
  ON EMAIL_ADDRESS
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.HR_DATA);

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

-- Customer financial data (SSN, credit cards, income)
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

CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA')
);

CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_FINANCIAL_SEARCH
  ON FULL_NAME
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA);

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

CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.PATIENT_RECORDS',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.PATIENT_RECORDS')
);

CREATE OR REPLACE CORTEX SEARCH SERVICE DEMO_DB.PUBLIC.DEMO_PATIENT_SEARCH
  ON PATIENT_NAME
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  AS (SELECT * FROM DEMO_DB.PUBLIC.PATIENT_RECORDS);

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
-- 5. TRIGGER THREAT INTELLIGENCE EVENT-DRIVEN DETECTIONS
-- Triggers: AUTHENTICATION_POLICY_CHANGES, SENSITIVE_POLICY_CHANGES,
--           SENSITIVE_PARAMETER_PROTECTION
-- ============================================================================

CREATE OR REPLACE AUTHENTICATION POLICY DEMO_DB.PUBLIC.DEMO_WEAK_AUTH_POLICY
  COMMENT = 'Demo auth policy for detection trigger';

CREATE OR REPLACE PASSWORD POLICY DEMO_DB.PUBLIC.DEMO_WEAK_PASSWORD_POLICY
  PASSWORD_MIN_LENGTH = 8
  PASSWORD_MAX_AGE_DAYS = 999
  PASSWORD_HISTORY = 0
  COMMENT = 'Demo weak password policy for detection trigger';

CREATE OR REPLACE SESSION POLICY DEMO_DB.PUBLIC.DEMO_LONG_SESSION_POLICY
  SESSION_IDLE_TIMEOUT_MINS = 240
  SESSION_UI_IDLE_TIMEOUT_MINS = 240
  COMMENT = 'Demo overly permissive session policy';

ALTER ACCOUNT SET ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION = TRUE;

-- ============================================================================
-- 6. DATA SECURITY — Classification Profile
-- Populates: Data Security tab (Dashboard, Sensitive objects, Settings)
-- ============================================================================

GRANT DATABASE ROLE SNOWFLAKE.CLASSIFICATION_ADMIN TO ROLE ACCOUNTADMIN;

CREATE SCHEMA IF NOT EXISTS DEMO_DB.GOVERNANCE;
GRANT CREATE SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE ON SCHEMA DEMO_DB.GOVERNANCE TO ROLE ACCOUNTADMIN;

-- Detach profile from databases first (safe if not attached)
ALTER DATABASE DEMO_DB UNSET CLASSIFICATION_PROFILE;
ALTER DATABASE RBAC_DEMO_DB UNSET CLASSIFICATION_PROFILE;
DROP SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE IF EXISTS DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE;

CREATE OR REPLACE SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE
  DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE({
    'minimum_object_age_for_classification_days': 0,
    'maximum_classification_validity_days': 30,
    'auto_tag': true,
    'classify_views': false
  });

ALTER DATABASE DEMO_DB
  SET CLASSIFICATION_PROFILE = 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE';

ALTER DATABASE RBAC_DEMO_DB
  SET CLASSIFICATION_PROFILE = 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE';

-- Remove any manually applied tags that conflict with auto-classification
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;

CALL SYSTEM$CLASSIFY('DEMO_DB.PUBLIC.HR_DATA', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');
CALL SYSTEM$CLASSIFY('RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');
CALL SYSTEM$CLASSIFY('DEMO_DB.PUBLIC.PERSONS', 'DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE');

-- ============================================================================
-- 7. ENABLE ALL SCANNER PACKAGES AND RUN SCANNERS
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'THREAT_INTELLIGENCE', false);

CALL snowflake.trust_center.execute_scanner('CIS_BENCHMARKS');
CALL snowflake.trust_center.execute_scanner('SECURITY_ESSENTIALS');
CALL snowflake.trust_center.execute_scanner('AI_SECURITY');
CALL snowflake.trust_center.execute_scanner('THREAT_INTELLIGENCE');

-- ============================================================================
-- 8. INVOKE AGENTS TO TRIGGER AI SECURITY DETECTIONS
-- NOTE: Access history has ~2 hour latency. Run this script at least 2 hours
--       before the demo. Re-run the scanners in Section 7 before going on stage.
-- ============================================================================

SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "List all employee email addresses"}]}]}',
  TRUE
);

SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_FINANCIAL_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "What customers do you have records for?"}]}]}',
  TRUE
);

SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
  'DEMO_DB.PUBLIC.DEMO_PATIENT_AGENT',
  '{"messages": [{"role": "user", "content": [{"type": "text", "text": "What patients are on Metformin?"}]}]}',
  TRUE
);

-- ============================================================================
-- 9. DISABLE AI SECURITY + THREAT INTELLIGENCE FOR LIVE ENABLE MOMENT
-- The demo script enables these live on stage.
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- 10. VERIFY
-- ============================================================================

SELECT ID, NAME, STATE FROM snowflake.trust_center.scanner_packages ORDER BY NAME;
-- EXPECTED: AI_SECURITY=FALSE, CIS_BENCHMARKS=TRUE, SECURITY_ESSENTIALS=TRUE, THREAT_INTELLIGENCE=FALSE

SELECT SEVERITY, COUNT(*) AS FINDING_COUNT, SUM(TOTAL_AT_RISK_COUNT) AS TOTAL_AT_RISK
FROM snowflake.trust_center.findings
WHERE UPPER(STATE) = 'OPEN' AND TOTAL_AT_RISK_COUNT > 0
GROUP BY SEVERITY
ORDER BY CASE SEVERITY
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
END;

-- ============================================================================
-- SETUP COMPLETE — Ready for demo
-- All Trust Center tabs should be populated:
--   Overview:        Summary from all 4 packages
--   Violations:      CIS compliance + AI Security violations
--   Detections:      Client security + agent sensitive data + TI events
--   Data Security:   Classification profile + classified tables
--   AI Security:     36+ agents, 4/4 scanners, guardrails flagged
--   Manage Scanners: All 4 packages enabled
-- ============================================================================
