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
-- SECTION 5: CLASSIFY HR_DATA FOR DATA SECURITY TAB
-- Populates: Data Security tab with classification results
-- Also makes AI Security "Sensitive Data Accessed by Agent" scanner fire
-- ============================================================================

CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.HR_DATA',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.HR_DATA')
);

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
--   Data Security:   HR_DATA classification results
--   AI Security:     36+ agents, 4/4 scanners, guardrails flagged
--   Manage Scanners: All 4 packages enabled
-- ============================================================================
