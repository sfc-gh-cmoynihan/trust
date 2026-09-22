-- ============================================================================
-- DEMO TEARDOWN — Run AFTER the demo to reset state
-- SWT London 2026: Innovate at Scale — Powering a Secure and Resilient AI Estate
-- ============================================================================
-- Drops all DEMO_ objects, re-enables AI Guardrails, removes classification,
-- and disables AI Security + Threat Intelligence for repeatable demo.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- 1. DROP DEMO USERS AND ROLES
-- ============================================================================

DROP USER IF EXISTS DEMO_NO_MFA_USER;
DROP USER IF EXISTS DEMO_BAD_ADMIN;
DROP USER IF EXISTS DEMO_DORMANT_USER;
DROP ROLE IF EXISTS DEMO_OVERPRIVILEGED_ROLE;

-- ============================================================================
-- 2. DROP DEMO OBJECTS (tasks, procs)
-- ============================================================================

DROP TASK IF EXISTS DEMO_DB.PUBLIC.DEMO_ADMIN_TASK;
DROP PROCEDURE IF EXISTS DEMO_DB.PUBLIC.DEMO_ADMIN_PROC();

-- ============================================================================
-- 3. DROP DEMO AGENTS AND SEARCH SERVICES
-- ============================================================================

DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT;
DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_FINANCIAL_AGENT;
DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_PATIENT_AGENT;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_HR_SEARCH;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_FINANCIAL_SEARCH;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_PATIENT_SEARCH;

-- ============================================================================
-- 4. DROP DEMO TABLES
-- ============================================================================

DROP TABLE IF EXISTS DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA;
DROP TABLE IF EXISTS DEMO_DB.PUBLIC.PATIENT_RECORDS;

-- ============================================================================
-- 5. DROP DEMO POLICIES AND RESET PARAMETERS
-- ============================================================================

DROP AUTHENTICATION POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_WEAK_AUTH_POLICY;
DROP PASSWORD POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_WEAK_PASSWORD_POLICY;
DROP SESSION POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_LONG_SESSION_POLICY;
ALTER ACCOUNT UNSET ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION;

-- ============================================================================
-- 6. RE-ENABLE AI GUARDRAILS
-- ============================================================================

ALTER ACCOUNT SET AI_SETTINGS = $$
  guardrails:
    advanced_prompt_injection:
      - enabled: true
$$;

-- ============================================================================
-- 7. REMOVE CLASSIFICATION PROFILE AND TAGS
-- ============================================================================

ALTER DATABASE DEMO_DB UNSET CLASSIFICATION_PROFILE;
ALTER DATABASE RBAC_DEMO_DB UNSET CLASSIFICATION_PROFILE;

DROP SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE IF EXISTS DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE;
DROP SCHEMA IF EXISTS DEMO_DB.GOVERNANCE;

ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;

-- ============================================================================
-- 8. DISABLE AI SECURITY AND THREAT INTELLIGENCE
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- 9. VERIFY CLEAN STATE
-- ============================================================================

SELECT ID, NAME, STATE FROM snowflake.trust_center.scanner_packages ORDER BY NAME;
-- EXPECTED: AI_SECURITY=FALSE, CIS_BENCHMARKS=TRUE, SECURITY_ESSENTIALS=TRUE, THREAT_INTELLIGENCE=FALSE

SHOW PARAMETERS LIKE 'AI_SETTINGS' IN ACCOUNT;
-- EXPECTED: guardrails advanced_prompt_injection enabled: true

-- ============================================================================
-- TEARDOWN COMPLETE — Ready to run setup.sql again
-- ============================================================================
