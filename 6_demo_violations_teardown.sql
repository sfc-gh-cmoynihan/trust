-- ============================================================================
-- DEMO VIOLATIONS TEARDOWN
-- SWT London 2026: Clean up all demo violations
-- ============================================================================
-- Drops all DEMO_ objects, re-enables AI Guardrails, removes classification
-- tags, and disables AI Security + Threat Intelligence for repeatable demo.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- 1. DROP DEMO USERS
-- ============================================================================

DROP USER IF EXISTS DEMO_NO_MFA_USER;
DROP USER IF EXISTS DEMO_BAD_ADMIN;
DROP USER IF EXISTS DEMO_DORMANT_USER;

-- ============================================================================
-- 2. DROP DEMO ROLE
-- ============================================================================

DROP ROLE IF EXISTS DEMO_OVERPRIVILEGED_ROLE;

-- ============================================================================
-- 3. DROP DEMO OBJECTS
-- ============================================================================

DROP TASK IF EXISTS DEMO_DB.PUBLIC.DEMO_ADMIN_TASK;
DROP PROCEDURE IF EXISTS DEMO_DB.PUBLIC.DEMO_ADMIN_PROC();

-- ============================================================================
-- 4. DROP DEMO AGENTS AND SEARCH SERVICES
-- ============================================================================

DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT;
DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_FINANCIAL_AGENT;
DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_PATIENT_AGENT;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_HR_SEARCH;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_FINANCIAL_SEARCH;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_PATIENT_SEARCH;

-- ============================================================================
-- 4B. DROP DEMO TABLES (financial and patient data)
-- ============================================================================

DROP TABLE IF EXISTS DEMO_DB.PUBLIC.CUSTOMER_FINANCIAL_DATA;
DROP TABLE IF EXISTS DEMO_DB.PUBLIC.PATIENT_RECORDS;

-- ============================================================================
-- 4C. DROP DEMO POLICIES
-- ============================================================================

DROP AUTHENTICATION POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_WEAK_AUTH_POLICY;
DROP PASSWORD POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_WEAK_PASSWORD_POLICY;
DROP SESSION POLICY IF EXISTS DEMO_DB.PUBLIC.DEMO_LONG_SESSION_POLICY;

-- Reset sensitive parameter
ALTER ACCOUNT UNSET ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION;

-- ============================================================================
-- 5. RE-ENABLE AI GUARDRAILS
-- ============================================================================

ALTER ACCOUNT SET AI_SETTINGS = $$
  guardrails:
    advanced_prompt_injection:
      - enabled: true
$$;

-- ============================================================================
-- 6. REMOVE CLASSIFICATION PROFILE AND TAGS
-- ============================================================================

-- Unset classification profile from databases
ALTER DATABASE DEMO_DB UNSET CLASSIFICATION_PROFILE;
ALTER DATABASE RBAC_DEMO_DB UNSET CLASSIFICATION_PROFILE;

-- Drop classification profile and governance schema
DROP SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_PROFILE IF EXISTS DEMO_DB.GOVERNANCE.DEMO_CLASSIFICATION_PROFILE;
DROP SCHEMA IF EXISTS DEMO_DB.GOVERNANCE;

-- Remove auto-applied classification tags from HR_DATA
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;

-- ============================================================================
-- 7. DISABLE AI SECURITY AND THREAT INTELLIGENCE (for repeatable demo)
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- 8. VERIFY CLEAN STATE
-- ============================================================================

SELECT ID, NAME, STATE FROM snowflake.trust_center.scanner_packages ORDER BY NAME;

-- EXPECTED:
-- AI_SECURITY        | FALSE
-- CIS_BENCHMARKS     | TRUE
-- SECURITY_ESSENTIALS| TRUE
-- THREAT_INTELLIGENCE| FALSE

SHOW PARAMETERS LIKE 'AI_SETTINGS' IN ACCOUNT;
-- EXPECTED: guardrails advanced_prompt_injection enabled: true

-- ============================================================================
-- TEARDOWN COMPLETE — Ready to run violations setup again
-- ============================================================================
