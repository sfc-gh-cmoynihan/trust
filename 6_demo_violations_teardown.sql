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
-- 4. DROP DEMO AGENT AND SEARCH SERVICE
-- ============================================================================

DROP AGENT IF EXISTS DEMO_DB.PUBLIC.DEMO_INSECURE_AGENT;
DROP CORTEX SEARCH SERVICE IF EXISTS DEMO_DB.PUBLIC.DEMO_HR_SEARCH;

-- ============================================================================
-- 5. RE-ENABLE AI GUARDRAILS
-- ============================================================================

ALTER ACCOUNT SET AI_SETTINGS = $$
  guardrails:
    advanced_prompt_injection:
      - enabled: true
$$;

-- ============================================================================
-- 6. REMOVE CLASSIFICATION TAGS FROM HR_DATA
-- ============================================================================

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
