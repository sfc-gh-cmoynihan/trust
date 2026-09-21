-- ============================================================================
-- DEMO TEARDOWN — Run AFTER the demo to reset state
-- SWT London 2026: Innovate at Scale — Powering a Secure and Resilient AI Estate
-- ============================================================================
-- This script resets the account so the demo can be run again.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- 1. DISABLE AI SECURITY AND THREAT INTELLIGENCE
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- 2. REMOVE CLASSIFICATION TAGS FROM HR_DATA
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
-- 3. VERIFY RESET STATE
-- ============================================================================

SELECT ID, NAME, STATE
FROM snowflake.trust_center.scanner_packages
ORDER BY NAME;

-- EXPECTED:
-- AI_SECURITY        | FALSE
-- CIS_BENCHMARKS     | TRUE
-- SECURITY_ESSENTIALS| TRUE
-- THREAT_INTELLIGENCE| FALSE

-- ============================================================================
-- TEARDOWN COMPLETE — Ready to run demo again
-- ============================================================================
