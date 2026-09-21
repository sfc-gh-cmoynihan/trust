-- ============================================================================
-- DEMO SETUP — Run BEFORE going on stage
-- SWT London 2026: Innovate at Scale — Powering a Secure and Resilient AI Estate
-- ============================================================================
-- This script ensures the account is in the correct starting state:
--   - CIS Benchmarks and Security Essentials: ENABLED (with real findings)
--   - AI Security and Threat Intelligence: DISABLED (so we can enable live)
--   - HR_DATA table exists for classification demo
--   - Masking policies on STOCK_ANALYST_DATA are in place
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- 1. VERIFY SCANNER PACKAGE STATE
-- ============================================================================

-- Should show: CIS_BENCHMARKS=TRUE, SECURITY_ESSENTIALS=TRUE,
--              AI_SECURITY=FALSE, THREAT_INTELLIGENCE=FALSE
SELECT ID, NAME, STATE
FROM snowflake.trust_center.scanner_packages
ORDER BY NAME;

-- ============================================================================
-- 2. DISABLE AI SECURITY AND THREAT INTELLIGENCE (if previously enabled)
-- ============================================================================

CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'AI_SECURITY', false);
CALL snowflake.trust_center.set_configuration('ENABLED', 'FALSE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- 3. VERIFY CIS BENCHMARKS HAS FINDINGS
-- ============================================================================

-- Should show critical/high/medium/low findings with at-risk entities
SELECT SEVERITY, COUNT(*) AS FINDING_COUNT, SUM(TOTAL_AT_RISK_COUNT) AS TOTAL_AT_RISK
FROM snowflake.trust_center.findings
WHERE UPPER(STATE) = 'OPEN' AND TOTAL_AT_RISK_COUNT > 0
GROUP BY SEVERITY
ORDER BY CASE SEVERITY
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
END;

-- ============================================================================
-- 4. VERIFY HR_DATA TABLE FOR CLASSIFICATION DEMO
-- ============================================================================

SELECT COUNT(*) AS ROW_COUNT FROM DEMO_DB.PUBLIC.HR_DATA;
SELECT * FROM DEMO_DB.PUBLIC.HR_DATA LIMIT 5;

-- ============================================================================
-- 5. VERIFY MASKING POLICIES ON STOCK_ANALYST_DATA
-- ============================================================================

-- Should show masking policies on ANALYST_NAME, ANALYST_EMAIL, ANALYST_PHONE,
-- PRICE_TARGET, CONFIDENTIAL_NOTES
DESCRIBE TABLE RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA;

-- Quick check the data is there
SELECT COUNT(*) AS ROW_COUNT FROM RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA;

-- ============================================================================
-- 6. CLEAN UP ANY PREVIOUS CLASSIFICATION TAGS ON HR_DATA
-- ============================================================================

-- Remove tags if they were applied in a previous run
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN EMAIL_ADDRESS UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN FNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN LNAME UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.SEMANTIC_CATEGORY;
ALTER TABLE DEMO_DB.PUBLIC.HR_DATA MODIFY COLUMN AGE UNSET TAG SNOWFLAKE.CORE.PRIVACY_CATEGORY;

-- ============================================================================
-- 7. FINAL STATE CHECK
-- ============================================================================

-- Confirm scanner packages are in expected state
SELECT ID, NAME, STATE FROM snowflake.trust_center.scanner_packages ORDER BY NAME;

-- EXPECTED OUTPUT:
-- AI_SECURITY        | FALSE
-- CIS_BENCHMARKS     | TRUE
-- SECURITY_ESSENTIALS| TRUE
-- THREAT_INTELLIGENCE| FALSE

-- ============================================================================
-- SETUP COMPLETE — Ready for demo
-- ============================================================================
