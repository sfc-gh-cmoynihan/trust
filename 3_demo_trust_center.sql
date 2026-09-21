-- ============================================================================
-- TRUST CENTER DEMO — SWT London 2026
-- Innovate at Scale: Powering a Secure and Resilient AI Estate
-- ============================================================================
-- Duration: ~8 minutes
-- Structure: 4 Acts matching the slide deck narrative
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- ACT 1: THE SINGLE PANE OF GLASS
-- ============================================================================
-- TALK TRACK: "Let me show you Trust Center — Snowflake's single pane of glass
-- for security, compliance, and governance. This is where everything comes
-- together."
--
-- >>> SWITCH TO SNOWSIGHT: Navigate to Trust Center dashboard <<<
-- >>> Show the overview — severity distribution, scanner packages <<<
-- >>> Point out: CIS Benchmarks and Security Essentials are active <<<
-- >>> Note: AI Security and Threat Intelligence are not yet enabled <<<
-- ============================================================================

-- After showing the UI, run this to give the audience the numbers:

-- Current open findings across all severity levels
SELECT
    SEVERITY,
    COUNT(DISTINCT SCANNER_NAME) AS SCANNERS_WITH_FINDINGS,
    SUM(TOTAL_AT_RISK_COUNT)     AS TOTAL_AT_RISK_ENTITIES
FROM snowflake.trust_center.findings
WHERE UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
GROUP BY SEVERITY
ORDER BY CASE SEVERITY
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
    WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
END;

-- TALK TRACK: "We have critical findings that need attention. Let's drill in."

-- ============================================================================
-- Drill into: CIS 3.1 — No account-level network policy (CRITICAL)
-- ============================================================================
-- TALK TRACK: "CIS 3.1 — we don't have an account-level network policy.
-- That means any IP address can attempt to connect. This is the kind of
-- foundational security control that Trust Center flags immediately."
--
-- >>> SWITCH TO SNOWSIGHT: Click into CIS 3.1 finding <<<
-- >>> Show: severity, at-risk entities, suggested remediation SQL <<<

SELECT
    SCANNER_NAME,
    SEVERITY,
    TOTAL_AT_RISK_COUNT,
    SUGGESTED_ACTION
FROM snowflake.trust_center.findings
WHERE SCANNER_ID = 'CIS_BENCHMARKS_CIS3_1'
  AND UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
ORDER BY END_TIMESTAMP DESC
LIMIT 1;

-- ============================================================================
-- Drill into: CIS 1.14/1.15 — Tasks with admin privileges (HIGH)
-- ============================================================================
-- TALK TRACK: "Here's one that connects directly to least privilege —
-- 41 tasks running with ACCOUNTADMIN or SECURITYADMIN privileges.
-- In the agentic world, this is exactly the kind of over-privileged access
-- that creates risk."

SELECT
    SCANNER_NAME,
    SEVERITY,
    TOTAL_AT_RISK_COUNT
FROM snowflake.trust_center.findings
WHERE SCANNER_ID IN ('CIS_BENCHMARKS_CIS1_14', 'CIS_BENCHMARKS_CIS1_15',
                     'CIS_BENCHMARKS_CIS1_16', 'CIS_BENCHMARKS_CIS1_17')
  AND UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
QUALIFY ROW_NUMBER() OVER (PARTITION BY SCANNER_ID ORDER BY END_TIMESTAMP DESC) = 1
ORDER BY TOTAL_AT_RISK_COUNT DESC;

-- TALK TRACK: "Trust Center doesn't just flag these — it tells you exactly
-- how to fix them. But before we remediate, let's talk about protecting
-- the data itself."


-- ============================================================================
-- ACT 2: PII CLASSIFICATION AND DATA PROTECTION
-- ============================================================================
-- TALK TRACK: "One of the top concerns we hear from security leaders is
-- protecting sensitive data — especially when agents can access it.
-- Step one is knowing where your sensitive data lives."
-- ============================================================================

-- ============================================================================
-- Step 1: Auto-classify a table with PII
-- ============================================================================
-- TALK TRACK: "Here's an HR table. Let's ask Snowflake to automatically
-- classify what's in it."

SELECT * FROM DEMO_DB.PUBLIC.HR_DATA LIMIT 5;

-- Run auto-classification — Snowflake inspects the data and identifies
-- semantic categories (email, name, age, etc.)
SELECT EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.HR_DATA');

-- TALK TRACK: "Snowflake has identified EMAIL_ADDRESS as an email,
-- FNAME and LNAME as names, and AGE as a personal identifier.
-- Now let's apply these tags to the columns."

-- ============================================================================
-- Step 2: Apply classification tags
-- ============================================================================

CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
    'DEMO_DB.PUBLIC.HR_DATA',
    EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.HR_DATA')
);

-- Verify the tags were applied
SELECT *
FROM TABLE(
    INFORMATION_SCHEMA.TAG_REFERENCES('DEMO_DB.PUBLIC.HR_DATA', 'TABLE')
)
WHERE TAG_NAME IN ('SEMANTIC_CATEGORY', 'PRIVACY_CATEGORY')
ORDER BY COLUMN_NAME;

-- TALK TRACK: "Every column now has a semantic category and privacy category
-- tag. This is the foundation for data protection policies. Now let me show
-- you what happens when you combine classification with masking."

-- ============================================================================
-- Step 3: Show masking policies in action
-- ============================================================================
-- TALK TRACK: "Here's a stock analyst table that already has masking policies.
-- Watch what happens when different roles query the same table."

-- As ACCOUNTADMIN — full access
SELECT REPORT_ID, ANALYST_NAME, ANALYST_EMAIL, ANALYST_PHONE,
       TICKER, RECOMMENDATION, PRICE_TARGET, CONFIDENTIAL_NOTES
FROM RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA
LIMIT 5;

-- TALK TRACK: "As an admin, I see everything — names, emails, price targets,
-- confidential notes. But if I switch to a restricted analyst role..."

-- As a restricted role — data is masked
-- (Uncomment and adjust role name based on your account setup)
-- USE ROLE ANALYST_ROLE;
-- SELECT REPORT_ID, ANALYST_NAME, ANALYST_EMAIL, ANALYST_PHONE,
--        TICKER, RECOMMENDATION, PRICE_TARGET, CONFIDENTIAL_NOTES
-- FROM RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA
-- LIMIT 5;
-- USE ROLE ACCOUNTADMIN;

-- TALK TRACK: "Names are masked, emails are redacted, price targets are hidden.
-- Same table, same query — different results based on who's asking.
-- This is how you protect sensitive data from over-privileged access —
-- whether it's a human or an agent."

-- ============================================================================
-- Connect back to Trust Center
-- ============================================================================
-- TALK TRACK: "And Trust Center ties this together — CIS 4.10 flags tables
-- with sensitive data that don't have masking policies."

SELECT SCANNER_NAME, SEVERITY, TOTAL_AT_RISK_COUNT
FROM snowflake.trust_center.findings
WHERE SCANNER_ID = 'CIS_BENCHMARKS_CIS4_10'
  AND UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
ORDER BY END_TIMESTAMP DESC
LIMIT 1;


-- ============================================================================
-- ACT 3: AGENT SECURITY — ENABLE LIVE
-- ============================================================================
-- TALK TRACK: "Now let's turn on agent security. This is new — purpose-built
-- controls for the agentic era. Right now, AI Security is disabled.
-- Let's change that."
-- ============================================================================

-- Show current state — AI Security is OFF
SELECT ID, NAME, STATE
FROM snowflake.trust_center.scanner_packages
WHERE ID = 'AI_SECURITY';

-- ============================================================================
-- Enable AI Security — THE LIVE MOMENT
-- ============================================================================
-- TALK TRACK: "One command. That's all it takes."

CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'AI_SECURITY', false);

-- Verify it's enabled
SELECT ID, NAME, STATE
FROM snowflake.trust_center.scanner_packages
WHERE ID = 'AI_SECURITY';

-- ============================================================================
-- Show what AI Security checks for
-- ============================================================================
-- TALK TRACK: "Let me show you what we just turned on."

SELECT NAME, SHORT_DESCRIPTION
FROM snowflake.trust_center.scanners
WHERE SCANNER_PACKAGE_ID = 'AI_SECURITY'
ORDER BY NAME;

-- TALK TRACK:
-- "Four scanners, each addressing a real-world AI security concern:
--  1. Are Cortex AI Guardrails enabled? — Prompt injection protection
--  2. Are agents accessing sensitive classified data?
--  3. Are Cortex Search Services owned by privileged roles?
--  4. Are Cortex Code PATs scoped with network policies?
--
-- This is what agent security looks like — built into the platform."

-- ============================================================================
-- Run the AI Security scanners
-- ============================================================================
-- TALK TRACK: "Let's run the scanners now and see what they find."

CALL snowflake.trust_center.execute_scanner('AI_SECURITY');

-- Check for results (may take a moment to populate)
SELECT SCANNER_NAME, SEVERITY, TOTAL_AT_RISK_COUNT, UPPER(STATE) AS STATE
FROM snowflake.trust_center.findings
WHERE SCANNER_PACKAGE_ID = 'AI_SECURITY'
ORDER BY END_TIMESTAMP DESC
LIMIT 10;


-- ============================================================================
-- ACT 4: THREAT DETECTION — LOGIN PROTECTION
-- ============================================================================
-- TALK TRACK: "We've covered platform security, data protection, and agent
-- security. The final piece is threat detection — moving from violations
-- to real-time detections."
-- ============================================================================

-- Show current state — Threat Intelligence is OFF
SELECT ID, NAME, STATE
FROM snowflake.trust_center.scanner_packages
WHERE ID = 'THREAT_INTELLIGENCE';

-- ============================================================================
-- Enable Threat Intelligence
-- ============================================================================
-- TALK TRACK: "Let's enable Threat Intelligence."

CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'THREAT_INTELLIGENCE', false);

-- ============================================================================
-- Show the detection scanners
-- ============================================================================
-- TALK TRACK: "Look at what we've just turned on — these are detection
-- scanners. They don't just check configuration — they watch for threats."

SELECT NAME, SHORT_DESCRIPTION
FROM snowflake.trust_center.scanners
WHERE SCANNER_PACKAGE_ID = 'THREAT_INTELLIGENCE'
ORDER BY NAME;

-- TALK TRACK: "Login Protection — detects logins from known malicious IPs.
-- Dormant User Login — flags when inactive accounts suddenly wake up.
-- Authentication Failures — catches brute force attempts.
-- Sensitive Parameter Protection — alerts when someone disables
-- security parameters for data movement.
--
-- This is the shift from violations to detections that we talked about."

-- ============================================================================
-- Run Threat Intelligence scanners
-- ============================================================================

CALL snowflake.trust_center.execute_scanner('THREAT_INTELLIGENCE');

-- Check results
SELECT SCANNER_NAME, SEVERITY, TOTAL_AT_RISK_COUNT, SCANNER_TYPE, UPPER(STATE) AS STATE
FROM snowflake.trust_center.findings
WHERE SCANNER_PACKAGE_ID = 'THREAT_INTELLIGENCE'
ORDER BY END_TIMESTAMP DESC
LIMIT 15;

-- ============================================================================
-- CLOSING: THE FULL PICTURE
-- ============================================================================
-- TALK TRACK: "Let's step back and look at the full picture — every scanner
-- package, every finding, all in one place."

SELECT
    SCANNER_PACKAGE_NAME,
    SEVERITY,
    COUNT(*)                     AS FINDING_COUNT,
    SUM(TOTAL_AT_RISK_COUNT)     AS TOTAL_AT_RISK
FROM snowflake.trust_center.findings
WHERE UPPER(STATE) = 'OPEN'
  AND TOTAL_AT_RISK_COUNT > 0
GROUP BY SCANNER_PACKAGE_NAME, SEVERITY
ORDER BY SCANNER_PACKAGE_NAME,
    CASE SEVERITY
        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
    END;

-- TALK TRACK: "CIS Benchmarks for compliance. Security Essentials for
-- foundational hygiene. AI Security for agent guardrails. Threat Intelligence
-- for real-time detection.
--
-- All four packages. All severities. Every at-risk entity — visible in one
-- place. This is proactive, enterprise-grade security for data and AI.
-- Built in, not bolted on."
--
-- >>> SWITCH BACK TO SLIDES — Slide 7: THANK YOU <<<

-- ============================================================================
-- END OF DEMO
-- ============================================================================
